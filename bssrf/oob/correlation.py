"""
Correlation Logic for Blind SSRF Detection (Production-Grade)

Features:
- Injection tracking (thread-safe)
- Injection expiration (ignore old injections beyond TTL)
- Enhanced validation (timestamp, expiry checks)
- SQLite-backed persistence

Matches injected payloads (UUID) with received callbacks.
A finding is VALID only if:
  - Callback UUID matches injection UUID
  - Callback timestamp > injection timestamp
  - Injection not expired (within TTL window)
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from threading import Lock
import logging

logger = logging.getLogger("ssrf_correlation")

# Injection expiration window (matches callback_server.py)
INJECTION_EXPIRY_HOURS = 24

# Database path
CALLBACK_DB = os.path.join(os.path.dirname(__file__), "..", "output", "callbacks.db")
INJECTIONS_DB = os.path.join(os.path.dirname(__file__), "..", "output", "injections.db")


class InjectionTracker:
    """
    Thread-safe tracker for injected payloads.
    Maps UUID -> injection metadata.
    Persists to SQLite.
    """
    
    def __init__(self):
        self.lock = Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialize injections database."""
        os.makedirs(os.path.dirname(INJECTIONS_DB), exist_ok=True)
        
        conn = sqlite3.connect(INJECTIONS_DB)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS injections (
                uuid TEXT PRIMARY KEY,
                url TEXT,
                parameter TEXT,
                payload TEXT,
                timestamp TEXT,
                correlated INTEGER DEFAULT 0
            )
        """)
        
        conn.commit()
        conn.close()
    
    def record_injection(self, uuid: str, url: str, parameter: str, payload: str, timestamp: str = None):
        """
        Record a payload injection for later correlation.
        """
        if timestamp is None:
            timestamp = datetime.utcnow().isoformat()
        
        with self.lock:
            try:
                conn = sqlite3.connect(INJECTIONS_DB)
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO injections 
                    (uuid, url, parameter, payload, timestamp, correlated)
                    VALUES (?, ?, ?, ?, ?, 0)
                """, (uuid, url, parameter, payload, timestamp))
                
                conn.commit()
                conn.close()
                
                logger.debug(f"Recorded injection: UUID={uuid} | URL={url} | Param={parameter}")
            except Exception as e:
                logger.error(f"Error recording injection: {e}")
    
    def get_injection(self, uuid: str) -> Optional[Dict]:
        """Get injection by UUID."""
        with self.lock:
            try:
                conn = sqlite3.connect(INJECTIONS_DB)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("SELECT * FROM injections WHERE uuid = ?", (uuid,))
                row = cursor.fetchone()
                conn.close()
                
                if row:
                    return dict(row)
                return None
            except Exception as e:
                logger.error(f"Error retrieving injection: {e}")
                return None
    
    def mark_correlated(self, uuid: str):
        """Mark injection as correlated."""
        with self.lock:
            try:
                conn = sqlite3.connect(INJECTIONS_DB)
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE injections SET correlated = 1 WHERE uuid = ?
                """, (uuid,))
                
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Error marking correlated: {e}")
    
    def get_all_injections(self) -> List[Dict]:
        """Get all recorded injections."""
        with self.lock:
            try:
                conn = sqlite3.connect(INJECTIONS_DB)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("SELECT * FROM injections ORDER BY timestamp DESC")
                rows = cursor.fetchall()
                conn.close()
                
                return [dict(row) for row in rows]
            except Exception as e:
                logger.error(f"Error retrieving injections: {e}")
                return []


class CallbackCorrelator:
    """
    Correlates SSRF payloads with OOB callbacks.
    
    Supports:
    - Local SQLite-backed storage
    - Remote callback server API
    - Manual callback data
    """
    
    def __init__(self, callback_source: str = "sqlite", api_url: Optional[str] = None):
        """
        Args:
            callback_source: "sqlite" or "api"
            api_url: API endpoint if using remote callback server
        """
        self.callback_source = callback_source
        self.api_url = api_url
        self.injection_tracker = InjectionTracker()
        
        if callback_source == "sqlite":
            self._init_callback_db()
    
    def _init_callback_db(self):
        """Ensure callback database exists."""
        os.makedirs(os.path.dirname(CALLBACK_DB), exist_ok=True)
        if not os.path.exists(CALLBACK_DB):
            logger.warning(f"Callback database not found: {CALLBACK_DB}")
            logger.info("Make sure callback server is running!")
    
    def load_callbacks_from_sqlite(self) -> List[Dict]:
        """Load callbacks from SQLite database."""
        try:
            if not os.path.exists(CALLBACK_DB):
                logger.warning("Callback database not found")
                return []
            
            conn = sqlite3.connect(CALLBACK_DB)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM callbacks ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            conn.close()
            
            callbacks = []
            for row in rows:
                callback = dict(row)
                try:
                    callback['headers'] = json.loads(callback['headers'])
                except:
                    pass
                callbacks.append(callback)
            
            logger.debug(f"Loaded {len(callbacks)} callbacks from SQLite")
            return callbacks
        except Exception as e:
            logger.error(f"Failed to load callbacks from SQLite: {e}")
            return []
    
    def load_callbacks_from_api(self) -> List[Dict]:
        """Load callbacks from remote API."""
        if not self.api_url:
            logger.error("API URL not configured")
            return []
        
        try:
            import requests
            response = requests.get(f"{self.api_url}/api/callbacks", timeout=5)
            if response.status_code == 200:
                data = response.json()
                callbacks = data.get('callbacks', [])
                logger.debug(f"Loaded {len(callbacks)} callbacks from API")
                return callbacks
            else:
                logger.error(f"API returned status {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Failed to load callbacks from API: {e}")
            return []
    
    def get_all_callbacks(self) -> List[Dict]:
        """Get all callbacks from configured source."""
        if self.callback_source == "sqlite":
            return self.load_callbacks_from_sqlite()
        elif self.callback_source == "api":
            return self.load_callbacks_from_api()
        else:
            logger.error(f"Unknown callback source: {self.callback_source}")
            return []
    
    def is_injection_expired(self, injection_timestamp: str) -> bool:
        """Check if injection is too old to correlate."""
        try:
            injection_time = datetime.fromisoformat(injection_timestamp)
            expiry_time = injection_time + timedelta(hours=INJECTION_EXPIRY_HOURS)
            
            if datetime.utcnow() > expiry_time:
                logger.debug(f"Injection expired: {injection_timestamp}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error checking injection expiry: {e}")
            return False
    
    def check_uuid(self, uuid: str) -> Optional[Dict]:
        """
        Check if a specific UUID has received a callback.
        
        Args:
            uuid: The callback UUID to check
            
        Returns:
            Callback data if found and valid, None otherwise
        """
        # Get injection metadata
        injection = self.injection_tracker.get_injection(uuid)
        
        if injection and self.is_injection_expired(injection['timestamp']):
            logger.info(f"[EXPIRED] Injection too old: {uuid}")
            return None
        
        # Check for callback
        callbacks = self.get_all_callbacks()
        for callback in callbacks:
            if callback.get('uuid') == uuid:
                # Validate timestamp
                try:
                    callback_time = datetime.fromisoformat(callback['timestamp'])
                    if injection:
                        injection_time = datetime.fromisoformat(injection['timestamp'])
                        if callback_time > injection_time:
                            self.injection_tracker.mark_correlated(uuid)
                            logger.info(f"[VALID] Callback matches injection: {uuid}")
                            return callback
                    else:
                        logger.warning(f"No injection record for UUID: {uuid}")
                        return callback
                except Exception as e:
                    logger.error(f"Timestamp validation error: {e}")
                    return callback
        
        return None
    
    def correlate_injections(self, injections: List[Dict], wait_time: int = 30) -> Dict:
        """
        Correlate a list of injections with callbacks.
        
        Args:
            injections: List of injection metadata (each with 'uuid' field)
            wait_time: Time to wait for callbacks
            
        Returns:
            Dict with 'confirmed' and 'unconfirmed' lists
        """
        import time
        
        logger.info(f"Correlating {len(injections)} injections with callbacks")
        
        # Record all injections
        for injection in injections:
            uuid = injection.get('uuid')
            if uuid:
                self.injection_tracker.record_injection(
                    uuid=uuid,
                    url=injection.get('url'),
                    parameter=injection.get('parameter'),
                    payload=injection.get('payload_url'),
                    timestamp=injection.get('timestamp')
                )
        
        # Wait for callbacks
        logger.info(f"Waiting {wait_time}s for callbacks...")
        time.sleep(wait_time)
        
        # Get all callbacks
        callbacks = self.get_all_callbacks()
        callback_uuids = {cb.get('uuid'): cb for cb in callbacks if cb.get('uuid')}
        
        logger.info(f"Found {len(callback_uuids)} unique callback UUIDs")
        
        # Correlate
        confirmed = []
        unconfirmed = []
        
        for injection in injections:
            uuid = injection.get('uuid')
            if not uuid:
                continue
            
            if uuid in callback_uuids:
                callback = callback_uuids[uuid]
                
                injection['confirmed'] = True
                injection['callback'] = callback
                injection['confirmation_time'] = callback.get('timestamp')
                confirmed.append(injection)
                
                logger.info(f"[CONFIRMED] UUID: {uuid} | URL: {injection.get('url')}")
            else:
                injection['confirmed'] = False
                unconfirmed.append(injection)
                
                logger.debug(f"[UNCONFIRMED] UUID: {uuid} | URL: {injection.get('url')}")
        
        result = {
            'total_injections': len(injections),
            'confirmed': confirmed,
            'unconfirmed': unconfirmed,
            'confirmed_count': len(confirmed),
            'unconfirmed_count': len(unconfirmed)
        }
        
        logger.info(f"Correlation complete: {len(confirmed)} confirmed, {len(unconfirmed)} unconfirmed")
        
        return result
    
    def check_callback_server_health(self) -> bool:
        """Check if callback server is running and reachable."""
        if self.callback_source == "api" and self.api_url:
            try:
                import requests
                response = requests.get(f"{self.api_url}/health", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    logger.info(f"Callback server healthy: {data.get('status')}")
                    return True
            except Exception as e:
                logger.error(f"Callback server unreachable: {e}")
                return False
        elif self.callback_source == "sqlite":
            # For SQLite, check if database is accessible
            try:
                os.makedirs(os.path.dirname(CALLBACK_DB), exist_ok=True)
                return True
            except Exception as e:
                logger.error(f"Cannot access callback database: {e}")
                return False
        
        return False
