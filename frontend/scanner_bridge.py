#!/usr/bin/env python3
"""
Scanner Bridge Module
Handles integration between Flask frontend and backend scanner modules

This module:
- Spawns scanner processes
- Streams real-time output via WebSocket
- Manages scan lifecycle
- Aggregates results from multiple modules
"""

import os
import sys
import json
import subprocess
import threading
import queue
import uuid
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
import time


class ScannerBridge:
    """
    Bridge between Flask frontend and backend scanner
    
    Responsibilities:
    - Process management (start/stop scanner)
    - Real-time output streaming
    - Result aggregation
    - Report generation
    """
    
    def __init__(self, socketio, logger):
        """
        Initialize scanner bridge
        
        Args:
            socketio: Flask-SocketIO instance for real-time communication
            logger: Logger instance
        """
        self.socketio = socketio
        self.logger = logger
        
        # Scan state management
        self.current_scan_id = None
        self.scan_process = None
        self.scan_thread = None
        self.scan_running = False
        
        # Results storage
        self.results_cache = {}
        
        # Project root (parent directory of frontend/)
        self.project_root = Path(__file__).parent.parent
        self.output_dirs = {
            'bxss': self.project_root / 'bxss' / 'output',
            'bsqli': self.project_root / 'bsqli' / 'output',
            'bssrf': self.project_root / 'bssrf' / 'output',
            'bcmdi': self.project_root / 'bcmdi' / 'output',
            'bxxe': self.project_root / 'bxe' / 'output'
        }
        # Map frontend module keys to backend CLI values
        self.module_cli_map = {
            'bxss': 'bxss',
            'bsqli': 'sqli',
            'bssrf': 'ssrf',
            'bcmdi': 'cmdi',
            'bxxe': 'xxe'
        }
    
    def is_running(self) -> bool:
        """Check if a scan is currently running"""
        return self.scan_running
    
    def start_scan(self, config: Dict[str, Any]) -> str:
        """
        Start a new vulnerability scan
        
        Args:
            config: Scan configuration dictionary
                {
                    "input_type": "url" | "file",
                    "target": "value",
                    "recon": bool,
                    "recon_mode": "passive" | "active",
                    "modules": ["bxss", "bsqli", ...]
                }
        
        Returns:
            scan_id: Unique identifier for this scan
        """
        if self.scan_running:
            raise RuntimeError("A scan is already running")
        
        # Generate unique scan ID
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        self.current_scan_id = scan_id
        
        # Store configuration
        self.results_cache[scan_id] = {
            'config': config,
            'status': 'initializing',
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'findings': [],
            'logs': []
        }
        
        # Start scan in background thread
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, config),
            daemon=True
        )
        self.scan_thread.start()
        
        return scan_id
    
    def _run_scan(self, scan_id: str, config: Dict[str, Any]):
        """
        Execute scan in background thread
        
        This method:
        1. Builds command to execute backend scanner
        2. Spawns subprocess
        3. Streams output to WebSocket
        4. Aggregates results
        """
        try:
            self.scan_running = True
            self._emit_log(scan_id, "INFO", "Initializing vulnerability scan...")
            
            # Build scanner commands (one per selected module)
            commands = self._build_scanner_commands(config)
            self._emit_log(scan_id, "DEBUG", f"Prepared {len(commands)} command(s) for execution")

            # Update status
            self.results_cache[scan_id]['status'] = 'running'

            # Execute each module sequentially for backend compatibility
            for module_key, cmd in commands:
                self._emit_log(scan_id, "INFO", f"Starting module: {module_key.upper()}")
                self._emit_log(scan_id, "DEBUG", f"Command: {' '.join(cmd)}")
                self._execute_scanner(scan_id, cmd, config, current_module=module_key)
            
            # Aggregate results from module outputs
            self._aggregate_results(scan_id, config['modules'])
            
            # Mark as completed
            self.results_cache[scan_id]['status'] = 'completed'
            self.results_cache[scan_id]['end_time'] = datetime.now().isoformat()
            
            self._emit_log(scan_id, "SUCCESS", "Scan completed successfully")
            self._emit_status_update(scan_id, 'completed')
            
        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}", exc_info=True)
            self.results_cache[scan_id]['status'] = 'failed'
            self.results_cache[scan_id]['error'] = str(e)
            self._emit_log(scan_id, "ERROR", f"Scan failed: {str(e)}")
            self._emit_status_update(scan_id, 'failed')
        
        finally:
            self.scan_running = False
            self.scan_process = None
    
    def _build_scanner_commands(self, config: Dict[str, Any]) -> List[tuple[str, List[str]]]:
        """
        Build backend-compatible commands for each selected module.

        Returns:
            List of tuples: (module_key, command_args)
        """
        python_exe = sys.executable
        main_script = self.project_root / 'main.py'

        if not main_script.exists():
            raise FileNotFoundError(f"Scanner script not found: {main_script}")

        # Base command (target + recon flags)
        base_cmd: List[str] = [python_exe, str(main_script)]

        # Target flags aligned to backend usage: -u / -f
        if config['input_type'] == 'url':
            base_cmd.extend(['-u', config['target']])
        else:
            base_cmd.extend(['-f', config['target']])

        # Recon flags: backend expects --recon and --recon-mode {passive,active,both}
        if config.get('recon'):
            base_cmd.append('--recon')
            recon_mode = config.get('recon_mode', 'passive')
            # Map UI 'active' (Passive + Active) to backend 'both'
            cli_mode = 'both' if recon_mode == 'active' else 'passive'
            base_cmd.extend(['--recon-mode', cli_mode])
        # If recon disabled, omit recon flags entirely

        # Add callback URL if XSS is selected
        if 'bxss' in config.get('modules', []) and config.get('callback_url'):
            base_cmd.extend(['--listener', config['callback_url']])

        commands: List[tuple[str, List[str]]] = []
        for module_key in config['modules']:
            cli_val = self.module_cli_map.get(module_key)
            if not cli_val:
                continue
            cmd = list(base_cmd)  # copy
            cmd.extend(['--scan', cli_val])
            commands.append((module_key, cmd))

        return commands
    
    def _execute_scanner(self, scan_id: str, cmd: List[str], config: Dict[str, Any], current_module: Optional[str] = None):
        """
        Execute scanner subprocess and stream output
        
        Args:
            scan_id: Unique scan identifier
            cmd: Command to execute
            config: Scan configuration
            current_module: Module key being executed (for context)
        """
        try:
            # Start process
            self.scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
                cwd=str(self.project_root)
            )
            
            # Stream output line by line
            for line in iter(self.scan_process.stdout.readline, ''):
                if line:
                    line = line.rstrip()
                    # Parse log level from line if present
                    level = self._parse_log_level(line)
                    self._emit_log(scan_id, level, line)
                    
                    # Store log
                    self.results_cache[scan_id]['logs'].append({
                        'timestamp': datetime.now().isoformat(),
                        'level': level,
                        'message': line
                    })
            
            # Wait for process to complete
            self.scan_process.wait()
            
            if self.scan_process.returncode != 0:
                msg = f"Scanner exited with code {self.scan_process.returncode}"
                if current_module:
                    msg += f" (module: {current_module.upper()})"
                self._emit_log(scan_id, "WARNING", msg)
            else:
                if current_module:
                    self._emit_log(scan_id, "SUCCESS", f"Module completed: {current_module.upper()}")
            
        except Exception as e:
            self.logger.error(f"Error executing scanner: {str(e)}")
            self._emit_log(scan_id, "ERROR", f"Execution error: {str(e)}")
            raise
    
    def _parse_log_level(self, line: str) -> str:
        """Extract log level from log line"""
        line_upper = line.upper()
        if 'ERROR' in line_upper or 'FAIL' in line_upper:
            return 'ERROR'
        elif 'WARN' in line_upper:
            return 'WARNING'
        elif 'SUCCESS' in line_upper or 'CONFIRMED' in line_upper:
            return 'SUCCESS'
        elif 'INFO' in line_upper:
            return 'INFO'
        elif 'DEBUG' in line_upper:
            return 'DEBUG'
        else:
            return 'INFO'
    
    def _normalize_finding(self, finding: Dict[str, Any], module: str) -> Dict[str, Any]:
        """
        Normalize finding from various module output formats to standard format.
        
        Handles different field names from different modules:
        - confidence, confidence_level, certainty, status
        - url, target, endpoint
        - parameter, param, key
        - evidence, callback_url, delay, response
        """
        normalized = {
            'module': module,
        }
        
        # Extract URL (try multiple field names)
        normalized['url'] = (
            finding.get('url') or
            finding.get('target') or
            finding.get('endpoint') or
            'N/A'
        )
        
        # Extract parameter name
        normalized['parameter'] = (
            finding.get('parameter') or
            finding.get('param') or
            finding.get('key') or
            'N/A'
        )
        
        # Extract confidence level (multiple possible field names)
        confidence = (
            finding.get('confidence') or
            finding.get('confidence_level') or
            finding.get('certainty') or
            finding.get('status') or
            'MEDIUM'
        )
        normalized['confidence'] = str(confidence).upper()
        
        # Extract evidence
        normalized['evidence'] = (
            finding.get('evidence') or
            finding.get('callback_url') or
            finding.get('delay') or
            finding.get('response') or
            'See logs'
        )
        
        # Pass through any extra fields
        for key, value in finding.items():
            if key not in normalized:
                normalized[key] = value
        
        return normalized
    
    def _aggregate_results(self, scan_id: str, modules: List[str]):
        """
        Aggregate results from all executed modules
        
        Args:
            scan_id: Scan identifier
            modules: List of executed modules
        """
        self._emit_log(scan_id, "INFO", "Aggregating results from modules...")
        
        all_findings = []
        
        for module in modules:
            try:
                # Find output files for this module
                output_dir = self.output_dirs.get(module)
                if not output_dir or not output_dir.exists():
                    self._emit_log(scan_id, "WARNING", 
                                 f"Output directory not found for {module}")
                    continue
                
                # Look for JSON findings file (most modules use this)
                json_files = list(output_dir.glob('findings*.json'))
                
                for json_file in json_files:
                    try:
                        with open(json_file, 'r') as f:
                            findings = json.load(f)
                            
                            # Normalize findings format
                            if isinstance(findings, list):
                                for finding in findings:
                                    normalized = self._normalize_finding(finding, module)
                                    all_findings.append(normalized)
                            elif isinstance(findings, dict):
                                normalized = self._normalize_finding(findings, module)
                                all_findings.append(normalized)
                        
                        self._emit_log(scan_id, "INFO", 
                                     f"Loaded {len(findings) if isinstance(findings, list) else 1} findings from {module}")
                    
                    except json.JSONDecodeError:
                        self._emit_log(scan_id, "WARNING", 
                                     f"Invalid JSON in {json_file}")
                    except Exception as e:
                        self._emit_log(scan_id, "WARNING", 
                                     f"Error reading {json_file}: {str(e)}")
            
            except Exception as e:
                self.logger.error(f"Error aggregating {module}: {str(e)}")
                self._emit_log(scan_id, "WARNING", 
                             f"Failed to aggregate results from {module}")
        
        # Store aggregated findings
        self.results_cache[scan_id]['findings'] = all_findings
        self._emit_log(scan_id, "INFO", 
                     f"Total findings: {len(all_findings)}")
    
    def _emit_log(self, scan_id: str, level: str, message: str):
        """
        Emit log message to WebSocket clients
        
        Args:
            scan_id: Scan identifier
            level: Log level (INFO, WARNING, ERROR, etc.)
            message: Log message
        """
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        self.socketio.emit('scan_log', {
            'scan_id': scan_id,
            'timestamp': timestamp,
            'level': level,
            'message': message
        })
    
    def _emit_status_update(self, scan_id: str, status: str):
        """
        Emit status update to WebSocket clients
        
        Args:
            scan_id: Scan identifier
            status: New status
        """
        self.socketio.emit('scan_status', {
            'scan_id': scan_id,
            'status': status
        })
    
    def stop_scan(self):
        """Stop the currently running scan"""
        if self.scan_process and self.scan_process.poll() is None:
            self.scan_process.terminate()
            try:
                self.scan_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.scan_process.kill()
            
            self._emit_log(self.current_scan_id, "WARNING", "Scan stopped by user")
        
        self.scan_running = False
    
    def get_status(self) -> Dict[str, Any]:
        """Get current scan status"""
        if self.current_scan_id and self.current_scan_id in self.results_cache:
            return {
                'scan_id': self.current_scan_id,
                'running': self.scan_running,
                'status': self.results_cache[self.current_scan_id]['status']
            }
        return {
            'scan_id': None,
            'running': False,
            'status': 'idle'
        }
    
    def get_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve results for a specific scan
        
        Args:
            scan_id: Scan identifier
        
        Returns:
            Results dictionary or None if not found
        """
        return self.results_cache.get(scan_id)
    
    def generate_report(self, scan_id: str, format: str) -> Optional[str]:
        """
        Generate downloadable report
        
        Args:
            scan_id: Scan identifier
            format: Report format ('json' or 'txt')
        
        Returns:
            Path to generated report file
        """
        if scan_id not in self.results_cache:
            return None
        
        results = self.results_cache[scan_id]
        report_dir = Path(__file__).parent / 'logs'
        report_dir.mkdir(exist_ok=True)
        
        if format == 'json':
            report_path = report_dir / f'{scan_id}_report.json'
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=2)
        
        elif format == 'txt':
            report_path = report_dir / f'{scan_id}_report.txt'
            with open(report_path, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("BLACK-BOX WEB VULNERABILITY SCANNER - SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Scan ID: {scan_id}\n")
                f.write(f"Status: {results['status']}\n")
                f.write(f"Start Time: {results['start_time']}\n")
                f.write(f"End Time: {results.get('end_time', 'N/A')}\n\n")
                
                f.write("-" * 80 + "\n")
                f.write("CONFIGURATION\n")
                f.write("-" * 80 + "\n")
                config = results['config']
                f.write(f"Target: {config['target']}\n")
                f.write(f"Recon Enabled: {config.get('recon', False)}\n")
                if config.get('recon'):
                    f.write(f"Recon Mode: {config.get('recon_mode', 'N/A')}\n")
                f.write(f"Modules: {', '.join(config['modules'])}\n\n")
                
                f.write("-" * 80 + "\n")
                f.write(f"FINDINGS ({len(results['findings'])})\n")
                f.write("-" * 80 + "\n\n")
                
                for i, finding in enumerate(results['findings'], 1):
                    f.write(f"[{i}] {finding.get('module', 'Unknown').upper()}\n")
                    f.write(f"    URL: {finding.get('url', 'N/A')}\n")
                    f.write(f"    Parameter: {finding.get('parameter', 'N/A')}\n")
                    f.write(f"    Status: {finding.get('status', 'N/A')}\n")
                    if 'evidence' in finding:
                        f.write(f"    Evidence: {finding['evidence']}\n")
                    f.write("\n")
                
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
        
        else:
            return None
        
        return str(report_path)
