import requests
from requests.adapters import HTTPAdapter, Retry
from .config import DEFAULT_TIMEOUT, RETRY_TOTAL
from .logger import get_logger
from .header_pool import get_random_headers
import time
import random
from collections import defaultdict
from urllib.parse import urlparse

logger = get_logger("http_client")


class RateLimiter:
    """Per-host adaptive rate limiting with WAF detection."""
    
    def __init__(self):
        self.host_delays = defaultdict(lambda: 0.5)  # Default 500ms per host
        self.host_last_request = defaultdict(float)
        self.host_429_count = defaultdict(int)
        self.host_403_count = defaultdict(int)
    
    def wait_for_host(self, host: str):
        """Apply adaptive delay with jitter before request."""
        now = time.time()
        elapsed = now - self.host_last_request[host]
        delay = self.host_delays[host]
        
        # Add random jitter (±20%)
        jitter = delay * random.uniform(0.8, 1.2)
        
        if elapsed < jitter:
            sleep_time = jitter - elapsed
            logger.debug(f"Rate limit: sleeping {sleep_time:.2f}s for {host}")
            time.sleep(sleep_time)
        
        self.host_last_request[host] = time.time()
    
    def record_response(self, host: str, status_code: int):
        """Adjust rate limit based on response status."""
        if status_code == 429:
            # Rate limited - exponential backoff
            self.host_429_count[host] += 1
            self.host_delays[host] *= 2.0
            logger.warning(f"429 Too Many Requests for {host} - increasing delay to {self.host_delays[host]:.2f}s")
        
        elif status_code in (403, 406):
            # WAF detected - increase delay moderately
            self.host_403_count[host] += 1
            self.host_delays[host] *= 1.5
            logger.warning(f"{status_code} detected for {host} (WAF?) - increasing delay to {self.host_delays[host]:.2f}s")
        
        elif status_code == 200 and self.host_delays[host] > 0.5:
            # Success - gradually reduce delay if previously throttled
            self.host_delays[host] = max(0.5, self.host_delays[host] * 0.9)
    
    def is_blocked(self, host: str) -> bool:
        """Check if host appears to be blocking requests."""
        return self.host_429_count[host] > 5 or self.host_403_count[host] > 10


class HttpClient:
    def __init__(self, timeout=DEFAULT_TIMEOUT, retries=RETRY_TOTAL, rotate_headers=True):
        self.session = requests.Session()
        retries_cfg = Retry(total=retries, backoff_factor=0.3,
                            status_forcelist=(500,502,503,504))
        self.session.mount("http://", HTTPAdapter(max_retries=retries_cfg))
        self.session.mount("https://", HTTPAdapter(max_retries=retries_cfg))
        self.timeout = timeout
        self.rotate_headers = rotate_headers
        self.rate_limiter = RateLimiter()

    def get(self, url, params=None, headers=None, cookies=None):
        try:
            # Extract host for rate limiting
            host = urlparse(url).netloc
            
            # Check if host is blocked
            if self.rate_limiter.is_blocked(host):
                logger.error(f"Host {host} appears blocked (too many 429/403) - skipping")
                raise requests.RequestException(f"Host {host} blocked")
            
            # Apply per-host rate limiting with jitter
            self.rate_limiter.wait_for_host(host)
            
            # Rotate headers if enabled
            if self.rotate_headers:
                request_headers = get_random_headers()
                if headers:
                    request_headers.update(headers)
            else:
                request_headers = headers
            
            resp = self.session.get(
                url,
                params=params,
                headers=request_headers,
                cookies=cookies,
                timeout=self.timeout,
                allow_redirects=True,
            )
            
            # Record response for adaptive throttling
            self.rate_limiter.record_response(host, resp.status_code)
            
            return resp
        except requests.RequestException as e:
            logger.debug("HTTP GET error: %s", e)
            raise
