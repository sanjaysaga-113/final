import requests
from requests.adapters import HTTPAdapter, Retry
from .config import DEFAULT_TIMEOUT, RETRY_TOTAL
from .logger import get_logger

logger = get_logger("http_client")

class HttpClient:
    def __init__(self, timeout=DEFAULT_TIMEOUT, retries=RETRY_TOTAL):
        self.session = requests.Session()
        retries_cfg = Retry(total=retries, backoff_factor=0.3,
                            status_forcelist=(500,502,503,504))
        self.session.mount("http://", HTTPAdapter(max_retries=retries_cfg))
        self.session.mount("https://", HTTPAdapter(max_retries=retries_cfg))
        self.timeout = timeout

    def get(self, url, params=None, headers=None, cookies=None):
        try:
            resp = self.session.get(
                url,
                params=params,
                headers=headers,
                cookies=cookies,
                timeout=self.timeout,
                allow_redirects=True,
            )
            return resp
        except requests.RequestException as e:
            logger.debug("HTTP GET error: %s", e)
            raise
