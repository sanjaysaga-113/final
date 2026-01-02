import logging
import subprocess
import time
from typing import List, Optional
from urllib.parse import urlparse
import subprocess


logger = logging.getLogger("recon.gau_runner")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def run_gau(domain: str, timeout: Optional[int] = None) -> List[str]:
    """
    Run gau (getallurls) and return list of URLs. If gau is missing, return [].
    Accepts a bare domain or a full URL; if a scheme is present, it extracts the netloc for gau.
    """
    parsed = urlparse(domain)
    target = parsed.netloc or parsed.path or domain
    cmd = ["gau", target]
    try:
        t0 = time.time()
        logger.info("Running gau: %s", " ".join(cmd))
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout, text=True)
        urls = [line.strip() for line in out.splitlines() if line.strip()]
        logger.info("gau completed in %.1fs with %d URLs", time.time() - t0, len(urls))
        return urls
    except FileNotFoundError:
        logger.error("gau not found. Install gau (https://github.com/lc/gau).")
        return []
    except subprocess.TimeoutExpired:
        logger.error("gau timed out after %ss (cmd=%s)", timeout, " ".join(cmd))
        return []
    except subprocess.CalledProcessError as e:
        logger.error("gau failed (exit %s): %s", e.returncode, e.output.strip())
        return []
    except subprocess.SubprocessError as e:
        logger.error("gau execution error: %s", e)
        return []
