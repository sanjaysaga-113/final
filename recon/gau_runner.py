import logging
import subprocess
from typing import List


logger = logging.getLogger("recon.gau_runner")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def run_gau(domain: str, timeout: int = 10) -> List[str]:
    """
    Run gau (getallurls) and return list of URLs. If gau is missing, return [].
    """
    cmd = ["gau", domain]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout, text=True)
        urls = [line.strip() for line in out.splitlines() if line.strip()]
        return urls
    except FileNotFoundError:
        logger.error("gau not found. Install gau (https://github.com/lc/gau).")
        return []
    except subprocess.SubprocessError:
        logger.debug("gau execution failed or timed out.")
        return []
