import logging
import subprocess
from typing import List
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

logger = logging.getLogger("recon.gf_filter")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def run_gf_sqli(urls: List[str], timeout: int = 10) -> List[str]:
    """
    Feed urls to 'gf sqli' if available. Fallback: heuristic filtering by '?' and '='.
    """
    try:
        proc = subprocess.Popen(["gf", "sqli"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        stdin = "\n".join(urls)
        out, _ = proc.communicate(stdin, timeout=timeout)
        hits = [l.strip() for l in out.splitlines() if l.strip()]
        return hits
    except FileNotFoundError:
        logger.info("gf not found; using heuristic filtering.")
        return [u for u in urls if ("?" in u and "=" in u)]
    except subprocess.SubprocessError:
        logger.debug("gf execution failed; using heuristic filtering.")
        return [u for u in urls if ("?" in u and "=" in u)]


def normalize_and_dedup(urls: List[str]) -> List[str]:
    seen = set()
    out = []
    for u in urls:
        try:
            p = urlparse(u)
            qs = parse_qs(p.query, keep_blank_values=True)
            # sort params for normalization
            q = urlencode(sorted([(k, v[0] if isinstance(v, list) else v) for k, v in qs.items()]), doseq=False)
            norm = urlunparse((p.scheme or "http", p.netloc, p.path, "", q, ""))
            if norm not in seen:
                seen.add(norm)
                out.append(norm)
        except Exception:
            continue
    return out
