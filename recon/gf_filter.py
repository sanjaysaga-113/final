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
        if not hits:
            logger.info("gf returned 0 matches; using heuristic filtering instead.")
            # Heuristic: keep URLs that look parameterized (either '?' alone or with '=')
            return [u for u in urls if ("?" in u or "=" in u)]
        return hits
    except FileNotFoundError:
        logger.info("gf not found; using heuristic filtering.")
        return [u for u in urls if ("?" in u and "=" in u)]
    except subprocess.SubprocessError:
        logger.debug("gf execution failed; using heuristic filtering.")
        return [u for u in urls if ("?" in u and "=" in u)]


def normalize_and_dedup(urls: List[str]) -> List[str]:
    """
    Deduplicate by path + parameter names (ignore values).
    Preserves first occurrence of each unique URL signature.
    """
    seen = set()
    out = []
    for u in urls:
        try:
            p = urlparse(u)
            qs = parse_qs(p.query, keep_blank_values=True)
            # Create signature: scheme://netloc/path?param1&param2 (sorted, no values)
            param_names = "&".join(sorted(qs.keys()))
            signature = f"{p.scheme or 'http'}://{p.netloc}{p.path}?{param_names}"
            if signature not in seen:
                seen.add(signature)
                out.append(u)  # Preserve original URL with values
        except Exception:
            continue
    return out


def detect_context(url: str) -> str:
    """
    Detect endpoint context for payload selection.
    Returns: 'html', 'json', 'api', or 'unknown'
    """
    path_lower = urlparse(url).path.lower()
    if any(ext in path_lower for ext in ['.json', '/api/', '/v1/', '/v2/', '/graphql']):
        return 'json'
    if any(ext in path_lower for ext in ['.html', '.php', '.asp', '.jsp']):
        return 'html'
    if '/api' in path_lower or path_lower.startswith('/rest'):
        return 'api'
    return 'unknown'
