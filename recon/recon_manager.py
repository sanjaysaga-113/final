import logging
from typing import List
from .gau_runner import run_gau
from .gf_filter import run_gf_sqli, normalize_and_dedup
from .param_scorer import prioritize_urls, get_param_stats

logger = logging.getLogger("recon.manager")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def gather_parameterized_urls(domain_or_file: str, from_file: bool = False, scan_type: str = "sqli") -> List[str]:
    """
    Gather parameterized URLs for recon.

    Args:
        domain_or_file: Domain name or file path
        from_file: If True, read URLs from file; else run gau on domain
        scan_type: "sqli" for SQL injection candidates, "bxss" for XSS candidates

    Returns:
        List of URLs matching the scan type criteria
    """
    urls: List[str] = []
    if from_file:
        try:
            with open(domain_or_file, "r") as f:
                urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as e:
            logger.error("Failed to read file: %s", e)
            return []
    else:
        urls = run_gau(domain_or_file)

    logger.info("Recon input URLs: %d", len(urls))
    if not urls and not from_file:
        logger.error("Recon found no URLs. Ensure 'gau' is installed and accessible in this environment, or provide a URL file with -f.")

    # Filter based on scan type
    if scan_type == "bxss":
        filtered = [u for u in urls if "?" in u and "=" in u]
        logger.info("XSS filter: accepted %d parameterized URLs", len(filtered))
    elif scan_type == "ssrf":
        keywords = ["url", "redirect", "next", "callback", "webhook", "fetch", "uri", "link"]
        filtered = [u for u in urls if "?" in u and any(k in u.lower() for k in keywords)]
        if not filtered:
            filtered = [u for u in urls if "?" in u and "=" in u]
        logger.info("SSRF filter: accepted %d URLs after keyword heuristic", len(filtered))
    else:
        filtered = run_gf_sqli(urls)
        logger.info("SQLi filter: accepted %d URLs after gf/heuristic", len(filtered))

    normalized = normalize_and_dedup(filtered)
    logger.info("After dedup: %d URLs", len(normalized))
    
    # Prioritize by parameter risk scoring
    prioritized = prioritize_urls(normalized)
    
    # Log parameter statistics
    stats = get_param_stats(prioritized)
    if stats:
        top_params = list(stats.items())[:5]
        logger.info(f"Top params: {', '.join(f'{p}({c})' for p, c in top_params)}")
    
    logger.info("Recon produced %d parameterized URLs (prioritized by injection risk)", len(prioritized))
    return prioritized
