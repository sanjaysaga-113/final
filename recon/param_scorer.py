"""
Parameter Frequency Scorer

Prioritizes URLs by injection potential based on parameter names.
High-risk params (id, user, search, etc.) score higher.
"""

from typing import List, Dict
from urllib.parse import urlparse, parse_qs
import logging

logger = logging.getLogger("recon.param_scorer")

# Parameter risk weights (higher = more likely injection point)
PARAM_WEIGHTS = {
    # Identity params (highest risk)
    'id': 10, 'uid': 10, 'user_id': 10, 'userid': 10,
    'account': 9, 'username': 9, 'user': 9,
    
    # Query params (high risk)
    'q': 8, 'query': 8, 'search': 8, 's': 8,
    'keyword': 7, 'term': 7, 'filter': 7,
    
    # Content params
    'page': 6, 'cat': 6, 'category': 6, 'type': 6,
    'item': 6, 'product': 6, 'post': 6,
    
    # Navigation params
    'sort': 5, 'order': 5, 'limit': 5, 'offset': 5,
    'from': 5, 'to': 5, 'start': 5, 'end': 5,
    
    # Generic params (lower risk)
    'key': 4, 'value': 4, 'data': 4, 'input': 4,
}

DEFAULT_WEIGHT = 3  # Unknown params get baseline score


def score_url(url: str) -> int:
    """
    Calculate injection risk score for a URL based on parameter names.
    
    Returns:
        int: Risk score (higher = more priority)
    """
    try:
        qs = parse_qs(urlparse(url).query)
        score = 0
        for param in qs.keys():
            param_lower = param.lower()
            # Exact match
            if param_lower in PARAM_WEIGHTS:
                score += PARAM_WEIGHTS[param_lower]
            # Partial match (e.g., 'user_name' contains 'user')
            else:
                partial_score = max(
                    (PARAM_WEIGHTS[key] - 2 for key in PARAM_WEIGHTS if key in param_lower),
                    default=DEFAULT_WEIGHT
                )
                score += partial_score
        return score
    except Exception:
        return 0


def prioritize_urls(urls: List[str]) -> List[str]:
    """
    Sort URLs by injection potential (highest risk first).
    
    Args:
        urls: List of URLs to prioritize
    
    Returns:
        List[str]: Sorted URLs (highest priority first)
    """
    scored = [(url, score_url(url)) for url in urls]
    scored.sort(key=lambda x: x[1], reverse=True)
    
    logger.info(f"Prioritized {len(urls)} URLs (top score: {scored[0][1] if scored else 0})")
    return [url for url, _ in scored]


def get_param_stats(urls: List[str]) -> Dict[str, int]:
    """
    Analyze parameter frequency across URL list.
    
    Returns:
        Dict mapping param name → occurrence count
    """
    param_counts = {}
    for url in urls:
        try:
            qs = parse_qs(urlparse(url).query)
            for param in qs.keys():
                param_counts[param] = param_counts.get(param, 0) + 1
        except Exception:
            continue
    return dict(sorted(param_counts.items(), key=lambda x: x[1], reverse=True))
