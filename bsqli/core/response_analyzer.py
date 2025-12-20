import time
from difflib import SequenceMatcher
from typing import Tuple
from .config import TIME_DELTA_THRESHOLD
from .logger import get_logger

logger = get_logger("analyzer")

def measure_request_time(func, *args, **kwargs) -> Tuple[float, object]:
    t0 = time.time()
    resp = func(*args, **kwargs)
    t1 = time.time()
    return (t1 - t0), resp

def content_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def is_time_significant(baseline: float, injected: float, threshold: float = TIME_DELTA_THRESHOLD) -> bool:
    return (injected - baseline) >= threshold
