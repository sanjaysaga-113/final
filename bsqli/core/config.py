import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

DEFAULT_TIMEOUT = 10
RETRY_TOTAL = 2
TIME_DELAY_DEFAULT = 5  # seconds for time-based injections
TIME_DELTA_THRESHOLD = 3.0  # delta seconds to consider significant
THREADS = 10
