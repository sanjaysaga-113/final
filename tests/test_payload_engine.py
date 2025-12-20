import random
from bsqli.modules.blind_sqli.payload_engine import generate_payloads


def test_generate_payloads_reproducible():
    a = generate_payloads(seed_type="time", db="mssql", obfuscate=True, depth=2, delay=1, max_results=10, seed=123)
    b = generate_payloads(seed_type="time", db="mssql", obfuscate=True, depth=2, delay=1, max_results=10, seed=123)
    assert a == b
    assert len(a) > 0
    for entry in a:
        assert "payload" in entry
        # db can be None or string
        assert "db" in entry


def test_generate_payloads_non_deterministic_by_default():
    # these runs may produce different outputs
    a = generate_payloads(seed_type="time", db="mssql", obfuscate=True, depth=2, delay=1, max_results=10)
    b = generate_payloads(seed_type="time", db="mssql", obfuscate=True, depth=2, delay=1, max_results=10)
    # they can be equal by chance but usually not; ensure structure is valid
    assert isinstance(a, list)
    assert isinstance(b, list)
    if a and b:
        assert "payload" in a[0]
        assert "payload" in b[0]
