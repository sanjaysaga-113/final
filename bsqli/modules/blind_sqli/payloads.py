from .payload_engine import BOOLEAN_PAIRS, TIME_BASED

# Expose loader functions so payloads are not hardcoded in logic
def boolean_payloads():
    return [{'true': t, 'false': f} for t, f in BOOLEAN_PAIRS]

def time_payloads(delay=5):
    return [{'db': db, 'payload': tpl.format(delay=delay)} for db, tpl in TIME_BASED]
