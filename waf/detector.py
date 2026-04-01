from rules import sqli
from rules import xss
from rules import ssti
from rules import lfi
from rules import rfi
from rules import cmd_injection


# RULE REGISTRY

RULES = [
    ("SQL Injection", sqli.detect_sqli),
    ("XSS", xss.detect_xss),
    ("SSTI", ssti.detect_ssti),
    ("LFI", lfi.detect_lfi),
    ("RFI", rfi.detect_rfi),
    ("Command Injection", cmd_injection.detect_cmd_injection),
]


# DETECTION

def detect_attack(payload):

    detected = []

    for name, rule in RULES:
        try:
            if rule(payload):
                detected.append(name)
        except Exception:
            pass  # avoid breaking detection pipeline

    if detected:
        return detected

    return None
