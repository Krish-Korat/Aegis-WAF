import re
import urllib.parse
import html


# -----------------------
# NORMALIZATION
# -----------------------

def multi_decode(text, rounds=3):
    for _ in range(rounds):
        text = urllib.parse.unquote(text)
    return text


def normalize_input(text):

    # Limit payload size to avoid regex abuse
    text = text[:5000]

    # URL decode multiple times
    text = multi_decode(text)

    # Decode HTML entities
    text = html.unescape(text)

    # Case normalize
    text = text.casefold()

    # Remove JS / HTML comments
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.S)

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    return text


# -----------------------
# XSS PATTERNS
# -----------------------

xss_patterns = [

    # script tags
    r"<\s*script",

    # dangerous HTML tags
    r"<\s*(svg|img|iframe|object|embed|video|audio|body|details)",

    # event handlers
    r"on\w+\s*=",

    # javascript protocol
    r"javascript\s*:",

    # data URI injection
    r"data\s*:\s*text\/html",

    # javascript execution
    r"(alert|prompt|confirm)\s*\(",
    r"eval\s*\(",
    r"settimeout\s*\(",
    r"setinterval\s*\(",

    # DOM sensitive access
    r"document\.cookie",
    r"window\.location",

    # iframe srcdoc
    r"srcdoc\s*=",

    # JS constructor execution
    r"\.constructor\s*\(",

    # JSFuck style
    r"\[\]\s*\[",
]

xss_regex = re.compile("|".join(xss_patterns), re.IGNORECASE)

def detect_xss(payload):

    normalized = normalize_input(payload)

    return bool(xss_regex.search(normalized))
'''
if __name__ == "__main__":

    tests = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<a href='javascript:alert(1)'>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "script"
    ]

    for t in tests:
        print(t, "->", detect_xss(t))
'''
