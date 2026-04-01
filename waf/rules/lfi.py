import re
import urllib.parse
import html
import unicodedata


# NORMALIZATION

def multi_decode(text, rounds=3):
    for _ in range(rounds):
        text = urllib.parse.unquote(text)
    return text


def normalize_input(text):

    text = multi_decode(text)
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    text = text.casefold()

    text = text.replace("\\", "/")

    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"\s+", " ", text)

    return text


# PATTERNS

traversal = re.compile(r"\.\./")

deep_traversal = re.compile(r"(?:\.\./){3,}")

sensitive_files = re.compile(
    r"""
    /etc/passwd|
    /etc/shadow|
    /etc/hosts|
    /etc/group|
    /proc/self/environ|
    /proc/self/cmdline|
    /var/log|
    /boot.ini|
    /windows/win.ini|
    /windows/system32|
    c:/windows
    """,
    re.VERBOSE,
)

php_wrappers = re.compile(
    r"""
    php://|
    data://|
    expect://|
    file://|
    zip://|
    phar://
    """,
    re.VERBOSE,
)

null_byte = re.compile(r"%00|\x00")


# DETECTION

def detect_lfi(payload):

    normalized = normalize_input(payload)

    score = 0

    if traversal.search(normalized):
        score += 2

    if deep_traversal.search(normalized):
        score += 3

    if sensitive_files.search(normalized):
        score += 5

    if php_wrappers.search(normalized):
        score += 5

    if null_byte.search(normalized):
        score += 3

    return score >= 5



# TEST
'''
tests = [

    "../../../etc/passwd",
    "../../../etc/passwd%00",
    "%252e%252e%252fetc%252fpasswd",
    "....//....//etc/passwd",
    "..///////..////etc/passwd",

    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",

    "/images/logo.png",
    "/css/style.css",
]

for t in tests:
    print(f"{t} -> {detect_lfi(t)}")
'''
