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

    # normalize slashes
    text = text.replace("\\", "/")

    # remove comments
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)

    # normalize whitespace
    text = re.sub(r"\s+", " ", text)

    return text


# RFI DETECTION PATTERNS

# remote protocols commonly used in RFI
remote_protocols = re.compile(
    r"""
    (https?:\/\/) |
    (ftp:\/\/) |
    (php:\/\/) |
    (data:\/\/) |
    (expect:\/\/)
    """,
    re.VERBOSE
)


# UNC / SMB inclusion (Windows)
smb_inclusion = re.compile(
    r"""
    ^\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/ |
    ^\/\/[a-z0-9\.\-]+\/
    """,
    re.VERBOSE
)


# remote file extensions commonly used in RFI
remote_file = re.compile(
    r"""
    \.(php|phtml|php3|php4|php5|txt|inc|cgi|sh)(\?|$)
    """,
    re.VERBOSE
)


# null byte
null_byte = re.compile(
    r"%00|\x00"
)


# double encoding indicators
double_encoding = re.compile(
    r"%25[0-9a-f]{2}"
)


# DETECTION

def detect_rfi(payload):

    normalized = normalize_input(payload)

    # detect SMB/UNC inclusion
    if smb_inclusion.search(normalized):
        return True

    # detect remote protocol inclusion
    if remote_protocols.search(normalized):

        # remote file likely included
        if remote_file.search(normalized):
            return True

        # null byte bypass
        if null_byte.search(normalized):
            return True

        # double encoding trick
        if double_encoding.search(normalized):
            return True

    return False


# TEST
'''

tests = [

    "http://evil.com/shell.txt",
    "http://evil.com/shell.txt%00",
    "http:%252f%252fevil.com%252fshell.txt",
    "//10.0.0.1/share/shell.php",

    "https://example.com",
    "/images/logo.png",
    "index.php",
]

for t in tests:
    print(f"{t} -> {detect_rfi(t)}")

'''
