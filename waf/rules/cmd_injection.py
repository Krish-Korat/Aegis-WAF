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

    # remove comments
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)

    # normalize whitespace
    text = re.sub(r"\s+", " ", text)

    return text


# COMMAND INJECTION PATTERNS

# command separators
command_separators = re.compile(
    r"(;|\|\||&&|\||&)"
)

# command substitution
command_substitution = re.compile(
    r"""
    (`[^`]+`) |           # backticks
    (\$\([^)]+\))         # $(...)
    """,
    re.VERBOSE
)

# shell variable expansion / bypass tricks
shell_expansion = re.compile(
    r"""
    \$@ |                 # $@
    \$\{?ifs\}? |         # $IFS or ${IFS}
    \$\([^)]+\) |         # $(...)
    `[^`]+`               # backticks
    """,
    re.VERBOSE
)

# common dangerous commands
dangerous_commands = re.compile(
    r"""
    \b(
        cat|
        ls|
        id|
        whoami|
        uname|
        pwd|
        sleep|
        ping|
        bash|
        sh|
        nc|
        curl|
        wget|
        powershell|
        cmd|
        netcat
    )\b
    """,
    re.VERBOSE
)

# detect obfuscated commands like who$@ami
obfuscated_commands = re.compile(
    r"""
    w\s*ho[\$\@\{\(\)]*\s*am\s*i |
    c\s*at |
    l\s*s |
    w\s*get |
    c\s*url
    """,
    re.VERBOSE
)

# sensitive file access often used in command injection
sensitive_files = re.compile(
    r"""
    /etc/passwd|
    /etc/shadow|
    /proc/self/environ|
    /proc/self/cmdline|
    c:\\windows\\system32
    """,
    re.VERBOSE
)

# input/output redirection
redirection = re.compile(
    r"(>|<)"
)

# hex encoded payloads
hex_encoding = re.compile(
    r"\\x[0-9a-f]{2}"
)


# DETECTION

def detect_cmd_injection(payload):

    normalized = normalize_input(payload)

    # direct command substitution
    if command_substitution.search(normalized):
        return True

    # command chaining
    if command_separators.search(normalized):

        if dangerous_commands.search(normalized):
            return True

        if obfuscated_commands.search(normalized):
            return True

        if shell_expansion.search(normalized):
            return True

    # shell expansion tricks
    if shell_expansion.search(normalized):

        if dangerous_commands.search(normalized) or obfuscated_commands.search(normalized):
            return True

    # redirection attacks
    if redirection.search(normalized):

        if dangerous_commands.search(normalized):
            return True

    # sensitive file access
    if sensitive_files.search(normalized):

        if dangerous_commands.search(normalized) or obfuscated_commands.search(normalized):
            return True

    # hex encoded command tricks
    if hex_encoding.search(normalized):

        if dangerous_commands.search(normalized):
            return True

    return False


'''
# TEST

tests = [

    "8.8.8.8;cat /etc/passwd",
    "8.8.8.8 && whoami",
    "`cat /etc/passwd`",
    "$(whoami)",
    "cat${IFS}/etc/passwd",
    ";who$@ami",
    ";who${IFS}ami",
    "who$(echo am)i",

    "hello world",
    "normal input",
]

for t in tests:
    print(f"{t} -> {detect_cmd_injection(t)}")
    
'''
