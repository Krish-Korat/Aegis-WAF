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

# Command separators typically used for injection
# (We exclude single & to avoid false positives with URL query params)
command_separators = re.compile(
    r"(;|\|\||\&\&|\|)"
)

# command substitution
command_substitution = re.compile(
    r"""
    (`[^`]+`) |           # backticks with content
    (\$\([^)]+\))         # $(...)
    """,
    re.VERBOSE
)

# shell variable expansion / bypass tricks
shell_expansion = re.compile(
    r"""
    \$@\s*\w |            # $@ followed by word char
    \$\{?ifs\}? |         # $IFS or ${IFS}
    \$\([^)]+\) |         # $(...)
    `[^`]+`               # backticks
    """,
    re.VERBOSE
)

# Common dangerous commands used in an attack context
# Bounded by \b to ensure we don't trigger on substring matches (e.g. 'tomcat')
dangerous_commands = re.compile(
    r"""
    \b(
        cat|
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
        netcat
    )\b
    """,
    re.VERBOSE
)

# detect obfuscated commands like who$@ami
obfuscated_commands = re.compile(
    r"""
    w\s*ho[\$\@\{\(\)]+\s*am\s*i |
    c\s*a\s*t\s+\/     |
    w\s*g\s*e\s*t\s+   |
    c\s*u\s*r\s*l\s+
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

# input/output redirection (require context — not bare < > in HTML)
redirection = re.compile(
    r"""
    \b\w+\s*>>?\s*[/\w] |    # command > file  or  command >> file
    \b\w+\s*<\s*[/\w]         # command < file
    """,
    re.VERBOSE
)

# hex encoded payloads
hex_encoding = re.compile(
    r"\\x[0-9a-f]{2}"
)


# DETECTION

def detect_cmd_injection(payload):

    # For command injection, we primarily check if BOTH a separator AND a dangerous command exists.
    # We do NOT flag on just a dangerous word alone because words like 'ping' or 'cat' are common.

    normalized = normalize_input(payload)

    # 1. Direct command substitution — always suspicious
    if command_substitution.search(normalized):
        return True

    # 2. Command chaining with separator
    if command_separators.search(normalized):

        if dangerous_commands.search(normalized):
            return True

        if obfuscated_commands.search(normalized):
            return True

        if shell_expansion.search(normalized):
            return True

    # 3. Shell expansion tricks
    if shell_expansion.search(normalized):

        if dangerous_commands.search(normalized) or obfuscated_commands.search(normalized):
            return True

    # 4. Redirection attacks
    if redirection.search(normalized):

        if dangerous_commands.search(normalized):
            return True

    # 5. Sensitive file access
    if sensitive_files.search(normalized):

        if dangerous_commands.search(normalized) or obfuscated_commands.search(normalized):
            return True

    # 6. Hex encoded command tricks
    if hex_encoding.search(normalized):

        if dangerous_commands.search(normalized):
            return True

    return False
