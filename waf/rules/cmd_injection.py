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

# Command separators: only match when they look like shell chaining,
# not normal URL parameters. Require whitespace or dangerous command nearby.
command_separators = re.compile(
    r"""
    (?:^|[\s=])         # preceded by start, whitespace, or =
    (;|\|\||\&\&)       # semicolon, ||, or && (NOT single | or & which appear in URLs)
    (?:[\s]|$)          # followed by whitespace or end
    """,
    re.VERBOSE
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

# common dangerous commands — require word boundaries and minimum context
dangerous_commands = re.compile(
    r"""
    \b(
        cat\s+|
        whoami|
        uname\s|
        pwd\b|
        sleep\s+\d|
        ping\s|
        bash\b|
        \/bin\/sh|
        \bnc\s+-|
        netcat\s|
        curl\s|
        wget\s|
        powershell|
        cmd\s*\.exe|
        cmd\s+\/c
    )
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

    normalized = normalize_input(payload)

    # direct command substitution — always suspicious
    if command_substitution.search(normalized):
        return True

    # command chaining with separator
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
