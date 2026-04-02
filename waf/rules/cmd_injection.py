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

# command separators — semicolons can appear without spaces in attacks
command_separators = re.compile(
    r"""
    ;                |    # semicolon (most common separator)
    \|\|             |    # logical OR
    \&\&                  # logical AND
    """,
    re.VERBOSE
)

# single pipe (require spaces around it to avoid matching URL params)
pipe_separator = re.compile(r"\s\|\s")

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
        netcat|
        rm|
        chmod|
        chown|
        python|
        perl|
        ruby|
        php
    )\b
    """,
    re.VERBOSE
)

# detect obfuscated commands like who$@ami
obfuscated_commands = re.compile(
    r"""
    w\s*ho[\$\@\{\(\)]+\s*am\s*i |
    c\s*at |
    l\s*s |
    w\s*get |
    c\s*url
    """,
    re.VERBOSE
)

# sensitive file access
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


# URL-like content detector — used to skip false positives
url_pattern = re.compile(
    r"^https?://[^\s]+$"
)


def is_mostly_url(text):
    """Check if the normalized text is just a URL with query params.
    Normal URLs contain & and = for parameters which can false-positive."""
    # If the text is dominated by URL patterns, it's not an attack
    # Count suspicious chars vs total
    non_url = re.sub(r'https?://[^\s]+', '', text)
    # If after removing URLs there's almost nothing left, skip
    if len(non_url.strip()) < 5:
        return True
    return False


# DETECTION

def detect_cmd_injection(payload):

    normalized = normalize_input(payload)

    # Skip if the entire payload is just normal URL content
    # This prevents false positives on URLs like google.com/async?param=value&other=value
    if is_mostly_url(normalized):
        return False

    # direct command substitution — always suspicious
    if command_substitution.search(normalized):
        return True

    # command chaining with separator (;, ||, &&)
    if command_separators.search(normalized):

        if dangerous_commands.search(normalized):
            return True

        if obfuscated_commands.search(normalized):
            return True

        if shell_expansion.search(normalized):
            return True

    # pipe with spaces (   | command )
    if pipe_separator.search(normalized):

        if dangerous_commands.search(normalized):
            return True

    # shell expansion tricks
    if shell_expansion.search(normalized):

        if dangerous_commands.search(normalized) or obfuscated_commands.search(normalized):
            return True

    # redirection attacks (only if combined with dangerous commands)
    if redirection.search(normalized):

        if command_separators.search(normalized) and dangerous_commands.search(normalized):
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
