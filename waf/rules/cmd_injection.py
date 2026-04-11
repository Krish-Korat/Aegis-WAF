import re
import urllib.parse
import html
import unicodedata


def multi_decode(text, rounds=3):
    for _ in range(rounds):
        text = urllib.parse.unquote(text)
    return text


def normalize_input(text):
    text = multi_decode(text)
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    text = text.casefold()
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"\s+", " ", text)
    return text


command_separators = re.compile(r"(;|\|\||&&|\|)")

command_substitution = re.compile(r"(`[^`]+`|\$\([^)]*\))")

shell_expansion = re.compile(r"(\$@\s*\w|\$\{?ifs\}?|\$\([^)]*\)|`[^`]+`)")

dangerous_commands = re.compile(
    r"\b(cat|whoami|uname|pwd|sleep|ping|bash|sh|nc|curl|wget|powershell|netcat|ls|id|hostname)\b"
)

obfuscated_commands = re.compile(
    r"h\s*o\s*s\s*t\s*n\s*a\s*m\s*e|w\s*h\s*o\s*a\s*m\s*i|c\s*a\s*t|u\s*n\s*a\s*m\s*e|l\s*s|i\s*d|p\s*i\s*n\s*g"
)

sensitive_files = re.compile(
    r"/etc/passwd|/etc/shadow|/proc/self/environ|/proc/self/cmdline|c:\\windows\\system32"
)

redirection = re.compile(r"\b\w+\s*>>?\s*[/\w]|\b\w+\s*<\s*[/\w]")

hex_encoding = re.compile(r"\\x[0-9a-f]{2}")


def detect_cmd_injection(payload):
    normalized = normalize_input(payload)

    if command_substitution.search(normalized):
        return True

    if re.search(r"^\s*(;|&&|\|)\s*\w+", normalized):
        return True

    if sensitive_files.search(normalized):
        return True

    if obfuscated_commands.search(normalized):
        return True

    score = 0

    if command_separators.search(normalized):
        score += 1

    if dangerous_commands.search(normalized):
        score += 1

    if shell_expansion.search(normalized):
        score += 2

    if redirection.search(normalized):
        score += 1

    if hex_encoding.search(normalized):
        score += 1

    return True if score >= 2 else False


if __name__ == "__main__":
    tests = [
        "; ls",
        "&& whoami",
        "| cat /etc/passwd",
        "`id`",
        "$(uname -a)",
        "|hos\tname",
        "h o s t n a m e",
        "who$@ami",
        "normal input",
        "hello world",
        "ping google.com"
    ]

    for t in tests:
        print(f"{t} -> {detect_cmd_injection(t)}")
