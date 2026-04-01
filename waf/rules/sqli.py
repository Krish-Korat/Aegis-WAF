import re
import urllib.parse


def normalize_input(text):
    text = urllib.parse.unquote(text)

    text = re.sub(r"\$\{ifs\}", " ", text, flags=re.IGNORECASE)

    # replace comments with space instead of removing
    text = re.sub(r"/\*.*?\*/", " ", text)

    return text.lower()


sqli_pattern = re.compile(
r"(union\s+select|select\s+.+\s+from|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|sleep\s*\(|benchmark\s*\(|load_file\s*\(|into\s+outfile|information_schema|'\s*or\s*'?\d+'?\s*=\s*'?\d+|or\s+true|and\s+1\s*=\s*1|--|#)",
re.IGNORECASE
)


def detect_sqli(text):
    normalized = normalize_input(text)
    return bool(sqli_pattern.search(normalized))

'''
print(detect_sqli("select${IFS}name${IFS}FROM${IFS}users"))  # True
print(detect_sqli("UNION/**/SELECT"))                        # True
print(detect_sqli("UNION%0ASELECT"))                         # True
print(detect_sqli("union/*!500000select*/1,user() #"))       # True
print(detect_sqli("please select a color"))                  # False
'''