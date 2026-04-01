import re
import urllib.parse


def normalize_input(text):
    text = urllib.parse.unquote(text)

    # normalize template spacing tricks
    text = re.sub(r"\$\{ifs\}", " ", text, flags=re.IGNORECASE)

    # replace comments with space
    text = re.sub(r"/\*.*?\*/", " ", text)

    return text.lower()


ssti_pattern = re.compile(
r"(\{\{.*?\}\}"                         
r"|\{%\s*.*?\s*%\}"                     
r"|\$\{.*?\}"                           
r"|#\{.*?\}"                            
r"|<%=?\s*.*?\s*%>"                     
r"|@\{.*?\}"                            
r"|@\(.+?\)"                            

r"|\$\{\{<%[%\'\"}}%\\\."

r"|\{\{\s*\d+\s*[\*\+\-\/]\s*\d+\s*\}\}"
r"|\$\{\s*\d+\s*[\*\+\-\/]\s*\d+\s*\}"
r"|#\{\s*\d+\s*[\*\+\-\/]\s*\d+\s*\}"

r"|\(1\s*/\s*0\)"

r"|__globals__"
r"|__mro__"
r"|__subclasses__"
r"|self\.__init__"
r"|cycler\.__init__"
r"|config\.items"
r"|request\."
r"|os\.system"
r"|subprocess\."
r"|popen\("

r"|runtime\.getruntime"
r"|processbuilder"
r"|class\.forname"
r"|t\(java\.lang\.runtime\)"
r"|freemarker\.template"
r"|velocity\.engine"

r"|require\("
r"|process\.mainmodule"

r"|kernel\.system"
r"|open\("
r")",
re.IGNORECASE
)


def detect_ssti(text):
    normalized = normalize_input(text)
    return bool(ssti_pattern.search(normalized))

'''
print(detect_ssti("{{request['application']['\x5f\x5fglobals\x5f\x5f']['\x5f\x5fbuiltins\x5f\x5f']['\x5f\x5fimport\x5f\x5f']('os')['popen']('id')['read']()}}"))                                # True
print(detect_ssti("${7*7}"))                                 # True
print(detect_ssti("#{7*7}"))                                 # True
print(detect_ssti("<%= 7*7 %>"))                             # True
print(detect_ssti("{{self.__init__.__globals__}}"))          # True
print(detect_ssti("${T(java.lang.Runtime).getRuntime()}"))   # True
print(detect_ssti("${{<%[%\"'}}%\\."))                       # True
print(detect_ssti("hello world {7*7}"))                      # False
'''
