import re

_OP = re.compile(r"\b(query|mutation|subscription)\s+([A-Z][A-Za-z0-9_]+)\s*[(\{]")


def find_graphql_ops(js):
    out = set()
    for m in _OP.finditer(js):
        out.add(f"{m.group(1).lower()} {m.group(2)}")
    return out
