import re

_ROUTER_HINT = re.compile(
    r"react-router|createBrowserRouter|createHashRouter|createMemoryRouter|"
    r"RouterProvider|useRoutes|<Route\b|vue-router|createRouter\s*\(|VueRouter|"
    r"RouterModule|@angular/router|createRootRoute|createFileRoute|createRoutesFromElements",
    re.I)

_JSX_ROUTE = re.compile(r"""<Route\b[^>]*?\bpath\s*=\s*['"]([^'"]{1,80})['"]""", re.I)
_OBJ_ROUTE = re.compile(r"""\bpath\s*:\s*['"]([^'"]{1,80})['"]""")

_BAD_ROUTE = re.compile(
    r"""://|[<>\s'"`]|\.(?:png|jpe?g|svg|gif|css|js|mjs|json|woff2?|ttf|ico|map|webp|pdf|mp[34])(?:\?|$)""",
    re.I)
_ROUTE_SHAPE = re.compile(r"^[/a-zA-Z:*]")


def _clean_route(p):
    p = p.strip()
    if not p or p in ("/", "*", "/*"):
        return None
    if _BAD_ROUTE.search(p) or not _ROUTE_SHAPE.match(p):
        return None
    return p


def find_routes(js):
    if not _ROUTER_HINT.search(js):
        return set()
    out = set()
    for rx in (_JSX_ROUTE, _OBJ_ROUTE):
        for m in rx.finditer(js):
            r = _clean_route(m.group(1))
            if r:
                out.add(r)
    return out
