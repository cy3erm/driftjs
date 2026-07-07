import sys

from . import __version__

_ART = r"""
       __     _ ______    _
  ____/ /____(_) __/ /_  (_)____
 / __  / ___/ / /_/ __/ / / ___/
/ /_/ / /  / / __/ /_  / (__  )
\__,_/_/  /_/_/  \__/_/ /____/
                   /___/
"""


def banner():
    if not sys.stdout.isatty():
        return ""
    cyan, dim, reset = "\033[38;5;44m", "\033[2m", "\033[0m"
    lines = _ART.strip("\n").splitlines()
    out = [cyan + l + reset for l in lines]
    tag = f"{dim}  what a target ships, what it hides, what it deleted{reset}   {cyan}v{__version__}{reset}"
    author = f"{dim}  recon differ · by cy3erm{reset}"
    return "\n".join(out) + "\n" + tag + "\n" + author + "\n"


def print_banner():
    b = banner()
    if b:
        print(b)
