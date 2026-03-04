"""
Rich compatibility shim.
Tries to import rich normally; falls back to the version bundled with pip.
"""
import sys

def _ensure_rich():
    try:
        import rich
        return
    except ImportError:
        pass
    # Fall back to pip's bundled rich
    pip_vendor = '/usr/lib/python3/dist-packages/pip/_vendor'
    if pip_vendor not in sys.path:
        sys.path.insert(0, pip_vendor)
    try:
        import rich
        return
    except ImportError:
        raise ImportError(
            "rich is not installed. Install it with: pip install rich\n"
            "Or: pip install jwtforge"
        )

_ensure_rich()
