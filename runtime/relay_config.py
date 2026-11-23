"""Pure validation shared by the operator settings and the HTTPS backend."""
import ipaddress
import re
from urllib.parse import urlsplit

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_CALLBACK_PATH = re.compile(r"/[A-Za-z0-9._~/\-]+")


def validated_https_url(value, *, callback=False):
    label = "OAuth callback" if callback else "HTTPS origin"
    if (not isinstance(value, str) or not value.isascii() or len(value) > 512
            or any(ord(c) < 33 or ord(c) == 127 for c in value)):
        raise ValueError(f"Set a canonical {label} URL.")
    try:
        uri = urlsplit(value)
        port = uri.port
        host = uri.hostname
    except ValueError:
        raise ValueError(f"Invalid {label} hostname or port.") from None
    if (uri.scheme != "https" or not host or uri.username is not None or uri.password is not None
            or uri.query or uri.fragment or (port is not None and not 1 <= port <= 65535)):
        raise ValueError(f"Use HTTPS for {label}, without credentials, query or fragment.")
    if callback:
        if (not _CALLBACK_PATH.fullmatch(uri.path) or "//" in uri.path
                or any(part in {".", ".."} for part in uri.path.split("/"))):
            raise ValueError("An OAuth callback needs a fixed, explicit absolute path without wildcards.")
    elif uri.path:
        raise ValueError("The HTTPS origin must not contain a path.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        valid = ip.is_global and not ip.is_multicast and not ip.is_reserved
    else:
        labels = host.split(".")
        valid = (len(host) <= 253 and len(labels) >= 2 and not labels[-1].isdigit()
                 and labels[-1] not in {"localhost", "local", "internal"}
                 and all(_LABEL.fullmatch(part) for part in labels))
    authority = f"[{host}]" if ":" in host else host
    authority += f":{port}" if port not in (None, 443) else ""
    if not valid or value != "https://" + authority + uri.path:
        raise ValueError(f"Use a canonical, public HTTPS hostname for {label}.")
    return value


def validated_oauth_callbacks(values):
    """Validate one to sixteen operator-chosen canonical URLs; never add defaults."""
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= 16:
        raise ValueError("Configure 1–16 exact HTTPS OAuth callback URLs in the local manager.")
    callbacks = [validated_https_url(value, callback=True) for value in values]
    if len(set(callbacks)) != len(callbacks):
        raise ValueError("Duplicate OAuth callback URLs are not allowed.")
    return sorted(callbacks)
