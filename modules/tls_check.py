"""TLS inspection: certificate health, negotiated cipher and protocol support."""
import socket
import ssl
import time
import warnings

PROTOCOLS = [("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"), ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3")]


def _supports(host, port, attr, timeout):
    try:
        ver = getattr(ssl.TLSVersion, attr)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ctx.maximum_version = ver
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return True
    except (OSError, ssl.SSLError, ValueError, AttributeError):
        return False


def _unverified(info, host, port, timeout):
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                info["version"], info["cipher"] = ss.version(), ss.cipher()[0]
    except (OSError, ssl.SSLError) as exc:
        info["error"] = str(exc)


def check_tls(host, port=443, timeout=5.0, deep=True):
    info, cert = {"port": port, "verified": True}, None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                info["version"], info["cipher"] = ss.version(), ss.cipher()[0]
    except ssl.SSLCertVerificationError as exc:
        info["verified"], info["verify_error"] = False, exc.verify_message
        _unverified(info, host, port, timeout)
    except (OSError, ssl.SSLError) as exc:
        info["error"] = str(exc)
        return info
    if cert:
        info["issuer"] = " ".join(v for rdn in cert.get("issuer", ()) for _, v in rdn)
        info["subject_cn"] = dict(x[0] for x in cert.get("subject", ())).get("commonName", "")
        info["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:15]
        info["expires"] = cert.get("notAfter")
        try:
            info["days_left"] = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
        except (KeyError, ValueError):
            pass
    if deep:
        info["protocols"] = {name: _supports(host, port, attr, timeout) for name, attr in PROTOCOLS}
    return info
