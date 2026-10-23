"""Input validation and normalisation for scan targets."""
import re
import socket

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.I)


def normalize_target(target: str) -> str:
    t = target.strip().lower()
    t = re.sub(r"^[a-z]+://", "", t)
    return t.split("/")[0].split(":")[0].rstrip(".")


def is_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def is_valid_target(target: str) -> bool:
    return target == "localhost" or is_ip(target) or bool(DOMAIN_RE.match(target))


def parse_ports(text: str):
    ports = [int(p) for p in text.split(",") if p.strip()]
    if not all(0 < p < 65536 for p in ports):
        raise ValueError("ports must be between 1 and 65535")
    return ports
