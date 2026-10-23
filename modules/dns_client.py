"""Minimal DNS-over-UDP client (stdlib only): A, AAAA, NS, CNAME, MX, TXT."""
import random
import socket
import struct

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
RTYPES = {v: k for k, v in QTYPES.items()}


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError("bad label")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name: str, qtype: str, tid=None):
    tid = random.randint(0, 65535) if tid is None else tid
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return tid, header + encode_name(name) + struct.pack("!HH", QTYPES[qtype], 1)


def decode_name(data: bytes, off: int):
    labels, jumped, end, hops = [], False, off, 0
    while True:
        length = data[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
            continue
        off += 1
        labels.append(data[off:off + length].decode("ascii", "replace"))
        off += length
    return ".".join(labels), (end if jumped else off)


def parse_response(data: bytes):
    _, flags, qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    rcode, off = flags & 0xF, 12
    for _ in range(qd):
        _, off = decode_name(data, off)
        off += 4
    records = []
    for _ in range(an):
        name, off = decode_name(data, off)
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        rd, rdoff = data[off:off + rdlen], off
        off += rdlen
        if rtype == 1 and rdlen == 4:
            val = socket.inet_ntoa(rd)
        elif rtype == 28 and rdlen == 16:
            val = socket.inet_ntop(socket.AF_INET6, rd)
        elif rtype in (2, 5):
            val, _ = decode_name(data, rdoff)
        elif rtype == 15:
            pref = struct.unpack("!H", rd[:2])[0]
            host, _ = decode_name(data, rdoff + 2)
            val = "%d %s" % (pref, host)
        elif rtype == 16:
            i, parts = 0, []
            while i < len(rd):
                n = rd[i]
                parts.append(rd[i + 1:i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            val = "".join(parts)
        else:
            continue
        records.append({"name": name, "type": RTYPES[rtype], "value": val})
    return rcode, records


def query(name: str, qtype: str, server: str = "8.8.8.8", timeout: float = 3.0):
    """Returns (rcode, records) or None if the resolver could not be reached."""
    try:
        tid, packet = build_query(name, qtype)
    except (ValueError, UnicodeEncodeError):
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (server, 53))
            data, _ = s.recvfrom(4096)
        if struct.unpack("!H", data[:2])[0] != tid:
            return None
        return parse_response(data)
    except (OSError, struct.error, IndexError, ValueError):
        return None


def values(name: str, qtype: str, server: str = "8.8.8.8"):
    """List of record values, [] if none exist, None if DNS is unreachable."""
    r = query(name, qtype, server)
    if r is None:
        return None
    return [x["value"] for x in r[1] if x["type"] == qtype]
