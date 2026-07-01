import random
import socket
import ssl
import struct
import http.client
import urllib.parse

DOH_DEFAULT_URL = "https://cloudflare-dns.com/dns-query"

try:
    import certifi
    _DOH_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _DOH_SSL_CONTEXT = ssl.create_default_context()

QTYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}


def encode_qname(domain):
    out = b""
    for label in domain.strip(".").split("."):
        label = label.encode("ascii")
        out += struct.pack("!B", len(label)) + label
    return out + b"\x00"


def decode_name(data, offset):
    labels = []
    jumped = False
    end_offset = offset
    seen = set()

    while True:
        if offset in seen:
            raise ValueError("DNS name compression loop detected")
        seen.add(offset)

        length = data[offset]
        if length == 0:
            if not jumped:
                end_offset = offset + 1
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), end_offset


def build_query(domain, qtype):
    qid = random.randint(0, 0xFFFF)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)
    question = encode_qname(domain) + struct.pack("!HH", QTYPES[qtype], 1)
    return qid, header + question


def _parse_rdata(qtype_num, data, rdata_offset, rdlength):
    if qtype_num == QTYPES["A"]:
        return socket.inet_ntoa(data[rdata_offset:rdata_offset + 4])
    if qtype_num == QTYPES["AAAA"]:
        return socket.inet_ntop(socket.AF_INET6, data[rdata_offset:rdata_offset + 16])
    if qtype_num in (QTYPES["NS"], QTYPES["CNAME"]):
        name, _ = decode_name(data, rdata_offset)
        return name
    if qtype_num == QTYPES["MX"]:
        preference = struct.unpack("!H", data[rdata_offset:rdata_offset + 2])[0]
        exchange, _ = decode_name(data, rdata_offset + 2)
        return f"{preference} {exchange}"
    if qtype_num == QTYPES["TXT"]:
        chunks = []
        pos = rdata_offset
        end = rdata_offset + rdlength
        while pos < end:
            length = data[pos]
            pos += 1
            chunks.append(data[pos:pos + length].decode("utf-8", errors="replace"))
            pos += length
        return "".join(chunks)
    if qtype_num == QTYPES["SOA"]:
        mname, pos = decode_name(data, rdata_offset)
        rname, pos = decode_name(data, pos)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[pos:pos + 20])
        return f"{mname} {rname} (serial={serial} refresh={refresh} retry={retry} expire={expire} minimum={minimum})"
    return data[rdata_offset:rdata_offset + rdlength].hex()


def parse_response(data, qid):
    try:
        return _parse_response(data, qid)
    except (struct.error, IndexError) as e:
        raise ValueError(f"Malformed DNS response: {e}") from e


def _parse_response(data, qid):
    resp_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    if resp_id != qid:
        raise ValueError("DNS response ID mismatch (possible spoofing or stale response)")

    rcode = flags & 0x000F
    offset = 12

    for _ in range(qdcount):
        _, offset = decode_name(data, offset)
        offset += 4  # qtype + qclass

    records = []
    for _ in range(ancount):
        name, offset = decode_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = _parse_rdata(rtype, data, offset, rdlength)
        offset += rdlength
        records.append({
            "name": name,
            "type": QTYPE_NAMES.get(rtype, str(rtype)),
            "ttl": ttl,
            "data": rdata,
        })

    return rcode, records


def query(domain, qtype, server="8.8.8.8", port=53, timeout=2.0):
    qid, packet = build_query(domain, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    rcode, records = parse_response(data, qid)
    return rcode, records


def doh_query(domain, qtype, doh_url=DOH_DEFAULT_URL, timeout=5.0):
    qid, packet = build_query(domain, qtype)
    parsed = urllib.parse.urlparse(doh_url)

    conn = http.client.HTTPSConnection(parsed.netloc, timeout=timeout, context=_DOH_SSL_CONTEXT)
    try:
        conn.request(
            "POST",
            parsed.path or "/dns-query",
            body=packet,
            headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            },
        )
        resp = conn.getresponse()
        data = resp.read()
    finally:
        conn.close()

    rcode, records = parse_response(data, qid)
    return rcode, records
