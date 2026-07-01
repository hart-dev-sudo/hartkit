import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.dns_proto import encode_qname, decode_name, build_query, parse_response, QTYPES


def _build_synthetic_response(qid, qname, answers, flags=0x8180):
    """answers: list of (qtype_num, ttl, rdata_bytes)"""
    header = struct.pack("!HHHHHH", qid, flags, 1, len(answers), 0, 0)
    question = encode_qname(qname) + struct.pack("!HH", 1, 1)
    body = b""
    for qtype_num, ttl, rdata in answers:
        body += encode_qname(qname)
        body += struct.pack("!HHIH", qtype_num, 1, ttl, len(rdata))
        body += rdata
    return header + question + body


class TestEncodeDecodeName(unittest.TestCase):
    def test_encode_qname_simple(self):
        self.assertEqual(encode_qname("example.com"), b"\x07example\x03com\x00")

    def test_encode_qname_trailing_dot(self):
        self.assertEqual(encode_qname("example.com."), encode_qname("example.com"))

    def test_decode_name_simple(self):
        data = b"\x07example\x03com\x00"
        name, offset = decode_name(data, 0)
        self.assertEqual(name, "example.com")
        self.assertEqual(offset, len(data))

    def test_decode_name_with_compression_pointer(self):
        first_name = b"\x07example\x03com\x00"
        data = first_name + b"\xc0\x00"
        name, offset = decode_name(data, len(first_name))
        self.assertEqual(name, "example.com")
        self.assertEqual(offset, len(first_name) + 2)

    def test_decode_name_compression_loop_raises(self):
        data = b"\xc0\x00"  # pointer at offset 0 pointing to itself
        with self.assertRaises(ValueError):
            decode_name(data, 0)


class TestBuildQuery(unittest.TestCase):
    def test_build_query_structure(self):
        qid, packet = build_query("example.com", "A")
        qid_field, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
        self.assertEqual(qid_field, qid)
        self.assertEqual(flags, 0x0100)
        self.assertEqual(qdcount, 1)
        self.assertEqual((ancount, nscount, arcount), (0, 0, 0))
        question = packet[12:]
        self.assertTrue(question.endswith(struct.pack("!HH", QTYPES["A"], 1)))


class TestParseResponseRecordTypes(unittest.TestCase):
    def test_a_record(self):
        qid = 1234
        rdata = bytes([93, 184, 216, 34])
        data = _build_synthetic_response(qid, "example.com", [(QTYPES["A"], 300, rdata)])
        rcode, records = parse_response(data, qid)
        self.assertEqual(rcode, 0)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["type"], "A")
        self.assertEqual(records[0]["data"], "93.184.216.34")
        self.assertEqual(records[0]["ttl"], 300)

    def test_aaaa_record(self):
        qid = 5
        rdata = bytes.fromhex("26064700001000000000000068141234")  # 16 bytes
        data = _build_synthetic_response(qid, "example.com", [(QTYPES["AAAA"], 60, rdata)])
        rcode, records = parse_response(data, qid)
        self.assertEqual(records[0]["type"], "AAAA")
        self.assertIn(":", records[0]["data"])

    def test_txt_record(self):
        qid = 9
        chunk = b"v=spf1 -all"
        rdata = bytes([len(chunk)]) + chunk
        data = _build_synthetic_response(qid, "example.com", [(QTYPES["TXT"], 100, rdata)])
        rcode, records = parse_response(data, qid)
        self.assertEqual(records[0]["type"], "TXT")
        self.assertEqual(records[0]["data"], "v=spf1 -all")

    def test_mx_record(self):
        qid = 11
        exchange = encode_qname("mail.example.com")
        rdata = struct.pack("!H", 10) + exchange
        data = _build_synthetic_response(qid, "example.com", [(QTYPES["MX"], 200, rdata)])
        rcode, records = parse_response(data, qid)
        self.assertEqual(records[0]["type"], "MX")
        self.assertEqual(records[0]["data"], "10 mail.example.com")

    def test_ns_record(self):
        qid = 13
        rdata = encode_qname("ns1.example.com")
        data = _build_synthetic_response(qid, "example.com", [(QTYPES["NS"], 400, rdata)])
        rcode, records = parse_response(data, qid)
        self.assertEqual(records[0]["type"], "NS")
        self.assertEqual(records[0]["data"], "ns1.example.com")

    def test_soa_record(self):
        qid = 17
        rdata = encode_qname("ns1.example.com") + encode_qname("admin.example.com") + struct.pack("!IIIII", 1, 2, 3, 4, 5)
        data = _build_synthetic_response(qid, "example.com", [(QTYPES["SOA"], 500, rdata)])
        rcode, records = parse_response(data, qid)
        self.assertEqual(records[0]["type"], "SOA")
        self.assertIn("serial=1", records[0]["data"])


class TestParseResponseErrors(unittest.TestCase):
    def test_id_mismatch_raises_valueerror(self):
        data = _build_synthetic_response(1234, "example.com", [])
        with self.assertRaises(ValueError):
            parse_response(data, 9999)

    def test_truncated_header_raises_valueerror_not_struct_error(self):
        # Regression test: this used to raise struct.error, uncaught by
        # dns_enum.py's callers, crashing the tool on a malformed response.
        with self.assertRaises(ValueError):
            parse_response(b"\x00\x01\x02", 1)

    def test_truncated_answer_raises_valueerror(self):
        qid = 42
        header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)  # ancount=1, no answer bytes
        question = encode_qname("example.com") + struct.pack("!HH", 1, 1)
        data = header + question
        with self.assertRaises(ValueError):
            parse_response(data, qid)

    def test_truncated_question_raises_valueerror(self):
        qid = 7
        header = struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 0, 0)  # qdcount=1, no question bytes
        with self.assertRaises(ValueError):
            parse_response(header, qid)


if __name__ == "__main__":
    unittest.main()
