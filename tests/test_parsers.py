import unittest

from sentari.parsers.nmap import parse_nmap_xml

_XML = """<?xml version="1.0"?><nmaprun><host>
<ports>
<port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.24.0"/></port>
<port protocol="tcp" portid="22"><state state="closed"/>
<service name="ssh"/></port>
</ports></host></nmaprun>"""


class TestNmapParser(unittest.TestCase):
    def test_parse(self):
        recs = parse_nmap_xml(_XML)
        self.assertEqual(len(recs), 2)
        https = [r for r in recs if r.port == 443][0]
        self.assertEqual(https.state, "open")
        self.assertIn("nginx", https.label())
        self.assertIn("1.24.0", https.label())

    def test_empty_and_garbage(self):
        self.assertEqual(parse_nmap_xml(""), [])
        self.assertEqual(parse_nmap_xml("not xml"), [])


if __name__ == "__main__":
    unittest.main()
