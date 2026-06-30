# coding=utf-8

import unittest

from whois.whois import NICClient


class TestNICClient(unittest.TestCase):
    def setUp(self):
        self.client = NICClient()

    def test_choose_server(self):
        domain = "рнидс.срб"
        chosen = self.client.choose_server(domain)
        correct = "whois.rnids.rs"
        self.assertEqual(chosen, correct)

    def test_choose_server_extra_second_level_domains(self):
        def fail_iana(*args, **kwargs):
            raise AssertionError("IANA lookup should not be used")

        self.client.findwhois_iana = fail_iana

        cases = {
            "example.uk.com": "whois.centralnic.com",
            "example.net.ru": "whois.nic.net.ru",
            "example.co.ua": "whois.co.ua",
        }
        for domain, expected in cases.items():
            with self.subTest(domain=domain):
                self.assertEqual(self.client.choose_server(domain), expected)

    def test_choose_server_missing_top_level_domains(self):
        def fail_iana(*args, **kwargs):
            raise AssertionError("IANA lookup should not be used")

        self.client.findwhois_iana = fail_iana

        cases = {
            "example.abc": "whois.nic.abc",
            "example.au": "whois.auda.org.au",
            "example.bid": "whois.nic.bid",
            "example.ruhr": "whois.nic.ruhr",
            "example.xn--90a3ac": "whois.rnids.rs",
        }
        for domain, expected in cases.items():
            with self.subTest(domain=domain):
                self.assertEqual(self.client.choose_server(domain), expected)
