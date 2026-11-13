import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("port-forwarder.py")
SPEC = importlib.util.spec_from_file_location("port_forwarder", MODULE_PATH)
port_forwarder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(port_forwarder)


class ConfigTests(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(text)
            return port_forwarder.load_config(path)

    def test_single_port_is_backward_compatible(self):
        mappings = self.load(
            """mappings:
  - source_port: 41000
    destination_ip: 192.0.2.10
    destination_port: 42000
    protocol: udp
"""
        )
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0]["listen_port"], 41000)
        self.assertEqual(mappings[0]["target_port"], 42000)

    def test_range_expands_port_for_port(self):
        mappings = self.load(
            """mappings:
  - name: wireguard
    source_port: "60020-60022"
    destination_ip: 192.0.2.10
    destination_port: "61020-61022"
    protocol: udp
"""
        )
        self.assertEqual(
            [(item["listen_port"], item["target_port"]) for item in mappings],
            [(60020, 61020), (60021, 61021), (60022, 61022)],
        )
        self.assertEqual(mappings[0]["name"], "wireguard_60020")

    def test_colon_range_is_supported(self):
        mappings = self.load(
            """mappings:
  - source_port: "60020:60021"
    destination_ip: 192.0.2.10
    destination_port: "60020:60021"
    protocol: udp
"""
        )
        self.assertEqual(len(mappings), 2)

    def test_range_lengths_must_match(self):
        with self.assertRaisesRegex(port_forwarder.ConfigError, "same number of ports"):
            self.load(
                """mappings:
  - source_port: "60020-60022"
    destination_ip: 192.0.2.10
    destination_port: "60020-60021"
    protocol: udp
"""
            )

    def test_reversed_range_is_rejected(self):
        with self.assertRaisesRegex(port_forwarder.ConfigError, "start must not exceed"):
            self.load(
                """mappings:
  - source_port: "60022-60020"
    destination_ip: 192.0.2.10
    destination_port: "60022-60020"
    protocol: udp
"""
            )


if __name__ == "__main__":
    unittest.main()
