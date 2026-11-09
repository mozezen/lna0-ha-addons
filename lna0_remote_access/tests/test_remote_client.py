import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location("remote_client", Path(__file__).resolve().parents[1] / "remote_client.py")
module = importlib.util.module_from_spec(spec)
import sys
sys.modules["remote_client"] = module
spec.loader.exec_module(module)

BASE = {
    "gateway_host": "remote.55projects.com",
    "gateway_port": 443,
    "public_hostname": "a"*32 + ".remote.55projects.com",
    "homeassistant_port": 80,
    "certificate_file": "fullchain.pem",
    "private_key_file": "privkey.pem",
}

class TestClientSettings(unittest.TestCase):
    def test_valid(self):
        s = module.settings_from_dict(BASE)
        self.assertIn("proxy_pass http://homeassistant.local.hass.io:80", module.nginx_text(s))
        self.assertIn("ssl_reject_handshake on", module.nginx_text(s))
    def test_reject_sequential_house_name(self):
        x = dict(BASE, public_hostname="h000002.remote.55projects.com")
        with self.assertRaises(module.InvalidConfig):
            module.settings_from_dict(x)
    def test_reject_cert_path_traversal(self):
        x = dict(BASE, private_key_file="../../secret")
        with self.assertRaises(module.InvalidConfig):
            module.settings_from_dict(x)
    def test_reject_invalid_port(self):
        with self.assertRaises(module.InvalidConfig):
            module.settings_from_dict(dict(BASE, gateway_port=True))
    def test_credentials_privacy_and_binding(self):
        x = {
            "hostname": BASE["public_hostname"],
            "fernet_token": "A" * 100,
            "aes_key": os.urandom(32).hex(),
            "aes_iv": os.urandom(16).hex(),
            "expires_at": time.time() + 300,
            "cipher": "aes-gcm-siv",
            "protocol_version": 2,
        }
        cred = module.credentials_from_dict(x, BASE["public_hostname"])
        self.assertNotIn("AAAA", repr(cred))
        with self.assertRaises(module.InvalidConfig):
            module.credentials_from_dict(x, "b"*32 + ".remote.55projects.com")
    def test_credentials_file_public_permissions_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "credentials.json"
            p.write_text("{}")
            p.chmod(0o644)
            with self.assertRaises(module.InvalidConfig):
                module.read_credentials(p, BASE["public_hostname"])
    def test_expired_creds_rejected(self):
        x = {
            "hostname": BASE["public_hostname"], "fernet_token": "A"*100,
            "aes_key": "a"*64, "aes_iv": "a"*32,
            "expires_at": time.time()-1, "cipher": "aes-gcm-siv", "protocol_version": 2,
        }
        with self.assertRaises(module.InvalidConfig):
            module.credentials_from_dict(x, BASE["public_hostname"])

if __name__ == "__main__":
    unittest.main()
