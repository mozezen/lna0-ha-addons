import io
import json
import logging
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest

from stdin_credentials import COMMAND, consume_stream, validate_command
from remote_client import credentials_from_dict

HOST = "a" * 32 + ".remote.55projects.com"

def credentials(host=HOST):
    return {"hostname": host, "fernet_token": "A" * 100,
            "aes_key": os.urandom(32).hex(), "aes_iv": os.urandom(16).hex(),
            "expires_at": time.time() + 300,
            "protocol_version": 2, "cipher": "aes-gcm-siv"}

class CredentialStdinTests(unittest.TestCase):
    def command(self, value):
        return (json.dumps(value) + "\n").encode()

    def test_write_private_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            data = credentials()
            raw = self.command({"type": COMMAND, "credentials": data})
            consume_stream(io.BytesIO(raw), path, HOST, credentials_from_dict,
                           logging.getLogger("test"))
            self.assertEqual(json.loads(path.read_text()), data)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_wrong_house_and_expired_not_saved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            bad = [credentials("b" * 32 + ".remote.55projects.com"),
                   dict(credentials(), expires_at=time.time() - 1)]
            for record in bad:
                raw = self.command({"type": COMMAND, "credentials": record})
                consume_stream(io.BytesIO(raw), path, HOST, credentials_from_dict,
                               logging.getLogger("test"))
                self.assertFalse(path.exists())

    def test_malformed_command_does_not_replace_valid_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            good = self.command({"type": COMMAND, "credentials": credentials()})
            junk = b"{" + b"x" * 17000 + b"\n"
            consume_stream(io.BytesIO(good + junk), path, HOST,
                           credentials_from_dict, logging.getLogger("test"))
            self.assertEqual(json.loads(path.read_text())["hostname"], HOST)

    def test_reject_unexpected_type(self):
        with self.assertRaises(ValueError):
            validate_command(self.command({"type": "other", "credentials": credentials()}),
                             HOST, credentials_from_dict)
