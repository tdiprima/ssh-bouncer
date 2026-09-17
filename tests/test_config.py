import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from config import ConfigError, load_config, resolve_auth_log  # noqa: E402


def write_json(directory, content):
    path = os.path.join(directory, "config.json")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content if isinstance(content, str) else json.dumps(content))
    return path


class LoadConfigTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)

    def test_no_path_returns_validated_defaults(self):
        config = load_config(None)
        self.assertEqual(config["threshold"], 5)
        self.assertEqual(str(config["whitelist"][0]), "127.0.0.1/32")

    def test_file_overrides_defaults(self):
        path = write_json(self.tempdir.name, {"threshold": 3, "auth_log": "/tmp/x.log"})
        config = load_config(path)
        self.assertEqual(config["threshold"], 3)
        self.assertEqual(config["auth_log"], "/tmp/x.log")
        self.assertEqual(config["window_seconds"], 300)

    def test_missing_file_is_an_error(self):
        with self.assertRaises(ConfigError):
            load_config(os.path.join(self.tempdir.name, "nope.json"))

    def test_malformed_json_is_an_error(self):
        path = write_json(self.tempdir.name, "{not json")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_non_object_json_is_an_error(self):
        path = write_json(self.tempdir.name, "[1, 2, 3]")
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_comment_key_is_ignored(self):
        path = write_json(self.tempdir.name, {"_comment": "hello"})
        load_config(path)

    def test_invalid_threshold_values(self):
        for bad in (0, -1, "5", True, None, 10**9 * 0.5):
            path = write_json(self.tempdir.name, {"threshold": bad})
            with self.assertRaises(ConfigError, msg=repr(bad)):
                load_config(path)

    def test_invalid_block_method(self):
        path = write_json(self.tempdir.name, {"block_method": "nftables; rm -rf /"})
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_invalid_whitelist_entries(self):
        for bad in ("not-an-ip", "", 5, "10.0.0.0/99"):
            path = write_json(self.tempdir.name, {"whitelist": [bad]})
            with self.assertRaises(ConfigError, msg=repr(bad)):
                load_config(path)

    def test_whitelist_must_be_list(self):
        path = write_json(self.tempdir.name, {"whitelist": "127.0.0.1"})
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_email_enabled_requires_recipient(self):
        path = write_json(self.tempdir.name, {"email_enabled": True, "email_to": ""})
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_email_enabled_rejects_bad_port(self):
        for bad in (0, 70000, "25"):
            path = write_json(
                self.tempdir.name, {"email_enabled": True, "email_to": "a@b", "smtp_port": bad}
            )
            with self.assertRaises(ConfigError, msg=repr(bad)):
                load_config(path)

    def test_email_from_may_be_blank(self):
        path = write_json(self.tempdir.name, {"email_enabled": True, "email_to": "a@b"})
        config = load_config(path)
        self.assertEqual(config["email_from"], "")

    def test_smtp_password_env_overrides_file(self):
        path = write_json(self.tempdir.name, {"smtp_pass": "from-file"})
        with mock.patch.dict(os.environ, {"SSHBOUNCER_SMTP_PASS": "from-env"}):
            config = load_config(path)
        self.assertEqual(config["smtp_pass"], "from-env")

    def test_smtp_user_without_tls_is_rejected(self):
        path = write_json(self.tempdir.name, {"email_enabled": True, "email_to": "a@b",
                                              "smtp_user": "u", "smtp_tls": False})
        with self.assertRaises(ConfigError) as ctx:
            load_config(path)
        self.assertIn("smtp_tls", str(ctx.exception))

    def test_smtp_user_with_tls_is_accepted(self):
        path = write_json(self.tempdir.name, {"email_enabled": True, "email_to": "a@b",
                                              "smtp_user": "u", "smtp_tls": True})
        self.assertEqual(load_config(path)["smtp_user"], "u")

    def test_systemd_credential_wins_over_env_and_file(self):
        credentials_dir = os.path.join(self.tempdir.name, "creds")
        os.makedirs(credentials_dir)
        with open(os.path.join(credentials_dir, "smtp_pass"), "w", encoding="utf-8") as handle:
            handle.write("from-credential\n")
        path = write_json(self.tempdir.name, {"smtp_pass": "from-file"})
        env = {"CREDENTIALS_DIRECTORY": credentials_dir, "SSHBOUNCER_SMTP_PASS": "from-env"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(load_config(path)["smtp_pass"], "from-credential")

    def test_missing_systemd_credential_falls_back(self):
        empty_dir = os.path.join(self.tempdir.name, "creds")
        os.makedirs(empty_dir)
        path = write_json(self.tempdir.name, {"smtp_pass": "from-file"})
        with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": empty_dir}, clear=False):
            os.environ.pop("SSHBOUNCER_SMTP_PASS", None)
            self.assertEqual(load_config(path)["smtp_pass"], "from-file")

    def test_unreadable_systemd_credential_is_an_error(self):
        credentials_dir = os.path.join(self.tempdir.name, "creds")
        os.makedirs(credentials_dir)
        with open(os.path.join(credentials_dir, "smtp_pass"), "w", encoding="utf-8") as handle:
            handle.write("x")
        path = write_json(self.tempdir.name, {})
        with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": credentials_dir}), \
                mock.patch("config.Path.read_text", side_effect=PermissionError("denied")):
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_log_level_is_normalised(self):
        path = write_json(self.tempdir.name, {"log_level": "debug"})
        self.assertEqual(load_config(path)["log_level"], "DEBUG")

    def test_invalid_log_level(self):
        path = write_json(self.tempdir.name, {"log_level": "LOUD"})
        with self.assertRaises(ConfigError):
            load_config(path)


class ResolveAuthLogTests(unittest.TestCase):
    def test_explicit_path_is_returned_unchanged(self):
        self.assertEqual(resolve_auth_log("/tmp/whatever.log"), "/tmp/whatever.log")

    def test_auto_picks_first_existing_candidate(self):
        with mock.patch("config.os.path.isfile", side_effect=lambda p: p == "/var/log/secure"):
            self.assertEqual(resolve_auth_log("auto"), "/var/log/secure")

    def test_auto_with_no_candidates_is_an_error(self):
        with mock.patch("config.os.path.isfile", return_value=False):
            with self.assertRaises(ConfigError):
                resolve_auth_log("auto")


if __name__ == "__main__":
    unittest.main()
