import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wlt.config import NftablesConfig
from wlt.persist import (
    PersistedEntry,
    parse_map_entries,
    render_snapshot,
    run,
    save_snapshot,
    write_if_changed,
)


class PersistTests(unittest.TestCase):
    def setUp(self):
        self.config = NftablesConfig()

    def test_parses_and_sorts_permanent_and_timed_entries(self):
        data = {
            "nftables": [
                {"metainfo": {}},
                {
                    "map": {
                        "elem": [
                            [
                                {
                                    "elem": {
                                        "val": "192.0.2.20",
                                        "timeout": 3600,
                                        "expires": 125,
                                    }
                                },
                                "0x1220",
                            ],
                            ["192.0.2.3", 32],
                        ]
                    }
                },
            ]
        }

        self.assertEqual(
            parse_map_entries(data),
            [
                PersistedEntry(ip="192.0.2.3", mark=0x20),
                PersistedEntry(
                    ip="192.0.2.20",
                    mark=0x1220,
                    timeout=3600,
                    expires=125,
                ),
            ],
        )

    def test_renders_reloadable_snapshot(self):
        content = render_snapshot(
            self.config,
            [
                PersistedEntry(ip="192.0.2.3", mark=0x20),
                PersistedEntry(
                    ip="192.0.2.20",
                    mark=0x1220,
                    timeout=3600,
                    expires=125,
                ),
            ],
        )

        self.assertIn(
            "add element inet wlt src2mark {",
            content,
        )
        self.assertIn("192.0.2.3 : 0x20,", content)
        self.assertIn(
            "192.0.2.20 timeout 3600s expires 125s : 0x1220",
            content,
        )

    def test_empty_snapshot_contains_only_comments(self):
        content = render_snapshot(self.config, [])

        self.assertNotIn("add element", content)
        self.assertTrue(content.endswith("\n"))

    def test_missing_map_is_not_treated_as_an_empty_map(self):
        with self.assertRaisesRegex(ValueError, "does not contain a map"):
            parse_map_entries({"nftables": [{"metainfo": {}}]})

    def test_unchanged_content_does_not_replace_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.conf"
            path.write_text("same\n", encoding="utf-8")
            before = path.stat()

            changed = write_if_changed(path, "same\n")
            after = path.stat()

            self.assertFalse(changed)
            self.assertEqual(before.st_ino, after.st_ino)
            self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)

    def test_changed_content_is_atomically_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.conf"
            path.write_text("old\n", encoding="utf-8")
            before_inode = path.stat().st_ino

            changed = write_if_changed(path, "new\n")

            self.assertTrue(changed)
            self.assertEqual(path.read_text(encoding="utf-8"), "new\n")
            self.assertNotEqual(path.stat().st_ino, before_inode)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_fetch_failure_preserves_existing_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snapshot.conf"
            path.write_text("last good\n", encoding="utf-8")
            with patch(
                "wlt.persist.fetch_map",
                side_effect=json.JSONDecodeError("bad", "", 0),
            ):
                with self.assertRaises(json.JSONDecodeError):
                    save_snapshot(self.config, path)

            self.assertEqual(path.read_text(encoding="utf-8"), "last good\n")

    @patch("wlt.persist.signal.signal")
    @patch("wlt.persist._save_safely")
    @patch("wlt.persist.threading.Event")
    def test_shutdown_triggers_final_save(
        self, event_factory, save_safely, signal_handler
    ):
        stop_event = event_factory.return_value
        stop_event.wait.return_value = True

        run(self.config, Path("/tmp/snapshot"), interval=300)

        self.assertEqual(save_safely.call_count, 2)
        stop_event.wait.assert_called_once_with(300)
        self.assertEqual(signal_handler.call_count, 2)


if __name__ == "__main__":
    unittest.main()
