import tempfile
import textwrap
import unittest
from pathlib import Path

from wlt.config import load_config

BASE_CONFIG = """
time_limits = [1, 4, 8]

[flask]
port = 80

[[outlet_groups]]
title = "国内出口"
mask = 0xFF00
[outlet_groups.outlets]
"默认" = 0x0
"中国电信" = 0x1200

[[outlet_groups]]
title = "海外出口"
mask = 0xFF
[outlet_groups.outlets]
"默认" = 0x0
"""


class ConfigMergeTests(unittest.TestCase):
    def write(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(content), encoding="utf-8")

    def test_loads_main_config_without_config_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            main = Path(tmp) / "config.toml"
            self.write(main, BASE_CONFIG)

            config = load_config(str(main))

            self.assertEqual(config.flask.port, 80)
            self.assertEqual(config.outlet_groups[0].outlets["中国电信"], 0x1200)

    def test_merges_toml_files_in_filename_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            main = root / "config.toml"
            self.write(main, BASE_CONFIG)
            self.write(
                root / "config.d" / "10-extra.toml",
                """
                [flask]
                port = 8080

                [[outlet_groups]]
                title = "国内出口"
                [outlet_groups.outlets]
                "测试出口1" = 0xff00

                [[outlet_groups]]
                title = "新增分组"
                mask = 0xF0000
                [outlet_groups.outlets]
                "新增出口" = 0x10000
                """,
            )
            self.write(
                root / "config.d" / "20-override.toml",
                """
                time_limits = [10, 24]

                [[outlet_groups]]
                title = "国内出口"
                [outlet_groups.outlets]
                "测试出口1" = 0xfe00
                "测试出口2" = 0xfd00
                """,
            )

            config = load_config(str(main))

            self.assertEqual(config.flask.port, 8080)
            self.assertEqual(config.time_limits, [10, 24])
            self.assertEqual(
                [group.title for group in config.outlet_groups],
                ["国内出口", "海外出口", "新增分组"],
            )
            domestic = config.outlet_groups[0]
            self.assertEqual(domestic.mask, 0xFF00)
            self.assertEqual(domestic.outlets["中国电信"], 0x1200)
            self.assertEqual(domestic.outlets["测试出口1"], 0xFE00)
            self.assertEqual(domestic.outlets["测试出口2"], 0xFD00)

    def test_ignores_non_toml_files_and_subdirectories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            main = root / "config.toml"
            self.write(main, BASE_CONFIG)
            self.write(root / "config.d" / "README.md", "not toml")
            self.write(
                root / "config.d" / "nested" / "ignored.toml",
                "this is not valid toml",
            )

            config = load_config(str(main))

            self.assertEqual(config.flask.port, 80)

    def test_reports_the_invalid_fragment_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            main = root / "config.toml"
            fragment = root / "config.d" / "10-invalid.toml"
            self.write(main, BASE_CONFIG)
            self.write(fragment, "invalid = [")

            with self.assertRaisesRegex(RuntimeError, "10-invalid.toml"):
                load_config(str(main))


if __name__ == "__main__":
    unittest.main()
