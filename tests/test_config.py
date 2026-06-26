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

    def test_cn_last_moves_cn_outlets_to_the_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            main = Path(tmp) / "config.toml"
            self.write(
                main,
                """
                time_limits = [1]

                [[outlet_groups]]
                title = "海外出口"
                mask = 0xFF
                cn_last = true
                [outlet_groups.outlets]
                "默认" = 0x0
                "CN 合肥 | 中国电信" = 0x12
                "JP 东京 | Cloudflare WARP" = 0x66
                "CN 杭州 | 阿里云" = 0x40
                "US 圣何塞 | Cloudflare WARP" = 0x67
                """,
            )

            config = load_config(str(main))
            group = config.outlet_groups[0]

            self.assertEqual(
                list(group.display_outlets_for(4).keys()),
                [
                    "默认",
                    "JP 东京 | Cloudflare WARP",
                    "US 圣何塞 | Cloudflare WARP",
                    "CN 合肥 | 中国电信",
                    "CN 杭州 | 阿里云",
                ],
            )
            # Underlying outlets and mark lookups are untouched.
            self.assertEqual(group.outlets["CN 合肥 | 中国电信"], 0x12)
            self.assertEqual(
                list(group.outlets.keys())[1], "CN 合肥 | 中国电信"
            )

    def test_cn_last_defaults_off_and_preserves_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            main = Path(tmp) / "config.toml"
            self.write(main, BASE_CONFIG)

            config = load_config(str(main))
            overseas = config.outlet_groups[1]

            self.assertFalse(overseas.cn_last)
            self.assertEqual(
                list(overseas.display_outlets_for(4).keys()),
                list(overseas.outlets.keys()),
            )

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
