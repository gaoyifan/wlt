import json
import logging
import subprocess
from dataclasses import dataclass
from typing import Any, List, Optional

from .config import NftablesConfig, OutletGroup

logger = logging.getLogger(__name__)


def get_duration_label(hours: int) -> str:
    return "永久" if hours == 0 else f"{hours}小时"


def get_group_selection(mark_value: int, group: OutletGroup) -> Optional[str]:
    masked_value = mark_value & group.mask
    for name, value in group.outlets.items():
        if (value & group.mask) == masked_value:
            return name
    return None


@dataclass
class NftEntry:
    mark: int
    expires: Optional[int] = None


class NftHandler:
    def __init__(self, config: NftablesConfig):
        self.cfg = config

    def _run(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["nft"] + args
        logger.debug("Running: %s", " ".join(cmd))
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def _json_cmd(self, args: List[str]) -> Any:
        res = self._run(["--json"] + args)
        return json.loads(res.stdout)

    def get_entry(self, ip: str) -> Optional[NftEntry]:
        try:
            data = self._json_cmd(
                ["list", "map", self.cfg.family, self.cfg.table, self.cfg.map]
            )

            # Navigate JSON structure: {"nftables": [..., {"map": {"elem": [...]}}]}
            nftables = data.get("nftables", [])
            if len(nftables) <= 1:
                return None

            map_data = nftables[1].get("map", {})
            elements = map_data.get("elem", [])

            for item in elements:
                # Item format:
                # Case 1 (Timeout): [{"elem": {"val": "IP", "timeout": ..., "expires": ...}}, "MARK"]
                # Case 2 (Permanent): ["IP", "MARK"]

                elem_key = item[0]
                mark_val = item[1]
                expires = None
                matched_ip = None

                if isinstance(elem_key, dict) and "elem" in elem_key:
                    matched_ip = elem_key["elem"].get("val")
                    expires = elem_key["elem"].get("expires")
                else:
                    matched_ip = elem_key

                if matched_ip == ip:
                    mark = (
                        mark_val
                        if isinstance(mark_val, int)
                        else int(str(mark_val), 0)
                    )
                    return NftEntry(mark=mark, expires=expires)

        except (
            subprocess.SubprocessError,
            json.JSONDecodeError,
            KeyError,
            IndexError,
        ) as e:
            logger.error("Failed to fetch nftables entry for %s: %s", ip, e)
        return None

    def delete_element(self, ip: str) -> bool:
        try:
            # Check if element exists first
            entry = self.get_entry(ip)
            if entry is None:
                # Element doesn't exist, return success directly
                return True

            # Element exists, proceed with deletion
            res = self._run(
                [
                    "delete",
                    "element",
                    self.cfg.family,
                    self.cfg.table,
                    self.cfg.map,
                    "{",
                    ip,
                    "}",
                ],
                check=False,
            )
            if res.returncode == 0:
                return True

            logger.error("Error deleting rule for %s: %s", ip, res.stderr)
            return False
        except subprocess.SubprocessError as e:
            logger.error("Error deleting rule for %s: %s", ip, e)
            return False

    def add_element(self, ip: str, mark: str, hours: Optional[int]) -> bool:
        try:
            # Construct element string
            if hours:
                elem_spec = [f"{ip}", "timeout", f"{hours}h", ":", mark]
            else:
                elem_spec = [f"{ip}", ":", mark]

            cmd = (
                [
                    "add",
                    "element",
                    self.cfg.family,
                    self.cfg.table,
                    self.cfg.map,
                    "{",
                ]
                + elem_spec
                + ["}"]
            )
            self._run(cmd)
            return True
        except subprocess.SubprocessError as e:
            logger.error("Error adding rule for %s: %s", ip, e)
            return False
