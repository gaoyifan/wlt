"""Persist the nftables src2mark map to a reloadable include file."""

import ipaddress
import json
import logging
import os
import signal
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import NftablesConfig, load_config

logger = logging.getLogger(__name__)

SNAPSHOT_PATH = Path("/etc/nftables/wlt_src2mark.conf")
SAVE_INTERVAL_SECONDS = 300


@dataclass(frozen=True)
class PersistedEntry:
    ip: str
    mark: int
    timeout: int | None = None
    expires: int | None = None


def parse_map_entries(data: dict[str, Any]) -> list[PersistedEntry]:
    map_data = next(
        (
            item["map"]
            for item in data.get("nftables", [])
            if isinstance(item, dict) and isinstance(item.get("map"), dict)
        ),
        None,
    )
    if map_data is None:
        raise ValueError("nftables JSON does not contain a map")

    entries: list[PersistedEntry] = []

    for item in map_data.get("elem", []):
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(f"Unexpected nftables map element: {item!r}")

        key, raw_mark = item
        timeout = None
        expires = None
        if isinstance(key, dict) and isinstance(key.get("elem"), dict):
            element = key["elem"]
            raw_ip = element.get("val")
            timeout = _optional_seconds(element.get("timeout"))
            expires = _optional_seconds(element.get("expires"))
        else:
            raw_ip = key

        ip = str(ipaddress.ip_address(str(raw_ip)))
        mark = raw_mark if isinstance(raw_mark, int) else int(str(raw_mark), 0)
        if mark < 0 or mark > 0xFFFFFFFF:
            raise ValueError(f"Invalid mark for {ip}: {mark}")

        entries.append(
            PersistedEntry(
                ip=ip,
                mark=mark,
                timeout=timeout,
                expires=expires,
            )
        )

    return sorted(entries, key=lambda entry: ipaddress.ip_address(entry.ip))


def _optional_seconds(value: Any) -> int | None:
    if value is None:
        return None
    seconds = int(value)
    return max(seconds, 1)


def render_snapshot(
    config: NftablesConfig, sections: list[tuple[str, list[PersistedEntry]]]
) -> str:
    lines = [
        "# Managed by wlt-persist. Manual changes will be overwritten.",
        "# Timeout counters resume from the saved remaining time after reload.",
    ]
    for map_name, entries in sections:
        if not entries:
            continue
        lines.append(f"add element {config.family} {config.table} {map_name} {{")
        for index, entry in enumerate(entries):
            options = []
            if entry.timeout is not None:
                options.append(f"timeout {entry.timeout}s")
            if entry.expires is not None:
                options.append(f"expires {entry.expires}s")
            option_text = f" {' '.join(options)}" if options else ""
            comma = "," if index < len(entries) - 1 else ""
            lines.append(f"    {entry.ip}{option_text} : {hex(entry.mark)}{comma}")
        lines.append("}")
    return "\n".join(lines) + "\n"


def map_names(config: NftablesConfig) -> list[str]:
    names = [config.map]
    if config.map_v6 and config.map_v6 not in names:
        names.append(config.map_v6)
    return names


def fetch_map(config: NftablesConfig, map_name: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            "nft",
            "--json",
            "list",
            "map",
            config.family,
            config.table,
            map_name,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def write_if_changed(path: Path, content: str) -> bool:
    encoded = content.encode()
    try:
        if path.read_bytes() == encoded:
            return False
    except FileNotFoundError:
        pass

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temp_path.unlink(missing_ok=True)
    return True


def save_snapshot(config: NftablesConfig, path: Path = SNAPSHOT_PATH) -> bool:
    sections: list[tuple[str, list[PersistedEntry]]] = []
    total = 0
    for map_name in map_names(config):
        entries = parse_map_entries(fetch_map(config, map_name))
        sections.append((map_name, entries))
        total += len(entries)
    changed = write_if_changed(path, render_snapshot(config, sections))
    if changed:
        logger.info("Saved %d src2mark entries to %s", total, path)
    else:
        logger.debug("src2mark snapshot is unchanged")
    return changed


def _save_safely(config: NftablesConfig, path: Path) -> None:
    try:
        save_snapshot(config, path)
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        ValueError,
    ) as e:
        logger.error("Failed to save src2mark snapshot: %s", e)


def run(
    config: NftablesConfig,
    path: Path = SNAPSHOT_PATH,
    interval: int = SAVE_INTERVAL_SECONDS,
) -> None:
    stop_event = threading.Event()

    def request_stop(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    _save_safely(config, path)
    while not stop_event.wait(interval):
        _save_safely(config, path)
    _save_safely(config, path)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    run(load_config().nftables)


if __name__ == "__main__":
    main()
