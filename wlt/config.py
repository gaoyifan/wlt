import logging
import os
import tomllib
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

from pydantic import BaseModel, Field, ValidationError, field_validator

logger = logging.getLogger(__name__)


class FlaskConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 80
    debug: bool = True


class NftablesConfig(BaseModel):
    family: str = "inet"
    table: str = "wlt"
    map: str = "src2mark"          # IPv4 src -> mark map
    map_v6: str | None = None      # IPv6 src -> mark map (enables v6 selection)


class PortalConfig(BaseModel):
    # Split-horizon hostnames used by the dual-stack composer page: each one
    # must resolve to a single address family so the browser reveals (and the
    # backend registers) the client's address for that family.
    v4_host: str | None = None
    v6_host: str | None = None


class OutletGroup(BaseModel):
    title: str
    mask: int
    outlets: Dict[str, int]
    # Parallel IPv6 outlet set. The same group title/mask serves both families;
    # an IPv6 client is offered (and writes) outlets_v6, an IPv4 client outlets.
    outlets_v6: Dict[str, int] = Field(default_factory=dict)

    @field_validator("outlets")
    @classmethod
    def validate_outlets(cls, v: Dict[str, int]) -> Dict[str, int]:
        if not v:
            raise ValueError("outlet_groups.outlets cannot be empty")
        return v

    def outlets_for(self, family: int) -> Dict[str, int]:
        return self.outlets_v6 if family == 6 else self.outlets


class AppConfig(BaseModel):
    flask: FlaskConfig = Field(default_factory=FlaskConfig)
    nftables: NftablesConfig = Field(default_factory=NftablesConfig)
    portal: PortalConfig = Field(default_factory=PortalConfig)
    outlet_groups: List[OutletGroup]
    time_limits: List[int]

    def map_for(self, family: int) -> str | None:
        return self.nftables.map_v6 if family == 6 else self.nftables.map

    @field_validator("outlet_groups")
    @classmethod
    def validate_outlet_groups(cls, v: List[OutletGroup]) -> List[OutletGroup]:
        if not v:
            raise ValueError("outlet_groups cannot be empty")
        titles = [group.title for group in v]
        if len(titles) != len(set(titles)):
            raise ValueError("outlet_groups titles must be unique")
        return v

    @field_validator("time_limits")
    @classmethod
    def validate_time_limits(cls, v: List[int]) -> List[int]:
        if not v:
            raise ValueError("time_limits cannot be empty")
        return v


def _load_toml(path: Path) -> Dict[str, Any]:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError) as e:
        logger.error("Config file error in %s: %s", path, e)
        raise RuntimeError(f"Failed to load config file {path}: {e}") from e


def _merge_outlet_groups(base: List[Any], override: List[Any]) -> List[Any]:
    merged = deepcopy(base)
    indexes = {
        group["title"]: index
        for index, group in enumerate(merged)
        if isinstance(group, dict) and isinstance(group.get("title"), str)
    }

    for group in override:
        title = group.get("title") if isinstance(group, dict) else None
        if isinstance(title, str) and title in indexes:
            index = indexes[title]
            merged[index] = _deep_merge(merged[index], group)
        else:
            merged.append(deepcopy(group))
            if isinstance(title, str):
                indexes[title] = len(merged) - 1

    return merged


def _deep_merge(base: Any, override: Any, key: str | None = None) -> Any:
    if key == "outlet_groups" and isinstance(base, list) and isinstance(override, list):
        return _merge_outlet_groups(base, override)

    if isinstance(base, dict) and isinstance(override, dict):
        merged = deepcopy(base)
        for child_key, value in override.items():
            if child_key in merged:
                merged[child_key] = _deep_merge(merged[child_key], value, child_key)
            else:
                merged[child_key] = deepcopy(value)
        return merged

    return deepcopy(override)


def load_config(path: str = "config.toml") -> AppConfig:
    full_path = Path(path)
    if not full_path.is_absolute():
        full_path = Path(os.path.dirname(os.path.dirname(__file__))) / full_path

    if not full_path.is_file():
        raise RuntimeError(f"Failed to load config: {full_path} not found.")

    data: Dict[str, Any] = _load_toml(full_path)
    config_dir = full_path.parent / "config.d"
    if config_dir.exists() and not config_dir.is_dir():
        raise RuntimeError(f"Failed to load config: {config_dir} is not a directory.")

    if config_dir.is_dir():
        config_files = sorted(
            (
                candidate
                for candidate in config_dir.iterdir()
                if candidate.is_file() and candidate.suffix == ".toml"
            ),
            key=lambda candidate: candidate.name,
        )
        for config_file in config_files:
            data = _deep_merge(data, _load_toml(config_file))

    try:
        return AppConfig.model_validate(data or {})
    except ValidationError as e:
        logger.error("Config error: %s", e)
        raise RuntimeError(f"Failed to validate merged config: {e}") from e
