import logging
import os
import tomllib
from typing import Dict, List

from pydantic import BaseModel, Field, ValidationError, field_validator

logger = logging.getLogger(__name__)


class FlaskConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 80
    debug: bool = True


class NftablesConfig(BaseModel):
    family: str = "inet"
    table: str = "wlt"
    map: str = "src2mark"


class OutletGroup(BaseModel):
    title: str
    mask: int
    outlets: Dict[str, int]

    @field_validator("outlets")
    @classmethod
    def validate_outlets(cls, v: Dict[str, int]) -> Dict[str, int]:
        if not v:
            raise ValueError("outlet_groups.outlets cannot be empty")
        return v


class AppConfig(BaseModel):
    flask: FlaskConfig = Field(default_factory=FlaskConfig)
    nftables: NftablesConfig = Field(default_factory=NftablesConfig)
    outlet_groups: List[OutletGroup]
    time_limits: List[int]

    @field_validator("outlet_groups")
    @classmethod
    def validate_outlet_groups(cls, v: List[OutletGroup]) -> List[OutletGroup]:
        if not v:
            raise ValueError("outlet_groups cannot be empty")
        return v

    @field_validator("time_limits")
    @classmethod
    def validate_time_limits(cls, v: List[int]) -> List[int]:
        if not v:
            raise ValueError("time_limits cannot be empty")
        return v


def load_config(path: str = "config.toml") -> AppConfig:
    full_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), path)
    if not os.path.exists(full_path):
        raise RuntimeError("Failed to load config: config.toml not found.")
    try:
        with open(full_path, "rb") as f:
            data = tomllib.load(f)
        return AppConfig.model_validate(data or {})
    except (tomllib.TOMLDecodeError, ValidationError, OSError) as e:
        logger.error("Config error: %s", e)
        raise RuntimeError(f"Failed to load config: {e}")
