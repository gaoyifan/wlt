import json
import logging
import os
import socket
import subprocess
import tomllib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from flask import Flask, flash, redirect, render_template, request, url_for
from pydantic import BaseModel, Field, ValidationError, field_validator

# --- Configuration Models ---


class FlaskConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 80
    debug: bool = True


class NftablesConfig(BaseModel):
    family: str = "inet"
    table: str = "wlt"
    map: str = "src2mark"


class AppConfig(BaseModel):
    flask: FlaskConfig = Field(default_factory=FlaskConfig)
    nftables: NftablesConfig = Field(default_factory=NftablesConfig)
    outlets: Dict[str, str]
    time_limits: List[int]

    @field_validator("outlets")
    @classmethod
    def validate_outlets(cls, v: Dict[str, str]) -> Dict[str, str]:
        if not v:
            raise ValueError("outlets cannot be empty")
        return v

    @field_validator("time_limits")
    @classmethod
    def validate_time_limits(cls, v: List[int]) -> List[int]:
        if not v:
            raise ValueError("time_limits cannot be empty")
        return v


# --- Globals & Setup ---

app = Flask(__name__)
app.secret_key = os.urandom(24)
logging.basicConfig(level=logging.INFO)
logger = app.logger


def load_config(path: str = "config.toml") -> AppConfig:
    full_path = os.path.join(os.path.dirname(__file__), path)
    if not os.path.exists(full_path):
        raise RuntimeError("Failed to load config: config.toml not found.")
    try:
        with open(full_path, "rb") as f:
            data = tomllib.load(f)
        return AppConfig.model_validate(data or {})
    except (tomllib.TOMLDecodeError, ValidationError, OSError) as e:
        logger.error(f"Config error: {e}")
        raise RuntimeError(f"Failed to load config: {e}")


CONFIG = load_config()

# Gunicorn can load this module as a config source via `-c python:main`.
bind = f"{CONFIG.flask.host}:{CONFIG.flask.port}"

# --- Helpers ---


def get_duration_label(hours: int) -> str:
    return "永久" if hours == 0 else f"{hours}小时"


@dataclass
class NftEntry:
    outlet: str
    mark: str
    expires: Optional[int] = None


class NftHandler:
    def __init__(self, config: NftablesConfig, outlets: Dict[str, str]):
        self.cfg = config
        self.outlets = outlets
        self.rev_outlets = {v: k for k, v in outlets.items()}

    def _run(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["nft"] + args
        logger.debug(f"Running: {' '.join(cmd)}")
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def _json_cmd(self, args: List[str]) -> Any:
        res = self._run(["--json"] + args)
        return json.loads(res.stdout)

    def get_entry(self, ip: str) -> Optional[NftEntry]:
        try:
            data = self._json_cmd(["list", "map", self.cfg.family, self.cfg.table, self.cfg.map])

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
                    outlet_name = self.rev_outlets.get(hex(mark_val) if isinstance(mark_val, int) else mark_val, "未知")
                    return NftEntry(outlet=outlet_name, mark=str(mark_val), expires=expires)

        except (subprocess.SubprocessError, json.JSONDecodeError, KeyError, IndexError) as e:
            logger.error(f"Failed to fetch nftables entry for {ip}: {e}")
        return None

    def delete_element(self, ip: str) -> bool:
        try:
            # Check if element exists first
            entry = self.get_entry(ip)
            if entry is None:
                # Element doesn't exist, return success directly
                return True

            # Element exists, proceed with deletion
            res = self._run(["delete", "element", self.cfg.family, self.cfg.table, self.cfg.map, "{", ip, "}"], check=False)
            if res.returncode == 0:
                return True

            logger.error(f"Error deleting rule for {ip}: {res.stderr}")
            return False
        except subprocess.SubprocessError as e:
            logger.error(f"Error deleting rule for {ip}: {e}")
            return False

    def add_element(self, ip: str, mark: str, hours: Optional[int]) -> bool:
        try:
            # Construct element string
            if hours:
                elem_spec = [f"{ip}", "timeout", f"{hours}h", ":", mark]
            else:
                elem_spec = [f"{ip}", ":", mark]

            cmd = ["add", "element", self.cfg.family, self.cfg.table, self.cfg.map, "{"] + elem_spec + ["}"]
            self._run(cmd)
            return True
        except subprocess.SubprocessError as e:
            logger.error(f"Error adding rule for {ip}: {e}")
            return False


nft = NftHandler(CONFIG.nftables, CONFIG.outlets)


def get_client_info() -> tuple[str, str]:
    ip = request.remote_addr or "127.0.0.1"
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, OSError):
        hostname = ip
    return ip, hostname


# --- Routes ---


@app.route("/", methods=["GET"])
def index():
    ip, hostname = get_client_info()
    entry = nft.get_entry(ip)

    return render_template(
        "index.html.j2",
        ip=ip,
        hostname=hostname,
        current_outlet=entry.outlet if entry else "默认",
        expires_seconds=entry.expires if entry else None,
        outlets=CONFIG.outlets.keys(),
        time_limits=[(get_duration_label(t), t) for t in CONFIG.time_limits],
    )


@app.route("/open", methods=["POST"])
def open_net():
    ip, _ = get_client_info()
    outlet = request.form.get("outlet")
    hours_str = request.form.get("hours")

    if not outlet or outlet not in CONFIG.outlets:
        flash("无效的出口选择")
        return redirect(url_for("index"))

    mark = CONFIG.outlets[outlet]

    try:
        # Validate hours input
        if hours_str is None:
            raise ValueError("Missing hours")
        hours = int(hours_str)
        if hours not in CONFIG.time_limits:
            raise ValueError("Invalid hours value")
    except ValueError:
        flash("无效的时限选择")
        return redirect(url_for("index"))

    # Clean up old rule first
    nft.delete_element(ip)

    if nft.add_element(ip, mark, hours):
        duration = f"{hours}小时" if hours else "永久"
        flash(f"网络已开通：出口「{outlet}」，时限「{duration}」")
    else:
        flash("设置网络出口失败")

    return redirect(url_for("index"))


@app.route("/close", methods=["POST"])
def close_net():
    ip, _ = get_client_info()
    if nft.delete_element(ip):
        flash("网络已重置")
    else:
        flash("重置网络失败")
    return redirect(url_for("index"))


def main():
    app.run(host=CONFIG.flask.host, port=CONFIG.flask.port, debug=CONFIG.flask.debug)


if __name__ == "__main__":
    main()
