import json
import os
import socket
import subprocess
from typing import Dict, List, Tuple

import yaml
from flask import Flask, flash, redirect, render_template, request, url_for
from pydantic import BaseModel, Field, ValidationError, field_validator

app = Flask(__name__)

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")


class FlaskConfig(BaseModel):
    secret_key: str = "dev_key_for_testing"
    host: str = "0.0.0.0"
    port: int = 80
    debug: bool = True


class NftablesConfig(BaseModel):
    family: str = "inet"
    table: str = "wlt"
    map: str = "src2mark"


class TimeLimit(BaseModel):
    label: str
    hours: int | None = None


class AppConfig(BaseModel):
    flask: FlaskConfig = Field(default_factory=FlaskConfig)
    nftables: NftablesConfig = Field(default_factory=NftablesConfig)
    outlets: Dict[str, str]
    time_limits: List[TimeLimit]

    @field_validator("outlets")
    @classmethod
    def validate_outlets(cls, value: Dict[str, str]) -> Dict[str, str]:
        if not value:
            raise ValueError("outlets 至少需要一个条目")
        return value

    @field_validator("time_limits")
    @classmethod
    def validate_time_limits(cls, value: List[TimeLimit]) -> List[TimeLimit]:
        if not value:
            raise ValueError("time_limits 不能为空")
        return value


def load_config(path: str = CONFIG_PATH) -> AppConfig:
    """Load YAML config and validate via Pydantic."""
    try:
        with open(path, "r", encoding="utf-8") as config_file:
            loaded = yaml.safe_load(config_file) or {}
    except FileNotFoundError as err:
        raise RuntimeError(f"找不到配置文件: {path}") from err
    except yaml.YAMLError as err:
        raise RuntimeError(f"解析配置文件失败: {err}") from err

    try:
        return AppConfig.model_validate(loaded)
    except ValidationError as err:
        raise RuntimeError(f"配置文件字段验证失败: {err}") from err


CONFIG = load_config()

app.secret_key = CONFIG.flask.secret_key

OUTLETS = CONFIG.outlets
TIME_LIMITS: List[Tuple[str, int | None]] = [
    (limit.label, limit.hours) for limit in CONFIG.time_limits
]

def get_client_ip() -> str:
    """取客户端IP地址"""
    return request.remote_addr

def get_hostname_from_ip(ip: str) -> str:
    """通过PTR记录获取IP对应的主机名"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError) as e:
        app.logger.debug(f"无法获取IP {ip} 的主机名: {e}")
        return ip  # 如果无法获取主机名，返回IP地址

def get_nft_map_entry(ip):
    """获取指定IP在nftables中的记录"""
    try:
        result = subprocess.run(
            [
                "nft",
                "--json",
                "list",
                "map",
                CONFIG.nftables.family,
                CONFIG.nftables.table,
                CONFIG.nftables.map,
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)
        
        # 解析nft输出查找指定IP
        if "nftables" in data and len(data["nftables"]) > 1:
            map_data = data["nftables"][1].get("map", {})
            if "elem" in map_data:
                for elem in map_data["elem"]:
                    ip_match = False
                    expires = None
                    
                    # 提取IP和过期时间
                    if isinstance(elem[0], dict) and "elem" in elem[0]:
                        # 有超时信息的格式
                        if elem[0]["elem"]["val"] == ip:
                            ip_match = True
                            expires = elem[0]["elem"].get("expires")
                    elif elem[0] == ip:
                        # 无超时信息的格式
                        ip_match = True
                    
                    if ip_match:
                        mark_value = elem[1]
                        outlet = next((k for k, v in OUTLETS.items() if v == hex(mark_value)), "未知")
                        return {
                            "outlet": outlet,
                            "expires": expires,
                            "mark": mark_value
                        }
        return None
    except (subprocess.SubprocessError, json.JSONDecodeError, KeyError, IndexError) as e:
        app.logger.error(f"获取nftables记录失败: {e}")
        return None

@app.route("/", methods=["GET"])
def index():
    ip = get_client_ip()
    hostname = get_hostname_from_ip(ip)
    record = get_nft_map_entry(ip)
    
    current_outlet = record.get("outlet", "默认") if record else "默认"
    expires_seconds = record.get("expires") if record else None
    
    return render_template("index.html.j2", ip=ip, hostname=hostname, current_outlet=current_outlet,
                          expires_seconds=expires_seconds, outlets=OUTLETS.keys(), time_limits=TIME_LIMITS)

@app.route("/open", methods=["POST"])
def open_net():
    ip = get_client_ip()
    outlet = request.form.get("outlet")
    hours = request.form.get("hours")
    if not outlet or hours is None:
        flash("请选择出口与时限")
        return redirect(url_for("index"))
        
    # 验证 outlet 是否在允许的列表中
    if outlet not in OUTLETS:
        flash("无效的出口选择")
        return redirect(url_for("index"))

    # 获取对应的标记值
    mark = OUTLETS.get(outlet)
    if not mark:
        flash("出口配置错误")
        return redirect(url_for("index"))
    
    # 先删除可能存在的旧规则
    try:
        subprocess.run(
            [
                "nft",
                "delete",
                "element",
                CONFIG.nftables.family,
                CONFIG.nftables.table,
                CONFIG.nftables.map,
                "{",
                ip,
                "}",
            ],
            capture_output=True,
            check=False,
        )
    except subprocess.SubprocessError as e:
        app.logger.warning(f"删除旧规则失败或规则不存在: {e}")
    
    # 添加新规则
    try:
        if hours != "None" and hours is not None:
            # 有时限的规则
            try:
                hours_int = int(hours)
                cmd = [
                    "nft",
                    "add",
                    "element",
                    CONFIG.nftables.family,
                    CONFIG.nftables.table,
                    CONFIG.nftables.map,
                    "{",
                    f"{ip}",
                    "timeout",
                    f"{hours_int}h",
                    ":",
                    mark,
                    "}",
                ]
                subprocess.run(cmd, capture_output=True, check=True)
                flash(f"网络已开通：出口「{outlet}」，时限「{hours}小时」")
            except (ValueError, TypeError):
                flash("时限格式无效")
                return redirect(url_for("index"))
        else:
            # 永久规则
            cmd = [
                "nft",
                "add",
                "element",
                CONFIG.nftables.family,
                CONFIG.nftables.table,
                CONFIG.nftables.map,
                "{",
                f"{ip}",
                ":",
                mark,
                "}",
            ]
            subprocess.run(cmd, capture_output=True, check=True)
            flash(f"网络已开通：出口「{outlet}」，时限「永久」")
    except subprocess.SubprocessError as e:
        app.logger.error(f"添加nftables规则失败: {e}")
        flash(f"设置网络出口失败: {str(e)}")
    
    return redirect(url_for("index"))

@app.route("/close", methods=["POST"])
def close_net():
    ip = get_client_ip()
    try:
        subprocess.run(
            [
                "nft",
                "delete",
                "element",
                CONFIG.nftables.family,
                CONFIG.nftables.table,
                CONFIG.nftables.map,
                "{",
                ip,
                "}",
            ],
            capture_output=True,
            check=True,
        )
        flash("网络已重置")
    except subprocess.SubprocessError as e:
        app.logger.error(f"删除nftables规则失败: {e}")
        flash(f"重置网络失败: {str(e)}")
    
    return redirect(url_for("index"))

def main():
    app.run(
        debug=CONFIG.flask.debug,
        host=CONFIG.flask.host,
        port=CONFIG.flask.port,
    )

if __name__ == "__main__":
    main()
