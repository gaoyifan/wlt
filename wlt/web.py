import ipaddress
import logging
import os

import dns.exception
import dns.resolver
import dns.reversename
from flask import Flask, jsonify, render_template, request

from .config import load_config
from .nft import NftHandler, get_duration_label, get_group_selection

logging.basicConfig(level=logging.INFO)

CONFIG = load_config()
nft = NftHandler(CONFIG.nftables)

# --- gunicorn settings (loaded via `-c python:wlt.web`) ---
# Real concurrency so one slow request can never wedge the whole server: with a
# single default sync worker a blocking call (e.g. a reverse-DNS lookup for a
# client whose PTR zone times out) stalls every other request, including ones
# from other clients. gthread workers handle requests on a thread pool.
_host = CONFIG.flask.host
bind = f"[{_host}]:{CONFIG.flask.port}" if ":" in _host else f"{_host}:{CONFIG.flask.port}"
workers = 2
threads = 8
worker_class = "gthread"

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"))
logger = app.logger


@app.after_request
def _cors(resp):
    # The SPA loads from one split-horizon host and fetches the sibling family's
    # API cross-origin. Allow any *.gaof.net origin (no credentials are used).
    origin = request.headers.get("Origin")
    if origin:
        try:
            host = origin.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
        except IndexError:
            host = ""
        if host == "gaof.net" or host.endswith(".gaof.net"):
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Vary"] = "Origin"
    return resp


def _normalize_ip(raw: str) -> str:
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def get_client_ip() -> str:
    return _normalize_ip(request.remote_addr or "127.0.0.1")


# Reverse-DNS (PTR) lookup with a hard 1s timeout. gthread concurrency means a
# blocking lookup only ties up its own request thread, and the 1s cap keeps the
# requesting client from waiting on a reverse zone that does not answer (musl's
# libc resolver ignores resolv.conf timeouts, so we bound it here via dnspython).
_PTR_TIMEOUT = 1.0
_ptr_resolver = dns.resolver.Resolver()
_ptr_resolver.timeout = _PTR_TIMEOUT
_ptr_resolver.lifetime = _PTR_TIMEOUT


def resolve_hostname(ip: str) -> str | None:
    try:
        answer = _ptr_resolver.resolve(
            dns.reversename.from_address(ip), "PTR", lifetime=_PTR_TIMEOUT
        )
        return str(answer[0]).rstrip(".")
    except (dns.exception.DNSException, ValueError):
        return None


def _family(ip: str) -> int:
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return 4


def _status_payload() -> dict:
    ip = get_client_ip()
    hostname = resolve_hostname(ip)
    family = _family(ip)
    map_name = CONFIG.map_for(family)
    if not map_name:
        return {
            "ip": ip,
            "hostname": hostname,
            "family": family,
            "available": False,
            "groups": [],
            "current_outlet": "默认",
            "expires": None,
            "time_limits": [
                {"label": get_duration_label(t), "value": t} for t in CONFIG.time_limits
            ],
        }

    entry = nft.get_entry(ip, map_name)
    mark_value = entry.mark if entry else None

    groups = []
    current_labels = []
    for idx, group in enumerate(CONFIG.outlet_groups):
        outlets = group.outlets_for(family)
        if not outlets:
            continue
        selection = (
            get_group_selection(mark_value, group.mask, outlets)
            if mark_value is not None
            else None
        )
        if selection:
            current_labels.append(selection)
        groups.append(
            {
                "title": group.title,
                "field": f"group_{idx}",
                "options": list(outlets.keys()),
                "selected": selection or next(iter(outlets.keys())),
            }
        )

    current_outlet = "默认"
    if mark_value is not None:
        current_outlet = " + ".join(current_labels) if current_labels else hex(mark_value)

    return {
        "ip": ip,
        "hostname": hostname,
        "family": family,
        "available": True,
        "groups": groups,
        "current_outlet": current_outlet,
        "expires": entry.expires if entry else None,
        "time_limits": [
            {"label": get_duration_label(t), "value": t} for t in CONFIG.time_limits
        ],
    }


@app.route("/", methods=["GET"])
def index():
    portal = CONFIG.portal
    return render_template(
        "index.html.j2",
        v4_host=portal.v4_host,
        v6_host=portal.v6_host,
    )


@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify(_status_payload())


@app.route("/api/open", methods=["POST"])
def api_open():
    ip = get_client_ip()
    family = _family(ip)
    map_name = CONFIG.map_for(family)
    if not map_name:
        return jsonify({"ok": False, "message": "当前协议族暂不支持出口选择", "family": family}), 400

    mark_value = 0
    selected_labels = []
    for idx, group in enumerate(CONFIG.outlet_groups):
        outlets = group.outlets_for(family)
        if not outlets:
            continue
        outlet = request.form.get(f"group_{idx}")
        if not outlet or outlet not in outlets:
            return jsonify({"ok": False, "message": f"无效的出口选择：{group.title}", "family": family}), 400
        selected_labels.append(outlet)
        mark_value |= outlets[outlet] & group.mask

    try:
        hours = int(request.form.get("hours", ""))
        if hours not in CONFIG.time_limits:
            raise ValueError
    except ValueError:
        return jsonify({"ok": False, "message": "无效的时限选择", "family": family}), 400

    nft.delete_element(ip, map_name)
    if nft.add_element(ip, hex(mark_value), hours, map_name):
        duration = f"{hours}小时" if hours else "永久"
        message = f"IPv{family} 已开通：「{' + '.join(selected_labels)}」，{duration}"
        return jsonify({"ok": True, "message": message, "family": family})
    return jsonify({"ok": False, "message": "设置网络出口失败", "family": family}), 500


@app.route("/api/close", methods=["POST"])
def api_close():
    ip = get_client_ip()
    family = _family(ip)
    map_name = CONFIG.map_for(family)
    if map_name and nft.delete_element(ip, map_name):
        return jsonify({"ok": True, "message": f"IPv{family} 已重置", "family": family})
    return jsonify({"ok": False, "message": "重置网络失败", "family": family}), 500


def main():
    app.run(host=CONFIG.flask.host, port=CONFIG.flask.port, debug=CONFIG.flask.debug)
