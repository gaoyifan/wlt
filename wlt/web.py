import logging
import os
import socket

from flask import Flask, flash, redirect, render_template, request, url_for

from .config import load_config
from .nft import NftHandler, get_duration_label, get_group_selection

logging.basicConfig(level=logging.INFO)

CONFIG = load_config()
nft = NftHandler(CONFIG.nftables)

# Gunicorn can load this module as a config source via `-c python:wlt.web`.
bind = f"{CONFIG.flask.host}:{CONFIG.flask.port}"

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"))
app.secret_key = os.urandom(24)
logger = app.logger


def get_client_info() -> tuple[str, str]:
    ip = request.remote_addr or "127.0.0.1"
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, OSError):
        hostname = ip
    return ip, hostname


@app.route("/", methods=["GET"])
def index():
    ip, hostname = get_client_info()
    entry = nft.get_entry(ip)
    mark_value = entry.mark if entry else None

    outlet_groups = []
    current_labels = []
    for idx, group in enumerate(CONFIG.outlet_groups):
        selection = (
            get_group_selection(mark_value, group) if mark_value is not None else None
        )
        if selection:
            current_labels.append(selection)
        outlet_groups.append(
            {
                "title": group.title,
                "field": f"group_{idx}",
                "options": list(group.outlets.keys()),
                "selected": selection or next(iter(group.outlets.keys())),
            }
        )

    current_outlet = "默认"
    if mark_value is not None:
        current_outlet = (
            " + ".join(current_labels) if current_labels else hex(mark_value)
        )

    return render_template(
        "index.html.j2",
        ip=ip,
        hostname=hostname,
        current_outlet=current_outlet,
        expires_seconds=entry.expires if entry else None,
        outlet_groups=outlet_groups,
        time_limits=[(get_duration_label(t), t) for t in CONFIG.time_limits],
    )


@app.route("/open", methods=["POST"])
def open_net():
    ip, _ = get_client_info()
    hours_str = request.form.get("hours")

    mark_value = 0
    selected_labels = []
    for idx, group in enumerate(CONFIG.outlet_groups):
        field_name = f"group_{idx}"
        outlet = request.form.get(field_name)
        if not outlet or outlet not in group.outlets:
            flash(f"无效的出口选择：{group.title}")
            return redirect(url_for("index"))
        selected_labels.append(outlet)
        mark_value |= group.outlets[outlet] & group.mask

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

    if nft.add_element(ip, hex(mark_value), hours):
        duration = f"{hours}小时" if hours else "永久"
        outlet_label = " + ".join(selected_labels)
        flash(f"网络已开通：出口「{outlet_label}」，时限「{duration}」")
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
