from flask import Flask, request, render_template_string, redirect, url_for, flash
import os
import json
import subprocess

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_for_testing')  # 添加密钥配置

# 出口配置
OUTLETS = {
    "1 国内出口": "0x1",
    "2 国际出口": "0x2",
}

TIME_LIMITS = [("1小时", 1), ("4小时", 4), ("11小时", 11), ("14小时", 14), ("永久", None)]

def get_client_ip() -> str:
    """取客户端IP地址"""
    return request.remote_addr

def get_nft_map_entry(ip):
    """获取指定IP在nftables中的记录"""
    try:
        result = subprocess.run(
            ["nft", "--json", "list", "map", "inet", "wlt", "src2mark"],
            capture_output=True, text=True, check=True
        )
        data = json.loads(result.stdout)
        
        # 解析nft输出查找指定IP
        if "nftables" in data and len(data["nftables"]) > 1:
            map_data = data["nftables"][1].get("map", {})
            if "elem" in map_data:
                for elem in map_data["elem"]:
                    if elem[0]["elem"]["val"] == ip:
                        mark_value = elem[1]
                        # 查找对应的出口名称
                        outlet = next((k for k, v in OUTLETS.items() if v == hex(mark_value)), "未知")
                        return {
                            "outlet": outlet,
                            "expires": elem[0]["elem"].get("expires"),
                            "mark": mark_value
                        }
        return None
    except (subprocess.SubprocessError, json.JSONDecodeError, KeyError, IndexError) as e:
        app.logger.error(f"获取nftables记录失败: {e}")
        return None

@app.route("/", methods=["GET"])
def index():
    ip = get_client_ip()
    record = get_nft_map_entry(ip)
    
    current_outlet = record.get("outlet", "已重置") if record else "已重置"
    return render_template_string(TEMPLATE, ip=ip, current_outlet=current_outlet,
                                  outlets=OUTLETS.keys(), time_limits=TIME_LIMITS)

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
            ["nft", "delete", "element", "inet", "wlt", "src2mark", "{", ip, "}"],
            capture_output=True, check=False
        )
    except subprocess.SubprocessError as e:
        app.logger.warning(f"删除旧规则失败或规则不存在: {e}")
    
    # 添加新规则
    try:
        if hours != "None" and hours is not None:
            # 有时限的规则
            try:
                hours_int = int(hours)
                cmd = ["nft", "add", "element", "inet", "wlt", "src2mark", 
                       "{", f"{ip}", "timeout", f"{hours_int}h", ":", mark, "}"]
                subprocess.run(cmd, capture_output=True, check=True)
                flash(f"网络已开通：出口「{outlet}」，时限「{hours}小时」")
            except (ValueError, TypeError):
                flash("时限格式无效")
                return redirect(url_for("index"))
        else:
            # 永久规则
            cmd = ["nft", "add", "element", "inet", "wlt", "src2mark", 
                   "{", f"{ip}", ":", mark, "}"]
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
            ["nft", "delete", "element", "inet", "wlt", "src2mark", "{", ip, "}"],
            capture_output=True, check=True
        )
        flash("网络已重置")
    except subprocess.SubprocessError as e:
        app.logger.error(f"删除nftables规则失败: {e}")
        flash(f"重置网络失败: {str(e)}")
    
    return redirect(url_for("index"))

# ------------------------
# HTML 模板
# ------------------------
TEMPLATE = """
<!doctype html>
<title>网络通</title>
<style>
body {font-family: sans-serif; margin:40px;}
h2   {margin-bottom:5px;}
label{display:block;margin-top:8px;}
button{margin-top:12px;padding:6px 16px;font-size:1em;}
.flash{color:green;margin-bottom:12px;}
</style>

<h2>当前信息</h2>
<p><strong>IP：</strong>{{ ip }}</p>
<p><strong>当前出口：</strong>{{ current_outlet }}</p>

{% with messages = get_flashed_messages() %}
  {% if messages %}
    <div class="flash">{{ messages[0] }}</div>
  {% endif %}
{% endwith %}

<form method="post" action="{{ url_for('open_net') }}">
  <h2>选择出口</h2>
  {% for o in outlets %}
      <label><input type="radio" name="outlet" value="{{ o }}" {% if loop.first %}checked{% endif %}> {{ o }}</label>
  {% endfor %}

  <h2>选择时限</h2>
  {% for label, hour in time_limits %}
      <label>
        <input type="radio" name="hours" value="{{ hour }}" {% if loop.first %}checked{% endif %}> {{ label }}
      </label>
  {% endfor %}

  <button type="submit">开通网络</button>
</form>

<form method="post" action="{{ url_for('close_net') }}">
  <button type="submit" style="background:#c33;color:#fff;">重置网络</button>
</form>
"""

def main():
    host = os.environ.get('WLT_HOST', '0.0.0.0')
    port = int(os.environ.get('WLT_PORT', 80))
    app.run(debug=True, host=host, port=port)

if __name__ == "__main__":
    main()
