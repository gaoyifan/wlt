"""AsyncSSH TUI for network outlet selection."""
import asyncio
import logging
import os
import socket
import asyncssh
from main import CONFIG, nft, get_duration_label, get_group_selection

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ssh")
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
RST = "\033[0m"


async def handle_client(process: asyncssh.SSHServerProcess):
    ip = process.get_extra_info("peername")[0]
    try:
        hostname = (await asyncio.to_thread(socket.gethostbyaddr, ip))[0]
    except (socket.herror, OSError):
        hostname = ip
    log.info("Connected: %s (%s)", ip, hostname)

    def w(s=""):
        process.stdout.write(s + "\r\n")

    async def key():
        return (await process.stdin.read(1)) or None

    async def pick(title, items):
        w(f"  {BOLD}{title}{RST}")
        for i, name in enumerate(items, 1):
            w(f"    {i}. {name}")
        w()
        n = len(items)
        process.stdout.write(f"  选择 [1-{n}]: ")
        while True:
            ch = await key()
            if not ch or ch in "qQ\x03":
                return None
            if ch.isdigit() and 1 <= int(ch) <= n:
                w(ch)
                return int(ch) - 1

    try:
        while True:
            process.stdout.write("\033[2J\033[H")
            w(f"  {BOLD}网络通{RST}")
            w()
            entry = await asyncio.to_thread(nft.get_entry, ip)
            w(f"  IP: {ip} ({hostname})")
            if entry:
                labels = [s for g in CONFIG.outlet_groups if (s := get_group_selection(entry.mark, g))]
                outlet = " + ".join(labels) if labels else hex(entry.mark)
                expires = "永久" if entry.expires is None else f"{entry.expires}秒"
                w(f"  当前出口: {CYAN}{outlet}{RST}")
                w(f"  剩余时间: {expires}")
            else:
                w(f"  当前出口: {DIM}默认{RST}")
            w()
            w(f"  {BOLD}[O]{RST} 开通  {BOLD}[R]{RST} 重置  {BOLD}[Q]{RST} 退出")
            w()
            process.stdout.write("  请选择: ")
            ch = await key()
            if not ch or ch in "qQ\x03":
                break
            if ch in "rR":
                await asyncio.to_thread(nft.delete_element, ip)
                w()
                w()
                w(f"  {GREEN}网络已重置{RST}")
                await asyncio.sleep(1)
                continue
            if ch not in "oO":
                continue
            w()
            w()
            selections = []
            for group in CONFIG.outlet_groups:
                names = list(group.outlets.keys())
                idx = await pick(group.title, names)
                if idx is None:
                    break
                selections.append((group, names[idx]))
                w()
            if len(selections) != len(CONFIG.outlet_groups):
                continue
            time_labels = [get_duration_label(h) for h in CONFIG.time_limits]
            idx = await pick("选择时限", time_labels)
            if idx is None:
                continue
            hours = CONFIG.time_limits[idx]
            mark_value = 0
            labels = []
            for group, name in selections:
                mark_value |= group.outlets[name] & group.mask
                labels.append(name)
            await asyncio.to_thread(nft.delete_element, ip)
            ok = await asyncio.to_thread(nft.add_element, ip, hex(mark_value), hours)
            w()
            if ok:
                w(f"  {GREEN}已开通：{' + '.join(labels)}，{get_duration_label(hours)}{RST}")
            else:
                w(f"  {RED}设置失败{RST}")
            await asyncio.sleep(1.5)
    except Exception:
        pass
    process.exit(0)


class NoAuthSSHServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return False


async def main():
    key_path = os.path.join(os.path.dirname(__file__), "ssh_host_key")
    if not os.path.exists(key_path):
        asyncssh.generate_private_key("ssh-rsa").write_private_key(key_path)
        log.info("Generated host key: %s", key_path)
    async with await asyncssh.create_server(
        NoAuthSSHServer, "", 2222,
        server_host_keys=[key_path],
        process_factory=handle_client,
    ):
        log.info("Listening on port 2222")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
