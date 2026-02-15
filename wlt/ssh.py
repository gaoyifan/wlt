"""AsyncSSH TUI for network outlet selection."""

import asyncio
import logging
import os
import socket

import asyncssh

from .config import load_config
from .nft import NftHandler, get_duration_label, get_group_selection

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

CONFIG = load_config()
nft = NftHandler(CONFIG.nftables)

BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
RED = "\033[31m"
RST = "\033[0m"
KEYS = "1234567890abcdefghijklmnopqrstuvwxyz"


async def handle_client(process: asyncssh.SSHServerProcess):
    ip = process.get_extra_info("peername")[0]
    try:
        hostname = (await asyncio.to_thread(socket.gethostbyaddr, ip))[0]
    except (socket.herror, OSError):
        hostname = ip
    log.info("Connected: %s (%s)", ip, hostname)

    def show(text):
        process.stdout.write(text.replace("\n", "\r\n"))

    async def key():
        return (await process.stdin.read(1)) or None

    def menu(title, items):
        keys = KEYS[: len(items)]
        opts = "\n".join(f"    {k}. {name}" for k, name in zip(keys, items))
        return f"  {BOLD}{title}{RST}\n{opts}\n\n  选择 [{keys}] q=返回: "

    async def pick(title, items):
        show(menu(title, items))
        keys = KEYS[: len(items)]
        while True:
            ch = await key()
            if not ch or ch in "qQ\x03":
                return None
            ch = ch.lower()
            if ch in keys:
                show(ch + "\n\n")
                return keys.index(ch)

    try:
        while True:
            entry = await asyncio.to_thread(nft.get_entry, ip)
            if entry:
                labels = [
                    s
                    for g in CONFIG.outlet_groups
                    if (s := get_group_selection(entry.mark, g))
                ]
                outlet = " + ".join(labels) if labels else hex(entry.mark)
                expires = "永久" if entry.expires is None else f"{entry.expires}秒"
                status = (
                    f"  当前出口: {CYAN}{outlet}{RST}\n  剩余时间: {expires}"
                )
            else:
                status = f"  当前出口: {DIM}默认{RST}"
            show(
                f"\033[2J\033[H\n"
                f"  {BOLD}网络通{RST}\n\n"
                f"  IP: {ip} ({hostname})\n"
                f"{status}\n\n"
                f"  {BOLD}[1]{RST} 开通  {BOLD}[2]{RST} 重置  {BOLD}[q]{RST} 退出\n\n"
                f"  请选择: "
            )

            ch = await key()
            if not ch or ch in "qQ\x03":
                break
            if ch == "2":
                await asyncio.to_thread(nft.delete_element, ip)
                show(f"\n\n  {GREEN}网络已重置{RST}\n")
                await asyncio.sleep(1)
                continue
            if ch != "1":
                continue
            show("\n\n")

            selections = []
            for group in CONFIG.outlet_groups:
                names = list(group.outlets.keys())
                idx = await pick(group.title, names)
                if idx is None:
                    break
                selections.append((group, names[idx]))
            if len(selections) != len(CONFIG.outlet_groups):
                continue

            idx = await pick(
                "选择时限", [get_duration_label(h) for h in CONFIG.time_limits]
            )
            if idx is None:
                continue
            hours = CONFIG.time_limits[idx]

            mark_value = 0
            labels = []
            for group, name in selections:
                mark_value |= group.outlets[name] & group.mask
                labels.append(name)
            await asyncio.to_thread(nft.delete_element, ip)
            ok = await asyncio.to_thread(
                nft.add_element, ip, hex(mark_value), hours
            )
            if ok:
                show(
                    f"  {GREEN}已开通：{' + '.join(labels)}，{get_duration_label(hours)}{RST}\n"
                )
            else:
                show(f"  {RED}设置失败{RST}\n")
            await asyncio.sleep(1.5)
    except Exception:
        pass
    process.exit(0)


class NoAuthSSHServer(asyncssh.SSHServer):
    def begin_auth(self, username):
        return False


async def _async_main():
    key_path = os.environ.get("SSH_HOST_KEY", "ssh_host_key")
    if not os.path.exists(key_path):
        asyncssh.generate_private_key("ssh-rsa").write_private_key(key_path)
        log.info("Generated host key: %s", key_path)
    async with await asyncssh.create_server(
        NoAuthSSHServer,
        "",
        2222,
        server_host_keys=[key_path],
        process_factory=handle_client,
        line_editor=False,
    ):
        log.info("Listening on port 2222")
        await asyncio.Future()


def main():
    asyncio.run(_async_main())
