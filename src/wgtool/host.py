"""Host utilities for network interface and forwarding."""

import os
import re
import shutil
import subprocess
from pathlib import Path


def default_interface() -> str:
    """Return the default network interface name."""
    try:
        command = 'ip route list default | grep -Eo " dev ([0-9a-z]+)"'
        return subprocess.check_output(command, shell=True, encoding="utf-8").strip().split()[1]
    except Exception:
        return "eth0"


def enable_forwarding(ipv4: bool, ipv6: bool) -> None:
    if os.name != "posix":
        return

    if Path("/etc/sysctl.conf").exists():
        _enable_forwarding_sysctl_conf(ipv4, ipv6)
        return

    if Path("/etc/sysctl.d").exists():
        _enable_forwarding_sysctl_d(ipv4, ipv6)
        return

    raise FileNotFoundError("No sysctl configuration file found")


def _enable_forwarding_sysctl_conf(ipv4: bool, ipv6: bool) -> None:
    file = "/etc/sysctl.conf"
    try:
        with open(file) as f:
            content = f.read()
            new_content = content

        # IPv4
        if ipv4:
            if re.search(r"net.ipv4.ip_forward\s*=\s*1$", new_content, re.MULTILINE):
                new_content = re.sub(
                    r"#\s*net.ipv4.ip_forward\s*=\s*1",
                    "net.ipv4.ip_forward=1",
                    new_content,
                    flags=re.MULTILINE,
                )
            else:
                new_content = new_content.strip("\n") + "\nnet.ipv4.ip_forward=1\n"

        # IPv6
        if ipv6:
            if re.search(r"net.ipv6.conf.all.forwarding\s*=\s*1", new_content, re.MULTILINE):
                new_content = re.sub(
                    r"#\s*net.ipv6.conf.all.forwarding\s*=\s*1",
                    "net.ipv6.conf.all.forwarding=1",
                    new_content,
                    flags=re.MULTILINE,
                )
            else:
                new_content = new_content.strip("\n") + "\nnet.ipv6.conf.all.forwarding=1\n"
        if content == new_content:
            return

        print(f'Updating "{file}"')
        file_backup = f"{file}.wgtool"
        if not os.path.exists(file_backup):
            shutil.copy(file, file_backup)
        with open(file, "w") as f:
            f.write(new_content)
        print("Applying changes to sysctl:")
        result = subprocess.check_output("sudo sysctl -p", shell=True, encoding="utf-8").strip()  # noqa: S607
        print(result)

    except FileNotFoundError:
        print(f'Cannot open "{file}"')


def _enable_forwarding_sysctl_d(ipv4: bool, ipv6: bool) -> None:
    with open("/etc/sysctl.d/99-ip-forwarding.conf", "w") as f:
        if ipv6:
            f.write("net.ipv6.conf.all.forwarding=1\n")
        if ipv4:
            f.write("net.ipv4.ip_forward=1\n")


def restart_systemctl_service() -> bool:
    print("Restarting service...")
    if os.name != "posix":
        return False
    commands = [
        "sudo systemctl enable wg-quick@wg0.service",
        "sudo systemctl daemon-reload",
        "sudo systemctl restart wg-quick@wg0",
    ]
    for command in commands:
        result = subprocess.run(command, shell=True, encoding="utf-8")
        if result.returncode != 0:
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(result.stderr)
            return False
    return True
