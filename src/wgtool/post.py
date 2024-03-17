from ipaddress import ip_interface
from wgtool.models import WGServerConfig
import subprocess
import os

POST_UP_LINE_NUMBER = "{iptables} -L INPUT --line-number | head -3 | wc -l"
POST_UP = (  # iptables, ifname, network
    "{iptables} -I FORWARD 1 -i %i -o {ifname} -j ACCEPT; "
    "{iptables} -I FORWARD 1 -i {ifname} -o %i -j ACCEPT; "
    "{iptables} -t nat -I POSTROUTING 1 -s {network} -o {ifname} -j MASQUERADE; "
    "{iptables} -I INPUT {ln_minus_1} -i %i -j ACCEPT > /dev/null; "
    "{iptables} -I INPUT {ln} -p udp -m udp --dport {port} -j ACCEPT > /dev/null;"
)
POST_DN = (
    "{iptables} -D FORWARD   -i %i -o {ifname} -j ACCEPT; "
    "{iptables} -D FORWARD   -i {ifname} -o %i -j ACCEPT; "
    "{iptables} -t nat -D POSTROUTING   -s {network} -o {ifname} -j MASQUERADE; "
    "{iptables} -D INPUT   -i %i -j ACCEPT > /dev/null; "
    "{iptables} -D INPUT   -p udp -m udp --dport {port} -j ACCEPT > /dev/null;"
)


def get_post_up(config: WGServerConfig, ifname: str) -> str:
    if os.name == "posix":
        command = []
        if config.ipv4:
            line_number = subprocess.check_output(
                POST_UP_LINE_NUMBER.format(iptables="iptables"), shell=True
            )
            command.append(
                POST_UP.format(
                    iptables="iptables",
                    ifname=ifname,
                    network=ip_interface(config.ipv4).network.with_prefixlen,
                    port=config.server.port,
                    ln=int(line_number),
                    ln_minus_1=int(line_number) - 1,
                )
            )
        if config.ipv6:
            line_number = subprocess.check_output(
                POST_UP_LINE_NUMBER.format(iptables="ip6tables"), shell=True
            )
            command.append(
                POST_UP.format(
                    iptables="ip6tables",
                    ifname=ifname,
                    network=ip_interface(config.ipv6).network.with_prefixlen,
                    port=config.server.port,
                    ln=int(line_number),
                    ln_minus_1=int(line_number) - 1,
                )
            )
        if command:
            return "; ".join(command)
    return ""


def get_post_down(config: WGServerConfig, ifname: str) -> str:
    if os.name == "posix":
        command = []
        if config.ipv4:
            command.append(
                POST_DN.format(
                    iptables="iptables",
                    ifname=ifname,
                    network=ip_interface(config.ipv4).network.with_prefixlen,
                    port=config.server.port,
                )
            )
        if config.ipv6:
            command.append(
                POST_DN.format(
                    iptables="ip6tables",
                    ifname=ifname,
                    network=ip_interface(config.ipv6).network.with_prefixlen,
                    port=config.server.port,
                )
            )
        if command:
            return "; ".join(command)
    return ""
