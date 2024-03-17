#!/usr/bin/env python3
"""
WireGuard Configuration Tool (wgtool)
by rpcsp (pcunha at hotmail.com) - 10/2021
https://github.com/rpcsp/wgtool
"""
from __future__ import annotations
import sys
import os
import logging
import pprint
from ipaddress import ip_interface
from typing import List, Literal, Optional, Union
from wgtool.exceptions import WGToolError
from wgtool import post, wgcli
from wgtool.exporter import WGPeerConfigExporter, WGServerConfigExporter
from wgtool import host
from wgtool.importer import WGServerConfigImporter
from wgtool.models import DEFAULT_FILE, WGPeerConfig, WGServerConfig


MIN_PYTHON = (3, 8)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)


DEFAULT_DNS_LIST_IPV4 = ["8.8.8.8", "1.1.1.1"]
DEFAULT_DNS_LIST_IPV6 = ["2001:4860:4860::8888", "2606:4700:4700::1111"]


logger = logging.getLogger()
pp = pprint.PrettyPrinter(indent=4, width=100)


class WGTool:
    def __init__(self, file: str = DEFAULT_FILE, ifname: str = "") -> None:
        self.file = file or DEFAULT_FILE
        self.ifname = ifname or host.default_interface()
        self.config = WGServerConfig()

    def set_config(self, ipv4: str = "", ipv6: str = "", **params: str) -> None:
        if ipv4 or ipv6:
            params["Address"] = f"{ipv4}, {ipv6}".strip(", ")
        WGServerConfigImporter(self.config).read_interface(params)
        self._generate_server_credentials()
        self._generate_post_commands()

    def load_config(self) -> None:
        self.config = WGServerConfigImporter().from_file(self.file)
        self._generate_server_credentials()
        self._generate_post_commands()

    def save_config(self) -> None:
        WGServerConfigExporter(self.config).to_file(self.file)

    def server_config_file_present(self) -> bool:
        return os.path.isfile(self.file)

    def _generate_server_credentials(self) -> None:
        self.config.server.private_key = (
            self.config.server.private_key or wgcli.generate_preshared_key()
        )
        self.config.server.public_key = self.config.server.public_key or wgcli.generate_public_key(
            self.config.server.private_key
        )

    def _generate_post_commands(self) -> None:
        if not self.config.post_down:
            self.config.post_down = post.get_post_down(self.config, self.ifname)
        if not self.config.post_up:
            self.config.post_up = post.get_post_up(self.config, self.ifname)

    def enable_forwarding(self) -> None:
        host.enable_forwarding(ipv4=bool(self.config.ipv4), ipv6=bool(self.config.ipv6))

    def restart_systemctl_service(self) -> None:
        host.restart_systemctl_service()

    @property
    def peers(self) -> List[WGPeerConfig]:
        return self.config.peers

    def get_peer(self, name_or_index: Union[str, int]) -> Optional[WGPeerConfig]:
        for index, peer in enumerate(self.peers):
            if name_or_index in [peer.name, str(index)]:
                return peer
        return None

    def add_peer(
        self, name: str, dns: Optional[List[str]] = None, split_tunnel: bool = False
    ) -> str:
        # # Validation
        # endpoint = endpoint or self.endpoint
        # if not endpoint:
        #     raise WGToolError("Endpoint is required, but not configured. Provide this parameter.")
        # if ":" not in endpoint:
        #     raise WGToolError("Endpoint must include port: <ip/name>:<port>")
        # if name.isdigit():
        #     raise WGToolError(f"Peer name cannot be a number: {name}")

        # Remove peer with same name
        if peer := self.get_peer(name):
            self.config.peers.remove(peer)

        # Keys
        peer_preshared_key = wgcli.generate_preshared_key()
        peer_private_key = wgcli.generate_private_key()
        peer_public_key = wgcli.generate_public_key(peer_private_key)

        ipv4 = self.get_next_address("ipv4", required=True)
        ipv6 = self.get_next_address("ipv6")

        if split_tunnel:
            allowed_ips = "0.0.0.0/1, 128.0.0.0/1"
            if ipv6:
                allowed_ips = ", ::/1, 8000::/1"
        else:
            allowed_ips = "0.0.0.0/0"
            if ipv6:
                allowed_ips += ", ::/0"
        if not dns:
            dns = [*DEFAULT_DNS_LIST_IPV4]
            if ipv6:
                dns += DEFAULT_DNS_LIST_IPV6

        peer = WGPeerConfig(
            name=name,
            preshared_key=peer_preshared_key,
            private_key=peer_private_key,
            public_key=peer_public_key,
            ipv4=ipv4,
            ipv6=ipv6,
            allowed_ips=allowed_ips,
            server=self.config.server,
            dns=", ".join(dns),
        )
        self.config.peers.append(peer)
        self.save_config()

        file = f"{name}.conf"
        WGPeerConfigExporter(peer).to_file(file)

        logger.debug(f'New peer "{name}"')
        logger.debug(f"  Peer:\n{pp.pformat(peer)}")
        return file

    def get_next_address(self, ipv: Literal["ipv4", "ipv6"], required: bool = False) -> str:
        """Return the next available IPv6 address"""
        server_ip = getattr(self.config, ipv)
        if not server_ip and not required:
            return ""
        if not server_ip:
            raise WGToolError(f"Server {ipv} not found")

        addresses_in_use = [ip_interface(getattr(p, ipv)).ip for p in self.peers]
        addresses_in_use.append(ip_interface(server_ip).ip)

        for address in ip_interface(server_ip).network.hosts():
            if address in addresses_in_use:
                continue
            mask = server_ip.split("/")[1]
            return f"{address}/{mask}"
        raise WGToolError("Cannot find free IP address for peer")

    def peer_delete(self, name_or_index: str) -> None:
        peer = self.get_peer(name_or_index)
        if not peer:
            raise WGToolError(f"Peer name or index not found: {name_or_index}")
        logger.debug(f'Deleting peer "{peer.name}"')
        self.config.peers.remove(peer)
        self.save_config()
