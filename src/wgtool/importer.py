from __future__ import annotations
import re
from typing import Dict, List, Optional
from wgtool.exceptions import WGToolError
from wgtool.models import WGConfigGroup, WGPeerConfig, WGServerConfig
from ipaddress import ip_interface


re_group = re.compile(r"\[(\w+)\]")
re_key_value = re.compile(r"^([^=]+)\s*=\s*(.+)$")


class WGServerConfigImporter:
    def __init__(self, current_config: Optional[WGServerConfig] = None) -> None:
        self.config = current_config or WGServerConfig()
        self.interface = WGPeerConfig(name="Interface")
        self.peers: List[WGPeerConfig] = []

    def read_interface(self, attrs: Dict[str, str]) -> None:
        cfg = self.config
        for item in attrs.pop("Address", "").split(","):
            if item.strip():
                address = ip_interface(item.strip())
                if address.version == 4:
                    cfg.ipv4 = address.with_prefixlen
                elif address.version == 6:
                    cfg.ipv6 = address.with_prefixlen

        cfg = cfg
        cfg.mtu = int(attrs.pop("MTU", "") or cfg.mtu)
        cfg.post_up = attrs.pop("PostUp", "") or cfg.post_up
        cfg.post_down = attrs.pop("PostDown", "") or cfg.post_down
        cfg.server.private_key = attrs.pop("PrivateKey", "") or cfg.server.private_key
        cfg.server.port = int(attrs.pop("ListenPort", "") or cfg.server.port)
        cfg.server.address = (attrs.pop("# Endpoint", "") or cfg.server.address).split(":")[0]
        cfg.others = {k: v for k, v in attrs.items() if k[0] == k[0].upper()}

    def read_peers(self, peers: List[WGConfigGroup]) -> None:

        class PeerNames:
            def __init__(self) -> None:
                self.i = 0

            def get_name(self) -> str:
                self.i += 1
                return f"Peer {self.i}"

        peer_names = PeerNames()
        for peer in peers:
            name = peer.key_values.pop("# Name", "") or peer_names.get_name()
            pc = WGPeerConfig(name=name)
            for ip_string in peer.key_values.pop("AllowedIPs", "").split(","):
                ip_string = ip_string.strip()
                if ip_string and ip_interface(ip_string).version == 4:
                    pc.ipv4 = ip_string
                elif ip_string and ip_interface(ip_string).version == 6:
                    pc.ipv6 = ip_string
            pc.public_key = peer.key_values.pop("PublicKey", pc.public_key)
            pc.preshared_key = peer.key_values.pop("PresharedKey", pc.preshared_key)
            pc.dns = peer.key_values.pop("DNS", pc.private_key)
            pc.server = self.config.server
            pc.others = {k: v for k, v in peer.key_values.items() if k[0] == k[0].upper()}
            self.config.peers.append(pc)

    def from_file(self, file: str) -> WGServerConfig:
        groups = self._from_file(file)
        for i, group in enumerate(groups):
            if group.name == "Interface":
                self.read_interface(group.key_values)
                groups.pop(i)
                break
        else:
            raise WGToolError("Config not found")
        self.read_peers(groups)
        return self.config

    def _from_file(self, file: str) -> List[WGConfigGroup]:
        with open(file) as f:
            content = f.read()

        config: List[WGConfigGroup] = []
        key_values: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            if match := re_group.match(line):
                name = match.group(1).strip()
                key_values = {}
                config.append(WGConfigGroup(name, key_values))
            elif match := re_key_value.match(line):
                key = match.group(1).strip()
                value = match.group(2).strip()
                key_values[key] = value
        return config
