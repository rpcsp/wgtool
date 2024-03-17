from __future__ import annotations
import os
from typing import Dict, List
from wgtool.models import WGConfigGroup, WGPeerConfig, WGServerConfig


class WGConfigExporter:
    def to_text(self, config: List[WGConfigGroup]) -> str:
        key_width = max(len(key) for group in config for key in group.key_values)
        text = ""
        for group in config:
            text += f"\n[{group.name}]\n"
            for key, value in group.key_values.items():
                text += f"{key: <{key_width}} = {value}\n"
        return text.lstrip("\n")

    def _to_file(self, config: List[WGConfigGroup], file: str, mode: int = 0o600) -> str:
        directory = os.path.dirname(os.path.realpath(file))
        text = self.to_text(config)
        os.makedirs(directory, mode=mode, exist_ok=True)
        with open(file, "w") as f:
            f.write(text)
        os.chmod(file, mode=mode)
        return text


class WGServerConfigExporter(WGConfigExporter):
    def __init__(self, server_config: WGServerConfig) -> None:
        self.config = server_config

    def to_file(self, file: str) -> str:
        interface = self.get_interface_group()
        peers = self.get_peer_groups()
        return self._to_file([interface] + peers, file)

    def get_interface_group(self) -> WGConfigGroup:
        interface: Dict[str, str] = {
            "Address": f"{self.config.ipv4}, {self.config.ipv6}".strip(", "),
            "ListenPort": str(self.config.server.port),
            "MTU": str(self.config.mtu),
            "PostUp": self.config.post_up,
            "PostDown": self.config.post_down,
            "PrivateKey": self.config.server.private_key,
            **self.config.others,
            "# PublicKey": self.config.server.public_key,
            "# Endpoint": self.config.server.endpoint,
        }
        return WGConfigGroup("Interface", interface)

    def get_peer_groups(self) -> List[WGConfigGroup]:
        peers: List[WGConfigGroup] = []
        for peer in self.config.peers:
            peer_attributes = {
                "# Name": peer.name,
                "PublicKey": peer.public_key,
                "PresharedKey": peer.preshared_key,
                "AllowedIPs": f"{peer.ipv4}, {peer.ipv6}".strip(", "),
                **peer.others,
            }
            peers.append(WGConfigGroup("Peer", peer_attributes))
        return peers


class WGPeerConfigExporter(WGConfigExporter):
    def __init__(self, peer_config: WGPeerConfig) -> None:
        self.peer_config = peer_config

    def to_file(self, file: str) -> str:
        interface = self.get_interface_group()
        peer = self.get_peer_group()
        return self._to_file([interface, peer], file)

    def get_interface_group(self) -> WGConfigGroup:
        interface_attributes = {
            "Address": f"{self.peer_config.ipv4}, {self.peer_config.ipv6}".strip(", "),
            "DNS": self.peer_config.dns,
            "PrivateKey": self.peer_config.private_key,
        }
        interface_attributes = {k: v for k, v in interface_attributes.items() if v}
        return WGConfigGroup("Interface", interface_attributes)

    def get_peer_group(self) -> WGConfigGroup:
        peer_attributes = {
            "Endpoint": self.peer_config.server.endpoint,
            "AllowedIPs": self.peer_config.allowed_ips,
            "PresharedKey": self.peer_config.preshared_key,
            "PublicKey": self.peer_config.server.public_key,
        }
        return WGConfigGroup("Peer", peer_attributes)
