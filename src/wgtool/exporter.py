import os

from wgtool.models import WGConfigGroup, WGPeerConfig, WGServerConfig


class WGConfigExporter:
    """Base class for exporting WireGuard configurations.

    This class provides methods for converting configuration data into text format
    and writing it to files.
    """

    def to_text(self, config: list[WGConfigGroup]) -> str:
        """Convert a list of configuration groups to text format."""
        key_width = max(len(key) for group in config for key in group.key_values)
        text = ""
        for group in config:
            text += f"\n[{group.name}]\n"
            for key, value in group.key_values.items():
                text += f"{key: <{key_width}} = {value}\n"
        return text.lstrip("\n")

    def _to_file(self, config: list[WGConfigGroup], file: str, mode: int = 0o600) -> str:
        """Write configuration text to a file."""
        directory = os.path.dirname(os.path.realpath(file))
        text = self.to_text(config)
        os.makedirs(directory, mode=mode, exist_ok=True)
        with open(file, "w") as f:
            f.write(text)
        os.chmod(file, mode=mode)
        return text


class WGServerConfigExporter(WGConfigExporter):
    """Exports server configurations to WireGuard format.

    This class handles the conversion of server configuration data into
    WireGuard configuration file format.
    """

    def __init__(self, server_config: WGServerConfig) -> None:
        """Initialize the exporter with a server configuration."""
        self.config = server_config

    def to_file(self, file: str) -> str:
        """Export the server configuration to a file."""
        interface = self.get_interface_group()
        peers = self.get_peer_groups()
        return self._to_file([interface, *peers], file)

    def get_interface_group(self) -> WGConfigGroup:
        """Generate the interface configuration group."""
        interface: dict[str, str] = {
            "Address": self.config.address,
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

    def get_peer_groups(self) -> list[WGConfigGroup]:
        """Generate peer configuration groups."""
        peers: list[WGConfigGroup] = []
        for peer in self.config.peers:
            peer_attributes = {
                "# Name": peer.name,
                "PublicKey": peer.public_key,
                "PresharedKey": peer.preshared_key,
                "AllowedIPs": peer.address,
                **peer.others,
            }
            peers.append(WGConfigGroup("Peer", peer_attributes))
        return peers


class WGPeerConfigExporter(WGConfigExporter):
    """Exports peer configurations to WireGuard format.

    This class handles the conversion of peer configuration data into
    WireGuard configuration file format.
    """

    def __init__(self, peer_config: WGPeerConfig) -> None:
        """Initialize the exporter with a peer configuration."""
        self.peer_config = peer_config

    def to_file(self, file: str) -> str:
        """Export the peer configuration to a file."""
        interface = self.get_interface_group()
        peer = self.get_peer_group()
        return self._to_file([interface, peer], file)

    def get_interface_group(self) -> WGConfigGroup:
        """Generate the interface configuration group."""
        interface_attributes = {
            "Address": self.peer_config.address,
            "DNS": ", ".join(str(ip) for ip in self.peer_config.dns),
            "PrivateKey": self.peer_config.private_key,
        }
        interface_attributes = {k: v for k, v in interface_attributes.items() if v}
        return WGConfigGroup("Interface", interface_attributes)

    def get_peer_group(self) -> WGConfigGroup:
        """Generate the peer configuration group. """
        peer_attributes = {
            "Endpoint": self.peer_config.server.endpoint,
            "AllowedIPs": ", ".join(str(ip) for ip in self.peer_config.allowed_ips),
            "PresharedKey": self.peer_config.preshared_key,
            "PublicKey": self.peer_config.server.public_key,
        }
        return WGConfigGroup("Peer", peer_attributes)
