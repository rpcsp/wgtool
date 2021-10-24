# WireGuard Configuration Tool

WGTool is python script perform basic configuration tasks in a WireGuard Server.

It is meant to be used in new deployments and supports the following action:

- Configure wireguard server
- Add peers
- Remove peers
- List peers

When a peer is added, the tool can display a QR code with the configuration if "qrencode" is available.

## Commands

Configuring new server with default settings:

    python ./wgtool.py server myserver012.duckdns.org

Configuring new server with some custom settings:

    python ./wgtool.py server myserver012.duckdns.org --ip 192.168.254.1/24 --port 2345

Adding peer "PeerA":

    python ./wgtool.py add "PeerA"

Adding peer "PeerA" with custom DNS and showing QR code:

    python ./wgtool.py add "PeerA" --dns 1.1.1.1 1.0.0.1 --qrcode

Listing peers:

    python ./wgtool.py list

Removing peer "PeerA":

    python ./wgtool.py delete "PeerA"

If WireGuard Server is on a Windows machine, you must provide the path to the configuration file:

    python wgtool.py --file C:\Wireguard\wg0.conf <arguments>


## Requirements

- Required:
  - python 3.7.x or superior (no additional modules required)
- Optional:
  - qrencode 4.x or superior
