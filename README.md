# WireGuard Configuration Tool

WGTool is python script to perform basic configuration tasks in a WireGuard Server.

It is meant to be used in new deployments and supports the following action:

- Configure wireguard server
- Add peers
- Remove peers
- List peers

When a peer is added, the tool generates a file and displays a QR code with the configuration.

## Requirements

- Required:
  - python 3.8 or newer
  - Updated python pip
  - Dependencies from requirements.txt

## Installation

    python -m pip install wgtool

## Commands

Configuring new server with default settings:

    wgtool server myserver012.duckdns.org

Configuring new server with some custom settings:

    wgtool server myserver012.duckdns.org --ip 192.168.254.1/24 --port 2345

Adding peer "PeerA":

    wgtool add "PeerA"

Adding peer "PeerA" with custom DNS, split-tunnel:

    wgtool add "PeerA" --dns 1.1.1.1 1.0.0.1 --split-tunnel

Listing peers:

    wgtool list

Removing peer "PeerA":

    wgtool delete "PeerA"

If WireGuard Server is on a Windows machine, you must provide the path to the configuration file. For linux users, the default path is /etc/wireguard/wg0.conf:

    wgtool --file C:\Wireguard\wg0.conf <arguments>


## License

GNU GPLv3
