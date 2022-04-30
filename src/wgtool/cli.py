#!/usr/bin/env python3
"""
WireGuard Configuration Tool CLI (wgtool)
by rpcsp (pcunha at hotmail.com) - 10/2021
https://github.com/rpcsp/wgtool
"""
import sys
import os
import argparse
import logging
import subprocess

from .wgtool import WGTool, DEFAULT_FILE, DEFAULT_PORT
from .exceptions import WGToolException

logger = logging.getLogger()


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments"""

    default_interface = WGTool.default_interface()
    parser = argparse.ArgumentParser(description="WireGuard Configuration Tool")
    subparser = parser.add_subparsers(dest="action", required=True)

    # server
    parser_server = subparser.add_parser("server", help="Setup new server")
    parser_server.add_argument(
        "domain_name",
        metavar="<server-domain-name>",
        help="Server domain name used by peers. E.g. server1.duckdns.org",
    )
    parser_server.add_argument(
        "-4",
        "--ip",
        metavar="<ip/mask>",
        help="IPv4 prefix with mask",
    )
    parser_server.add_argument(
        "-6",
        "--ipv6",
        metavar="<ip/mask>",
        help="IPv6 prefix with mask",
    )
    parser_server.add_argument(
        "-p",
        "--port",
        dest="ListenPort",
        type=int,
        default=DEFAULT_PORT,
        help="UDP port",
    )

    # list
    subparser.add_parser("list", help="List peers")

    # add
    parser_add = subparser.add_parser("add", help="Add peer")
    parser_add.add_argument(
        "name",
        help="Name to identify this new peer",
    )
    parser_add.add_argument(
        "-n",
        "--dns",
        nargs="+",
        help="Optional, one or two DNS servers",
    )
    parser_add.add_argument(
        "-e",
        "--endpoint",
        help="Optional, overwrites default. Format: <ip or domain name>:<port>",
    )
    parser_add.add_argument(
        "-q",
        "--qrcode",
        action="store_true",
        help="Display QR code corresponding to config",
    )
    parser_add.add_argument(
        "-s",
        "--split-tunnel",
        action="store_true",
        help="Configure split tunneling (allow LAN access)",
    )

    # del
    parser_del = subparser.add_parser("delete", help="Delete peer")
    parser_del.add_argument(
        "name",
        help="Peer name or number to be added",
    )

    # others
    parser.add_argument(
        "-f",
        "--file",
        metavar="<conf-file>",
        required=(os.name == "nt"),
        help=(
            f"For Windows users mainly, path to wireguard config file. "
            f"Defaults to {DEFAULT_FILE} for linux"
        ),
    )
    parser.add_argument(
        "-i",
        "--ifname",
        metavar="<interface>",
        default=default_interface,
        help=(
            "For linux users, define LAN interface used with iptables rules. "
            f'Defaults to "{default_interface}"'
        ),
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )

    args = parser.parse_args()
    if not args.file and os.name != "nt":
        args.file = DEFAULT_FILE
    return args


def action_server(wg: WGTool, config: argparse.Namespace) -> None:
    """Creates server config"""

    if wg.server_config_file_present():
        response = input(
            "Do you want to overwrite the existing configuration "
            "and delete any peers? [y/N] "
        )
        if response.lower()[:1] != "y":
            sys.exit(0)

    params = {k: v for k, v in vars(config).items() if k != "action"}
    wg.server_config_set(**params)
    config = wg.save_server_config()
    print(f'Content of the new configuration file "{wg.file}":\n\n{config}')
    wg.enable_forwarding()
    wg.restart_systemctl_service()


def action_list(wg: WGTool) -> None:
    """Lists configured clients"""

    wg.load_server_config()
    print("List of configured peers:")
    for index, name in wg.peers.items():
        print(f"{index: >2}) {name}")


def action_add(wg: WGTool, config: argparse.Namespace) -> None:
    """Adds new client"""

    wg.load_server_config()
    if wg.peer_present(config.name):
        response = input(
            f'Peer "{config.name}" exists. Do you want to overwrite it? [y/N] '
        )
        if response.lower()[:1] != "y":
            sys.exit(0)
    try:
        file = wg.peer_add(config.name, config.endpoint, config.dns, config.split_tunnel)
        with open(file) as f:
            print(f'Peer "{config.name}" config file: {file}\n\n{f.read()}\n')
        if config.qrcode:
            print(
                subprocess.check_output(
                    f'cat "{file}" | qrencode -t ansiutf8', shell=True, encoding="utf-8"
                )
            )
        wg.restart_systemctl_service()
    except (subprocess.SubprocessError, FileNotFoundError):
        print('Note: To display peer config as a QR code, please install "qrencode"')


def action_delete(wg: WGTool, config: argparse.Namespace):
    """Deletes a client"""

    wg.load_server_config()
    if not wg.peer_present(config.name):
        sys.exit(f'error: Peer "{config.name}" not found')
    wg.peer_delete(config.name)
    wg.restart_systemctl_service()


def main() -> None:
    config = parse_args()
    if config.debug:
        logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(message)s")
    logger.debug(f"CLI arguments: {config}")

    try:
        wg = WGTool(config.file, ifname=config.ifname)

        if config.action in ["add", "delete", "qrcode"]:
            while not config.name:
                config.name = input("Peer name: ")

        if config.action == "server":
            action_server(wg, config)

        elif config.action == "list":
            action_list(wg)

        elif config.action == "add":
            action_add(wg, config)

        elif config.action == "delete":
            action_delete(wg, config)

    except WGToolException as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
