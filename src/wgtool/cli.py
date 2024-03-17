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

from wgtool.exceptions import WGToolError
from wgtool import host
from wgtool.models import DEFAULT_PORT, DEFAULT_FILE
from wgtool.wgtool import WGTool
from wgtool.qrcode import print_qrcode
from pydantic_core import ValidationError


logger = logging.getLogger()


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments"""

    default_interface = host.default_interface()
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
        "--ipv4",
        default="",
        metavar="<ip/mask>",
        help="IPv4 prefix with mask",
    )
    parser_server.add_argument(
        "-6",
        "--ipv6",
        default="",
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

    # show
    parser_show = subparser.add_parser("show", help="show peers")
    parser_show.add_argument(
        "name",
        nargs="?",
        help="Peer name or number to be added",
    )

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
        "-s",
        "--split-tunnel",
        action="store_true",
        help="Configure split tunneling (allow LAN access)",
    )

    # delete
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
            "Do you want to overwrite the existing configuration and delete any peers? [y/N] "
        )
        if response.lower()[:1] != "y":
            sys.exit(0)

    params = {k: v for k, v in vars(config).items() if k != "action"}
    wg.set_config(**params)
    wg.save_config()
    print(f'Content of the new configuration file "{wg.file}":')
    print(wg.config.model_dump_json(indent=4, exclude_unset=False))
    wg.enable_forwarding()
    wg.restart_systemctl_service()


def action_show(wg: WGTool, args: argparse.Namespace) -> None:
    """Show configured clients"""

    wg.load_config()
    if args.name is None:
        print("Configured peers:")
        if not wg.peers:
            print("  none")
        for index, peer in enumerate(wg.peers):
            print(f"  {index: >2}) {peer.name}")
        return

    request_peer = wg.get_peer(name_or_index=args.name)
    if not request_peer:
        raise WGToolError(f"Peer name or index not found: {args.name}")
    print(request_peer.model_dump_json(indent=4, exclude_defaults=True))


def action_add(wg: WGTool, config: argparse.Namespace) -> None:
    """Adds new client"""

    wg.load_config()
    if wg.get_peer(config.name):
        response = input(f'Peer "{config.name}" exists. Do you want to overwrite it? [y/N] ')
        if response.lower()[:1] != "y":
            sys.exit(0)

    file = wg.add_peer(config.name, config.dns, config.split_tunnel)
    with open(file) as f:
        print(f'Peer "{config.name}" config file: {file}\n\n{f.read()}\n')
    print_qrcode(file)
    wg.restart_systemctl_service()


def action_delete(wg: WGTool, config: argparse.Namespace) -> None:
    """Deletes a client"""

    wg.load_config()
    if not wg.get_peer(config.name):
        sys.exit(f'error: Peer "{config.name}" not found')
    wg.peer_delete(config.name)
    wg.restart_systemctl_service()


def main() -> None:
    args = parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(message)s")
    logger.debug(f"CLI arguments: {args}")

    try:
        wg = WGTool(args.file, ifname=args.ifname)
        if args.action in ["add", "delete"]:
            while not args.name:
                args.name = input("Peer name: ")
        if args.action == "server":
            action_server(wg, args)
        elif args.action == "show":
            action_show(wg, args)
        elif args.action == "add":
            action_add(wg, args)
        elif args.action == "delete":
            action_delete(wg, args)

    except PermissionError:
        sys.exit("error: Permission denied. You need root privilege to run this commad.")
    except ValidationError as e:
        for item in e.errors():
            fields = ", ".join([str(e) for e in item["loc"]])
            print(f"failed to validate '{fields}': {item['msg']}")
        sys.exit("error: one or more validations failed")
    except WGToolError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
