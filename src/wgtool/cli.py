#!/usr/bin/env python3
'''
WireGuard Configuration Tool CLI (wgtool)
by rpcsp (pcunha at hotmail.com) - 10/2021
https://github.com/rpcsp/wgtool
'''
import sys
import os
import argparse
import logging
import subprocess

from .wgtool import WGTool
from .exceptions import WGToolException


logger = logging.getLogger()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='WireGuard Configuration Tool')
    subparser = parser.add_subparsers(dest='action', required=True)

    # server
    parser_server = subparser.add_parser('server', help='Setup new server')
    parser_server.add_argument(
        'domain_name',
        metavar='<server-domain-name>',
        help='Server domain name used by peers. E.g. server1.duckdns.org',
    )
    parser_server.add_argument(
        '-4',
        '--ip',
        metavar='<ip/mask>',
        help='IPv4 prefix with mask',
    )
    parser_server.add_argument(
        '-6',
        '--ipv6',
        metavar='<ip/mask>',
        help='IPv6 prefix with mask',
    )
    parser_server.add_argument(
        '-p',
        '--port',
        dest='ListenPort',
        type=int,
        default=51820,
        help='UDP port',
    )

    # list
    parser_list = subparser.add_parser('list', help='List peers')  # noqa F841

    # add
    parser_add = subparser.add_parser('add', help='Add peer')
    parser_add.add_argument(
        'name',
        help='Name to identify this new peer',
    )
    parser_add.add_argument(
        '-n',
        '--dns',
        nargs='+',
        help='Optional, one or two DNS servers',
    )
    parser_add.add_argument(
        '-e',
        '--endpoint',
        help='Optional, overwrites default. Format: <ip or domain name>:<port>',
    )
    parser_add.add_argument(
        '-q',
        '--qrcode',
        action='store_true',
        help='Display QR code corresponding to config',
    )
    parser_add.add_argument(
        '-s',
        '--split-tunnel',
        action='store_true',
        help='Configure split tunneling (allow LAN access)',
    )

    # del
    parser_del = subparser.add_parser('delete', help='Delete peer')
    parser_del.add_argument(
        'name',
        help='Peer name or number to be added',
    )

    # others
    parser.add_argument(
        '-f',
        '--file',
        metavar='<conf-file>',
        required=(os.name == 'nt'),
        help=(
            'For Windows users mainly, path to wireguard config file. '
            'Default is /etc/wireguard/wg0.conf'
        ),
    )
    parser.add_argument(
        '-i',
        '--ifname',
        metavar='<interface>',
        default='eth0',
        help='For linux users, define LAN interface used with iptables rules. Default is "eth0"',
    )
    parser.add_argument(
        '-d',
        '--debug',
        action='store_true',
        help='Enable debug mode',
    )

    args = parser.parse_args()
    if not args.file and os.name != 'nt':
        args.file = '/etc/wireguard/wg0.conf'
    return args


def main() -> None:
    config = parse_args()
    if config.debug:
        logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
    logger.debug(f'CLI arguments: {config}')

    params = {k: v for k, v in vars(config).items() if k != 'action'}

    try:
        wg = WGTool(config.file, ifname=config.ifname)

        if config.action in ['add', 'delete', 'qrcode']:
            while not config.name:
                config.name = input('Peer name: ')

        # server
        if config.action == 'server':
            if wg.server_config_file_present():
                response = input(
                    'Do you want to overwrite the existing configuration '
                    'and delete any peers? [y/N] '
                )
                if response.lower()[:1] != 'y':
                    sys.exit(0)

            wg.server_config_set(**params)
            config = wg.save_server_config()
            print(f'Content of the new configuration file "{wg.file}":\n\n{config}')
            wg.enable_forwarding()
            wg.restart_systemctl_service()

        # list
        elif config.action == 'list':
            wg.load_server_config()
            print('List of configured peers:')
            for index, name in wg.peers.items():
                print(f'{index: >2}) {name}')

        # add
        elif config.action == 'add':
            wg.load_server_config()
            if wg.peer_present(config.name):
                response = input(
                    f'Peer "{config.name}" exists. Do you want to overwrite it? [y/N] '
                )
                if response.lower()[:1] != 'y':
                    sys.exit(0)
            try:
                file = wg.peer_add(config.name, config.endpoint, config.dns, config.split_tunnel)
                with open(file) as f:
                    print(f'Peer "{config.name}" config file: {file}\n\n{f.read()}\n')
                if config.qrcode:
                    print(
                        subprocess.check_output(
                            f'cat "{file}" | qrencode -t ansiutf8', shell=True, encoding='utf-8'
                        )
                    )
                wg.restart_systemctl_service()
            except (subprocess.SubprocessError, FileNotFoundError):
                print('Note: To display peer config as a QR code, please install "qrencode"')

        # delete
        elif config.action == 'delete':
            wg.load_server_config()
            if not wg.peer_present(config.name):
                sys.exit(f'error: Peer "{config.name}" not found')
            wg.peer_delete(config.name)
            wg.restart_systemctl_service()

    except WGToolException as e:
        sys.exit(f'error: {e}')


if __name__ == '__main__':
    main()
