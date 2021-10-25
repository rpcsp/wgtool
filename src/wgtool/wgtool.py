#!/usr/bin/env python3
'''
WireGuard Configuration Tool (wgtool)
by rpcsp (pcunha at hotmail.com) - 10/2021
https://github.com/rpcsp/wgtool
'''
import sys
import os
import argparse
import logging
import pprint
import subprocess
import tempfile
import re
from ipaddress import ip_interface, IPv4Interface, IPv6Interface
from typing import Union

POST_UP = ('iptables -I FORWARD 1 -i %i -o {0} -j ACCEPT; '
           'iptables -I FORWARD 1 -i {0} -o %i -j ACCEPT; '
           'iptables -t nat -I POSTROUTING 1 -s {1} -o {0} -j MASQUERADE; '
           'ip6tables -I FORWARD 1 -i %i -o {0} -j ACCEPT; '
           'ip6tables -I FORWARD 1 -i {0} -o %i -j ACCEPT; '
           'ip6tables -t nat -I POSTROUTING 1 -s {2} -o {0} -j MASQUERADE')
POST_DN = ('iptables -D FORWARD   -i %i -o {0} -j ACCEPT; '
           'iptables -D FORWARD   -i {0} -o %i -j ACCEPT; '
           'iptables -t nat -D POSTROUTING   -s {1} -o {0} -j MASQUERADE; '
           'ip6tables -D FORWARD   -i %i -o {0} -j ACCEPT; '
           'ip6tables -D FORWARD   -i {0} -o %i -j ACCEPT; '
           'ip6tables -t nat -D POSTROUTING   -s {2} -o {0} -j MASQUERADE')
MIN_PYTHON = (3, 7)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

IPInterface = Union[IPv4Interface, IPv6Interface]

logger = logging.getLogger()
pp = pprint.PrettyPrinter(indent=4, width=100)


class WGTool:
    def __init__(self, file: str, ifname: str = 'eth0') -> None:
        self.file = file
        self.ifname = ifname
        self._server_ip = None
        self._server_ipv6 = None
        self.domain_name = ''
        self._public_key = {}
        self.interface_config = {}
        self.peers_config = []

    @property
    def server_ip(self) -> IPv4Interface:
        return self._server_ip or IPv4Interface('10.6.0.1/24')

    @server_ip.setter
    def server_ip(self, value):
        self._server_ip = self._get_valid_host_ip(IPv4Interface, current_value=self._server_ip, new_value=value)

    @property
    def server_ipv6(self) -> IPv6Interface:
        return self._server_ipv6

    @server_ipv6.setter
    def server_ipv6(self, value):
        self._server_ipv6 = self._get_valid_host_ip(IPv6Interface, current_value=self._server_ipv6, new_value=value)

    @property
    def address(self) -> str:
        return ', '.join([str(ip) for ip in [self.server_ip, self.server_ipv6] if ip])

    @property
    def mtu(self) -> int:
        return self.interface_config.get('MTU', 1420)

    @mtu.setter
    def mtu(self, value):
        if not value:
            return
        try:
            if not (1280 <= int(value) <= 65535):
                raise ValueError()
            self.interface_config['MTU'] = int(value)
        except ValueError:
            raise WGToolException('MTU must be an integer within 1280 and 65535')

    @property
    def port(self) -> int:
        return self.interface_config.get('ListenPort', 51820)

    @port.setter
    def port(self, value):
        if not value:
            return
        try:
            if not (1024 <= int(value) <= 65535):
                raise ValueError()
            self.interface_config['ListenPort'] = int(value)
        except ValueError:
            raise WGToolException('MTU must be an integer within 1024 and 65535')

    @property
    def endpoint(self) -> str:
        if self.domain_name:
            return f'{self.domain_name}:{self.port}'

    @property
    def post_up(self) -> str:
        if os.name == 'posix':
            return self.interface_config.get(
                'PostUp',
                POST_UP.format(self.ifname, self.server_ip.network, self.server_ipv6.network)
            )
        return ''

    @property
    def post_down(self) -> str:
        if os.name == 'posix':
            return self.interface_config.get(
                'PostDown',
                POST_DN.format(self.ifname, self.server_ip.network, self.server_ipv6.network)
            )
        return ''

    @property
    def private_key(self) -> str:
        if 'PrivateKey' not in self.interface_config:
            self.interface_config['PrivateKey'] = self.generate_private_key()
            if self.peers_config:
                print(f'Server keys have changed. Update clinets with the key below:\nPublicKey = {self.public_key}')
        return self.interface_config['PrivateKey']

    @private_key.setter
    def private_key(self, value):
        if not value or len(value) != 44 or value[-1:] != '=':
            return
        self.interface_config['PrivateKey'] = value

    @property
    def public_key(self) -> str:
        if self.private_key not in self._public_key:
            self._public_key = {self.private_key: self.generate_public_key(self.private_key)}
        return self._public_key[self.private_key]

    def server_config_set(self, ip: str = '', ipv6: str = '', domain_name: str = '', **params) -> dict:
        '''
        Set one or more server interface parameters.
        Some valid params: ip, ipv6,or any wireguard valid key/value such as ListenPort, MTU
        '''
        self.server_ip = self._get_ip(params.get('Address')) or ip
        self.server_ipv6 = self._get_ipv6(params.get('Address')) or ipv6
        self.mtu = params.get('MTU')
        self.port = params.get('ListenPort')
        self.private_key = params.get('PrivateKey')
        self.domain_name = params.get('# Endpoint', '').split(':')[0] or domain_name

        excluded_keys = ['Address', 'MTU', 'ListenPort', 'PrivateKey', 'PublicKey', '# PublicKey', 'PostUp', 'PostDown']
        self.interface_config.update({
            k: v for k, v in params.items()
            if (v and k[:1] == k.upper()[:1] and k[:1] != k[:1].lower() and k not in excluded_keys)
        })

    def load_server_config(self) -> None:
        interface_config = {}
        peers_config = []
        config = {}
        try:
            with open(self.file) as f:
                content = '\n' + f.read()
            for record in content.split('\n['):
                lines = record.strip().splitlines()
                if not lines:
                    continue  # Empty file

                # Read group name
                group = lines.pop(0).strip().strip(']')
                if group == 'Interface':
                    interface_config = config = {}
                elif group == 'Peer':
                    config = {}
                    peers_config.append(config)
                else:
                    continue  # Unknown group

                # Read group params
                for line in lines:
                    if '=' not in line:
                        continue
                    key = line.split('=', 1)[0].strip()
                    value = line.split('=', 1)[1].strip()
                    config[key] = value

        except FileNotFoundError:
            pass
        self.peers_config = peers_config
        self.assign_name_to_peers()
        self.server_config_set(**interface_config)

    def assign_name_to_peers(self) -> None:
        '''
        Assign a peer name to all peers without one
        '''
        for index, config in enumerate(self.peers_config):
            if '# Name' not in config or config['# Name'] in list(self.peers.values())[:index]:
                config['# Name'] = self.get_new_peer_name()

    def save_server_config(self) -> str:
        interface = {
            'Address': self.address,
            'ListenPort': self.port,
            'MTU': self.mtu,
            'PostUp': self.post_up,
            'PostDown': self.post_down,
            'PrivateKey': self.private_key,
            '# PublicKey': self.public_key,
            '# Endpoint': self.endpoint,
        }
        interface.update({k: v for k, v in self.interface_config.items() if k not in interface})

        peers = []
        for peer_config in self.peers_config:
            peer = {
                '# Name': peer_config['# Name'],
            }
            peer.update({k: v for k, v in peer_config.items() if k not in peer})  # and k[:1].upper() == k[:1]})
            peers.append(peer)

        # Save to file
        directory = os.path.dirname(self.file)
        try:
            if directory and not os.path.isdir(directory):
                os.makedirs(directory, mode=0o700,  exist_ok=True)
            content = self._save_to_file(interface, peers, self.file)
        except PermissionError:
            sys.exit('error: Permission denied creating files. Are you running with sudo?')
        return content

    def peers_delete_all(self):
        self.peers_config = []

    @staticmethod
    def _get_first_host_ip(ip: IPInterface) -> IPInterface:
        '''
        Get first host IP
        '''
        if str(ip.network) == str(ip):
            mask = str(ip).split('/')[1]
            ip = ip_interface(f'{ip.ip + 1}/{mask}')
        return ip

    def _get_valid_host_ip(self, ip_class, current_value, new_value) -> IPInterface:
        try:
            new_value = ip_class(new_value) if new_value else None
            if not new_value or new_value == current_value:
                return current_value
            if current_value:
                self.peers_delete_all()

            # Get first host ip
            if str(new_value.network) == str(new_value):
                mask = str(new_value).split('/')[1]
                new_value = ip_interface(f'{new_value.ip + 1}/{mask}')
            return new_value
        except Exception:
            raise WGToolException(f'Invalid IPv{ip_class.version} address: "{current_value}"')

    @staticmethod
    def _get_ip(text) -> Union[IPv4Interface, None]:
        '''
        Extract first IPv4 from text
        '''
        try:
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})', text)
            return IPv4Interface(match.group(1))
        except Exception:
            return None

    @staticmethod
    def _get_ipv6(text) -> Union[IPv6Interface, None]:
        '''
        Extract first IPv6 from text
        '''
        try:
            match = re.search(r'([0-9a-fA-F:]{6,}/\d{1,3})', text)
            return IPv6Interface(match.group(1))
        except Exception:
            return None

    @staticmethod
    def _save_to_file(interface: dict, peers: list, file: str):
        '''
        Save config to file
        Format: (<group-name>: {key1: value1, key2: value2}, ...)
        Keys without value are ignored
        '''
        def to_text(group_name: str, key_values: dict) -> str:
            width = max([len(str(v)) for v in key_values if v])
            content = f'[{group_name}]\n'
            for key, value in key_values.items():
                if value:
                    content += f'{key: <{width}} = {value}\n'
            return f'{content}\n'

        content = to_text('Interface', interface)
        for peer in peers:
            content += to_text('Peer', peer)

        with open(file, 'w') as f:
            f.write(content.strip() + '\n')
        os.chmod(file, mode=0o700)
        return content

    def get_next_ip(self) -> Union[IPv4Interface, None]:
        ''' Return the next available IP address '''
        server = self.server_ip
        if not server:
            return None
        ip_networks_in_use = [self._get_ip(p.get('AllowedIPs')) for p in self.peers_config] + [server]
        ip_list_in_use = [str(address.ip) for address in ip_networks_in_use if address]
        for host in server.network.hosts():
            if str(host) not in ip_list_in_use:
                mask = str(server).split('/')[1]
                return IPv4Interface(f'{host}/{mask}')
        return None

    def get_next_ipv6(self) -> Union[IPv6Interface, None]:
        ''' Return the next available IPv6 address '''
        server = self.server_ipv6
        if not server:
            return None
        ip_networks_in_use = [self._get_ipv6(p.get('AllowedIPs')) for p in self.peers_config] + [server]
        ip_list_in_use = [str(address.ip) for address in ip_networks_in_use if address]
        for host in server.network.hosts():
            if str(host) not in ip_list_in_use:
                mask = str(server).split('/')[1]
                return IPv6Interface(f'{host}/{mask}')
        return None

    def server_config_file_present(self):
        return os.path.isfile(self.file)

    @property
    def peers(self):
        return {i: p.get('# Name') for i, p in enumerate(self.peers_config)}

    def get_peer_index(self, name_or_index: str) -> int:
        name_or_index = str(name_or_index)
        for index, name in self.peers.items():
            if name_or_index == name or name_or_index == str(index):
                return index

    def get_peer_name(self, index: int) -> str:
        return self.peers_config[index].get('# Name')

    def get_new_peer_name(self) -> str:
        peers = self.peers.values()
        index = 1
        while f'Peer{index}' in peers:
            index += 1
        return f'Peer{index}'

    def peer_present(self, name: str):
        return self.get_peer_index(name) is not None

    def peer_add(self, name: str, endpoint: str, dns: list = None) -> str:
        # Validation
        endpoint = endpoint or self.endpoint
        if not endpoint:
            raise WGToolException('Endpoint is required, but not configured. Provide this parameter.')
        if ':' not in endpoint:
            raise WGToolException('Endpoint must include port: <ip/name>:<port>')
        if name.isdigit():
            raise WGToolException(f'Peer name cannot be a number: {name}')

        # Remove peer with same name
        if name in self.peers.values():
            self.peer_delete(name)

        # Keys
        peer_preshared_key = self.generate_preshared_key()
        peer_private_key = self.generate_private_key()
        peer_public_key = self.generate_public_key(peer_private_key)

        # Assign IPs
        ip = self.get_next_ip()
        ipv6 = self.get_next_ipv6()

        # Server Config
        self.peers_config.append({
            '# Name': name,
            'PublicKey': peer_public_key,
            'PresharedKey': peer_preshared_key,
            'AllowedIPs': ', '.join([str(v + 0) for v in [ip, ipv6] if v]),  # Convert to /32 or /128
        })
        self.save_server_config()

        # Peer Config
        allowed_ips = '0.0.0.0/0'
        if ipv6:
            allowed_ips += ', ::/0'
        if not dns:
            dns = ['8.8.8.8', '1.1.1.1']
            if ipv6:
                dns += ['2001:4860:4860::8888', '2606:4700:4700::1111']

        interface_config = {
            'Address': ', '.join([str(v) for v in [ip, ipv6] if v]),
            'PrivateKey': peer_private_key,
            'DNS': ', '.join([str(v) for v in dns if v]),
        }
        peer_config = [{
            'PublicKey': self.public_key,
            'PresharedKey': peer_preshared_key,
            'AllowedIPs': allowed_ips,
            'Endpoint': endpoint
        }]
        logger.debug(f'New peer "{name}"')
        logger.debug(f'  Interface: {pp.pformat(interface_config)}')
        logger.debug(f'  Peer:\n{pp.pformat(peer_config)}')
        file = f'{name}.conf'
        self._save_to_file(interface_config, peer_config, file)
        return file

    def peer_delete(self, name_or_index: str):
        index = self.get_peer_index(name_or_index)
        name = self.get_peer_name(index)
        logger.debug(f'Deleting peer "{name}" (index {index})')
        self.peers_config.pop(index)
        self.save_server_config()

    def _run_command(self, command) -> str:
        try:
            return subprocess.check_output(command, shell=True, encoding='utf-8').strip()
        except Exception as e:
            if '127' in str(e) and 'wg ' in str(e):
                sys.exit('WireGuard command "wg" not found. Is wireguard installed?')
            sys.exit(f'Error executing command "{command}": {e}')

    def generate_preshared_key(self) -> str:
        return self._run_command('wg genpsk')

    def generate_private_key(self) -> str:
        return self._run_command('wg genkey')

    def generate_public_key(self, private: str) -> str:
        with tempfile.TemporaryDirectory() as tempdir:
            file = os.path.join(tempdir, 'key')
            with open(file, 'w') as f:
                f.write(private)
            try:
                if os.name == 'nt':
                    return self._run_command(f'type "{file}" | wg pubkey')
                return self._run_command(f'cat "{file}" | wg pubkey')
            except subprocess.CalledProcessError:
                raise WGToolException(f'Invalid private key: {private}')

    def restart_systemctl_service(self) -> bool:
        print('Restarting service...')
        if os.name != 'posix':
            return False
        command = ('sudo systemctl enable wg-quick@wg0.service && '
                   'sudo systemctl daemon-reload && '
                   'sudo systemctl restart wg-quick@wg0')
        result = self._run_command(command)
        print(result)


class WGToolException(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='WireGuard Configuration Tool')
    subparser = parser.add_subparsers(dest='action', required=True)
    # server
    parser_server = subparser.add_parser('server', help='Setup new server')
    parser_server.add_argument('domain_name', metavar='<server-domain-name>',
                               help='Server domain name used by peers. E.g. server1.duckdns.org')
    parser_server.add_argument('-4', '--ip', metavar='<ip/mask>', help='IPv4 prefix with mask')
    parser_server.add_argument('-6', '--ipv6', metavar='<ip/mask>', help='IPv6 prefix with mask')
    parser_server.add_argument('-p', '--port', dest='ListenPort', type=int, default=51820, help='UDP port')
    # list
    parser_list = subparser.add_parser('list', help='List peers')  # noqa F841
    # add
    parser_add = subparser.add_parser('add', help='Add peer')
    parser_add.add_argument('name', help='Name to identify this new peer')
    parser_add.add_argument('-n', '--dns', nargs='+', help='Optional, one or two DNS servers')
    parser_add.add_argument('-e', '--endpoint', help='Optional, overwrites default. Format: <ip or domain name>:<port>')
    parser_add.add_argument('-q', '--qrcode', action='store_true', help='Display QR code corresponding to config')
    # del
    parser_del = subparser.add_parser('delete', help='Delete peer')
    parser_del.add_argument('name', help='Peer name or number to be added')
    # others
    parser.add_argument('-f', '--file', metavar='<conf-file>', required=(os.name == 'nt'),
                        help=('For Windows users mainly, path to wireguard config file. '
                              'Default is /etc/wireguard/wg0.conf'))
    parser.add_argument('-i', '--ifname', metavar='<interface>', default='eth0',
                        help='For linux users, define LAN interface used with iptables rules. Default is "eth0"')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
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
                response = input('Do you want to overwrite the existing configuration and delete any peers? [y/N] ')
                if response.lower()[:1] != 'y':
                    sys.exit(0)

            wg.server_config_set(**params)
            config = wg.save_server_config()
            print(f'Content of the new configuration file "{wg.file}":\n\n{config}')
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
                response = input(f'Peer "{config.name}" exists. Do you want to overwrite it? [y/N] ')
                if response.lower()[:1] != 'y':
                    sys.exit(0)
            try:
                file = wg.peer_add(config.name, config.endpoint, config.dns)
                with open(file) as f:
                    print(f'Peer "{config.name}" config file: {file}\n\n{f.read()}\n')
                if config.qrcode:
                    print(subprocess.check_output(f'qrencode -t ansiutf8 -r "{file}"', shell=True, encoding='utf-8'))
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
