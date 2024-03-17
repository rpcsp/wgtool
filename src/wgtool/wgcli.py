import tempfile
import os
import subprocess
from wgtool.exceptions import WGToolError


def generate_preshared_key() -> str:
    return _run_command("wg genpsk")


def generate_private_key() -> str:
    return _run_command("wg genkey")


def generate_public_key(private: str) -> str:
    with tempfile.TemporaryDirectory() as tempdir:
        file = os.path.join(tempdir, "key")
        with open(file, "w") as f:
            f.write(private)
        try:
            if os.name == "nt":
                return _run_command(f'type "{file}" | wg pubkey')
            return _run_command(f'cat "{file}" | wg pubkey')
        except subprocess.CalledProcessError as e:
            raise WGToolError(f"Invalid private key: {private}") from e


def _run_command(command: str) -> str:
    try:
        return subprocess.check_output(command, shell=True, encoding="utf-8").strip()
    except Exception as e:
        if "127" in str(e) and "wg " in str(e):
            raise WGToolError('WireGuard command "wg" not found. Is wireguard installed?')
        raise WGToolError(f'Error executing command "{command}": {e}')
