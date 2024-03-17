import subprocess


def print_qrcode(file: str) -> None:
    try:
        command = ["qrencode", "-r", file, "-t", "ansiutf8"]
        print(subprocess.check_output(command, encoding="utf-8"))
    except FileNotFoundError:
        print('Note: To display peer config as a QR code, please install "qrencode"')
    except subprocess.CalledProcessError:
        print("Failed to execute qrencode")
