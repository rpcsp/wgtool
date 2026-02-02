"""QRCode generation and printing utility."""

from qrcode import ERROR_CORRECT_L, QRCode


def print_qrcode(text: str) -> None:
    """Print a QR code for the given text to the terminal."""
    qr = QRCode(error_correction=ERROR_CORRECT_L, box_size=1, border=2)
    qr.add_data(text)
    qr.make(fit=True)
    qr.print_ascii(invert=True)
