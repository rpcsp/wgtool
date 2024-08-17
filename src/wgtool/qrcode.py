import qrcode
from qrcode.main import QRCode


def print_qrcode(text: str) -> None:
    qr = QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=1,
        border=2,  # Add some padding to make the QR code more readable
    )

    # Add data to the QR code
    qr.add_data(text)
    qr.make(fit=True)
    
    # Generate the QR code matrix (1s and 0s)
    qr_matrix = qr.get_matrix()
    
    # Print the QR code two rows at a time to create a more compact output
    for y in range(0, len(qr_matrix), 2):
        line = ''
        for x in range(len(qr_matrix[y])):
            upper_pixel = qr_matrix[y][x]
            lower_pixel = qr_matrix[y + 1][x] if y + 1 < len(qr_matrix) else 0
            
            if upper_pixel and lower_pixel:
                line += ' '  # Empty, show black
            elif upper_pixel and not lower_pixel:
                line += '▄'  # Lower filled, upper not filled
            elif not upper_pixel and lower_pixel:
                line += '▀'  # Upper filled, lower not filled
            else:
                line += '█'  # Both filled, show whit
        print(line)


