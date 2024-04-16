
import sys
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

def encrypt_pin(pin, key):
    # Pad the PIN to be 16 bytes long
    padded_pin = pin.ljust(16, '\0')

    # Encrypt the padded PIN
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_pin = encryptor.update(padded_pin.encode()) + encryptor.finalize()

    return encrypted_pin

def get_params():
    # Define the path to your file
    file_path = './inc/ectf_params.h'

    # Define the search term
    search_term = '#define AP_PIN'

    # Define your AES key (must be 16, 24, or 32 bytes long)
    aes_key = b'ThisIsASecretKey'  # Change this to your own secret key

    # Read the content of the file
    with open(file_path, "r") as file:
        lines = file.readlines()

    # Modify the AP_PIN line
    new_content = []
    for line in lines:
        if search_term in line:
            # Encrypt the PIN
            encrypted_pin = encrypt_pin("3333", aes_key)
            # Convert the encrypted PIN to a hexadecimal string for storage
            encrypted_pin_hex = encrypted_pin.hex()
            new_content.append(f'#define AP_PIN "{encrypted_pin_hex}"\n')  # Change the AP_PIN value here
        else:
            new_content.append(line)

    # Write the modified content back to the file
    with open(file_path, 'w') as file:
        file.writelines(new_content)

    print("AP_PIN has been updated.")

if __name__ == "__main__":
    get_params()
    sys.exit(0)
