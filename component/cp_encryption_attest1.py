
import sys
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from binascii import hexlify

def read_aes_key(file_path):
    # Read the AES key from the specified file
    with open(file_path, 'r') as header_file:
        for line in header_file:
            if line.startswith('#define SECRET'):
                key_hex = line.split('"')[1]
                return bytes.fromhex(key_hex)

def add_padding(message):
    padding_length = 16 - (len(message) % 16)
    padded_message = message + b'\x00' * padding_length
    return padded_message

def encrypt_value(value, key):
    # Pad the value to be a multiple of 16 bytes long
    padded_value = add_padding(value.encode())

    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the padded value
    #encrypted_value = cipher.encrypt(padded_value)
    encrypted_value = padded_value

    return encrypted_value


def get_params(secret_file_path):
    # Define the path to your file
    file_path = './inc/ectf_params.h'

    # Define the search term
    search_term = '#define ATTESTATION_LOC'

    # Read the AES key
    aes_key = read_aes_key(secrets_file_path)

    # Read the content of the file
    with open(file_path, "r") as file:
        lines = file.readlines()

    attestation_loc = None

    # Modify the ATTESTATION_LOC line
    new_content = []
    for line in lines:
        if search_term in line:
            # Extract the location
            attestation_loc = line.split('"')[1]
            # Encrypt the location
            encrypted_loc = encrypt_value(attestation_loc, aes_key)
            # Convert the encrypted location to a hexadecimal string for storage
            encrypted_loc_hex = hexlify(encrypted_loc).decode()
            new_content.append(f'{search_term} "{encrypted_loc_hex}"\n')  # Change the ATTESTATION_LOC value here
        else:
            new_content.append(line)

    # Write the modified content back to the file
    with open(file_path, 'w') as file:
        file.writelines(new_content)

    print("ATTESTATION_LOC has been updated.")

if __name__ == "__main__":
   if len(sys.argv) != 2:
       print("Usage: python script.py path/to/global_secrets.h")
       sys.exit(1)
   secrets_file_path = sys.argv[1]
   get_params(secrets_file_path)