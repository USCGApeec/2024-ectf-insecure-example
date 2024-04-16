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
    padded_message = pad(message, AES.block_size)
    return padded_message

def encrypt_token(token, key):
    # Ensure the token is exactly 16 bytes long
    token = token[:16]

    # Pad the TOKEN to be 16 bytes long
    padded_token = add_padding(token.encode())

    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the padded TOKEN
    encrypted_token = cipher.encrypt(padded_token)

    # Use a simple XOR operation to get 16 bytes from the encryption output
    truncated_encrypted_token = encrypted_token[:16]

    # Convert the truncated encrypted TOKEN to a hexadecimal string
    encrypted_token_hex = truncated_encrypted_token.hex()

    return encrypted_token_hex

def get_params(secrets_file_path):
    # Define the path to your file
    file_path = './inc/ectf_params.h'

    # Define the search term
    line_to_update = '#define AP_TOKEN'

    # Read the AES key
    aes_key = read_aes_key(secrets_file_path)

    # Read the content of the file
    with open(file_path, "r") as file:
        lines = file.readlines()

    ap_token = None

    # Modify the AP_TOKEN line
    new_content = []
    for line in lines:
        if line_to_update in line:
            # Extract the TOKEN
            ap_token = line.split('"')[1]
            # Encrypt the TOKEN
            encrypted_token = encrypt_token(ap_token, aes_key)
            new_content.append(f'#define AP_TOKEN "{encrypted_token}"\n')  # Change the AP_TOKEN value here
        else:
            new_content.append(line)

    # Write the modified content back to the file
    with open(file_path, 'w') as file:
        file.writelines(new_content)

    print("AP_TOKEN has been updated.")

if __name__ == "__main__":
   if len(sys.argv) != 2:
       print("Usage: python script.py path/to/global_secrets.h")
       sys.exit(1)
   secrets_file_path = sys.argv[1]
   get_params(secrets_file_path)