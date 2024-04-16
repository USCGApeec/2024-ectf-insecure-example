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

def encrypt_pin(pin, key):
    # Pad the PIN to be 16 bytes long
    padded_pin = add_padding(pin.encode())

    # Create AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Encrypt the padded PIN
    encrypted_pin = cipher.encrypt(padded_pin)

    return encrypted_pin

def get_params(secrets_file_path):
   # Define the path to your file
   file_path = './inc/ectf_params.h'

   # Define the search term
   search_term = '#define AP_PIN'

   # Read the AES key
   aes_key = read_aes_key(secrets_file_path)

   # Read the content of the file
   with open(file_path, "r") as file:
       lines = file.readlines()

   ap_pin = None

   # Modify the AP_PIN line
   new_content = []
   for line in lines:
       if search_term in line:
           # Extract the PIN
           ap_pin = line.split('"')[1]
           # Encrypt the PIN
           encrypted_pin = encrypt_pin(ap_pin, aes_key)
           # Convert the encrypted PIN to a hexadecimal string for storage
           encrypted_pin_hex = hexlify(encrypted_pin).decode()
           new_content.append(f'#define AP_PIN "{encrypted_pin_hex}"\n')  # Change the AP_PIN value here
       else:
           new_content.append(line)

   # Write the modified content back to the file
   with open(file_path, 'w') as file:
       file.writelines(new_content)

   print("AP_PIN has been updated.")

if __name__ == "__main__":
   if len(sys.argv) != 2:
       print("Usage: python script.py path/to/global_secrets.h")
       sys.exit(1)
   secrets_file_path = sys.argv[1]
   get_params(secrets_file_path)