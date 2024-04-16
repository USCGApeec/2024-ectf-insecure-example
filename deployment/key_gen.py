import os

#def generated_aes_key():
#    return os.urandom(16)

#def bytes_to_binary(byte_string):
#    return ''.join(format(byte, '08b') for byte in byte_string)

#key = generated_aes_key()
#binary_key = bytes_to_binary(key)

#with open('global_secrets.h', 'a') as header_file:
#    header_file.write(f'#define SECRET "{binary_key}"\n')





# Generate a random AES key (128 bits)
aes_key = os.urandom(16)

# Convert the AES key to a hex string
aes_key_hex = ''.join([f'{byte:02x}' for byte in aes_key])

# Write the key to global_secrets.h
with open('global_secrets.h', 'w') as header_file:
    header_file.write(f'#define SECRET "{aes_key_hex}"\n')
