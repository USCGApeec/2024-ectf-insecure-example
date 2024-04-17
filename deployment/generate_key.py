import os

def generated_aes_key():
    return os.urandom(16)

def bytes_to_binary(byte_string):
    return ''.join(format(byte, '08b') for byte in byte_string)

def generated_nonce():
    return os.urandom(4)

key = generated_aes_key()
binary_key = bytes_to_binary(key)

print ("#define AES_KEY ", binary_key)
print ("#define AP_NONCE ", bytes_to_binary(generated_nonce()))



