import os

def bytes_to_binary(byte_string):
    return ''.join(format(byte, '08b') for byte in byte_string)

def generated_nonce():
    return os.urandom(4)

def remove_line(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()

    # Remove the last line
    lines = lines[:-1]

    # Write the modified content back to the file
    with open(filename, 'w') as file:
        file.writelines(lines)


def update_file(filename):
    found_comp_1 = True
    found_comp_2 = True
    with open(filename, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if "#define COMP_1_NONCE" in line:
                found_comp_1 = False
            if "#define COMP_2_NONCE" in line:
                found_comp_2 = False

    with open(filename, 'a') as file:
        with open('./inc/ectf_params.h','a') as params:
            if found_comp_1:
                comp_1_nonce = bytes_to_binary(generated_nonce())
                file.write("#define COMP_1_NONCE ")
                file.write(comp_1_nonce)
                file.write("\n")
                params.write("#define COMP_NONCE ")
                params.write(comp_1_nonce)
                params.write("\n#endif")
            elif found_comp_2:
                comp_2_nonce = bytes_to_binary(generated_nonce())
                file.write("#define COMP_2_NONCE ")
                file.write(comp_2_nonce)
                file.write("\n")
                params.write("#define COMP_NONCE ")
                params.write(comp_2_nonce)
                params.write("\n#endif")

remove_line('./inc/ectf_params.h')

update_file('../deployment/global_secrets.h')