/**
 * @file application_processor.c
 * @author Jacob Doll
 * @brief eCTF AP Example Design Implementation
 * @date 2024
 *
 * This source file is part of an example system for MITRE's 2024 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2024 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2024 The MITRE Corporation
 */

#include "board.h"
#include "i2c.h"
#include "icc.h"
#include "led.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "nvic_table.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "board_link.h"
#include "simple_flash.h"
#include "host_messaging.h"
#ifdef CRYPTO_EXAMPLE
#include "simple_crypto.h"
#endif

#ifdef POST_BOOT
#include "mxc_delay.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#endif

// Includes from containerized build
#include "ectf_params.h"
#include "global_secrets.h"

/********************************* CONSTANTS **********************************/

// Passed in through ectf-params.h
// Example of format of ectf-params.h shown here
/*
#define AP_PIN "123456"
#define AP_TOKEN "0123456789abcdef"
#define COMPONENT_IDS 0x11111124, 0x11111125
#define COMPONENT_CNT 2
#define AP_BOOT_MSG "Test boot message"
*/

// Flash Macros
#define FLASH_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
#define FLASH_MAGIC 0xDEADBEEF

// Library call return types
#define SUCCESS_RETURN 0
#define ERROR_RETURN -1

/******************************** TYPE DEFINITIONS ********************************/
// Data structure for sending commands to component
// Params allows for up to MAX_I2C_MESSAGE_LEN - 1 bytes to be send
// along with the opcode through board_link. This is not utilized by the example
// design but can be utilized by your design.
typedef struct {
    uint8_t opcode;
    uint8_t params[MAX_I2C_MESSAGE_LEN-1];
} command_message;

// Data type for receiving a validate message
typedef struct {
    uint32_t component_id;
} validate_message;

// Data type for receiving a scan message
typedef struct {
    uint32_t component_id;
} scan_message;

// Datatype for information stored in flash
typedef struct {
    uint32_t flash_magic;
    uint32_t component_cnt;
    uint32_t component_ids[32];
} flash_entry;

// Datatype for commands sent to components
typedef enum {
    COMPONENT_CMD_NONE,
    COMPONENT_CMD_SCAN,
    COMPONENT_CMD_VALIDATE,
    COMPONENT_CMD_BOOT,
    COMPONENT_CMD_ATTEST
} component_cmd_t;

/********************************* GLOBAL VARIABLES **********************************/
// Variable for information stored in flash memory
flash_entry flash_status;
size_t packet_size = BLOCK_SIZE * 15;

/******************************* POST BOOT FUNCTIONALITY *********************************/
/**
 * @brief Secure Send 
 * 
 * @param address: i2c_addr_t, I2C address of recipient
 * @param buffer: uint8_t*, pointer to data to be send
 * @param len: uint8_t, size of data to be sent 
 * 
 * Securely send data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.

*/
int secure_send(uint8_t address, uint8_t* buffer, uint8_t len) {
    print_debug("Attempting send");

    if (len > packet_size) {
        print_debug("len too big");
        return -1;
    }

    // need to do coles key here
    uint8_t key[KEY_SIZE];
    bzero(key, KEY_SIZE);

    print_debug("Created key");

    //memcpy(key, AES_KEY, KEY_SIZE);

    uint8_t padded_buffer[packet_size];
    uint8_t encrypted_buffer[packet_size];
    print_debug("Created buffers");

    memcpy(padded_buffer, buffer, len);
    print_debug("Copied to buffers");

    for (int i = len; i < packet_size; i++) {
        padded_buffer[i] = '\0';
    }
    print_debug("Padded buffer");
    
    encrypt_sym((uint8_t*)padded_buffer, packet_size, key, encrypted_buffer);
    print_debug("encrpyted");

    return send_packet(address, packet_size, encrypted_buffer); 

    //return send_packet(address, len, buffer);
}

/**
 * @brief Secure Receive
 * 
 * @param address: i2c_addr_t, I2C address of sender
 * @param buffer: uint8_t*, pointer to buffer to receive data to
 * 
 * @return int: number of bytes received, negative if error
 * 
 * Securely receive data over I2C. This function is utilized in POST_BOOT functionality.
 * This function must be implemented by your team to align with the security requirements.
*/
int secure_receive(i2c_addr_t address, uint8_t* buffer) {
    uint8_t key[KEY_SIZE];
    bzero(key, KEY_SIZE); 
    //memcpy(key, AES_KEY, KEY_SIZE);

    poll_and_receive_packet(address, buffer);

    decrypt_sym(buffer, packet_size, key, buffer);

    size_t pad = 0;
    for (int i = packet_size - 1; i >= 0; i--) {
        if (buffer[i] == '\0')
            pad++;
        else
            break;
    }

    return (packet_size - pad);
}

/**
 * @brief Get Provisioned IDs
 * 
 * @param uint32_t* buffer
 * 
 * @return int: number of ids
 * 
 * Return the currently provisioned IDs and the number of provisioned IDs
 * for the current AP. This functionality is utilized in POST_BOOT functionality.
 * This function must be implemented by your team.
*/
int get_provisioned_ids(uint32_t* buffer) {
    memcpy(buffer, flash_status.component_ids, flash_status.component_cnt * sizeof(uint32_t));
    return flash_status.component_cnt;
}

/********************************* UTILITIES **********************************/

// Initialize the device
// This must be called on startup to initialize the flash and i2c interfaces
void init() {

    // Enable global interrupts    
    __enable_irq();

    // Setup Flash
    flash_simple_init();

    // Test application has been booted before
    flash_simple_read(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

    // Write Component IDs from flash if first boot e.g. flash unwritten
    if (flash_status.flash_magic != FLASH_MAGIC) {
        print_debug("First boot, setting flash!\n");

        flash_status.flash_magic = FLASH_MAGIC;
        flash_status.component_cnt = COMPONENT_CNT;
        uint32_t component_ids[COMPONENT_CNT] = {COMPONENT_IDS};
        memcpy(flash_status.component_ids, component_ids, 
            COMPONENT_CNT*sizeof(uint32_t));

        flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));
    }
    
    // Initialize board link interface
    board_link_init();
}

// Send a command to a component and receive the result
int issue_cmd(i2c_addr_t addr, uint8_t* transmit, uint8_t* receive) {
    // Send message
    //int result = send_packet(addr, sizeof(uint8_t), transmit);
    int result = secure_send(addr, transmit, sizeof(uint8_t));
    if (result == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    
    // Receive message
    int len = secure_receive(addr, receive);
    //int len = poll_and_receive_packet(addr, receive);
    if (len == ERROR_RETURN) {
        return ERROR_RETURN;
    }
    return len;
}

/******************************** COMPONENT COMMS ********************************/

int scan_components() {
    // Print out provisioned component IDs
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        print_info("P>0x%08x\n", flash_status.component_ids[i]);
    }

    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Scan scan command to each component 
    for (i2c_addr_t addr = 0x8; addr < 0x78; addr++) {
        // I2C Blacklist:
        // 0x18, 0x28, and 0x36 conflict with separate devices on MAX78000FTHR
        if (addr == 0x18 || addr == 0x28 || addr == 0x36) {
            continue;
        }

        // Create command message 
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_SCAN;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);

        // Success, device is present
        if (len > 0) {
            scan_message* scan = (scan_message*) receive_buffer;
            print_info("F>0x%08x\n", scan->component_id);
        }
    }
    print_success("List\n");
    return SUCCESS_RETURN;
}

int validate_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send validate command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);

        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_VALIDATE;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not validate component\n");
            return ERROR_RETURN;
        }

        validate_message* validate = (validate_message*) receive_buffer;
        // Check that the result is correct
        if (validate->component_id != flash_status.component_ids[i]) {
            print_error("Component ID: 0x%08x invalid\n", flash_status.component_ids[i]);
            return ERROR_RETURN;
        }
    }
    return SUCCESS_RETURN;
}

int boot_components() {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Send boot command to each component
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        // Set the I2C address of the component
        i2c_addr_t addr = component_id_to_i2c_addr(flash_status.component_ids[i]);
        
        // Create command message
        command_message* command = (command_message*) transmit_buffer;
        command->opcode = COMPONENT_CMD_BOOT;
        
        // Send out command and receive result
        int len = issue_cmd(addr, transmit_buffer, receive_buffer);
        if (len == ERROR_RETURN) {
            print_error("Could not boot component\n");
            return ERROR_RETURN;
        }

        // Print boot message from component
        print_info("0x%08x>%s\n", flash_status.component_ids[i], receive_buffer);
    }
    return SUCCESS_RETURN;
}

uint32_t key[4]; // Array to hold the key as four uint32_t variables

void initialize_key() {
    // Initialize the key with your 128-bit value
    char stoke_hex[] = SECRET;
    for (int i = 0; i < 4; ++i) {
        sscanf(stoke_hex + (i * 8), "%8x", &key[i]);
    }
}

void decrypt_line(uint8_t *encrypted_data, uint8_t *decrypted_data) {
    // Decrypt the data using the AES decryption function
    initialize_key(); // Initialize the key

    uint8_t key_bytes[KEY_SIZE]; // Buffer to hold the key in byte form

    // Convert the uint32_t key to byte array
    for (int i = 0; i < 4; ++i) {
        key_bytes[i * 4] = (key[i] >> 24) & 0xFF;
        key_bytes[i * 4 + 1] = (key[i] >> 16) & 0xFF;
        key_bytes[i * 4 + 2] = (key[i] >> 8) & 0xFF;
        key_bytes[i * 4 + 3] = key[i] & 0xFF;
    }

    //encrypted_data[strcspn(encrypted_data, "\n\r")] ='\0';

    decrypt_sym(encrypted_data, BLOCK_SIZE, key_bytes, decrypted_data);
}

void decrypt_and_print_attestation_data(uint8_t *receive_buffer) {

    uint8_t decrypted_loc[BLOCK_SIZE], decrypted_date[BLOCK_SIZE], decrypted_cust[BLOCK_SIZE];

    char *loc_ptr, *date_ptr, *cust_ptr;
    char loc[33], date[33], cust[33];

    // Finding the pointers to the beginning of each substring
    loc_ptr = strstr(receive_buffer, "LOC>");
    date_ptr = strstr(receive_buffer, "DATE>");
    cust_ptr = strstr(receive_buffer, "CUST>");

    if (loc_ptr && date_ptr && cust_ptr) {
        // Copying the values into separate variables
        //upgrade to strncpy for safety
        strcpy(loc, loc_ptr + 4);
        strcpy(date, date_ptr + 5);
        strcpy(cust, cust_ptr + 5);

        // Truncating the strings at newline characters if present
        char *newline_loc = strchr(loc, '\n');
        if (newline_loc)
            *newline_loc = '\0';

        char *newline_date = strchr(date, '\n');
        if (newline_date)
            *newline_date = '\0';

        char *newline_cust = strchr(cust, '\n');
        if (newline_cust)
            *newline_cust = '\0';
    }

    uint8_t loc_bytes[BLOCK_SIZE];
    uint8_t date_bytes[BLOCK_SIZE];
    uint8_t cust_bytes[BLOCK_SIZE]; 

    for (int i = 0; i < BLOCK_SIZE*2; i += 2) {
        sscanf(&loc[i], "%2hhx", &loc_bytes[i / 2]);
    }

    for (int i = 0; i < BLOCK_SIZE*2; i += 2) {
        sscanf(&date[i], "%2hhx", &date_bytes[i / 2]);
    }

    for (int i = 0; i < BLOCK_SIZE*2; i += 2) {
        sscanf(&cust[i], "%2hhx", &cust_bytes[i / 2]);
    }

    // Decrypt each line separately
    decrypt_line((uint8_t*)loc_bytes, decrypted_loc);
    decrypt_line((uint8_t*)date_bytes, decrypted_date);
    decrypt_line((uint8_t*)cust_bytes, decrypted_cust);

    char reconstructed_buffer[256];
    sprintf((char*)reconstructed_buffer, "LOC>%s\nDATE>%s\nCUST>%s\n", (char*)decrypted_loc, (char*)decrypted_date, (char*)decrypted_cust);

    int i, j = 0;
    int recon_size = strlen(reconstructed_buffer);
    for (i = 0; i < recon_size; i++) {
        if (reconstructed_buffer[i] != '\0' && reconstructed_buffer[i] != '\a') {
            reconstructed_buffer[j++] = reconstructed_buffer[i];
        }
    }

    // Print out attestation data 
    print_info("%s", reconstructed_buffer);
}

int attest_component(uint32_t component_id) {
    // Buffers for board link communication
    uint8_t receive_buffer[MAX_I2C_MESSAGE_LEN];
    uint8_t transmit_buffer[MAX_I2C_MESSAGE_LEN];

    // Set the I2C address of the component
    i2c_addr_t addr = component_id_to_i2c_addr(component_id);

    // Create command message
    command_message* command = (command_message*) transmit_buffer;
    command->opcode = COMPONENT_CMD_ATTEST;

    // Send out command and receive result
    int len = issue_cmd(addr, transmit_buffer, receive_buffer);
    if (len == ERROR_RETURN) {
        print_error("Could not attest component\n");
        return ERROR_RETURN;
    }
    
    print_info("C>0x%08x\n", component_id);
    decrypt_and_print_attestation_data(receive_buffer);

    return SUCCESS_RETURN;
}

/********************************* AP LOGIC ***********************************/

// Boot sequence
// YOUR DESIGN MUST NOT CHANGE THIS FUNCTION
// Boot message is customized through the AP_BOOT_MSG macro
void boot() {
    // Example of how to utilize included simple_crypto.h
    #ifdef CRYPTO_EXAMPLE
    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char* data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    
    // Zero out the key
    bzero(key, BLOCK_SIZE);

    // Encrypt example data and print out
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext); 
    print_debug("Encrypted data: ");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results 
    uint8_t hash_out[HASH_SIZE];
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: ");
    print_hex_debug(hash_out, HASH_SIZE);
    
    // Decrypt the encrypted message and print out
    uint8_t decrypted[BLOCK_SIZE];
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    print_debug("Decrypted message: %s\r\n", decrypted);
    #endif

    // POST BOOT FUNCTIONALITY
    // DO NOT REMOVE IN YOUR DESIGN
    #ifdef POST_BOOT
        POST_BOOT
    #else
    // Everything after this point is modifiable in your design
    // LED loop to show that boot occurred
    while (1) {
        LED_On(LED1);
        MXC_Delay(500000);
        LED_On(LED2);
        MXC_Delay(500000);
        LED_On(LED3);
        MXC_Delay(500000);
        LED_Off(LED1);
        MXC_Delay(500000);
        LED_Off(LED2);
        MXC_Delay(500000);
        LED_Off(LED3);
        MXC_Delay(500000);
    }
    #endif
}

uint32_t pin[4]; // Array to hold the pin as four uint32_t variables
uint32_t token[4]; // Array to hold the token as four uint32_t variables

void initialize_pin() {
    // Initialize the key with your 128-bit value
    char spin_hex[] = AP_PIN;
    for (int i = 0; i < 4; ++i) {
        sscanf(spin_hex + (i * 8), "%8x", &pin[i]);
    }
}

void initialize_token() {
    // Initialize the key with your 128-bit value
    char stoke_hex[] = AP_TOKEN;
    for (int i = 0; i < 4; ++i) {
        sscanf(stoke_hex + (i * 8), "%8x", &token[i]);
    }
}

int validate_pin() {
    initialize_key(); // Initialize the key
    initialize_pin(); //Initialize the pin

    uint8_t key_bytes[KEY_SIZE]; // Buffer to hold the key in byte form

    // Convert the uint32_t key to byte array
    for (int i = 0; i < 4; ++i) {
        key_bytes[i * 4] = (key[i] >> 24) & 0xFF;
        key_bytes[i * 4 + 1] = (key[i] >> 16) & 0xFF;
        key_bytes[i * 4 + 2] = (key[i] >> 8) & 0xFF;
        key_bytes[i * 4 + 3] = key[i] & 0xFF;
    }

    uint8_t pin_bytes[BLOCK_SIZE]; // Buffer to hold the key in byte form

    // Convert the uint32_t pin to byte array
    for (int i = 0; i < 4; ++i) {
        pin_bytes[i * 4] = (pin[i] >> 24) & 0xFF;
        pin_bytes[i * 4 + 1] = (pin[i] >> 16) & 0xFF;
        pin_bytes[i * 4 + 2] = (pin[i] >> 8) & 0xFF;
        pin_bytes[i * 4 + 3] = pin[i] & 0xFF;
    }

    char buf[50];
    recv_input("Enter pin: ", buf);

    memset(buf+strlen(buf), '\0', BLOCK_SIZE-strlen(buf));

    buf[strcspn(buf, "\n\r")] ='\0';
    
    uint8_t encrypted_input[BLOCK_SIZE];

    // Assuming encrypt_sym function takes uint8_t key[] as input
    encrypt_sym(buf, BLOCK_SIZE, key_bytes, encrypted_input);

    if (memcmp(pin_bytes, encrypted_input, BLOCK_SIZE) == 0) {
        print_debug("Pin Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Pin!\n");
    return ERROR_RETURN;
}

// Function to validate the replacement token
int validate_token() {
    initialize_key(); // Initialize the key
    initialize_token(); //Initialize the pin

    uint8_t key_bytes[KEY_SIZE]; // Buffer to hold the key in byte form

    // Convert the uint32_t key to byte array
    for (int i = 0; i < 4; ++i) {
        key_bytes[i * 4] = (key[i] >> 24) & 0xFF;
        key_bytes[i * 4 + 1] = (key[i] >> 16) & 0xFF;
        key_bytes[i * 4 + 2] = (key[i] >> 8) & 0xFF;
        key_bytes[i * 4 + 3] = key[i] & 0xFF;
    }

    uint8_t token_bytes[BLOCK_SIZE]; // Buffer to hold the token in byte form

    // Convert the uint32_t token to byte array
    for (int i = 0; i < 4; ++i) {
        token_bytes[i * 4] = (token[i] >> 24) & 0xFF;
        token_bytes[i * 4 + 1] = (token[i] >> 16) & 0xFF;
        token_bytes[i * 4 + 2] = (token[i] >> 8) & 0xFF;
        token_bytes[i * 4 + 3] = token[i] & 0xFF;
    }

    char buf[50];
    recv_input("Enter token: ", buf);

    memset(buf+strlen(buf), '\0', BLOCK_SIZE-strlen(buf));

    buf[strcspn(buf, "\n\r")] ='\0';
    
    uint8_t encrypted_input[BLOCK_SIZE];

    // Assuming encrypt_sym function takes uint8_t token[] as input
    encrypt_sym(buf, BLOCK_SIZE, key_bytes, encrypted_input);

    if (memcmp(token_bytes, encrypted_input, BLOCK_SIZE) == 0) {
        print_debug("Token Accepted!\n");
        return SUCCESS_RETURN;
    }
    print_error("Invalid Token!\n");
    return ERROR_RETURN;
}

// Boot the components and board if the components validate
void attempt_boot() {
    if (validate_components()) {
        print_error("Components could not be validated\n");
        return;
    }
    print_debug("All Components validated\n");
    if (boot_components()) {
        print_error("Failed to boot all components\n");
        return;
    }
    // Print boot message
    // This always needs to be printed when booting
    print_info("AP>%s\n", AP_BOOT_MSG);
    print_success("Boot\n");
    // Boot
    boot();
}

// Replace a component if the PIN is correct
void attempt_replace() {
    char buf[50];

    if (validate_token()) {
        return;
    }

    uint32_t component_id_in = 0;
    uint32_t component_id_out = 0;

    recv_input("Component ID In: ", buf);
    sscanf(buf, "%x", &component_id_in);
    recv_input("Component ID Out: ", buf);
    sscanf(buf, "%x", &component_id_out);

    // Find the component to swap out
    for (unsigned i = 0; i < flash_status.component_cnt; i++) {
        if (flash_status.component_ids[i] == component_id_out) {
            flash_status.component_ids[i] = component_id_in;

            // write updated component_ids to flash
            flash_simple_erase_page(FLASH_ADDR);
            flash_simple_write(FLASH_ADDR, (uint32_t*)&flash_status, sizeof(flash_entry));

            print_debug("Replaced 0x%08x with 0x%08x\n", component_id_out,
                    component_id_in);
            print_success("Replace\n");
            return;
        }
    }

    // Component Out was not found
    print_error("Component 0x%08x is not provisioned for the system\r\n",
            component_id_out);
}

// Attest a component if the PIN is correct
void attempt_attest() {
    char buf[50];

    if (validate_pin()) {
        return;
    }
    uint32_t component_id;
    recv_input("Component ID: ", buf);
    sscanf(buf, "%x", &component_id);
    if (attest_component(component_id) == SUCCESS_RETURN) {
        print_success("Attest\n");
    }
}

/*********************************** MAIN *************************************/

int main() {
    // Initialize board
    init();

    // Print the component IDs to be helpful
    // Your design does not need to do this
    print_info("Application Processor Started\n");

    // Handle commands forever
    char buf[100];
    while (1) {
        recv_input("Enter Command: ", buf);

        // Execute requested command
        if (!strcmp(buf, "list")) {
            scan_components();
        } else if (!strcmp(buf, "boot")) {
            attempt_boot();
        } else if (!strcmp(buf, "replace")) {
            attempt_replace();
        } else if (!strcmp(buf, "attest")) {
            attempt_attest();
        } else {
            print_error("Unrecognized command '%s'\n", buf);
        }
    }

    // Code never reaches here
    return 0;
}
