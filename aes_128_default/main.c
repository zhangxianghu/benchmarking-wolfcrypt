#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "xtimer.h"

/* Add required includes here */
#include "shell.h"
#include "fmt.h"
#include "crypto/ciphers.h"
#include "crypto/modes/ctr.h"

/* Intermediate encryption/decryption buffers  */
#define BUF_SIZE (64U)
static uint8_t data[BUF_SIZE] = { 0 };
static char buf_str[BUF_SIZE * 2] = { 0 };
static uint8_t ctr_copy[16];

/* Add here the key and the nonce */
static const uint8_t key[] = {
    0x23, 0xA0, 0x18, 0x53, 0xFA, 0xB3, 0x89, 0x23,
    0x65, 0x89, 0x2A, 0xBC, 0x43, 0x99, 0xCC, 0x00
};

static const uint8_t ctr[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

/* Implement the encrypt command handler here */
static int _encrypt_handler_aes128_ctr(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: %s <input to encrypt>\n", argv[0]);
        return 1;
    }

    size_t start = xtimer_now_usec();

    /* Clear intermediate data buffer */
    memset(data, 0, BUF_SIZE);

    /* Copy the nonce in memory */
    memcpy(ctr_copy, ctr, 16);

    /* Encrypt the message */
    cipher_t cipher;
    cipher_init(&cipher, CIPHER_AES_128, key, sizeof(key));
    size_t enc_len = cipher_encrypt_ctr(&cipher, ctr_copy, 0, (uint8_t *)argv[1], strlen(argv[1]), data);

    /* Convert the byte array to a string of hex characters */
    size_t len = fmt_bytes_hex(buf_str, data, enc_len);
    buf_str[len] = 0;

    /* Print the result */
    printf("%s\n", buf_str);

    printf("%lu\n", xtimer_now_usec() - start);

    return 0;
}

/* Implement the decrypt command handler here */
static int _decrypt_handler_aes128_ctr(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: %s <input to decrypt>\n", argv[0]);
        return 1;
    }

    /* Clear intermediate data buffer */
    memset(data, 0, BUF_SIZE);

    /* Copy the nonce in memory */
    memcpy(ctr_copy, ctr, 16);

    /* Convert encrypt message from hex string to byte array */
    size_t len = fmt_hex_bytes(data, argv[1]);

    /* Decrypt the message */
    cipher_t cipher;
    cipher_init(&cipher, CIPHER_AES_128, key, sizeof(key));
    cipher_decrypt_ctr(&cipher, ctr_copy, 0, data, len, (uint8_t *)buf_str);
    buf_str[len] = 0;

    /* Print the result */
    printf("%s\n", buf_str);

    return 0;
}

/* Declare the list of shell commands */
static const shell_command_t shell_commands[] = {
    { "encrypt", "Encrypt input string", _encrypt_handler_aes128_ctr },
    { "decrypt", "Decrypt input string", _decrypt_handler_aes128_ctr },
    { NULL, NULL, NULL }
};

int main(void)
{
    xtimer_sleep(10);
    printf("Start AES-128 encryption task\n");
    /* Configure and start the shell */
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
