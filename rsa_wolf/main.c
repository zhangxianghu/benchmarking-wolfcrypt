/* Test RSA encryption and decryption
*  1. If test on IoT devices, change %u to %lu in line: printf("Running time: %u\n", result);
*/

#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include "xtimer.h"
// #include "log.h"
#include "shell.h"
// #include "malloc.h"
#include "ps.h"
#include <unistd.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>

/* start time of a function */
static void time_start(uint32_t* start) {
    *start = xtimer_now_usec();
}

/* running time of a function */
static void time_result_print(uint32_t start) {
    uint32_t result;
    result = xtimer_now_usec() - start;

    printf("Running time: %u\n", result);
}

/* Initialize the secret key */
static unsigned key_size;
static byte* input;
static byte* c_text; 
RsaKey key;

/* Generate a secret key with specific size: 2048, 3072 */
static int _encrypt_handler_keyGen(int argc, char **argv) {

    if (argc < 2) {
        printf("usage: %s [size]\n", argv[0]);
        return 1;
    }

    key_size = (unsigned) (strtoul(argv[1], 0L, 10));
    // if (key_size != 1024 && key_size != 2048 && key_size != 4096) {
    //     printf("Invalid 3DES key size\n");
    //     return -4;
    // }

    // key_size /= 8;
	int ret = 0;
	uint32_t start;
	WC_RNG rng;

	printf("start key generation...\n");
	time_start(&start);

	wc_InitRsaKey(&key, 0);
	wc_InitRng(&rng);
	if (ret != 0) {
        printf("Failed to initialize random number generator\n");
        return -1;
    }

	ret = wc_MakeRsaKey(&key, key_size, 65537, &rng);
	if (ret != 0) {
		printf("test0, %d\n", ret);
		return -10;
	}

	time_result_print(start);
	printf("End key generation!\n");

    ps();

	/* convert to DER format and print out the key */
	/*	
		byte der[4096];
		int derSz = wc_RsaKeyToDer(&key, der, sizeof(der));
		if (derSz < 0)
			return -11;

		for(unsigned i = 0; i < 4096; i++) {
	        printf("%02X ", der[i]);
	    }
	*/

	wc_FreeRng(&rng);
    return 0;
    
}

/* Encrypt a random input with rsa */
static int _encrypt_handler_rsa(int argc, char **argv) { 
    if (argc < 2) {
        printf("usage: %s [input_size_bytes]\n", argv[0]);
        return 1;
    }

    puts("\nInitializing everything...");
    xtimer_sleep(2);

    /* Get input and output size */
    unsigned input_size = (unsigned) (strtoul(argv[1], 0L, 10));
    unsigned out_size = key_size/8;
    
    /* --------------Initialize everything for encryption-------------- */
	int ret = 0;
    uint32_t start;
    WC_RNG rng;
    
    /* Initialize input "input" and output "c_text" */
    c_text = malloc(out_size * (sizeof(byte)));
    input = malloc(out_size * (sizeof(byte)));

    /* Initialize PRG seed */
    wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize random number generator\n");
        return -1;
    }

    /* Initialize random input */
    ret = wc_RNG_GenerateBlock(&rng, input, input_size);
    if (ret != 0)
        return -2;

    printf("Randomly generated input (%d bytes): ", input_size);
    for(unsigned i = 0; i < input_size; i++) {
        printf("%X ", input[i]);
    }
    puts("");


    /* ------------------Encryption start------------------- */
    xtimer_sleep(2);
    puts("\n-----------------------");
    puts("\nEncryption start...");
    xtimer_sleep(1);

    time_start(&start);

    /* return the number bytes written to c_text */
	ret = wc_RsaPublicEncrypt(input, input_size, c_text, out_size, &key, &rng);

	
	// printf("reset rng test %d\n\n", ret);
 //    byte output[16];   //Store the decrypted text
	// // output = malloc(input_size * sizeof(byte));
 //    ret = wc_RsaPrivateDecrypt(c_text, out_size, output, 16, &key);
	
	// printf("Plaintext (%d bytes), %d:", input_size, ret);
 //    for(unsigned i = 0; i < input_size; i++) {
 //        printf("%X ", output[i]);
 //    }
 //    puts("");

    time_result_print(start);
    puts("End Encryption!\n");
    /* ------------------Encryption end--------------------- */
    ps();

    printf("Ciphertext of size %d bytes: ", out_size);
    for(unsigned i = 0; i < out_size; i++) {
        printf("%02X ", c_text[i]);
    }

    printf("\n\n");


	wc_FreeRng(&rng);
    return 0;
}

static int _decrypt_handler_rsa(int argc, char **argv) {
    /* Check argc and print necessary information */
    if (argc < 2) {
         printf("usage: %s [ouput_size]\n", argv[0]);
         return 1;
    }

    unsigned plain_size = (unsigned) (strtoul(argv[1], 0L, 10));
    unsigned c_size = key_size/8;

    printf("\n\nInitializing everything...\n\n");
    xtimer_sleep(2);
    printf("Ciphertext (%d bytes):", c_size);
    for(unsigned i = 0; i < c_size; i++) {
        printf("%02X ", c_text[i]);
    }

    xtimer_sleep(1);

    /* Initialize decryption */
    short ret = 0;
    uint32_t start;
    WC_RNG rng;
    byte* output;   //Store the decrypted text

    output = malloc(plain_size * sizeof(byte));

    wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize random number generator\n");
        return -1;
    }

    printf("\n-----------------------");
    printf("\nStart decryption in 2 seconds...\n");
    xtimer_sleep(2);

    /* Start decryption */
    time_start(&start);

	ret = wc_RsaSetRNG(&key, &rng);		// When WC_RSA_BLINDING is enabled, must set key with rng before decryption
    ret = wc_RsaPrivateDecrypt(c_text, c_size, output, plain_size, &key);

    time_result_print(start);

    ps();

    printf("End Decryption!\n\n");
    printf("Print plaintext in 2 seconds...\n");
    xtimer_sleep(2);
    printf("Plaintext (%d bytes):", plain_size);
    for(unsigned i = 0; i < plain_size; i++) {
        printf("%02X ", output[i]);
    }
    puts("");

    printf("\n\n");
    free(output);
    return ret;
}

/* Declare the list of shell commands */
static const shell_command_t shell_commands[] = {
    { "keygen", "Generate key", _encrypt_handler_keyGen },
    { "encrypt", "Encrypt input string", _encrypt_handler_rsa },
    { "decrypt", "Decrypt input string", _decrypt_handler_rsa },
    { NULL, NULL, NULL }
};

int main(void) {

    /* Uncomment this if test on SAMR21 */
    // xtimer_sleep(5);

    puts("================================");
    puts("Start testing for RSA encryption");
    puts("================================\n");

    puts("Key size for RSA is 2048 bits (can also test 3072 bits).\n\n");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    
    printf("\n");

    return 0;
}









