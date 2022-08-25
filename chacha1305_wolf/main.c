/* Test chacha1305 encryption and decryption, only provides 256-bit security level
*  1. If test on IoT devices, change %u to %lu in line: printf("Running time: %u\n", result);
*/

#include <stdio.h>
#include <string.h>
#include "xtimer.h"
#include "shell.h"
#include <unistd.h>
#include "ps.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/Chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

/* Define salt size for PRG */
#define SALT_SIZE 8
#define ADD_SIZE 16

/* Initialize the secret key */
// static short mode;
static unsigned key_size;
static unsigned input_size;
static byte* key;
static byte* c_text; 
static byte tag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
// static byte* aes_nonce;                                  // Nonce for CCM and GCM
// static byte tag[AES_BLOCK_SIZE];                         // Buffer used to store the authentication tag
static byte ivchacha[CHACHA20_POLY1305_AEAD_IV_SIZE];       // IV
static byte authIn[ADD_SIZE];         // Additional authenticated data 

/* start time of a function */
static void time_start(uint32_t* start) {
    *start = xtimer_now_usec();
}

/* running time of a function */
// static void time_result_print(uint32_t start) {
//     uint32_t result;
//     result = xtimer_now_usec() - start;

//     printf("Running time: %lu\n", result);
// }

static uint32_t time_result_return(uint32_t start) {
    uint32_t result;
    result = xtimer_now_usec() - start;

    // printf("*** Runninsg time: %lu ****\n", result);
    // printf("*** Running time: %lu ****\n", result);
    // printf("*** Running time: %lu ****\n", result);

    return result;
}

//test vars
static unsigned test_num;
static unsigned key_result;
static unsigned en_result;
static unsigned de_result;

/* Generate a secret key with specific size: 128, 192, 256 */
static int _encrypt_handler_keyGen(int argc, char **argv) {

    if (argc < 2) {
        // printf("Keygen usage: %s [size]\n", argv[1]);
        return 1;
    }
    int ret;
    WC_RNG rng;
    uint32_t start;

    key_size = (unsigned) (strtoul(argv[1], 0L, 10));
    if (key_size != 256) {
        /* if the entered size does not match acceptable size */
        printf("Invalid Chacha20 key size.\n");
        puts("Key size for Chacha20: 256 bits.");
        return -4;
    }

    key_size /= 8;

    // puts("Start key generation...");
    // xtimer_sleep(1);    
    // printf("Key generated with size %d!\n", key_size * 8);

    // Start time
    time_start(&start);

    key = malloc(key_size*(sizeof(byte)));
    
    // Hardcode password
    char* passwd = "passwordpasswordpasswordpassword";

    /* Hardcode salt */
    // byte salt[] = { 0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06 }; 

    /* Or generate salt randomly */
    byte salt[SALT_SIZE];

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize random number generator\n");
        return -1;
    }
    
    ret = wc_RNG_GenerateBlock(&rng, salt, SALT_SIZE);
    if (ret != 0)
        return -2;
    
    // Generate key with PBKDF2
    ret = wc_PBKDF2(key, (byte*)passwd, (int)XSTRLEN(passwd), salt, (int)sizeof(salt), 1024, key_size, WC_SHA256);

    if (ret != 0) {
        return ret;
    }

    // print running time
    // time_result_print(start);
    key_result = time_result_return(start);
    // puts("End key generation...\n");

    // ps();

    // for(unsigned i = 0; i < key_size; i++) {
    //     printf("%02X ", key[i]);
    // }
    
    // printf("\n\n");
    wc_FreeRng(&rng); 
    return 0;
}

/* Encrypt a random input with Chacha20_poly1305 */

static int _encrypt_handler_chacha20poly1305(int argc, char **argv) { 
    if (argc < 2) {
        printf("usage: %s [input_size_bytes]\n", argv[0]);
        return 1;
    }

    // printf("Encrypt Arg 1 is: %s \n", argv[1]);

    /* print out encryption key */
    // puts("\nInitializing everything...");
    // xtimer_sleep(2);
    // printf("\nEncryption key is: ");
    // for(unsigned i = 0; i < key_size; i++) {
    //     printf("%02X ", key[i]);
    // }
    // printf("\n");

    input_size = (unsigned) (strtoul(argv[1], 0L, 10));

    /* Initialize variables */    
    int ret = 0;
    uint32_t start;
    WC_RNG rng;
    byte input[input_size]; 

    /* --------------Initialize everything for encryption-------------- */
    /* Initialize ciphertext */
    c_text = malloc(input_size * (sizeof(byte)));

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

    // printf("Randomly generated input (%d bytes): ", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%02X ", input[i]);
    // }
    // puts("");

    /* Initialize 12 bytes random IV */
    ret = wc_RNG_GenerateBlock(&rng, ivchacha, CHACHA20_POLY1305_AEAD_IV_SIZE);
    if (ret != 0)
        return -2;

    // printf("Random IV (%d bytes): ", CHACHA20_POLY1305_AEAD_IV_SIZE);
    // for(unsigned i = 0; i < CHACHA20_POLY1305_AEAD_IV_SIZE; i++) {
    //     printf("%02X ", ivchacha[i]);
    // }
    // puts("");

    /* Initialize 16 bytes additional authenticated data */
    ret = wc_RNG_GenerateBlock(&rng, authIn, ADD_SIZE);
    if (ret != 0)
        return -2;

    // printf("Random authenticated data (%d bytes): ", ADD_SIZE);
    // for(unsigned i = 0; i < ADD_SIZE ; i++) {
    //     printf("%02X ", authIn[i]);
    // }
    // puts("");

    /* ------------------Encryption start------------------- */
    // xtimer_sleep(2);
    // puts("\n-----------------------");
    // printf("\nEncryption start in 1 second...\n");
    // xtimer_sleep(1);
    time_start(&start);

    ret = wc_ChaCha20Poly1305_Encrypt(key, ivchacha, authIn, ADD_SIZE, input, input_size, c_text, tag);
    if (ret < 0) {
        printf("Encryption error, code: %d\n", ret);
        return ret;
    }

    // time_result_print(start);
    en_result = time_result_return(start);
    // puts("End Encryption!\n");
    // puts("\n-----------------------\n");
    /* ------------------Encryption end--------------------- */

    // ps();

    /* Print out ciphertext and authentication tag */
    // printf("Ciphertext of size %d\n", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%02X ", c_text[i]);
    // }
    // printf("\n\n");

    // printf("Authentication tag (%d bytes):\n", CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    // for(unsigned i = 0; i < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE; i++) {
    //     printf("%02X ", tag[i]);
    // }
    // printf("\n\n");

    wc_FreeRng(&rng); 
    return 0;
}

/* ============================================================ 
*  ============================================================ 
*  ============================================================ 
*/


/* Decryption for Chacha20_poly1305 */
static int _decrypt_handler_chacha20poly1305(int argc, char **argv) {

    /* Check argc and print necessary information */
    if (argc < 2) {
         printf("usage: %s [cipher]\n", argv[0]);
         return 1;
    }

    /* Print out decryption information */
    // printf("\n\nInitializing everything...\n\n");
    // xtimer_sleep(2);
    // printf("Ciphertext (%d bytes):", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%02X ", c_text[i]);
    // }
    // puts("");

    // printf("\nDecryption key (%d bytes): ", key_size);
    // for(unsigned i = 0; i < key_size; i++) {
    //     printf("%02X ", key[i]);
    // }
    // puts("");

    // printf("Authentication tag (%d bytes):", CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    // for(unsigned i = 0; i < CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE; i++) {
    //     printf("%02X ", tag[i]);
    // }
    // puts("");

    // printf("IV (%d bytes): ", CHACHA20_POLY1305_AEAD_IV_SIZE);
    // for(unsigned i = 0; i < CHACHA20_POLY1305_AEAD_IV_SIZE; i++) {
    //     printf("%02X ", ivchacha[i]);
    // }
    // puts("");

    // printf("Random authenticated data (%d bytes): ", ADD_SIZE);
    // for(unsigned i = 0; i < ADD_SIZE ; i++) {
    //     printf("%02X ", authIn[i]);
    // }
    // puts("");

    /* Initialize decryption */
    int ret;
    uint32_t start;
    byte* output;   //Store the decrypted text

    output = malloc(input_size * sizeof(byte));

    // printf("\n-----------------------");
    // printf("\nStart decryption of in 1 seconds...\n");
    // xtimer_sleep(1);

    /* Start decryption */
    time_start(&start);

    ret = wc_ChaCha20Poly1305_Decrypt(key, ivchacha, authIn, ADD_SIZE, c_text, input_size, tag, output);
    if (ret < 0) {
        printf("Decryption error, code: %d\n", ret);
        return ret;
    }

    // time_result_print(start);
    de_result = time_result_return(start);
    // puts("End Decryption!\n\n");

    // ps(); 
    
    // printf("Print plaintext in 1 seconds...\n");
    // xtimer_sleep(1);
    // printf("Plaintext (%d bytes):", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%02X ", output[i]);
    // }
    // puts("");

    // free(output);
    return 0;
}

static int _etest_handler_aes(int argc, char **argv) { 
    if (argc < 3) {
        printf("usage: %s [input_size_bytes] [number_of_tests] \n", argv[0]);
        return 1;
    }

    // Get encryption mode
    // if(strcmp(argv[1], "cbc") == 0) {
    //     mode = 1;
    // } else if (strcmp(argv[1], "ctr") == 0) {
    //     mode = 2;
    // } else if (strcmp(argv[1], "cfb") == 0) {
    //     mode = 3;
    // }

    // Get input size
    input_size = (unsigned) (strtoul(argv[1], 0L, 10));

    //manually input key size so we don't get stack overflow
    //choices are 128, 192, 256
    char *keysize[2] = {"blank","256"}; 

    // Get number of tests
    test_num = (unsigned) (strtoul(argv[2], 0L, 10));
    // printf("Number of tests is %d\n", test_num);
    // printf("*** Keysize is %s ***\n", keysize[0]);

    // int ret = 0;  
    // uint32_t start;
    // WC_RNG rng;
    // Aes aes;
    // byte input[input_size]; 

    // printf("Test mode is %d\n", mode);

    //allocate memory for keygen results
    uint32_t key_total = 0;
    float key_diff = 0;
    float key_std_dev = 0;
    float key_float_avg = 0;
    uint32_t* key_test_results = (uint32_t*)calloc(test_num, sizeof(uint32_t));
    float* key_std_dev_array = (float*)calloc(test_num, sizeof(float));

    // allocate memory for encrypt test results
    uint32_t total = 0;
    float diff = 0;
    float std_dev = 0;
    float float_avg = 0;
    uint32_t* test_results = (uint32_t*)calloc(test_num, sizeof(uint32_t));
    float* std_dev_array = (float*)calloc(test_num, sizeof(float));

    //allocate memory for decrypt test results
    uint32_t de_total = 0;
    float de_diff = 0;
    float de_std_dev = 0;
    float de_float_avg = 0;
    uint32_t* de_test_results = (uint32_t*)calloc(test_num, sizeof(uint32_t));
    float* de_std_dev_array = (float*)calloc(test_num, sizeof(float)); 

    float key_testr = 0;
    float testr = 0;
    float de_testr = 0;   

    /* ---------- Run the specified number of tests ---------- */
    for(unsigned i = 0; i < test_num; i++) {

        // generate a key
        // key_test_results[i] = _encrypt_handler_keyGen(1, keysize);
         _encrypt_handler_keyGen(2, keysize);
        key_test_results[i] = key_result;

        /* ---- Encrypt ------ */
        // test_results[i] = _encrypt_handler_des3(argc, argv);
        _encrypt_handler_chacha20poly1305(argc, argv);
        test_results[i] = en_result;

        /* ------------------- Decrypt ----------------------- */
        // de_test_results[i] = _decrypt_handler_des3(argc, argv);
        _decrypt_handler_chacha20poly1305(argc, argv);
        de_test_results[i] = de_result;

        //print results
        // printf("keygen %2d: %ld\n", i+1, key_test_results[i]);
        // printf("encrypt %2d: %ld\n", i+1, test_results[i]);
        // printf("decrypt %2d: %ld\n", i+1, de_test_results[i]);
    }


    /* ----------- Finding Mean of Encrypt Test Results ------------------ */
    for(unsigned i = 0; i < test_num; i++) {
        key_total += key_test_results[i];
        total += test_results[i];
        de_total += de_test_results[i];
        // printf("keygen %2d: %ld\n", i+1, key_test_results[i]);
        // printf("encrypt %2d: %ld\n", i+1, test_results[i]);
        // printf("decrypt %2d: %ld\n", i+1, de_test_results[i]);
        // fprintf(fptr, "%2d: %ld\n", i+1, test_results[i]);
    }
    //Find key average after making sure key total isn't 0
    if (key_total == 0) {
        printf("\n **** Key Avg == 0 *****");
        // fprintf(fptr, "\n **** Avg == 0 *****");
    }
    else {
        key_float_avg = (float)key_total / test_num;
        printf("\n *** Key Gen average: %f *****", key_float_avg);
        printf("\n *** Key Gen average: %f *****", key_float_avg);
        // fprintf(fptr, "\n *** Average test results are: %ld ***** \n", avg);
    }
    //Find encrypt average after making sure encrypt total isn't 0
    if (total == 0) {
        printf("\n **** Encrypt Avg == 0 *****");
        // fprintf(fptr, "\n **** Avg == 0 *****");
    }
    else {
        float_avg = (float)total / test_num;
        printf("\n *** Encrypt Average: %f *****", float_avg);
        printf("\n *** Encrypt Average: %f *****", float_avg);
        // fprintf(fptr, "\n *** Average test results are: %ld ***** \n", avg);
    }
    //Find decrypt average after making sure decrypt total isn't 0
    if (total == 0) {
        printf("\n **** Decrypt Avg == 0 *****");
        // fprintf(fptr, "\n **** Avg == 0 *****");
    }
    else {
        de_float_avg = (float)de_total / test_num;
        printf("\n *** Decrypt Average: %f *****", de_float_avg);
        printf("\n *** Decrypt Average: %f *****", de_float_avg);
        // fprintf(fptr, "\n *** Average test results are: %ld ***** \n", avg);
    }

    /* ----------- Finding Standard Deviation of Encrypt Test Results ------------------ */
    
    //for each test result, find difference from mean
    for(unsigned i = 0; i < test_num; i++) {
        key_testr = (float)key_test_results[i];
        testr = (float)test_results[i];
        de_testr = (float)de_test_results[i];
        // float float_avg = (float)avg;
        key_diff = key_testr - key_float_avg;
        diff = testr - float_avg;
        de_diff = de_testr - de_float_avg;
        // printf("float of test r is: %f and float avg is: %f, and Diff is %f\n", testr, float_avg, diff);
        key_std_dev_array[i] = key_diff * key_diff;
        std_dev_array[i] = diff * diff;
        de_std_dev_array[i] = de_diff * de_diff;
        // printf("std dev array @ pos i: %f\n",std_dev_array[i]);
    }

    // Get total difference of each array
    for(unsigned i = 0; i < test_num; i++) {
        key_std_dev += key_std_dev_array[i];
        std_dev += std_dev_array[i];
        de_std_dev += de_std_dev_array[i];
        // printf("std dev array @ pos i: %f\n",std_dev_array[i]);
    }
    // xtimer_sleep(1);
    // Find Key Standard deviation after making sure total std dev isn't 0
    if (key_std_dev == 0) {
        printf("\n **** Key Std Dev == 0  *****");
        printf("\n **** Key Std Dev == 0  *****");
    }
    else {
        key_std_dev = key_std_dev / test_num;
        printf("\n *** Key Standard deviation: %f *****", key_std_dev);
        printf("\n *** Key Standard deviation: %f *****", key_std_dev);
    }
    // xtimer_sleep(1);
    // Find Encrypt Standard deviation after making sure total std dev isn't 0
    if (std_dev == 0) {
        printf("\n **** Encrypt Std Dev == 0  *****");
        printf("\n **** Encrypt Std Dev == 0  *****");
    }
    else {
        std_dev = std_dev / test_num;
        printf("\n *** Encrypt Standard deviation: %f *****", std_dev);
        printf("\n *** Encrypt Standard deviation: %f *****", std_dev);
    }
    // xtimer_sleep(1);
    // Find Decrypt Standard deviation after making sure total std dev isn't 0
    if (de_std_dev == 0) {
        printf("\n **** Decrypt Std Dev == 0  *****");
        printf("\n **** Decrypt Std Dev == 0  *****");
    }
    else {
        de_std_dev = de_std_dev / test_num;
        printf("\n *** Decrypt Standard deviation: %f *****", de_std_dev);
        printf("\n *** Decrypt Standard deviation: %f *****", de_std_dev);
    }

    free(key_test_results);
    free(key_std_dev_array);

    free(test_results);
    free(std_dev_array);

    free(de_test_results);
    free(de_std_dev_array);

    // wc_FreeRng(&rng); 
    // printf("\n\n");
    
    return 0;
}

/* Declare the list of shell commands */
static const shell_command_t shell_commands[] = {
    { "keygen", "Generate key", _encrypt_handler_keyGen },
    { "encrypt", "Encrypt input string", _encrypt_handler_chacha20poly1305 },
    { "decrypt", "Decrypt input string", _decrypt_handler_chacha20poly1305 },
    { "etest", "Automate encryption", _etest_handler_aes },
    { NULL, NULL, NULL }
};

int main(void) {

    /* Uncomment this if test on SAMR21 */
    // xtimer_sleep(5);

    puts("===================================");
    puts("Start testing for Chacha20_poly1305");
    puts("===================================\n");

    puts("Key size for Chacha20: 256 bits");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    
    printf("\n");
    // printf("%d\n", TESTC);
    // printf("%d\n", TESTAES);

    return 0;
}










