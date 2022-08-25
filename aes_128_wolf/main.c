/* Test AES encryption and decryption, three modes are supported: CBC, CTR, CFB
*  1. If test on IoT devices, change %u to %lu in line: printf("Running time: %u\n", result);
*/

// #include <unistd.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ps.h"
#include "xtimer.h"
#include "log.h"
#include "shell.h"
// #include "resource.h"

#include <unistd.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

/* Define salt size for PRG */
#define SALT_SIZE 8

        // #if defined(WOLFSSL_AES_COUNTER)
        // #define TESTC 10 
        // #endif

/* start time of a function */
static void time_start(uint32_t* start) {
    *start = xtimer_now_usec();
}

/* running time of a function */
// static void time_result_print(uint32_t start) {
//     uint32_t result;
//     result = xtimer_now_usec() - start;

//     // printf("Running time: %lu\n", result);
//     printf("Running time: %lu\n", result);
// }

static uint32_t time_result_return(uint32_t start) {
    uint32_t result;
    result = xtimer_now_usec() - start;

    // printf("*** Running time: %lu ****\n", result);
    // printf("*** Running time: %lu ****\n", result);
    // printf("*** Running time: %lu ****\n", result);

    return result;
}

/* print a unsigned number */
// static void print_unsigned(unsigned num) {
//     printf("%u bytes\n", num);
// }

/* Initialize the secret key */
static short mode = 0;
static unsigned key_size;
static unsigned input_size;
static byte* key;
static byte* c_text; 
static byte iv[AES_BLOCK_SIZE];

//test vars
static unsigned test_num;
static unsigned key_result;
static unsigned en_result;
static unsigned de_result;

/* Generate a secret key with specific size: 128, 192, 256 */
static int _encrypt_handler_keyGen(int argc, char **argv) {

    if (argc < 2) {
        printf("usage: %s [size]\n", argv[0]);
        return 1;
    }
    int ret;
    WC_RNG rng;
    uint32_t start;
    // struct rusage r_usage;
    // int mem;

    key_size = (unsigned) (strtoul(argv[1], 0L, 10));
    if (key_size != 128 && key_size != 192 && key_size != 256) {
        /* if the entered size does not match acceptable size */
        printf("Invalid AES key size\n");
        return -4;
    }

    key_size /= 8;

    // puts("Start key generation...");
    // xtimer_sleep(1);    
    // LOG_INFO("Key generated with size %d!\n", key_size * 8);

    // Start time
    time_start(&start);

    key = malloc(key_size*(sizeof(byte)));
    
    // Hardcode password
    char* passwd = "passwordpasswordpasswordpassword";

    // Hardcode salt 
    // byte salt[] = { 0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06 }; 
    // Or generate salt randomly
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

    /* print running time */
    // time_result_print(start);
    key_result = time_result_return(start);

    /* stack usage */
    // ps();

    // puts("End key generation...\n");

    // for(unsigned i = 0; i < key_size; i++) {
    //     printf("%X, ", key[i]);
    // }

    
    // mem = getrusage(RUSAGE_SELF,&r_usage);
    // printf("%d\n", mem);
      // if(mem == 0)
         // printf("Memory usage: %ld kilobytes\n",r_usage.ru_maxrss);

    // printf("\n\n");
    wc_FreeRng(&rng); 
    // mem = getrusage(RUSAGE_SELF,&r_usage);
    // printf("%d\n", mem);
      // if(mem == 0)
         // printf("Memory usage: %ld kilobytes\n",r_usage.ru_maxrss);
    return 0;
}

/* Encrypt a random input 
*  Support AES-CTR and AES-CBC
*/

static int _encrypt_handler_aes(int argc, char **argv) { 
    if (argc < 3) {
        printf("usage: %s [block_mode] [input_size_bytes]\n", argv[0]);
        return 1;
    }

    // print out encryption key
    // puts("\nInitializing everything...");
    // xtimer_sleep(2);
    // printf("\nEncryption key is: ");
    // for(unsigned i = 0; i < key_size; i++) {
    //     printf("%X ", key[i]);
    // }
    // printf("\n");

    // Get input size
    input_size = (unsigned) (strtoul(argv[2], 0L, 10));
    
    int ret = 0;  
    uint32_t start;
    WC_RNG rng;
    Aes aes;
    byte input[input_size]; 

    // Get encryption mode
    if(strcmp(argv[1], "cbc") == 0) {
        mode = 1;
    } else if (strcmp(argv[1], "ctr") == 0) {
        mode = 2;
    } else if (strcmp(argv[1], "cfb") == 0) {
        mode = 3;
    }

    // printf("Test mode is %d\n", mode);

    /* --------------Initialize everything for encryption-------------- */
    // Initialize output
    c_text = malloc(input_size * (sizeof(byte)));

    // Initialize PRG seed
    wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize random number generator\n");
        return -1;
    }
    
    // Initialize random input
    ret = wc_RNG_GenerateBlock(&rng, input, input_size);
    if (ret != 0)
        return -2;

    // printf("Randomly generated input (%d bytes): ", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%X ", input[i]);
    // }
    // puts("");

    // Initialize initial vector
    // ret = wc_RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);
    // if (ret != 0)
    //     return -2;

    // printf("IV (%d bytes): ", (int)sizeof(iv));
    // for(int i = 0; i < (int)sizeof(iv); i++) {
    //     printf("%X ", iv[i]);
    // }
    // puts("");

    /* ------------------Encryption start------------------- */
    // xtimer_sleep(3);
    // puts("\n-----------------------");
    // puts("\nEncryption start...");
    // xtimer_sleep(1);
    time_start(&start);
    
    // Initialize initial vector
    ret = wc_RNG_GenerateBlock(&rng, iv, AES_BLOCK_SIZE);
    if (ret != 0)
        return -2;

    /* sets key */
    ret = wc_AesSetKey(&aes, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0)
        return -3;

    if(mode == 1){
        ret = wc_AesCbcEncrypt(&aes, c_text, input, sizeof(input)); 
    } else if(mode == 2) {
        ret = wc_AesCtrEncrypt(&aes, c_text, input, sizeof(input));   
    } else if(mode == 3) {
        ret = wc_AesCfbEncrypt(&aes, c_text, input, sizeof(input));   
    }
     
    if (ret != 0)
        return -5;
    // time_result_print(start);
    en_result = time_result_return(start);
    // puts("End Encryption!\n");
    /* ------------------Encryption end--------------------- */

    /* stack usage */
    // ps();

    // printf("Ciphertext of size %d\n", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%X ", c_text[i]);
    // }

    wc_FreeRng(&rng); 
    // printf("\n\n");

    return 0;
}

static int _decrypt_handler_aes(int argc, char **argv) {
    /* Check argc and print necessary information */
    if (argc < 2) {
         printf("usage: %s [block_mode]\n", argv[0]);
         return 1;
    }

    // Get encryption mode
    if(strcmp(argv[1], "cbc") == 0) {
        mode = 1;
    } else if (strcmp(argv[1], "ctr") == 0) {
        mode = 2;
    } else if (strcmp(argv[1], "cfb") == 0) {
        mode = 3;
    }

    // printf("\n\nInitializing everything...\n\n");
    // xtimer_sleep(2);
    // printf("Ciphertext (%d bytes):", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%X ", c_text[i]);
    // }
    // printf("\nDecryption key: ");
    // for(unsigned i = 0; i < key_size; i++) {
    //     printf("%X ", key[i]);
    // }
    // printf("\n");

    // printf("IV (%d bytes): ", (int)sizeof(iv));
    // for(int i = 0; i < (int)sizeof(iv); i++) {
    //     printf("%X ", iv[i]);
    // }
    // puts("");
    // xtimer_sleep(1);

    /* Initialize decryption */
    int ret = 0;
    uint32_t start;
    byte* output;   //Store the decrypted text
    Aes des;

    output = malloc(input_size * sizeof(byte));

    // printf("\n-----------------------");
    // printf("\nStart decryption in 2 seconds...\n");
    // xtimer_sleep(2);

    /* Start decryption */
    time_start(&start);
    // if (ret != 0)
        // return -3;

    if(mode == 1){
        wc_AesSetKey(&des, key, AES_BLOCK_SIZE, iv, AES_DECRYPTION);
        ret = wc_AesCbcDecrypt(&des, output, c_text, input_size); 
    } else if(mode == 2) {
        wc_AesSetKey(&des, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        ret = wc_AesCtrEncrypt(&des, output, c_text, input_size);
    } else if(mode == 3) {
        wc_AesSetKey(&des, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
        ret = wc_AesCfbDecrypt(&des, output, c_text, input_size);
    }

    if (ret != 0)
        return -6;
    // time_result_print(start);
    de_result = time_result_return(start);
    // puts("End Decryption!\n\n");

    /* stack usage */
    // ps();

    // printf("Print plaintext in 2 seconds...\n");
    // xtimer_sleep(2);
    // printf("Plaintext (%d bytes):", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%X ", output[i]);
    // }
    // puts("");

    // printf("\n\n");
    free(output);
    return ret;
}

static int _etest_handler_aes(int argc, char **argv) { 
    if (argc < 3) {
        printf("usage: %s [block_mode] [input_size_bytes] [number_of_tests] \n", argv[0]);
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
    input_size = (unsigned) (strtoul(argv[2], 0L, 10));

    //manually input key size so we don't get stack overflow
    //choices are 128, 192, 256
    char *keysize[2] = {"blank","192"}; 

    // Get number of tests
    test_num = (unsigned) (strtoul(argv[3], 0L, 10));
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
        _encrypt_handler_aes(argc, argv);
        test_results[i] = en_result;

        /* ------------------- Decrypt ----------------------- */
        // de_test_results[i] = _decrypt_handler_des3(argc, argv);
        _decrypt_handler_aes(argc, argv);
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
        printf("\n *** Key Gen average test results are: %f *****", key_float_avg);
        printf("\n *** Key Gen average test results are: %f *****", key_float_avg);
        // fprintf(fptr, "\n *** Average test results are: %ld ***** \n", avg);
    }
    //Find encrypt average after making sure encrypt total isn't 0
    if (total == 0) {
        printf("\n **** Encrypt Avg == 0 *****");
        // fprintf(fptr, "\n **** Avg == 0 *****");
    }
    else {
        float_avg = (float)total / test_num;
        printf("\n *** Encrypt Average test results are: %f *****", float_avg);
        printf("\n *** Encrypt Average test results are: %f *****", float_avg);
        // fprintf(fptr, "\n *** Average test results are: %ld ***** \n", avg);
    }
    //Find decrypt average after making sure decrypt total isn't 0
    if (total == 0) {
        printf("\n **** Decrypt Avg == 0 *****");
        // fprintf(fptr, "\n **** Avg == 0 *****");
    }
    else {
        de_float_avg = (float)de_total / test_num;
        printf("\n *** Decrypt Average test results are: %f *****", de_float_avg);
        printf("\n *** Decrypt Average test results are: %f *****", de_float_avg);
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
    xtimer_sleep(1);
    // Find Key Standard deviation after making sure total std dev isn't 0
    if (key_std_dev == 0) {
        printf("\n **** Key Std Dev == 0  *****");
        printf("\n **** Key Std Dev == 0  *****");
    }
    else {
        key_std_dev = key_std_dev / test_num;
        printf("\n *** Key Standard deviation of the test results are: %f *****", key_std_dev);
        printf("\n *** Key Standard deviation of the test results are: %f *****", key_std_dev);
    }
    xtimer_sleep(1);
    // Find Encrypt Standard deviation after making sure total std dev isn't 0
    if (std_dev == 0) {
        printf("\n **** Encrypt Std Dev == 0  *****");
        printf("\n **** Encrypt Std Dev == 0  *****");
    }
    else {
        std_dev = std_dev / test_num;
        printf("\n *** Encrypt Standard deviation of the test results are: %f *****", std_dev);
        printf("\n *** Encrypt Standard deviation of the test results are: %f *****", std_dev);
    }
    xtimer_sleep(1);
    // Find Decrypt Standard deviation after making sure total std dev isn't 0
    if (de_std_dev == 0) {
        printf("\n **** Decrypt Std Dev == 0  *****");
        printf("\n **** Decrypt Std Dev == 0  *****");
    }
    else {
        de_std_dev = de_std_dev / test_num;
        printf("\n *** Decrypt Standard deviation of the test results are: %f *****", de_std_dev);
        printf("\n *** Decrypt Standard deviation of the test results are: %f *****", de_std_dev);
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
    { "encrypt", "Encrypt input string", _encrypt_handler_aes },
    { "decrypt", "Decrypt input string", _decrypt_handler_aes },
    { "etest", "Automate encryption", _etest_handler_aes },
    { NULL, NULL, NULL }
};

int main(void) {

    /* Uncomment this if test on SAMR21 */
    // xtimer_sleep(5);

    puts("===========================================");
    puts("Start testing for AES-CBC, AES-CTR, AES-CFB");
    puts("===========================================\n");

    puts("Key size for AES: 128, 192, 256\n\n");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    
    printf("\n");
    // printf("%d\n", TESTC);
    // printf("%d\n", TESTAES);

    return 0;
}










