/*  Test ECC encryption and decryption. 
*   For ECC key pairs, P-224, P-256, P-384, P-521 curves correspond to 112-bits, 128-bits, 192-bits 
*   and 256-bits of security strength, respectively.
*
*   1. If test on IoT devices, change %u to %lu in line: printf("Running time: %u\n", result);
*/

#include <stdio.h>
#include <string.h>
//  it would not compile if I left this in?
// #include <wolfssl/options.h>
#include "xtimer.h"
#include "shell.h"
#include "ps.h"
#include <unistd.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* start time of a function */
static void time_start(uint32_t* start) {
    *start = xtimer_now_usec();
}

/* print running time of a function */
// static void time_result_print(uint32_t start) {
//     uint32_t result;
//     result = xtimer_now_usec() - start;

//     printf("Running time: %lu\n", result);
// }

/* return runtime of a function */
static uint32_t time_result_return(uint32_t start) {
    uint32_t result;
    result = xtimer_now_usec() - start;

    // printf("*** Runninsg time: %lu ****\n", result);
    // printf("*** Running time: %lu ****\n", result);
    // printf("*** Running time: %lu ****\n", result);

    return result;
}

/* Initialize the secret key */
static int cur_id;
static word32 c_size;
static ecc_key cliKey, servKey;
static byte* input;

//test vars
static unsigned input_size;
static unsigned test_num;
static unsigned key_result;
static unsigned en_result;
static unsigned de_result;

/* change this value if want to test upper bound */
static byte c_text[512] = {0}; 

/*  Generate keys with specific curves. 
    P-256, P-384, P-521
    ECC_SECP256R1,
    ECC_SECP384R1,
    ECC_SECP521R1,
*/
static int _encrypt_handler_keyGen(int argc, char **argv) {
    /* take care of the input */
    if (argc < 2) {
        printf("usage: %s [sec_level]\n", argv[0]);
        return 1;
    }

    int sec_lvl;
    int key_size;

    sec_lvl = (unsigned) (strtoul(argv[1], 0L, 10));
    if (sec_lvl == 128) {
        cur_id = ECC_SECP256R1;
        key_size = 32;
    } else if (sec_lvl == 192) {
        cur_id = ECC_SECP384R1;
        key_size = 48;
    } else if (sec_lvl == 256) {
        cur_id = ECC_SECP521R1;
        key_size = wc_ecc_get_curve_size_from_id(cur_id);
    } else {
        printf("Invalid security level, use 128, 192, 256.\n");
        return -4;
    }

    // printf("Key size: %d, curve: %d\n", key_size, ECC_CURVE_DEF);
    /* Initialize key generation */
    int ret = 0;
    uint32_t start;
    WC_RNG rng;

    // printf("start key generation...\n");
    time_start(&start);

    wc_ecc_init(&cliKey);
    wc_ecc_init(&servKey);
    wc_InitRng(&rng);

    ret = wc_ecc_make_key(&rng, key_size, &cliKey);
    if (ret != MP_OKAY) {
            printf("Failed to generate client keys. %d, %d.\n", ret, key_size);
            return -3;
    }

    ret = wc_ecc_make_key(&rng, key_size, &servKey);
    if (ret != MP_OKAY) {
            printf("Failed to generate server keys. %d, %d.\n", ret, key_size);
            return -3;
    }
    /*  Generate key with specific cruve. */
    /*  
        int keySize = wc_ecc_get_curve_size_from_id(cur_id);
        ret = wc_ecc_make_key_ex(&rng, keySize, &key, cur_id);
        if (ret != MP_OKAY) {
            printf("Failed to generate ECC keys. %d, %d.\n", ret, keySize);
            return -3;
        }
    */

    /* print running time */
    // time_result_print(start);
    key_result = time_result_return(start);

    // puts("End key generation.\n");

    // ps();

	wc_FreeRng(&rng);
    return 0;
}

/* Encrypt a random input with ecc */
static int _encrypt_handler_ecc(int argc, char **argv) { 
    if (argc < 2) {
        printf("usage: %s [input_size_bytes]\n", argv[0]);
        return 1;
    }

    // puts("\nInitializing everything...");
    // xtimer_sleep(2);

    /* Get input and output size */
    unsigned input_size = (unsigned) (strtoul(argv[1], 0L, 10));
    
    /* --------------Initialize everything for encryption-------------- */
	int ret = 0;
    c_size = sizeof(c_text);
    uint32_t start;
    WC_RNG rng;
    
    // puts("\n-----------------------");
    // puts("\nEncryption start in one second...");
    // xtimer_sleep(1);
    time_start(&start);

    /* Initialize input "input" */
    input = malloc(input_size * (sizeof(byte)));

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
    //     printf("%X ", input[i]);
    // }
    // puts("");


    /* ------------------Encryption start------------------- */
    // xtimer_sleep(2);
    // puts("\n-----------------------");
    // puts("\nEncryptions start in one second...");
    // xtimer_sleep(1);

    time_start(&start);
    ret = wc_ecc_encrypt(&cliKey, &servKey, input, input_size, c_text, &c_size, NULL);
    if(ret < 0) {
        printf("Encryption error, code: %d\n", ret);
        return ret;
    }

    // time_result_print(start);
    en_result = time_result_return(start);
    // puts("End Encryption!\n");
    // puts("\n-----------------------\n");
    /* ------------------Encryption end--------------------- */

    // ps();

    // puts("\nPrint out ciphertext in one second...");
    // printf("Ciphertext of size %d\n", c_size);
    // for(unsigned i = 0; i < c_size; i++) {
    //     printf("%X ", c_text[i]);
    // }

    wc_FreeRng(&rng); 
    // printf("\n\n");

    return 0;
}

static int _decrypt_handler_ecc(int argc, char **argv) {
    /* Check argc and print necessary information */
    if (argc < 2) {
         printf("usage: %s [ouput_size_byte]\n", argv[0]);
         return 1;
    }

    unsigned plain_size = (unsigned) (strtoul(argv[1], 0L, 10));
    // word32 c_size = sizeof(c_text);

    // printf("\n\nInitializing everything...\n\n");
    // xtimer_sleep(2);
    // printf("Ciphertext (%d bytes):", c_size);
    // for(unsigned i = 0; i < c_size; i++) {
    //     printf("%02X ", c_text[i]);
    // }
    // xtimer_sleep(1);

    /* Initialize decryption */
    short ret = 0;
    uint32_t start;
    byte* output;   //Store the decrypted text

    // puts("\n-----------------------");
    // puts("\nDecryption starts in one second...");
    // xtimer_sleep(1);
    time_start(&start);
    output = malloc(plain_size * sizeof(byte));

    ret = wc_ecc_decrypt(&servKey, &cliKey, c_text, c_size, output, &plain_size, NULL);
    if(ret < 0) {
        printf("Decryption error, code: %d\n", ret);
        return ret;
    }
    // time_result_print(start);
    de_result = time_result_return(start);
    // puts("End Decryption!\n");
    // puts("\n-----------------------\n");
    // ps();

    // printf("Print plaintext in 2 seconds...\n");
    // xtimer_sleep(2);
    // printf("Plaintext (%d bytes):", plain_size);
    // for(unsigned i = 0; i < plain_size; i++) {
    //     printf("%02X ", output[i]);
    // }
    // puts("");

    /* Free memory */
    // free(output);
    // wc_ecc_free(&cliKey);
    // wc_ecc_free(&servKey);

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
    //choices are 128, 192
    char *keysize[2] = {"blank","192"}; 

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
        _encrypt_handler_ecc(argc, argv);
        test_results[i] = en_result;

        /* ------------------- Decrypt ----------------------- */
        // de_test_results[i] = _decrypt_handler_des3(argc, argv);
        _decrypt_handler_ecc(argc, argv);
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
    { "encrypt", "Encrypt input string", _encrypt_handler_ecc },
    { "decrypt", "Decrypt input string", _decrypt_handler_ecc },
    { "etest", "Automate encryption", _etest_handler_aes },
    { NULL, NULL, NULL }
};

int main(void) {

    /* Uncomment this if test on SAMR21 */
    // xtimer_sleep(5);

    puts("================================");
    puts("Start testing for ECC encryption");
    puts("================================\n");

    puts("Security levels for ECC: 128, 192. (256 is not supported currently)\n\n");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    
    printf("\n");

    return 0;
}









