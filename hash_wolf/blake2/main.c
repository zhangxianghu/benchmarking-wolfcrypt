/* Test BLAKE2
*  1. If test on IoT devices, change %u to %lu in line: printf("Running time: %u\n", result);
*/

#include <stdio.h>
#include <string.h>
#include "xtimer.h"
#include "shell.h"
#include "ps.h"
#include <unistd.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/blake2.h>
#include <wolfssl/wolfcrypt/random.h>

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

/* print a unsigned number */
// static void print_unsigned(unsigned num) {
//     printf("%u bytes\n", num);
// }

/* Initialize global parameter */
static unsigned input_size;
static unsigned hash_size;
static byte* input; 

//test vars
static unsigned input_size;
static unsigned test_num;
static unsigned hash_result;
// static unsigned en_result;
// static unsigned de_result;

/* Generate input for hash */
static int _hash_input_gen(int argc, char **argv) {
    /* handle parameters from command */
    if (argc < 2) {
        printf("usage: %s [size]\n", argv[0]);
        return 1;
    }

    input_size = (unsigned) (strtoul(argv[1], 0L, 10));

/* Generate random input */
    int ret = 0;
    WC_RNG rng;
    
    /* Initialize PRG seed */
    wc_InitRng(&rng);
    if (ret != 0) {
        printf("Failed to initialize random number generator\n");
        return -1;
    }

    input = malloc(input_size * (sizeof(byte)));
    ret = wc_RNG_GenerateBlock(&rng, input, input_size);
    if (ret != 0)
        return -2;

    // printf("Randomly generated inputs (%d bytes): ", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%X ", input[i]);
    // }
    // puts("");

    wc_FreeRng(&rng); 
    return 0;
}

static int _hash_handler(int argc, char **argv) {
    /* handle parameters from command */
    if (argc < 3) {
        printf("usage: %s [input_size] [hash_size]\n", argv[0]);
        return 1;
    }

    hash_size = (unsigned) (strtoul(argv[2], 0L, 10));

    /* Print out input information */
    // printf("\n\nInitializing everything...\n\n");
    // xtimer_sleep(2);
    // printf("Input (%d bytes):", input_size);
    // for(unsigned i = 0; i < input_size; i++) {
    //     printf("%X ", input[i]);
    // }

    /* Compute hash value */
    uint32_t start;
    int ret;
    byte hash_value[hash_size];
    Blake2b b2;

    // printf("\n\nHashing starts in 2 seconds...\n");
    // xtimer_sleep(2); 

    // Start time
    time_start(&start);

    ret = wc_InitBlake2b(&b2, hash_size);
    if (ret != 0) {
        return -7;
    }
    ret = wc_Blake2bUpdate(&b2, input, input_size);  /*can be called again and again*/
    if (ret != 0) {
        return -8;
    }

    ret = wc_Blake2bFinal(&b2, hash_value, hash_size);
    if (ret != 0) {
        return -9;
    }
    // print running time
    // time_result_print(start);
    hash_result = time_result_return(start);

    // printf("End hashing!");

    // ps();
    
    // printf("\n\n");
    // printf("Hash value: ");
    // for (unsigned i = 0; i < hash_size; i++)
    //     printf("%02X ", hash_value[i]);
    // printf("\n");
    // ps();

    free(input);
    // free(hash_value);
    // wc_blake2bFree(&b2);
    return 0;
}

static int _etest_handler_aes(int argc, char **argv) { 
    if (argc < 3) {
        printf("usage: %s [input_size_bytes] [hash_size] [number_of_tests] \n", argv[0]);
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
    // char *keysize[2] = {"blank","128"}; 

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
    // uint32_t key_total = 0;
    // float key_diff = 0;
    // float key_std_dev = 0;
    // float key_float_avg = 0;
    // uint32_t* key_test_results = (uint32_t*)calloc(test_num, sizeof(uint32_t));
    // float* key_std_dev_array = (float*)calloc(test_num, sizeof(float));

    // allocate memory for encrypt test results
    uint32_t total = 0;
    float diff = 0;
    float std_dev = 0;
    float float_avg = 0;
    uint32_t* test_results = (uint32_t*)calloc(test_num, sizeof(uint32_t));
    float* std_dev_array = (float*)calloc(test_num, sizeof(float));

    //allocate memory for decrypt test results
    // uint32_t de_total = 0;
    // float de_diff = 0;
    // float de_std_dev = 0;
    // float de_float_avg = 0;
    // uint32_t* de_test_results = (uint32_t*)calloc(test_num, sizeof(uint32_t));
    // float* de_std_dev_array = (float*)calloc(test_num, sizeof(float)); 

    // float key_testr = 0;
    float testr = 0;
    // float de_testr = 0;   

    /* ---------- Run the specified number of tests ---------- */
    for(unsigned i = 0; i < test_num; i++) {

        // generate a key
        // key_test_results[i] = _encrypt_handler_keyGen(1, keysize);
         _hash_input_gen(argc, argv);
        // key_test_results[i] = key_result;

        /* ---- Encrypt ------ */
        // test_results[i] = _encrypt_handler_des3(argc, argv);
        _hash_handler(argc, argv);
        test_results[i] = hash_result;

        /* ------------------- Decrypt ----------------------- */
        // de_test_results[i] = _decrypt_handler_des3(argc, argv);
        // _decrypt_handler_ecc(argc, argv);
        // de_test_results[i] = de_result;

        //print results
        // printf("keygen %2d: %ld\n", i+1, key_test_results[i]);
        // printf("encrypt %2d: %ld\n", i+1, test_results[i]);
        // printf("decrypt %2d: %ld\n", i+1, de_test_results[i]);
    }


    /* ----------- Finding Mean of Encrypt Test Results ------------------ */
    for(unsigned i = 0; i < test_num; i++) {
        // key_total += key_test_results[i];
        total += test_results[i];
        // de_total += de_test_results[i];
        // printf("keygen %2d: %ld\n", i+1, key_test_results[i]);
        // printf("hash time %2d: %ld\n", i+1, test_results[i]);
        // printf("decrypt %2d: %ld\n", i+1, de_test_results[i]);
        // fprintf(fptr, "%2d: %ld\n", i+1, test_results[i]);
    }
    //Find key average after making sure key total isn't 0
    // if (key_total == 0) {
    //     printf("\n **** Key Avg == 0 *****");
    //     // fprintf(fptr, "\n **** Avg == 0 *****");
    // }
    // else {
    //     key_float_avg = (float)key_total / test_num;
    //     printf("\n *** Key Gen average: %f *****", key_float_avg);
    //     printf("\n *** Key Gen average: %f *****", key_float_avg);
    //     // fprintf(fptr, "\n *** Average test results are: %ld ***** \n", avg);
    // }
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
    // if (de_total == 0) {
    //     printf("\n **** Decrypt Avg == 0 *****");
    //     // fprintf(fptr, "\n **** Avg == 0 *****");
    // }
    // else {
    //     de_float_avg = (float)de_total / test_num;
    //     printf("\n *** Decrypt Average: %f *****", de_float_avg);
    //     printf("\n *** Decrypt Average: %f *****", de_float_avg);
    //     // fprintf(fptr, "\n *** Average test results are: %ld ***** \n", avg);
    // }

    /* ----------- Finding Standard Deviation of Encrypt Test Results ------------------ */
    
    //for each test result, find difference from mean
    for(unsigned i = 0; i < test_num; i++) {
        // key_testr = (float)key_test_results[i];
        testr = (float)test_results[i];
        // de_testr = (float)de_test_results[i];

        // key_diff = key_testr - key_float_avg;
        diff = testr - float_avg;
        // de_diff = de_testr - de_float_avg;
        // printf("float of test r is: %f and float avg is: %f, and Diff is %f\n", testr, float_avg, diff);
        // key_std_dev_array[i] = key_diff * key_diff;
        std_dev_array[i] = diff * diff;
        // de_std_dev_array[i] = de_diff * de_diff;
        // printf("std dev array @ pos i: %f\n",std_dev_array[i]);
    }

    // Get total difference of each array
    for(unsigned i = 0; i < test_num; i++) {
        // key_std_dev += key_std_dev_array[i];
        std_dev += std_dev_array[i];
        // de_std_dev += de_std_dev_array[i];
        // printf("std dev array @ pos i: %f\n",std_dev_array[i]);
    }
    // xtimer_sleep(1);
    // Find Key Standard deviation after making sure total std dev isn't 0
    // if (key_std_dev == 0) {
    //     printf("\n **** Key Std Dev == 0  *****");
    //     printf("\n **** Key Std Dev == 0  *****");
    // }
    // else {
    //     key_std_dev = key_std_dev / test_num;
    //     printf("\n *** Key Standard deviation: %f *****", key_std_dev);
    //     printf("\n *** Key Standard deviation: %f *****", key_std_dev);
    // }
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
    // if (de_std_dev == 0) {
    //     printf("\n **** Decrypt Std Dev == 0  *****");
    //     printf("\n **** Decrypt Std Dev == 0  *****");
    // }
    // else {
    //     de_std_dev = de_std_dev / test_num;
    //     printf("\n *** Decrypt Standard deviation: %f *****", de_std_dev);
    //     printf("\n *** Decrypt Standard deviation: %f *****", de_std_dev);
    // }

    // free(key_test_results);
    // free(key_std_dev_array);

    free(test_results);
    free(std_dev_array);

    // free(de_test_results);
    // free(de_std_dev_array);

    // wc_FreeRng(&rng); 
    // printf("\n\n");
    
    return 0;
}

/* Declare the list of shell commands */
static const shell_command_t shell_commands[] = {
    { "input", "Generate random input", _hash_input_gen },
    { "hash", "Hash the input string", _hash_handler },
    { "etest", "Automate encryption", _etest_handler_aes },
    // { "decrypt", "Decrypt input string", _decrypt_handler_ccm },
    { NULL, NULL, NULL }
};

int main(void) {

    /* Uncomment this if test on SAMR21 */
    // xtimer_sleep(5);

    puts("================================================================");
    puts("Start testing for Blake2b: digest size should be 32 or 64 bytes.");
    puts("================================================================\n");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    
    printf("\n");
    // printf("%d\n", TESTC);
    // printf("%d\n", TESTAES);

    return 0;
}










