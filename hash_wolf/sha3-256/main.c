/* Test SHA256
*  1. If test on IoT devices, change %u to %lu in line: printf("Running time: %u\n", result);
*/

#include <stdio.h>
#include <string.h>
#include "xtimer.h"
#include "shell.h"
#include "ps.h"
#include <unistd.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/random.h>

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

/* print running time of a function */
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
static byte* input; 

//test vars
// static unsigned input_size;
static unsigned test_num;
static unsigned hash_result;

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
    //     printf("%02X ", input[i]);
    // }
    // puts("");

    // ps(); 

    wc_FreeRng(&rng); 
    return 0;
}

static int _hash_handler(int argc, char **argv) {
    /* handle parameters from command */
    if (argc < 2) {
        printf("usage: %s [size]\n", argv[0]);
        return 1;
    }

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
    byte hash_value[WC_SHA3_256_DIGEST_SIZE];
    wc_Sha3 sha3;

    // printf("\n\nHashing starts in 2 seconds...\n");
    // xtimer_sleep(2); 

    // Start time
    time_start(&start);

    ret = wc_InitSha3_512(&sha3, NULL, 0);
    if (ret != 0) {
        return -7;
    }

    ret = wc_Sha3_512_Update(&sha3, input, input_size);  /*can be called again and again*/
    if (ret != 0) {
        return -8;
    }

    ret = wc_Sha3_512_Final(&sha3, hash_value);
    if (ret != 0) {
        return -9;
    }

    // print running time
    // time_result_print(start);
    hash_result = time_result_return(start);

    // printf("End hashing!");

    // printf("\n\n");
    // printf("Hash value: ");
    // for (unsigned i = 0; i < WC_SHA3_256_DIGEST_SIZE; i++)
    //     printf("%02X ", hash_value[i]);
    // printf("\n");

    // ps();
    
    wc_Sha3_512_Free(&sha3);
    return 0;
}

static int _etest_handler_aes(int argc, char **argv) { 
    if (argc < 3) {
        printf("usage: %s [input_size_bytes] [number_of_tests] \n", argv[0]);
        return 1;
    }

    // Get input size
    input_size = (unsigned) (strtoul(argv[1], 0L, 10));

    //manually input key size so we don't get stack overflow
    //choices are 128, 192
    // char *keysize[2] = {"blank","128"}; 

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

    // allocate memory for hash test results
    uint32_t total = 0;
    float diff = 0;
    float std_dev = 0;
    float float_avg = 0;
    uint32_t* test_results = (uint32_t*)calloc(test_num, sizeof(uint32_t));
    float* std_dev_array = (float*)calloc(test_num, sizeof(float));

    float testr = 0;  

    /* ---------- Run the specified number of tests ---------- */
    for(unsigned i = 0; i < test_num; i++) {

        /* ---- Generate input ------ */
        _hash_input_gen(argc, argv);

        /* ---- Hash ------ */
        _hash_handler(argc, argv);
        test_results[i] = hash_result;
    }


    /* ----------- Finding Mean of Encrypt Test Results ------------------ */
    for(unsigned i = 0; i < test_num; i++) {
        // key_total += key_test_results[i];
        total += test_results[i];
        // printf("hash time %2d: %ld\n", i+1, test_results[i]);
    }

    //Find hash average after making sure hash total isn't 0
    if (total == 0) {
        printf("\n **** Hash Avg == 0 *****");
        // fprintf(fptr, "\n **** Avg == 0 *****");
    }
    else {
        float_avg = (float)total / test_num;
        printf("\n *** Hash Average: %f *****", float_avg);
        printf("\n *** Hash Average: %f *****", float_avg);
        // fprintf(fptr, "\n *** Average test results are: %ld ***** \n", avg);
    }

    /* ----------- Finding Standard Deviation of Encrypt Test Results ------------------ */
    
    //for each test result, find difference from mean
    for(unsigned i = 0; i < test_num; i++) {
        testr = (float)test_results[i];
        diff = testr - float_avg;
        // printf("float of test r is: %f and float avg is: %f, and Diff is %f\n", testr, float_avg, diff);
        std_dev_array[i] = diff * diff;
        // printf("std dev array @ pos i: %f\n",std_dev_array[i]);
    }

    // Get total difference of array
    for(unsigned i = 0; i < test_num; i++) {
        std_dev += std_dev_array[i];
        // printf("std dev array @ pos i: %f\n",std_dev_array[i]);
    }
    
    // Find Hash Standard deviation after making sure total std dev isn't 0
    if (std_dev == 0) {
        printf("\n **** Hash Std Dev == 0  *****");
        printf("\n **** Encrypt Std Dev == 0  *****");
    }
    else {
        std_dev = std_dev / test_num;
        printf("\n *** Hash Standard deviation: %f *****", std_dev);
        printf("\n *** Hash Standard deviation: %f *****", std_dev);
    }

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
    { NULL, NULL, NULL }
};

int main(void) {

    /* Uncomment this if test on SAMR21 */
    // xtimer_sleep(5);

    puts("=======================");
    puts("Start testing for SHA3:");
    puts("=======================\n");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    
    printf("\n");
    // printf("%d\n", TESTC);
    // printf("%d\n", TESTAES);

    return 0;
}










