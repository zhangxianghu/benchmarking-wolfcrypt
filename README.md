# benchmarking-wolfcrypt

### compile program on RIOT 
	1. BOARD=yourboard make flash #write the program to the device
	2. BOARD=yourboard make term  #run the program 

	RIOT provides a number of examples in the examples/ directory. 
	Every example has a README that documents its usage and its purpose. 
	You can build them by typing
		make BOARD=samr21-xpro
	or
		make all BOARD=samr21-xpro
	into your shell.

	To flash the application to a board just type
		make flash BOARD=samr21-xpro
		make flash BOARD=saml11-xpro
		make flash BOARD=arduino-nano-33-ble
		make flash BOARD=arduino-due

	You can then access the board via the serial interface:
		make term BOARD=samr21-xpro

	If you are using multiple boards you can use the PORT macro to specify the serial interface:
		make term BOARD=samr21-xpro PORT=/dev/ttyACM1

	If you are using samr21-xpro, run help first to load the program

### wolfCrypt and wolfSSL
	1. For all key generation in symmetric key encryption, we use "wc_PBKDF2" and iterate "WC_SHA256" for 1024 times

	2. To use wolfCrypt, the settings.h header should always be included FIRST preceding any other wolfSSL headers 
		to ensure the correct configuration is picked up when including other wolfSSL headers: 

		#include <wolfssl/wolfcrypt/settings.h>

	3. Extra features of wolfCrypt should be controlled with the header "user_settings.h". 
	   The header file is located in "/RIOT/pkg/wolfssl/include"
	   Uncomment corresponding #undef and #define to test different primitives.
		E.g. To enable AES-CTR, add following to "user_settings.h"
			#undef WOLFSSL_AES_COUNTER
			#define WOLFSSL_AES_COUNTER

	4. Modules
		wolfCrypt:

		wolfcrypt_poly1305
		wolfcrypt_chacha
		wolfcrypt_ed25519
		wolfcrypt_aes
		wolfcrypt_pwdbased
		wolfcrypt_asn
		wolfcrypt_random
		wolfcrypt_* (e.g. ecc, rsa, sha3, ...)

		wolfSSL:
		wolfssl_tls
		wolfsll_tls13
		wolfssl_dtls
		wolfssl_* (e.g. ocsp, crl, ...)

	5. AEAD: AES-CCM, AES-GCM, CHACHA20 (Supported by TLS 1.3)


### Return values
	1:  argc error
	-1: Failed to initialize random number generator
	-2: Failed to generate random number
	-3: Failed to set key in encryption or decryption
	-4: Invalid key size
	-5: Failed for encryption
	-6: Failed for decryption
	-7: Hash initialization failed
	-8: Hash update failed
	-9: Hash final failed
	-10: Failed to generate RSA key
	-11: Failed to convert rsa key to DER format

### Evaluation
	1. For size information, use command "size bin/samr21-xpro/test_aes.elf"
	2. ps() function for memory usage
	3. Chacha20 has 256-bit key and provide 256-bit security level
	4. SAML11 ran AES 535 times (16 more bytes each time) and issued RAM outage 

### Devices and evaluation metrics 
	1.  Running time: test the running time multiple times (e.g. 30 times) and calculate the average and the standard deviation  
	2.  Memory usage: it is the same as the storage size since 
		a device needs to load all files into its memory in order to run the code    
	3.  Energy consumption: we use formula E = U ·I ·t where 
		U is the voltage, I is the current intensity, and t is the running time.     
	4. Stack usage (optional, need discussion): 
		stack usage is also important in embedded applications. 
		We can use stack usage to track stack overflows and the encryption capability. 
		For example, an algorithm may require too many variables that the stack cannot store. 
		Generally we don't use dynamic memory in embedded systems. 
		Hard to track the maximum RAM usage since it is dynamic. Memories are allocated and freed during the execution. There is a tool to track the maximum stack usage. Each thread is allocated with a default stack and we can use ps() to find out the maximum ussage of the stack. 


		Datasheet (worst case (based on the coreMark benchmark) under normal condition (25 degree).)
								flash Memory 		RAM  		CPU						Voltage 		Current
		SAML11 Xplained Pro 		64kb			16kb		32MHz, ATSAML11E16A		5V				2.64mA
		SAMR21 Xplained Pro 		256kb			32kb		48MHz, ATSAMR21G18A		3.3V			7mA
		Arduino Due					512kb			96kb		84MHz, AT91SAM3X8E		3.3V			77.50mA
		Arduino Nano 33 BLE 		1MB				256kb		64MHz, nRF52840			3.3V			6.3mA

### Evaluation algorithms
	1. Symmetric key cryptography: 
		Block ciphers:
			AES (CFB, CBC, CTR) (128, 192, 256): 9 combinations
			3DES
			Camellia (128, 192, 256)
			authenticated encryption 
				AES-CCM, AES-GCM
		Stream ciphers:
			Rabbit
			authenticated: Chacha20_poly1305

		N=[16, 32, 64, 128, 256] bytes 

	2. Hash functions: 
		SHA256: SHA2, SHA3
		SHA512: SHA2, SHA3
		BLAKE2

		N = 1KB, 1MB, 1GB, 1TB?

	3. Public-key cryptography: 
		RSA: how long it takes to encrypt a N-byte message wit RSA (N=16, 128, ..., 256, or 384 if M=3072) with key to be M-bits (M=2048, 3072)
		ECC: N= same as RSA, M=128, 192