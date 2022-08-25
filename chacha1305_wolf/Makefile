# include ../Makefile.tests_common
APPLICATION = test_chacha1305
# This is an optimized stack value based on testing, if you observe
# a segmentation fault please increase this stack size.

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
DEVELHELP ?= 1

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

CFLAGS += -DTHREAD_STACKSIZE_MAIN=2*THREAD_STACKSIZE_LARGE

USEPKG += wolfssl

USEMODULE += shell
USEMODULE += shell_commands

# USEMODULE += wolfcrypt_aes
USEMODULE += wolfcrypt_hmac
USEMODULE += wolfcrypt_chacha
USEMODULE += wolfcrypt_poly1305
# USEMODULE += wolfcrypt-tes
# USEMODULE += wolfcrypt_asn
USEMODULE += wolfcrypt
USEMODULE += wolfcrypt_random
USEMODULE += wolfcrypt_sha256
# USEMODULE += wolfssl_dtls
USEMODULE += wolfcrypt_pwdbased

# Use module socket for wolfssl
# USEMODULE += gnrc_sock_check_reuse
# USEMODULE += gnrc_sock_udp
# USEMODULE += gnrc_ipv6

# Uncomment the following line to enable RSA tests
# (e.g. when enough resources are available on platform)
#USEMODULE += wolfcrypt_rsa wolfcrypt_dh

# Comment the following line to disable full-benchmark test
# USEMODULE += wolfcrypt-benchmark

USEMODULE += xtimer
USEMODULE += ps
USEMODULE += printf_float

ifneq ($(BOARD),native)
  CFLAGS += -DBENCH_EMBEDDED
endif

TEST_ON_CI_WHITELIST += native

include $(RIOTBASE)/Makefile.include
