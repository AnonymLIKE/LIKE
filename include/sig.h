#pragma once

#include <stddef.h>

#define ED25519_SIG_LENGTH 64

void sgen_ed25519(char * pub_key_path, char * priv_key_path);

void ssig_ed25519(char * priv_key_path, const unsigned char * msg, size_t msg_len, unsigned char ** sig, size_t * sig_len);

void sver_ed25519(char * pub_key_path, const unsigned char * msg, size_t msg_len, unsigned char * sig, size_t sig_len);
