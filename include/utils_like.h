#pragma once

#include <stddef.h>

void handle_mcl_error(int rc, char * msg);

char *  bytes_to_hexstring(unsigned char * data_bytes, size_t data_bytes_len);

unsigned char * sha256(unsigned char * data, size_t data_len);

void concat_arrays(unsigned char * buffer, int nb_args, ...);
