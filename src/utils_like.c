#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "utils_like.h"

/*
 * Print mcl error and exit 
 * rc : return code from mcl call
 * msg : error message
 */
void handle_mcl_error(int rc, char * msg)
{

    //fprintf(stderr, msg);
    fprintf(stderr, "error msg : %s\n", msg);
    fprintf(stderr, "error code : %d\n", rc);
    exit(EXIT_FAILURE);

}

/*
 * Convert bytes array to a hexadecimal string reprersentation (without 0x)
 * data_bytes : Array of bytes 
 * data_bytes_len : Length of the array
 * Return : pointer to the resulting hexadecimal string, must be free()
 */
char *  bytes_to_hexstring(unsigned char * data_bytes, size_t data_bytes_len)
{

    char * data_hexstring = (char * ) malloc(sizeof(char) * ((data_bytes_len * 2) + 1));
   
    for(int i = 0; i < (int)data_bytes_len; i++)
    {
        sprintf(data_hexstring + (i * 2), "%02x", data_bytes[i]);
    }
    data_hexstring[(data_bytes_len * 2)] = '\0';

    return data_hexstring;

}

/*
 * Compute sha256
 * data : data to hash as a bytes array
 * data_len : length of data array
 * return : pointer to the hash as bytes array, must be free()
 */
unsigned char * sha256(unsigned char * data, size_t data_len)
{

    int rc;
    unsigned char * hash;
    unsigned int hash_len = SHA256_DIGEST_LENGTH;
    EVP_MD_CTX * md_ctx = NULL;

    md_ctx = EVP_MD_CTX_new();
    if(md_ctx == NULL)
    {
        fprintf(stderr, "EVP_MD_CTX_new failed, error 0x%lx\n", ERR_get_error());
        EVP_MD_CTX_free(md_ctx);
        exit(EXIT_FAILURE);
    }

    rc = EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    if(rc != 1)
    {
        fprintf(stderr, "EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
        EVP_MD_CTX_free(md_ctx);
        exit(EXIT_FAILURE);
    }
    
    rc = EVP_DigestUpdate(md_ctx, data, data_len);
    if(rc != 1)
    {
        fprintf(stderr, "EVP_DigestUpdate failed, error 0x%lx\n", ERR_get_error());
        EVP_MD_CTX_free(md_ctx);
        exit(EXIT_FAILURE);
    }
    
    hash = (unsigned char *)OPENSSL_malloc(EVP_MD_size(EVP_sha256()));
    if(hash == NULL)
    {
        fprintf(stderr, "OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
        EVP_MD_CTX_free(md_ctx);
        exit(EXIT_FAILURE);
    }

    rc = EVP_DigestFinal_ex(md_ctx, hash, &hash_len);
    if(rc != 1)
    {
        fprintf(stderr, "EVP_DigestFinal_ex failed, error 0x%lx\n", ERR_get_error());
        EVP_MD_CTX_free(md_ctx);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(md_ctx);

    return hash;

}

/*
 * Concatenate multiples arrays
 * buffer : destination array, there is no verification to ensure the buffer is big enougth, you must do it before calling concat_arrays in order to avoid overflow
 * nb_arg : numbe of variadic arguments
 * ... : variadic arguments, an array follow by the length of this array
 * example call : concat_array(buffer, buffer_len, 4 array1, array1_len, array2, array2_len)
 */
void concat_arrays(unsigned char * buffer, int nb_args, ...)
{

    va_list list;
    int start_index = 0;
    unsigned char * buffer_tmp;
    size_t buffer_tmp_len;

    va_start(list, nb_args);

    for(int i = 0; i < (nb_args / 2); i++)
    {
        buffer_tmp = va_arg(list, unsigned char *);
        buffer_tmp_len = va_arg(list, size_t);
        memcpy(buffer + start_index, buffer_tmp, buffer_tmp_len * sizeof(unsigned char));
        start_index += buffer_tmp_len;
    }

    va_end(list);

}
