#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h> 
#include <openssl/pem.h>

#include "sig.h"

/*
 * Create an ed25519 public/private key pair and store them in PEM format
 * pub_key_path : path and name of the file to store the public key
 * priv_key_path : path and name of the file to store the private key
 */
void sgen_ed25519(char * pub_key_path, char * priv_key_path)
{

    int rc;
    int result = 0;
    FILE * file_pub = NULL;
    FILE * file_priv = NULL;
    EVP_PKEY * pkey = NULL;
    EVP_PKEY_CTX * pkey_ctx = NULL;

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if(pkey_ctx == NULL) 
    {
        fprintf(stderr, "EVP_PKEY_CTX_new_id failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_PKEY_keygen_init(pkey_ctx);
    if(rc != 1)
    {
        fprintf(stderr, "EVP_PKEY_keygen_init failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_PKEY_keygen(pkey_ctx, &pkey);
    if(rc != 1)
    {
        fprintf(stderr, "EVP_PKEY_keygen failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    file_pub = fopen(pub_key_path, "w");
    if(file_pub == NULL)
    {
        fprintf(stderr, "Open %s failed\n", pub_key_path);
        goto err;
    }

    rc = PEM_write_PUBKEY(file_pub, pkey);
    if(rc != 1)
    {
        fprintf(stderr, "PEM_write_PUBKEY failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }
    
    file_priv = fopen(priv_key_path, "w");
    if(file_priv == NULL)
    {
        fprintf(stderr, "Open %s failed\n", priv_key_path);
        goto err;
    }
    
    rc = PEM_write_PrivateKey(file_priv, pkey, NULL, NULL, 0, NULL, NULL);
    if(rc != 1)
    {
        fprintf(stderr, "PEM_write_PrivateKey failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    result = 1;

    err:
        fclose(file_pub);
        fclose(file_priv);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(pkey);
        if(result != 1)
            exit(EXIT_FAILURE);

}

/*
 * Sign a message using ed25519 signature scheme
 * priv_key_path : path to the file containing the pivate key in PEM format
 * msg : message to sign as bytes array
 * msg_len : length of the array msg
 * sig : address of pointer to store the resulting signature
 * sig_len : length of the signature in bytes
 */
void ssig_ed25519(char * priv_key_path, const unsigned char * msg, size_t msg_len, unsigned char ** sig, size_t * sig_len)
{

    int rc;
    int result = 0;
    EVP_PKEY * pkey = NULL;
    FILE * file_priv = NULL;
    EVP_MD_CTX  * md_ctx = NULL;

    file_priv = fopen(priv_key_path, "r");
    if(file_priv == NULL)
    {
        fprintf(stderr, "Open %s failed\n", priv_key_path);
        goto err;
    }
   
    pkey = PEM_read_PrivateKey(file_priv, NULL, NULL, NULL);
    if(pkey == NULL)
    {
        fprintf(stderr, "PEM_read_PrivateKey failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    md_ctx = EVP_MD_CTX_create();
    if(md_ctx == NULL) 
    {
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey);
    if(rc != 1)
    {
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestSign(md_ctx, *sig, sig_len, msg, msg_len);
    if(rc != 1)
    {
        printf("EVP_DigestSign failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    result = 1;

    err:
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        fclose(file_priv);
        if(result != 1)
            exit(EXIT_FAILURE);

}

/*
 * Verify an ed25519 signature
 * pub_key_path : path to the file containing the public key in PEM format
 * msg : the message as bytes array
 * msg_len : length of the array msg
 * sig : the signature of msg
 * sig_len : length of the signature in bytes
 * return : 1 if verification succed
 */
void sver_ed25519(char * pub_key_path, const unsigned char * msg, size_t msg_len, unsigned char * sig, size_t sig_len)
{

    int rc;
    int result = 0;
    FILE * file_pub = NULL;
    EVP_PKEY * pkey = NULL;
    EVP_MD_CTX  * md_ctx = NULL;

    file_pub = fopen(pub_key_path, "r");
    if(file_pub == NULL)
    {
        fprintf(stderr, "Open %s failed\n", pub_key_path);
        goto err;
    }

    pkey = PEM_read_PUBKEY(file_pub, NULL, NULL, NULL);
    if(pkey == NULL)
    {
        fprintf(stderr, "PEM_read_PUBKEY failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    md_ctx = EVP_MD_CTX_create();
    if(md_ctx == NULL) 
    {
        printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey);
    if(rc != 1)
    {
        printf("EVP_DigestVerifyInit failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }

    rc = EVP_DigestVerify(md_ctx, sig, sig_len, msg, msg_len);
    if(rc != 1)
    {
        printf("EVP_DigestVerify failed, error 0x%lx\n", ERR_get_error());
        goto err;
    }  

    result = 1;

    err:
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        fclose(file_pub);
        if(result != 1)
            exit(EXIT_FAILURE);

}
