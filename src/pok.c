#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>

#include "pok.h"
#include "bn512.h"
#include "utils_like.h"

/*
 * Compute a Signature of knowledge of the message m wih the xQ = x * Q log over the group G2 
 * Use the Shnorr algorithm with Fiat-Shamir heuristic (replace challenge by hash of the message concatenate with points of G2 Q, xQ and Rho)
 * Q : Base point of the G2 elliptic curve group
 * x : secret integer in Fr
 * xQ : xQ <-- x * Q
 * msg : message to sign as bytes array
 * msg_len : len of the message
 * Rho : buffer pf G2 object to receive Rho <-- rQ
 * d : buffe for Fr object to receive d <-- (e * x) + r
 */
void sok_G2(mclBnG2 * Q, mclBnFr * x, mclBnG2 * xQ, unsigned char * msg, size_t msg_len, mclBnG2 * Rho, mclBnFr * d)
{

    int rc;
    mclBnFr r, e;

    // r <-$- Fr
    rc = mclBnFr_setByCSPRNG(&r);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBnFr_setByCSPRNG");
    }

    // Rho <-- rQ
    mclBnG2_mul(Rho, Q, &r);

    // Get H(rho||Q||xQ||msg)
    size_t serialize_len = mclBn_getG1ByteSize() * 2;
    unsigned char rho_bytes[serialize_len];
    unsigned char q_bytes[serialize_len];
    unsigned char xq_bytes[serialize_len];
    rc  = mclBnG2_serialize(rho_bytes, serialize_len, Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    rc  = mclBnG2_serialize(q_bytes, serialize_len, Q);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    rc  = mclBnG2_serialize(xq_bytes, serialize_len, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    size_t buffer_len = (serialize_len * 3) + msg_len;
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 8, rho_bytes, serialize_len, q_bytes, serialize_len, xq_bytes, serialize_len, msg, msg_len);
    unsigned char * hash = sha256(buffer, buffer_len);

    // e <-- H(rho||Q||xQ||msg) mod r
    char * e_str = bytes_to_hexstring(hash, SHA256_DIGEST_LENGTH);
    mclBnFr_setStr(&e, e_str, strnlen(e_str, (SHA256_DIGEST_LENGTH * 2) + 1), 16);

    // d <-- (e * x) + r
    mclBnFr_mul(d, &e, x);
    mclBnFr_add(d, d, &r);

    free(hash);
    free(e_str);

}

/*
 * Verfify a sok_G2 signature of knowledge 
 * Q : Base point of the G2 elliptic curve group
 * xQ : xQ <-- x * Q
 * Rho : Rho <-- rQ
 * d : d <-- (e * x) + r
 * msg : message to sign as bytes array
 * msg_len : len of the message
 * return : 1 if success
 */
int sokver_G2(mclBnG2 * Q, mclBnG2 * xQ, mclBnG2 * Rho, mclBnFr * d, unsigned char * msg, size_t msg_len)
{

    int rc;
    mclBnFr e;
    mclBnG2 A, B;

    // Get H(rho||Q||xQ||msg)
    size_t serialize_len = mclBn_getG1ByteSize() * 2;
    unsigned char rho_bytes[serialize_len];
    unsigned char q_bytes[serialize_len];
    unsigned char xq_bytes[serialize_len];
    rc  = mclBnG2_serialize(rho_bytes, serialize_len, Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    rc  = mclBnG2_serialize(q_bytes, serialize_len, Q);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    rc  = mclBnG2_serialize(xq_bytes, serialize_len, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    size_t buffer_len = (serialize_len * 3) + msg_len;
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 8, rho_bytes, serialize_len, q_bytes, serialize_len, xq_bytes, serialize_len, msg, msg_len);
    unsigned char * hash = sha256(buffer, buffer_len);
    
    // e <-- H(rho||Q||xQ||msg) mod r
    char * e_str = bytes_to_hexstring(hash, SHA256_DIGEST_LENGTH);
    mclBnFr_setStr(&e, e_str, strnlen(e_str, (SHA256_DIGEST_LENGTH * 2) + 1), 16);

    // A <-- dQ
    mclBnG2_mul(&A, Q, d);

    // B <-- e(xQ) + Rho  
    mclBnG2_mul(&B, xQ, &e);
    mclBnG2_add(&B, &B, Rho);

    free(hash);
    free(e_str);

    return mclBnG2_isEqual(&A, &B);

}

/*
 * Compute a non-interactive zero-knowledge proof of the xP = x * P log over the group G1
 * Use the Schnorr algorithm with Fiat-Shamir heuristic (replace challenge by hash of points of G1 P, xP and Rho)
 * P : Base point of the G1 elliptic curve group
 * x : secret integer in Fr
 * xP : xP <-- x * P
 * Rho : buffer of G1 object to receive Rho <-- rP
 * d : buffer of Fr object to receive d <-- (e * x) + r
 */
void nipok_G1(mclBnG1 * P, mclBnFr * x, mclBnG1 * xP, mclBnG1 * Rho, mclBnFr * d)
{

    int rc;
    mclBnFr r, e;

    // r <-$- Fr
    rc = mclBnFr_setByCSPRNG(&r);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBnFr_setByCSPRNG");
    }

    // Rho <-- rP
    mclBnG1_mul(Rho, P, &r);

    // Get H(rho||P||xP)
    size_t serialize_len = mclBn_getG1ByteSize();
    unsigned char rho_bytes[serialize_len];
    unsigned char p_bytes[serialize_len];
    unsigned char xp_bytes[serialize_len];
    rc  = mclBnG1_serialize(rho_bytes, serialize_len, Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG1_serialize(p_bytes, serialize_len, P);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG1_serialize(xp_bytes, serialize_len, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    size_t buffer_len = (serialize_len * 3);
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 6, rho_bytes, serialize_len, p_bytes, serialize_len, xp_bytes, serialize_len);
    unsigned char * hash = sha256(buffer, buffer_len);

    // e <-- H(rho||P||xP) mod r
    char * e_str = bytes_to_hexstring(hash, SHA256_DIGEST_LENGTH);
    mclBnFr_setStr(&e, e_str, strnlen(e_str, (SHA256_DIGEST_LENGTH * 2) + 1), 16);

    // d <-- (e * x) + r
    mclBnFr_mul(d, &e, x);
    mclBnFr_add(d, d, &r);

    free(hash);
    free(e_str);

}

/*
 * Verfify a nipok_G1 non-interactive zero-knowledge proof
 * P : Base point of the G1 elliptic curve group
 * xP : xP <-- x * P
 * Rho : Rho <-- rP
 * d : d <-- (e * x) + r
 * return : 1 if success
 */
int nipokver_G1(mclBnG1 * P, mclBnG1 * xP, mclBnG1 * Rho, mclBnFr * d)
{

    int rc;
    mclBnFr e;
    mclBnG1 A, B;

    // Get H(rho||P||xP)
    size_t serialize_len = mclBn_getG1ByteSize();
    unsigned char rho_bytes[serialize_len];
    unsigned char p_bytes[serialize_len];
    unsigned char xp_bytes[serialize_len];
    rc  = mclBnG1_serialize(rho_bytes, serialize_len, Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG1_serialize(p_bytes, serialize_len, P);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG1_serialize(xp_bytes, serialize_len, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    size_t buffer_len = (serialize_len * 3);
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 6, rho_bytes, serialize_len, p_bytes, serialize_len, xp_bytes, serialize_len);
    unsigned char * hash = sha256(buffer, buffer_len);
    
    // e <-- H(rho||P||xP) mod r
    char * e_str = bytes_to_hexstring(hash, SHA256_DIGEST_LENGTH);
    mclBnFr_setStr(&e, e_str, strnlen(e_str, (SHA256_DIGEST_LENGTH * 2) + 1), 16);

    // A <-- dP
    mclBnG1_mul(&A, P, d);

    // B <-- e(xP) + Rho  
    mclBnG1_mul(&B, xP, &e);
    mclBnG1_add(&B, &B, Rho);

    free(hash);
    free(e_str);

    return mclBnG1_isEqual(&A, &B);

}

/*
 * Compute a non-interactive zero-knowledge proof of the equality of the xP = x * P log over the group G1 and the xQ = x * Q log over the group G2 
 * Use the Chaum and Pedersen protocol with Fiat-Shamir heuristic (replace challenge by hash of points Rho||Sigma||P||Q||xP||xQ)
 * P : Base point of the G1 elliptic curve group
 * xP : xP <-- x * P
 * Q : Base point of the G2 elliptic curve group
 * xQ : xQ <-- x * Q
 * x : secret integer in Fr
 * Rho : buffer of G1 object to receive Rho <-- rP
 * Sigma : buffer of G2 object to receive Sigma <-- rQ
 * d : buffer of Fr object to receive d <-- (e * x) + r
 */
void eq_nipok_G1_G2(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * Q, mclBnG2 * xQ, mclBnFr * x,  mclBnG1 * Rho,  mclBnG2 * Sigma, mclBnFr * d)
{

    int rc;
    mclBnFr r, e;

    // r <-$- Fr
    rc = mclBnFr_setByCSPRNG(&r);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBnFr_setByCSPRNG");
    }   

    // Rho <-- rP
    mclBnG1_mul(Rho, P, &r);

    // Sigma <-- rQ
    mclBnG2_mul(Sigma, Q, &r);

    // Get H(Rho||Sigma||P||Q||xP||xQ)
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    unsigned char rho_bytes[serialize_len_G1];
    unsigned char p_bytes[serialize_len_G1];
    unsigned char xp_bytes[serialize_len_G1];
    unsigned char sigma_bytes[serialize_len_G2];
    unsigned char q_bytes[serialize_len_G2];
    unsigned char xq_bytes[serialize_len_G2];
    rc  = mclBnG1_serialize(rho_bytes, serialize_len_G1, Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG1_serialize(p_bytes, serialize_len_G1, P);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG1_serialize(xp_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(sigma_bytes, serialize_len_G2, Sigma);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    rc  = mclBnG2_serialize(q_bytes, serialize_len_G2, Q);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    rc  = mclBnG2_serialize(xq_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    size_t buffer_len = (serialize_len_G1 * 3) + (serialize_len_G2 * 3);
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 12, rho_bytes, serialize_len_G1, p_bytes, serialize_len_G1, xp_bytes, serialize_len_G1,
                                          sigma_bytes, serialize_len_G2, q_bytes, serialize_len_G2, xq_bytes, serialize_len_G2);
    unsigned char * hash = sha256(buffer, buffer_len);

    // e <-- H(Rho||Sigma||P||Q||xP||xQ) mod r
    char * e_str = bytes_to_hexstring(hash, SHA256_DIGEST_LENGTH);
    mclBnFr_setStr(&e, e_str, strnlen(e_str, (SHA256_DIGEST_LENGTH * 2) + 1), 16);

    // d <-- (e * x) + r
    mclBnFr_mul(d, &e, x);
    mclBnFr_add(d, d, &r);

    free(hash);
    free(e_str);

}

/*
 * Verfify a eq_nipok_G1_G2 non-interactive zero-knowledge proof
 * P : Base point of the G1 elliptic curve group
 * xP : xP <-- x * P
 * Q : Base point of the G2 elliptic curve group
 * xQ : xQ <-- x * Q
 * Rho : Rho <-- rP
 * Sigma : Sigma <-- rQ
 * d : d <-- (e * x) + r
 * return : 1 if success
 */
int eq_nipokver_G1_G2(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * Q, mclBnG2 * xQ, mclBnG1 * Rho,  mclBnG2 * Sigma, mclBnFr * d)
{

    int rc;
    mclBnFr e;
    mclBnG1 A1, B1;
    mclBnG2 A2, B2;

    // Get H(Rho||Sigma||P||Q||xP||xQ)
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    unsigned char rho_bytes[serialize_len_G1];
    unsigned char p_bytes[serialize_len_G1];
    unsigned char xp_bytes[serialize_len_G1];
    unsigned char sigma_bytes[serialize_len_G2];
    unsigned char q_bytes[serialize_len_G2];
    unsigned char xq_bytes[serialize_len_G2];
    rc  = mclBnG1_serialize(rho_bytes, serialize_len_G1, Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG1_serialize(p_bytes, serialize_len_G1, P);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG1_serialize(xp_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(sigma_bytes, serialize_len_G2, Sigma);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    rc  = mclBnG2_serialize(q_bytes, serialize_len_G2, Q);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    rc  = mclBnG2_serialize(xq_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_serialize");
    }
    size_t buffer_len = (serialize_len_G1 * 3) + (serialize_len_G2 * 3);
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 12, rho_bytes, serialize_len_G1, p_bytes, serialize_len_G1, xp_bytes, serialize_len_G1,
                                          sigma_bytes, serialize_len_G2, q_bytes, serialize_len_G2, xq_bytes, serialize_len_G2);
    unsigned char * hash = sha256(buffer, buffer_len);

    // e <-- H(Rho||Sigma||P||Q||xP||xQ) mod r
    char * e_str = bytes_to_hexstring(hash, SHA256_DIGEST_LENGTH);
    mclBnFr_setStr(&e, e_str, strnlen(e_str, (SHA256_DIGEST_LENGTH * 2) + 1), 16);

    // A1 <-- d * P
    mclBnG1_mul(&A1, P, d);

    // B1 <-- (P * e) + Rho
    mclBnG1_mul(&B1, xP, &e);
    mclBnG1_add(&B1, &B1, Rho);

    // A2 <-- d * Q
    mclBnG2_mul(&A2, Q, d);

    // B2 <-- (e * Q) + Sigma
    mclBnG2_mul(&B2, xQ, &e);
    mclBnG2_add(&B2, &B2, Sigma);

    free(hash);
    free(e_str);

    return mclBnG1_isEqual(&A1, &B1) && mclBnG2_isEqual(&A2, &B2);

}

/*
 */
void eq_nipok_G1_GT(mclBnG1 * P, mclBnG1 * Li_pk, mclBnGT * pairing_res, mclBnGT * li_T1, mclBnFr * li_sk,  mclBnG1 * Rho,  mclBnGT * sigma, mclBnFr * d)
{

    int rc;
    mclBnFr r, e;

    // r <-$- Fr
    rc = mclBnFr_setByCSPRNG(&r);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBnFr_setByCSPRNG");
    }   

    // Rho <-- rP
    mclBnG1_mul(Rho, P, &r);

    // Sigma <-- rQ
    mclBnGT_pow(sigma, pairing_res, &r);

    // Get H(Rho||Sigma||P||pairing_res||Li_pk||li_T1)
    char rho_str[4096];
    size_t rho_str_len = mclBnG1_getStr(rho_str, sizeof(rho_str), Rho, 16);

    char sigma_str[4096];
    size_t sigma_str_len = mclBnGT_getStr(sigma_str, sizeof(sigma_str), sigma, 16);

    char p_str[4096];
    size_t p_str_len = mclBnG1_getStr(p_str, sizeof(p_str), P, 16);

    char pairing_res_str[4096];
    size_t pairing_res_str_len = mclBnGT_getStr(pairing_res_str, sizeof(pairing_res_str), pairing_res, 16);
    
    char li_pk_str[4096];
    size_t li_pk_str_len = mclBnG1_getStr(li_pk_str, sizeof(li_pk_str), Li_pk, 16);

    char li_T1_str[4096];
    size_t li_T1_str_len = mclBnGT_getStr(li_T1_str, sizeof(li_T1_str), li_T1, 16);

    size_t buffer_len = rho_str_len + sigma_str_len + p_str_len + pairing_res_str_len + li_pk_str_len + li_T1_str_len;
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 12, 
                        rho_str, rho_str_len,
                        sigma_str, sigma_str_len,
                        p_str, p_str_len,
                        pairing_res_str, pairing_res_str_len,
                        li_pk_str, li_pk_str_len,
                        li_T1_str, li_T1_str_len);
            

    unsigned char * hash = sha256(buffer, buffer_len);

    // e <-- H(Rho||Sigma||P||Q||xP||xQ) mod r
    char * e_str = bytes_to_hexstring(hash, SHA256_DIGEST_LENGTH);
    mclBnFr_setStr(&e, e_str, strnlen(e_str, (SHA256_DIGEST_LENGTH * 2) + 1), 16);

    // d <-- (e * x) + r
    mclBnFr_mul(d, &e, li_sk);
    mclBnFr_add(d, d, &r);

    free(hash);
    free(e_str);

}

/*
 */
int eq_nipokver_G1_GT(mclBnG1 * P, mclBnG1 * Li_pk, mclBnGT * pairing_res, mclBnGT * li_T1,  mclBnG1 * Rho,  mclBnGT * sigma, mclBnFr * d)
{

    mclBnFr e;
    mclBnG1 A1, B1;
    mclBnGT a2, b2;

    // Get H(Rho||Sigma||P||pairing_res||Li_pk||li_T1)
    char rho_str[4096];
    size_t rho_str_len = mclBnG1_getStr(rho_str, sizeof(rho_str), Rho, 16);

    char sigma_str[4096];
    size_t sigma_str_len = mclBnGT_getStr(sigma_str, sizeof(sigma_str), sigma, 16);

    char p_str[4096];
    size_t p_str_len = mclBnG1_getStr(p_str, sizeof(p_str), P, 16);

    char pairing_res_str[4096];
    size_t pairing_res_str_len = mclBnGT_getStr(pairing_res_str, sizeof(pairing_res_str), pairing_res, 16);
    
    char li_pk_str[4096];
    size_t li_pk_str_len = mclBnG1_getStr(li_pk_str, sizeof(li_pk_str), Li_pk, 16);

    char li_T1_str[4096];
    size_t li_T1_str_len = mclBnGT_getStr(li_T1_str, sizeof(li_T1_str), li_T1, 16);

    size_t buffer_len = rho_str_len + sigma_str_len + p_str_len + pairing_res_str_len + li_pk_str_len + li_T1_str_len;
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 12, 
                        rho_str, rho_str_len,
                        sigma_str, sigma_str_len,
                        p_str, p_str_len,
                        pairing_res_str, pairing_res_str_len,
                        li_pk_str, li_pk_str_len,
                        li_T1_str, li_T1_str_len);
            

    unsigned char * hash = sha256(buffer, buffer_len);

    // e <-- H(Rho||Sigma||P||pairing_res||Li_pk||li_T1) mod r
    char * e_str = bytes_to_hexstring(hash, SHA256_DIGEST_LENGTH);
    mclBnFr_setStr(&e, e_str, strnlen(e_str, (SHA256_DIGEST_LENGTH * 2) + 1), 16);

    // A1 <-- d * P
    mclBnG1_mul(&A1, P, d);

    // B1 <-- (P * e) + Rho
    mclBnG1_mul(&B1, Li_pk, &e);
    mclBnG1_add(&B1, &B1, Rho);

    // a2 <-- pairing_res^(d)
    mclBnGT_pow(&a2, pairing_res, d);

    // b2 <-- li_T1^(e) + sigma
    mclBnGT_pow(&b2, li_T1, &e);
    mclBnGT_mul(&b2, &b2, sigma);

    free(hash);
    free(e_str);

    return mclBnG1_isEqual(&A1, &B1) && mclBnGT_isEqual(&a2, &b2);

}
