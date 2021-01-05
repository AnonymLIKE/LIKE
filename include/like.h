#pragma once

#include "sig.h"
#include "bn512.h"
#include "utils_like.h"

typedef struct lambda_ni
{

    mclBnG1 Rho;
    mclBnFr d;

} Lambda_ni;


typedef struct xy_ni
{

    mclBnG2 Rho;
    mclBnFr d;

} XY_ni;

typedef struct lambda_eq_ni
{

    mclBnG1 Rho;
    mclBnGT Sigma;
    mclBnFr d;

} Lambda_eq_ni;

typedef struct sst
{
    unsigned char * m;
    size_t m_len;
    unsigned char * sigma_O;
    size_t sigma_O_len;
} SST;

void setup(mclBnG1 * P, mclBnG2 * Q);

//void u_o_key_gen(char * pub_key_path, char * priv_key_path);
#define u_o_key_gen sgen_ed25519

void a_key_gen(mclBnG1 * P, mclBnFr * lambda_sk, mclBnG1 * lambda_pk, Lambda_ni * lambda_ni);

void verify_L_ni(mclBnG1 * P, int nb_args, ...);

void ake_precalc_add_lipk(mclBnG1 * L_pk, int nb_args, ...);

#define ake_precalc_get_omega concat_arrays

void ake_a_get_mx(mclBnG1 * P, mclBnG2 * Q, mclBnFr * x, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni);

void verify_mx(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * Q, mclBnG2 * xQ, unsigned char * omega, size_t omega_len, XY_ni * x_ni);

void ake_b_get_my(mclBnG2 * Q, mclBnFr * y, unsigned char * omega, size_t omega_len, mclBnG2 * yQ, XY_ni * y_ni);

void verify_my(mclBnG2 * Q, mclBnG2 * yQ, unsigned char * omega, size_t omega_len, XY_ni * y_ni);

void ake_b_get_sigma_Y_1(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1, size_t sig_len);

void verify_sigma_Y_1(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1, size_t sig_len);

void ake_a_get_sigma_X(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, size_t sig_len);

void verify_sigma_X(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, size_t sig_len);

void ake_b_get_sigma_Y_2(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len);

void verify_sigma_Y_2(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len);

void ake_a_get_shared_key(mclBnG1 * L_pk, mclBnG2 * yQ, mclBnFr * x, mclBnGT * ka);

void ake_b_get_shared_key(mclBnG1 * L_pk, mclBnG2 * xQ, mclBnFr * y, mclBnGT * kb);

void ake_O_get_sst(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len, SST * sst);

void verify_sst(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len, SST * sst);

void tdgen_get_li_T1(mclBnG1 * xP, mclBnG2 * yQ, int nb_args, ...);

void tdgen_get_li_T2(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * yQ, int nb_args, ...);

void verify_li_T2(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * yQ, int nb_args, ...);

void open_get_shared_key(mclBnGT * k, int nb_args, ...);
