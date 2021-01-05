#pragma once

#include "bn512.h"

void sok_G2(mclBnG2 * Q, mclBnFr * x, mclBnG2 * xQ, unsigned char * msg, size_t msg_len, mclBnG2 * Rho, mclBnFr * d);

int sokver_G2(mclBnG2 * Q, mclBnG2 * xQ, mclBnG2 * Rho, mclBnFr * d, unsigned char * msg, size_t msg_len);

void nipok_G1(mclBnG1 * P, mclBnFr * x, mclBnG1 * xP, mclBnG1 * Rho, mclBnFr * d);

int nipokver_G1(mclBnG1 * P, mclBnG1 * xP, mclBnG1 * Rho, mclBnFr * d);

void eq_nipok_G1_G2(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * Q, mclBnG2 * xQ, mclBnFr * x,  mclBnG1 * Rho,  mclBnG2 * Sigma, mclBnFr * d);

int eq_nipokver_G1_G2(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * Q, mclBnG2 * xQ, mclBnG1 * Rho,  mclBnG2 * Sigma, mclBnFr * d);

void eq_nipok_G1_GT(mclBnG1 * P, mclBnG1 * Li_pk, mclBnGT * pairing_res, mclBnGT * li_T1, mclBnFr * li_sk,  mclBnG1 * Rho,  mclBnGT * sigma, mclBnFr * d);

int eq_nipokver_G1_GT(mclBnG1 * P, mclBnG1 * Li_pk, mclBnGT * pairing_res, mclBnGT * li_T1,  mclBnG1 * Rho,  mclBnGT * sigma, mclBnFr * d);
