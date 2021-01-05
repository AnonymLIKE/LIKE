#include <time.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <uuid/uuid.h>

#include <openssl/sha.h>

#include <gsl/gsl_statistics_double.h>

#include "sig.h"
#include "pok.h"
#include "like.h"
#include "bn512.h"
#include "utils_like.h"

double print_trials_res(double * trials_res, int nb_trials) 
{

    double mean = gsl_stats_mean(trials_res, 1, nb_trials);
    double stddev = gsl_stats_sd_m(trials_res, 1, nb_trials, mean);
    double confidence_lo = mean - ((1.96 * stddev) / sqrt(nb_trials));
    double confidence_hi = mean + ((1.96 * stddev) / sqrt(nb_trials));
    printf("    mean                   = %f\n", mean * 1000);
    printf("    stddev                 = %f\n", stddev * 1000);
    printf("    95%% confidence inteval = [%f, %f]\n\n", confidence_lo * 1000, confidence_hi * 1000);
    return mean * 1000;

}

void mesure_pairing(int nb_trials)
{

    printf("pairing : \n");

    mclBnG1 P;
    mclBnG2 Q;
    mclBnGT e;

    mclBn_init(MCL_BN462, MCLBN_COMPILED_TIME_VAR);

    mclBnG1_hashAndMapTo(&P, "abc", 3);
    mclBnG2_hashAndMapTo(&Q, "def", 3);

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        mclBn_pairing(&e, &P, &Q);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    print_trials_res(trials_res, nb_trials);

}

void mesure_arithmetic_EC(int nb_trials)
{

    mclBnG1 P, xP;
    mclBnG2 Q, xQ;
    mclBnFr x;

    mclBn_init(MCL_BN462, MCLBN_COMPILED_TIME_VAR);

    mclBnFr_setByCSPRNG(&x);
    mclBnG1_hashAndMapTo(&P, "abc", 3);
    mclBnG2_hashAndMapTo(&Q, "def", 3);

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    printf("Scalar mult in G1 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        mclBnG1_mul(&xP, &P, &x);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }
    print_trials_res(trials_res, nb_trials);

    printf("Scalar mult in G2 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        mclBnG2_mul(&xQ, &Q, &x);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }
    print_trials_res(trials_res, nb_trials);

    printf("Add point in G1 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        mclBnG1_add(&xP, &P, &xP);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }
    print_trials_res(trials_res, nb_trials);

    printf("Add point in G2 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        mclBnG2_add(&xQ, &Q, &xQ);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }
    print_trials_res(trials_res, nb_trials);

}

void mesure_edd25519(int nb_trials)
{
    struct stat st = {0};
    size_t sig_len = ED25519_SIG_LENGTH;
    unsigned char * sig = (unsigned char *) malloc(sig_len * sizeof(unsigned char));;
    unsigned char msg[] = "Test sig";

    if (stat("./keys", &st) == -1) {
        mkdir("./keys", 0700);
    }

    sgen_ed25519("keys/pub.pem", "keys/priv.pem");

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    printf("sig ed25519 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        ssig_ed25519("keys/priv.pem", msg, sizeof(msg), &sig, &sig_len);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    print_trials_res(trials_res, nb_trials);

    printf("verif ed25519 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        sver_ed25519("keys/pub.pem", msg, sizeof(msg), sig, sig_len);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    print_trials_res(trials_res, nb_trials);

    free(sig);

}

void mesure_sok(int nb_trials)
{

    const char * G2_basePoint_hexstr = "1 0257ccc85b58dda0dfb38e3a8cbdc5482e0337e7c1cd96ed61c913820408208f9ad2699bad92e0032ae1f0aa6a8b48807695468e3d934ae1e4df 1d2e4343e8599102af8edca849566ba3c98e2a354730cbed9176884058b18134dd86bae555b783718f50af8b59bf7e850e9b73108ba6aa8cd283 0a0650439da22c1979517427a20809eca035634706e23c3fa7a6bb42fe810f1399a1f41c9ddae32e03695a140e7b11d7c3376e5b68df0db7154e 073ef0cbd438cbe0172c8ae37306324d44d5e6b0c69ac57b393f1ab370fd725cc647692444a04ef87387aa68d53743493b9eba14cc552ca2a93a";

    char msg[] = "test";
    mclBnFr x, d;
    mclBnG2 Q, xQ, Rho;

    mclBnFr_setByCSPRNG(&x);
    mclBnG2_setStr(&Q, G2_basePoint_hexstr, strlen(G2_basePoint_hexstr), 16);
    mclBnG2_mul(&xQ, &Q, &x);

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    printf("sok_G2 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();  
        sok_G2(&Q, &x, &xQ, (unsigned char *)msg, strlen(msg), &Rho, &d);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    print_trials_res(trials_res, nb_trials);

    printf("sokver_G2 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        sokver_G2(&Q, &xQ, &Rho, &d, (unsigned char *)msg, strlen(msg));
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    print_trials_res(trials_res, nb_trials);

}

void mesure_nipok(int nb_trials)
{
    
    const char * G1_basePoint_hexstr = "1 21a6d67ef250191fadba34a0a30160b9ac9264b6f95f63b3edbec3cf4b2e689db1bbb4e69a416a0b1e79239c0372e5cd70113c98d91f36b6980d 0118ea0460f7f7abb82b33676a7432a490eeda842cccfa7d788c659650426e6af77df11b8ae40eb80f475432c66600622ecaa8a5734d36fb03de";

    mclBnFr x, d;
    mclBnG1 P, xP, Rho;

    mclBnFr_setByCSPRNG(&x);
    mclBnG1_setStr(&P, G1_basePoint_hexstr, strlen(G1_basePoint_hexstr), 16);

    mclBnG1_mul(&xP, &P, &x);

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    printf("nipok_G1 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();  
        nipok_G1(&P, &x, &xP, &Rho, &d);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    print_trials_res(trials_res, nb_trials);

    printf("nipokver_G1 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        nipokver_G1(&P, &xP, &Rho, &d);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    print_trials_res(trials_res, nb_trials);

}

void mesure_eqnipok(int nb_trials)
{
    const char * G1_basePoint_hexstr = "1 21a6d67ef250191fadba34a0a30160b9ac9264b6f95f63b3edbec3cf4b2e689db1bbb4e69a416a0b1e79239c0372e5cd70113c98d91f36b6980d 0118ea0460f7f7abb82b33676a7432a490eeda842cccfa7d788c659650426e6af77df11b8ae40eb80f475432c66600622ecaa8a5734d36fb03de";
    const char * G2_basePoint_hexstr = "1 0257ccc85b58dda0dfb38e3a8cbdc5482e0337e7c1cd96ed61c913820408208f9ad2699bad92e0032ae1f0aa6a8b48807695468e3d934ae1e4df 1d2e4343e8599102af8edca849566ba3c98e2a354730cbed9176884058b18134dd86bae555b783718f50af8b59bf7e850e9b73108ba6aa8cd283 0a0650439da22c1979517427a20809eca035634706e23c3fa7a6bb42fe810f1399a1f41c9ddae32e03695a140e7b11d7c3376e5b68df0db7154e 073ef0cbd438cbe0172c8ae37306324d44d5e6b0c69ac57b393f1ab370fd725cc647692444a04ef87387aa68d53743493b9eba14cc552ca2a93a";

    mclBnFr x, d;
    mclBnG1 P, xP, Rho;
    mclBnG2 Q, xQ, Sigma;

    mclBnFr_setByCSPRNG(&x);
    mclBnG1_setStr(&P, G1_basePoint_hexstr, strlen(G1_basePoint_hexstr), 16);
    mclBnG2_setStr(&Q, G2_basePoint_hexstr, strlen(G2_basePoint_hexstr), 16);

    mclBnG1_mul(&xP, &P, &x);

    mclBnG2_mul(&xQ, &Q, &x);

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    printf("eq_nipok_G1_G2 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();    
        eq_nipok_G1_G2(&P, &xP, &Q, &xQ, &x, &Rho, &Sigma, &d);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    print_trials_res(trials_res, nb_trials);

    printf("eq_nipokver_G1_G2 : \n");
    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        eq_nipokver_G1_G2(&P, &xP, &Q, &xQ, &Rho, &Sigma, &d);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    print_trials_res(trials_res, nb_trials);

}

double mesure_ake_a_get_mx(mclBnG1 * P, mclBnG2 * Q, mclBnFr * x, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, int nb_trials)
{

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        ake_a_get_mx(P, Q, x, omega, omega_len, xP, xQ, x_ni);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);

}

double mesure_verify_mx(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * Q, mclBnG2 * xQ, unsigned char * omega, size_t omega_len, XY_ni * x_ni, int nb_trials) 
{
  
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        verify_mx(P, xP, Q, xQ, omega, omega_len, x_ni);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);

}

double mesure_ake_b_get_my(mclBnG2 * Q, mclBnFr * y, unsigned char * omega, size_t omega_len, mclBnG2 * yQ, XY_ni * y_ni, int nb_trials)
{

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        ake_b_get_my(Q, y, omega, omega_len, yQ, y_ni);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);

}

double mesure_ake_b_get_sigma_Y_1(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1, size_t sig_len, int nb_trials)
{

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        ake_b_get_sigma_Y_1(priv_key_path, omega, omega_len, xP, xQ, x_ni, yQ, y_ni, sigma_Y_1, sig_len);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);

}

double mesure_verify_my(mclBnG2 * Q, mclBnG2 * yQ, unsigned char * omega, size_t omega_len, XY_ni * y_ni, int nb_trials)
{

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        verify_my(Q, yQ, omega, omega_len, y_ni);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);

}

double mesure_verify_sigma_Y_1(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1, size_t sig_len, int nb_trials)
{

    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        verify_sigma_Y_1(pub_key_path, omega, omega_len, xP, xQ, x_ni, yQ, y_ni, sigma_Y_1, sig_len);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);

}

double mesure_ake_a_get_sigma_X(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, size_t sig_len, int nb_trials)
{
  
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        ake_a_get_sigma_X(priv_key_path, omega, omega_len, xP, xQ, x_ni, yQ, y_ni, sigma_Y_1, sigma_X, sig_len);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
  
}

double mesure_verify_sigma_X(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, size_t sig_len, int nb_trials)
{
  
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        verify_sigma_X(pub_key_path, omega, omega_len, xP, xQ, x_ni, yQ, y_ni, sigma_Y_1, sigma_X, sig_len);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
  
}

double mesure_ake_b_get_sigma_Y_2(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len, int nb_trials)
{
  
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        ake_b_get_sigma_Y_2(priv_key_path, omega, omega_len, xP, xQ, x_ni, yQ, y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
  
}

double mesure_verify_sigma_Y_2(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len, int nb_trials)
{
  
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        verify_sigma_Y_2(pub_key_path, omega, omega_len, xP, xQ, x_ni, yQ, y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
  
}

double mesure_ake_a_get_shared_key(mclBnG1 * L_pk, mclBnG2 * yQ, mclBnFr * x, mclBnGT * ka, int nb_trials)
{
  
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        ake_a_get_shared_key(L_pk, yQ, x, ka);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
  
}

double mesure_ake_b_get_shared_key(mclBnG1 * L_pk, mclBnG2 * xQ, mclBnFr * y, mclBnGT * kb, int nb_trials)
{
  
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        ake_b_get_shared_key(L_pk, xQ, y, kb);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
  
}

double mesure_ake_O_get_sst(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len, SST * sst, int nb_trials)
{
  
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        ake_O_get_sst(priv_key_path, omega, omega_len, xP, xQ, x_ni, yQ, y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, sst);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
        free(sst->m);
        free(sst->sigma_O);
    }

    return print_trials_res(trials_res, nb_trials);
  
}

double mesure_verify_sst(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len, SST * sst, int nb_trials)
{
  
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        verify_sst(pub_key_path, omega, omega_len, xP, xQ, x_ni, yQ, y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, sst);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
  
}

double mesure_verify_L_ni_for_2L(mclBnG1 * P, mclBnG1 * L1_pk, Lambda_ni * l1_ni, mclBnG1 * L2_pk, Lambda_ni * l2_ni, int nb_trials)
{
   
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        verify_L_ni(P, 4, L1_pk, l1_ni, L2_pk, l2_ni);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
     
}

double mesure_tdgen_get_li_T1_for_2L(mclBnG1 * xP, mclBnG2 * yQ, mclBnFr * l1_sk, mclBnGT * l1_T1, mclBnFr * l2_sk, mclBnGT * l2_T1, int nb_trials)
{
   
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        tdgen_get_li_T1(xP, yQ, 4, l1_sk, l1_T1, l2_sk, l2_T1);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
     
}

double mesure_tdgen_get_li_T2_for_2L(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * yQ, mclBnG1 * L1_pk, mclBnFr * l1_sk, mclBnGT * l1_T1, Lambda_eq_ni * l1_T2, mclBnG1 * L2_pk, mclBnFr * l2_sk, mclBnGT * l2_T1, Lambda_eq_ni * l2_T2, int nb_trials)
{
    
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        tdgen_get_li_T2(P, xP, yQ, 8, L1_pk, l1_sk, l1_T1, l1_T2, L2_pk, l2_sk, l2_T1, l2_T2);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
       
}

double mesure_verify_li_T2_for_2L(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * yQ, mclBnG1 * L1_pk, mclBnGT * l1_T1, Lambda_eq_ni * l1_T2, mclBnG1 * L2_pk, mclBnGT * l2_T1, Lambda_eq_ni * l2_T2, int nb_trials)
{
      
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        verify_li_T2(P, xP, yQ, 6, L1_pk, l1_T1, l1_T2, L2_pk, l2_T1, l2_T2);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
     
}

double mesure_open_get_shared_key_for_2(mclBnGT * k, mclBnGT * l1_T1, mclBnGT * l2_T1, int nb_trials)
{
      
    double trials_res[nb_trials];
    clock_t begin;
    clock_t end;

    for(int i = 0; i < nb_trials; i++)
    {
        begin = clock();
        open_get_shared_key(k, 2, l1_T1, l2_T1);
        end = clock();
        trials_res[i] = (double)(end - begin) / CLOCKS_PER_SEC;
    }

    return print_trials_res(trials_res, nb_trials);
     
}

int main(int argc, char *argv[])
{

    printf("Run multiple times differents functions of the like potocol. All mesures are in ms.\n\n");

    // Mesure perf parameter
    int nb_trials = 100;
    if( argc == 2 )
        nb_trials = atoi(argv[1]);
    printf("Number of trials : %d\n\n", nb_trials);
    double total_time_A = 0.0;
    double total_time_B = 0.0;
    double total_time_O = 0.0;
    double total_time_Ver = 0.0;
    double total_time_TDGen = 0.0;
    double total_time_Open = 0.0;


    /*******************************************************************
     *                                                                 *
     *                      INDEPENDANT MESURES                        *
     *                                                                 *
     * *****************************************************************/

    mesure_pairing(nb_trials);
    mesure_arithmetic_EC(nb_trials);
    mesure_edd25519(nb_trials);
    mesure_sok(nb_trials);
    mesure_nipok(nb_trials);
    mesure_eqnipok(nb_trials);

    /*******************************************************************
     *                                                                 *
     *                          LIKE MESURES                           *
     *                                                                 *
     * *****************************************************************/

    // General Param
    mclBnG1 P, xP;
    mclBnG2 Q, xQ, yQ;
    mclBnFr x, y; 
    XY_ni x_ni, y_ni;
    mclBnGT ka, kb, k, l1_T1, l2_T1;
    SST sst;
    Lambda_eq_ni l1_T2, l2_T2;

    // Id
    size_t id_len = sizeof(uuid_t);
    uuid_t id_A, id_B, id_L1, id_L2;
    uuid_generate_random(id_A);
    uuid_generate_random(id_B);
    uuid_generate_random(id_L1);
    uuid_generate_random(id_L2); 
    size_t omega_len = 4 * id_len;
    unsigned char omega[omega_len];

    // Keys
    char pub_key_A[] = "keys/a_pub_key.pem";
    char priv_key_A[] = "keys/a_priv_key.pem";
    char pub_key_B[] = "keys/b_pub_key.pem";
    char priv_key_B[] = "keys/b_priv_key.pem";
    char pub_key_O[] = "keys/o_pub_key.pem";
    char priv_key_O[] = "keys/o_priv_key.pem";
    mclBnG1 L1_pk, L2_pk, L_pk;
    mclBnFr l1_sk, l2_sk;
    Lambda_ni l1_ni, l2_ni;

    // Sig buffer
    size_t sig_len = ED25519_SIG_LENGTH;
    unsigned char * sigma_Y_1 = (unsigned char *) malloc(sig_len * sizeof(unsigned char));
    unsigned char * sigma_X = (unsigned char *) malloc(sig_len * sizeof(unsigned char));
    unsigned char * sigma_Y_2 = (unsigned char *) malloc(sig_len * sizeof(unsigned char));

    // Setup
    setup(&P, &Q);

    //UKeyGen A
    u_o_key_gen(pub_key_A, priv_key_A);

    // UKeyGen B
    u_o_key_gen(pub_key_B, priv_key_B);

    // UKeyGen O
    u_o_key_gen(pub_key_O, priv_key_O);

    // LambdaKeyGen L1
    a_key_gen(&P, &l1_sk, &L1_pk, &l1_ni);

    // LambdaKeyGen L2
    a_key_gen(&P, &l2_sk, &L2_pk, &l2_ni);

    // AKE Precal
    verify_L_ni(&P, 4, &L1_pk, &l1_ni, &L2_pk, &l2_ni);
    ake_precalc_add_lipk(&L_pk, 2, &L1_pk, &L2_pk);
    ake_precalc_get_omega(omega, 8, id_A, id_len, id_B, id_len, id_L1, id_len, id_L2, id_len);

    // Mesure ake_a_get_mx
    printf("ake_a_get_mx : \n");
    double time_ake_a_get_mx = mesure_ake_a_get_mx(&P, &Q, &x, omega, omega_len, &xP, &xQ, &x_ni, nb_trials);

    // A : ake_a_get_mx
    ake_a_get_mx(&P, &Q, &x, omega, omega_len, &xP, &xQ, &x_ni);
    total_time_A += time_ake_a_get_mx;

    // Mesure verify_mx
    printf("verify_mx : \n");
    double time_verify_mx = mesure_verify_mx(&P, &xP, &Q, &xQ, omega, omega_len, &x_ni, nb_trials);

    // O : verify_mx
    verify_mx(&P, &xP, &Q, &xQ, omega, omega_len, &x_ni);
    total_time_O += time_verify_mx;

    // Mesure ake_b_get_my
    printf("ake_b_get_my : \n");
    double time_ake_b_get_my = mesure_ake_b_get_my(&Q, &y, omega, omega_len, &yQ, &y_ni, nb_trials);

    // Mesure ake_b_get_sigma_Y_1
    printf("ake_b_get_sigma_Y_1 : \n");
    double time_ake_b_get_sigma_Y_1 = mesure_ake_b_get_sigma_Y_1(priv_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len, nb_trials);

    // B : ake_b_get_my, verify_mx, ake_b_get_sigma_Y_1
    verify_mx(&P, &xP, &Q, &xQ, omega, omega_len, &x_ni);
    ake_b_get_my(&Q, &y, omega, omega_len, &yQ, &y_ni);
    ake_b_get_sigma_Y_1(priv_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len);
    total_time_B += time_verify_mx + time_ake_b_get_my + time_ake_b_get_sigma_Y_1;

    // Mesure verify_my
    printf("verify_my : \n");
    double time_verify_my = mesure_verify_my(&Q, &yQ, omega, omega_len, &y_ni, nb_trials);

    // Mesure verify_sigma_Y_1
    printf("verify_sigma_Y_1 : \n");
    double time_verify_sigma_Y_1 = mesure_verify_sigma_Y_1(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len, nb_trials);

    // O : verify_my, verify_sigma_Y_1
    verify_my(&Q, &yQ, omega, omega_len, &y_ni);
    verify_sigma_Y_1(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len);
    total_time_O += time_verify_my + time_verify_sigma_Y_1;

    // Mesure ake_a_get_sigma_X
    printf("ake_a_get_sigma_X : \n");
    double time_ake_a_get_sigma_X = mesure_ake_a_get_sigma_X(priv_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len, nb_trials);

    // A : verify_my, verify_sigma_Y_1, ake_a_get_sigma_X
    verify_my(&Q, &yQ, omega, omega_len, &y_ni);
    verify_sigma_Y_1(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len);
    ake_a_get_sigma_X(priv_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len);
    total_time_A += time_verify_my + time_verify_sigma_Y_1 + time_ake_a_get_sigma_X;

    // Mesure verify_sigma_X
    printf("verify_sigma_X : \n");
    double time_verify_sigma_X = mesure_verify_sigma_X(pub_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len, nb_trials);
 
    // O : verify_sigma_X
    verify_sigma_X(pub_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len);
    total_time_O += time_verify_sigma_X;

    // Mesure ake_b_get_sigma_Y_2
    printf("ake_b_get_sigma_Y_2 : \n");
    double time_ake_b_get_sigma_Y_2 = mesure_ake_b_get_sigma_Y_2(priv_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, nb_trials);
    
    // B : verify_sigma_X, ake_b_get_sigma_Y_2
    verify_sigma_X(pub_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len);
    ake_b_get_sigma_Y_2(priv_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len);
    total_time_B += time_verify_sigma_X + time_ake_b_get_sigma_Y_2;

    // Mesure ake_a_get_shared_key
    printf("ake_a_get_shared_key : \n");
    double time_ake_a_get_shared_key = mesure_ake_a_get_shared_key(&L_pk, &yQ, &x, &ka, nb_trials);

    // A : ake_a_get_shared_key
    ake_a_get_shared_key(&L_pk, &yQ, &x, &ka);
    total_time_A += time_ake_a_get_shared_key;

    // Mesure ake_b_get_shared_key
    printf("ake_b_get_shared_key : \n");
    double time_ake_b_get_shared_key = mesure_ake_b_get_shared_key(&L_pk, &xQ, &y, &kb, nb_trials);

    // B : ake_b_get_shared_key
    ake_b_get_shared_key(&L_pk, &xQ, &y, &kb);
    total_time_B += time_ake_b_get_shared_key;

    // Mesure ake_b_get_sigma_Y_2
    printf("verify_sigma_Y_2 : \n");
    double time_verify_sigma_Y_2 = mesure_verify_sigma_Y_2(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, nb_trials);
  
    // Mesure ake_O_get_sst
    printf("ake_O_get_sst : \n");
    double time_ake_O_get_sst = mesure_ake_O_get_sst(priv_key_O, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, &sst, nb_trials);
  
    // O : verify_sigma_Y_2, ake_O_get_sst
    verify_sigma_Y_2(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len);
    ake_O_get_sst(priv_key_O, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, &sst);
    total_time_O += time_verify_sigma_Y_2 + time_ake_O_get_sst;

    // Mesure verify_sst
    printf("verify_sst : \n");
    double time_verify_sst = mesure_verify_sst(pub_key_O, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, &sst, nb_trials);

    // Mesure verify_L_ni
    printf("verify_L_ni (2 Authorities) : \n");
    double time_verify_L_ni = mesure_verify_L_ni_for_2L(&P, &L1_pk, &l1_ni, &L2_pk, &l2_ni, nb_trials);

    // Verification
    verify_L_ni(&P, 4, &L1_pk, &l1_ni, &L2_pk, &l2_ni);
    verify_mx(&P, &xP, &Q, &xQ, omega, omega_len, &x_ni);
    verify_my(&Q, &yQ, omega, omega_len, &y_ni);
    verify_sigma_Y_1(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len);
    verify_sigma_X(pub_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len);
    verify_sigma_Y_2(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len);
    verify_sst(pub_key_O, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, &sst);
    total_time_Ver += time_verify_L_ni + time_verify_mx + time_verify_my + time_verify_sigma_Y_1 + time_verify_sigma_X + time_verify_sigma_Y_2 + time_verify_sst;

    // Mesure tdgen_get_li_T1
    printf("tdgen_get_li_T1 (2 Authorities) : \n");
    double time_tdgen_get_li_T1_for_2L = mesure_tdgen_get_li_T1_for_2L(&xP, &yQ, &l1_sk, &l1_T1, &l2_sk, &l2_T1, nb_trials);

    // Mesure tdgen_get_li_T2
    printf("tdgen_get_li_T2 (2 Authorities) : \n");
    double time_tdgen_get_li_T2_for_2L = mesure_tdgen_get_li_T2_for_2L(&P, &xP, &yQ, &L1_pk, &l1_sk, &l1_T1, &l1_T2, &L2_pk, &l2_sk, &l2_T1, &l2_T2, nb_trials);

    // TDGen
    tdgen_get_li_T1(&xP, &yQ, 4, &l1_sk, &l1_T1, &l2_sk, &l2_T1);
    tdgen_get_li_T2(&P, &xP, &yQ, 8, &L1_pk, &l1_sk, &l1_T1, &l1_T2, &L2_pk, &l2_sk, &l2_T1, &l2_T2);
    total_time_TDGen += time_tdgen_get_li_T1_for_2L + time_tdgen_get_li_T2_for_2L;
    
    // Mesure verify_li_T2
    printf("verify_li_T2 (2 Authorities) : \n");
    double time_verify_li_T2_for_2 = mesure_verify_li_T2_for_2L(&P, &xP, &yQ, &L1_pk, &l1_T1, &l1_T2, &L2_pk, &l2_T1, &l2_T2, nb_trials);

    // Mesure open_get_shared_key
    printf("open_get_shared_key (2 Authorities) : \n");
    double time_open_get_shared_key_for_2 = mesure_open_get_shared_key_for_2(&k, &l1_T1, &l2_T1, nb_trials);
    
    // Open
    verify_li_T2(&P, &xP, &yQ, 6, &L1_pk, &l1_T1, &l1_T2, &L2_pk, &l2_T1, &l2_T2);
    open_get_shared_key(&k, 2, &l1_T1, &l2_T1);
    total_time_Open += time_verify_li_T2_for_2 + time_open_get_shared_key_for_2;

    // Check key
    int res = mclBnGT_isEqual(&ka, &kb);
    if(res != 1)
    {
        printf("Keys not equal\n");
    }
    res = mclBnGT_isEqual(&ka, &k);
    if(res != 1)
    {
        printf("Keys not equal\n");
    }

    printf("Total CPU running time for A : %f\n", total_time_A);
    printf("Total CPU running time for B : %f\n", total_time_B);
    printf("Total CPU running time for O : %f\n", total_time_O);
    printf("Total CPU running time for Verification : %f\n", total_time_Ver);
    printf("Total CPU running time for TDGen (2 Authorities) : %f\n", total_time_TDGen);
    printf("Total CPU running time for Open (2 Authorities) : %f\n", total_time_Open);

    free(sigma_Y_1);
    free(sigma_X);
    free(sigma_Y_2);
    free(sst.m);
    free(sst.sigma_O);

    return 0;

}
