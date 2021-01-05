#include <stdio.h>
#include <uuid/uuid.h>

#include "like.h"
#include "bn512.h"

int main()
{

    /*******************************************************************
     *                                                                 *
     *                            VARIABLES                            *
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

    /*******************************************************************
     *                                                                 *
     *                       SETUP && KEYGEN                           *
     *                                                                 *
     * *****************************************************************/

    // Setup
    printf("Set up pairing... ");
    setup(&P, &Q);
    printf("Done\n");

    printf("Key gen... ");
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
    printf("Done\n");

    /*******************************************************************
     *                                                                 *
     *                               AKE                               *
     *                                                                 *
     * *****************************************************************/

    // *********************** AKE Precal ***********************

    printf("Ake pre-computations... ");
    verify_L_ni(&P, 4, &L1_pk, &l1_ni, &L2_pk, &l2_ni);
    ake_precalc_add_lipk(&L_pk, 2, &L1_pk, &L2_pk);
    ake_precalc_get_omega(omega, 8, id_A, id_len, id_B, id_len, id_L1, id_len, id_L2, id_len);
    printf("Done\n");


    // *************************  AKE  **************************

    printf("Ake... ");
    // A : ake_a_get_mx
    ake_a_get_mx(&P, &Q, &x, omega, omega_len, &xP, &xQ, &x_ni);
 
    // O : verify_mx
    verify_mx(&P, &xP, &Q, &xQ, omega, omega_len, &x_ni);

    // B : ake_b_get_my, verify_mx, ake_b_get_sigma_Y_1
    ake_b_get_my(&Q, &y, omega, omega_len, &yQ, &y_ni);
    verify_mx(&P, &xP, &Q, &xQ, omega, omega_len, &x_ni);
    ake_b_get_sigma_Y_1(priv_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len);

    // O : verify_my, verify_sigma_Y_1
    verify_my(&Q, &yQ, omega, omega_len, &y_ni);
    verify_sigma_Y_1(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len);

    // A : verify_my, verify_sigma_Y_1, ake_a_get_sigma_X
    verify_my(&Q, &yQ, omega, omega_len, &y_ni);
    verify_sigma_Y_1(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len);
    ake_a_get_sigma_X(priv_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len);

    // O : verify_sigma_X
    verify_sigma_X(pub_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len);

    // B : verify_sigma_X, ake_b_get_sigma_Y_2
    verify_sigma_X(pub_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len);
    ake_b_get_sigma_Y_2(priv_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len);

    // A : ake_a_get_shared_key
    ake_a_get_shared_key(&L_pk, &yQ, &x, &ka);

    // B : ake_b_get_shared_key
    ake_b_get_shared_key(&L_pk, &xQ, &y, &kb);

    // O : verify_sigma_Y_2, ake_O_get_sst
    verify_sigma_Y_2(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len);
    ake_O_get_sst(priv_key_O, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, &sst);
    printf("Done\n");

    /*******************************************************************
     *                                                                 *
     *                           VERIFICATION                          *
     *                                                                 *
     * *****************************************************************/

    // Verification
    printf("Verify_L_ni... ");
    verify_L_ni(&P, 4, &L1_pk, &l1_ni, &L2_pk, &l2_ni);
    printf("Done\n");

    printf("Verify_mx... ");
    verify_mx(&P, &xP, &Q, &xQ, omega, omega_len, &x_ni);
    printf("Done\n");

    printf("Verify_my... ");
    verify_my(&Q, &yQ, omega, omega_len, &y_ni);
    printf("Done\n");

    printf("Verify_sigma_Y_1... ");
    verify_sigma_Y_1(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sig_len);
    printf("Done\n");

    printf("Verify_sigma_X... ");
    verify_sigma_X(pub_key_A, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sig_len);
    printf("Done\n");

    printf("Verify_sigma_Y_2... ");
    verify_sigma_Y_2(pub_key_B, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len);
    printf("Done\n");

    printf("Verify_sst... ");
    verify_sst(pub_key_O, omega, omega_len, &xP, &xQ, &x_ni, &yQ, &y_ni, sigma_Y_1, sigma_X, sigma_Y_2, sig_len, &sst);
    printf("Done\n");

    /*******************************************************************
     *                                                                 *
     *                              TDGen                              *
     *                                                                 *
     * *****************************************************************/

    // TDGen
    printf("Gen trapdoors... ");
    tdgen_get_li_T1(&xP, &yQ, 4, &l1_sk, &l1_T1, &l2_sk, &l2_T1);
    tdgen_get_li_T2(&P, &xP, &yQ, 8, &L1_pk, &l1_sk, &l1_T1, &l1_T2, &L2_pk, &l2_sk, &l2_T1, &l2_T2);
    printf("Done\n");


    /*******************************************************************
     *                                                                 *
     *                              OPEN                               *
     *                                                                 *
     * *****************************************************************/

    // Open
    printf("Recover secret... ");
    verify_li_T2(&P, &xP, &yQ, 6, &L1_pk, &l1_T1, &l1_T2, &L2_pk, &l2_T1, &l2_T2);
    open_get_shared_key(&k, 2, &l1_T1, &l2_T1);
    printf("Done\n");
    printf("\n");

    /*******************************************************************
     *                                                                 *
     *                              PRINT                              *
     *                                                                 *
     * *****************************************************************/

    // Check key
    printf("Check A, B and recover key are equals : ");
    if(mclBnGT_isEqual(&ka, &kb) == 1 && mclBnGT_isEqual(&ka, &k))
    {
        printf("Equals\n");
    }
    else 
    {
        printf("Not equals\n");
    }
    printf("\n");


    // Print key
    printf("Print secret :\n");
    printf("\n");
    char buf[1024] = {0};
    mclBnGT_getStr(buf, 1024, &ka, 16);
    printf("ka = %s\n", buf);
    printf("\n");
    mclBnGT_getStr(buf, 1024, &kb, 16);
    printf("kb = %s\n", buf);
    printf("\n");
    mclBnGT_getStr(buf, 1024, &k, 16);
    printf("k = %s\n", buf);

    free(sigma_Y_1);
    free(sigma_X);
    free(sigma_Y_2);
    free(sst.m);
    free(sst.sigma_O);

    return 0;

}
