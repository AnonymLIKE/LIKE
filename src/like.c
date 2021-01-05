#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "pok.h"
#include "like.h"
#include "bn512.h"
#include "utils_like.h"

const char * G1_basePoint_hexstr = "1 21a6d67ef250191fadba34a0a30160b9ac9264b6f95f63b3edbec3cf4b2e689db1bbb4e69a416a0b1e79239c0372e5cd70113c98d91f36b6980d 0118ea0460f7f7abb82b33676a7432a490eeda842cccfa7d788c659650426e6af77df11b8ae40eb80f475432c66600622ecaa8a5734d36fb03de";
const char * G2_basePoint_hexstr = "1 0257ccc85b58dda0dfb38e3a8cbdc5482e0337e7c1cd96ed61c913820408208f9ad2699bad92e0032ae1f0aa6a8b48807695468e3d934ae1e4df 1d2e4343e8599102af8edca849566ba3c98e2a354730cbed9176884058b18134dd86bae555b783718f50af8b59bf7e850e9b73108ba6aa8cd283 0a0650439da22c1979517427a20809eca035634706e23c3fa7a6bb42fe810f1399a1f41c9ddae32e03695a140e7b11d7c3376e5b68df0db7154e 073ef0cbd438cbe0172c8ae37306324d44d5e6b0c69ac57b393f1ab370fd725cc647692444a04ef87387aa68d53743493b9eba14cc552ca2a93a";

/*
 * Init pairing over a bn462 curve and set generator of G1 and G2
 * P : pointer to store the G1 generator
 * G : pointer to store the G2 generator
 */
void setup(mclBnG1 * P, mclBnG2 * Q)
{

    int rc;

    rc = mclBn_init(MCL_BN462, MCLBN_COMPILED_TIME_VAR);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBn_init");
    }

    rc = mclBnG1_setStr(P, G1_basePoint_hexstr, strlen(G1_basePoint_hexstr), 16);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_setStr");
    }

    rc = mclBnG2_setStr(Q, G2_basePoint_hexstr, strlen(G2_basePoint_hexstr), 16);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBnG2_setStr");
    }

}

/*
 * Generate a signature key pair in pem format for a user or for an operator
 * pub_key_path : path and name of the file to store the public key
 * priv_key_path : path and name of the file to store the private key
 */
/*void u_o_key_gen(char * pub_key_path, char * priv_key_path)
{

    sgen_ed25519(pub_key_path, priv_key_path);

}*/

/*
 *
 */
void a_key_gen(mclBnG1 * P, mclBnFr * lambda_sk, mclBnG1 * lambda_pk, Lambda_ni * lambda_ni)
{

    int rc;

    rc = mclBnFr_setByCSPRNG(lambda_sk);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBnFr_setByCSPRNG");
    }

    mclBnG1_mul(lambda_pk, P, lambda_sk);

    nipok_G1(P, lambda_sk, lambda_pk, &lambda_ni->Rho, &lambda_ni->d);

}

/*
 *
 */
void verify_L_ni(mclBnG1 * P, int nb_args, ...)
{

    va_list list;
    mclBnG1 * Li_pk;
    Lambda_ni * li_ni;

    va_start(list, nb_args);

    for(int i = 0; i < (nb_args / 2); i++)
    {
        Li_pk = va_arg(list, mclBnG1 *);
        li_ni = va_arg(list, Lambda_ni *);
        if(nipokver_G1(P, Li_pk, &li_ni->Rho, &li_ni->d) != 1)
        {
            fprintf(stderr, "NIZKP verification failed\n");
            exit(EXIT_FAILURE);
        }
    }

    va_end(list);

}

/*
 *
 */
void ake_precalc_add_lipk(mclBnG1 * L_pk, int nb_args, ...)
{

    va_list list;
    mclBnG1 * Li_pk_current;
    mclBnG1 * Li_pk_next;

    va_start(list, nb_args);

    Li_pk_current = va_arg(list, mclBnG1 *);

    for(int i = 0; i < nb_args - 1; i++)
    {
        Li_pk_next = va_arg(list, mclBnG1 *);
        mclBnG1_add(L_pk, Li_pk_current, Li_pk_next);
        Li_pk_current = Li_pk_next;
    }

    va_end(list);

}

/*
 */
void ake_a_get_mx(mclBnG1 * P, mclBnG2 * Q, mclBnFr * x, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni) 
{

    int rc;

    // r <-$- Fr
    rc = mclBnFr_setByCSPRNG(x);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBnFr_setByCSPRNG");
    }

    // xP <-- x * P
    mclBnG1_mul(xP, P, x);

    // xQ <-- x * Q
    mclBnG2_mul(xQ, Q, x);

    // ni_X <-- SoK_omega(x : xQ <-- x * Q)
    sok_G2(Q, x, xQ, omega, omega_len, &x_ni->Rho, &x_ni->d);

}

/*
 *
 */
void verify_mx(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * Q, mclBnG2 * xQ, unsigned char * omega, size_t omega_len, XY_ni * x_ni) 
{

    mclBnGT e1, e2;

    if(sokver_G2(Q, xQ, &x_ni->Rho, &x_ni->d, omega, omega_len) != 1 )
    {
        fprintf(stderr, "Verify mx failed --> verify ni_x failed\n");
        exit(EXIT_FAILURE);
    }

    mclBn_pairing(&e1, xP, Q);
    mclBn_pairing(&e2, P, xQ);
    if(mclBnGT_isEqual(&e1, &e2) != 1)
    {
        fprintf(stderr, "Verify mx failed --> e(xP, Q) =/= e(P, xQ)\n");
        exit(EXIT_FAILURE);
    }

}

/*
 */
void ake_b_get_my(mclBnG2 * Q, mclBnFr * y, unsigned char * omega, size_t omega_len, mclBnG2 * yQ, XY_ni * y_ni)
{

    int rc;

    // y <-$- Fr
    rc = mclBnFr_setByCSPRNG(y);
    if(rc != 0)
    {
        handle_mcl_error(rc, "Error with mclBnFr_setByCSPRNG");
    }

    // yQ <-- y * Q
    mclBnG2_mul(yQ, Q, y);

    // ni_Y <-- SoK_omega(y : yQ <-- y * Q)
    sok_G2(Q, y, yQ, omega, omega_len, &y_ni->Rho, &y_ni->d);

}

/*
 */
void verify_my(mclBnG2 * Q, mclBnG2 * yQ, unsigned char * omega, size_t omega_len, XY_ni * y_ni)
{

    if(sokver_G2(Q, yQ, &y_ni->Rho, &y_ni->d, omega, omega_len) != 1)
    {
        fprintf(stderr, "Verify my failed --> verify ni_y failed\n");
        exit(EXIT_FAILURE);
    }

}

/*
 */
void ake_b_get_sigma_Y_1(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1, size_t sig_len)
{
    
    int rc;

    // Serialize mcl ec pairing objects
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    size_t serialize_len_Fr = mclBn_getFrByteSize();
    unsigned char mx_xP_bytes[serialize_len_G1];
    unsigned char mx_xQ_bytes[serialize_len_G2];
    unsigned char mx_Rho_bytes[serialize_len_G2];
    unsigned char mx_d_bytes[serialize_len_Fr];
    unsigned char my_yQ_bytes[serialize_len_G2];
    unsigned char my_Rho_bytes[serialize_len_G2];
    unsigned char my_d_bytes[serialize_len_Fr];
    rc  = mclBnG1_serialize(mx_xP_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_xQ_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_Rho_bytes, serialize_len_G2, &x_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(mx_d_bytes, serialize_len_Fr, &x_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_yQ_bytes, serialize_len_G2, yQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_Rho_bytes, serialize_len_G2, &y_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(my_d_bytes, serialize_len_Fr, &y_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }

    // Concat data
    size_t buffer_len = (serialize_len_G1) + (serialize_len_G2 * 4) + (serialize_len_Fr * 2) + omega_len;
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 16, 
                    omega, omega_len,
                    mx_xP_bytes, serialize_len_G1,
                    mx_xQ_bytes, serialize_len_G2,
                    mx_Rho_bytes, serialize_len_G2,
                    mx_d_bytes, serialize_len_Fr,
                    my_yQ_bytes, serialize_len_G2,
                    my_Rho_bytes, serialize_len_G2,
                    my_d_bytes, serialize_len_Fr);
    

    // Sign concated data
    ssig_ed25519(priv_key_path, buffer, buffer_len, &sigma_Y_1, &sig_len);

}

/*
 */
void verify_sigma_Y_1(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1, size_t sig_len)
{

    int rc;

    // Serialize mcl ec pairing objects
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    size_t serialize_len_Fr = mclBn_getFrByteSize();
    unsigned char mx_xP_bytes[serialize_len_G1];
    unsigned char mx_xQ_bytes[serialize_len_G2];
    unsigned char mx_Rho_bytes[serialize_len_G2];
    unsigned char mx_d_bytes[serialize_len_Fr];
    unsigned char my_yQ_bytes[serialize_len_G2];
    unsigned char my_Rho_bytes[serialize_len_G2];
    unsigned char my_d_bytes[serialize_len_Fr];
    rc  = mclBnG1_serialize(mx_xP_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_xQ_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_Rho_bytes, serialize_len_G2, &x_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(mx_d_bytes, serialize_len_Fr, &x_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_yQ_bytes, serialize_len_G2, yQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_Rho_bytes, serialize_len_G2, &y_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(my_d_bytes, serialize_len_Fr, &y_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }

    // Concat data
    size_t buffer_len = (serialize_len_G1) + (serialize_len_G2 * 4) + (serialize_len_Fr * 2) + omega_len;
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 16, 
                    omega, omega_len,
                    mx_xP_bytes, serialize_len_G1,
                    mx_xQ_bytes, serialize_len_G2,
                    mx_Rho_bytes, serialize_len_G2,
                    mx_d_bytes, serialize_len_Fr,
                    my_yQ_bytes, serialize_len_G2,
                    my_Rho_bytes, serialize_len_G2,
                    my_d_bytes, serialize_len_Fr);
    

    // Verify sig
    sver_ed25519(pub_key_path, buffer, buffer_len, sigma_Y_1, sig_len);

}

/*
 */
void ake_a_get_sigma_X(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, size_t sig_len)
{

    int rc;

    // Serialize mcl ec pairing objects
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    size_t serialize_len_Fr = mclBn_getFrByteSize();
    unsigned char mx_xP_bytes[serialize_len_G1];
    unsigned char mx_xQ_bytes[serialize_len_G2];
    unsigned char mx_Rho_bytes[serialize_len_G2];
    unsigned char mx_d_bytes[serialize_len_Fr];
    unsigned char my_yQ_bytes[serialize_len_G2];
    unsigned char my_Rho_bytes[serialize_len_G2];
    unsigned char my_d_bytes[serialize_len_Fr];
    rc  = mclBnG1_serialize(mx_xP_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_xQ_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_Rho_bytes, serialize_len_G2, &x_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(mx_d_bytes, serialize_len_Fr, &x_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_yQ_bytes, serialize_len_G2, yQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_Rho_bytes, serialize_len_G2, &y_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(my_d_bytes, serialize_len_Fr, &y_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }

    // Concat data
    size_t buffer_len = (serialize_len_G1) + (serialize_len_G2 * 4) + (serialize_len_Fr * 2) + omega_len + sig_len;
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 18, 
                    omega, omega_len,
                    mx_xP_bytes, serialize_len_G1,
                    mx_xQ_bytes, serialize_len_G2,
                    mx_Rho_bytes, serialize_len_G2,
                    mx_d_bytes, serialize_len_Fr,
                    my_yQ_bytes, serialize_len_G2,
                    my_Rho_bytes, serialize_len_G2,
                    my_d_bytes, serialize_len_Fr,
                    sigma_Y_1, sig_len);
    

    // Sign concated data
    ssig_ed25519(priv_key_path, buffer, buffer_len, &sigma_X, &sig_len);

}

/*
 */
void verify_sigma_X(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, size_t sig_len)
{

    int rc;

    // Serialize mcl ec pairing objects
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    size_t serialize_len_Fr = mclBn_getFrByteSize();
    unsigned char mx_xP_bytes[serialize_len_G1];
    unsigned char mx_xQ_bytes[serialize_len_G2];
    unsigned char mx_Rho_bytes[serialize_len_G2];
    unsigned char mx_d_bytes[serialize_len_Fr];
    unsigned char my_yQ_bytes[serialize_len_G2];
    unsigned char my_Rho_bytes[serialize_len_G2];
    unsigned char my_d_bytes[serialize_len_Fr];
    rc  = mclBnG1_serialize(mx_xP_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_xQ_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_Rho_bytes, serialize_len_G2, &x_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(mx_d_bytes, serialize_len_Fr, &x_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_yQ_bytes, serialize_len_G2, yQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_Rho_bytes, serialize_len_G2, &y_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(my_d_bytes, serialize_len_Fr, &y_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }

    // Concat data
    size_t buffer_len = (serialize_len_G1) + (serialize_len_G2 * 4) + (serialize_len_Fr * 2) + omega_len + sig_len;
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 18, 
                    omega, omega_len,
                    mx_xP_bytes, serialize_len_G1,
                    mx_xQ_bytes, serialize_len_G2,
                    mx_Rho_bytes, serialize_len_G2,
                    mx_d_bytes, serialize_len_Fr,
                    my_yQ_bytes, serialize_len_G2,
                    my_Rho_bytes, serialize_len_G2,
                    my_d_bytes, serialize_len_Fr,
                    sigma_Y_1, sig_len);
    

    // Verify sig
    sver_ed25519(pub_key_path, buffer, buffer_len, sigma_X, sig_len);

}

/*
 */
void ake_b_get_sigma_Y_2(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len)
{

    int rc;

    // Serialize mcl ec pairing objects
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    size_t serialize_len_Fr = mclBn_getFrByteSize();
    unsigned char mx_xP_bytes[serialize_len_G1];
    unsigned char mx_xQ_bytes[serialize_len_G2];
    unsigned char mx_Rho_bytes[serialize_len_G2];
    unsigned char mx_d_bytes[serialize_len_Fr];
    unsigned char my_yQ_bytes[serialize_len_G2];
    unsigned char my_Rho_bytes[serialize_len_G2];
    unsigned char my_d_bytes[serialize_len_Fr];
    rc  = mclBnG1_serialize(mx_xP_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_xQ_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_Rho_bytes, serialize_len_G2, &x_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(mx_d_bytes, serialize_len_Fr, &x_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_yQ_bytes, serialize_len_G2, yQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_Rho_bytes, serialize_len_G2, &y_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(my_d_bytes, serialize_len_Fr, &y_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }

    // Concat data
    size_t buffer_len = (serialize_len_G1) + (serialize_len_G2 * 4) + (serialize_len_Fr * 2) + omega_len + (sig_len * 2);
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 20, 
                    omega, omega_len,
                    mx_xP_bytes, serialize_len_G1,
                    mx_xQ_bytes, serialize_len_G2,
                    mx_Rho_bytes, serialize_len_G2,
                    mx_d_bytes, serialize_len_Fr,
                    my_yQ_bytes, serialize_len_G2,
                    my_Rho_bytes, serialize_len_G2,
                    my_d_bytes, serialize_len_Fr,
                    sigma_Y_1, sig_len,
                    sigma_X, sig_len);
    

    // Sign concated data
    ssig_ed25519(priv_key_path, buffer, buffer_len, &sigma_Y_2, &sig_len);

}

/*
 */
void verify_sigma_Y_2(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len)
{

    int rc;

    // Serialize mcl ec pairing objects
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    size_t serialize_len_Fr = mclBn_getFrByteSize();
    unsigned char mx_xP_bytes[serialize_len_G1];
    unsigned char mx_xQ_bytes[serialize_len_G2];
    unsigned char mx_Rho_bytes[serialize_len_G2];
    unsigned char mx_d_bytes[serialize_len_Fr];
    unsigned char my_yQ_bytes[serialize_len_G2];
    unsigned char my_Rho_bytes[serialize_len_G2];
    unsigned char my_d_bytes[serialize_len_Fr];
    rc  = mclBnG1_serialize(mx_xP_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_xQ_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_Rho_bytes, serialize_len_G2, &x_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(mx_d_bytes, serialize_len_Fr, &x_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_yQ_bytes, serialize_len_G2, yQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_Rho_bytes, serialize_len_G2, &y_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(my_d_bytes, serialize_len_Fr, &y_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }

    // Concat data
    size_t buffer_len = (serialize_len_G1) + (serialize_len_G2 * 4) + (serialize_len_Fr * 2) + omega_len + (sig_len * 2);
    unsigned char buffer[buffer_len];
    concat_arrays(buffer, 20, 
                    omega, omega_len,
                    mx_xP_bytes, serialize_len_G1,
                    mx_xQ_bytes, serialize_len_G2,
                    mx_Rho_bytes, serialize_len_G2,
                    mx_d_bytes, serialize_len_Fr,
                    my_yQ_bytes, serialize_len_G2,
                    my_Rho_bytes, serialize_len_G2,
                    my_d_bytes, serialize_len_Fr,
                    sigma_Y_1, sig_len,
                    sigma_X, sig_len);
    

    // Verify
    sver_ed25519(pub_key_path, buffer, buffer_len, sigma_Y_2, sig_len);

}

/* 
 */
void ake_a_get_shared_key(mclBnG1 * L_pk, mclBnG2 * yQ, mclBnFr * x, mclBnGT * ka)
{

    // ka <-- e(Lamda.pk, yQ)
    mclBn_pairing(ka, L_pk, yQ);

    // ka <-- e(Lamda.pk, yQ)^x
    mclBnGT_pow(ka, ka, x);

}

/*
 */
void ake_b_get_shared_key(mclBnG1 * L_pk, mclBnG2 * xQ, mclBnFr * y, mclBnGT * kb)
{

    // kb <-- e(Lamda.pk, xQ)
    mclBn_pairing(kb, L_pk, xQ);

    // kb <-- e(Lamda.pk, xQ)^y
    mclBnGT_pow(kb, kb, y);

}

/*
 */
void ake_O_get_sst(char * priv_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len, SST * sst)
{

    int rc;

    // Serialize mcl ec pairing objects
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    size_t serialize_len_Fr = mclBn_getFrByteSize();
    unsigned char mx_xP_bytes[serialize_len_G1];
    unsigned char mx_xQ_bytes[serialize_len_G2];
    unsigned char mx_Rho_bytes[serialize_len_G2];
    unsigned char mx_d_bytes[serialize_len_Fr];
    unsigned char my_yQ_bytes[serialize_len_G2];
    unsigned char my_Rho_bytes[serialize_len_G2];
    unsigned char my_d_bytes[serialize_len_Fr];
    rc  = mclBnG1_serialize(mx_xP_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_xQ_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_Rho_bytes, serialize_len_G2, &x_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(mx_d_bytes, serialize_len_Fr, &x_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_yQ_bytes, serialize_len_G2, yQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_Rho_bytes, serialize_len_G2, &y_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(my_d_bytes, serialize_len_Fr, &y_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }

    // Concat data
    sst->m_len = (serialize_len_G1) + (serialize_len_G2 * 4) + (serialize_len_Fr * 2) + omega_len + (sig_len * 3);
    sst->m = (unsigned char *) malloc(sst->m_len * sizeof(unsigned char));
    concat_arrays(sst->m, 22, 
                    omega, omega_len,
                    mx_xP_bytes, serialize_len_G1,
                    mx_xQ_bytes, serialize_len_G2,
                    mx_Rho_bytes, serialize_len_G2,
                    mx_d_bytes, serialize_len_Fr,
                    my_yQ_bytes, serialize_len_G2,
                    my_Rho_bytes, serialize_len_G2,
                    my_d_bytes, serialize_len_Fr,
                    sigma_Y_1, sig_len,
                    sigma_X, sig_len,
                    sigma_Y_2, sig_len);
    

    // Allocate sst
    sst->sigma_O_len = sig_len;
    sst->sigma_O = (unsigned char *) malloc(sig_len * sizeof(unsigned char));

    // Sign concated data
    ssig_ed25519(priv_key_path, sst->m, sst->m_len, &sst->sigma_O, &sig_len);

}

/*
 */
void verify_sst(char * pub_key_path, unsigned char * omega, size_t omega_len, mclBnG1 * xP, mclBnG2 * xQ, XY_ni * x_ni, mclBnG2 * yQ, XY_ni * y_ni, unsigned char * sigma_Y_1 , unsigned char * sigma_X, unsigned char * sigma_Y_2, size_t sig_len, SST * sst)
{

    int rc;

    // Serialize mcl ec pairing objects
    size_t serialize_len_G1 = mclBn_getG1ByteSize();
    size_t serialize_len_G2 = serialize_len_G1 * 2;
    size_t serialize_len_Fr = mclBn_getFrByteSize();
    unsigned char mx_xP_bytes[serialize_len_G1];
    unsigned char mx_xQ_bytes[serialize_len_G2];
    unsigned char mx_Rho_bytes[serialize_len_G2];
    unsigned char mx_d_bytes[serialize_len_Fr];
    unsigned char my_yQ_bytes[serialize_len_G2];
    unsigned char my_Rho_bytes[serialize_len_G2];
    unsigned char my_d_bytes[serialize_len_Fr];
    rc  = mclBnG1_serialize(mx_xP_bytes, serialize_len_G1, xP);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_xQ_bytes, serialize_len_G2, xQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(mx_Rho_bytes, serialize_len_G2, &x_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(mx_d_bytes, serialize_len_Fr, &x_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_yQ_bytes, serialize_len_G2, yQ);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnG2_serialize(my_Rho_bytes, serialize_len_G2, &y_ni->Rho);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }
    rc  = mclBnFr_serialize(my_d_bytes, serialize_len_Fr, &y_ni->d);
    if(rc == 0)
    {
        handle_mcl_error(rc, "Error with mclBnG1_serialize");
    }

    // Concat data
    size_t m_len = (serialize_len_G1) + (serialize_len_G2 * 4) + (serialize_len_Fr * 2) + omega_len + (sig_len * 3);
    unsigned char m[m_len];
    concat_arrays(m, 22, 
                    omega, omega_len,
                    mx_xP_bytes, serialize_len_G1,
                    mx_xQ_bytes, serialize_len_G2,
                    mx_Rho_bytes, serialize_len_G2,
                    mx_d_bytes, serialize_len_Fr,
                    my_yQ_bytes, serialize_len_G2,
                    my_Rho_bytes, serialize_len_G2,
                    my_d_bytes, serialize_len_Fr,
                    sigma_Y_1, sig_len,
                    sigma_X, sig_len,
                    sigma_Y_2, sig_len);
    

    // Verify
    sver_ed25519(pub_key_path, m, m_len, sst->sigma_O, sig_len);

}

/*
 */
void tdgen_get_li_T1(mclBnG1 * xP, mclBnG2 * yQ, int nb_args, ...)
{

    va_list list;
    mclBnFr * l_sk;
    mclBnGT * l_t1;

    va_start(list, nb_args);

    for(int i = 0; i < (nb_args / 2); i++)
    {
        l_sk = va_arg(list, mclBnFr *);
        l_t1 = va_arg(list, mclBnGT *);
        mclBn_pairing(l_t1, xP, yQ);
        mclBnGT_pow(l_t1, l_t1, l_sk);
    }

    va_end(list);

}

/*
 */
void tdgen_get_li_T2(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * yQ, int nb_args, ...)
{

    mclBnGT pairing_res;

    va_list list;
    mclBnG1 * li_pk;
    mclBnFr * li_sk;
    mclBnGT * li_T1;
    Lambda_eq_ni * li_T2;
    
    va_start(list, nb_args);

    for(int i = 0; i < (nb_args / 4); i++)
    {
        li_pk = va_arg(list, mclBnG1 *);
        li_sk = va_arg(list, mclBnFr *);
        li_T1 = va_arg(list, mclBnGT *);
        li_T2 = va_arg(list, Lambda_eq_ni *);
        mclBn_pairing(&pairing_res, xP, yQ);
        eq_nipok_G1_GT(P, li_pk, &pairing_res, li_T1, li_sk, &li_T2->Rho, &li_T2->Sigma, &li_T2->d);
    }

    va_end(list);

}

/*
 */
void verify_li_T2(mclBnG1 * P, mclBnG1 * xP, mclBnG2 * yQ, int nb_args, ...)
{

    mclBnGT pairing_res;
    mclBn_pairing(&pairing_res, xP, yQ);

    va_list list;
    mclBnG1 * li_pk;
    mclBnGT * li_T1;
    Lambda_eq_ni * li_T2;

    va_start(list, nb_args);

    for(int i = 0; i < (nb_args / 3); i++)
    {
        li_pk = va_arg(list, mclBnG1 *);
        li_T1 = va_arg(list, mclBnGT *);
        li_T2 = va_arg(list, Lambda_eq_ni *);
        if(eq_nipokver_G1_GT(P, li_pk, &pairing_res, li_T1, &li_T2->Rho, &li_T2->Sigma, &li_T2->d) != 1)
        {
            fprintf(stderr, "verify_li_T2 failed\n");
            exit(EXIT_FAILURE);
        }
    }

    va_end(list);

}

/*
 */
void open_get_shared_key(mclBnGT * k, int nb_args, ...)
{
    
    va_list list;

    mclBnGT * l_t1;
    mclBnGT * l_t1_next;

    va_start(list, nb_args);

    l_t1 = va_arg(list, mclBnGT *);
    for(int i = 0; i < (nb_args - 1); i++)
    {
        l_t1_next = va_arg(list, mclBnGT *);
        mclBnGT_mul(k, l_t1, l_t1_next);
        l_t1 = l_t1_next;
    }

    va_end(list);

}
