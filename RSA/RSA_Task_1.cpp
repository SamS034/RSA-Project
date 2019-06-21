// RSA Task 1
// Written by Samuel Shen
#include<stdio.h>
#include<openssl/bn.h>

#define NBITS 128

void printBN(char *msg, BIGNUM * a)
{
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}

int main()
{
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *p_minus_one = BN_new();
    BIGNUM *q_minus_one = BN_new();
    BIGNUM *one = BN_new();

    // Initialize p, q, e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");
    BN_hex2bn(&one, "1");

    // key generation
    // n = p * q
    BN_mul(n, p, q, ctx);
    printBN("p * q = ", n);

    // phi = (p - 1)(q - 1)
    BN_sub(p_minus_one, p, one);
    BN_sub(q_minus_one, q, one);
    BN_mul(phi, p_minus_one, q_minus_one, ctx);
    printBN("(p - 1)(q - 1) =", phi);

    //find e
        /* e is given */

    // private key d (d*e mod phi = 1)
    BN_mod_inverse(d, e, phi, ctx);
    printBN("Private Key = ", d);

    return 0;
}
