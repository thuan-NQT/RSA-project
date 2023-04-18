#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

int main()
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new(); //khoa cong khai
	BIGNUM *M = BN_new();
	BIGNUM *C = BN_new();
	
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_dec2bn(&e, "65537");
	BN_hex2bn(&M, "4120746F702073656372657421");
	
	BN_mod_exp(C, M, e, n, ctx); //ma hoa C = M^e (mod n)
	printBN("Encrypt: ", C);
	
	BN_clear_free(n);
	BN_clear_free(e);
	BN_clear_free(M);
	BN_clear_free(C);
	
	return 0;
}
