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
	BIGNUM *d = BN_new(); //khoa bi mat
	BIGNUM *M = BN_new();
	BIGNUM *C = BN_new();
	BIGNUM *M1 = BN_new();
	BIGNUM *C1 = BN_new();
	
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
	BN_hex2bn(&M, "49206F776520796F75202432303030"); //encode I owe you $2000
	BN_hex2bn(&M1, "49206F776520796F75202433303030");//encode I owe you $3000
	
	//tao chu ky cho thu nen ta su dung khoa bi mat
	BN_mod_exp(C, M, d, n, ctx);//ma hoa cau dau
	printBN("M:  ", C);
	
	BN_mod_exp(C1, M1, d, n, ctx);//ma hoa cau thu 2
	printBN("M1: ", C1);
	
	BN_clear_free(n);
	BN_clear_free(d);
	BN_clear_free(M);
	BN_clear_free(C);
	BN_clear_free(M1);
	BN_clear_free(C1);
	
	return 0;
}
