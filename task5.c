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
	BIGNUM *e = BN_new();
	BIGNUM *M = BN_new();
	BIGNUM *C = BN_new();
	BIGNUM *S = BN_new();
	
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_dec2bn(&e, "65537");
	BN_hex2bn(&M, "4C61756E63682061206D697373696C652E");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");//sua 2F thanh 3F o day
	
	//ta su gui thong diep da duoc ma hoa qua ben nhan
	
	BN_mod_exp(C, S, e, n, ctx);
	
	//so sanh thong diep moi ma hoa duoc voi thong diep da co
	if (BN_cmp(C, M) == 0)//xac minh chu ki
	{
		printf("Verification success!\n");
	}
	else
	{
		printf("Verification fails!\n");
	}
	
	BN_clear_free(n);
	BN_clear_free(e);
	BN_clear_free(M);
	BN_clear_free(C);
	BN_clear_free(S);
	
	return 0;
}
