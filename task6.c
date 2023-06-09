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
	
	BN_hex2bn(&n, "BB021528CCF6A094D30F12EC8D5592C3F882F199A67A4288A75D26AAB52BB9C54CB1AF8E6BF975C8A3D70F4794145535578C9EA8A23919F5823C42A94E6EF53BC32EDB8DC0B05CF35938E7EDCF69F05A0B1BBEC094242587FA3771B313E71CACE19BEFDBE43B45524596A9C153CE34C852EEB5AEED8FDE6070E2A554ABB66D0E97A540346B2BD3BC66EB66347CFA6B8B8F572999F830175DBA726FFB81C5ADD286583D17C7E709BBF12BF786DCC1DA715DD446E3CCAD25C188BC60677566B3F118F7A25CE653FF3A88B647A5FF1318EA9809773F9D53F9CF01E5F5A6701714AF63A4FF99B3939DDC53A706FE48851DA169AE2575BB13CC5203F5ED51A18BDB15");
	BN_dec2bn(&e, "65537");
	BN_hex2bn(&M, "0001FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003031300D06096086480165030402010500042082a4d4148a78b4fe38ba61382613eca887aafb24b85fa745a69240197153f241");
	BN_hex2bn(&S, "96f577074aa6026b25741d46f92bad4d1903c5c8b8ced34d35171edabb47ada8804770fde81ddca2848c1d9696b18ed97f5a45c1cbdd27e743885bb62f05007abb472d40a3d72eab1da672b681cbd2237803d41dca937ddde9cb95704bf1c57e7ef30e3c9d27b51e386c0e2622cb7fc048ae246e6ef75e630a13dae8fed44dfa252efc545c153a3eef4040d12eb378c15292a0ecab6ea20d6ff4ca82be99c8552d7c70b35dd745a67ea45e1319ec598435320b3a1aa2eb376313381cd8ddffdca52631d4c65b818b7488ad25d142c9a7694a63d67bf684e3d5baf116b28a9e77ec5ff2d2402e0a46bb412a3dec0afad821bbad4f787bf11e8e51b069f61c1661");//sua 2F thanh 3F o day
	
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
