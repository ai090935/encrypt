#include<iostream>
#include<algorithm>
#include<exception>
#include<crypto/HMAC.h>
#include<crypto/SHA.h>
#include"HMAC_test_vector.h"

template<typename Hash, int N>
void test_HMAC(const HMAC_test_vector (&array)[N], const char* str)
{
	for (int i = 0; i < N; i++)
	{
		using crypto::MAC::HMAC;
		unsigned char digest[64];
		HMAC<Hash>(array[i].key, array[i].key_length, array[i].message, array[i].length, digest);
		if (!std::equal(digest, digest + HMAC<Hash>::output_size, array[i].digest))
		{
			std::cerr << str;
			std::terminate();
		}
	}
}

int main()
{
	using namespace crypto::hash;

	test_HMAC<SHA1>(hmac_sha1_vector1, "HMAC_SHA1 fail\n");
	test_HMAC<SHA1>(hmac_sha1_vector2, "HMAC_SHA1 fail\n");
	test_HMAC<SHA224>(hmac_sha224_vector1, "HMAC_SHA224 fail\n");
	test_HMAC<SHA224>(hmac_sha224_vector2, "HMAC_SHA224 fail\n");
	test_HMAC<SHA256>(hmac_sha256_vector1, "HMAC_SHA256 fail\n");
	test_HMAC<SHA256>(hmac_sha256_vector2, "HMAC_SHA256 fail\n");
	test_HMAC<SHA384>(hmac_sha384_vector1, "HMAC_SHA384 fail\n");
	test_HMAC<SHA384>(hmac_sha384_vector2, "HMAC_SHA384 fail\n");
	test_HMAC<SHA512>(hmac_sha512_vector1, "HMAC_SHA512 fail\n");
	test_HMAC<SHA512>(hmac_sha512_vector2, "HMAC_SHA512 fail\n");

	return 0;
}