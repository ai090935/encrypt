#include<iostream>
#include<algorithm>
#include<exception>
#include<crypto/SHA.h>
#include"SHA_test_vector.h"

template<typename Hash, int N>
void test_sha(const SHA_test_vector (&array)[N], const char* str)
{
	for (int i = 0; i < N; i++)
	{
		unsigned char digest[64];
		Hash(array[i].message, array[i].length, digest);
		if (!std::equal(digest, digest + Hash::output_size, array[i].digest))
		{
			std::cerr << str;
			std::terminate();
		}
	}
}

int main()
{
	using namespace crypto::hash;

	test_sha<SHA1>(sha1_vector1, "SHA1 fail\n");
	test_sha<SHA1>(sha1_vector2, "SHA1 fail\n");
	test_sha<SHA224>(sha224_vector1, "SHA224 fail\n");
	test_sha<SHA224>(sha224_vector2, "SHA224 fail\n");
	test_sha<SHA256>(sha256_vector1, "SHA256 fail\n");
	test_sha<SHA256>(sha256_vector2, "SHA256 fail\n");
	test_sha<SHA384>(sha384_vector1, "SHA384 fail\n");
	test_sha<SHA384>(sha384_vector2, "SHA384 fail\n");
	test_sha<SHA512>(sha512_vector1, "SHA512 fail\n");
	test_sha<SHA512>(sha512_vector2, "SHA512 fail\n");
	test_sha<SHA512_224>(sha512_224_vector1, "SHA512_224 fail\n");
	test_sha<SHA512_224>(sha512_224_vector2, "SHA512_224 fail\n");
	test_sha<SHA512_256>(sha512_256_vector1, "SHA512_256 fail\n");
	test_sha<SHA512_256>(sha512_256_vector2, "SHA512_256 fail\n");

	return 0;
}