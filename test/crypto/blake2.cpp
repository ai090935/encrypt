#include<iostream>
#include<algorithm>
#include<exception>
#include<crypto/blake2.h>
#include"blake2_test_vector.h"

template<typename Hash, int N>
void test_blake2(const blake2_test_vector (&array)[N], const char* str)
{
	for (int i = 0; i < N; i++)
	{
		unsigned char digest[64];
		Hash(array[i].key, array[i].key_length, array[i].message, array[i].length, digest, array[i].digest_length);
		if (!std::equal(array[i].digest, array[i].digest + array[i].digest_length, digest))
		{
			std::cerr << str;
			std::terminate();
		}
	}
}

int main()
{
	using namespace crypto::MAC;

	test_blake2<blake2b>(blake2b_hash_vector1, "blake2b fail\n");
	test_blake2<blake2b>(blake2b_hash_vector2, "blake2b fail\n");
	test_blake2<blake2b>(blake2b_mac_vector1, "blake2b fail\n");
	test_blake2<blake2s>(blake2s_hash_vector1, "blake2s fail\n");
	test_blake2<blake2s>(blake2s_hash_vector2, "blake2s fail\n");
	test_blake2<blake2s>(blake2s_mac_vector1, "blake2s fail\n");

	return 0;
}