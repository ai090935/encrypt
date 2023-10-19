#include<iostream>
#include<algorithm>
#include<exception>
#include<crypto/AES.h>
#include<crypto/CTR_mode.h>
#include"AES_test_vector.h"

template<typename Cipher, int N>
void test_aes(const AES_test_vector (&array)[N])
{
	for (int i = 0; i < N; i++)
	{
		unsigned char plaintext[16], ciphertext[16];
		typename Cipher::encryption enc(array[i].key);
		typename Cipher::decryption dec(array[i].key);
		enc.encrypt(array[i].plaintext, ciphertext);
		dec.decrypt(array[i].ciphertext, plaintext);
		if (!std::equal(array[i].plaintext, array[i].plaintext + 16, plaintext) || !std::equal(array[i].ciphertext, array[i].ciphertext + 16, ciphertext))
		{
			std::cout << "AES fail\n";
			std::terminate();
		}
	}
}

template<typename Cipher, int N>
void test_aes_ctr(const AES_CTR_test_vector (&array)[N])
{
	for (int i = 0; i < N; i++)
	{
		unsigned char plaintext[64], ciphertext[64];
		typename Cipher::encryption enc(array[i].key, array[i].counter);
		typename Cipher::decryption dec(array[i].key, array[i].counter);
		for (int ii = 0; ii < 4; ii++)
			enc.encrypt(array[i].plaintext + ii * 16, ciphertext + ii * 16);
		for (int ii = 0; ii < 4; ii++)
			dec.decrypt(array[i].ciphertext + ii * 16, plaintext + ii * 16);
		if (!std::equal(array[i].plaintext, array[i].plaintext + 64, plaintext) || !std::equal(array[i].ciphertext, array[i].ciphertext + 64, ciphertext))
		{
			std::cerr << "AES CTR fail\n";
			std::terminate();
		}
	}
}

int main()
{
	using namespace crypto::cipher;

	test_aes<AES_128>(aes_128_vector1);
	test_aes<AES_128>(aes_128_vector2);
	test_aes<AES_128>(aes_128_vector3);
	test_aes<AES_128>(aes_128_vector4);
	test_aes<AES_128>(aes_128_vector5);
	test_aes<AES_128>(aes_128_vector6);
	test_aes<AES_128>(aes_128_vector7);

	test_aes<AES_192>(aes_192_vector1);
	test_aes<AES_192>(aes_192_vector2);
	test_aes<AES_192>(aes_192_vector3);
	test_aes<AES_192>(aes_192_vector4);
	test_aes<AES_192>(aes_192_vector5);
	test_aes<AES_192>(aes_192_vector6);
	test_aes<AES_192>(aes_192_vector7);

	test_aes<AES_256>(aes_256_vector1);
	test_aes<AES_256>(aes_256_vector2);
	test_aes<AES_256>(aes_256_vector3);
	test_aes<AES_256>(aes_256_vector4);
	test_aes<AES_256>(aes_256_vector5);
	test_aes<AES_256>(aes_256_vector6);
	test_aes<AES_256>(aes_256_vector7);


	test_aes_ctr<CTR<AES_128>>(aes_128_ctr_vector1);
	test_aes_ctr<CTR<AES_128>>(aes_128_ctr_vector2);

	test_aes_ctr<CTR<AES_192>>(aes_192_ctr_vector1);
	test_aes_ctr<CTR<AES_192>>(aes_192_ctr_vector2);

	test_aes_ctr<CTR<AES_256>>(aes_256_ctr_vector1);
	test_aes_ctr<CTR<AES_256>>(aes_256_ctr_vector2);

	return 0;
}