#include<iostream>
#include<algorithm>
#include<exception>
#include<crypto/chacha20.h>
#include"chacha20_test_vector.h"

using namespace crypto::cipher;

void rfc_test_chacha20(const chacha20_test_vector& vector)
{
	unsigned char plaintext[128], ciphertext[128];
	chacha20::encryption enc(vector.key, vector.counter, vector.nonce);
	chacha20::decryption dec(vector.key, vector.counter, vector.nonce);
	for (int i = 0; i < 2; i++)
		enc.encrypt(vector.plaintext + i * 64, ciphertext + i * 64);
	for (int i = 0; i < 2; i++)
		dec.decrypt(vector.ciphertext + i * 64, plaintext + i * 64);
	if (!std::equal(vector.plaintext, vector.plaintext + 114, plaintext) || !std::equal(vector.ciphertext, vector.ciphertext + 114, ciphertext))
	{
		std::cerr << "chacha20 fail\n";
		std::terminate();
	}
}

template<int N>
void test_chacha20(const chacha20_test_vector(&array)[N])
{
	for (int i = 0; i < N; i++)
	{
		unsigned char plaintext[256], ciphertext[256];
		chacha20::encryption enc(array[i].key, array[i].counter, array[i].nonce);
		chacha20::decryption dec(array[i].key, array[i].counter, array[i].nonce);
		for (int ii = 0; ii < 4; ii++)
			enc.encrypt(array[i].plaintext + ii * 64, ciphertext + ii * 64);
		for (int ii = 0; ii < 4; ii++)
			dec.decrypt(array[i].ciphertext + ii * 64, plaintext + ii * 64);
		if (!std::equal(array[i].plaintext, array[i].plaintext + 256, plaintext) || !std::equal(array[i].ciphertext, array[i].ciphertext + 256, ciphertext))
		{
			std::cerr << "chacha20 fail\n";
			std::terminate();
		}
	}
}

int main()
{
	rfc_test_chacha20(rfc_chahca20_vector);
	test_chacha20(chahca20_vector);

	return 0;
}