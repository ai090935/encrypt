#ifndef libencrypt_encrypt_h
#define libencrypt_encrypt_h
#include<cstdio>
#include<vector>
#include"define.h"
#include"cipher.h"
#include"mac.h"
#include"kdf.h"

namespace libencrypt
{
	//if salt is null, randomly generate 32-bytes and write.
	void encrypt(std::FILE* input, std::FILE* output, kdf_algorithm algorithm, kdf_parameter& parameter, const std::vector<cipher_algorithm>& cipher_list, const std::vector<mac_algorithm>& mac_list, int threads);

	//if salt is null, read first 32-bytes.
	void decrypt(std::FILE* input, std::FILE* output, kdf_algorithm algorithm, kdf_parameter& parameter, const std::vector<cipher_algorithm>& cipher_list, const std::vector<mac_algorithm>& mac_list, int threads);
}

#endif