#include<iostream>
#include<algorithm>
#include<exception>
#include<crypto/argon2.h>
#include"argon2_test_vector.h"

template<typename F, int N>
void test_argon2(F&& f, const argon2_test_vector (&array)[N], const char* str)
{
	for (int i = 0; i < N; i++)
	{
		unsigned char buf[100];
		utils::const_array pass = { array[i].pass, static_cast<utils::size_t>(array[i].pass_len) };
		utils::const_array salt = { array[i].salt, static_cast<utils::size_t>(array[i].salt_len) };
		utils::const_array secret = { array[i].secret, static_cast<utils::size_t>(array[i].secret_len) };
		utils::const_array ad = { array[i].ad, static_cast<utils::size_t>(array[i].ad_len) };
		crypto::KDF::argon2_input in = { pass, salt, secret, ad };
		crypto::KDF::argon2_option opt = { static_cast<utils::uint32_t>(array[i].t_cost), static_cast<utils::uint32_t>(array[i].m_cost), static_cast<utils::uint32_t>(array[i].p_cost) };
		utils::array out = { buf, static_cast<utils::size_t>(array[i].result_len) };
		f(in, opt, out);
		if (!std::equal(array[i].result, array[i].result + array[i].result_len, buf))
		{
			std::cerr << str;
			std::terminate();
		}
	}
}

int main()
{
	test_argon2(crypto::KDF::argon2i, argon2i_vector1, "argon2i fail\n");
	test_argon2(crypto::KDF::argon2i, argon2i_vector2, "argon2i fail\n");
	test_argon2(crypto::KDF::argon2d, argon2d_vector1, "argon2d fail\n");
	test_argon2(crypto::KDF::argon2d, argon2d_vector2, "argon2d fail\n");
	test_argon2(crypto::KDF::argon2id, argon2id_vector1, "argon2id fail\n");
	test_argon2(crypto::KDF::argon2id, argon2id_vector2, "argon2id fail\n");

	return 0;
}
