#ifndef crypto_argon2_h
#define crypto_argon2_h
#include"define.h"

//RFC 9106

namespace crypto::KDF
{
	struct argon2_input
	{
		const_array password;
		const_array salt;
		const_array secret;
		const_array associated_data;
	};

	struct argon2_option
	{
		uint32_t time_cost;
		uint32_t memory_cost;
		uint32_t parallelism;
	};

	void argon2i(argon2_input input, argon2_option option, array output);
	void argon2d(argon2_input input, argon2_option option, array output);
	void argon2id(argon2_input input, argon2_option option, array output);
}

#endif