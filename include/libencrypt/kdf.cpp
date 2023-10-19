#include"kdf.h"
#include<stdexcept>

using namespace libencrypt;

//-------------------------------------------------------------------------------------------------

#if defined(libencrypt_use_openssl)
#include<vector>
#include<openssl/kdf.h>
#include<openssl/params.h>
#include<openssl/thread.h>
#include<openssl/core_names.h>

namespace
{
	class argon2
	{
	public:
		argon2() noexcept : ctx(nullptr), algorithm(nullptr) {}

		void derive(const char* name, argon2_parameter parameter, array output)
		{
			if (OSSL_set_max_threads(nullptr, parameter.parallelism) != 1)
				throw std::runtime_error("libencrypt::argon2 OSSL_set_max_threads error");

			this->algorithm = EVP_KDF_fetch(nullptr, name, nullptr);
			if (!this->algorithm)
				throw std::runtime_error("libencrypt::argon2 EVP_KDF_fetch error");
			this->ctx = EVP_KDF_CTX_new(this->algorithm);
			if (!this->ctx)
				throw std::runtime_error("libencrypt::argon2 EVP_KDF_CTX_new error");

			uint32_t threads = parameter.parallelism;
			std::vector<byte> password(parameter.password.data, parameter.password.data + parameter.password.length);
			std::vector<byte> salt(parameter.salt.data, parameter.salt.data + parameter.salt.length);
			std::vector<byte> key(parameter.key.data, parameter.key.data + parameter.key.length);

			OSSL_PARAM params[8];
			OSSL_PARAM* p = params;
			*p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &parameter.time_cost);
			*p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &parameter.memory_cost);
			*p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &parameter.parallelism);
			*p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
			if (!password.empty())
				*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password.data(), password.size());
			if (!salt.empty())
				*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size());
			if (!key.empty())
				*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, key.data(), key.size());
			*p = OSSL_PARAM_construct_end();

			if (EVP_KDF_derive(this->ctx, output.data, output.length, params) != 1)
				throw std::runtime_error("libencrypt::argon2 EVP_KDF_derive error");
		}

		~argon2() noexcept
		{
			if (this->algorithm)
				EVP_KDF_free(this->algorithm);
			if (this->ctx)
				EVP_KDF_CTX_free(this->ctx);
		}

		EVP_KDF_CTX* ctx;
		EVP_KDF* algorithm;
	};

	void argon2i(argon2_parameter parameter, array output)
	{
		argon2().derive("argon2i", parameter, output);
	}

	void argon2d(argon2_parameter parameter, array output)
	{
		argon2().derive("argon2d", parameter, output);
	}

	void argon2id(argon2_parameter parameter, array output)
	{
		argon2().derive("argon2id", parameter, output);
	}
}

#else
#include<crypto/argon2.h>

namespace
{
	void check(argon2_parameter parameter, array output)
	{
		if (parameter.time_cost == 0)
			throw std::out_of_range("time_cost must be greater than zero");
		if (parameter.memory_cost < 8 * parameter.parallelism)
			throw std::out_of_range("memory_cost out of range");
		if (parameter.parallelism == 0 || parameter.parallelism >= 0x100'0000)
			throw std::out_of_range("parallelism out of range");
		if (output.length < 4)
			throw std::out_of_range("output length out of range");
	}

	void argon2i(argon2_parameter parameter, array output)
	{
		check(parameter, output);
		crypto::KDF::argon2i({ parameter.password, parameter.salt, parameter.key, {} }, { parameter.time_cost, parameter.memory_cost, parameter.parallelism }, output);
	}

	void argon2d(argon2_parameter parameter, array output)
	{
		check(parameter, output);
		crypto::KDF::argon2d({ parameter.password, parameter.salt, parameter.key, {} }, { parameter.time_cost, parameter.memory_cost, parameter.parallelism }, output);
	}

	void argon2id(argon2_parameter parameter, array output)
	{
		check(parameter, output);
		crypto::KDF::argon2id({ parameter.password, parameter.salt, parameter.key, {} }, { parameter.time_cost, parameter.memory_cost, parameter.parallelism }, output);
	}
}

#endif

//-------------------------------------------------------------------------------------------------

void libencrypt::kdf(kdf_algorithm algorithm, const kdf_parameter& parameter, array output)
{
	if (algorithm == kdf_algorithm::argon2i)
		argon2i(dynamic_cast<const argon2_parameter&>(parameter), output);
	else if (algorithm == kdf_algorithm::argon2d)
		argon2d(dynamic_cast<const argon2_parameter&>(parameter), output);
	else if (algorithm == kdf_algorithm::argon2id)
		argon2id(dynamic_cast<const argon2_parameter&>(parameter), output);
	else
		throw std::invalid_argument("libencrypt::kdf unknown kdf_algorithm");
}