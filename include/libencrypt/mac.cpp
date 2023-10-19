#include"mac.h"
#include<stdexcept>

using namespace libencrypt;

//-------------------------------------------------------------------------------------------------

#if defined(libencrypt_use_openssl)
#include<string>
#include<openssl/evp.h>
#include<openssl/params.h>

namespace
{
	template<const char* Hash, int Output_size>
	class hmac : public mac
	{
	public:
		hmac() : mac(this->key_size, this->output_size), algorithm(nullptr), ctx(nullptr) {}

		~hmac() override
		{
			if (this->ctx)
				EVP_MAC_CTX_free(this->ctx);
			if (this->algorithm)
				EVP_MAC_free(this->algorithm);
		}

		void init(const byte* key) override
		{
			this->algorithm = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
			if (!this->algorithm)
				throw std::runtime_error("libencrypt::hmac::init EVP_MAC_fetch error");
			this->ctx = EVP_MAC_CTX_new(this->algorithm);
			if (!this->ctx)
				throw std::runtime_error("libencrypt::hmac::init EVP_MAC_CTX_new error");
			std::string str = Hash;
			OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string("digest", str.data(), 0), OSSL_PARAM_construct_end() };
			if (!EVP_MAC_init(this->ctx, key, this->key_size, params))
				throw std::runtime_error("libencrypt::hmac::init EVP_MAC_init error");
		}

		void update(const byte* input, size_t length) override
		{
			if (!EVP_MAC_update(this->ctx, input, length))
				throw std::runtime_error("libencrypt::hmac::update EVP_MAC_update error");
		}

		void final(byte* output) override
		{
			size_t out_length = 0;
			if (!EVP_MAC_final(this->ctx, output, &out_length, this->output_size) || out_length != this->output_size)
				throw std::runtime_error("libencrypt::hmac::final EVP_MAC_final error");
		}

	private:
		static constexpr int key_size = 32;
		static constexpr int output_size = Output_size;
		EVP_MAC* algorithm;
		EVP_MAC_CTX* ctx;
	};

	constexpr char const_str_sha1[] = "sha1";
	constexpr char const_str_sha256[] = "sha256";
	constexpr char const_str_sha512[] = "sha512";
	using hmac_sha1 = hmac<const_str_sha1, 20>;
	using hmac_sha256 = hmac<const_str_sha256, 32>;
	using hmac_sha512 = hmac<const_str_sha512, 64>;

	class poly1305 : public mac
	{
	public:
		poly1305() : mac(this->key_size, this->output_size), algorithm(nullptr), ctx(nullptr) {}

		~poly1305() override
		{
			if (this->ctx)
				EVP_MAC_CTX_free(this->ctx);
			if (this->algorithm)
				EVP_MAC_free(this->algorithm);
		}

		void init(const byte* key) override
		{
			this->algorithm = EVP_MAC_fetch(nullptr, "poly1305", nullptr);
			if (!this->algorithm)
				throw std::runtime_error("libencrypt::poly1305::init EVP_MAC_fetch error");
			this->ctx = EVP_MAC_CTX_new(this->algorithm);
			if (!this->ctx)
				throw std::runtime_error("libencrypt::poly1305::init EVP_MAC_CTX_new error");
			if (!EVP_MAC_init(this->ctx, key, this->key_size, nullptr))
				throw std::runtime_error("libencrypt::poly1305::init EVP_MAC_init error");
		}

		void update(const byte* input, size_t length) override
		{
			if (!EVP_MAC_update(this->ctx, input, length))
				throw std::runtime_error("libencrypt::poly1305::update EVP_MAC_update error");
		}

		void final(byte* output) override
		{
			size_t out_length = 0;
			if (!EVP_MAC_final(this->ctx, output, &out_length, this->output_size) || out_length != this->output_size)
				throw std::runtime_error("libencrypt::poly1305::final EVP_MAC_final error");
		}

	private:
		static constexpr int key_size = 32;
		static constexpr int output_size = 16;
		EVP_MAC* algorithm;
		EVP_MAC_CTX* ctx;
	};
}

#else
#include<crypto/HMAC.h>
#include<crypto/SHA.h>
#include<crypto/poly1305.h>

namespace
{
	template<typename Hash>
	class hmac : public mac
	{
	public:
		hmac() : mac(this->key_size, this->output_size) {}

		void init(const byte* key) override
		{
			this->impl.init(key, this->key_size);
		}

		void update(const byte* input, size_t length) override
		{
			this->impl.update(input, length);
		}

		void final(byte* output) override
		{
			this->impl.final(output);
		}

	private:
		static constexpr int key_size = 32;
		static constexpr int output_size = crypto::MAC::HMAC<Hash>::output_size;
		crypto::MAC::HMAC<Hash> impl;
	};

	using hmac_sha1 = hmac<crypto::hash::SHA1>;
	using hmac_sha256 = hmac<crypto::hash::SHA256>;
	using hmac_sha512 = hmac<crypto::hash::SHA512>;

	class poly1305 : public mac
	{
	public:
		poly1305() : mac(this->key_size, this->output_size) {}

		void init(const byte* key) override
		{
			this->impl.init(key);
		}

		void update(const byte* input, size_t length) override
		{
			this->impl.update(input, length);
		}

		void final(byte* output) override
		{
			this->impl.final(output);
		}

	private:
		static constexpr int key_size = crypto::MAC::poly1305::key_size;
		static constexpr int output_size = crypto::MAC::poly1305::output_size;
		crypto::MAC::poly1305 impl;
	};
}

#endif

//-------------------------------------------------------------------------------------------------

std::unique_ptr<mac> libencrypt::make_mac(mac_algorithm algorithm)
{
	if (algorithm == mac_algorithm::hmac_sha1)
		return std::make_unique<hmac_sha1>();
	else if (algorithm == mac_algorithm::hmac_sha256)
		return std::make_unique<hmac_sha256>();
	else if (algorithm == mac_algorithm::hmac_sha512)
		return std::make_unique<hmac_sha512>();
	else if (algorithm == mac_algorithm::poly1305)
		return std::make_unique<poly1305>();
	else
		throw std::invalid_argument("libencrypt::make_mac unknown mac_algorithm");
}