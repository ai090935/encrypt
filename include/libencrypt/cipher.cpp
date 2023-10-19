#include"cipher.h"
#include<stdexcept>

using namespace libencrypt;

//-------------------------------------------------------------------------------------------------

#if defined(libencrypt_use_openssl)
#include<algorithm>
#include<openssl/evp.h>
#include<utils/bit.h>
#include<utils/uint128.h>

using utils::uint128_t;
using utils::endian;
using utils::byte_to_word;
using utils::word_to_byte;

namespace
{
	template<const char* Cipher, int Key_size>
	class aes_ctr : public cipher
	{
	public:
		aes_ctr() noexcept : cipher(this->key_size, this->block_size), initial_ctx(nullptr), ctx(nullptr), algorithm(nullptr) {}

		~aes_ctr() override
		{
			if (this->algorithm)
				EVP_CIPHER_free(this->algorithm);
			if (this->ctx)
				EVP_CIPHER_CTX_free(this->ctx);
			if (this->initial_ctx)
				EVP_CIPHER_CTX_free(this->initial_ctx);
		}

		void init(const byte* key) override
		{
			this->initial_ctx = EVP_CIPHER_CTX_new();
			this->ctx = EVP_CIPHER_CTX_new();
			this->algorithm = EVP_CIPHER_fetch(nullptr, Cipher, nullptr);
			if (!this->initial_ctx || !this->ctx || !this->algorithm)
				throw std::runtime_error("libencrypt::aes_ctr::init error");
			if (!EVP_EncryptInit_ex2(this->initial_ctx, this->algorithm, key, nullptr, nullptr) || !EVP_EncryptInit_ex2(this->ctx, this->algorithm, nullptr, nullptr, nullptr))
				throw std::runtime_error("libencrypt::aes_ctr::init EVP_EncryptInit_ex2 error");
			this->counter = byte_to_word<endian::big, uint128_t>(key + this->key_size - 16);
		}

		void set_counter(uint64_t offset) override
		{
			byte iv[16];
			uint128_t counter = this->counter + offset;
			word_to_byte<endian::big>(counter, iv);
			if (!EVP_CIPHER_CTX_copy(this->ctx, this->initial_ctx) || !EVP_EncryptInit_ex2(this->ctx, nullptr, nullptr, iv, nullptr))
				throw std::runtime_error("libencrypt::aes_ctr::set_counter error");
		}

		void encrypt(const byte* in, byte* out, size_t count) override
		{
			size_t length = count * this->block_size;
			int out_length = 0;
			if (!EVP_EncryptUpdate(this->ctx, out, &out_length, in, static_cast<int>(length)) || length != static_cast<size_t>(out_length))
				throw std::runtime_error("libencrypt::aes_ctr::encrypt EVP_EncryptUpdate error");
		}

		std::unique_ptr<cipher> copy() const override
		{
			if (!EVP_CIPHER_up_ref(this->algorithm))
				throw std::runtime_error("libencrypt::aes_ctr::copy EVP_CIPHER_up_ref error");

			auto p = std::make_unique<aes_ctr<Cipher, Key_size>>();
			p->initial_ctx = EVP_CIPHER_CTX_dup(this->initial_ctx);
			p->ctx = EVP_CIPHER_CTX_dup(this->ctx);
			p->algorithm = this->algorithm;
			if (!p->initial_ctx || !p->ctx)
				throw std::runtime_error("libencrypt::aes_ctr::copy EVP_CIPHER_CTX_dup error");
			p->counter = this->counter;

			return std::unique_ptr<cipher>(p.release());
		}

	private:
		static constexpr int key_size = Key_size + 16;
		static constexpr int block_size = 16;
		EVP_CIPHER_CTX* initial_ctx;
		EVP_CIPHER_CTX* ctx;
		EVP_CIPHER* algorithm;
		uint128_t counter;
	};

	constexpr char const_str_aes_128_ctr[] = "aes-128-ctr";
	constexpr char const_str_aes_192_ctr[] = "aes-192-ctr";
	constexpr char const_str_aes_256_ctr[] = "aes-256-ctr";
	using aes_128_ctr = aes_ctr<const_str_aes_128_ctr, 16>;
	using aes_192_ctr = aes_ctr<const_str_aes_192_ctr, 24>;
	using aes_256_ctr = aes_ctr<const_str_aes_256_ctr, 32>;

	class chacha20 : public cipher
	{
	public:
		chacha20() noexcept : cipher(this->key_size, this->block_size), initial_ctx(nullptr), ctx(nullptr), algorithm(nullptr) {}

		~chacha20() override
		{
			if (this->algorithm)
				EVP_CIPHER_free(this->algorithm);
			if (this->ctx)
				EVP_CIPHER_CTX_free(this->ctx);
			if (this->initial_ctx)
				EVP_CIPHER_CTX_free(this->initial_ctx);
		}

		void init(const byte* key) override
		{
			this->initial_ctx = EVP_CIPHER_CTX_new();
			this->ctx = EVP_CIPHER_CTX_new();
			this->algorithm = EVP_CIPHER_fetch(nullptr, "chacha20", nullptr);
			if (!this->initial_ctx || !this->ctx || !this->algorithm)
				throw std::runtime_error("libencrypt::chacha20::init error");
			if (!EVP_EncryptInit_ex2(this->initial_ctx, this->algorithm, key, nullptr, nullptr) || !EVP_EncryptInit_ex2(this->ctx, this->algorithm, nullptr, nullptr, nullptr))
				throw std::runtime_error("libencrypt::chacha20::init EVP_EncryptInit_ex2 error");
			this->counter = byte_to_word<endian::little, uint64_t>(key + 32);
			std::copy(key + 40, key + this->key_size, this->nonce);
		}

		void set_counter(uint64_t offset) override
		{
			byte iv[16];
			uint64_t counter = this->counter + offset;
			word_to_byte<endian::little>(counter, iv);
			std::copy(this->nonce, this->nonce + 8, iv + 8);
			if (!EVP_CIPHER_CTX_copy(this->ctx, this->initial_ctx) || !EVP_EncryptInit_ex2(this->ctx, nullptr, nullptr, iv, nullptr))
				throw std::runtime_error("libencrypt::chacha20::set_counter error");
		}

		void encrypt(const byte* in, byte* out, size_t count) override
		{
			size_t length = count * this->block_size;
			int out_length = 0;
			if (!EVP_EncryptUpdate(this->ctx, out, &out_length, in, static_cast<int>(length)) || length != static_cast<size_t>(out_length))
				throw std::runtime_error("libencrypt::aes_ctr::encrypt EVP_EncryptUpdate error");
		}

		std::unique_ptr<cipher> copy() const override
		{
			if (!EVP_CIPHER_up_ref(this->algorithm))
				throw std::runtime_error("libencrypt::chacha20::copy EVP_CIPHER_up_ref error");

			auto p = std::make_unique<chacha20>();
			p->initial_ctx = EVP_CIPHER_CTX_dup(this->initial_ctx);
			p->ctx = EVP_CIPHER_CTX_dup(this->ctx);
			p->algorithm = this->algorithm;
			if (!p->initial_ctx || !p->ctx)
				throw std::runtime_error("libencrypt::chacha20::copy EVP_CIPHER_CTX_dup error");
			p->counter = this->counter;
			std::copy(this->nonce, this->nonce + 8, p->nonce);

			return std::unique_ptr<cipher>(p.release());
		}

	private:
		static constexpr int key_size = 48;
		static constexpr int block_size = 64;
		EVP_CIPHER_CTX* initial_ctx;
		EVP_CIPHER_CTX* ctx;
		EVP_CIPHER* algorithm;
		uint64_t counter;
		byte nonce[8];
	};
}

#else
#include<crypto/AES.h>
#include<crypto/CTR_mode.h>
#include<crypto/chacha20.h>
#include<utils/bit.h>
#include<utils/uint128.h>

using utils::uint128_t;
using utils::endian;
using utils::byte_to_word;
using utils::word_to_byte;

namespace
{
	template<typename Cipher>
	class aes_ctr : public cipher
	{
	public:
		aes_ctr() : cipher(this->key_size, this->block_size) {}

		void init(const byte* key) override
		{
			const byte* k = key;
			const byte* c = k + this->impl.key_size;
			this->impl.init(k, c);
			this->counter = byte_to_word<endian::big, uint128_t>(c);
		}

		void set_counter(uint64_t offset) override
		{
			byte temp[16];
			word_to_byte<endian::big>(static_cast<uint128_t>(this->counter + offset), temp);
			this->impl.init_counter(temp);
		}

		void encrypt(const byte* in, byte* out, size_t count) override
		{
			for (size_t i = 0; i < count; i++)
				this->impl.encrypt(in + i * this->block_size, out + i * this->block_size);
		}

		std::unique_ptr<cipher> copy() const override
		{
			return std::unique_ptr<cipher>(new aes_ctr<Cipher>(*this));
		}

	private:
		static constexpr int key_size = crypto::cipher::CTR<Cipher>::key_size + crypto::cipher::CTR<Cipher>::counter_size;
		static constexpr int block_size = crypto::cipher::CTR<Cipher>::block_size;
		typename crypto::cipher::CTR<Cipher>::encryption impl;
		uint128_t counter;
	};

	using aes_128_ctr = aes_ctr<crypto::cipher::AES_128>;
	using aes_192_ctr = aes_ctr<crypto::cipher::AES_192>;
	using aes_256_ctr = aes_ctr<crypto::cipher::AES_256>;

	class chacha20 : public cipher
	{
	public:
		chacha20() : cipher(this->key_size, this->block_size) {}

		void init(const byte* key) override
		{
			const byte* k = key;
			const byte* c = k + this->impl.key_size;
			const byte* n = c + this->impl.counter_size;
			this->impl.init(k, c, n);
			this->counter = byte_to_word<endian::little, uint64_t>(c);
		}

		void set_counter(uint64_t offset) override
		{
			byte temp[8];
			word_to_byte<endian::little>(static_cast<uint64_t>(this->counter + offset), temp);
			this->impl.init_counter(temp);
		}

		void encrypt(const byte* in, byte* out, size_t count) override
		{
			for (size_t i = 0; i < count; i++)
				this->impl.encrypt(in + i * this->block_size, out + i * this->block_size);
		}

		std::unique_ptr<cipher> copy() const override
		{
			return std::unique_ptr<cipher>(new chacha20(*this));
		}

	private:
		static constexpr int key_size = crypto::cipher::chacha20::key_size + crypto::cipher::chacha20::counter_size + crypto::cipher::chacha20::nonce_size;
		static constexpr int block_size = crypto::cipher::chacha20::block_size;
		crypto::cipher::chacha20::encryption impl;
		uint64_t counter;
	};
}

#endif

//-------------------------------------------------------------------------------------------------

std::unique_ptr<cipher> libencrypt::make_cipher(cipher_algorithm algorithm)
{
	if (algorithm == cipher_algorithm::aes_128_ctr)
		return std::make_unique<aes_128_ctr>();
	else if (algorithm == cipher_algorithm::aes_192_ctr)
		return std::make_unique<aes_192_ctr>();
	else if (algorithm == cipher_algorithm::aes_256_ctr)
		return std::make_unique<aes_256_ctr>();
	else if (algorithm == cipher_algorithm::chacha20)
		return std::make_unique<chacha20>();
	else
		throw std::invalid_argument("libencrypt::make_cipher unknown cipher_algorithm");
}