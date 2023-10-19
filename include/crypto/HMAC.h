#ifndef crypto_HMAC_h
#define crypto_HMAC_h
#include"define.h"
#include<algorithm>

//RFC 2104

namespace crypto::MAC
{
	template<typename Hash>
	class HMAC
	{
	public:
		HMAC() = default;
		HMAC(const byte* key, size_t keylen) noexcept;
		HMAC(const byte* key, size_t keylen, const byte* input, size_t length, byte* output) noexcept;

		void init(const byte* key, size_t keylen) noexcept;
		void update(const byte* input, size_t length) noexcept;
		void final(byte* output) noexcept;

		static constexpr int block_size = Hash::block_size;
		static constexpr int output_size = Hash::output_size;

	private:
		Hash outer_hash;
		Hash inner_hash;
	};
}

template<typename Hash>
crypto::MAC::HMAC<Hash>::HMAC(const byte* key, size_t keylen) noexcept
{
	this->init(key, keylen);
}

template<typename Hash>
crypto::MAC::HMAC<Hash>::HMAC(const byte* key, size_t keylen, const byte* input, size_t length, byte* output) noexcept : HMAC<Hash>(key, keylen)
{
	this->update(input, length);
	this->final(output);
}

template<typename Hash>
void crypto::MAC::HMAC<Hash>::init(const byte* key, size_t keylen) noexcept
{
	byte k[Hash::block_size] = {};

	if (keylen > Hash::block_size)
		Hash(key, keylen, k);
	else
		std::copy(key, key + keylen, k);

	byte opad_key[Hash::block_size];
	for (int i = 0; i < Hash::block_size; i++)
		opad_key[i] = k[i] ^ 0x5c;

	byte ipad_key[Hash::block_size];
	for (int i = 0; i < Hash::block_size; i++)
		ipad_key[i] = k[i] ^ 0x36;

	this->outer_hash.update(opad_key, Hash::block_size);
	this->inner_hash.update(ipad_key, Hash::block_size);
}

template<typename Hash>
void crypto::MAC::HMAC<Hash>::update(const byte* input, size_t length) noexcept
{
	this->inner_hash.update(input, length);
}

template<typename Hash>
void crypto::MAC::HMAC<Hash>::final(byte* output) noexcept
{
	byte temp[Hash::output_size];
	this->inner_hash.final(temp);

	this->outer_hash.update(temp, Hash::output_size);
	this->outer_hash.final(output);
}

#endif