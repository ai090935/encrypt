#include"chacha20.h"
#include<algorithm>
#include<utils/bit.h>

using namespace crypto;
using utils::endian;
using utils::byte_to_word;
using utils::word_to_byte;

namespace
{
	void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) noexcept
	{
		a += b;
		d ^= a;
		d = utils::rotl(d, 16);

		c += d;
		b ^= c;
		b = utils::rotl(b, 12);

		a += b;
		d ^= a;
		d = utils::rotl(d, 8);

		c += d;
		b ^= c;
		b = utils::rotl(b, 7);
	}

	void inner_block(uint32_t* state) noexcept
	{
		quarter_round(state[0], state[4], state[8], state[12]);
		quarter_round(state[1], state[5], state[9], state[13]);
		quarter_round(state[2], state[6], state[10], state[14]);
		quarter_round(state[3], state[7], state[11], state[15]);
		quarter_round(state[0], state[5], state[10], state[15]);
		quarter_round(state[1], state[6], state[11], state[12]);
		quarter_round(state[2], state[7], state[8], state[13]);
		quarter_round(state[3], state[4], state[9], state[14]);
	}

	void chacha20_block(const uint32_t* initial_state, byte* key_stream) noexcept
	{
		uint32_t state[16];
		std::copy(initial_state, initial_state + 16, state);

		for (int i = 0; i < 10; i++)
			inner_block(state);
		for (int i = 0; i < 16; i++)
			state[i] += initial_state[i];

		for (int i = 0; i < 16; i++)
			word_to_byte<endian::little>(state[i], key_stream + i * sizeof(uint32_t));
	}

	void increment(uint32_t* state) noexcept
	{
		state[12]++;
		if (state[12] == 0)
			state[13]++;
	}
}

//-------------------------------------------------------------------------------------------------

crypto::cipher::chacha20::encryption::encryption() noexcept
{
	this->state[0] = 0x61707865;
	this->state[1] = 0x3320646e;
	this->state[2] = 0x79622d32;
	this->state[3] = 0x6b206574;
}

crypto::cipher::chacha20::encryption::encryption(const byte* key, const byte* counter, const byte* nonce) noexcept : encryption()
{
	this->init(key, counter, nonce);
}

void crypto::cipher::chacha20::encryption::init(const byte* key, const byte* counter, const byte* nonce) noexcept
{
	this->init_key(key);
	this->init_counter(counter);
	this->init_nonce(nonce);
}

void crypto::cipher::chacha20::encryption::init_key(const byte* key) noexcept
{
	for (int i = 0; i < 8; i++)
		this->state[i + 4] = byte_to_word<endian::little, uint32_t>(key + i * sizeof(uint32_t));
}

void crypto::cipher::chacha20::encryption::init_counter(const byte* counter) noexcept
{
	for (int i = 0; i < 2; i++)
		this->state[i + 12] = byte_to_word<endian::little, uint32_t>(counter + i * sizeof(uint32_t));
}

void crypto::cipher::chacha20::encryption::init_nonce(const byte* nonce) noexcept
{
	for (int i = 0; i < 2; i++)
		this->state[i + 14] = byte_to_word<endian::little, uint32_t>(nonce + i * sizeof(uint32_t));
}

void crypto::cipher::chacha20::encryption::encrypt(const byte* in, byte* out) noexcept
{
	chacha20_block(this->state, out);
	increment(this->state);
	utils::memxor(out, in, out, this->block_size);
}

//-------------------------------------------------------------------------------------------------

crypto::cipher::chacha20::decryption::decryption() noexcept : a() {}

crypto::cipher::chacha20::decryption::decryption(const byte* key, const byte* counter, const byte* nonce) noexcept : a(key, counter, nonce) {}

void crypto::cipher::chacha20::decryption::init(const byte* key, const byte* counter, const byte* nonce) noexcept
{
	this->a.init(key, counter, nonce);
}

void crypto::cipher::chacha20::decryption::init_key(const byte* key) noexcept
{
	this->a.init_key(key);
}

void crypto::cipher::chacha20::decryption::init_counter(const byte* counter) noexcept
{
	this->a.init_counter(counter);
}

void crypto::cipher::chacha20::decryption::init_nonce(const byte* nonce) noexcept
{
	this->a.init_nonce(nonce);
}

void crypto::cipher::chacha20::decryption::decrypt(const byte* in, byte* out) noexcept
{
	this->a.encrypt(in, out);
}