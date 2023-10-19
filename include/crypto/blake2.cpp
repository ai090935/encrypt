#include"blake2.h"
#include<algorithm>
#include<utils/bit.h>

using namespace crypto;
using utils::endian;
using utils::byte_to_word;
using utils::word_to_byte;

namespace
{
	//rfc 3.1
	template<const auto& parameter, typename word>
	void mixing(word* v, int a, int b, int c, int d, word x, word y) noexcept
	{
		v[a] = v[a] + v[b] + x;
		v[d] = utils::rotr(static_cast<word>(v[d] ^ v[a]), parameter.R[0]);
		v[c] = v[c] + v[d];
		v[b] = utils::rotr(static_cast<word>(v[b] ^ v[c]), parameter.R[1]);
		v[a] = v[a] + v[b] + y;
		v[d] = utils::rotr(static_cast<word>(v[d] ^ v[a]), parameter.R[2]);
		v[c] = v[c] + v[d];
		v[b] = utils::rotr(static_cast<word>(v[b] ^ v[c]), parameter.R[3]);
	}

	//rfc 3.2
	template<const auto& parameter, typename word, typename T>
	void compress(word* h, byte* b, T& total_length, bool last) noexcept
	{
		constexpr byte sigma[10][16] = {
			{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
			{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
			{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
			{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
			{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
			{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
			{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
			{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
			{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
			{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
		};

		word v[16], m[16];

		std::copy(h, h + 8, v);
		std::copy(parameter.IV, parameter.IV + 8, v + 8);
		v[12] ^= static_cast<word>(utils::low_bits<utils::bit_size<T> / 2>(total_length));
		v[13] ^= static_cast<word>(utils::high_bits<utils::bit_size<T> / 2>(total_length));
		if (last)
			v[14] = ~v[14];

		for (int i = 0; i < 16; i++)
			m[i] = byte_to_word<endian::little, word>(b + i * sizeof(word));

		for (int i = 0; i < parameter.r; i++)
		{
			mixing<parameter>(v, 0, 4, 8, 12, m[sigma[i % 10][0]], m[sigma[i % 10][1]]);
			mixing<parameter>(v, 1, 5, 9, 13, m[sigma[i % 10][2]], m[sigma[i % 10][3]]);
			mixing<parameter>(v, 2, 6, 10, 14, m[sigma[i % 10][4]], m[sigma[i % 10][5]]);
			mixing<parameter>(v, 3, 7, 11, 15, m[sigma[i % 10][6]], m[sigma[i % 10][7]]);
			mixing<parameter>(v, 0, 5, 10, 15, m[sigma[i % 10][8]], m[sigma[i % 10][9]]);
			mixing<parameter>(v, 1, 6, 11, 12, m[sigma[i % 10][10]], m[sigma[i % 10][11]]);
			mixing<parameter>(v, 2, 7, 8, 13, m[sigma[i % 10][12]], m[sigma[i % 10][13]]);
			mixing<parameter>(v, 3, 4, 9, 14, m[sigma[i % 10][14]], m[sigma[i % 10][15]]);
		}

		for (int i = 0; i < 8; i++)
			h[i] ^= v[i] ^ v[i + 8];
	}

	//-------------------------------------------------------------------------------------------------

	template<int block_size, typename word>
	void init(const byte* key, int keylen, word* h, byte* b, int& b_length, int output_size) noexcept
	{
		h[0] ^= 0x01010000 ^ (keylen << 8) ^ output_size;
		if (keylen)
		{
			std::copy(key, key + keylen, b);
			std::fill(b + keylen, b + block_size, 0);
			b_length = block_size;
		}
	}

	template<int block_size, typename T, typename F>
	void update(const byte* input, size_t length, byte* b, int& b_length, T& total_length, F&& compress) noexcept
	{
		while (length)
		{
			if (b_length == block_size)
			{
				total_length += b_length;
				compress();
				b_length = 0;
			}

			int outlen = (b_length + length < block_size) ? length : block_size - b_length;
			std::copy(input, input + outlen, b + b_length);

			b_length += outlen;
			input += outlen;
			length -= outlen;
		}
	}

	template<int block_size, typename word, typename T, typename F>
	void final(byte* output, word* h, byte* b, int b_length, int output_size, T& total_length, F&& compress) noexcept
	{
		total_length += b_length;
		std::fill(b + b_length, b + block_size, 0);
		compress();

		byte temp[8 * sizeof(word)];
		for (int i = 0; i < 8; i++)
			word_to_byte<endian::little>(h[i], temp + i * sizeof(word));
		std::copy(temp, temp + output_size, output);
	}

	template<typename word>
	struct blake2_parameter
	{
		word IV[8];
		int r;
		int R[4];
	};

	constexpr blake2_parameter<uint64_t> blake2b_parameter = { { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 }, 12, { 32, 24, 16, 63 } };
	constexpr blake2_parameter<uint32_t> blake2s_parameter = { { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }, 10, { 16, 12, 8, 7 } };

}

//-------------------------------------------------------------------------------------------------

crypto::MAC::blake2b::blake2b(int output_size) noexcept : h{ 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 }, b_length(0), output_size(output_size), total_length(0) {}

crypto::MAC::blake2b::blake2b(const byte* key, int keylen, int output_size) noexcept : blake2b(output_size)
{
	this->init(key, keylen);
}

crypto::MAC::blake2b::blake2b(const byte* key, int keylen, const byte* input, size_t length, byte* output, int output_size) noexcept : blake2b(key, keylen, output_size)
{
	this->update(input, length);
	this->final(output);
}

void crypto::MAC::blake2b::init(const byte* key, int keylen) noexcept
{
	::init<block_size>(key, keylen, this->h, this->b, this->b_length, this->output_size);
}

void crypto::MAC::blake2b::update(const byte* input, size_t length) noexcept
{
	auto compress = [&]() { ::compress<blake2b_parameter>(this->h, this->b, this->total_length, false); };
	::update<block_size>(input, length, this->b, this->b_length, this->total_length, compress);
}

void crypto::MAC::blake2b::final(byte* output) noexcept
{
	auto compress = [&]() { ::compress<blake2b_parameter>(this->h, this->b, this->total_length, true); };
	::final<block_size>(output, this->h, this->b, this->b_length, this->output_size, this->total_length, compress);
}

//-------------------------------------------------------------------------------------------------

crypto::MAC::blake2s::blake2s(int output_size) noexcept : h{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }, b_length(0), output_size(output_size), total_length(0) {}

crypto::MAC::blake2s::blake2s(const byte* key, int keylen, int output_size) noexcept : blake2s(output_size)
{
	this->init(key, keylen);
}

crypto::MAC::blake2s::blake2s(const byte* key, int keylen, const byte* input, size_t length, byte* output, int output_size) noexcept : blake2s(key, keylen, output_size)
{
	this->update(input, length);
	this->final(output);
}

void crypto::MAC::blake2s::init(const byte* key, int keylen) noexcept
{
	::init<block_size>(key, keylen, this->h, this->b, this->b_length, this->output_size);
}

void crypto::MAC::blake2s::update(const byte* input, size_t length) noexcept
{
	auto compress = [&]() { ::compress<blake2s_parameter>(this->h, this->b, this->total_length, false); };
	::update<block_size>(input, length, this->b, this->b_length, this->total_length, compress);
}

void crypto::MAC::blake2s::final(byte* output) noexcept
{
	auto compress = [&]() { ::compress<blake2s_parameter>(this->h, this->b, this->total_length, true); };
	::final<block_size>(output, this->h, this->b, this->b_length, this->output_size, this->total_length, compress);
}

//-------------------------------------------------------------------------------------------------

crypto::hash::blake2b::blake2b(int output_size) noexcept : MAC::blake2b(nullptr, 0, output_size) {}

crypto::hash::blake2b::blake2b(const byte* input, size_t length, byte* output, int output_size) noexcept : MAC::blake2b(nullptr, 0, input, length, output, output_size) {}

//-------------------------------------------------------------------------------------------------

crypto::hash::blake2s::blake2s(int output_size) noexcept : MAC::blake2s(nullptr, 0, output_size) {}

crypto::hash::blake2s::blake2s(const byte* input, size_t length, byte* output, int output_size) noexcept : MAC::blake2s(nullptr, 0, input, length, output, output_size) {}