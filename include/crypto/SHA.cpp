#include"SHA.h"
#include<algorithm>
#include<utils/bit.h>

using namespace crypto;
using utils::endian;
using utils::byte_to_word;
using utils::word_to_byte;
using utils::rotl;
using utils::rotr;

namespace
{
	template<typename word>
	word Ch(word x, word y, word z) noexcept
	{
		return (x & y) ^ (~x & z);
	}

	template<typename word>
	word Maj(word x, word y, word z) noexcept
	{
		return (x & y) ^ (x & z) ^ (y & z);
	}

	//-------------------------------------------------------------------------------------------------

	template<int block_size, typename T, typename F>
	void update(const byte* input, size_t length, byte* M, int& M_length, T& total_length , F&& compress) noexcept
	{
		total_length += length;

		while (length)
		{
			int outlen = (M_length + length < block_size) ? length : block_size - M_length;
			std::copy(input, input + outlen, M + M_length);

			M_length += outlen;
			input += outlen;
			length -= outlen;

			if (M_length == block_size)
			{
				compress();
				M_length = 0;
			}
		}
	}

	template<int block_size, typename word, int N, typename T, typename F>
	void final(byte* output, word(&H)[N], byte* M, int& M_length, T& total_length, F&& compress) noexcept
	{
		M[M_length] = 0x80;
		M_length++;

		if (M_length + sizeof(total_length) > block_size)
		{
			std::fill(M + M_length, M + block_size, 0);
			compress();
			M_length = 0;
		}

		std::fill(M + M_length, M + block_size - sizeof(total_length), 0);
		word_to_byte<endian::big>(static_cast<T>(total_length * 8), M + block_size - sizeof(total_length));
		compress();

		for (int i = 0; i < N; i++)
			word_to_byte<endian::big>(H[i], output + i * sizeof(word));
	}
}

//-------------------------------------------------------------------------------------------------

namespace
{
	uint32_t Parity(uint32_t x, uint32_t y, uint32_t z) noexcept
	{
		return x ^ y ^ z;
	}
}

crypto::hash::SHA1::SHA1() noexcept : H{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 }, M_length(0), total_length(0) {}

crypto::hash::SHA1::SHA1(const byte* input, size_t length, byte* output) noexcept : SHA1()
{
	this->update(input, length);
	this->final(output);
}

void crypto::hash::SHA1::update(const byte* input, size_t length) noexcept
{
	::update<block_size>(input, length, this->M, this->M_length, this->total_length, [&]() { this->compress(); });
}

void crypto::hash::SHA1::final(byte* output) noexcept
{
	::final<block_size>(output, this->H, this->M, this->M_length, this->total_length, [&]() { this->compress(); });
}

void crypto::hash::SHA1::compress() noexcept
{
	word W[80];
	word a, b, c, d, e;

	for (int t = 0; t <= 15; t++)
		W[t] = byte_to_word<endian::big, word>(this->M + t * sizeof(word));
	for (int t = 16; t <= 79; t++)
		W[t] = rotl(static_cast<word>(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]), 1);

	a = this->H[0];
	b = this->H[1];
	c = this->H[2];
	d = this->H[3];
	e = this->H[4];

	for (int t = 0; t <= 79; t++)
	{
		word T;
		if (0 <= t && t <= 19)
			T = rotl(a, 5) + Ch(b, c, d) + e + 0x5a827999 + W[t];
		else if (20 <= t && t <= 39)
			T = rotl(a, 5) + Parity(b, c, d) + e + 0x6ed9eba1 + W[t];
		else if (40 <= t && t <= 59)
			T = rotl(a, 5) + Maj(b, c, d) + e + 0x8f1bbcdc + W[t];
		else// if (60 <= t && t <= 79)
			T = rotl(a, 5) + Parity(b, c, d) + e + 0xca62c1d6 + W[t];
		e = d;
		d = c;
		c = rotl(b, 30);
		b = a;
		a = T;
	}

	this->H[0] += a;
	this->H[1] += b;
	this->H[2] += c;
	this->H[3] += d;
	this->H[4] += e;
}

//-------------------------------------------------------------------------------------------------

namespace
{
	uint32_t Sigma0(uint32_t x) noexcept
	{
		return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
	}

	uint32_t Sigma1(uint32_t x) noexcept
	{
		return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
	}

	uint32_t sigma0(uint32_t x) noexcept
	{
		return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
	}

	uint32_t sigma1(uint32_t x) noexcept
	{
		return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
	}
}

crypto::hash::SHA256::SHA256() noexcept : H{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }, M_length(0), total_length(0) {}

crypto::hash::SHA256::SHA256(std::initializer_list<word> H) noexcept : SHA256()
{
	std::copy(H.begin(), H.end(), this->H);
}

crypto::hash::SHA256::SHA256(const byte* input, size_t length, byte* output) noexcept : SHA256()
{
	this->update(input, length);
	this->final(output);
}

void crypto::hash::SHA256::update(const byte* input, size_t length) noexcept
{
	::update<block_size>(input, length, this->M, this->M_length, this->total_length, [&]() { this->compress(); });
}

void crypto::hash::SHA256::final(byte* output) noexcept
{
	::final<block_size>(output, this->H, this->M, this->M_length, this->total_length, [&]() { this->compress(); });
}

void crypto::hash::SHA256::compress() noexcept
{
	constexpr word K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};

	word W[64];
	word a, b, c, d, e, f, g, h;

	for (int t = 0; t <= 15; t++)
		W[t] = byte_to_word<endian::big, word>(this->M + t * sizeof(word));
	for (int t = 16; t <= 63; t++)
		W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];

	a = this->H[0];
	b = this->H[1];
	c = this->H[2];
	d = this->H[3];
	e = this->H[4];
	f = this->H[5];
	g = this->H[6];
	h = this->H[7];

	for (int t = 0; t <= 63; t++)
	{
		word T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
		word T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	this->H[0] += a;
	this->H[1] += b;
	this->H[2] += c;
	this->H[3] += d;
	this->H[4] += e;
	this->H[5] += f;
	this->H[6] += g;
	this->H[7] += h;
}

//-------------------------------------------------------------------------------------------------

crypto::hash::SHA224::SHA224() noexcept : SHA256({ 0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 }) {}

crypto::hash::SHA224::SHA224(const byte* input, size_t length, byte* output) noexcept : SHA224()
{
	this->update(input, length);
	this->final(output);
}

void crypto::hash::SHA224::final(byte* output) noexcept
{
	byte temp[SHA256::output_size];
	this->SHA256::final(temp);
	std::copy(temp, temp + this->output_size, output);
}

//-------------------------------------------------------------------------------------------------

namespace
{
	uint64_t Sigma0(uint64_t x) noexcept
	{
		return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
	}

	uint64_t Sigma1(uint64_t x) noexcept
	{
		return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
	}

	uint64_t sigma0(uint64_t x) noexcept
	{
		return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
	}

	uint64_t sigma1(uint64_t x) noexcept
	{
		return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
	}
}

crypto::hash::SHA512::SHA512() noexcept : H{ 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 }, M_length(0), total_length(0) {}

crypto::hash::SHA512::SHA512(std::initializer_list<word> H) noexcept : SHA512()
{
	std::copy(H.begin(), H.end(), this->H);
}

crypto::hash::SHA512::SHA512(const byte* input, size_t length, byte* output) noexcept : SHA512()
{
	this->update(input, length);
	this->final(output);
}

void crypto::hash::SHA512::update(const byte* input, size_t length) noexcept
{
	::update<block_size>(input, length, this->M, this->M_length, this->total_length, [&]() { this->compress(); });
}

void crypto::hash::SHA512::final(byte* output) noexcept
{
	::final<block_size>(output, this->H, this->M, this->M_length, this->total_length, [&]() { this->compress(); });
}

void crypto::hash::SHA512::compress() noexcept
{
	constexpr word K[80] = {
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
	};

	word W[80];
	word a, b, c, d, e, f, g, h;

	for (int t = 0; t <= 15; t++)
		W[t] = byte_to_word<endian::big, word>(this->M + t * sizeof(word));
	for (int t = 16; t <= 79; t++)
		W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];

	a = this->H[0];
	b = this->H[1];
	c = this->H[2];
	d = this->H[3];
	e = this->H[4];
	f = this->H[5];
	g = this->H[6];
	h = this->H[7];

	for (int t = 0; t <= 79; t++)
	{
		word T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
		word T2 = Sigma0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	this->H[0] += a;
	this->H[1] += b;
	this->H[2] += c;
	this->H[3] += d;
	this->H[4] += e;
	this->H[5] += f;
	this->H[6] += g;
	this->H[7] += h;
}

//-------------------------------------------------------------------------------------------------

template<int Output_size>
crypto::hash::derived_from_SHA512<Output_size>::derived_from_SHA512(const byte* input, size_t length, byte* output) noexcept : derived_from_SHA512<Output_size>()
{
	this->update(input, length);
	this->final(output);
}

template<int Output_size>
void crypto::hash::derived_from_SHA512<Output_size>::final(byte* output) noexcept
{
	byte temp[SHA512::output_size];
	this->SHA512::final(temp);
	std::copy(temp, temp + this->output_size, output);
}

//-------------------------------------------------------------------------------------------------

template<>
crypto::hash::derived_from_SHA512<48>::derived_from_SHA512() noexcept : SHA512({ 0xcbbb9d5dc1059ed8, 0x629a292a367cd507,0x9159015a3070dd17,0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4 }) {}

template<>
crypto::hash::derived_from_SHA512<28>::derived_from_SHA512() noexcept : SHA512({ 0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf, 0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1 }) {}

template<>
crypto::hash::derived_from_SHA512<32>::derived_from_SHA512() noexcept : SHA512({ 0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2 }) {}

//-------------------------------------------------------------------------------------------------

template class crypto::hash::derived_from_SHA512<48>;
template class crypto::hash::derived_from_SHA512<28>;
template class crypto::hash::derived_from_SHA512<32>;