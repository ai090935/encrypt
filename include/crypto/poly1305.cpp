#include"poly1305.h"
#include<algorithm>
#include<utils/bit.h>
#include<utils/overflow.h>

using utils::endian;
using utils::byte_to_word;
using utils::word_to_byte;
using utils::uint128_t;
using utils::operator""_uint128;

crypto::MAC::poly1305::poly1305() noexcept : length(0), acc(0, 0) {}

crypto::MAC::poly1305::poly1305(const byte* key) noexcept : poly1305()
{
	this->init(key);
}

crypto::MAC::poly1305::poly1305(const byte* key, const byte* input, size_t length, byte* output) noexcept : poly1305(key)
{
	this->update(input, length);
	this->final(output);
}

void crypto::MAC::poly1305::init(const byte* key) noexcept
{
	constexpr uint128_t mask = 0x0ffffffc'0ffffffc'0ffffffc'0fffffff_uint128;
	this->r = byte_to_word<endian::little, uint128_t>(key) & mask;
	this->s = byte_to_word<endian::little, uint128_t>(key + sizeof(uint128_t));
}

void crypto::MAC::poly1305::update(const byte* input, size_t length) noexcept
{
	while (length)
	{
		if (this->length == this->block_size)
		{
			this->compress();
			this->length = 0;
		}

		int outlen = (this->length + length < this->block_size) ? length : this->block_size - this->length;
		std::copy(input, input + outlen, this->block + this->length);

		this->length += outlen;
		input += outlen;
		length -= outlen;
	}
}

void crypto::MAC::poly1305::final(byte* output) noexcept
{
	this->compress();
	this->acc += this->s;
	word_to_byte<endian::little>(this->acc.low, output);
}

void crypto::MAC::poly1305::compress() noexcept
{
	if (this->length == this->block_size)
		this->acc.high++;
	else
	{
		this->block[this->length] = 0x01;
		std::fill(this->block + this->length + 1, this->block + this->block_size, 0);
	}

	this->acc += byte_to_word<endian::little, uint128_t>(this->block);
	this->acc *= this->r;
	this->modulo_p();
}

void crypto::MAC::poly1305::modulo_p() noexcept
{
	/*
	* let p = 2^130 - 5
	* acc % p
	* => ((acc % 2^130) + (acc / 2^130) * 5) % 2^130 - 5
	*
	* c = (acc / 2^130) * 5
	* = (acc / 2^130) * 2^2 + (acc / 2^130)
	* = ((acc >> 130) << 2) + (acc >> 130)
	*             v                v
	*             a                b
	* result less than 2^128
	*/
	const uint128_t a = this->acc.high & ~uint128_t(3);
	const uint128_t b = this->acc.high >> 2;
	const uint128_t c = a + b;

	//acc = acc % 2^130 + c
	this->acc.high &= 3;
	this->acc += c;

	//if (!(acc < p)) acc -= p
	constexpr integer p = integer(3, ~uint128_t(0) - 4);
	if (!(acc.high != p.high ? acc.high < p.high : acc.low < p.low))
	{
		acc.high -= (p.high + utils::unsigned_sub_overflow(acc.low, p.low));
		acc.low -= p.low;
	}
}

//-------------------------------------------------------------------------------------------------

crypto::MAC::poly1305::integer& crypto::MAC::poly1305::integer::operator+=(const utils::uint128_t& b) noexcept
{
	this->high += utils::unsigned_add_overflow(this->low, b);
	this->low += b;
	return *this;
}

crypto::MAC::poly1305::integer& crypto::MAC::poly1305::integer::operator*=(const utils::uint128_t& b) noexcept
{
	/*
	* let uint64 a[0] = this.high.low, a[1] = this.low.high, a[2] = this.low.low, b[0] = b.high, b[1] = b.low
	* 
	* a * b
	* => (a[0] * 2^128 * b[0] * 2^64) + (a[0] * 2^128 * b[1] * 2^0) + (a[1] * 2^64 * b[0] * 2^64) + (a[1] * 2^64 * b[1] * 2^0) + (a[2] * 2^0 * b[0] * 2^64) + (a[2] * 2^0 * b[1] * 2^0)
	* =>
	* uint128 v[6]
	* v[0] = (a[0] * 2^128 * b[0] * 2^64) = a[0] * b[0] * 2^192, result less than 2^64
	* v[1] = (a[0] * 2^128 * b[1] * 2^0) = a[0] * b[1] * 2^128
	* v[2] = (a[1] * 2^64 * b[0] * 2^64) = a[1] * b[0] * 2^128
	* v[3] = (a[1] * 2^64 * b[1] * 2^0) = a[1] * b[1] * 2^64
	* v[4] = (a[2] * 2^0 * b[0] * 2^64) = a[2] * b[0] * 2^64
	* v[5] = (a[2] * 2^0 * b[1] * 2^0) = a[2] * b[1]
	*
	* -			v[0]
	* --		v[1]
	* --		v[2]
	*  --		v[3]
	*  --		v[4]
	*   --		v[5]
	* 3210		2^(n * 64)
	*
	* uint64 result[4] = v[0] + v[1] + ... + v[5], result less than 2^256
	* result[3] = v[5].low
	*
	* temp = (v[3].low + v[4].low + v[5].high) * 2^64
	* result[2] = temp.low * 2^64
	*
	* temp = temp.high * 2^128
	* temp = (temp + v[1].low + v[2].low + v[3].high + v[4].high) * 2^128
	* result[1] = temp.low * 2^128
	*
	* temp = temp.high * 2^192
	* temp = (temp + v[0].low + v[1].high + v[2].high) * 2^192
	* result[0] = temp.low * 2^192
	*/
	uint128_t v[6], temp;
	v[0] = static_cast<uint64_t>(utils::low_bits<64>(this->high)) * static_cast<uint64_t>(utils::high_bits<64>(b));
	v[1] = utils::low_bits<64>(this->high) * utils::low_bits<64>(b);
	v[2] = utils::high_bits<64>(this->low) * utils::high_bits<64>(b);
	v[3] = utils::high_bits<64>(this->low) * utils::low_bits<64>(b);
	v[4] = utils::low_bits<64>(this->low) * utils::high_bits<64>(b);
	v[5] = utils::low_bits<64>(this->low) * utils::low_bits<64>(b);

	this->low = utils::low_bits<64>(v[5]);

	temp = utils::low_bits<64>(v[3]) + utils::low_bits<64>(v[4]) + utils::high_bits<64>(v[5]);
	this->low |= utils::low_bits<64>(temp) << 64;

	temp = utils::high_bits<64>(temp);
	temp = temp + utils::low_bits<64>(v[1]) + utils::low_bits<64>(v[2]) + utils::high_bits<64>(v[3]) + utils::high_bits<64>(v[4]);
	this->high = utils::low_bits<64>(temp);

	temp = utils::high_bits<64>(temp);
	temp = temp + utils::low_bits<64>(v[0]) + utils::high_bits<64>(v[1]) + utils::high_bits<64>(v[2]);
	this->high |= utils::low_bits<64>(temp) << 64;

	return *this;
}