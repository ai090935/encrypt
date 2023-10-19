#ifndef utils_bit_h
#define utils_bit_h
#include"define.h"
#include<climits>

namespace utils
{
	enum class endian
	{
		big,
		little,
	};

	//word must be unsigned integer type
	template<endian word_endian, typename word>
	word byte_to_word(const byte* p) noexcept;

	//word must be unsigned integer type
	template<endian word_endian, typename word>
	void word_to_byte(word n, byte* p) noexcept;

	template<typename T>
	inline constexpr size_t bit_size = sizeof(T) * CHAR_BIT;

	//T must be unsigned integer type
	template<typename T>
	constexpr T rotl(T value, size_t shift) noexcept;

	//T must be unsigned integer type
	template<typename T>
	constexpr T rotr(T value, size_t shift) noexcept;

	//T must be unsigned integer type, 1 <= bits <= bit_size<T>
	template<size_t bits, typename T>
	constexpr T high_bits(T value) noexcept;

	//T must be unsigned integer type, 1 <= bits <= bit_size<T>
	template<size_t bits, typename T>
	constexpr T low_bits(T value) noexcept;

	constexpr void memxor(void* dest, const void* a, const void* b, size_t count);
}

//-------------------------------------------------------------------------------------------------

template<utils::endian word_endian, typename word>
word utils::byte_to_word(const byte* p) noexcept
{
	word n = 0;
	if constexpr (word_endian == endian::big)
		for (size_t i = 0; i < sizeof(word); i++)
			n |= static_cast<word>(p[i]) << (sizeof(word) - 1 - i) * CHAR_BIT;
	else if constexpr (word_endian == endian::little)
		for (size_t i = 0; i < sizeof(word); i++)
			n |= static_cast<word>(p[i]) << i * CHAR_BIT;

	return n;
}

template<utils::endian word_endian, typename word>
void utils::word_to_byte(word n, byte* p) noexcept
{
	if constexpr (word_endian == endian::big)
		for (size_t i = 0; i < sizeof(word); i++)
			p[i] = static_cast<byte>(n >> (sizeof(word) - 1 - i) * CHAR_BIT);
	else if constexpr (word_endian == endian::little)
		for (size_t i = 0; i < sizeof(word); i++)
			p[i] = static_cast<byte>(n >> i * CHAR_BIT);
}

template<typename T>
constexpr T utils::rotl(T value, size_t shift) noexcept
{
	return (value << shift) | (value >> (bit_size<T> - shift));
}

template<typename T>
constexpr T utils::rotr(T value, size_t shift) noexcept
{
	return (value >> shift) | (value << (bit_size<T> - shift));
}

template<utils::size_t bits, typename T>
constexpr T utils::high_bits(T value) noexcept
{
	return value >> (bit_size<T> - bits);
}

template<utils::size_t bits, typename T>
constexpr T utils::low_bits(T value) noexcept
{
	return value & high_bits<bits>(~T(0));
}

constexpr void utils::memxor(void* dest, const void* a, const void* b, size_t count)
{
	for (std::size_t i = 0; i < count; i++)
		static_cast<byte*>(dest)[i] = static_cast<const byte*>(a)[i] ^ static_cast<const byte*>(b)[i];
}

#endif