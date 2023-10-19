#ifndef utils_define_h
#define utils_define_h
#include<cstddef>
#include<cstdint>
#include<climits>

namespace utils
{
	typedef unsigned char byte;
	typedef std::size_t size_t;

	typedef std::int8_t int8_t;
	typedef std::int16_t int16_t;
	typedef std::int32_t int32_t;
	typedef std::int64_t int64_t;
	typedef std::uint8_t uint8_t;
	typedef std::uint16_t uint16_t;
	typedef std::uint32_t uint32_t;
	typedef std::uint64_t uint64_t;

	struct array
	{
		array() noexcept : array(nullptr, 0) {}
		array(byte* data, size_t length) noexcept : data(data), length(length) {}

		byte* data;
		size_t length;
	};

	struct const_array
	{
		const_array() noexcept : const_array(nullptr, 0) {}
		const_array(const byte* data, size_t length) noexcept : data(data), length(length) {}

		const byte* data;
		size_t length;
	};

	static_assert(CHAR_BIT == 8);
}

#endif