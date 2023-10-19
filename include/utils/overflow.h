#ifndef utils_overflow_h
#define utils_overflow_h
#include<limits>

namespace utils
{
	template<typename T>
	constexpr bool unsigned_add_overflow(T a, T b) noexcept;

	template<typename T>
	constexpr bool unsigned_sub_overflow(T a, T b) noexcept;
}

template<typename T>
constexpr bool utils::unsigned_add_overflow(T a, T b) noexcept
{
	return static_cast<T>(a + b) < a;
}

template<typename T>
constexpr bool utils::unsigned_sub_overflow(T a, T b) noexcept
{
	return a < b;
}

#endif