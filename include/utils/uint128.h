#ifndef utils_uint128_h
#define utils_uint128_h
#include"define.h"
#include<string>
#include<type_traits>
#include"bit.h"
#include"overflow.h"
#include"utils/define.h"

namespace utils
{
	class uint128_t
	{
	public:
		uint128_t() = default;
		uint128_t(const uint128_t&) = default;
		uint128_t& operator=(const uint128_t&) = default;

		template<typename T>
		constexpr uint128_t(T n) noexcept;

		constexpr uint128_t& operator+=(const uint128_t& other) noexcept;
		constexpr uint128_t& operator-=(const uint128_t& other) noexcept;
		constexpr uint128_t& operator*=(const uint128_t& other) noexcept;
		constexpr uint128_t& operator/=(const uint128_t& other) noexcept;
		constexpr uint128_t& operator%=(const uint128_t& other) noexcept;
		constexpr uint128_t& operator&=(const uint128_t& other) noexcept;
		constexpr uint128_t& operator|=(const uint128_t& other) noexcept;
		constexpr uint128_t& operator^=(const uint128_t& other) noexcept;
		constexpr uint128_t& operator<<=(const uint128_t& other) noexcept;
		constexpr uint128_t& operator>>=(const uint128_t& other) noexcept;

		constexpr uint128_t& operator++() noexcept;
		constexpr uint128_t& operator--() noexcept;
		constexpr uint128_t operator++(int) noexcept;
		constexpr uint128_t operator--(int) noexcept;

		constexpr uint128_t operator+() const noexcept;
		constexpr uint128_t operator-() const noexcept;
		constexpr uint128_t operator~() const noexcept;

		explicit constexpr operator bool() const noexcept;
		template<typename T>
		explicit constexpr operator T() const noexcept;

	private:
		uint64_t high;
		uint64_t low;

		static constexpr uint128_t mul(uint64_t a, uint64_t b) noexcept;
		static constexpr void div(const uint128_t& dividend, const uint128_t& divisor, uint128_t& quotient, uint128_t& remainder) noexcept;
		static constexpr void binary_long_division(uint128_t dividend, uint128_t divisor, uint128_t& quotient, uint128_t& remainder) noexcept;
		static constexpr int countl_zero(uint128_t value) noexcept;

		friend constexpr bool operator==(const uint128_t& a, const uint128_t& b) noexcept;
		friend constexpr bool operator<(const uint128_t& a, const uint128_t& b) noexcept;
	};

	constexpr uint128_t operator+(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr uint128_t operator-(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr uint128_t operator*(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr uint128_t operator/(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr uint128_t operator%(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr uint128_t operator&(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr uint128_t operator|(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr uint128_t operator^(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr uint128_t operator<<(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr uint128_t operator>>(const uint128_t& a, const uint128_t& b) noexcept;

	constexpr bool operator==(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr bool operator!=(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr bool operator<(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr bool operator>(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr bool operator<=(const uint128_t& a, const uint128_t& b) noexcept;
	constexpr bool operator>=(const uint128_t& a, const uint128_t& b) noexcept;

	constexpr uint128_t operator""_uint128(const char* str);

	static_assert(sizeof(uint128_t) == 128 / 8);
}

template<typename T>
constexpr utils::uint128_t::uint128_t(T n) noexcept : high(0), low(static_cast<uint64_t>(n)) { static_assert(std::is_integral_v<T>, "T must be integral type"); }

constexpr utils::uint128_t& utils::uint128_t::operator+=(const uint128_t& other) noexcept
{
	this->high += other.high + unsigned_add_overflow(this->low, other.low);
	this->low += other.low;

	return *this;
}

constexpr utils::uint128_t& utils::uint128_t::operator-=(const uint128_t& other) noexcept
{
	this->high -= (other.high + unsigned_sub_overflow(this->low, other.low));
	this->low -= other.low;

	return *this;
}

constexpr utils::uint128_t utils::uint128_t::mul(uint64_t a, uint64_t b) noexcept
{
	/*
	* a * b = c
	* => (a.high * 2^32 * b.high * 2^32) + (a.high * 2^32 * b.low * 2^0) + (a.low * 2^0 * b.high * 2^32) + (a.low * 2^0 * b.low * 2^0)
	* =>
	* v1 = (a.high * 2^32 * b.high * 2^32) = a.high * b.high * 2^64
	* v2 = (a.high * 2^32 * b.low * 2^0) = a.high * b.low * 2^32
	* v3 = (a.low * 2^0 * b.high * 2^32) = a.low * b.high * 2^32
	* v4 = (a.low * 2^0 * b.low * 2^0) = a.low * b.low
	* 
	* temp = (v2.low + v3.low + v4.high) * 2^32
	* c.high = (v1 + v2.high + v3.high + temp.high) * 2^64, c.low = temp.low * 2^32 + v4.low
	*/
	const uint64_t v1 = high_bits<32>(a) * high_bits<32>(b);
	const uint64_t v2 = high_bits<32>(a) * low_bits<32>(b);
	const uint64_t v3 = low_bits<32>(a) * high_bits<32>(b);
	const uint64_t v4 = low_bits<32>(a) * low_bits<32>(b);

	const uint64_t temp = low_bits<32>(v2) + low_bits<32>(v3) + high_bits<32>(v4);

	uint128_t result = 0;
	result.high = v1 + high_bits<32>(v2) + high_bits<32>(v3) + high_bits<32>(temp);
	result.low = (temp << 32) + low_bits<32>(v4);

	return result;
}

constexpr utils::uint128_t& utils::uint128_t::operator*=(const uint128_t& other) noexcept
{
	/*
	* a * b = c 
	* => (a.high * 2^64 * b.high * 2^64) + (a.high * 2^64 * b.low * 2^0) + (a.low * 2^0 * b.high * 2^64) + (a.low * 2^0 * b.low * 2^0)
	* =>
	* (a.high * 2^64 * b.high * 2^64) = a.high * b.high * 2^128, drop
	* v1 = (a.high * 2^64 * b.low * 2^0) = a.high * b.low * 2^64
	* v2 = (a.low * 2^0 * b.high * 2^64) = a.low * b.high * 2^64
	* v3 = (a.low * 2^0 * b.low * 2^0) = a.low * b.low
	* 
	* c.high = (v1 + v2 + v3.high) * 2^64, c.low = v3.low
	*/
	uint128_t result = this->mul(this->low, other.low);
	result.high += this->high * other.low + this->low * other.high;

	return *this = result;
}

constexpr int utils::uint128_t::countl_zero(uint128_t value) noexcept
{
	if (!value)
		return 128;

	uint128_t a = 0;
	int n = 0;
	for (int shift = 64; shift; shift /= 2)
	{
		a <<= shift;
		if (!(value & a))
		{
			n += shift;
			value <<= shift;
		}
	}

	return n;
}

constexpr void utils::uint128_t::binary_long_division(uint128_t dividend, uint128_t divisor, uint128_t& quotient, uint128_t& remainder) noexcept
{
	//0 <= shift <= 128 - 1
	int shift = static_cast<int>(countl_zero(divisor) - countl_zero(dividend));
	divisor <<= shift;
	quotient = 0;

	for (; shift >= 0; shift--)
	{
		quotient <<= 1;
		if (dividend >= divisor)
		{
			dividend -= divisor;
			quotient |= 1;
		}
		divisor >>= 1;
	}

	remainder = dividend;
}

//if divisor is zero, the behavior is undefined
constexpr void utils::uint128_t::div(const uint128_t& dividend, const uint128_t& divisor, uint128_t& quotient, uint128_t& remainder) noexcept
{
	//n n n n = dividend.high dividend.low divisor.high divisor.low, n = 1 is != 0, else n = 0
	if (dividend < divisor)
	{
		quotient = 0;
		remainder = dividend;
	}
	else if (dividend == divisor)
	{
		quotient = 1;
		remainder = 0;
	}
	else if (!dividend.high)
	{
		//dividend.high is zero and dividend > divisor, 0 1 0 1 
		quotient.high = 0;
		quotient.low = dividend.low / divisor.low;
		remainder.high = 0;
		remainder.low = dividend.low % divisor.low;
	}
	//now 1 n n n
	else if (!divisor.low)
	{
		//1 0 1 0, 1 1 1 0, because 1 n n 0 and divisor != 0, 1 n 1 0
		quotient.high = 0;
		quotient.low = dividend.high / divisor.high;
		remainder.high = dividend.high % divisor.high;
		remainder.low = dividend.low;
	}
	//now 1 n n 1
	else
		binary_long_division(dividend, divisor, quotient, remainder);//1 0 1 1, 1 1 1 1 (128 / 128) and 1 0 0 1, 1 1 0 1 (128 / 64)
}

constexpr utils::uint128_t& utils::uint128_t::operator/=(const uint128_t& other) noexcept
{
	uint128_t quotient = 0;
	uint128_t remainder = 0;
	this->div(*this, other, quotient, remainder);
	return *this = quotient;
}

constexpr utils::uint128_t& utils::uint128_t::operator%=(const uint128_t& other) noexcept
{
	uint128_t quotient = 0;
	uint128_t remainder = 0;
	this->div(*this, other, quotient, remainder);
	return *this = remainder;
}

constexpr utils::uint128_t& utils::uint128_t::operator&=(const uint128_t& other) noexcept
{
	this->high &= other.high;
	this->low &= other.low;

	return *this;
}

constexpr utils::uint128_t& utils::uint128_t::operator|=(const uint128_t& other) noexcept
{
	this->high |= other.high;
	this->low |= other.low;

	return *this;
}

constexpr utils::uint128_t& utils::uint128_t::operator^=(const uint128_t& other) noexcept
{
	this->high ^= other.high;
	this->low ^= other.low;

	return *this;
}

constexpr utils::uint128_t& utils::uint128_t::operator<<=(const uint128_t& other) noexcept
{
	const uint64_t shift = other.low;

	if (!shift)
		return *this;
	else if (shift < 64)
	{
		this->high = (this->high << shift) | (this->low >> (64 - shift));
		this->low <<= shift;
	}
	else
	{
		this->high = this->low << (shift - 64);
		this->low = 0;
	}

	return *this;
}

constexpr utils::uint128_t& utils::uint128_t::operator>>=(const uint128_t& other) noexcept
{
	const uint64_t shift = other.low;

	if (!shift)
		return *this;
	else if (shift < 64)
	{
		this->low = (this->high << (64 - shift)) | (this->low >> shift);
		this->high >>= shift;
	}
	else
	{
		this->low = this->high >> (shift - 64);
		this->high = 0;
	}

	return *this;
}

constexpr utils::uint128_t& utils::uint128_t::operator++() noexcept
{
	return *this += 1;
}

constexpr utils::uint128_t& utils::uint128_t::operator--() noexcept
{
	return *this -= 1;
}

constexpr utils::uint128_t utils::uint128_t::operator++(int) noexcept
{
	uint128_t temp = *this;
	++(*this);
	return temp;
}

constexpr utils::uint128_t utils::uint128_t::operator--(int) noexcept
{
	uint128_t temp = *this;
	--(*this);
	return temp;
}

constexpr utils::uint128_t utils::uint128_t::operator+() const noexcept
{
	return *this;
}

constexpr utils::uint128_t utils::uint128_t::operator-() const noexcept
{
	return ~uint128_t(0) - (*this) + 1;
}

constexpr utils::uint128_t utils::uint128_t::operator~() const noexcept
{
	uint128_t temp = 0;
	temp.high = ~this->high;
	temp.low = ~this->low;
	return temp;
}

constexpr utils::uint128_t::operator bool() const noexcept
{
	return this->high || this->low;
}

template<typename T>
constexpr utils::uint128_t::operator T() const noexcept
{
	static_assert(std::is_integral_v<T>, "T must be integral type");
	return static_cast<T>(this->low);
}

constexpr utils::uint128_t utils::operator+(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) += b;
}

constexpr utils::uint128_t utils::operator-(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) -= b;
}

constexpr utils::uint128_t utils::operator*(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) *= b;
}

constexpr utils::uint128_t utils::operator/(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) /= b;
}

constexpr utils::uint128_t utils::operator%(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) %= b;
}

constexpr utils::uint128_t utils::operator&(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) &= b;
}

constexpr utils::uint128_t utils::operator|(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) |= b;
}

constexpr utils::uint128_t utils::operator^(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) ^= b;
}

constexpr utils::uint128_t utils::operator<<(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) <<= b;
}

constexpr utils::uint128_t utils::operator>>(const uint128_t& a, const uint128_t& b) noexcept
{
	return uint128_t(a) >>= b;
}

constexpr bool utils::operator==(const uint128_t& a, const uint128_t& b) noexcept
{
	return a.high == b.high && a.low == b.low;
}

constexpr bool utils::operator!=(const uint128_t& a, const uint128_t& b) noexcept
{
	return !(a == b);
}

constexpr bool utils::operator<(const uint128_t& a, const uint128_t& b) noexcept
{
	return a.high != b.high ? a.high < b.high : a.low < b.low;
}

constexpr bool utils::operator>(const uint128_t& a, const uint128_t& b) noexcept
{
	return b < a;
}

constexpr bool utils::operator<=(const uint128_t& a, const uint128_t& b) noexcept
{
	return !(b < a);
}

constexpr bool utils::operator>=(const uint128_t& a, const uint128_t& b) noexcept
{
	return !(a < b);
}

namespace utils::implementation
{
	struct ill_formed {};

	constexpr int get_base(const char* str);
	constexpr char to_lowercase(char c);
	constexpr int to_int(char c, int base);
}

constexpr int utils::implementation::get_base(const char* str)
{
	if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
		return 16;
	else if (str[0] == '0' && (str[1] == 'b' || str[1] == 'B'))
		return 2;
	else if (str[0] == '0')
		return 8;
	else
		return 10;
}

constexpr char utils::implementation::to_lowercase(char c)
{
	constexpr auto lowercase = "abcdefghijklmnopqrstuvwxyz";
	constexpr auto uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	for (int i = 0; i < 26; i++)
		if (c == uppercase[i])
			return lowercase[i];
	return c;
}

constexpr int utils::implementation::to_int(char c, int base)
{
	constexpr auto number = "0123456789abcdef";

	c = to_lowercase(c);
	for (int i = 0; i < base; i++)
		if (c == number[i])
			return i;

	throw ill_formed();
}

constexpr utils::uint128_t utils::operator""_uint128(const char* str)
{
	using utils::implementation::get_base;
	using utils::implementation::to_int;

	uint128_t sum = 0;
	uint128_t exponent = 1;
	int base = get_base(str);

	if (base == 8)
		str += 1;
	else if (base == 2 || base == 16)
		str += 2;

	for (const char* p = str + std::char_traits<char>::length(str) - 1; p != str; p--)
	{
		if (*p == '\'')
			continue;

		sum += to_int(*p, base) * exponent;
		exponent *= base;
	}

	return sum += to_int(*str, base) * exponent;
}

#endif