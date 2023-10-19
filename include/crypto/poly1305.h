#ifndef crypto_poly1305_h
#define crypto_poly1305_h
#include"define.h"
#include<utils/uint128.h>

//RFC 8439

namespace crypto::MAC
{
	class poly1305
	{
	public:
		poly1305() noexcept;
		poly1305(const byte* key) noexcept;
		poly1305(const byte* key, const byte* input, size_t length, byte* output) noexcept;

		void init(const byte* key) noexcept;
		void update(const byte* input, size_t length) noexcept;
		void final(byte* output) noexcept;

		static constexpr int key_size = 32;
		static constexpr int block_size = 16;
		static constexpr int output_size = 16;

	private:
		class integer
		{
		public:
			constexpr integer(utils::uint128_t high, utils::uint128_t low) noexcept : high(high), low(low) {}

			integer& operator+=(const utils::uint128_t& b) noexcept;
			integer& operator*=(const utils::uint128_t& b) noexcept;

			utils::uint128_t high;
			utils::uint128_t low;
		};

		void compress() noexcept;
		void modulo_p() noexcept;

		byte block[block_size];
		int length;
		utils::uint128_t r;
		utils::uint128_t s;
		integer acc;
	};
}

#endif