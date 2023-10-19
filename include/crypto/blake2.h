#ifndef crypto_blake2_h
#define crypto_blake2_h
#include"define.h"
#include<utils/uint128.h>

//RFC 7693

namespace crypto::MAC
{
	//0 <= keylen <= 64, 1 <= output_size <= 64
	class blake2b
	{
	public:
		blake2b(int output_size = 64) noexcept;
		blake2b(const byte* key, int keylen, int output_size = 64) noexcept;
		blake2b(const byte* key, int keylen, const byte* input, size_t length, byte* output, int output_size = 64) noexcept;

		void init(const byte* key, int keylen) noexcept;
		void update(const byte* input, size_t length) noexcept;
		void final(byte* output) noexcept;

		static constexpr int block_size = 128;

	private:
		typedef uint64_t word;

		word h[8];
		byte b[block_size];
		int b_length;
		int output_size;
		utils::uint128_t total_length;
	};

	//0 <= keylen <= 32, 1 <= output_size <= 32
	class blake2s
	{
	public:
		blake2s(int output_size = 32) noexcept;
		blake2s(const byte* key, int keylen, int output_size = 32) noexcept;
		blake2s(const byte* key, int keylen, const byte* input, size_t length, byte* output, int output_size = 32) noexcept;

		void init(const byte* key, int keylen) noexcept;
		void update(const byte* input, size_t length) noexcept;
		void final(byte* output) noexcept;

		static constexpr int block_size = 64;

	private:
		typedef uint32_t word;

		word h[8];
		byte b[block_size];
		int b_length;
		int output_size;
		uint64_t total_length;
	};
}

namespace crypto::hash
{
	class blake2b : public MAC::blake2b
	{
	public:
		blake2b(int output_size = 64) noexcept;
		blake2b(const byte* input, size_t length, byte* output, int output_size = 64) noexcept;
	};

	class blake2s : public MAC::blake2s
	{
	public:
		blake2s(int output_size = 32) noexcept;
		blake2s(const byte* input, size_t length, byte* output, int output_size = 32) noexcept;
	};
}

#endif