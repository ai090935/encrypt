#ifndef crypto_SHA_h
#define crypto_SHA_h
#include"define.h"
#include<initializer_list>
#include<utils/uint128.h>

//FIPS 180-4

namespace crypto::hash
{
	class SHA1
	{
	public:
		SHA1() noexcept;
		SHA1(const byte* input, size_t length, byte* output) noexcept;

		void update(const byte* input, size_t length) noexcept;
		void final(byte* output) noexcept;

		static constexpr int block_size = 64;
		static constexpr int output_size = 20;

	private:
		typedef uint32_t word;

		void compress() noexcept;

		word H[5];
		byte M[block_size];
		int M_length;
		uint64_t total_length;
	};

	class SHA256
	{
	public:
		SHA256() noexcept;
		SHA256(const byte* input, size_t length, byte* output) noexcept;

		void update(const byte* input, size_t length) noexcept;
		void final(byte* output) noexcept;

		static constexpr int block_size = 64;
		static constexpr int output_size = 32;

	protected:
		typedef uint32_t word;

		SHA256(std::initializer_list<word> H) noexcept;

	private:
		void compress() noexcept;

		word H[8];
		byte M[block_size];
		int M_length;
		uint64_t total_length;
	};

	class SHA224 : public SHA256
	{
	public:
		SHA224() noexcept;
		SHA224(const byte* input, size_t length, byte* output) noexcept;

		void final(byte* output) noexcept;

		static constexpr int output_size = 28;
	};

	class SHA512
	{
	public:
		SHA512() noexcept;
		SHA512(const byte* input, size_t length, byte* output) noexcept;

		void update(const byte* input, size_t length) noexcept;
		void final(byte* output) noexcept;

		static constexpr int block_size = 128;
		static constexpr int output_size = 64;

	protected:
		typedef uint64_t word;

		SHA512(std::initializer_list<word> H) noexcept;

	private:
		void compress() noexcept;

		word H[8];
		byte M[block_size];
		int M_length;
		utils::uint128_t total_length;
	};

	template<int Output_size>
	class derived_from_SHA512 : public SHA512
	{
	public:
		derived_from_SHA512() noexcept;
		derived_from_SHA512(const byte* input, size_t length, byte* output) noexcept;

		void final(byte* output) noexcept;

		static constexpr int output_size = Output_size;
	};

	typedef derived_from_SHA512<48> SHA384;
	typedef derived_from_SHA512<28> SHA512_224;
	typedef derived_from_SHA512<32> SHA512_256;
}

#endif