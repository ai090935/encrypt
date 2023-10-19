#ifndef crypto_chacha20_h
#define crypto_chacha20_h
#include"define.h"

//RFC 8439, but 64-bit initial counter, 64-bit nonce
//counter is little-endian

namespace crypto::cipher
{
	class chacha20
	{
	public:
		chacha20() = delete;

		static constexpr int key_size = 32;
		static constexpr int counter_size = 8;
		static constexpr int nonce_size = 8;
		static constexpr int block_size = 64;

		class encryption
		{
		public:
			encryption() noexcept;
			encryption(const byte* key, const byte* counter, const byte* nonce) noexcept;

			void init(const byte* key, const byte* counter, const byte* nonce) noexcept;
			void init_key(const byte* key) noexcept;
			void init_counter(const byte* counter) noexcept;
			void init_nonce(const byte* nonce) noexcept;
			void encrypt(const byte* in, byte* out) noexcept;

			static constexpr int key_size = chacha20::key_size;
			static constexpr int counter_size = chacha20::counter_size;
			static constexpr int nonce_size = chacha20::nonce_size;
			static constexpr int block_size = chacha20::block_size;

		private:
			uint32_t state[16];
		};

		class decryption
		{
		public:
			decryption() noexcept;
			decryption(const byte* key, const byte* counter, const byte* nonce) noexcept;

			void init(const byte* key, const byte* counter, const byte* nonce) noexcept;
			void init_key(const byte* key) noexcept;
			void init_counter(const byte* counter) noexcept;
			void init_nonce(const byte* nonce) noexcept;
			void decrypt(const byte* in, byte* out) noexcept;

			static constexpr int key_size = chacha20::key_size;
			static constexpr int counter_size = chacha20::counter_size;
			static constexpr int nonce_size = chacha20::nonce_size;
			static constexpr int block_size = chacha20::block_size;

		private:
			encryption a;
		};
	};
}

#endif