#ifndef crypto_AES_h
#define crypto_AES_h
#include"define.h"

//FIPS 197

namespace crypto::cipher
{
	template<int Nk, int Nb, int Nr>
	class AES
	{
	public:
		AES() = delete;

		static constexpr int key_size = 4 * Nk;
		static constexpr int block_size = 4 * Nb;

		class encryption
		{
		public:
			encryption() = default;
			encryption(const byte* key) noexcept;

			void init(const byte* key) noexcept;
			void encrypt(const byte* in, byte* out) noexcept;

			static constexpr int key_size = AES<Nk, Nb, Nr>::key_size;
			static constexpr int block_size = AES<Nk, Nb, Nr>::block_size;

		private:
			byte w[4 * Nb * (Nr + 1)];
		};

		class decryption
		{
		public:
			decryption() = default;
			decryption(const byte* key) noexcept;

			void init(const byte* key) noexcept;
			void decrypt(const byte* in, byte* out) noexcept;

			static constexpr int key_size = AES<Nk, Nb, Nr>::key_size;
			static constexpr int block_size = AES<Nk, Nb, Nr>::block_size;

		private:
			byte w[4 * Nb * (Nr + 1)];
		};
	};

	typedef AES<4, 4, 10> AES_128;
	typedef AES<6, 4, 12> AES_192;
	typedef AES<8, 4, 14> AES_256;
}

#endif