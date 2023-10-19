#ifndef crypto_CTR_mode_h
#define crypto_CTR_mode_h
#include"define.h"
#include<algorithm>
#include<utils/bit.h>

//SP 800-38A

namespace crypto::cipher
{
	//counter block is big-endian
	template<typename Cipher>
	class CTR
	{
	public:
		CTR() = delete;

		static constexpr int key_size = Cipher::key_size;
		static constexpr int counter_size = Cipher::block_size;
		static constexpr int block_size = Cipher::block_size;

		class encryption
		{
		public:
			encryption() = default;
			encryption(const byte* key, const byte* counter) noexcept;

			void init(const byte* key, const byte* counter) noexcept;
			void init_key(const byte* key) noexcept;
			void init_counter(const byte* counter) noexcept;
			void encrypt(const byte* in, byte* out) noexcept;

			static constexpr int key_size = CTR<Cipher>::key_size;
			static constexpr int counter_size = CTR<Cipher>::block_size;
			static constexpr int block_size = CTR<Cipher>::block_size;

		private:
			void increment() noexcept;

			typename Cipher::encryption cipher;
			byte counter[block_size];
		};

		class decryption
		{
		public:
			decryption() = default;
			decryption(const byte* key, const byte* counter) noexcept;

			void init(const byte* key, const byte* counter) noexcept;
			void init_key(const byte* key) noexcept;
			void init_counter(const byte* counter) noexcept;
			void decrypt(const byte* in, byte* out) noexcept;

			static constexpr int key_size = CTR<Cipher>::key_size;
			static constexpr int counter_size = CTR<Cipher>::block_size;
			static constexpr int block_size = CTR<Cipher>::block_size;

		private:
			encryption a;
		};
	};
}

//-------------------------------------------------------------------------------------------------

template<typename Cipher>
crypto::cipher::CTR<Cipher>::encryption::encryption(const byte* key, const byte* counter) noexcept
{
	this->init(key, counter);
}

template<typename Cipher>
void crypto::cipher::CTR<Cipher>::encryption::init(const byte* key, const byte* counter) noexcept
{
	this->init_key(key);
	this->init_counter(counter);
}

template<typename Cipher>
void crypto::cipher::CTR<Cipher>::encryption::init_key(const byte* key) noexcept
{
	this->cipher.init(key);
}

template<typename Cipher>
void crypto::cipher::CTR<Cipher>::encryption::init_counter(const byte* counter) noexcept
{
	std::copy(counter, counter + this->block_size, this->counter);
}

template<typename Cipher>
void crypto::cipher::CTR<Cipher>::encryption::encrypt(const byte* in, byte* out) noexcept
{
	this->cipher.encrypt(this->counter, out);
	this->increment();
	utils::memxor(out, in, out, this->block_size);
}

template<typename Cipher>
void crypto::cipher::CTR<Cipher>::encryption::increment() noexcept
{
	this->counter[this->block_size - 1]++;
	for (int i = this->block_size - 1; this->counter[i] == 0 && i > 0; i--)
		this->counter[i - 1]++;
}

template<typename Cipher>
crypto::cipher::CTR<Cipher>::decryption::decryption(const byte* key, const byte* counter) noexcept : a(key, counter) {}

template<typename Cipher>
void crypto::cipher::CTR<Cipher>::decryption::init(const byte* key, const byte* counter) noexcept
{
	this->a.init(key, counter);
}

template<typename Cipher>
void crypto::cipher::CTR<Cipher>::decryption::init_key(const byte* key) noexcept
{
	this->a.init_key(key);
}

template<typename Cipher>
void crypto::cipher::CTR<Cipher>::decryption::init_counter(const byte* counter) noexcept
{
	this->a.init_counter(counter);
}

template<typename Cipher>
void crypto::cipher::CTR<Cipher>::decryption::decrypt(const byte* in, byte* out) noexcept
{
	this->a.encrypt(in, out);
}

#endif