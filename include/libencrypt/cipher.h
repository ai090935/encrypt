#ifndef libencrypt_cipher_h
#define libencrypt_cipher_h
#include"define.h"
#include<memory>

namespace libencrypt
{
	enum class cipher_algorithm
	{
		aes_128_ctr,
		aes_192_ctr,
		aes_256_ctr,
		chacha20,
	};

	class cipher
	{
	public:
		cipher(int key_size, int block_size) noexcept : key_size(key_size), block_size(block_size) {}
		virtual ~cipher() {}

		virtual void init(const byte* key) = 0;
		virtual void set_counter(uint64_t offset) = 0;
		virtual void encrypt(const byte* in, byte* out, size_t count) = 0;
		virtual std::unique_ptr<cipher> copy() const = 0;

		const int key_size;
		const int block_size;
	};

	std::unique_ptr<cipher> make_cipher(cipher_algorithm algorithm);
}

#endif