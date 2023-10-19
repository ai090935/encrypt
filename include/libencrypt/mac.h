#ifndef libencrypt_mac_h
#define libencrypt_mac_h
#include"define.h"
#include<memory>

namespace libencrypt
{
	enum class mac_algorithm
	{
		hmac_sha1,
		hmac_sha256,
		hmac_sha512,
		poly1305,
	};

	class mac
	{
	public:
		mac(int key_size, int output_size) noexcept : key_size(key_size), output_size(output_size) {}
		virtual ~mac() {}

		virtual void init(const byte* key) = 0;
		virtual void update(const byte* input, size_t length) = 0;
		virtual void final(byte* output) = 0;

		const int key_size;
		const int output_size;
	};

	std::unique_ptr<mac> make_mac(mac_algorithm algorithm);
}

#endif