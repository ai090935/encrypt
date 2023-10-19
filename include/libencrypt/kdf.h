#ifndef libencrypt_kdf_h
#define libencrypt_kdf_h
#include"define.h"

namespace libencrypt
{
	enum class kdf_algorithm
	{
		argon2i,
		argon2d,
		argon2id,
	};

	struct kdf_parameter
	{
		kdf_parameter(const_array password, const_array salt, const_array key) noexcept : password(password), salt(salt), key(key) {}
		virtual ~kdf_parameter() {}

		const_array password;
		const_array salt;
		const_array key;
	};

	struct argon2_parameter : public kdf_parameter
	{
		argon2_parameter(const_array password, const_array salt, const_array key, uint32_t time_cost, uint32_t memory_cost, uint32_t parallelism) noexcept : kdf_parameter(password, salt, key), time_cost(time_cost), memory_cost(memory_cost), parallelism(parallelism) {}

		uint32_t time_cost;
		uint32_t memory_cost;
		uint32_t parallelism;
	};

	void kdf(kdf_algorithm algorithm, const kdf_parameter& parameter, array output);
}

#endif