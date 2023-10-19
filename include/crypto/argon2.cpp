#include"argon2.h"
#include<algorithm>
#include<mutex>
#include<condition_variable>
#include<vector>
#include<tuple>
#include<memory>
#include<future>
#include"blake2.h"
#include<utils/bit.h>

//assuming mutex and condition_variable don't throw exceptions

using namespace crypto;
using crypto::KDF::argon2_input;
using crypto::KDF::argon2_option;
using utils::endian;
using utils::byte_to_word;
using utils::word_to_byte;

namespace
{
	template<typename T>
	class matrix
	{
	public:
		matrix(size_t row, size_t col) : col(col), data(new T[row * col]) {}

		T* operator[](size_t row) noexcept
		{
			return this->data.get() + row * this->col;
		}

	private:
		size_t col;
		std::unique_ptr<T[]> data;
	};

	class barrier
	{
	public:
		barrier(size_t expected) : arrive_count(0), expected(expected), phase(0) {}
		barrier(const barrier&) = delete;
		barrier& operator=(const barrier&) = delete;

		void arrive_and_wait() noexcept
		{
			std::unique_lock lock(this->mutex);
			this->arrive_count++;

			if (this->arrive_count < this->expected)
				this->condition_variable.wait(lock, [current_phase = this->phase, this]() { return current_phase != this->phase; });
			else
			{
				this->arrive_count = 0;
				this->phase++;

				lock.unlock();
				this->condition_variable.notify_all();
			}
		}

	private:
		size_t arrive_count;
		size_t expected;
		size_t phase;
		std::mutex mutex;
		std::condition_variable condition_variable;
	};

	//-------------------------------------------------------------------------------------------------

	enum class argon2_type
	{
		argon2d = 0,
		argon2i = 1,
		argon2id = 2,
	};

	class argon2_block
	{
	public:
		argon2_block() = default;

		argon2_block& operator^=(const argon2_block& other) noexcept
		{
			utils::memxor(this->data, this->data, other.data, sizeof(this->data));
			return *this;
		}

		uint64_t data[128];
	};

	argon2_block operator^(const argon2_block& a, const argon2_block& b) noexcept
	{
		return argon2_block(a) ^= b;
	}

	static_assert(sizeof(argon2_block) == 1024);

	class argon2_instance
	{
	public:
		argon2_instance(argon2_option option, argon2_type type) noexcept : passes(option.time_cost), memory_size(option.memory_cost), lanes(option.parallelism), memory_blocks(4 * lanes * (memory_size / (4 * lanes))), lane_length(memory_blocks / lanes), segment_length(lane_length / 4), type(type) {}

		const uint32_t passes;
		const uint32_t memory_size;
		const uint32_t lanes;

		const uint32_t memory_blocks;
		const uint32_t lane_length;
		const uint32_t segment_length;

		const argon2_type type;
	};

	class argon2_position
	{
	public:
		argon2_position(uint32_t pass, uint32_t lane, int slice) noexcept : pass(pass), lane(lane), slice(slice) {}

		const uint32_t pass;
		const uint32_t lane;
		const int slice;
	};

	//-------------------------------------------------------------------------------------------------

	//rfc 3.3
	void H_prime(const byte* in, uint32_t len, byte* out, uint32_t outlen) noexcept
	{
		byte temp[4];
		crypto::hash::blake2b h(outlen <= 64 ? outlen : 64);

		word_to_byte<endian::little>(outlen, temp);
		h.update(temp, 4);
		h.update(in, len);
		h.final(out);

		if (outlen > 64)
		{
			byte v[64];
			const uint32_t r = outlen / 32 + static_cast<bool>(outlen % 32) - 2;

			std::copy(out, out + 64, v);
			for (uint32_t i = 1; i < r; i++)
			{
				crypto::hash::blake2b(v, 64, v);
				std::copy(v, v + 32, out + i * 32);
			}
			crypto::hash::blake2b(v, 64, out + r * 32, outlen - 32 * r);
		}
	}

	//rfc 3.6
	void GB(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d) noexcept
	{
		a = a + b + 2 * utils::low_bits<32>(a) * utils::low_bits<32>(b);
		d = utils::rotr(static_cast<uint64_t>(d ^ a), 32);
		c = c + d + 2 * utils::low_bits<32>(c) * utils::low_bits<32>(d);
		b = utils::rotr(static_cast<uint64_t>(b ^ c), 24);

		a = a + b + 2 * utils::low_bits<32>(a) * utils::low_bits<32>(b);
		d = utils::rotr(static_cast<uint64_t>(d ^ a), 16);
		c = c + d + 2 * utils::low_bits<32>(c) * utils::low_bits<32>(d);
		b = utils::rotr(static_cast<uint64_t>(b ^ c), 63);
	}

	//rfc 3.6
	void P(uint64_t* s0, uint64_t* s1, uint64_t* s2, uint64_t* s3, uint64_t* s4, uint64_t* s5, uint64_t* s6, uint64_t* s7) noexcept
	{
		GB(s0[0], s2[0], s4[0], s6[0]);
		GB(s0[1], s2[1], s4[1], s6[1]);
		GB(s1[0], s3[0], s5[0], s7[0]);
		GB(s1[1], s3[1], s5[1], s7[1]);

		GB(s0[0], s2[1], s5[0], s7[1]);
		GB(s0[1], s3[0], s5[1], s6[0]);
		GB(s1[0], s3[1], s4[0], s6[1]);
		GB(s1[1], s2[0], s4[1], s7[0]);
	}

	//rfc 3.5
	argon2_block G(const argon2_block& x, const argon2_block& y) noexcept
	{
		const argon2_block r = x ^ y;

		argon2_block z = r;
		for (int i = 0; i < 8; i++)
		{
			uint64_t* row = z.data + i * 16;
			P(row + 0, row + 2, row + 4, row + 6, row + 8, row + 10, row + 12, row + 14);
		}
		for (int i = 0; i < 8; i++)
		{
			uint64_t* col = z.data + i * 2;
			P(0 * 16 + col, 1 * 16 + col, 2 * 16 + col, 3 * 16 + col, 4 * 16 + col, 5 * 16 + col, 6 * 16 + col, 7 * 16 + col);
		}

		return z ^ r;
	}

	//-------------------------------------------------------------------------------------------------

	//rfc 3.4.2
	std::tuple<uint32_t, uint32_t> mapping_index(uint32_t j1, uint32_t j2, argon2_instance instance, argon2_position position, uint32_t index) noexcept
	{
		const uint32_t l = (position.pass == 0 && position.slice == 0) ? position.lane : j2 % instance.lanes;

		const uint32_t finished_blocks = (position.pass == 0 ? position.slice : 3) * instance.segment_length;
		const uint32_t w = l == position.lane ? finished_blocks + index - 1 : finished_blocks - (index == 0 ? 1 : 0);

		const uint64_t x = (static_cast<uint64_t>(j1) * static_cast<uint64_t>(j1)) >> 32;
		const uint64_t y = (w * x) >> 32;
		const uint64_t zz = w - 1 - y;

		const uint32_t start_position = (position.pass == 0 || position.slice == 3) ? 0 : (position.slice + 1) * instance.segment_length;
		const uint32_t z = (start_position + zz) % instance.lane_length;

		return { l, z };
	}

	//rfc 3.4.1.1
	auto compute_argon2d_index(const argon2_block& block, argon2_instance instance, argon2_position position, uint32_t index) noexcept
	{
		uint32_t j1 = utils::low_bits<32>(block.data[0]);
		uint32_t j2 = utils::high_bits<32>(block.data[0]);
		return mapping_index(j1, j2, instance, position, index);
	}

	//rfc 3.4.1.2
	auto compute_argon2i_index(const argon2_block& block, argon2_instance instance, argon2_position position, uint32_t index) noexcept
	{
		uint32_t j1 = utils::low_bits<32>(block.data[index % 128]);
		uint32_t j2 = utils::high_bits<32>(block.data[index % 128]);
		return mapping_index(j1, j2, instance, position, index);
	}

	void init_argon2i_input_block(argon2_block& input_block, argon2_instance instance, argon2_position position) noexcept
	{
		input_block.data[0] = position.pass;
		input_block.data[1] = position.lane;
		input_block.data[2] = position.slice;
		input_block.data[3] = instance.memory_blocks;
		input_block.data[4] = instance.passes;
		input_block.data[5] = static_cast<uint64_t>(instance.type);
		std::fill(input_block.data + 6, input_block.data + 128, 0);
	}

	void compute_argon2i_index_block(argon2_block& input_block, argon2_block& index_block) noexcept
	{
		constexpr argon2_block zero_block = {};

		input_block.data[6]++;
		index_block = G(zero_block, G(zero_block, input_block));
	}

	void compute_segment(matrix<argon2_block>& B, argon2_instance instance, argon2_position position) noexcept
	{
		argon2_block input_block, index_block;
		const bool is_argon2i_index = (instance.type == argon2_type::argon2i) || (instance.type == argon2_type::argon2id && position.pass == 0 && position.slice < 2);

		if (is_argon2i_index)
		{
			init_argon2i_input_block(input_block, instance, position);
			compute_argon2i_index_block(input_block, index_block);
		}

		for (uint32_t index = (position.pass == 0 && position.slice == 0 ? 2 : 0); index < instance.segment_length; index++)
		{
			const uint32_t absolute_index = instance.segment_length * position.slice + index;
			argon2_block& curr = B[position.lane][absolute_index];
			argon2_block& prev = B[position.lane][absolute_index != 0 ? absolute_index - 1 : instance.lane_length - 1];

			if (is_argon2i_index && index % 128 == 0 && index != 0)
				compute_argon2i_index_block(input_block, index_block);

			auto [l, z] = is_argon2i_index ? compute_argon2i_index(index_block, instance, position, index) : compute_argon2d_index(prev, instance, position, index);
			const argon2_block& ref = B[l][z];

			if (position.pass == 0)
				curr = G(prev, ref);
			else
				curr ^= G(prev, ref);
		}
	}

	//-------------------------------------------------------------------------------------------------

	//rfc 3.2.1
	void compute_H0(argon2_input input, argon2_option option, array output, argon2_type type, byte* H0) noexcept
	{
		crypto::hash::blake2b h;
		byte temp[sizeof(uint32_t)];

		word_to_byte<endian::little>(option.parallelism, temp);
		h.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(static_cast<uint32_t>(output.length), temp);
		h.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(option.memory_cost, temp);
		h.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(option.time_cost, temp);
		h.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(static_cast<uint32_t>(0x13), temp);
		h.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(static_cast<uint32_t>(type), temp);
		h.update(temp, sizeof(uint32_t));

		word_to_byte<endian::little>(static_cast<uint32_t>(input.password.length), temp);
		h.update(temp, sizeof(uint32_t));

		h.update(input.password.data, input.password.length);

		word_to_byte<endian::little>(static_cast<uint32_t>(input.salt.length), temp);
		h.update(temp, sizeof(uint32_t));

		h.update(input.salt.data, input.salt.length);

		word_to_byte<endian::little>(static_cast<uint32_t>(input.secret.length), temp);
		h.update(temp, sizeof(uint32_t));

		h.update(input.secret.data, input.secret.length);

		word_to_byte<endian::little>(static_cast<uint32_t>(input.associated_data.length), temp);
		h.update(temp, sizeof(uint32_t));

		h.update(input.associated_data.data, input.associated_data.length);

		h.final(H0);
	}

	//rfc 3.2.1 ~ 3.2.4
	void init(matrix<argon2_block>& B, argon2_input input, argon2_option option, array output, argon2_type type) noexcept
	{
		byte in[72], out[1024];

		compute_H0(input, option, output, type, in);
		std::fill(in + 64, in + 68, 0);
		for (uint32_t i = 0; i < option.parallelism; i++)
		{
			word_to_byte<endian::little>(i, in + 68);
			H_prime(in, 72, out, 1024);
			for (size_t j = 0; j < 128; j++)
				B[i][0].data[j] = byte_to_word<endian::little, uint64_t>(out + j * sizeof(uint64_t));
		}

		in[64]++;
		for (uint32_t i = 0; i < option.parallelism; i++)
		{
			word_to_byte<endian::little>(i, in + 68);
			H_prime(in, 72, out, 1024);
			for (size_t j = 0; j < 128; j++)
				B[i][1].data[j] = byte_to_word<endian::little, uint64_t>(out + j * sizeof(uint64_t));
		}
	}

	//rfc 3.2.5 ~ 3.2.6
	void iterator(matrix<argon2_block>& B, argon2_instance instance)
	{
		bool stop = true;
		std::mutex mutex;
		barrier sync_point(instance.lanes);
		std::vector<std::future<void>> vec(instance.lanes);

		auto f = [&](uint32_t lane)
		{
			mutex.lock();
			mutex.unlock();
			if (stop)
				return;

			for (uint32_t pass = 0; pass < instance.passes; pass++)
				for (int slice = 0; slice < 4; slice++)
				{
					compute_segment(B, instance, argon2_position(pass, lane, slice));
					sync_point.arrive_and_wait();
				}
		};

		try
		{
			mutex.lock();
			for (uint32_t lane = 0; lane < instance.lanes; lane++)
				vec[lane] = std::async(std::launch::async, f, lane);
		}
		catch (...)
		{
			mutex.unlock();
			for (const auto& i : vec)
				if (i.valid())
					i.wait();
			throw;
		}

		stop = false;
		mutex.unlock();
		for (const auto& i : vec)
			i.wait();
	}

	//rfc 3.2.7
	void final(matrix<argon2_block>& B, uint32_t row, uint32_t col, array output) noexcept
	{
		argon2_block& C = B[0][col - 1];
		for (uint32_t i = 1; i < row; i++)
			C ^= B[i][col - 1];

		byte temp[1024];
		for (size_t i = 0; i < 128; i++)
			word_to_byte<endian::little>(C.data[i], temp + i * sizeof(uint64_t));
		H_prime(temp, 1024, output.data, output.length);
	}

	void argon2(argon2_input input, argon2_option option, array output, argon2_type type)
	{
		argon2_instance instance(option, type);
		matrix<argon2_block> B(instance.lanes, instance.lane_length);

		init(B, input, option, output, type);
		iterator(B, instance);
		final(B, instance.lanes, instance.lane_length, output);
	}
}

//-------------------------------------------------------------------------------------------------

void crypto::KDF::argon2i(argon2_input input, argon2_option option, array output)
{
	argon2(input, option, output, argon2_type::argon2i);
}

void crypto::KDF::argon2d(argon2_input input, argon2_option option, array output)
{
	argon2(input, option, output, argon2_type::argon2d);
}

void crypto::KDF::argon2id(argon2_input input, argon2_option option, array output)
{
	argon2(input, option, output, argon2_type::argon2id);
}