#include"encrypt.h"
#include<algorithm>
#include<cstdio>
#include<random>
#include<memory>
#include<future>
#include<atomic>
#include<mutex>
#include<condition_variable>
#include<exception>
#include<stdexcept>
#include<cstring>

//assuming mutex and condition_variable don't throw exceptions
//encrypt format = [salt] || ciphertext || mac

using namespace libencrypt;

namespace
{
	class scoped_condition_variable
	{
	public:
		template<typename Predicate>
		scoped_condition_variable(std::mutex& mutex, std::condition_variable& condition_variable, Predicate&& stop_waiting) : lock(mutex), condition_variable(condition_variable)
		{
			this->condition_variable.wait(this->lock, stop_waiting);
		}

		~scoped_condition_variable()
		{
			this->lock.unlock();
			this->condition_variable.notify_all();
		}

	private:
		std::unique_lock<std::mutex> lock;
		std::condition_variable& condition_variable;
	};

	//-------------------------------------------------------------------------------------------------

	class input_management
	{
	public:
		input_management(std::FILE* input) noexcept : input(input), good(true), position(0) {}

		size_t raw_read(byte* data, size_t count)
		{
			if (!this->good)
				return 0;

			size_t read_size = std::fread(data, sizeof(byte), count, this->input);
			if (std::ferror(this->input))
			{
				this->good = false;
				throw std::runtime_error("libencrypt::input_management::raw_read error");
			}

			return read_size;
		}

		size_t read(byte* data, size_t count)
		{
			if (!this->good)
				return 0;

			try
			{
				this->buf = this->reserve;
				this->buf.resize(this->reserve.size() + count);
				size_t read_size = this->raw_read(this->buf.data() + this->reserve.size(), count);
				std::copy(this->buf.data(), this->buf.data() + read_size, data);
				std::copy(this->buf.data() + read_size, this->buf.data() + read_size + this->reserve.size(), this->reserve.data());
				return read_size;
			}
			catch (...)
			{
				this->good = false;
				throw;
			}
		}

		size_t sync_read(byte* data, uint64_t& position)
		{
			std::scoped_lock lock(this->mutex);
			size_t read_size = this->read(data, this->max_read_size);
			position = this->position;
			this->position += read_size;
			return read_size;
		}

		void init_reserve(size_t reserve_size)
		{
			this->reserve.resize(reserve_size);
			this->raw_read(this->reserve.data(), reserve_size);
			if (std::feof(this->input))
				throw std::runtime_error("libencrypt::input_management::init_reserve error");
		}

		const byte* read_reserve() noexcept
		{
			return this->reserve.data();
		}

		static constexpr int max_read_size = 1 << 20;

	private:
		std::FILE* input;
		bool good;
		uint64_t position;
		std::mutex mutex;
		std::vector<byte> reserve;
		std::vector<byte> buf;
	};

	class output_management
	{
	public:
		output_management(std::FILE* output) noexcept : output(output), position(0) {}

		bool write(const byte* data, size_t count)
		{
			if (std::ferror(this->output))
				return false;

			std::fwrite(data, sizeof(byte), count, this->output);
			if (std::ferror(this->output))
				throw std::runtime_error("libencrypt::output_management::write error");

			return true;
		}

		bool sync_write(const byte* data, size_t count, uint64_t position)
		{
			scoped_condition_variable cv(this->mutex, this->condition_variable, [&]() { return this->position == position || std::ferror(this->output); });
			if (!this->write(data, count))
				return false;

			this->position += count;
			return true;
		}

	private:
		std::FILE* output;
		uint64_t position;
		std::mutex mutex;
		std::condition_variable condition_variable;
	};

	class cipher_management
	{
	private:
		static std::vector<std::unique_ptr<cipher>> get_ciphers(const std::vector<cipher_algorithm>& cipher_list)
		{
			std::vector<std::unique_ptr<cipher>> ciphers;
			for (const auto& i : cipher_list)
				ciphers.push_back(make_cipher(i));
			return ciphers;
		}

		int get_key_size() const noexcept
		{
			int result = 0;
			for (const auto& i : this->ciphers)
				result += i->key_size;
			return result;
		}

		std::vector<std::unique_ptr<cipher>> ciphers;
		std::vector<byte> buf;

	public:
		cipher_management(const std::vector<cipher_algorithm>& cipher_list) : ciphers(this->get_ciphers(cipher_list)), key_size(this->get_key_size()) {}

		cipher_management(const cipher_management& other) : buf(), key_size(other.key_size)
		{
			for (const auto& i : other.ciphers)
				this->ciphers.push_back(i->copy());
		}

		void init(const byte* key)
		{
			for (auto& i : this->ciphers)
			{
				i->init(key);
				key += i->key_size;
			}
		}

		//assert(position % i->block_size == 0)
		void encrypt(byte* data, size_t length, uint64_t position)
		{
			for (auto& i : this->ciphers)
			{
				i->set_counter(position / i->block_size);
				this->buf.resize((length / i->block_size + static_cast<bool>(length % i->block_size)) * i->block_size);
				i->encrypt(data, this->buf.data(), length / i->block_size + static_cast<bool>(length % i->block_size));
				std::copy(this->buf.data(), this->buf.data() + length, data);
			}
		}

		const int key_size;
	};

	class mac_management
	{
	private:
		static std::vector<std::unique_ptr<mac>> get_macs(const std::vector<mac_algorithm>& mac_list)
		{
			std::vector<std::unique_ptr<mac>> macs;
			for (const auto& i : mac_list)
				macs.push_back(make_mac(i));
			return macs;
		}

		int get_key_size() const noexcept
		{
			int result = 0;
			for (const auto& i : this->macs)
				result += i->key_size;
			return result;
		}

		int get_output_size() const noexcept
		{
			int result = 0;
			for (const auto& i : this->macs)
				result += i->output_size;
			return result;
		}

		std::vector<std::unique_ptr<mac>> macs;
		bool good;
		uint64_t position;
		std::mutex mutex;
		std::condition_variable condition_variable;

	public:
		mac_management(const std::vector<mac_algorithm>& mac_list) : macs(this->get_macs(mac_list)), good(true), position(0), key_size(this->get_key_size()), output_size(this->get_output_size()) {}

		void init(const byte* key)
		{
			for (auto& i : this->macs)
			{
				i->init(key);
				key += i->key_size;
			}
		}

		bool sync_update(const byte* data, size_t length, uint64_t position)
		{
			scoped_condition_variable cv(this->mutex, this->condition_variable, [&]() { return this->position == position || !this->good; });
			if (!this->good)
				return false;

			try
			{
				for (auto& i : this->macs)
					i->update(data, length);
			}
			catch (...)
			{
				this->good = false;
				throw;
			}

			this->position += length;
			return true;
		}

		void final(byte* output)
		{
			for (auto& i : this->macs)
			{
				i->final(output);
				output += i->output_size;
			}
		}

		const int key_size;
		const int output_size;
	};

	//-------------------------------------------------------------------------------------------------

	constexpr int default_salt_len = 32;

	void init_cipher_and_mac(kdf_algorithm algorithm, const kdf_parameter& parameter, cipher_management& ciphers, mac_management& macs)
	{
		std::vector<byte> key(ciphers.key_size + macs.key_size);
		kdf(algorithm, parameter, { key.data(), key.size() });
		ciphers.init(key.data());
		macs.init(key.data() + ciphers.key_size);
	}

	template<typename F, typename... Args>
	void thread_run(int threads, F&& f, Args&&... args)
	{
		std::atomic_bool good = true;
		auto g = [&]()
		{
			try
			{
				f(args..., good);
			}
			catch (...)
			{
				good = false;
				throw;
			}
		};

		std::vector<std::future<void>> vec(threads);
		try
		{
			for (auto& i : vec)
				i = std::async(std::launch::async, g);
		}
		catch (...)
		{
			good = false;
			for (const auto& i : vec)
				if (i.valid())
					i.wait();
			throw;
		}

		for (const auto& i : vec)
			i.wait();
		for (auto& i : vec)
			i.get();
	}

	template<typename F, typename G>
	void try_catch(F&& f, G&& g)
	{
		try
		{
			f();
		}
		catch (...)
		{
			g();
		}
	}

	void random_byte(byte* output, std::size_t length)
	{
		std::random_device rd;
		using result_type = std::random_device::result_type;

		while (length)
		{
			std::size_t outlen = (length < sizeof(result_type) ? length : sizeof(result_type));
			result_type temp = rd();

			std::memcpy(output, &temp, outlen);
			output += outlen;
			length -= outlen;
		}
	}

	//-------------------------------------------------------------------------------------------------

	void write_salt(output_management& out, kdf_parameter& parameter, byte* default_salt)
	{
		if (parameter.salt.data)
			return;

		random_byte(default_salt, default_salt_len);
		out.write(default_salt, default_salt_len);
		parameter.salt = { default_salt, default_salt_len };
	}

	void encrypt_core(input_management& in, output_management& out, cipher_management ciphers, mac_management& macs, const std::atomic_bool& good)
	{
		std::vector<byte> buf(input_management::max_read_size);

		uint64_t read_size, position;
		std::exception_ptr ptr;
		auto g = [&]() { ptr = std::current_exception(); };
		while (good)
		{
			read_size = in.sync_read(buf.data(), position);
			if (!read_size)
				break;

			try_catch([&]() { ciphers.encrypt(buf.data(), read_size, position); }, g);
			try_catch([&]() { macs.sync_update(buf.data(), read_size, position); }, g);

			if (!out.sync_write(buf.data(), read_size, position))
				break;

			if (ptr)
				std::rethrow_exception(ptr);
		}
	}

	void write_mac(output_management& out, mac_management& macs)
	{
		std::vector<byte> buf(macs.output_size);
		macs.final(buf.data());
		out.write(buf.data(), buf.size());
	}

	//-------------------------------------------------------------------------------------------------

	void read_salt(input_management& in, kdf_parameter& parameter, byte* default_salt)
	{
		if (parameter.salt.data)
			return;

		if (in.read(default_salt, default_salt_len) != default_salt_len)
			throw std::runtime_error("libencrypt::read_salt error");
		parameter.salt = { default_salt, default_salt_len };
	}

	void decrypt_core(input_management& in, output_management& out, cipher_management ciphers, mac_management& macs, const std::atomic_bool& good)
	{
		std::vector<byte> buf(input_management::max_read_size);

		uint64_t read_size, position;
		std::exception_ptr ptr;
		auto g = [&]() { ptr = std::current_exception(); };
		while (good)
		{
			read_size = in.sync_read(buf.data(), position);
			if (!read_size)
				break;

			try_catch([&]() { macs.sync_update(buf.data(), read_size, position); }, g);
			try_catch([&]() { ciphers.encrypt(buf.data(), read_size, position); }, g);

			if (!out.sync_write(buf.data(), read_size, position))
				break;

			if (ptr)
				std::rethrow_exception(ptr);
		}
	}

	void read_mac(input_management& in, mac_management& macs)
	{
		std::vector<byte> buf(macs.output_size);
		macs.final(buf.data());
		if (!std::equal(buf.begin(), buf.end(), in.read_reserve()))
			throw std::runtime_error("libencrypt::read_mac MAC verify failure");
	}
}

//-------------------------------------------------------------------------------------------------

void libencrypt::encrypt(std::FILE* input, std::FILE* output, kdf_algorithm algorithm, kdf_parameter& parameter, const std::vector<cipher_algorithm>& cipher_list, const std::vector<mac_algorithm>& mac_list, int threads)
{
	if (cipher_list.size() == 0 || cipher_list.size() > 2 || mac_list.size() == 0 || mac_list.size() > 2)
		throw std::runtime_error("libencrypt::encrypt error algorithm list");
	if (threads <= 0)
		throw std::runtime_error("libencrypt::encrypt number of threads must be greater than zero");

	input_management in(input);
	output_management out(output);
	cipher_management ciphers(cipher_list);
	mac_management macs(mac_list);

	byte default_salt[default_salt_len];
	write_salt(out, parameter, default_salt);
	init_cipher_and_mac(algorithm, parameter, ciphers, macs);
	thread_run(threads, encrypt_core, in, out, ciphers, macs);
	write_mac(out, macs);
}

void libencrypt::decrypt(std::FILE* input, std::FILE* output, kdf_algorithm algorithm, kdf_parameter& parameter, const std::vector<cipher_algorithm>& cipher_list, const std::vector<mac_algorithm>& mac_list, int threads)
{
	if (cipher_list.size() == 0 || cipher_list.size() > 2 || mac_list.size() == 0 || mac_list.size() > 2)
		throw std::runtime_error("libencrypt::decrypt error algorithm list");
	if (threads <= 0)
		throw std::runtime_error("libencrypt::decrypt number of threads must be greater than zero");

	input_management in(input);
	output_management out(output);
	cipher_management ciphers(cipher_list);
	mac_management macs(mac_list);
	in.init_reserve(macs.output_size);

	byte default_salt[default_salt_len];
	read_salt(in, parameter, default_salt);
	init_cipher_and_mac(algorithm, parameter, ciphers, macs);
	thread_run(threads, decrypt_core, in, out, ciphers, macs);
	read_mac(in, macs);
}