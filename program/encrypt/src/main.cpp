#include<iostream>
#include<fstream>
#include<cstdio>
#include<vector>
#include<string>
#include<tuple>
#include<memory>
#include<cstdlib>
#include<charconv>
#include<iterator>
#include<filesystem>
#include<exception>
#include<stdexcept>
#include<libencrypt/encrypt.h>

constexpr auto help =
R"(
NAME
	encrypt - encrypt utility

SYNOPSIS
	encrypt -e [-k kdf][-c cipher][-m mac][-p password][-s key][-t threads][-i file][-o file]
	encrypt -d [-k kdf][-c cipher][-m mac][-p password][-s key][-t threads][-i file][-o file]
	encrypt -h

OPTIONS
	-e
		Encrypt file.
	-d
		Decrypt file.
	-h
		Show help.

	-k kdf
		Specifies the KDF algorithm.

		The supported KDFs are:
			argon2i,<time cost>,<memory cost>,<parallelism>
			argon2d,<time cost>,<memory cost>,<parallelism>
			argon2id,<time cost>,<memory cost>,<parallelism>

		The default is "argon2id,1,2097152,4".
	-c cipher
		Specifies the cipher algorithm, multiple ciphers must be comma-separated.

		The supported ciphers are:
			aes-128-ctr
			aes-192-ctr
			aes-256-ctr
			chacha20

		The default is "chacha20".
	-m mac
		Specifies the MAC algorithm, multiple MACs must be comma-separated.

		The supported MACs are:
			hmac-sha1
			hmac-sha256
			hmac-sha512
			poly1305

		The default is "poly1305".
	-p password
		Password file path, the default password is empty.
	-s key
		Secret key file path, the default secret key is empty.
	-t threads
		Number of threads, the default is 4.

	-i input
		Input file path, the default is stdin.
	-o output
		Output file path, the default is stdout.

NOTES
	Do not use pipeline when decrypting. This is due to having to begin streaming output before the authentication tag could be validated.
	assert(input size < 2^64 byte)

EXAMPLES
	Encrypt and decrypt file. The password is in the password.txt:
		encrypt -e -i plaintext.txt -o ciphertext.txt -p password.txt
		encrypt -d -i ciphertext.txt -o plaintext.txt -p password.txt
)";

namespace
{
	enum class command
	{
		encrypt,
		decrypt,
		help,
	};

	struct option
	{
		option() : cmd(command::help), input(nullptr), output(nullptr), algorithm(libencrypt::kdf_algorithm::argon2id), time_cost(1), memory_cost(1 << 21), parallelism(4), cipher_list{ libencrypt::cipher_algorithm::chacha20 }, mac_list{ libencrypt::mac_algorithm::poly1305 }, threads(4) {}
		option(option&&) = default;

		~option()
		{
			if (this->input && this->input != stdin)
				std::fclose(this->input);
			if (this->output && this->output != stdout)
				std::fclose(this->output);
		}

		command cmd;
		std::FILE* input;
		std::FILE* output;
		std::unique_ptr<libencrypt::kdf_parameter> parameter;
		libencrypt::kdf_algorithm algorithm;
		std::vector<char> password;
		std::vector<char> key;
		libencrypt::uint32_t time_cost;
		libencrypt::uint32_t memory_cost;
		libencrypt::uint32_t parallelism;
		std::vector<libencrypt::cipher_algorithm> cipher_list;
		std::vector<libencrypt::mac_algorithm> mac_list;
		int threads;
	};

	//-------------------------------------------------------------------------------------------------

	std::vector<char> read_file(const std::filesystem::path& path)
	{
		std::ifstream ifs;
		ifs.exceptions(std::ifstream::failbit | std::ifstream::badbit);
		ifs.open(path, std::ios::in | std::ios::binary);
		return std::vector<char>(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
	}

	template<int count = 1>
	auto split(const std::string& str, const std::string& delimiter = " ")
	{
		auto pos = str.find(delimiter);
		auto pair = (pos == std::string::npos) ? std::make_tuple(str, std::string()) : std::make_tuple(str.substr(0, pos), str.substr(pos + 1));
		if constexpr (count == 1)
			return pair;
		else
			return std::tuple_cat(std::make_tuple(std::get<0>(pair)), split<count - 1>(std::get<1>(pair), delimiter));
	}

	template<typename T>
	T string_to_integer(const std::string& str)
	{
		T result = 0;
		const char* first = str.data();
		const char* last = str.data() + str.size();

		auto [ptr, ec] = std::from_chars(first, last, result);
		if (ec == std::errc::result_out_of_range)
			throw std::out_of_range("string_to_integer result out of range");
		else if (ptr != last)
			throw std::invalid_argument("string_to_integer invalid argument");

		return result;
	}

	int stoi(const std::string& str)
	{
		return string_to_integer<int>(str);
	}

	libencrypt::uint32_t stou32(const std::string& str)
	{
		return string_to_integer<libencrypt::uint32_t>(str);
	}

	//-------------------------------------------------------------------------------------------------

	auto get_argument_k(const std::string& arg)
	{
		auto to_kdf_algorithm = [](const std::string& algorithm)
		{
			if (algorithm == "argon2i")
				return libencrypt::kdf_algorithm::argon2i;
			else if (algorithm == "argon2d")
				return libencrypt::kdf_algorithm::argon2d;
			else if (algorithm == "argon2id")
				return libencrypt::kdf_algorithm::argon2id;
			else
				throw std::invalid_argument("unknown KDF algorithm");
		};

		auto [algorithm, time_cost, memory_cost, parallelism] = split<3>(arg, ",");
		return std::make_tuple(to_kdf_algorithm(algorithm), stou32(time_cost), stou32(memory_cost), stou32(parallelism));
	}

	std::vector<libencrypt::cipher_algorithm> get_argument_c(const std::string& arg)
	{
		auto to_cipher_algorithm = [](const std::string& algorithm)
		{
			if (algorithm == "aes-128-ctr")
				return libencrypt::cipher_algorithm::aes_128_ctr;
			else if (algorithm == "aes-192-ctr")
				return libencrypt::cipher_algorithm::aes_192_ctr;
			else if (algorithm == "aes-256-ctr")
				return libencrypt::cipher_algorithm::aes_256_ctr;
			else if (algorithm == "chacha20")
				return libencrypt::cipher_algorithm::chacha20;
			else
				throw std::invalid_argument("unknown cipher algorithm");
		};

		if (arg.find(',') == std::string::npos)
			return { to_cipher_algorithm(arg) };
		else
		{
			auto [c1, c2] = split<1>(arg, ",");
			return { to_cipher_algorithm(c1), to_cipher_algorithm(c2) };
		}
	}

	std::vector<libencrypt::mac_algorithm> get_argument_m(const std::string& arg)
	{
		auto to_mac_algorithm = [](const std::string& algorithm)
		{
			if (algorithm == "hmac-sha1")
				return libencrypt::mac_algorithm::hmac_sha1;
			else if (algorithm == "hmac-sha256")
				return libencrypt::mac_algorithm::hmac_sha256;
			else if (algorithm == "hmac-sha512")
				return libencrypt::mac_algorithm::hmac_sha512;
			else if (algorithm == "poly1305")
				return libencrypt::mac_algorithm::poly1305;
			else
				throw std::invalid_argument("unknown MAC algorithm");
		};

		if (arg.find(',') == std::string::npos)
			return { to_mac_algorithm(arg) };
		else
		{
			auto [m1, m2] = split<1>(arg, ",");
			return { to_mac_algorithm(m1), to_mac_algorithm(m2) };
		}
	}

	std::FILE* get_argument_i(const std::string& arg)
	{
		std::FILE* p = std::fopen(arg.c_str(), "rb");
		if (!p)
			throw std::runtime_error("open input file error");
		return p;
	}

	std::FILE* get_argument_o(const std::string& arg)
	{
		std::FILE* p = std::fopen(arg.c_str(), "wb");
		if (!p)
			throw std::runtime_error("open output file error");
		return p;
	}

	//-------------------------------------------------------------------------------------------------

	command get_command(int argc, char* argv[])
	{
		if (argc < 2)
			throw std::invalid_argument("missing arguments; type -h for a list");
		if (std::string(argv[1]) == "-e")
			return command::encrypt;
		else if (std::string(argv[1]) == "-d")
			return command::decrypt;
		else if (std::string(argv[1]) == "-h")
			return command::help;
		else
			throw std::invalid_argument("unknown command; type -h for a list");
	}

	void read_argument(int argc, char* argv[], option& opt)
	{
		if (argc % 2)
			throw std::invalid_argument("missing arguments");
		for (int i = 2; i < argc; i += 2)
		{
			std::string a = argv[i];
			std::string b = argv[i + 1];

			if (a == "-k")
				std::tie(opt.algorithm, opt.time_cost, opt.memory_cost, opt.parallelism) = get_argument_k(b);
			else if (a == "-c")
				opt.cipher_list = get_argument_c(b);
			else if (a == "-m")
				opt.mac_list = get_argument_m(b);
			else if (a == "-p")
				opt.password = read_file(b);
			else if (a == "-s")
				opt.key = read_file(b);
			else if (a == "-t")
				opt.threads = ::stoi(b);
			else if (a == "-i")
				opt.input = get_argument_i(b);
			else if (a == "-o")
				opt.output = get_argument_o(b);
			else
				throw std::invalid_argument("unknown option");
		}
	}

	std::unique_ptr<libencrypt::kdf_parameter> make_kdf_parameter(option& opt)
	{
		libencrypt::const_array password = { reinterpret_cast<const libencrypt::byte*>(opt.password.data()), opt.password.size() };
		libencrypt::const_array salt = {};
		libencrypt::const_array key = { reinterpret_cast<const libencrypt::byte*>(opt.key.data()), opt.key.size() };
		return std::make_unique<libencrypt::argon2_parameter>(password, salt, key, opt.time_cost, opt.memory_cost, opt.parallelism);
	}

	FILE* get_input(FILE* file)
	{
		if (!file)
			file = std::freopen(nullptr, "rb", stdin);
		if (!file)
			throw std::runtime_error("reopen stdin error");
		return file;
	}

	FILE* get_output(FILE* file)
	{
		if (!file)
			file = std::freopen(nullptr, "wb", stdout);
		if (!file)
			throw std::runtime_error("reopen stdout error");
		return file;
	}

	option get_option(int argc, char* argv[])
	{
		option opt;
		opt.cmd = get_command(argc, argv);
		if (opt.cmd != command::help)
		{
			read_argument(argc, argv, opt);
			opt.parameter = make_kdf_parameter(opt);
			opt.input = get_input(opt.input);
			opt.output = get_output(opt.output);
		}

		return opt;
	}
}

int main(int argc, char* argv[])
{
	try
	{
		option opt = get_option(argc, argv);
		if (opt.cmd == command::encrypt)
			libencrypt::encrypt(opt.input, opt.output, opt.algorithm, *opt.parameter, opt.cipher_list, opt.mac_list, opt.threads);
		else if (opt.cmd == command::decrypt)
			libencrypt::decrypt(opt.input, opt.output, opt.algorithm, *opt.parameter, opt.cipher_list, opt.mac_list, opt.threads);
		else if (opt.cmd == command::help)
			std::cout << help << '\n';
	}
	catch (const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}