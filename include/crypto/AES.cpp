#include"AES.h"
#include<algorithm>

using namespace crypto;

namespace
{
	class word
	{
	public:
		word() = default;
		constexpr word(byte a0, byte a1, byte a2, byte a3) noexcept : a{ a0, a1, a2, a3 } {}

		byte& operator[](int index) noexcept
		{
			return this->a[index];
		}

		const byte& operator[](int index) const noexcept
		{
			return this->a[index];
		}

		word operator^(const word& other) const noexcept
		{
			word temp = *this;
			for (int i = 0; i < 4; i++)
				temp.a[i] ^= other.a[i];

			return temp;
		}

	private:
		byte a[4];
	};

	template<int Nb>
	class matrix
	{
	public:
		/*
		*  0  1  2  3        0  4  8 12
		*  4  5  6  7        1  5  9 13
		*  8  9 10 11   ->   2  6 10 14
		* 12 13 14 15        3  7 11 15
		*/
		matrix(const byte* in) noexcept
		{
			for (int c = 0; c < Nb; c++)
				for (int r = 0; r < 4; r++)
					this->data[r][c] = in[r + 4 * c];
		}

		byte* operator[](int row) noexcept
		{
			return this->data[row];
		}

		void copy_to(byte* out) const noexcept
		{
			for (int c = 0; c < Nb; c++)
				for (int r = 0; r < 4; r++)
					out[r + 4 * c] = this->data[r][c];
		}

	private:
		byte data[4][Nb];
	};

	//-------------------------------------------------------------------------------------------------

	constexpr byte S_box[256] = {
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
	};

	constexpr byte Inv_S_box[256] = {
		0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
		0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
		0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
		0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
		0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
		0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
		0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
		0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
		0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
		0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
		0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
		0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
		0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
		0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
		0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
		0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
	};

	//-------------------------------------------------------------------------------------------------

	byte xtime(byte x) noexcept
	{
		if (x >> 7)
			return (x << 1) ^ 0x1b;
		else
			return (x << 1);
	}

	//-------------------------------------------------------------------------------------------------

	word SubWord(word x) noexcept
	{
		for (int i = 0; i < 4; i++)
			x[i] = S_box[x[i]];

		return x;
	}

	word RotWord(word x) noexcept
	{
		byte temp = x[0];
		x[0] = x[1];
		x[1] = x[2];
		x[2] = x[3];
		x[3] = temp;

		return x;
	}

	template<int Nk, int Nb, int Nr>
	void KeyExpansion(const byte* key, word* w) noexcept
	{
		constexpr word Rcon[10] = {
			{ 0x01, 0, 0, 0 }, { 0x02, 0, 0, 0 }, { 0x04, 0, 0, 0 }, { 0x08, 0, 0, 0 }, { 0x10, 0, 0, 0 },
			{ 0x20, 0, 0, 0 }, { 0x40, 0, 0, 0 }, { 0x80, 0, 0, 0 }, { 0x1b, 0, 0, 0 }, { 0x36, 0, 0, 0 },
		};

		for (int i = 0; i < Nk; i++)
			w[i] = word(key[4 * i + 0], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);

		for (int i = Nk; i < Nb * (Nr + 1); i++)
		{
			word temp = w[i - 1];
			if (i % Nk == 0)
				temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
			else if (Nk > 6 && i % Nk == 4)
				temp = SubWord(temp);
			w[i] = w[i - Nk] ^ temp;
		}
	}

	template<int Nb>
	void AddRoundKey(matrix<Nb>& state, const byte* RoundKey) noexcept
	{
		for (int c = 0; c < Nb; c++)
			for (int r = 0; r < 4; r++)
				state[r][c] ^= RoundKey[r + 4 * c];
	}

	template<int Nb>
	void SubBytes(matrix<Nb>& state) noexcept
	{
		for (int c = 0; c < Nb; c++)
			for (int r = 0; r < 4; r++)
				state[r][c] = S_box[state[r][c]];
	}

	template<int Nb>
	void ShiftRows(matrix<Nb>& state) noexcept
	{
		constexpr int shift[4] = { 0, 1, 2, 3 };

		matrix<Nb> s = state;
		for (int r = 0; r < 4; r++)
			for (int c = 0; c < Nb; c++)
				state[r][c] = s[r][(c + shift[r]) % Nb];
	}

	template<int Nb>
	void MixColumns(matrix<Nb>& state) noexcept
	{
		for (int c = 0; c < Nb; c++)
		{
			byte mul1[4], mul2[4], mul3[4];
			for (int i = 0; i < 4; i++)
			{
				mul1[i] = state[i][c];
				mul2[i] = xtime(mul1[i]);
				mul3[i] = mul2[i] ^ mul1[i];
			}

			state[0][c] = mul2[0] ^ mul3[1] ^ mul1[2] ^ mul1[3];
			state[1][c] = mul1[0] ^ mul2[1] ^ mul3[2] ^ mul1[3];
			state[2][c] = mul1[0] ^ mul1[1] ^ mul2[2] ^ mul3[3];
			state[3][c] = mul3[0] ^ mul1[1] ^ mul1[2] ^ mul2[3];
		}
	}

	template<int Nb>
	void InvShiftRows(matrix<Nb>& state) noexcept
	{
		constexpr int shift[4] = { 0, 1, 2, 3 };

		matrix<Nb> s = state;
		for (int r = 0; r < 4; r++)
			for (int c = 0; c < Nb; c++)
				state[r][(c + shift[r]) % Nb] = s[r][c];
	}

	template<int Nb>
	void InvSubBytes(matrix<Nb>& state) noexcept
	{
		for (int c = 0; c < Nb; c++)
			for (int r = 0; r < 4; r++)
				state[r][c] = Inv_S_box[state[r][c]];
	}

	template<int Nb>
	void InvMixColumns(matrix<Nb>& state) noexcept
	{
		for (int c = 0; c < Nb; c++)
		{
			byte mul1[4], mul2[4], mul4[4], mul8[4], mul9[4], mulb[4], muld[4], mule[4];
			for (int i = 0; i < 4; i++)
			{
				mul1[i] = state[i][c];
				mul2[i] = xtime(mul1[i]);
				mul4[i] = xtime(mul2[i]);
				mul8[i] = xtime(mul4[i]);
				mul9[i] = mul8[i] ^ mul1[i];
				mulb[i] = mul9[i] ^ mul2[i];
				muld[i] = mul9[i] ^ mul4[i];
				mule[i] = mul8[i] ^ mul4[i] ^ mul2[i];
			}

			state[0][c] = mule[0] ^ mulb[1] ^ muld[2] ^ mul9[3];
			state[1][c] = mul9[0] ^ mule[1] ^ mulb[2] ^ muld[3];
			state[2][c] = muld[0] ^ mul9[1] ^ mule[2] ^ mulb[3];
			state[3][c] = mulb[0] ^ muld[1] ^ mul9[2] ^ mule[3];
		}
	}

	//-------------------------------------------------------------------------------------------------

	template<int Nk, int Nb, int Nr>
	void init(const byte* key, byte* byte_w) noexcept
	{
		word w[Nb * (Nr + 1)];
		KeyExpansion<Nk, Nb, Nr>(key, w);

		for (int i = 0; i < Nb * (Nr + 1); i++)
			for (int j = 0; j < 4; j++)
				byte_w[i * 4 + j] = w[i][j];
	}
}

//-------------------------------------------------------------------------------------------------

template<int Nk, int Nb, int Nr>
crypto::cipher::AES<Nk, Nb, Nr>::encryption::encryption(const byte* key) noexcept
{
	this->init(key);
}

template<int Nk, int Nb, int Nr>
void crypto::cipher::AES<Nk, Nb, Nr>::encryption::init(const byte* key) noexcept
{
	::init<Nk, Nb, Nr>(key, this->w);
}

template<int Nk, int Nb, int Nr>
void crypto::cipher::AES<Nk, Nb, Nr>::encryption::encrypt(const byte* in, byte* out) noexcept
{
	matrix<Nb> state(in);

	AddRoundKey(state, this->w);

	for (int i = 1; i <= Nr - 1; i++)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, this->w + i * 4 * Nb);
	}

	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, this->w + Nr * 4 * Nb);

	state.copy_to(out);
}

//-------------------------------------------------------------------------------------------------

template<int Nk, int Nb, int Nr>
crypto::cipher::AES<Nk, Nb, Nr>::decryption::decryption(const byte* key) noexcept
{
	this->init(key);
}

template<int Nk, int Nb, int Nr>
void crypto::cipher::AES<Nk, Nb, Nr>::decryption::init(const byte* key) noexcept
{
	::init<Nk, Nb, Nr>(key, this->w);
}

template<int Nk, int Nb, int Nr>
void crypto::cipher::AES<Nk, Nb, Nr>::decryption::decrypt(const byte* in, byte* out) noexcept
{
	matrix<Nb> state(in);

	AddRoundKey(state, this->w + Nr * 4 * Nb);

	for (int i = Nr - 1; i >= 1; i--)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, this->w + i * 4 * Nb);
		InvMixColumns(state);
	}

	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, this->w);

	state.copy_to(out);
}

//-------------------------------------------------------------------------------------------------

template class crypto::cipher::AES<4, 4, 10>;
template class crypto::cipher::AES<6, 4, 12>;
template class crypto::cipher::AES<8, 4, 14>;