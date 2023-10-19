#include<iostream>
#include<algorithm>
#include<exception>
#include<crypto/poly1305.h>
#include"poly1305_test_vector.h"

template<int N>
void test_poly1305(const poly1305_test_vector (&array)[N])
{
	for (int i = 0; i < N; i++)
	{
		using crypto::MAC::poly1305;
		unsigned char mac[poly1305::output_size];
		poly1305(array[i].key, array[i].message, array[i].length, mac);
		if (!std::equal(mac, mac + poly1305::output_size, array[i].mac))
		{
			std::cerr << "poly1305 fail\n";
			std::terminate();
		}
	}
}

int main()
{
	test_poly1305(poly1305_vector1);
	test_poly1305(poly1305_vector2);

	return 0;
}