#ifndef rsa_hpp
#define rsa_hpp

#include<boost/multiprecision/cpp_int.hpp>


using boost::multiprecision::cpp_int;

struct pub_key{
    cpp_int n;
    cpp_int e;
};

struct prv_key{
    cpp_int d;
    cpp_int p;
    cpp_int q;
};

struct key_pair{
    pub_key pub;
    prv_key prv;
};

key_pair generate_key_pair(int keySize);

cpp_int encrypt(cpp_int plaintext, pub_key publicKey);

cpp_int decrypt(cpp_int ciphertext, prv_key privateKey);

#endif