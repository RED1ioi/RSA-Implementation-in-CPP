#include<iostream>
#include<openssl/rand.h>
#include<algorithm>
#include<boost/multiprecision/cpp_int.hpp>
#include <boost/integer/common_factor_rt.hpp>

using namespace std;
using namespace boost::multiprecision;

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


cpp_int random_bits(unsigned int k, bool strictDigitCount, bool mustBeOdd){
    unsigned int bytes = (k+7)/8;

    vector<uint8_t> buffer(bytes);

    if(RAND_bytes(buffer.data(), bytes) != 1) 
        throw runtime_error("RAND_bytes failed");

    cpp_int result = 0;
    for(uint8_t b : buffer) {
        result <<= 8;
        result += b;
    }

    result &= (cpp_int(1) << k) - 1;
    if(strictDigitCount) result |= cpp_int(1) << (k - 1);
    if(mustBeOdd) result |= 1;

    return result;
}

cpp_int random_a(cpp_int p){
    cpp_int a;
    unsigned int k = msb(p - 3) + 1;

    do {
        a = random_bits(k,false,false);
    } while (a >= p-3);

    return a + 2;
}

cpp_int mod_exp(cpp_int a, cpp_int b, cpp_int mod){
    if(b==0) return 1;
    cpp_int res = mod_exp(a,b/2,mod);
    return ((res*res)%mod * (b%2==1 ? a : 1)) % mod;
}

bool miller_rabin(cpp_int p, int s){
    cpp_int r = p - 1;
    int u = 0;
    while(r%2==0){
        u++;
        r/=2;
    }
    for(int i = 0; i < s; ++i){
        cpp_int a = random_a(p);
        cpp_int z = mod_exp(a,r,p);
        if(z != 1 && z != p - 1){
            for(int j = 1; j < u && z != p - 1; ++j){
                z = (z*z)%p;
                if(z == 1) return 0;
            }
            if(z != p-1) return 0;
        }
    }
    return 1;
}

cpp_int generate_prime(int keySize){
    unsigned int primeSize = keySize/2;
    cpp_int p = random_bits(primeSize, true, true);

    while(!miller_rabin(p, 40))
        p = random_bits(primeSize, true, true);

    return p;
}

cpp_int mod_inverse(cpp_int a, cpp_int m){
    cpp_int m0 = m;
    cpp_int x0 = 0, x1 = 1;

    while(a > 1){
        cpp_int q = a / m;

        cpp_int tmp = m;
        m = a % m;
        a = tmp;

        tmp = x0;
        x0 = x1 - q * x0;
        x1 = tmp;
    }

    if(x1 < 0) x1 += m0;

    return x1;
}



key_pair generate_key_pair(int keySize){
    cpp_int e = 65537;

    cpp_int p, q, phi;
    do {
        p = generate_prime(keySize);
        q = generate_prime(keySize);

        phi = (p - 1) * (q - 1);
    } while(p == q || gcd(e, phi) != 1);

    cpp_int n = p * q;
    cpp_int d = mod_inverse(e, phi);

    return {{n, e}, {d, p, q}};
}


cpp_int encrypt(cpp_int plaintext, pub_key publicKey){
    cpp_int e = publicKey.e, n = publicKey.n;

    return mod_exp(plaintext,e,n);
}

cpp_int decrypt(cpp_int ciphertext, prv_key privateKey){
    cpp_int d = privateKey.d, n = privateKey.p * privateKey.q;

    return mod_exp(ciphertext,d,n);
}

cpp_int text_to_int(const string& text){
    cpp_int result = 0;

    for(uint8_t c : text){
        result <<= 8;
        result |= c;
    }

    return result;
}

string int_to_text(cpp_int n){
    string result;

    while(n > 0){
        result += static_cast<char>(
            (n & 255).convert_to<uint8_t>()
        );
        n >>= 8;
    }

    reverse(result.begin(), result.end());
    return result;
}

string to_hex(cpp_int n) {
    if (n == 0) return "0";

    string result;
    const char digits[] = "0123456789ABCDEF";

    while (n > 0) {
        unsigned int digit = (n % 16).convert_to<unsigned int>();
        result += digits[digit];
        n >>= 4;
    }

    reverse(result.begin(), result.end());
    return result;
}

int main(){
    key_pair keys = generate_key_pair(2048);

    cout << "Public key:\n";
    cout << "n: " << to_hex(keys.pub.n) << '\n';
    cout << "e: " << to_hex(keys.pub.e) << '\n';

    cout << "\nPrivate key:\n";
    cout << "d: " << to_hex(keys.prv.d) << '\n';
    cout << "p: " << to_hex(keys.prv.p) << '\n';
    cout << "q: " << to_hex(keys.prv.q) << '\n';

    string message = "Hachem Zna avec Chakib Sahnoune Yal Bnin";

    cpp_int plaintext = text_to_int(message);

    cpp_int ciphertext = encrypt(plaintext, keys.pub);
    cpp_int decrypted = decrypt(ciphertext, keys.prv);

    string recovered = int_to_text(decrypted);

    cout << "Original: " << message << '\n';
    cout << "Recovered: " << recovered << '\n';

}