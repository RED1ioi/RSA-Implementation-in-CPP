#include<iostream>
#include<openssl/rand.h>
#include<algorithm>
#include<boost/multiprecision/cpp_int.hpp>
#include<boost/integer/common_factor_rt.hpp>
#include<rsa.hpp>

using namespace std;
using namespace boost::multiprecision;

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

    string message = "Hachem avec Chakib Sahnoune Yal Bnin";

    cpp_int plaintext = text_to_int(message);

    cpp_int ciphertext = encrypt(plaintext, keys.pub);
    cpp_int decrypted = decrypt(ciphertext, keys.prv);

    string recovered = int_to_text(decrypted);

    cout << "Original: " << message << '\n';
    cout << "Recovered: " << recovered << '\n';

}