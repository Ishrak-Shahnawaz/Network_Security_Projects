#include <iostream>
#include <iomanip>
#include <bitset>
#include <cstring>
#include <random>
#include <openssl/aes.h>

class Speck128 {
private:
    uint64_t round_keys[33];
    
    void key_schedule(const uint64_t k[2]) {
        uint64_t B = k[1];
        uint64_t A = k[0];
        round_keys[0] = B;
        for(int i = 0; i < 31; i++) {
            A = (A >> 8) | (A << 56);
            A += B;
            A ^= i;
            B = (B << 3) | (B >> 61);
            B ^= A;
            round_keys[i+1] = B;
        }
    }
    
public:
    Speck128(const uint8_t key[16]) {
        uint64_t k[2] = {0, 0};
        for(int i = 0; i < 8; i++) {
            k[0] = (k[0] << 8) | key[i];
            k[1] = (k[1] << 8) | key[i+8];
        }
        key_schedule(k);
    }
    
    void encrypt(const uint8_t input[16], uint8_t output[16]) {
        uint64_t x = 0, y = 0;
        for(int i = 0; i < 8; i++) {
            x = (x << 8) | input[i];
            y = (y << 8) | input[i+8];
        }
        for(int i = 0; i < 32; i++) {
            x = (x >> 8) | (x << 56);
            x += y;
            x ^= round_keys[i];
            y = (y << 3) | (y >> 61);
            y ^= x;
        }
        for(int i = 0; i < 8; i++) {
            output[7-i] = x & 0xFF;
            output[15-i] = y & 0xFF;
            x >>= 8;
            y >>= 8;
        }
    }
};

int hamming_distance(const uint8_t* a, const uint8_t* b, size_t len) {
    int diff = 0;
    for(size_t i = 0; i < len; i++) {
        std::bitset<8> bits(a[i] ^ b[i]);
        diff += bits.count();
    }
    return diff;
}

void flip_random_bits(uint8_t* data, int num_bits, std::mt19937& rng) {
    std::uniform_int_distribution<int> bit_dist(0, 127);
    bool* flipped = new bool[128]();
    
    for(int f = 0; f < num_bits; f++) {
        int bit_pos = bit_dist(rng);
        int byte_pos = bit_pos / 8;
        int bit_in_byte = bit_pos % 8;
        
        if(!flipped[bit_pos]) {
            data[byte_pos] ^= (1 << bit_in_byte);
            flipped[bit_pos] = true;
        }
    }
    delete[] flipped;
}

int main() {
    uint8_t key[16];
    for(int i = 0; i < 16; i++) key[i] = i;
    
    Speck128 speck(key);
    const int NUM_TESTS = 1000;
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "\n";
    std::cout << "================================================================\n";
    std::cout << "   AVALANCHE EFFECT: AES-128 vs SPECK-128\n";
    std::cout << "   (1 to 5 random bit flips in plaintext)\n";
    std::cout << "================================================================\n\n";
    
    std::cout << "Bits Flipped |     AES-128 (%)   |   SPECK-128 (%)   |   Ideal\n";
    std::cout << "----------------------------------------------------------------\n";
    
    for(int bits_to_flip = 1; bits_to_flip <= 5; bits_to_flip++) {
        double aes_total = 0, speck_total = 0;
        
        for(int test = 0; test < NUM_TESTS; test++) {
            uint8_t plaintext[16];
            for(int i = 0; i < 16; i++) plaintext[i] = byte_dist(rng);
            
            uint8_t modified[16];
            memcpy(modified, plaintext, 16);
            flip_random_bits(modified, bits_to_flip, rng);
            
            // AES test
            AES_KEY aes_key;
            AES_set_encrypt_key(key, 128, &aes_key);
            uint8_t aes_c1[16], aes_c2[16];
            AES_encrypt(plaintext, aes_c1, &aes_key);
            AES_encrypt(modified, aes_c2, &aes_key);
            int aes_diff = hamming_distance(aes_c1, aes_c2, 16);
            aes_total += (aes_diff / 128.0) * 100;
            
            // SPECK test
            uint8_t speck_c1[16], speck_c2[16];
            speck.encrypt(plaintext, speck_c1);
            speck.encrypt(modified, speck_c2);
            int speck_diff = hamming_distance(speck_c1, speck_c2, 16);
            speck_total += (speck_diff / 128.0) * 100;
        }
        
        double aes_avg = aes_total / NUM_TESTS;
        double speck_avg = speck_total / NUM_TESTS;
        
        std::cout << "      " << bits_to_flip << "      |        " 
                  << std::setw(6) << aes_avg << "%       |       " 
                  << std::setw(6) << speck_avg << "%       |    50%\n";
    }
    
    std::cout << "----------------------------------------------------------------\n";
    
    return 0;
}