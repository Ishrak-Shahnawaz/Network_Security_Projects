#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <openssl/aes.h>

void aes_process(const uint8_t* data, size_t size, unsigned char* buffer, const unsigned char* key) {
    size_t padded_size = ((size + 15)/16)*16;
    unsigned char* padded = new unsigned char[padded_size];
    memset(padded, 0, padded_size);
    memcpy(padded, data, size);

    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(key, 128, &enc_key);
    AES_set_decrypt_key(key, 128, &dec_key);

    for(size_t i = 0; i < padded_size; i += 16) {
        AES_encrypt(padded + i, buffer + i, &enc_key);
        AES_decrypt(buffer + i, buffer + i, &dec_key);
    }
    delete[] padded;
}

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
    
    void encrypt_block(const uint8_t input[16], uint8_t output[16]) {
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
    
    void encrypt_data(const uint8_t* plaintext, uint8_t* ciphertext, size_t size) {
        size_t padded = ((size + 15) / 16) * 16;
        std::vector<uint8_t> temp(padded, 0);
        memcpy(temp.data(), plaintext, size);
        for(size_t i = 0; i < padded; i += 16) {
            encrypt_block(temp.data() + i, ciphertext + i);
        }
    }
};

struct Stats {
    double mean, stddev, min, max, median;
};

Stats compute_stats(std::vector<double>& times) {
    Stats s;
    std::sort(times.begin(), times.end());
    s.min = times.front();
    s.max = times.back();
    s.median = times[times.size()/2];
    
    double sum = 0;
    for(double t : times) sum += t;
    s.mean = sum / times.size();
    
    double sq_sum = 0;
    for(double t : times) sq_sum += (t - s.mean) * (t - s.mean);
    s.stddev = std::sqrt(sq_sum / times.size());
    
    return s;
}

int main() {
    const int ITERATIONS = 1000;
    const int WARMUP = 100;
    
    std::vector<size_t> sizes = {8, 16, 32, 64, 128, 256, 512, 1024};
    uint8_t key[16];
    for(int i = 0; i < 16; i++) key[i] = i;
    
    Speck128 speck(key);
    
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "\n========== BENCHMARK WITH STD DEVIATION ==========\n\n";
    std::cout << "Iterations: " << ITERATIONS << " per test\n";
    std::cout << "Warmup: " << WARMUP << " iterations\n\n";
    std::cout << "Size(B)\tAES (μs)\t\tSPECK (μs)\t\tSpeedup\n";
    std::cout << "--------------------------------------------------------------\n";
    
    for(size_t size : sizes) {
        std::vector<uint8_t> plaintext(size);
        for(size_t i = 0; i < size; i++) plaintext[i] = i % 256;
        
        size_t padded = ((size + 15) / 16) * 16;
        std::vector<unsigned char> aes_out(padded);
        std::vector<uint8_t> speck_out(padded);
        
        // Warmup
        for(int i = 0; i < WARMUP; i++) {
            aes_process(plaintext.data(), size, aes_out.data(), key);
            speck.encrypt_data(plaintext.data(), speck_out.data(), size);
        }
        
        // Benchmark AES
        std::vector<double> aes_times;
        for(int iter = 0; iter < ITERATIONS; iter++) {
            auto start = std::chrono::high_resolution_clock::now();
            aes_process(plaintext.data(), size, aes_out.data(), key);
            auto end = std::chrono::high_resolution_clock::now();
            double us = std::chrono::duration<double, std::micro>(end - start).count();
            aes_times.push_back(us);
        }
        
        // Benchmark SPECK
        std::vector<double> speck_times;
        for(int iter = 0; iter < ITERATIONS; iter++) {
            auto start = std::chrono::high_resolution_clock::now();
            speck.encrypt_data(plaintext.data(), speck_out.data(), size);
            auto end = std::chrono::high_resolution_clock::now();
            double us = std::chrono::duration<double, std::micro>(end - start).count();
            speck_times.push_back(us);
        }
        
        Stats aes_stats = compute_stats(aes_times);
        Stats speck_stats = compute_stats(speck_times);
        double speedup = aes_stats.mean / speck_stats.mean;
        
        std::cout << std::setw(5) << size << "\t"
                  << std::setw(8) << aes_stats.mean << " ±" << std::setw(5) << aes_stats.stddev << "\t"
                  << std::setw(8) << speck_stats.mean << " ±" << std::setw(5) << speck_stats.stddev << "\t"
                  << std::setw(6) << speedup << "x\n";
    }
    
    std::cout << "\n==============================================================\n";
    std::cout << "Values: Mean ± Standard Deviation (microseconds)\n";
    
    return 0;
}