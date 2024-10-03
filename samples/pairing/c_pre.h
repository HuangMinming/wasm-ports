// c_pre.h
#ifndef C_PRE_H 
#define C_PRE_H 
#include <stdio.h>
#include <string.h>
// #include "/usr/local/include/pbc/pbc.h"
#include <pbc/pbc.h>
#include <emscripten/emscripten.h>

#define SHA256_DIGEST_LENGTH_32 32
#define ZR_ELEMENT_LENGTH_IN_BYTES 20
#define G1_ELEMENT_LENGTH_IN_BYTES 128
#define G2_ELEMENT_LENGTH_IN_BYTES 128
#define GT_ELEMENT_LENGTH_IN_BYTES 128


// 结构体定义
typedef struct {
    element_t pk;   // 公钥
    element_t sk;   // 私钥
} KeyPair;

typedef struct {
    element_t rk1;  // 重加密密钥 rk1
    element_t rk2;  // 重加密密钥 rk2
} ReKeyPair;

typedef struct {
    element_t c1;   // 密文的第一部分
    element_t c2;   // 密文的第二部分
    uint8_t *c3;       // 密文的第三部分（比特串）
    element_t c4;   // 密文的第四部分
} CipherText;


// 函数声明
void Setup(pairing_t pairing, element_t g, element_t Z, int *p_n);
void Hash1(element_t result, char* m, element_t R);
void Hash2(element_t result, element_t pk, char* w);
void Hash3(char* bitstring, element_t R);
void Hash4(element_t result, element_t c1, element_t c2, char* c3);

// void bytes_to_bits(unsigned char* bytes, int byte_len, char* bitstring, int n);
// void xor_bitstrings(char* result, char* str1, char* str2);
// void random_bitstring(char *bitstring, int n);
//测试函数
// #ifdef __cplusplus
// extern "C" {
// #endif
// void EMSCRIPTEN_KEEPALIVE Enc1Test();
// void EMSCRIPTEN_KEEPALIVE Enc2Test();
// void EMSCRIPTEN_KEEPALIVE ReEncTest();
// #ifdef __cplusplus
// }
// #endif

#endif // C-PRE_H