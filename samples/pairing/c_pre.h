// c_pre.h
#ifndef C_PRE_H 
#define C_PRE_H 
#include <stdio.h>
#include <string.h>
// #include "/usr/local/include/pbc/pbc.h"
#include <pbc/pbc.h>
#include <emscripten/emscripten.h>


extern pairing_t pairing;
extern element_t g;
extern int n;
extern element_t Z;

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
    char *c3;       // 密文的第三部分（比特串）
    element_t c4;   // 密文的第四部分
} CipherText;


// 函数声明
void Setup(int nlength);
void Hash1(element_t result, char* m, element_t R);
void Hash1Test();
void Hash2(element_t result, element_t pk, char* w);
void Hash2Test();
void Hash3(char* bitstring, element_t R);
void Hash4(element_t result, element_t c1, element_t c2, char* c3);
KeyPair KeyGen();
ReKeyPair ReKeyGen(element_t ski, char* w, element_t pkj, element_t pki);
CipherText Enc1(element_t pk, char* m);
CipherText Enc2(element_t pk, char* w, char* m);
char* Dec1(CipherText CT, element_t sk, element_t pk);
char* Dec2(CipherText CT, element_t sk, element_t pk, char* w);
CipherText ReEnc(CipherText CT_i, ReKeyPair rekeypair);
void bytes_to_bits(unsigned char* bytes, int byte_len, char* bitstring, int n);
void xor_bitstrings(char* result, char* str1, char* str2);
void random_bitstring(char *bitstring, int n);
//测试函数
#ifdef __cplusplus
extern "C" {
#endif
void EMSCRIPTEN_KEEPALIVE Enc1Test();
void EMSCRIPTEN_KEEPALIVE Enc2Test();
void EMSCRIPTEN_KEEPALIVE ReEncTest();
#ifdef __cplusplus
}
#endif

#endif // C-PRE_H