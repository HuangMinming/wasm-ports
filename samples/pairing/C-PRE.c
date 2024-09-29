#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>

#include <stdio.h>
#include <emscripten/emscripten.h>
#include <pbc/pbc.h>
#include <string.h>
#include "sha256.h"
#include "C-PRE.h"


pairing_t pairing;
element_t g;
int n;
element_t Z;



void Setup(int nlength){
    char param[1024];
    size_t count = fread(param, 1, 1024, stdin);
    if (!count)
        pbc_die("input error");
    pairing_init_set_buf(pairing, param, count);
    element_init_G1(g, pairing);
    element_random(g);
    element_init_GT(Z, pairing);
    pairing_apply(Z, g, g, pairing);
    n = nlength;
}

//Hash1 {0,1}* -> Zq
void Hash1(element_t result, char* m, element_t R)
{
    int R_len = element_length_in_bytes(R);
    unsigned char *R_bytes = (unsigned char *) malloc(R_len);
    element_to_bytes(R_bytes, R);  // 序列化 GT 群中的元素 R
    
    // 获取输入字符串 m 的长度
    int m_len = strlen(m);
    
    // 合并 m 和 R_bytes
    unsigned char *input = (unsigned char *) malloc(m_len + R_len);
    memcpy(input, m, m_len);
    memcpy(input + m_len, R_bytes, R_len);
    
    // 使用 OpenSSL SHA256 进行哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // SHA256(input, m_len + R_len, hash);
    sha256_context ctx;
    sha256_starts( &ctx );
    sha256_update( &ctx, (uint8 *) input, m_len + R_len );
    sha256_finish( &ctx, hash );
    
    // 将哈希值转化为大整数
    mpz_t hash_int;
    mpz_init(hash_int);
    mpz_import(hash_int, SHA256_DIGEST_LENGTH, 1, sizeof(hash[0]), 0, 0, hash);

    // 对 hash_int 取模并存入 result
    element_init_Zr(result, pairing);  // 初始化 result 为 Zq 上的元素
    element_set_mpz(result, hash_int);  // 将哈希值映射到 Zq 上
    
    // 释放内存
    free(R_bytes);
    free(input);
    mpz_clear(hash_int);
}

void Hash1Test()
{
    printf("-----------Strat Hash1Test----------\n");
    element_t result;
    element_init_Zr(result, pairing);
    element_t R;
    element_init_GT(R, pairing);
    element_random(R);
    // element_set_si(R, 40);
    Hash1(result, "101", R);
    element_printf("result = %B\n", result);
    Hash1(result, "101", R);
    element_printf("result = %B\n", result);
    printf("-----------End Hash1Test----------\n");
}

//Hash2 {0,1}* -> G1
void Hash2(element_t result, element_t pk,  char* w) {
    // SHA256_CTX sha256;
    // SHA256_Init(&sha256);
    sha256_context ctx;
    sha256_starts( &ctx );

    unsigned char hash[SHA256_DIGEST_LENGTH];
    size_t pk_len = element_length_in_bytes(pk);
    size_t w_len = strlen(w);
    unsigned char combined_input[pk_len + w_len];

    // 将 pk 转换为字节形式
    element_to_bytes(combined_input, pk); 

    // 将 w 也转换为字节形式，并拼接到 combined_input 中
    memcpy(combined_input + pk_len, w, w_len);

    // SHA256_Update(&sha256, combined_input, pk_len + w_len);
    // SHA256_Final(hash, &sha256);
    sha256_update( &ctx, (uint8 *) combined_input, pk_len + w_len );
    sha256_finish( &ctx, hash );
    element_init_G1(result, pairing);
    // 将哈希值映射到群元素
    element_from_hash(result, hash, SHA256_DIGEST_LENGTH); // result 是群元素
}

void Hash2Test()
{
    printf("-----------Strat Hash2Test----------\n");
    KeyPair keypair = KeyGen();
    element_t result;
    element_init_G1(result, pairing);
    Hash2(result, keypair.pk, "hello world");
    element_printf("result = %B\n", result);
    Hash2(result, keypair.pk, "hello world");
    element_printf("result = %B\n", result);
    printf("-----------End Hash2Test----------\n");
}

// Hash3 G1 -> {0,1}^n
void Hash3(char *bitstring, element_t R){
    // 获取 G1 群元素 R 的字节表示
    int R_len = element_length_in_bytes(R);
    unsigned char *R_bytes = (unsigned char *) malloc(R_len);
    element_to_bytes(R_bytes, R);  // 序列化 G1 群中的元素 R

    // 使用 OpenSSL 的 SHA256 进行哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // SHA256(R_bytes, R_len, hash);
    sha256_context ctx;
    sha256_starts( &ctx );
    sha256_update( &ctx, (uint8 *) R_bytes, R_len );
    sha256_finish( &ctx, hash );

    // 将哈希结果转化为二进制比特串
    bytes_to_bits(hash, SHA256_DIGEST_LENGTH, bitstring, n);
    // 释放内存
    free(R_bytes);
}

void Hash4(element_t result, element_t c1, element_t c2,  char* c3) {
    // SHA256_CTX sha256;
    // SHA256_Init(&sha256);
    sha256_context ctx;
    sha256_starts( &ctx );

    // 获取 G1 群元素 c1 的字节长度
    size_t c1_len = element_length_in_bytes(c1);
    // 获取 GT 群元素 c2 的字节长度
    size_t c2_len = element_length_in_bytes(c2);
    // 获取 c3 的长度
    size_t c3_len = strlen(c3);

    // 分配足够大的缓冲区来存储 c1, c2 和 c3 的拼接结果
    unsigned char combined_input[c1_len + c2_len + c3_len];

    // 将 c1 转换为字节形式
    element_to_bytes(combined_input, c1);

    // 将 c2 转换为字节形式，并拼接到 combined_input 中
    element_to_bytes(combined_input + c1_len, c2);

    // 将 c3 拼接到 combined_input 中
    memcpy(combined_input + c1_len + c2_len, c3, c3_len);

    // 进行 SHA256 哈希
    unsigned char hash[SHA256_DIGEST_LENGTH];
    // SHA256_Update(&sha256, combined_input, c1_len + c2_len + c3_len);
    // SHA256_Final(hash, &sha256);
    sha256_update( &ctx, (uint8 *) combined_input, c1_len + c2_len + c3_len );
    sha256_finish( &ctx, hash );

    element_init_G1(result, pairing);
    // 将哈希值映射到群元素 result
    element_from_hash(result, hash, SHA256_DIGEST_LENGTH);  // 将哈希值映射为群元素

}

KeyPair KeyGen()
{
    KeyPair keypair;
    element_init_G1(keypair.pk, pairing);
    element_init_Zr(keypair.sk, pairing);
    element_random(keypair.sk);
    element_pow_zn(keypair.pk, g, keypair.sk);
    return keypair;
}

ReKeyPair ReKeyGen(element_t ski, char* w, element_t pkj, element_t pki) //pki不在输入中
{
    ReKeyPair rk_ij;
    element_init_G1(rk_ij.rk1, pairing);
    element_init_G1(rk_ij.rk2, pairing);
    element_t hashresult, powresult, s, negski;
    element_init_G1(powresult, pairing);
    element_init_G1(hashresult, pairing);
    element_init_Zr(negski, pairing);
    element_init_Zr(s, pairing);
    element_random(s);
    Hash2(hashresult, pki, w);
    element_pow_zn(powresult, pkj, s);
    element_mul(rk_ij.rk1, powresult, hashresult);
    element_neg(negski, ski);
    element_pow_zn(rk_ij.rk1, rk_ij.rk1, negski);
    element_pow_zn(rk_ij.rk2, pki, s);
    element_clear(hashresult);
    element_clear(powresult);
    element_clear(s);
    element_clear(negski);
    return rk_ij;
}

CipherText Enc2(element_t pk,  char* w,  char* m)
{
    CipherText ciphertext;
    element_init_G1(ciphertext.c1, pairing);
    element_init_GT(ciphertext.c2, pairing);
    element_init_G1(ciphertext.c4, pairing);
    // 为 ciphertext.c3 分配内存
    ciphertext.c3 = (char *) malloc(n + 1);
    element_t R, r, hash2result, eresult, hash4result;
    element_init_GT(R, pairing);
    element_random(R);
    element_init_Zr(r, pairing);
    element_init_G1(hash2result, pairing);
    element_init_GT(eresult, pairing);
    element_init_G1(hash4result, pairing);
    Hash1(r, m, R); 
    element_pow_zn(ciphertext.c1, g, r);
    Hash2(hash2result, pk, w);
    element_pairing(eresult, pk, hash2result);
    element_pow_zn(eresult, eresult, r);
    element_mul(ciphertext.c2, R, eresult);
    char *hash3result = (char *) malloc(n + 1);
    Hash3(hash3result, R);
    xor_bitstrings(ciphertext.c3, m, hash3result);
    Hash4(hash4result, ciphertext.c1, ciphertext.c2, ciphertext.c3);
    element_pow_zn(ciphertext.c4, hash4result, r);
    element_clear(R);
    element_clear(r);
    element_clear(hash2result);
    element_clear(eresult);
    element_clear(hash4result);
    free(hash3result);
    return ciphertext;
}

CipherText Enc1(element_t pk, char* m)
{
    CipherText ciphertext;
    element_init_G1(ciphertext.c1, pairing);
    element_init_GT(ciphertext.c2, pairing);
    element_init_G1(ciphertext.c4, pairing);
    // 为 ciphertext.c3 分配内存
    ciphertext.c3 = (char *) malloc(n + 1);
    element_t R, r, s0, eresult, emuls;
    element_init_GT(R, pairing);
    element_random(R);
    element_init_Zr(s0, pairing);
    element_random(s0);
    element_init_Zr(r, pairing);
    element_init_GT(eresult, pairing);
    element_init_Zr(emuls, pairing);
    Hash1(r, m, R); 
    element_pow_zn(ciphertext.c1, g, r);
    element_mul(emuls, s0, r);
    element_neg(emuls, emuls);
    element_pairing(eresult, g, pk);
    element_pow_zn(eresult, eresult, emuls);
    element_mul(ciphertext.c2, R, eresult);
    char *hash3result = (char *) malloc(n + 1);
    Hash3(hash3result, R);
    xor_bitstrings  (ciphertext.c3, m, hash3result);
    element_pow_zn(ciphertext.c4, g, s0);
    element_clear(R);
    element_clear(r);
    element_clear(eresult);
    element_clear(emuls);
    free(hash3result);
    return ciphertext;
}

char* Dec2(CipherText CipherText, element_t sk, element_t pk, char* w)
{
    element_t hash2result, eresult, R;
    element_init_G1(hash2result, pairing);
    element_init_GT(eresult, pairing);
    element_init_GT(R, pairing);

    Hash2(hash2result, pk, w);
    element_pairing(eresult, CipherText.c1, hash2result);
    element_pow_zn(eresult, eresult, sk);
    element_invert(eresult, eresult);
    element_mul(R, CipherText.c2, eresult);
    char *hash3result = (char *) malloc(n + 1);
    Hash3(hash3result, R);
    char *m = (char *) malloc(n + 1);
    xor_bitstrings(m, CipherText.c3, hash3result);
    element_clear(hash2result);
    element_clear(eresult);
    element_clear(R);
    free(hash3result);
    return m;
}

CipherText ReEnc(CipherText CT_i, ReKeyPair rekeypair) {
    CipherText CT_j;
    
    // 初始化 CT_j 的元素
    element_init_G1(CT_j.c1, pairing);
    element_init_GT(CT_j.c2, pairing);
    element_init_G1(CT_j.c4, pairing);
    CT_j.c3 = (char *) malloc(n + 1);  // n 是比特长度，根据需要调整

    // 计算双线性对 e(C1, H4(C1, C2, C3))
    element_t H4_result, pairing1, pairing2;
    element_init_GT(pairing1, pairing);
    element_init_GT(pairing2, pairing);
    element_init_G1(H4_result, pairing);

    // 计算 H4(C1, C2, C3)
    Hash4(H4_result, CT_i.c1, CT_i.c2, CT_i.c3);

    // 计算双线性对 e(C1, H4(C1, C2, C3))
    element_pairing(pairing1, CT_i.c1, H4_result);

    // 计算双线性对 e(g, C4)
    element_pairing(pairing2, g, CT_i.c4);

    // 检查双线性对是否相等
    if (element_cmp(pairing1, pairing2) != 0) {
        printf("双线性对检查失败，返回 NULL 密文\n");
        element_clear(CT_j.c1);
        element_clear(CT_j.c2);
        element_clear(CT_j.c4);
        free(CT_j.c3);
        // 处理错误，或返回 ⊥
        return CT_j;
    }

    // 双线性对匹配，继续重加密
    // C̄1 = C1
    element_set(CT_j.c1, CT_i.c1);

    // C̄2 = C2 · e(C1, rk1)
    element_t pairing3;
    element_init_GT(pairing3, pairing);
    element_pairing(pairing3, CT_i.c1, rekeypair.rk1);
    element_mul(CT_j.c2, CT_i.c2, pairing3);

    // C̄3 = C3 (复制第三部分)
    strcpy(CT_j.c3, CT_i.c3);

    // C̄4 = rk2
    element_set(CT_j.c4, rekeypair.rk2);

    // 清除临时变量
    element_clear(H4_result);
    element_clear(pairing1);
    element_clear(pairing2);
    element_clear(pairing3);
    return CT_j;
}

char* Dec1(CipherText CT, element_t sk, element_t pk)
{
    element_t R, eresult;
    element_init_GT(R, pairing);
    element_init_GT(eresult, pairing);

    element_pairing(eresult, CT.c1, CT.c4);
    element_pow_zn(eresult, eresult, sk);
    element_mul(R, CT.c2, eresult);
    char *hash3result = (char *) malloc(n + 1);
    Hash3(hash3result, R);
    char *m = (char *) malloc(n + 1);
    xor_bitstrings(m, CT.c3, hash3result);
    element_clear(R);
    element_clear(eresult);
    free(hash3result);
    return m;
}


#ifdef __cplusplus
extern "C" {
#endif


void EMSCRIPTEN_KEEPALIVE Enc1Test()
{
    printf("-----------Strat Enc1Test----------\n");
    KeyPair keypair = KeyGen();
    //生成n位的随机比特串
    char* m = (char *) malloc(n + 1);
    random_bitstring(m, n);
    // char* m = "1001011";
    CipherText ciphertext = Enc1(keypair.pk, m);
    char* m1 = Dec1(ciphertext, keypair.sk, keypair.pk);
    printf("Message = %s\n", m);
    printf("DecryptResult = %s\n", m1);
    //比较解密结果
    if(strcmp(m, m1) == 0)
    {
        printf("Enc1Test success\n");
    }
    else
    {
        printf("Enc1Test fail\n");
    }
    printf("-----------End Enc1Test----------\n");
}

void EMSCRIPTEN_KEEPALIVE Enc2Test()
{
    printf("-----------Strat Enc2Test----------\n");
    KeyPair keypair = KeyGen();
    char* m = (char *) malloc(n + 1);
    random_bitstring(m, n);
    char* w = "hello world";
    CipherText ciphertext = Enc2(keypair.pk,w, m);
    char* m1 = Dec2(ciphertext, keypair.sk, keypair.pk, w);
    printf("Message = %s\n", m);
    printf("DecryptResult = %s\n", m1);
    if(strcmp(m, m1) == 0)
    {
        printf("Enc2Test success\n");
    }
    else
    {
        printf("Enc2Test fail\n");
    }
    printf("-----------End Enc2Test----------\n");
}

void EMSCRIPTEN_KEEPALIVE ReEncTest()
{
    printf("-----------Strat ReEncTest----------\n");
    KeyPair keypair_i = KeyGen();
    KeyPair keypair_j = KeyGen();
    char* m = (char *) malloc(n + 1);
    random_bitstring(m, n);
    char* w = "hello world";
    CipherText ciphertext = Enc2(keypair_i.pk,w, m);
    ReKeyPair rekeypair = ReKeyGen(keypair_i.sk, w, keypair_j.pk, keypair_i.pk);
    CipherText ciphertext_reEnc = ReEnc(ciphertext, rekeypair);
    char* m1 = Dec1(ciphertext_reEnc, keypair_j.sk, keypair_j.pk);
    printf("Message = %s\n", m);
    printf("DecryptResult = %s\n", m1);
    //比较解密结果
    if(strcmp(m, m1) == 0)
    {
        printf("ReEncTest success\n");
    }
    else
    {
        printf("ReEncTest fail\n");
    }
    printf("-----------End RecEncTest----------\n");
}



#ifdef __cplusplus
}
#endif

void bytes_to_bits( unsigned char *bytes, int byte_len, char *bitstring, int n) {
    int i, j;
    int bit_index = 0;
    for (i = 0; i < byte_len && bit_index < n; i++) {
        for (j = 7; j >= 0 && bit_index < n; j--) {
            bitstring[bit_index++] = (bytes[i] & (1 << j)) ? '1' : '0';
        }
    }
    bitstring[bit_index] = '\0';  // 结束符
}

void xor_bitstrings(char *result, char *str1, char *str2) {
    int n = strlen(str1);
    for (int i = 0; i < n; i++) {
        // 逐位进行异或 ('0' 异或 '0' 为 '0', '0' 异或 '1' 为 '1', '1' 异或 '1' 为 '0')
        if (str1[i] == str2[i]) {
            result[i] = '0';  // 相同为 '0'
        } else {
            result[i] = '1';  // 不同为 '1'
        }
    }
    result[n] = '\0';  // 确保字符串以 '\0' 结束
}

// 生成n位的随机比特串
void random_bitstring(char *bitstring, int n) {
    time_t t;
    srand((unsigned) time(&t));
    for (int i = 0; i < n; i++) {
        bitstring[i] = rand() % 2 ? '1' : '0';
    }
    bitstring[n] = '\0'; 
}

int main()
{
  printf("main start\n");
  // 加密系统初始化
  Setup(50);//设置n的大小

  Enc1Test();
  Enc2Test();
  ReEncTest();

  
  element_clear(g);
  element_clear(Z);
  pairing_clear(pairing);
  printf("main finish\n");
  return 0;
}
