#include <stdio.h>
#include <emscripten/emscripten.h>
#include <pbc/pbc.h>
#include <string.h>
#include "sha256.h"
#include "c_pre.h"
#include <time.h>
#include <ctype.h>


/*
[0x23, 0x3A, 0x46, 0x4C, 0x52] ==> “233A464C52”
*/
uint32_t ByteStrToHexStr(const uint8_t * src_buf, int src_len, uint8_t * dest_buf)
{
    uint8_t highHex, lowHex;
    if(NULL == src_buf)
		return 1;
	const uint8_t * index = src_buf, * end = src_buf + src_len;
    uint8_t * ridx = dest_buf;
    
    while (index < end)
    {
        highHex = (* index) >> 4;
        lowHex = (* index) & 0x0F;
        index ++;

        if (highHex > 0x09)
            highHex += 0x57;
        else
            highHex += 0x30;

        if (lowHex > 0x09)
            lowHex += 0x57;
        else
            lowHex += 0x30;

        *ridx ++ = highHex;
        *ridx ++ = lowHex;
    }
    return 0;
}

/*
 “233A464C52” ==>[0x23, 0x3A, 0x46, 0x4C, 0x52]
*/
uint32_t HexStrToByteStr(const uint8_t * src_buf, int src_len, uint8_t * dest_buf)
{
    uint8_t highByte, lowByte;
    if(NULL == src_buf)
		return 1;
	const uint8_t * index = src_buf, * end = src_buf + src_len;
    uint8_t * ridx = dest_buf;
    
    while (index < end)
    {
        highByte = tolower(* (index ++));
        lowByte  = tolower(* (index ++));

        if (highByte > 0x39)
            highByte -= 0x57;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x57;
        else
            lowByte -= 0x30;

        *ridx ++ = (highByte << 4) | lowByte;
    }

    printf("ByteStrToHexStr start:\n");
    for(int i=0;i<src_len/2;i++){
        printf("%02x ", dest_buf[i]);
    }
    printf("\nByteStrToHexStr end:\n");
    return 0;
}
// "11010011" --> 0xD3
void bits_to_bytes( uint8_t *bitstring, int bit_len, uint8_t *bytes) {
    printf("bits_to_bytes, bitstring = %s\n", bitstring);
    int i, j;
    int byte_index = 0;
    int n = bit_len / 8;
    for (i = 0; i < bit_len && byte_index < n; ) {
        bytes[byte_index]= bitstring[i++] - '0';
        // printf("%02x %c\n", bytes[byte_index],bitstring[i]);
        for (j = 1; j < 8 && i < bit_len; j++) {
            bytes[byte_index] = (bytes[byte_index] << 1) | (bitstring[i++] - '0');
            // printf("%02x %c\n", bytes[byte_index], bitstring[i]);
        }
        // printf("bytes[%d]= %02x\n", byte_index, bytes[byte_index]);
        byte_index ++;
    }
    bytes[byte_index] = '\0';  // 结束符
}

void bytes_to_bits( uint8_t *bytes, int byte_len, uint8_t *bitstring) {
    int i, j;
    int bit_index = 0;
    int n = byte_len * 8;
    for (i = 0; i < byte_len && bit_index < n; i++) {
        for (j = 7; j >= 0 && bit_index < n; j--) {
            bitstring[bit_index++] = (bytes[i] & (1 << j)) ? '1' : '0';
        }
    }
    bitstring[bit_index] = '\0';  // 结束符
}

//这里要求str1和str2的长度必须一致，否则会越界，这里都是256
void xor_bitstrings(uint8_t *result, uint8_t *str1, uint8_t *str2) {
    int n = strlen((const char *)str1);
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

void Setup(pairing_t pairing, element_t g, element_t Z)
{
    char *param="type a\n\
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n\
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n\
r 730750818665451621361119245571504901405976559617\n\
exp2 159\n\
exp1 107\n\
sign1 1\n\
sign0 1";
    // size_t count = fread(param, 1, 1024, stdin);
    // if (!count)
    //     pbc_die("input error");
    size_t count = strlen(param);
    printf("count=%d\n", count);
    pairing_init_set_buf(pairing, param, count);
    element_init_G1(g, pairing);
    // element_random(g);
    element_from_hash(g, "31415926", strlen("31415926"));
    element_init_GT(Z, pairing);
    pairing_apply(Z, g, g, pairing);
    uint8_t g_bytes[1024];
    size_t g_len = element_length_in_bytes(g);
    element_to_bytes(g_bytes, g);
    printf("g_len = %d, g=\n", g_len);
    for(int i=0;i<g_len;i++){
        printf("%02x ", g_bytes[i]);
    }
    printf("\n");
    uint8_t Z_bytes[1024];
    size_t Z_len = element_length_in_bytes(Z);
    element_to_bytes(Z_bytes, Z);
    printf("Z_len = %d, Z=\n", Z_len);
    for(int i=0;i<Z_len;i++){
        printf("%02x ", Z_bytes[i]);
    }
    printf("\n");

    
}

//Hash1 {0,1}* -> Zq
// 注意：m是以\0结束的字符串
void Hash1(element_t result, uint8_t * m, element_t R)
{
    int R_len = element_length_in_bytes(R);
    uint8_t *R_bytes = (uint8_t *) malloc(R_len);
    element_to_bytes(R_bytes, R);  // 序列化 GT 群中的元素 R
    
    // 获取输入字符串 m 的长度
    int m_len = strlen((const char *)m);
    
    // 合并 m 和 R_bytes
    uint8_t *hash_input = (uint8_t *) malloc(m_len + R_len);
    memcpy(hash_input, m, m_len);
    memcpy(hash_input + m_len, R_bytes, R_len);
    
    uint8_t hash[SHA256_DIGEST_LENGTH_32];
    sha256_context ctx;
    sha256_starts( &ctx );
    sha256_update( &ctx, (uint8 *) hash_input, m_len + R_len );
    sha256_finish( &ctx, hash );
    
    // 将哈希值转化为大整数
    mpz_t hash_int;
    mpz_init(hash_int);
    mpz_import(hash_int, SHA256_DIGEST_LENGTH_32, 1, sizeof(hash[0]), 0, 0, hash);

    // 对 hash_int 取模并存入 result
    // element_init_Zr(result, pairing);  // 初始化 result 为 Zq 上的元素，调用前需要初始化，这样就不用传递pairing了
    element_set_mpz(result, hash_int);  // 将哈希值映射到 Zq 上
    
    // 释放内存
    free(R_bytes);
    free(hash_input);
    mpz_clear(hash_int);
}

//Hash2 {0,1}* -> G1
// 注意：w是以\0结束的字符串
void Hash2(element_t result, element_t pk,  uint8_t * w) {

    sha256_context ctx;
    sha256_starts( &ctx );

    uint8_t hash[SHA256_DIGEST_LENGTH_32];
    size_t pk_len = element_length_in_bytes(pk);
    size_t w_len = strlen((const char *)w);
    uint8_t * hash_input = (uint8_t *) malloc(pk_len + w_len);

    // 将 pk 转换为字节形式
    element_to_bytes(hash_input, pk); 

    // 将 w 也转换为字节形式，并拼接到 combined_input 中
    memcpy(hash_input + pk_len, w, w_len);

    sha256_update( &ctx, (uint8 *) hash_input, pk_len + w_len );
    sha256_finish( &ctx, hash );
    // element_init_G1(result, pairing); //调用前需要初始化，这样就不用传递pairing了
    // 将哈希值映射到群元素
    element_from_hash(result, hash, SHA256_DIGEST_LENGTH_32); // result 是群元素

    free(hash_input);
}


// Hash3 G1 -> {0,1}^n
void Hash3(uint8_t *bitstring, element_t R){
    // 获取 G1 群元素 R 的字节表示
    int R_len = element_length_in_bytes(R);
    uint8_t *R_bytes = (uint8_t *) malloc(R_len);
    element_to_bytes(R_bytes, R);  // 序列化 G1 群中的元素 R

    uint8_t hash[SHA256_DIGEST_LENGTH_32];
    sha256_context ctx;
    sha256_starts( &ctx );
    sha256_update( &ctx, (uint8 *) R_bytes, R_len );
    sha256_finish( &ctx, hash );

    // 将哈希结果转化为二进制比特串
    bytes_to_bits(hash, SHA256_DIGEST_LENGTH_32, bitstring);
    // 释放内存
    free(R_bytes);
}

void Hash4(element_t result, element_t c1, element_t c2,  uint8_t* c3) {
    sha256_context ctx;
    sha256_starts( &ctx );

    // 获取 G1 群元素 c1 的字节长度
    size_t c1_len = element_length_in_bytes(c1);
    // 获取 GT 群元素 c2 的字节长度
    size_t c2_len = element_length_in_bytes(c2);
    // 获取 c3 的长度
    size_t c3_len = strlen((const char *)c3);

    // 分配足够大的缓冲区来存储 c1, c2 和 c3 的拼接结果
    uint8_t * hash_input = (uint8_t *) malloc(c1_len + c2_len + c3_len);

    // 将 c1 转换为字节形式
    element_to_bytes(hash_input, c1);

    // 将 c2 转换为字节形式，并拼接到 combined_input 中
    element_to_bytes(hash_input + c1_len, c2);

    // 将 c3 拼接到 combined_input 中
    memcpy(hash_input + c1_len + c2_len, c3, c3_len);

    // 进行 SHA256 哈希
    uint8_t hash[SHA256_DIGEST_LENGTH_32];
    sha256_update( &ctx, (uint8 *) hash_input, c1_len + c2_len + c3_len );
    sha256_finish( &ctx, hash );

    // element_init_G1(result, pairing);////调用前需要初始化，这样就不用传递pairing了
    // 将哈希值映射到群元素 result
    element_from_hash(result, hash, SHA256_DIGEST_LENGTH_32);  // 将哈希值映射为群元素
    free(hash_input);

}


// ReKeyPair ReKeyGen(element_t ski, char* w, element_t pkj, element_t pki) //pki不在输入中
// {
//     ReKeyPair rk_ij;
//     element_init_G1(rk_ij.rk1, pairing);
//     element_init_G1(rk_ij.rk2, pairing);
//     element_t hashresult, powresult, s, negski;
//     element_init_G1(powresult, pairing);
//     element_init_G1(hashresult, pairing);
//     element_init_Zr(negski, pairing);
//     element_init_Zr(s, pairing);
//     element_random(s);
//     Hash2(hashresult, pki, w);
//     element_pow_zn(powresult, pkj, s);
//     // element_mul(rk_ij.rk1, powresult, hashresult);
//     element_mul(rk_ij.rk1, hashresult, powresult);
//     element_neg(negski, ski);
//     element_pow_zn(rk_ij.rk1, rk_ij.rk1, negski);
//     element_pow_zn(rk_ij.rk2, pki, s);
//     element_clear(hashresult);
//     element_clear(powresult);
//     element_clear(s);
//     element_clear(negski);
//     return rk_ij;
// }

// CipherText Enc2(element_t pk,  char* w,  char* m)
// {
//     CipherText ciphertext;
//     element_init_G1(ciphertext.c1, pairing);
//     element_init_GT(ciphertext.c2, pairing);
//     element_init_G1(ciphertext.c4, pairing);
//     // 为 ciphertext.c3 分配内存
//     ciphertext.c3 = (char *) malloc(n + 1);
//     element_t R, r, hash2result, eresult, hash4result;
//     element_init_GT(R, pairing);
//     element_random(R);
//     element_init_Zr(r, pairing);
//     element_init_G1(hash2result, pairing);
//     element_init_GT(eresult, pairing);
//     element_init_G1(hash4result, pairing);
//     Hash1(r, m, R); 
//     element_pow_zn(ciphertext.c1, g, r);
//     Hash2(hash2result, pk, w);
//     element_pairing(eresult, pk, hash2result);
//     element_pow_zn(eresult, eresult, r);
//     element_mul(ciphertext.c2, R, eresult);
//     char *hash3result = (char *) malloc(n + 1);
//     Hash3(hash3result, R);
//     xor_bitstrings(ciphertext.c3, m, hash3result);
//     Hash4(hash4result, ciphertext.c1, ciphertext.c2, ciphertext.c3);
//     element_pow_zn(ciphertext.c4, hash4result, r);
//     element_clear(R);
//     element_clear(r);
//     element_clear(hash2result);
//     element_clear(eresult);
//     element_clear(hash4result);
//     free(hash3result);
//     return ciphertext;
// }

// CipherText Enc1(element_t pk, char* m)
// {
//     CipherText ciphertext;
//     element_init_G1(ciphertext.c1, pairing);
//     element_init_GT(ciphertext.c2, pairing);
//     element_init_G1(ciphertext.c4, pairing);
//     // 为 ciphertext.c3 分配内存
//     ciphertext.c3 = (char *) malloc(n + 1);
//     element_t R, r, s0, eresult, emuls;
//     element_init_GT(R, pairing);
//     element_random(R);
//     element_init_Zr(s0, pairing);
//     element_random(s0);
//     element_init_Zr(r, pairing);
//     element_init_GT(eresult, pairing);
//     element_init_Zr(emuls, pairing);
//     Hash1(r, m, R); 
//     element_pow_zn(ciphertext.c1, g, r);
//     element_mul(emuls, s0, r);
//     element_neg(emuls, emuls);
//     element_pairing(eresult, g, pk);
//     element_pow_zn(eresult, eresult, emuls);
//     element_mul(ciphertext.c2, R, eresult);
//     char *hash3result = (char *) malloc(n + 1);
//     Hash3(hash3result, R);
//     xor_bitstrings  (ciphertext.c3, m, hash3result);
//     element_pow_zn(ciphertext.c4, g, s0);
//     element_clear(R);
//     element_clear(r);
//     element_clear(eresult);
//     element_clear(emuls);
//     free(hash3result);
//     return ciphertext;
// }

// char* Dec2(CipherText CipherText, element_t sk, element_t pk, char* w)
// {
//     element_t hash2result, eresult, R;
//     element_init_G1(hash2result, pairing);
//     element_init_GT(eresult, pairing);
//     element_init_GT(R, pairing);

//     Hash2(hash2result, pk, w);
//     element_pairing(eresult, CipherText.c1, hash2result);
//     element_pow_zn(eresult, eresult, sk);
//     element_invert(eresult, eresult);
//     element_mul(R, CipherText.c2, eresult);
//     char *hash3result = (char *) malloc(n + 1);
//     Hash3(hash3result, R);
//     char *m = (char *) malloc(n + 1);
//     xor_bitstrings(m, CipherText.c3, hash3result);

//     //verify g^H1(m, R) == C1
//     element_t hash1result;
//     element_init_Zr(hash1result, pairing);
//     Hash1(hash1result, m, R); 
//     element_t C1_2;
//     element_init_G1(C1_2, pairing);
//     element_pow_zn(C1_2, g, hash1result);
//     if (element_cmp(C1_2, CipherText.c1) != 0) {
//         printf("verify g^H1(m, R) == C1 fail\n");
//         element_clear(hash1result);
//         element_clear(C1_2);
//         element_clear(hash2result);
//         element_clear(eresult);
//         element_clear(R);
//         free(hash3result);
//         // 处理错误，或返回 ⊥
//         return NULL;
//     }
//     printf("verify g^H1(m, R) == C1 success\n");


//     element_clear(hash2result);
//     element_clear(eresult);
//     element_clear(R);
//     free(hash3result);
//     return m;
// }

// CipherText ReEnc(CipherText CT_i, ReKeyPair rekeypair) {
//     CipherText CT_j;
    
//     // 初始化 CT_j 的元素
//     element_init_G1(CT_j.c1, pairing);
//     element_init_GT(CT_j.c2, pairing);
//     element_init_G1(CT_j.c4, pairing);
//     CT_j.c3 = (char *) malloc(n + 1);  // n 是比特长度，根据需要调整

//     // 计算双线性对 e(C1, H4(C1, C2, C3))
//     element_t H4_result, pairing1, pairing2;
//     element_init_GT(pairing1, pairing);
//     element_init_GT(pairing2, pairing);
//     element_init_G1(H4_result, pairing);

//     // 计算 H4(C1, C2, C3)
//     Hash4(H4_result, CT_i.c1, CT_i.c2, CT_i.c3);

//     // 计算双线性对 e(C1, H4(C1, C2, C3))
//     element_pairing(pairing1, CT_i.c1, H4_result);

//     // 计算双线性对 e(g, C4)
//     element_pairing(pairing2, g, CT_i.c4);

//     // 检查双线性对是否相等
//     if (element_cmp(pairing1, pairing2) != 0) {
//         printf("双线性对检查失败，返回 NULL 密文\n");
//         element_clear(CT_j.c1);
//         element_clear(CT_j.c2);
//         element_clear(CT_j.c4);
//         free(CT_j.c3);
//         // 处理错误，或返回 ⊥
//         return CT_j;
//     }

//     // 双线性对匹配，继续重加密
//     // C̄1 = C1
//     element_set(CT_j.c1, CT_i.c1);

//     // C̄2 = C2 · e(C1, rk1)
//     element_t pairing3;
//     element_init_GT(pairing3, pairing);
//     element_pairing(pairing3, CT_i.c1, rekeypair.rk1);
//     element_mul(CT_j.c2, CT_i.c2, pairing3);

//     // C̄3 = C3 (复制第三部分)
//     strcpy(CT_j.c3, CT_i.c3);

//     // C̄4 = rk2
//     element_set(CT_j.c4, rekeypair.rk2);

//     // 清除临时变量
//     element_clear(H4_result);
//     element_clear(pairing1);
//     element_clear(pairing2);
//     element_clear(pairing3);
//     return CT_j;
// }

// char* Dec1(CipherText CT, element_t sk, element_t pk)
// {
//     element_t R, eresult;
//     element_init_GT(R, pairing);
//     element_init_GT(eresult, pairing);

//     element_pairing(eresult, CT.c1, CT.c4);
//     element_pow_zn(eresult, eresult, sk);
//     element_mul(R, CT.c2, eresult);
//     char *hash3result = (char *) malloc(n + 1);
//     Hash3(hash3result, R);
//     char *m = (char *) malloc(n + 1);
//     xor_bitstrings(m, CT.c3, hash3result);
//     element_clear(R);
//     element_clear(eresult);
//     free(hash3result);
//     return m;
// }


// #ifdef __cplusplus
// extern "C" {
// #endif


// void EMSCRIPTEN_KEEPALIVE Enc1Test()
// {
//     printf("-----------Strat Enc1Test----------\n");
//     KeyPair keypair = KeyGen();
//     //生成n位的随机比特串
//     char* m = (char *) malloc(n + 1);
//     random_bitstring(m, n);
//     // char* m = "1001011";
//     CipherText ciphertext = Enc1(keypair.pk, m);
//     char* m1 = Dec1(ciphertext, keypair.sk, keypair.pk);
//     printf("Message = %s\n", m);
//     printf("DecryptResult = %s\n", m1);
//     //比较解密结果
//     if(strcmp(m, m1) == 0)
//     {
//         printf("Enc1Test success\n");
//     }
//     else
//     {
//         printf("Enc1Test fail\n");
//     }
//     printf("-----------End Enc1Test----------\n");
// }

// void EMSCRIPTEN_KEEPALIVE Enc2Test()
// {
//     printf("-----------Strat Enc2Test----------\n");
//     KeyPair keypair = KeyGen();
//     char* m = (char *) malloc(n + 1);
//     random_bitstring(m, n);
//     char* w = "hello world";
//     CipherText ciphertext = Enc2(keypair.pk,w, m);
//     char* m1 = Dec2(ciphertext, keypair.sk, keypair.pk, w);
//     printf("Message = %s\n", m);
//     printf("DecryptResult = %s\n", m1);
//     if(strcmp(m, m1) == 0)
//     {
//         printf("Enc2Test success\n");
//     }
//     else
//     {
//         printf("Enc2Test fail\n");
//     }
//     printf("-----------End Enc2Test----------\n");
// }

// void EMSCRIPTEN_KEEPALIVE ReEncTest()
// {
//     printf("-----------Strat ReEncTest----------\n");
//     KeyPair keypair_i = KeyGen();
//     KeyPair keypair_j = KeyGen();
//     char* m = (char *) malloc(n + 1);
//     random_bitstring(m, n);
//     char* w = "hello world";
//     CipherText ciphertext = Enc2(keypair_i.pk,w, m);
//     ReKeyPair rekeypair = ReKeyGen(keypair_i.sk, w, keypair_j.pk, keypair_i.pk);
//     CipherText ciphertext_reEnc = ReEnc(ciphertext, rekeypair);
//     char* m1 = Dec1(ciphertext_reEnc, keypair_j.sk, keypair_j.pk);
//     printf("Message = %s\n", m);
//     printf("DecryptResult = %s\n", m1);
//     //比较解密结果
//     if(strcmp(m, m1) == 0)
//     {
//         printf("ReEncTest success\n");
//     }
//     else
//     {
//         printf("ReEncTest fail\n");
//     }
//     printf("-----------End RecEncTest----------\n");
// }


// void EMSCRIPTEN_KEEPALIVE main_test()
// {
//   printf("main_test start\n");
//   // 加密系统初始化
//   printf("Setup start\n");
//   Setup(50);//设置n的大小
//   printf("Setup finish\n");

//   printf("Enc1Test start\n");
//   Enc1Test();
//   printf("Enc1Test finish\n");

//   printf("Enc2Test start\n");
//   Enc2Test();
//   printf("Enc2Test finish\n");

//   printf("ReEncTest start\n");
//   ReEncTest();
//   printf("ReEncTest finish\n");

  
//   element_clear(g);
//   element_clear(Z);
//   pairing_clear(pairing);
//   printf("main_test finish\n");

// }

// char* EMSCRIPTEN_KEEPALIVE keyGenTest(char *inArray, int inLen, char *outArray, int *outLen) {
//     printf("inLen=%d\n", inLen);
//     for(int i=0;i<inLen;i++) {
//         printf("%02x", inArray[i]);
//     }
//     printf("\n");
//     const char *my_string = "12345\007abcdefg";
//     (*outLen) = strlen(my_string);
//     memcpy(outArray, my_string, (*outLen));
//     printf("outLen=%d\n", (*outLen));
//     return outArray;
// }



// #ifdef __cplusplus
// }
// #endif


// // 生成n位的随机比特串
// void random_bitstring(char *bitstring, int n) {
//     time_t t;
//     srand((unsigned) time(&t));
//     for (int i = 0; i < n; i++) {
//         bitstring[i] = rand() % 2 ? '1' : '0';
//     }
//     bitstring[n] = '\0'; 
// }

// int main_test()
// {
//   printf("main start\n");
//   // 加密系统初始化
//   printf("Setup start\n");
//   Setup(50);//设置n的大小
//   printf("Setup finish\n");

//   printf("Enc1Test start\n");
//   Enc1Test();
//   printf("Enc1Test finish\n");

//   printf("Enc2Test start\n");
//   Enc2Test();
//   printf("Enc2Test finish\n");

//   printf("ReEncTest start\n");
//   ReEncTest();
//   printf("ReEncTest finish\n");

  
//   element_clear(g);
//   element_clear(Z);
//   pairing_clear(pairing);
//   printf("main finish\n");
//   return 0;
// }


int KeyGen(uint8_t *pk_Hex, int *p_pk_Hex_len, uint8_t *sk_Hex, int *p_sk_Hex_len)
{
    printf("********************************\n");
    printf("**********KeyGen start************\n");
    printf("********************************\n");
    pairing_t pairing;
    element_t g;
    element_t Z;
    KeyPair keypair;
    Setup(pairing, g, Z);

    uint8_t g_bytes[1024];
    size_t g_len = element_length_in_bytes(g);
    element_to_bytes(g_bytes, g);
    printf("g_len = %d, g=\n", g_len);
    for(int i=0;i<g_len;i++){
        printf("%02x ", g_bytes[i]);
    }
    printf("\n");

    uint8_t hash[SHA256_DIGEST_LENGTH_32];
    sha256_context ctx;
    sha256_starts( &ctx );
    sha256_update( &ctx, (uint8 *) g_bytes, g_len );
    sha256_finish( &ctx, hash );
    printf("hash(g_bytes)=\n");
    for(int i=0;i<SHA256_DIGEST_LENGTH_32;i++) {
        printf("%02x ", hash[i]);
    }
    printf("\n");

    printf("n=%d\n", n);

    element_init_G1(keypair.pk, pairing);
    element_init_Zr(keypair.sk, pairing);
    element_random(keypair.sk);
    element_pow_zn(keypair.pk, g, keypair.sk);

    size_t pk_len = element_length_in_bytes(keypair.pk);
    size_t sk_len = element_length_in_bytes(keypair.sk);
    if (pk_len != G1_ELEMENT_LENGTH_IN_BYTES ||
        sk_len != ZR_ELEMENT_LENGTH_IN_BYTES)
    {
        printf("pk_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", pk_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("sk_len = %d, ZR_ELEMENT_LENGTH_IN_BYTES = %d\n", sk_len, ZR_ELEMENT_LENGTH_IN_BYTES);
        printf("exit \n");
        element_clear(keypair.pk);
        element_clear(keypair.sk);
        element_clear(Z);
        element_clear(g);
        pairing_clear(pairing);
        return -1;
    }
    
    uint8_t pk_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    uint8_t sk_bytes[ZR_ELEMENT_LENGTH_IN_BYTES];

    (*p_pk_Hex_len) = element_to_bytes(pk_bytes, keypair.pk);
    (*p_sk_Hex_len) = element_to_bytes(sk_bytes, keypair.sk);

    ByteStrToHexStr(pk_bytes, (*p_pk_Hex_len), pk_Hex);
    ByteStrToHexStr(sk_bytes, (*p_sk_Hex_len), sk_Hex);
    printf("(*p_pk_len) = %d, pk_bytes=\n", (*p_pk_Hex_len));
    for(int i=0;i<(*p_pk_Hex_len);i++){
        printf("%02x ", pk_bytes[i]);
    }
    printf("\n");
    printf("(*p_sk_Hex_len) = %d, sk_bytes=\n", (*p_sk_Hex_len));
    for(int i=0;i<(*p_sk_Hex_len);i++){
        printf("%02x ", sk_bytes[i]);
    }
    printf("\n");
    (*p_pk_Hex_len) *= 2;
    (*p_sk_Hex_len) *= 2;

    printf("(*p_pk_Hex_len) = %d, pk_Hex=\n", (*p_pk_Hex_len));
    for(int i=0;i<(*p_pk_Hex_len);i++) {
        printf("%c", pk_Hex[i]);
    }
    printf("\n");
    printf("(*p_sk_Hex_len) = %d, sk_Hex=\n", (*p_sk_Hex_len));
    for(int i=0;i<(*p_sk_Hex_len);i++) {
        printf("%c", sk_Hex[i]);
    }
    printf("\n");

    element_clear(keypair.pk);
    element_clear(keypair.sk);
    element_clear(Z);
    element_clear(g);
    pairing_clear(pairing);

    printf("********************************\n");
    printf("**********KeyGen end************\n");
    printf("********************************\n");

    return 0;
}

//m,w是以\0结束的字符串，代码中使用strlen()确定实际长度
//m是AES-GCM key，长度是256bit，32字节
//输出c1,c2,c3,c4，其中c1, c2, c4转为bytes后再转为Hex,c3直接转为Hex，所有长度都是固定的，无需输出
int Enc2(uint8_t *pk_Hex, int pk_Hex_len, 
    uint8_t *m_bytes,
    uint8_t *w,
    uint8_t *c1_Hex, uint8_t *c2_Hex, uint8_t *c3_Hex, uint8_t *c4_Hex
    )
{
    printf("********************************\n");
    printf("**********Enc2 start************\n");
    printf("********************************\n");
    if(pk_Hex_len != (G1_ELEMENT_LENGTH_IN_BYTES * 2) )
    {
        printf("error pk_Hex_len = %d\n", pk_Hex_len);
        printf("pk_Hex_len should equal to  %d\n", G1_ELEMENT_LENGTH_IN_BYTES * 2);
        return -1;
    }

    //先把m_bytes转成bit
    int m_len = strlen((const char *)m_bytes) * 8 + 1;
    uint8_t *m = (uint8_t *)malloc(m_len);
    bytes_to_bits(m_bytes, strlen((const char *)m_bytes), m);
    printf("m=%s\n", m);

    pairing_t pairing;
    element_t g;
    element_t Z;
    KeyPair keypair;
    Setup(pairing, g, Z);

    //import pk
    uint8_t pk_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    printf("pk_Hex=\n");
    for(int i=0;i<G1_ELEMENT_LENGTH_IN_BYTES * 2;i++) {
        printf("%c", (unsigned int)pk_Hex[i]);
    }
    printf("\n");
    int iret = HexStrToByteStr((uint8_t *)pk_Hex, pk_Hex_len, pk_bytes);
    printf("pk_bytes=\n");
    for(int i=0;i<G1_ELEMENT_LENGTH_IN_BYTES;i++) {
        printf("%02x ", pk_bytes[i]);
    }
    printf("\n");

    element_init_G1(keypair.pk, pairing);
    printf("ok0\n");
    int pk_len = element_from_bytes(keypair.pk, (uint8_t *)pk_bytes);
    printf("ok1\n");
    CipherText ciphertext;
    element_init_G1(ciphertext.c1, pairing);
    element_init_GT(ciphertext.c2, pairing);
    element_init_G1(ciphertext.c4, pairing);
    printf("ok2\n");
    // 为 ciphertext.c3 分配内存
    ciphertext.c3 = (uint8_t *) malloc(SHA256_DIGEST_LENGTH_32 * 8 + 1);
    element_t R, r, hash2result, eresult, hash4result;
    element_init_GT(R, pairing);
    element_random(R);
    //r在调用Hash1前需要完成初始化
    element_init_Zr(r, pairing);
    
    //m是以\0结束的字符串
    Hash1(r, m, R); 
    printf("ok3\n");
    //get c1
    element_pow_zn(ciphertext.c1, g, r);

    //hash2result在调用Hash2前需要完成初始化，w是以\0结束的字符串
    element_init_G1(hash2result, pairing);
    Hash2(hash2result, keypair.pk, w);
    printf("ok4\n");
    uint8_t hash2result_bytes[8196];
    int len = element_to_bytes(hash2result_bytes, hash2result); 
    printf("hash2result_bytes:\n");
    for(int i=0;i<len;i++) {
        printf("%02x ", hash2result_bytes[i]);
    }
    printf("\n");

    element_init_GT(eresult, pairing);
    element_pairing(eresult, keypair.pk, hash2result);
    element_pow_zn(eresult, eresult, r);
    //get c2
    element_mul(ciphertext.c2, R, eresult);
    
    //最后以\0结束，这里需要修改，hash3result应该是256 + 1
    uint8_t *hash3result = (uint8_t *) malloc(SHA256_DIGEST_LENGTH_32 * 8 + 1);
    Hash3(hash3result, R);
    printf("ok5\n");
    //get c3
    xor_bitstrings(ciphertext.c3, m, hash3result);

    //hash4result在调用Hash4前需要完成初始化
    element_init_G1(hash4result, pairing);
    Hash4(hash4result, ciphertext.c1, ciphertext.c2, ciphertext.c3);
    printf("ok6\n");
    //get c4
    element_pow_zn(ciphertext.c4, hash4result, r);

    //c1, c2, c4 conver to bytes
    int c1_len = element_length_in_bytes(ciphertext.c1);
    int c2_len = element_length_in_bytes(ciphertext.c2);
    int c4_len = element_length_in_bytes(ciphertext.c4);
    if (c1_len != G1_ELEMENT_LENGTH_IN_BYTES ||
        c2_len != GT_ELEMENT_LENGTH_IN_BYTES ||
        c4_len != G1_ELEMENT_LENGTH_IN_BYTES)
    {
        printf("c1_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", 
            c1_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("c2_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", 
            c2_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("c4_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", 
            c4_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("exit \n");
        free(m);
        element_clear(R);
        element_clear(r);
        element_clear(hash2result);
        element_clear(eresult);
        element_clear(hash4result);
        free(hash3result);
        element_clear(ciphertext.c4);
        free(ciphertext.c3);
        element_clear(ciphertext.c2);
        element_clear(ciphertext.c1);
        element_clear(keypair.pk);
        element_clear(Z);
        element_clear(g);
        pairing_clear(pairing);
        return -1;
    }
    uint8_t c1_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    uint8_t c2_bytes[GT_ELEMENT_LENGTH_IN_BYTES];
    uint8_t c4_bytes[G1_ELEMENT_LENGTH_IN_BYTES];

    element_to_bytes(c1_bytes, ciphertext.c1);
    element_to_bytes(c2_bytes, ciphertext.c2);
    element_to_bytes(c4_bytes, ciphertext.c4);
    printf("c1:\n");
    for(int i=0;i<G1_ELEMENT_LENGTH_IN_BYTES;i++) {
        printf("%02x ", c1_bytes[i]);
    }
    printf("\n");
    printf("c2:\n");
    for(int i=0;i<GT_ELEMENT_LENGTH_IN_BYTES;i++) {
        printf("%02x ", c2_bytes[i]);
    }
    printf("\n");
    printf("c3:\n");
    for(int i=0;i<SHA256_DIGEST_LENGTH_32 * 8;i++) {
        printf("%02x ", ciphertext.c3[i]);
    }
    printf("\n");
    printf("c4:\n");
    for(int i=0;i<G1_ELEMENT_LENGTH_IN_BYTES;i++) {
        printf("%02x ", c4_bytes[i]);
    }
    printf("\n");

    //c1, c2, c3, c4 convert to Hex
    ByteStrToHexStr(c1_bytes, G1_ELEMENT_LENGTH_IN_BYTES, c1_Hex);
    ByteStrToHexStr(c2_bytes, GT_ELEMENT_LENGTH_IN_BYTES, c2_Hex);
    ByteStrToHexStr(ciphertext.c3, SHA256_DIGEST_LENGTH_32 * 8, c3_Hex);
    ByteStrToHexStr(c4_bytes, G1_ELEMENT_LENGTH_IN_BYTES, c4_Hex);



    free(m);
    element_clear(R);
    element_clear(r);
    element_clear(hash2result);
    element_clear(eresult);
    element_clear(hash4result);
    free(hash3result);

    element_clear(ciphertext.c4);
    free(ciphertext.c3);
    element_clear(ciphertext.c2);
    element_clear(ciphertext.c1);
    element_clear(keypair.pk);
    element_clear(Z);
    element_clear(g);
    pairing_clear(pairing);

    printf("********************************\n");
    printf("**********Enc2 end************\n");
    printf("********************************\n");
    return 0;
}

int importCipherText(CipherText *ciphertext, 
    uint8_t *c1_Hex, int c1_Hex_len,
    uint8_t *c2_Hex, int c2_Hex_len,
    uint8_t *c3_Hex, int c3_Hex_len,
    uint8_t *c4_Hex, int c4_Hex_len)
{
    printf("********************************\n");
    printf("**********importCipherText start************\n");
    printf("********************************\n");
    if(c1_Hex_len != (G1_ELEMENT_LENGTH_IN_BYTES * 2) ||
       c2_Hex_len != (GT_ELEMENT_LENGTH_IN_BYTES * 2) ||
       c3_Hex_len != (SHA256_DIGEST_LENGTH_32 * 8 * 2) ||
       c4_Hex_len != (G1_ELEMENT_LENGTH_IN_BYTES * 2) )
    {
        printf("c1_Hex_len = %d, c1_Hex_len should equal to  %d\n", 
            c1_Hex_len, G1_ELEMENT_LENGTH_IN_BYTES * 2);
        printf("c2_Hex_len = %d, c2_Hex_len should equal to  %d\n", 
            c2_Hex_len, GT_ELEMENT_LENGTH_IN_BYTES * 2);
        printf("c3_Hex_len = %d, c3_Hex_len should equal to  %d\n", 
            c3_Hex_len, SHA256_DIGEST_LENGTH_32 * 8 * 2);
        printf("c4_Hex_len = %d, c4_Hex_len should equal to  %d\n", 
            c4_Hex_len, G1_ELEMENT_LENGTH_IN_BYTES * 2);  
        return -1;
    }

    //import c1
    uint8_t c1_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    printf("before HexStrToByteStr, c1_Hex=\n");
    for(int i=0;i<c1_Hex_len;i++) {
        printf("%c", (unsigned int)c1_Hex[i]);
    }
    printf("\n");
    int iret = HexStrToByteStr((uint8_t *)c1_Hex, c1_Hex_len, c1_bytes);
    printf("after HexStrToByteStr, c1_bytes=\n");
    for(int i=0;i<c1_Hex_len/2;i++) {
        printf("%02x ", c1_bytes[i]);
    }
    printf("\n");

    //ciphertext需要在调用importCipherText前完成初始化，这样就不用传递pairing
    // element_init_G1(ciphertext->c1, pairing); 
    int c1_len = element_from_bytes(ciphertext->c1, (uint8_t *)c1_bytes);

    //import c2
    uint8_t c2_bytes[GT_ELEMENT_LENGTH_IN_BYTES];
    printf("before HexStrToByteStr, c2_Hex=\n");
    for(int i=0;i<c2_Hex_len;i++) {
        printf("%c", (unsigned int)c2_Hex[i]);
    }
    printf("\n");
    iret = HexStrToByteStr((uint8_t *)c2_Hex, c2_Hex_len, c2_bytes);
    printf("after HexStrToByteStr, c2_bytes=\n");
    for(int i=0;i<c2_Hex_len/2;i++) {
        printf("%02x ", c2_bytes[i]);
    }
    printf("\n");

    //ciphertext需要在调用importCipherText前完成初始化，这样就不用传递pairing
    // element_init_GT(ciphertext->c2, pairing); 
    int c2_len = element_from_bytes(ciphertext->c2, (uint8_t *)c2_bytes);

    //import c3
    uint8_t c3_bytes[SHA256_DIGEST_LENGTH_32 * 8];
    printf("before HexStrToByteStr, c3_Hex=\n");
    for(int i=0;i<c3_Hex_len;i++) {
        printf("%c", (unsigned int)c3_Hex[i]);
    }
    printf("\n");
    iret = HexStrToByteStr((uint8_t *)c3_Hex, c3_Hex_len, c3_bytes);
    printf("after HexStrToByteStr, c3_bytes=\n");
    for(int i=0;i<c3_Hex_len/2;i++) {
        printf("%02x ", c3_bytes[i]);
    }
    printf("\n");

    //ciphertext需要在调用importCipherText前完成初始化
    memcpy(ciphertext->c3, c3_bytes, SHA256_DIGEST_LENGTH_32 * 8);


    //import c4
    uint8_t c4_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    printf("before HexStrToByteStr, c4_Hex=\n");
    for(int i=0;i<c4_Hex_len;i++) {
        printf("%c", (unsigned int)c4_Hex[i]);
    }
    printf("\n");
    iret = HexStrToByteStr((uint8_t *)c4_Hex, c4_Hex_len, c4_bytes);
    printf("after HexStrToByteStr, c4_bytes=\n");
    for(int i=0;i<c4_Hex_len/2;i++) {
        printf("%02x ", c4_bytes[i]);
    }
    printf("\n");

    //ciphertext需要在调用importCipherText前完成初始化，这样就不用传递pairing
    // element_init_G1(ciphertext->c4, pairing); 
    int c4_len = element_from_bytes(ciphertext->c4, (uint8_t *)c4_bytes);



    printf("********************************\n");
    printf("**********importCipherText end************\n");
    printf("********************************\n");
    return 0;
}

//还需要校验等式4
/*
m_bytes_len = SHA256_DIGEST_LENGTH_32 + 1;
*/
int Dec2(uint8_t *pk_Hex, int pk_Hex_len, 
    uint8_t *sk_Hex, int sk_Hex_len, 
    uint8_t *w,
    uint8_t *c1_Hex, int c1_Hex_len,
    uint8_t *c2_Hex, int c2_Hex_len,
    uint8_t *c3_Hex, int c3_Hex_len,
    uint8_t *c4_Hex, int c4_Hex_len,
    uint8_t *m_bytes, int m_bytes_len
    )
{
    printf("********************************\n");
    printf("**********Dec2 start************\n");
    printf("********************************\n");
    if(sk_Hex_len != (ZR_ELEMENT_LENGTH_IN_BYTES * 2) ||
       pk_Hex_len != (G1_ELEMENT_LENGTH_IN_BYTES * 2) ||
       m_bytes_len != (SHA256_DIGEST_LENGTH_32 + 1) || 
       c1_Hex_len != (G1_ELEMENT_LENGTH_IN_BYTES * 2) ||
       c2_Hex_len != (GT_ELEMENT_LENGTH_IN_BYTES * 2) ||
       c3_Hex_len != (SHA256_DIGEST_LENGTH_32 * 8 * 2) ||
       c4_Hex_len != (G1_ELEMENT_LENGTH_IN_BYTES * 2)
       )
    {
        printf("sk_Hex_len = %d, sk_Hex_len should equal to  %d\n", 
            sk_Hex_len, ZR_ELEMENT_LENGTH_IN_BYTES * 2);
        printf("pk_Hex_len = %d, pk_Hex_len should equal to  %d\n", 
            pk_Hex_len, G1_ELEMENT_LENGTH_IN_BYTES * 2);
        printf("m_bytes_len = %d, m_bytes_len should equal to  %d\n", 
            m_bytes_len, (SHA256_DIGEST_LENGTH_32 + 1));
        printf("c1_Hex_len = %d, c1_Hex_len should equal to  %d\n", 
            c1_Hex_len, G1_ELEMENT_LENGTH_IN_BYTES * 2);
        printf("c2_Hex_len = %d, c2_Hex_len should equal to  %d\n", 
            c2_Hex_len, GT_ELEMENT_LENGTH_IN_BYTES * 2);
        printf("c3_Hex_len = %d, c3_Hex_len should equal to  %d\n", 
            c3_Hex_len, SHA256_DIGEST_LENGTH_32 * 8 * 2);
        printf("c4_Hex_len = %d, c4_Hex_len should equal to  %d\n", 
            c4_Hex_len, G1_ELEMENT_LENGTH_IN_BYTES * 2);  
        return -1;
    }

    pairing_t pairing;
    element_t g;
    element_t Z;
    KeyPair keypair;
    Setup(pairing, g, Z);

    //import pk
    uint8_t pk_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    printf("before HexStrToByteStr, pk_Hex=\n");
    for(int i=0;i<G1_ELEMENT_LENGTH_IN_BYTES * 2;i++) {
        printf("%c", (unsigned int)pk_Hex[i]);
    }
    printf("\n");
    int iret = HexStrToByteStr((uint8_t *)pk_Hex, pk_Hex_len, pk_bytes);
    printf("after HexStrToByteStr, pk_bytes=\n");
    for(int i=0;i<G1_ELEMENT_LENGTH_IN_BYTES;i++) {
        printf("%02x ", pk_bytes[i]);
    }
    printf("\n");

    element_init_Zr(keypair.pk, pairing);

    int pk_len = element_from_bytes(keypair.pk, (uint8_t *)pk_bytes);

    //import sk
    uint8_t sk_bytes[ZR_ELEMENT_LENGTH_IN_BYTES];
    printf("before HexStrToByteStr, sk_Hex=\n");
    for(int i=0;i<ZR_ELEMENT_LENGTH_IN_BYTES * 2;i++) {
        printf("%c", (unsigned int)sk_Hex[i]);
    }
    printf("\n");
    iret = HexStrToByteStr((uint8_t *)sk_Hex, sk_Hex_len, sk_bytes);
    printf("after HexStrToByteStr, sk_bytes=\n");
    for(int i=0;i<ZR_ELEMENT_LENGTH_IN_BYTES;i++) {
        printf("%02x ", sk_bytes[i]);
    }
    printf("\n");

    element_init_Zr(keypair.sk, pairing);

    int sk_len = element_from_bytes(keypair.sk, (uint8_t *)sk_bytes);

    //import ciphertext
    CipherText ciphertext;
    element_init_G1(ciphertext.c1, pairing);
    element_init_GT(ciphertext.c2, pairing);
    element_init_G1(ciphertext.c4, pairing);
    // 为 ciphertext.c3 分配内存
    ciphertext.c3 = (uint8_t *) malloc(SHA256_DIGEST_LENGTH_32 * 8 + 1);
    iret = importCipherText(&ciphertext, c1_Hex, c1_Hex_len,
        c2_Hex, c2_Hex_len, c3_Hex, c3_Hex_len, 
        c4_Hex, c4_Hex_len);

    element_t hash2result, eresult, R;
    element_init_G1(hash2result, pairing);
    element_init_GT(eresult, pairing);
    element_init_GT(R, pairing);

    Hash2(hash2result, keypair.pk, w);

    uint8_t hash2result_bytes[8196];
    int len = element_to_bytes(hash2result_bytes, hash2result); 
    printf("hash2result_bytes:\n");
    for(int i=0;i<len;i++) {
        printf("%02x ", hash2result_bytes[i]);
    }
    printf("\n");



    element_pairing(eresult, ciphertext.c1, hash2result);
    element_pow_zn(eresult, eresult, keypair.sk);
    element_invert(eresult, eresult);
    element_mul(R, ciphertext.c2, eresult);
    uint8_t *hash3result = (uint8_t *) malloc(SHA256_DIGEST_LENGTH_32 * 8 + 1);
    Hash3(hash3result, R);
    uint8_t *m = (uint8_t *) malloc(SHA256_DIGEST_LENGTH_32 * 8 + 1);
    xor_bitstrings(m, ciphertext.c3, hash3result);
    printf("m=%s\n", m);

    //verify g^H1(m, R) == C1
    element_t hash1result;
    element_init_Zr(hash1result, pairing);
    Hash1(hash1result, m, R); 
    element_t c1_2;
    element_init_G1(c1_2, pairing);
    element_pow_zn(c1_2, g, hash1result);
    if (element_cmp(c1_2, ciphertext.c1) != 0) {
        printf("verify g^H1(m, R) == c1 fail\n");
        element_clear(c1_2);
        element_clear(hash1result);
        free(m);
        free(hash3result);
        element_clear(R);	
        element_clear(eresult);
        element_clear(hash2result);
        element_clear(ciphertext.c1);
        element_clear(ciphertext.c2);
        free(ciphertext.c3);
        element_clear(ciphertext.c4);
        element_clear(keypair.sk);
        element_clear(keypair.pk);
        element_clear(Z);
        element_clear(g);
        pairing_clear(pairing);	
        // 处理错误，或返回 ⊥
        return NULL;
    }
    printf("verify g^H1(m, R) == c1 success\n");
    bits_to_bytes(m, SHA256_DIGEST_LENGTH_32 * 8, m_bytes);
    printf("m_bytes = %s\n", m_bytes);
 


    element_clear(c1_2);
    element_clear(hash1result);
    free(m);
    free(hash3result);
    element_clear(R);	
    element_clear(eresult);
    element_clear(hash2result);
    element_clear(ciphertext.c1);
    element_clear(ciphertext.c2);
    free(ciphertext.c3);
    element_clear(ciphertext.c4);
    element_clear(keypair.sk);
    element_clear(keypair.pk);
    element_clear(Z);
    element_clear(g);
    pairing_clear(pairing);	


    printf("********************************\n");
    printf("**********Dec2 end************\n");
    printf("********************************\n");
    return 0;
}



int main() {

    uint8_t pk_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t sk_Hex[ZR_ELEMENT_LENGTH_IN_BYTES * 2];
    int pk_Hex_len = G1_ELEMENT_LENGTH_IN_BYTES * 2;
    int sk_Hex_len = ZR_ELEMENT_LENGTH_IN_BYTES * 2;

    KeyGen(pk_Hex, &pk_Hex_len, sk_Hex, &sk_Hex_len);

    printf("pk_Hex_len = %d, pk_Hex=\n", pk_Hex_len);
    for(int i=0;i<pk_Hex_len;i++) {
        printf("%c", pk_Hex[i]);
    }
    printf("\n");
    printf("sk_Hex_len = %d, sk_Hex=\n", sk_Hex_len);
    for(int i=0;i<sk_Hex_len;i++) {
        printf("%c", sk_Hex[i]);
    }
    printf("\n");

    uint8_t *m=(uint8_t *)"12345678901234567890123456789012";
    uint8_t *w=(uint8_t *)"hello world";
    uint8_t c1_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c2_Hex[GT_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c3_Hex[SHA256_DIGEST_LENGTH_32 * 8 * 2];
    uint8_t c4_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    Enc2(pk_Hex, pk_Hex_len, m, w, c1_Hex,c2_Hex,c3_Hex,c4_Hex);

    printf("c1:\n");
    for(int i=0;i<sizeof(c1_Hex);i++) {
        printf("%c", c1_Hex[i]);
    }
    printf("\n");
    printf("c2:\n");
    for(int i=0;i<sizeof(c2_Hex);i++) {
        printf("%c", c2_Hex[i]);
    }
    printf("\n");
    printf("c3:\n");
    for(int i=0;i<sizeof(c3_Hex);i++) {
        printf("%c", c3_Hex[i]);
    }
    printf("\n");
    printf("c4:\n");
    for(int i=0;i<sizeof(c4_Hex);i++) {
        printf("%c", c4_Hex[i]);
    }
    printf("\n");


    uint8_t m_bytes[SHA256_DIGEST_LENGTH_32 + 1];
    Dec2(pk_Hex, sizeof(pk_Hex), sk_Hex, sizeof(sk_Hex),
        w, c1_Hex, sizeof(c1_Hex), c2_Hex, sizeof(c2_Hex),
        c3_Hex, sizeof(c3_Hex), c4_Hex, sizeof(c4_Hex),
        m_bytes, sizeof(m_bytes));
    printf("main: m_bytes = %s\n", m_bytes);
    return 0;
}
