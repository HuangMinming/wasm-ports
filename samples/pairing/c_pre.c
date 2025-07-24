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
const uint8_t * src_buf: input, point to the source
int src_len: input, indicate the source length, should greater than 0
uint8_t * dest_buf: output, point to the destination
int dest_len: input, indicate the destination length, 
        should be greater or equal than src_len * 2
*/
uint32_t ByteStrToHexStr(const uint8_t * src_buf, int src_len, 
    uint8_t * dest_buf, int dest_len)
{
    if(NULL == src_buf || NULL == dest_buf ||
         src_len <= 0 || dest_len < src_len * 2)
	{
        printf("ByteStrToHexStr input error\n");
        return -1;
    }	
    uint8_t highHex, lowHex;
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
const uint8_t * src_buf: input, point to the source
int src_len: input, indicate the source length, should greater than 0, should be devided by 2
uint8_t * dest_buf: output, point to the destination
int dest_len: input, indicate the destination length, 
        should be greater or equal than src_len / 2
*/
uint32_t HexStrToByteStr(const uint8_t * src_buf, int src_len, 
    uint8_t * dest_buf, int dest_len)
{
    if(NULL == src_buf || NULL == dest_buf ||
         src_len <= 0 || 
         (src_len % 2 != 0) ||
         (dest_len < src_len / 2)
         )
	{
        printf("HexStrToByteStr input error\n");
        return -1;
    }	
    uint8_t highByte, lowByte;
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
    return 0;
}
/*
"1101001100010010" --> 0xD3 0x12
uint8_t *bitstring: input, point to the source bit string
int bit_len: input, indicate the source length, should greater than 0, should be devided by 8
uint8_t *bytes: point the destination, should not be null, no '\0' added
int byte_len:input, indicate the destination length, 
        should be greater or equal than bit_len / 8

*/
int bits_to_bytes( uint8_t *bitstring, int bit_len, 
        uint8_t *bytes, int byte_len) 
{
    if(NULL == bitstring || NULL == bytes ||
        bit_len <= 0 || 
        (bit_len % 8 != 0) ||
        byte_len < (bit_len / 8)
    )
    {
        printf("bits_to_bytes input error\n");
        return -1;
    }
#ifdef PRINT_DEBUG_INFO
    printf("bits_to_bytes, bitstring = \n");
    for(int i=0;i<bit_len;i++)
    {
        printf("%c", bitstring[i]);
    }
    printf("\n");
#endif
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
    // bytes[byte_index] = '\0';  // 结束符
    return 0;
}

/*
0xD3 0x12 --> "1101001100010010"
uint8_t *bytes: input, point to the source bytes string
int byte_len: input, indicate the source length, should greater than 0
uint8_t *bitstring: point the destination,  should not be null, no '\0' added
int bit_len:input, indicate the destination length, 
        should be greater or equal than bit_len * 8

*/
int bytes_to_bits( uint8_t *bytes, int byte_len, 
    uint8_t *bitstring, int bit_len) 
{
    if(NULL == bytes || NULL == bitstring ||
        byte_len <= 0 || 
        bit_len < (byte_len * 8)
    )
    {
        printf("bytes_to_bits input error\n");
        return -1;
    }
    int i, j;
    int bit_index = 0;
    int n = byte_len * 8;
    for (i = 0; i < byte_len && bit_index < n; i++) {
        for (j = 7; j >= 0 && bit_index < n; j--) {
            bitstring[bit_index++] = (bytes[i] & (1 << j)) ? '1' : '0';
        }
    }
    // bitstring[bit_index] = '\0';  // 结束符
    return 0;
}

//这里要求str1和str2的长度必须一致，否则会越界，这里都是256，
/*
uint8_t *result: output, compute str1 xor str2, 
    should not be null, no '\0' added
uint8_t *str1: input, is a string of '1' and '0'
int str1_len: the length of str1， not include the '\0'
uint8_t *str2: input, is a string of '1' and '0'
int str2_le: the length of str2，not include the '\0'
*/
int xor_bitstrings(uint8_t *result, uint8_t *str1, int str1_len, 
    uint8_t *str2, int str2_len) {
    if(NULL == result || NULL == str1 || NULL == str2 ||
        str1_len <= 0 || str1_len != str2_len)
    {
        printf("xor_bitstrings input error\n");
        return -1;
    }
    // int n = strlen((const char *)str1);
    for (int i = 0; i < str1_len; i++) {
        // 逐位进行异或 ('0' 异或 '0' 为 '0', '0' 异或 '1' 为 '1', '1' 异或 '1' 为 '0')
        if (str1[i] == str2[i]) {
            result[i] = '0';  // 相同为 '0'
        } else {
            result[i] = '1';  // 不同为 '1'
        }
    }
    // result[str1_len] = '\0';  // 确保字符串以 '\0' 结束，可能会越界
    return 0;
}

/*
pairing_t pairing: output, a fixed curve
element_t g: output, a fixed G1
element_t Z: output, a fixed GT
*/
int Setup(pairing_t pairing, element_t g, element_t Z)
{
    int iRet = -1;
    char *param="type a\n\
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n\
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n\
r 730750818665451621361119245571504901405976559617\n\
exp2 159\n\
exp1 107\n\
sign1 1\n\
sign0 1";

    size_t count = strlen(param);
#ifdef PRINT_DEBUG_INFO
    printf("Setup count(param)=%d\n", count);
#endif
    iRet = pairing_init_set_buf(pairing, param, count);
    if (iRet != 0) {
        printf("pairing_init_set_buf return %d, exit\n", iRet);
        return -1;
    }
    element_init_G1(g, pairing);
    // element_random(g);
    element_from_hash(g, "31415926", strlen("31415926"));
    element_init_GT(Z, pairing);
    pairing_apply(Z, g, g, pairing);
#ifdef PRINT_DEBUG_INFO
    size_t g_len = element_length_in_bytes(g);
    uint8_t *g_bytes = (uint8_t *) malloc(g_len);
    element_to_bytes(g_bytes, g);
    printf("Setup g_len = %d, g=\n", g_len);
    for(int i=0;i<g_len;i++){
        printf("%02x ", g_bytes[i]);
    }
    printf("\n");
    free(g_bytes);
    size_t Z_len = element_length_in_bytes(Z);
    uint8_t *Z_bytes = (uint8_t *) malloc(Z_len);
    element_to_bytes(Z_bytes, Z);
    printf("Setup Z_len = %d, Z=\n", Z_len);
    for(int i=0;i<Z_len;i++){
        printf("%02x ", Z_bytes[i]);
    }
    printf("\n");
    free(Z_bytes);
#endif
    return 0;    
}

//Hash1 {0,1}* -> Zq
/*
result = Hash1(m, R);
element_t result: output, the result of Hash1(m, R), is a Zr, must be initialized before calling
uint8_t * m: input, is a string of '1' and '0'
int m_len: input, the length of m not include the '\0'
element_t R: input, is a GT, must be initialized before calling
*/
int Hash1(element_t result, uint8_t * m, int m_len, element_t R)
{
    if(NULL == m || m_len <= 0)
    {
        printf("Hash1 input error\n");
        return -1;
    }
    int R_len = element_length_in_bytes(R);
    uint8_t *R_bytes = (uint8_t *) malloc(R_len);
    element_to_bytes(R_bytes, R);  // 序列化 GT 群中的元素 R
    
    // 获取输入字符串 m 的长度
    // int m_len = strlen((const char *)m);
    
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
    // element_init_Zr(result, pairing);  //调用前需要初始化，这样就不用传递pairing了
    element_set_mpz(result, hash_int);  // 将哈希值映射到 Zq 上
    
    // 释放内存
    free(R_bytes);
    free(hash_input);
    mpz_clear(hash_int);
    return 0;
}

//Hash2 {0,1}* -> G1
/*
result = Hash2(pk, w);
element_t result：output, the result of Hash2(pk, w), is a G1, must be initialized before calling
element_t pk：input, public key, is a G1, must set the right value 
uint8_t * w: input, is a string 
int w_len: input, the length of m not include the '\0'
*/
int Hash2(element_t result, element_t pk,  uint8_t * w, int w_len) 
{
    if(NULL == w || w_len <= 0)
    {
        printf("Hash2 input error\n");
        return -1;
    }
    sha256_context ctx;
    sha256_starts( &ctx );

    uint8_t hash[SHA256_DIGEST_LENGTH_32];
    size_t pk_len = element_length_in_bytes(pk);
    // size_t w_len = strlen((const char *)w);
    uint8_t * hash_input = (uint8_t *) malloc(pk_len + w_len);

    // 将 pk 转换为字节形式
    element_to_bytes(hash_input, pk); 

    // 将 w 也转换为字节形式，并拼接到 hash_input 中
    memcpy(hash_input + pk_len, w, w_len);

    sha256_update( &ctx, (uint8 *) hash_input, pk_len + w_len );
    sha256_finish( &ctx, hash );
    // element_init_G1(result, pairing); //调用前需要初始化，这样就不用传递pairing了
    // 将哈希值映射到群元素
    element_from_hash(result, hash, sizeof(hash)); // result 是群G1元素

    free(hash_input);
    return 0;
}


// Hash3 G1 -> {0,1}^256,输出的bitstring是0和1组成的字符串
/*
bitstring = Hash3(R)
uint8_t *bitstring: output, is a string of '0' and '1', 
    should not be null, no '\0' added
int bit_len: input, the size of bitstring, 
    should be greater or equal than SHA256_DIGEST_LENGTH_32 * 8
element_t R: input, is a GT
*/
int Hash3(uint8_t *bitstring, int bit_len, element_t R)
{
    if(NULL == bitstring || bit_len < SHA256_DIGEST_LENGTH_32 * 8)
    {
        printf("Hash3 input error\n");
        return -1;
    }
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
    bytes_to_bits(hash, sizeof(hash), bitstring, bit_len);
    // 释放内存
    free(R_bytes);
    return 0;
}

/*
result = Hash4(c1, c2, c3)
element_t result: output, is a G1, must be initialized before calling
element_t c1: input
element_t c2: input
uint8_t* c3: input
int c3_len: input, the length of c3, must greater than 0, not include '\0'
*/
int Hash4(element_t result, element_t c1, element_t c2,  uint8_t* c3, int c3_len) 
{
    if(NULL == c3 || c3_len <= 0)
    {
        printf("Hash4 input error\n");
        return -1;
    }
    sha256_context ctx;
    sha256_starts( &ctx );

    // 获取 G1 群元素 c1 的字节长度
    size_t c1_len = element_length_in_bytes(c1);
    // 获取 GT 群元素 c2 的字节长度
    size_t c2_len = element_length_in_bytes(c2);
    // 获取 c3 的长度
    // size_t c3_len = strlen((const char *)c3);

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
    element_from_hash(result, hash, sizeof(hash));  // 将哈希值映射为群元素
    free(hash_input);
    return 0;
}


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

/*
export keypair to pk_Hex,sk_Hex
KeyPair *p_kepair: input, should not NULL
uint8_t *pk_Hex: output, should not NULL
int pk_Hex_len: input, indicate the size of pk_Hex,
    should be greater or equal than G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *sk_Hex: output, should not NULL
int sk_Hex_len: input, indicate the size of sk_Hex,
    should be greater or equal than ZR_ELEMENT_LENGTH_IN_BYTES * 2
*/
int exportKeyPair(KeyPair *p_kepair, uint8_t *pk_Hex, int pk_Hex_len, 
    uint8_t *sk_Hex, int sk_Hex_len)
{
    if(NULL == p_kepair || NULL == pk_Hex || NULL == sk_Hex ||
        pk_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        sk_Hex_len < ZR_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("exportKeyPair input error\n");
        return -1;
    }
    size_t pk_len = element_length_in_bytes(p_kepair->pk);
    size_t sk_len = element_length_in_bytes(p_kepair->sk);
    if (pk_len != G1_ELEMENT_LENGTH_IN_BYTES ||
        sk_len != ZR_ELEMENT_LENGTH_IN_BYTES)
    {
        printf("pk_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", pk_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("sk_len = %d, ZR_ELEMENT_LENGTH_IN_BYTES = %d\n", sk_len, ZR_ELEMENT_LENGTH_IN_BYTES);
        printf("p_kepair error\n");
        return -1;
    }
    
    uint8_t pk_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    uint8_t sk_bytes[ZR_ELEMENT_LENGTH_IN_BYTES];

    element_to_bytes(pk_bytes, p_kepair->pk);
    element_to_bytes(sk_bytes, p_kepair->sk);
#ifdef PRINT_DEBUG_INFO
    printf("exportKeyPair:before ByteStrToHexStr, pk_len = %d, pk_bytes=\n", pk_len);
    for(int i=0;i<pk_len;i++){
        printf("%02x ", pk_bytes[i]);
    }
    printf("\n");
    printf("exportKeyPair:before ByteStrToHexStr, sk_len = %d, sk_bytes=\n", sk_len);
    for(int i=0;i<sk_len;i++){
        printf("%02x ", sk_bytes[i]);
    }
    printf("\n");
#endif
    ByteStrToHexStr(pk_bytes, pk_len, pk_Hex, pk_Hex_len);
    ByteStrToHexStr(sk_bytes, sk_len, sk_Hex, sk_Hex_len);    
#ifdef PRINT_DEBUG_INFO
    printf("exportKeyPair:after ByteStrToHexStr, pk_Hex=\n");
    for(int i=0;i<pk_Hex_len;) {
        printf("%c%c ", pk_Hex[i],pk_Hex[i+1]);
        i+=2;
    }
    printf("\n");
    printf("exportKeyPair:after ByteStrToHexStr, sk_Hex=\n");
    for(int i=0;i<sk_Hex_len;) {
        printf("%c%c ", sk_Hex[i], sk_Hex[i+1]);
        i+=2;
    }
    printf("\n");
#endif
    return 0;
}

/*
import pk_Hex,sk_Hex to keypair
KeyPair *p_kepair: output,  must be initialized before calling
uint8_t *pk_Hex: input, if it is NULL, skip import to p_kepair->pk
int pk_Hex_len: input, indicate the size of pk_Hex,
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *sk_Hex: input, if it is NULL, skip import to p_kepair->sk
int sk_Hex_len: input, indicate the size of sk_Hex,
    should be equal to ZR_ELEMENT_LENGTH_IN_BYTES * 2
*/
int importKeyPair(KeyPair *p_kepair, uint8_t *pk_Hex, int pk_Hex_len, 
    uint8_t *sk_Hex, int sk_Hex_len)
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********importKeyPair start************\n");
    printf("********************************\n");
#endif
    if(NULL == p_kepair) 
    {
        printf("importKeyPair error\n");
        return -1;
    }
    if(pk_Hex != NULL)
    {
        if(pk_Hex_len != (G1_ELEMENT_LENGTH_IN_BYTES * 2))
        {
            printf("importKeyPair pk_Hex_len = %d, pk_Hex_len should equal to %d\n", 
                pk_Hex_len, G1_ELEMENT_LENGTH_IN_BYTES * 2);
            return -1;
        }
        //import pk
        uint8_t pk_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
#ifdef PRINT_DEBUG_INFO
        printf("importKeyPair before HexStrToByteStr, pk_Hex=\n");
        for(int i=0;i<G1_ELEMENT_LENGTH_IN_BYTES * 2;) {
            printf("%c%c ", pk_Hex[i], pk_Hex[i+1]);
            i += 2;
        }
        printf("\n");
#endif
        HexStrToByteStr((uint8_t *)pk_Hex, pk_Hex_len, pk_bytes, sizeof(pk_bytes));
#ifdef PRINT_DEBUG_INFO
        printf("importKeyPair after HexStrToByteStr, pk_bytes=\n");
        for(int i=0;i<sizeof(pk_bytes);i++) {
            printf("%02x ", pk_bytes[i]);
        }
        printf("\n");
#endif
        //在调用importKeyPair前完成p_kepair->pk初始化
        element_from_bytes(p_kepair->pk, (uint8_t *)pk_bytes);
    }

    if(sk_Hex != NULL)
    {
        if(sk_Hex_len != (ZR_ELEMENT_LENGTH_IN_BYTES * 2))
        {
            printf("importKeyPair sk_Hex_len = %d, sk_Hex_len should equal to  %d\n", 
                sk_Hex_len, ZR_ELEMENT_LENGTH_IN_BYTES * 2);
            return -1;
        }
        //import sk
        uint8_t sk_bytes[ZR_ELEMENT_LENGTH_IN_BYTES];
#ifdef PRINT_DEBUG_INFO
        printf("importKeyPair before HexStrToByteStr, sk_Hex=\n");
        for(int i=0;i<ZR_ELEMENT_LENGTH_IN_BYTES * 2;) {
            printf("%c%c ", sk_Hex[i], sk_Hex[i+1]);
            i += 2;
        }
        printf("\n");
#endif
        HexStrToByteStr((uint8_t *)sk_Hex, sk_Hex_len, sk_bytes, sizeof(sk_bytes));
#ifdef PRINT_DEBUG_INFO
        printf("importKeyPair after HexStrToByteStr, sk_bytes=\n");
        for(int i=0;i<sizeof(sk_bytes);i++) {
            printf("%02x ", sk_bytes[i]);
        }
        printf("\n");
#endif
        //在调用importKeyPair前完成p_kepair->sk初始化
        element_from_bytes(p_kepair->sk, (uint8_t *)sk_bytes);
    }
#ifdef PRINT_DEBUG_INFO   
    printf("********************************\n");
    printf("**********importKeyPair end************\n");
    printf("********************************\n");
#endif
    return 0;
}


/*
export p_ciphertext to c1_Hex, c2_Hex, c3_Hex, c4_Hex in Hex string format
CipherText *p_ciphertext: input, should not be NULL
uint8_t *c1_Hex: output, should not be NULL
int c1_Hex_len: the size of c1_Hex, 
    should be greater or equal than G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c2_Hex: output, should not be NULL 
int c1_Hex_len: the size of c2_Hex, 
    should be greater or equal than GT_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c3_Hex: output, should not be NULL 
int c1_Hex_len: the size of c3_Hex, 
    should be greater or equal than SHA256_DIGEST_LENGTH_32 * 8 * 2
uint8_t *c4_Hex: output, should not be NULL
int c1_Hex_len: the size of c4_Hex, 
    should be greater or equal than G1_ELEMENT_LENGTH_IN_BYTES * 2
*/

int exportCipherText(CipherText *p_ciphertext, 
    uint8_t *c1_Hex, int c1_Hex_len, 
    uint8_t *c2_Hex, int c2_Hex_len, 
    uint8_t *c3_Hex, int c3_Hex_len, 
    uint8_t *c4_Hex, int c4_Hex_len)
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********exportCipherText start************\n");
    printf("********************************\n");
#endif
    if(NULL == p_ciphertext || NULL == p_ciphertext->c3 ||
        NULL == c1_Hex || c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c2_Hex || c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c3_Hex || c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2 ||
        NULL == c4_Hex || c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("exportCipherText input error \n");
        return -1;
    }
    int c1_len = element_length_in_bytes(p_ciphertext->c1);
    int c2_len = element_length_in_bytes(p_ciphertext->c2);
    int c3_len = SHA256_DIGEST_LENGTH_32 * 8;
    int c4_len = element_length_in_bytes(p_ciphertext->c4);
    if (c1_len != G1_ELEMENT_LENGTH_IN_BYTES ||
        c2_len != GT_ELEMENT_LENGTH_IN_BYTES ||
        c4_len != G1_ELEMENT_LENGTH_IN_BYTES)
    {
        printf("exportCipherText c1_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", 
            c1_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("exportCipherText c2_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", 
            c2_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("exportCipherText c4_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", 
            c4_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("exportCipherText exit \n");
        return -1;
    }
    uint8_t c1_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    uint8_t c2_bytes[GT_ELEMENT_LENGTH_IN_BYTES];
    uint8_t c4_bytes[G1_ELEMENT_LENGTH_IN_BYTES];

    element_to_bytes(c1_bytes, p_ciphertext->c1);
    element_to_bytes(c2_bytes, p_ciphertext->c2);
    element_to_bytes(c4_bytes, p_ciphertext->c4);
#ifdef PRINT_DEBUG_INFO
    printf("exportCipherText c1:\n");
    for(int i=0;i<sizeof(c1_bytes);i++) {
        printf("%02x ", c1_bytes[i]);
    }
    printf("\n");
    printf("exportCipherText c2:\n");
    for(int i=0;i<sizeof(c2_bytes);i++) {
        printf("%02x ", c2_bytes[i]);
    }
    printf("\n");
    printf("exportCipherText c3:\n");
    for(int i=0;i<c3_len;i++) {
        printf("%02x ", p_ciphertext->c3[i]);
    }
    printf("\n");
    printf("exportCipherText c4:\n");
    for(int i=0;i<sizeof(c4_bytes);i++) {
        printf("%02x ", c4_bytes[i]);
    }
    printf("\n");
#endif
    //c1, c2, c3, c4 convert to Hex
    //todo, add length
    ByteStrToHexStr(c1_bytes, sizeof(c1_bytes), c1_Hex, c1_Hex_len);
    ByteStrToHexStr(c2_bytes, sizeof(c2_bytes), c2_Hex, c2_Hex_len);
    ByteStrToHexStr(p_ciphertext->c3, c3_len, c3_Hex, c3_Hex_len);
    ByteStrToHexStr(c4_bytes, sizeof(c4_bytes), c4_Hex, c4_Hex_len);
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********exportCipherText end************\n");
    printf("********************************\n");
#endif
    return 0;
}

/*
import c1_Hex, c2_Hex, c3_Hex, c4_Hex to p_ciphertext
CipherText *p_ciphertext, 
uint8_t *c1_Hex: input, should not be NULL
int c1_Hex_len: input, indicate the length of c1_Hex, 
    should equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c2_Hex: input, should not be NULL
int c2_Hex_len: input, indicate the length of c2_Hex, 
    should equal to GT_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c3_Hex: input, should not be NULL
int c3_Hex_len: input, indicate the length of c3_Hex, 
    should equal to SHA256_DIGEST_LENGTH_32 * 8 * 2
uint8_t *c4_Hex: input, should not be NULL
int c4_Hex_len: input, indicate the length of c4_Hex, 
    should equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
*/
int importCipherText(CipherText *p_ciphertext, 
    uint8_t *c1_Hex, int c1_Hex_len,
    uint8_t *c2_Hex, int c2_Hex_len,
    uint8_t *c3_Hex, int c3_Hex_len,
    uint8_t *c4_Hex, int c4_Hex_len)
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********importCipherText start************\n");
    printf("********************************\n");
#endif
    if(NULL == p_ciphertext ||
       NULL == c1_Hex || NULL == c2_Hex ||
       NULL == c3_Hex || NULL == c4_Hex)
    {
        printf("importCipherText input error\n");
        return -1;
    }
    if(
       c1_Hex_len != (G1_ELEMENT_LENGTH_IN_BYTES * 2) ||
       c2_Hex_len != (GT_ELEMENT_LENGTH_IN_BYTES * 2) ||
       c3_Hex_len != (SHA256_DIGEST_LENGTH_32 * 8 * 2) ||
       c4_Hex_len != (G1_ELEMENT_LENGTH_IN_BYTES * 2) )
    {
        printf("importCipherText c1_Hex_len = %d, c1_Hex_len should equal to  %d\n", 
            c1_Hex_len, G1_ELEMENT_LENGTH_IN_BYTES * 2);
        printf("importCipherText c2_Hex_len = %d, c2_Hex_len should equal to  %d\n", 
            c2_Hex_len, GT_ELEMENT_LENGTH_IN_BYTES * 2);
        printf("importCipherText c3_Hex_len = %d, c3_Hex_len should equal to  %d\n", 
            c3_Hex_len, SHA256_DIGEST_LENGTH_32 * 8 * 2);
        printf("importCipherText c4_Hex_len = %d, c4_Hex_len should equal to  %d\n", 
            c4_Hex_len, G1_ELEMENT_LENGTH_IN_BYTES * 2);  
        return -1;
    }

    //import c1
#ifdef PRINT_DEBUG_INFO
    printf("importCipherText before HexStrToByteStr, c1_Hex=\n");
    for(int i=0;i<c1_Hex_len;) {
        printf("%c%c ", c1_Hex[i], c1_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    uint8_t c1_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    HexStrToByteStr((uint8_t *)c1_Hex, c1_Hex_len, c1_bytes, sizeof(c1_bytes));
#ifdef PRINT_DEBUG_INFO
    printf("importCipherText  after HexStrToByteStr, c1_bytes=\n");
    for(int i=0;i<c1_Hex_len/2;i++) {
        printf("%02x ", c1_bytes[i]);
    }
    printf("\n");
#endif
    //p_ciphertext->c1需要在调用importCipherText前完成初始化
    int c1_len = element_from_bytes(p_ciphertext->c1, (uint8_t *)c1_bytes);

    //import c2
#ifdef PRINT_DEBUG_INFO
    printf("importCipherText before HexStrToByteStr, c2_Hex=\n");
    for(int i=0;i<c2_Hex_len;) {
        printf("%c%c ", c2_Hex[i], c2_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    uint8_t c2_bytes[GT_ELEMENT_LENGTH_IN_BYTES];
    HexStrToByteStr((uint8_t *)c2_Hex, c2_Hex_len, c2_bytes, sizeof(c2_bytes));
#ifdef PRINT_DEBUG_INFO
    printf("importCipherText after HexStrToByteStr, c2_bytes=\n");
    for(int i=0;i<c2_Hex_len/2;i++) {
        printf("%02x ", c2_bytes[i]);
    }
    printf("\n");
#endif
    //p_ciphertext->c2需要在调用importCipherText前完成初始化
    int c2_len = element_from_bytes(p_ciphertext->c2, (uint8_t *)c2_bytes);

    //import c3
#ifdef PRINT_DEBUG_INFO
    printf("importCipherText before HexStrToByteStr, c3_Hex=\n");
    for(int i=0;i<c3_Hex_len;) {
        printf("%c%c ", c3_Hex[i], c3_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    uint8_t c3_bytes[SHA256_DIGEST_LENGTH_32 * 8];
    HexStrToByteStr((uint8_t *)c3_Hex, c3_Hex_len, c3_bytes, sizeof(c3_bytes));
#ifdef PRINT_DEBUG_INFO
    printf("importCipherText after HexStrToByteStr, c3_bytes=\n");
    for(int i=0;i<c3_Hex_len/2;i++) {
        printf("%02x ", c3_bytes[i]);
    }
    printf("\n");
#endif
    //p_ciphertext->c3需要在调用importCipherText前完成内存分配
    memcpy(p_ciphertext->c3, c3_bytes, sizeof(c3_bytes));
    //确保c3以'\0'结束
    // p_ciphertext->c3[sizeof(c3_bytes)] = '\0';


    //import c4
#ifdef PRINT_DEBUG_INFO
    printf("importCipherText before HexStrToByteStr, c4_Hex=\n");
    for(int i=0;i<c4_Hex_len;) {
        printf("%c%c ", c4_Hex[i], c4_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    uint8_t c4_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    HexStrToByteStr((uint8_t *)c4_Hex, c4_Hex_len, c4_bytes, sizeof(c4_bytes));
#ifdef PRINT_DEBUG_INFO
    printf("importCipherText after HexStrToByteStr, c4_bytes=\n");
    for(int i=0;i<c4_Hex_len/2;i++) {
        printf("%02x ", c4_bytes[i]);
    }
    printf("\n");
#endif
    //ciphertext需要在调用importCipherText前完成初始化，这样就不用传递pairing
    // element_init_G1(ciphertext->c4, pairing); 
    int c4_len = element_from_bytes(p_ciphertext->c4, (uint8_t *)c4_bytes);


#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********importCipherText end************\n");
    printf("********************************\n");
#endif
    return 0;
}



/*
check e(C1, H4(C1, C2, C3)) == e(g, C4)
pairing_t pairing: input, 
element_t g: input
CipherText *p_ciphertext: input, point to the cipherText, should not be NULL
*/
int checkEqual4(pairing_t pairing, element_t g, CipherText *p_ciphertext)
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********checkEqual4 start************\n");
    printf("********************************\n");
#endif
    element_t e1, e2, hash4result;
    element_init_GT(e1, pairing);
    element_init_GT(e2, pairing);
    element_init_G1(hash4result, pairing);

    int iRet = -1;

    if( NULL == p_ciphertext || 
        NULL == p_ciphertext->c3 )
    {
        printf("checkEqual4 input error \n");
        return -1;
    }
    
    Hash4(hash4result, p_ciphertext->c1, p_ciphertext->c2, 
        p_ciphertext->c3, SHA256_DIGEST_LENGTH_32 * 8);
    pairing_apply(e1, p_ciphertext->c1, hash4result, pairing);
    pairing_apply(e2, g, p_ciphertext->c4, pairing);
    iRet = element_cmp(e1, e2);
    if (iRet != 0) 
    {
        printf("e(C1, H4(C1,C2,C3)) = e(g, C4) check fail\n");
    }
    else 
    {
        printf("e(C1, H4(C1,C2,C3)) = e(g, C4) check success\n");
    }
    
    element_clear(hash4result);
    element_clear(e2);
    element_clear(e1);
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********checkEqual4 end************\n");
    printf("********************************\n");
#endif
    return iRet;
}


/*
export p_reKeyPair to rk1_Hex, rk2_Hex
ReKeyPair *p_reKeyPair: input, point to the reKeyPair
uint8_t *rk1_Hex: output, save rk1 with Hex string format in rk1_Hex, should not be NULL
int rk1_Hex_len: input, indicate the size of rk1_Hex, 
    should be greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *rk2_Hex: output, save rk2 with Hex string format in rk2_Hex, should not be NULL
int rk2_Hex_len:input, indicate the size of rk2_Hex, 
    should be greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
*/
int exportReKeyPair(ReKeyPair *p_reKeyPair, 
    uint8_t *rk1_Hex, int rk1_Hex_len,
    uint8_t *rk2_Hex, int rk2_Hex_len)
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********exportReKeyPair start************\n");
    printf("********************************\n");
#endif
    if( NULL == p_reKeyPair ||
        NULL == rk1_Hex || rk1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == rk2_Hex || rk2_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("exportReKeyPair input error \n");
        return -1;
    }

    size_t rk1_len = element_length_in_bytes(p_reKeyPair->rk1);
    size_t rk2_len = element_length_in_bytes(p_reKeyPair->rk2);
    if (rk1_len != G1_ELEMENT_LENGTH_IN_BYTES ||
        rk2_len != G1_ELEMENT_LENGTH_IN_BYTES)
    {
        printf("exportReKeyPair rk1_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", 
            rk1_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("exportReKeyPair rk2_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", 
            rk2_len, G1_ELEMENT_LENGTH_IN_BYTES);
        printf("exit \n");
        return -1;
    }
    
    uint8_t rk1_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
    uint8_t rk2_bytes[G1_ELEMENT_LENGTH_IN_BYTES];

    element_to_bytes(rk1_bytes, p_reKeyPair->rk1);
    element_to_bytes(rk2_bytes, p_reKeyPair->rk2);
#ifdef PRINT_DEBUG_INFO
    printf("exportReKeyPair before ByteStrToHexStr rk1_len = %d, rk1_bytes=\n", rk1_len);
    for(int i=0;i<rk1_len;i++){
        printf("%02x ", rk1_bytes[i]);
    }
    printf("\n");
    printf("exportReKeyPair before ByteStrToHexStr rk2_len = %d, rk2_bytes=\n", rk2_len);
    for(int i=0;i<rk2_len;i++){
        printf("%02x ", rk2_bytes[i]);
    }
    printf("\n");
#endif

    ByteStrToHexStr(rk1_bytes, rk1_len, rk1_Hex, rk1_Hex_len);
    ByteStrToHexStr(rk2_bytes, rk2_len, rk2_Hex, rk2_Hex_len);

#ifdef PRINT_DEBUG_INFO
    printf("exportReKeyPair after ByteStrToHexStr rk1_Hex_len = %d, rk1_Hex=\n", rk1_Hex_len);
    for(int i=0;i<rk1_Hex_len;) {
        printf("%c%c ", rk1_Hex[i], rk1_Hex[i+1]);
        i += 2;
    }
    printf("\n");
    printf("exportReKeyPair after ByteStrToHexStr rk2_Hex_len = %d, rk2_Hex=\n", rk2_Hex_len);
    for(int i=0;i<rk2_Hex_len;) {
        printf("%c%c ", rk2_Hex[i], rk2_Hex[i+1]);
        i += 2;
    }
    printf("\n");
    printf("********************************\n");
    printf("**********exportReKeyPair end************\n");
    printf("********************************\n");
#endif
    return 0;
}

/*
import p_reKeyPair from rk1_Hex, rk2_Hex
ReKeyPair *p_reKeyPair: output, point to the reKeyPair
uint8_t *rk1_Hex: input, retrieve rk1 with Hex string format from rk1_Hex, should not be NULL
int rk1_Hex_len: input, indicate the size of rk1_Hex, 
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *rk2_Hex: output, retrieve rk2 with Hex string format from rk2_Hex, should not be NULL
int rk2_Hex_len:input, indicate the size of rk2_Hex, 
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
*/
int importReKeyPair(ReKeyPair *p_reKeyPair, 
    uint8_t *rk1_Hex, int rk1_Hex_len,
    uint8_t *rk2_Hex, int rk2_Hex_len)
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********importReKeyPair start************\n");
    printf("********************************\n");
#endif
    if( NULL == p_reKeyPair ||
        NULL == rk1_Hex || rk1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == rk2_Hex || rk2_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("importReKeyPair input error \n");
        return -1;
    }

    //import rk1
    uint8_t rk1_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
#ifdef PRINT_DEBUG_INFO
    printf("importReKeyPair before HexStrToByteStr, rk1_Hex=\n");
    for(int i=0;i<rk1_Hex_len;) {
        printf("%c%c ", rk1_Hex[i], rk1_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    HexStrToByteStr((uint8_t *)rk1_Hex, rk1_Hex_len, rk1_bytes, sizeof(rk1_bytes));
#ifdef PRINT_DEBUG_INFO
    printf("importReKeyPair after HexStrToByteStr, rk1_bytes=\n");
    for(int i=0;i<rk1_Hex_len/2;i++) {
        printf("%02x ", rk1_bytes[i]);
    }
    printf("\n");
#endif
    //p_reKeyPair需要在调用importReKeyPair前完成初始化，这样就不用传递pairing
    int rk1_len = element_from_bytes(p_reKeyPair->rk1, (uint8_t *)rk1_bytes);

    //import rk2
    uint8_t rk2_bytes[G1_ELEMENT_LENGTH_IN_BYTES];
#ifdef PRINT_DEBUG_INFO
    printf("importReKeyPair before HexStrToByteStr, rk2_Hex=\n");
    for(int i=0;i<rk2_Hex_len;) {
        printf("%c%c ", rk2_Hex[i], rk2_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    HexStrToByteStr((uint8_t *)rk2_Hex, rk2_Hex_len, rk2_bytes, sizeof(rk2_bytes));
#ifdef PRINT_DEBUG_INFO
    printf("importReKeyPair after HexStrToByteStr, rk2_bytes=\n");
    for(int i=0;i<rk2_Hex_len/2;i++) {
        printf("%02x ", rk2_bytes[i]);
    }
    printf("\n");
#endif
    //p_reKeyPair需要在调用importReKeyPair前完成初始化，这样就不用传递pairing
    int rk2_len = element_from_bytes(p_reKeyPair->rk2, (uint8_t *)rk2_bytes);
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********importReKeyPair end************\n");
    printf("********************************\n");
#endif
    return 0;
}


/*
generate key
uint8_t *pk_Hex: output, should not be null, 
        store pk in Hex string format, like "1234567890"
int pk_Hex_len: input, indicate the size of pk_Hex, 
        should greater or equal than G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *sk_Hex: output, should not be null, 
        store sk in Hex string format, like "1234567890"
int sk_Hex_len: input, indicate the size of sk_Hex, 
        should greater or equal than ZR_ELEMENT_LENGTH_IN_BYTES * 2
*/
// #ifdef __cplusplus
// extern "C" {
// #endif
int EMSCRIPTEN_KEEPALIVE KeyGen(uint8_t *pk_Hex, int pk_Hex_len, uint8_t *sk_Hex, int sk_Hex_len)
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********KeyGen start************\n");
    printf("********************************\n");
#endif
    if(NULL == pk_Hex || NULL == sk_Hex ||
        (pk_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2) ||
        (sk_Hex_len < ZR_ELEMENT_LENGTH_IN_BYTES * 2)
        )
    {
        printf("KeyGen error input \n");
        printf("NULL == pk_Hex = %d\n", NULL == pk_Hex);
        printf("NULL == sk_Hex = %d\n", NULL == sk_Hex);
        printf("pk_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_Hex_len = %d\n", 
            pk_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_Hex_len);
        printf("sk_Hex_len < ZR_ELEMENT_LENGTH_IN_BYTES * 2 = %d, sk_Hex_len = %d\n", 
            sk_Hex_len < ZR_ELEMENT_LENGTH_IN_BYTES * 2, sk_Hex_len);
        return -1;
    }
    int iRet = -1;
    pairing_t pairing;
    element_t g;
    element_t Z;
    KeyPair keypair;
    iRet = Setup(pairing, g, Z);
    if(iRet != 0) 
    {
        printf("KeyGen Setup return %d, exit", iRet);
        return -1;
    }

    size_t g_len = element_length_in_bytes(g);
    uint8_t *g_bytes = (uint8_t *) malloc(g_len);
    element_to_bytes(g_bytes, g);
#ifdef PRINT_DEBUG_INFO
    printf("KeyGen g_len = %d, g=\n", g_len);
    for(int i=0;i<g_len;i++){
        printf("%02x ", g_bytes[i]);
    }
    printf("\n");
#endif
    uint8_t hash[SHA256_DIGEST_LENGTH_32];
    sha256_context ctx;
    sha256_starts( &ctx );
    sha256_update( &ctx, (uint8 *) g_bytes, g_len );
    sha256_finish( &ctx, hash );
#ifdef PRINT_DEBUG_INFO
    printf("KeyGen hash(g_bytes)=\n");
    for(int i=0;i<SHA256_DIGEST_LENGTH_32;i++) {
        printf("%02x ", hash[i]);
    }
    printf("\n");
#endif

    element_init_G1(keypair.pk, pairing);
    element_init_Zr(keypair.sk, pairing);
    element_random(keypair.sk);
    element_pow_zn(keypair.pk, g, keypair.sk);

    iRet = exportKeyPair(&keypair, pk_Hex, pk_Hex_len, sk_Hex, sk_Hex_len);
    if (iRet != 0)
    {
        printf("KeyGen exportKeyPair return error, iRet = %d\n", iRet);
    }

    element_clear(keypair.pk);
    element_clear(keypair.sk);
    element_clear(Z);
    element_clear(g);
    pairing_clear(pairing);
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********KeyGen end************\n");
    printf("********************************\n");
#endif
    return iRet;
}






//m是AES-GCM key，长度是256bit，32字节
//输出c1,c2,c3,c4，其中c1, c2, c4转为bytes后再转为Hex,c3直接转为Hex
/*
uint8_t *pk_Hex: input, point to public key Hex string, should not be NULL
int pk_Hex_len: indicate the size of pk_Hex,
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *m_bytes: input, point to the message which need to be encrypt, is a normal string
int m_bytes_len: input, indicate the length of m_bytes, should be equal to SHA256_DIGEST_LENGTH_32
uint8_t *w:input, point to the condition, is a normal string
int w_len: input, indicate the length of w, should be greater than 0
uint8_t *c1_Hex: output, save C1 with Hex string format in c1_Hex, should not be NULL
int c1_Hex_len: input, indicate the size of c1_Hex, 
    should greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c2_Hex: output, save C2 with Hex string format in c2_Hex, should not be NULL
int c2_Hex_len: input, indicate the size of c2_Hex, 
    should greater or equal to GT_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c3_Hex: output, save C3 with Hex string format in c3_Hex, should not be NULL
int c3_Hex_len: input, indicate the size of c3_Hex, 
    should greater or equal to SHA256_DIGEST_LENGTH_32 * 8 * 2
uint8_t *c4_Hex: output, save C4 with Hex string format in c4_Hex, should not be NULL
int c4_Hex_len: input, indicate the size of c4_Hex, 
    should greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
*/
int EMSCRIPTEN_KEEPALIVE Enc2(uint8_t *pk_Hex, int pk_Hex_len, 
    uint8_t *m_bytes, int m_bytes_len, 
    uint8_t *w, int w_len, 
    uint8_t *c1_Hex, int c1_Hex_len,
    uint8_t *c2_Hex, int c2_Hex_len,
    uint8_t *c3_Hex, int c3_Hex_len,
    uint8_t *c4_Hex, int c4_Hex_len
    )
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Enc2 start************\n");
    printf("********************************\n");
#endif
    if( NULL == pk_Hex || pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == m_bytes || m_bytes_len != SHA256_DIGEST_LENGTH_32 ||
        NULL == w || w_len <= 0 ||
        NULL == c1_Hex || c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c2_Hex || c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c3_Hex || c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2 ||
        NULL == c4_Hex || c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("Enc2 input error \n");
        printf("NULL == pk_Hex = %d\n", NULL == pk_Hex);
        printf("pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_Hex_len = %d\n", 
            pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_Hex_len);
        printf("NULL == m_bytes = %d\n", NULL == m_bytes);
        printf("m_bytes_len != SHA256_DIGEST_LENGTH_32 = %d, m_bytes_len = %d\n", 
            m_bytes_len != SHA256_DIGEST_LENGTH_32, m_bytes_len);
        printf("NULL == w = %d\n", NULL == w);
        printf("w_len <= 0 = %d, w_len = %d\n", w_len <= 0, w_len);
        printf("NULL == c1_Hex = %d\n", NULL == c1_Hex);
        printf("c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c1_Hex_len = %d\n", 
            c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, c1_Hex_len);
        printf("NULL == c2_Hex = %d\n", NULL == c2_Hex);
        printf("c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c2_Hex_len = %d\n", 
            c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2, c2_Hex_len);
        printf("NULL == c3_Hex = %d\n", NULL == c3_Hex);
        printf("c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2 = %d, c3_Hex_len = %d\n", 
            c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2, c3_Hex_len);
        printf("NULL == c4_Hex = %d\n", NULL == c4_Hex);
        printf("c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c4_Hex_len = %d\n", 
            c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, c4_Hex_len);
        return -1;
    }

    int iRet = -1;

    //先把m_bytes转成0和1组成的bit,
    int m_len = m_bytes_len * 8;
    uint8_t *m = (uint8_t *)malloc(m_len);
    bytes_to_bits(m_bytes, m_bytes_len, m, m_len);
#ifdef PRINT_DEBUG_INFO
    printf("Enc2 m=\n");
    for(int i=0;i<m_len;)
    {
        printf("%c%c ", m[i], m[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    pairing_t pairing;
    element_t g;
    element_t Z;
    KeyPair keypair;
    iRet = Setup(pairing, g, Z);
    if(iRet != 0) 
    {
        printf("Enc2 Setup return %d, exit", iRet);
        return -1;
    }

    //import pk
    element_init_G1(keypair.pk, pairing);
    importKeyPair(&keypair, pk_Hex, pk_Hex_len, NULL, 0);


    CipherText ciphertext;
    element_init_G1(ciphertext.c1, pairing);
    element_init_GT(ciphertext.c2, pairing);
    element_init_G1(ciphertext.c4, pairing);

    // 为 ciphertext.c3 分配内存
    int c3_len = SHA256_DIGEST_LENGTH_32 * 8;
    ciphertext.c3 = (uint8_t *) malloc(c3_len);
    element_t R, r, hash2result, eresult, hash4result;
    element_init_GT(R, pairing);
    element_random(R);
    //r在调用Hash1前需要完成初始化
    element_init_Zr(r, pairing);
    
    //m是以\0结束的字符串
    Hash1(r, m, m_len, R); 

    //get c1
    element_pow_zn(ciphertext.c1, g, r);

    //hash2result在调用Hash2前需要完成初始化，w是以\0结束的字符串(已经指定长度，不用此限制)
    element_init_G1(hash2result, pairing);
    Hash2(hash2result, keypair.pk, w, w_len);


    element_init_GT(eresult, pairing);
    element_pairing(eresult, keypair.pk, hash2result);
    element_pow_zn(eresult, eresult, r);
    //get c2
    element_mul(ciphertext.c2, R, eresult);
    

    int hash3result_len = SHA256_DIGEST_LENGTH_32 * 8;
    uint8_t *hash3result = (uint8_t *) malloc(hash3result_len);
    Hash3(hash3result, hash3result_len, R);
#ifdef PRINT_DEBUG_INFO
    printf("Enc2 hash3result: \n");
    for(int i=0;i<hash3result_len;)
    {
        printf("%c%c ", hash3result[i], hash3result[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    //get c3
    xor_bitstrings(ciphertext.c3, m, m_len, hash3result, hash3result_len);
#ifdef PRINT_DEBUG_INFO
    printf("Enc2 length(ciphertext.c3) = %d, ciphertext.c3 =\n", c3_len);
    for(int i=0;i<c3_len;)
    {
        printf("%c%c ", ciphertext.c3[i], ciphertext.c3[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    //hash4result在调用Hash4前需要完成初始化
    element_init_G1(hash4result, pairing);
    Hash4(hash4result, ciphertext.c1, ciphertext.c2, ciphertext.c3, c3_len);
    //get c4
    element_pow_zn(ciphertext.c4, hash4result, r);

    //c1, c2, c4 conver to bytes
    iRet = exportCipherText(&ciphertext, c1_Hex, c1_Hex_len,
            c2_Hex, c2_Hex_len, 
            c3_Hex, c3_Hex_len, 
            c4_Hex, c4_Hex_len);
    if(iRet != 0) 
    {
        printf("Enc2 exportCipherText return = %d\n", iRet);
    }
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
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Enc2 end************\n");
    printf("********************************\n");
#endif

    return iRet;
}

// set R fix element
int EMSCRIPTEN_KEEPALIVE Enc2_debug(uint8_t *pk_Hex, int pk_Hex_len, 
    uint8_t *m_bytes, int m_bytes_len, 
    uint8_t *w, int w_len, 
    uint8_t *c1_Hex, int c1_Hex_len,
    uint8_t *c2_Hex, int c2_Hex_len,
    uint8_t *c3_Hex, int c3_Hex_len,
    uint8_t *c4_Hex, int c4_Hex_len
    )
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Enc2_debug start************\n");
    printf("********************************\n");
#endif
    if( NULL == pk_Hex || pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == m_bytes || m_bytes_len != SHA256_DIGEST_LENGTH_32 ||
        NULL == w || w_len <= 0 ||
        NULL == c1_Hex || c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c2_Hex || c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c3_Hex || c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2 ||
        NULL == c4_Hex || c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("Enc2_debug input error \n");
        printf("NULL == pk_Hex = %d\n", NULL == pk_Hex);
        printf("pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_Hex_len = %d\n", 
            pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_Hex_len);
        printf("NULL == m_bytes = %d\n", NULL == m_bytes);
        printf("m_bytes_len != SHA256_DIGEST_LENGTH_32 = %d, m_bytes_len = %d\n", 
            m_bytes_len != SHA256_DIGEST_LENGTH_32, m_bytes_len);
        printf("NULL == w = %d\n", NULL == w);
        printf("w_len <= 0 = %d, w_len = %d\n", w_len <= 0, w_len);
        printf("NULL == c1_Hex = %d\n", NULL == c1_Hex);
        printf("c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c1_Hex_len = %d\n", 
            c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, c1_Hex_len);
        printf("NULL == c2_Hex = %d\n", NULL == c2_Hex);
        printf("c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c2_Hex_len = %d\n", 
            c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2, c2_Hex_len);
        printf("NULL == c3_Hex = %d\n", NULL == c3_Hex);
        printf("c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2 = %d, c3_Hex_len = %d\n", 
            c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2, c3_Hex_len);
        printf("NULL == c4_Hex = %d\n", NULL == c4_Hex);
        printf("c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c4_Hex_len = %d\n", 
            c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, c4_Hex_len);
        return -1;
    }

    int iRet = -1;

    //先把m_bytes转成0和1组成的bit,
    int m_len = m_bytes_len * 8;
    uint8_t *m = (uint8_t *)malloc(m_len);
    bytes_to_bits(m_bytes, m_bytes_len, m, m_len);
#ifdef PRINT_DEBUG_INFO
    printf("Enc2_debug m=\n");
    for(int i=0;i<m_len;)
    {
        printf("%c%c ", m[i], m[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    pairing_t pairing;
    element_t g;
    element_t Z;
    KeyPair keypair;
    iRet = Setup(pairing, g, Z);
    if(iRet != 0) 
    {
        printf("Enc2_debug Setup return %d, exit", iRet);
        return -1;
    }

    //import pk
    element_init_G1(keypair.pk, pairing);
    importKeyPair(&keypair, pk_Hex, pk_Hex_len, NULL, 0);


    CipherText ciphertext;
    element_init_G1(ciphertext.c1, pairing);
    element_init_GT(ciphertext.c2, pairing);
    element_init_G1(ciphertext.c4, pairing);

    // 为 ciphertext.c3 分配内存
    int c3_len = SHA256_DIGEST_LENGTH_32 * 8;
    ciphertext.c3 = (uint8_t *) malloc(c3_len);
    element_t R, r, hash2result, eresult, hash4result;
    element_init_GT(R, pairing);
    // element_random(R);
    element_set_si(R, 3);
    //r在调用Hash1前需要完成初始化
    element_init_Zr(r, pairing);
    
    //m是以\0结束的字符串
    Hash1(r, m, m_len, R); 

    //get c1
    element_pow_zn(ciphertext.c1, g, r);

    //hash2result在调用Hash2前需要完成初始化，w是以\0结束的字符串(已经指定长度，不用此限制)
    element_init_G1(hash2result, pairing);
    Hash2(hash2result, keypair.pk, w, w_len);


    element_init_GT(eresult, pairing);
    element_pairing(eresult, keypair.pk, hash2result);
    element_pow_zn(eresult, eresult, r);
    //get c2
    element_mul(ciphertext.c2, R, eresult);
    

    int hash3result_len = SHA256_DIGEST_LENGTH_32 * 8;
    uint8_t *hash3result = (uint8_t *) malloc(hash3result_len);
    Hash3(hash3result, hash3result_len, R);
#ifdef PRINT_DEBUG_INFO
    printf("Enc2_debug hash3result: \n");
    for(int i=0;i<hash3result_len;)
    {
        printf("%c%c ", hash3result[i], hash3result[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    //get c3
    xor_bitstrings(ciphertext.c3, m, m_len, hash3result, hash3result_len);
#ifdef PRINT_DEBUG_INFO
    printf("Enc2_debug length(ciphertext.c3) = %d, ciphertext.c3 =\n", c3_len);
    for(int i=0;i<c3_len;)
    {
        printf("%c%c ", ciphertext.c3[i], ciphertext.c3[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    //hash4result在调用Hash4前需要完成初始化
    element_init_G1(hash4result, pairing);
    Hash4(hash4result, ciphertext.c1, ciphertext.c2, ciphertext.c3, c3_len);
    //get c4
    element_pow_zn(ciphertext.c4, hash4result, r);

    //c1, c2, c4 conver to bytes
    iRet = exportCipherText(&ciphertext, c1_Hex, c1_Hex_len,
            c2_Hex, c2_Hex_len, 
            c3_Hex, c3_Hex_len, 
            c4_Hex, c4_Hex_len);
    if(iRet != 0) 
    {
        printf("Enc2_debug exportCipherText return = %d\n", iRet);
    }
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
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Enc2_debug end************\n");
    printf("********************************\n");
#endif

    return iRet;
}

/*

uint8_t *pk_Hex: input, point to public key Hex string, should not be NULL
int pk_Hex_len: indicate the size of pk_Hex,
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *sk_Hex: input, point to secret key Hex string, should not be NULL
int sk_Hex_len: indicate the size of sk_Hex,
    should be equal to ZR_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *w:input, point to the condition, is a normal string
int w_len: input, indicate the length of w, should be greater than 0
uint8_t *c1_Hex: input, retrieve C1 with Hex string format from c1_Hex, should not be NULL
int c1_Hex_len: input, indicate the size of C1, 
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c2_Hex: input, retrieve C2 with Hex string format from c2_Hex, should not be NULL
int c2_Hex_len: input, indicate the size of C2, 
    should be equal to GT_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c3_Hex: input, retrieve C3 with Hex string format from c3_Hex, should not be NULL 
int c3_Hex_len: input, indicate the size of C3, 
    should be equal to SHA256_DIGEST_LENGTH_32 * 8 * 2
uint8_t *c4_Hex: input, retrieve C4 with Hex string format from c4_Hex, should not be NULL
int c4_Hex_len: input, indicate the size of C4, 
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *m_bytes:output, should not be null, no '\0' added
int m_bytes_len: input, indicate the size of m_bytes, 
    should be greater or equal to SHA256_DIGEST_LENGTH_32

*/
int EMSCRIPTEN_KEEPALIVE Dec2(uint8_t *pk_Hex, int pk_Hex_len, 
    uint8_t *sk_Hex, int sk_Hex_len, 
    uint8_t *w, int w_len, 
    uint8_t *c1_Hex, int c1_Hex_len,
    uint8_t *c2_Hex, int c2_Hex_len,
    uint8_t *c3_Hex, int c3_Hex_len,
    uint8_t *c4_Hex, int c4_Hex_len,
    uint8_t *m_bytes, int m_bytes_len
    )
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Dec2 start************\n");
    printf("********************************\n");
#endif
    if( NULL == pk_Hex || pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == sk_Hex || sk_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == w || w_len <= 0 ||
        NULL == c1_Hex || c1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c2_Hex || c2_Hex_len != GT_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c3_Hex || c3_Hex_len != SHA256_DIGEST_LENGTH_32 * 8 * 2 ||
        NULL == c4_Hex || c4_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == m_bytes || m_bytes_len < SHA256_DIGEST_LENGTH_32)
    {
        printf("Dec2 input error \n");
        printf("NULL == pk_Hex = %d\n", NULL == pk_Hex);
        printf("pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_Hex_len = %d\n", 
            pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_Hex_len);
        printf("NULL == sk_Hex = %d\n", NULL == sk_Hex);
        printf("sk_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2 = %d, sk_Hex_len = %d\n", 
            sk_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2, sk_Hex_len);
        printf("NULL == w = %d\n", NULL == w);
        printf("w_len <= 0 = %d, w_len = %d\n", w_len <= 0, w_len);
        printf("NULL == c1_Hex = %d\n", NULL == c1_Hex);
        printf("c1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c1_Hex_len = %d\n", 
            c1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, c1_Hex_len);
        printf("NULL == c2_Hex = %d\n", NULL == c2_Hex);
        printf("c2_Hex_len != GT_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c2_Hex_len = %d\n", 
            c2_Hex_len != GT_ELEMENT_LENGTH_IN_BYTES * 2, c2_Hex_len);
        printf("NULL == c3_Hex = %d\n", NULL == c3_Hex);
        printf("c3_Hex_len != SHA256_DIGEST_LENGTH_32 * 8 * 2 = %d, c3_Hex_len = %d\n", 
            c3_Hex_len != SHA256_DIGEST_LENGTH_32 * 8 * 2, c3_Hex_len);
        printf("NULL == c4_Hex = %d\n", NULL == c4_Hex);
        printf("c4_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c4_Hex_len = %d\n", 
            c4_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, c4_Hex_len);
        printf("NULL == m_bytes = %d\n", NULL == m_bytes);
        printf("m_bytes_len < SHA256_DIGEST_LENGTH_32 = %d, m_bytes_len = %d\n", 
            m_bytes_len < SHA256_DIGEST_LENGTH_32, m_bytes_len);
        return -1;
    }

    int iRet = -1;

    pairing_t pairing;
    element_t g;
    element_t Z;
    KeyPair keypair;
    iRet = Setup(pairing, g, Z);
    if(iRet != 0) 
    {
        printf("Dec2 Setup return %d, exit", iRet);
        return -1;
    }

    //import ciphertext
    CipherText ciphertext;
    element_init_G1(ciphertext.c1, pairing);
    element_init_GT(ciphertext.c2, pairing);
    element_init_G1(ciphertext.c4, pairing);
    // 为 ciphertext.c3 分配内存
    int c3_len = SHA256_DIGEST_LENGTH_32 * 8;
    ciphertext.c3 = (uint8_t *) malloc(c3_len);
    iRet = importCipherText(&ciphertext, c1_Hex, c1_Hex_len,
        c2_Hex, c2_Hex_len, c3_Hex, c3_Hex_len, 
        c4_Hex, c4_Hex_len);

    iRet = checkEqual4(pairing, g, &ciphertext);
    if(iRet != 0) 
    {
        printf("Dec2 checkEqual4 return %d, exit", iRet);
        return -1;
    }

    //import pk, sk，需要先完成初始化
    element_init_G1(keypair.pk, pairing);
    element_init_Zr(keypair.sk, pairing);
    importKeyPair(&keypair, pk_Hex, pk_Hex_len, sk_Hex, sk_Hex_len);

    element_t hash2result, eresult, R;
    element_init_G1(hash2result, pairing);
    element_init_GT(eresult, pairing);
    element_init_GT(R, pairing);

    Hash2(hash2result, keypair.pk, w, w_len);

    element_pairing(eresult, ciphertext.c1, hash2result);
    element_pow_zn(eresult, eresult, keypair.sk);
    element_invert(eresult, eresult);
    element_mul(R, ciphertext.c2, eresult);
    int hash3result_len = SHA256_DIGEST_LENGTH_32 * 8;
    uint8_t *hash3result = (uint8_t *) malloc(hash3result_len);
    Hash3(hash3result, hash3result_len, R);
#ifdef PRINT_DEBUG_INFO
    printf("Dec2 hash3result: \n");
    for(int i=0;i<hash3result_len;) 
    {
        printf("%c%c ", hash3result[i], hash3result[i + 1]);
        i += 2;
    }
    printf("\n");
#endif

    int m_len = SHA256_DIGEST_LENGTH_32 * 8;
    uint8_t *m = (uint8_t *) malloc(m_len);
    xor_bitstrings(m, ciphertext.c3, c3_len,
        hash3result, hash3result_len);
#ifdef PRINT_DEBUG_INFO
    printf("Dec2 m=\n");
    for(int i=0;i<m_len;) 
    {
        printf("%c%c ", m[i], m[i + 1]);
        i += 2;
    }
    printf("\n");
#endif

    //verify g^H1(m, R) == C1
    element_t hash1result;
    element_init_Zr(hash1result, pairing);
    Hash1(hash1result, m, m_len, R); 
    element_t c1_2;
    element_init_G1(c1_2, pairing);
    element_pow_zn(c1_2, g, hash1result);
    iRet = element_cmp(c1_2, ciphertext.c1);
    if (element_cmp(c1_2, ciphertext.c1) != 0) {
        printf("Dec2 verify g^H1(m, R) == c1 fail\n");
    }
    else 
    {
        printf("Dec2 verify g^H1(m, R) == c1 success\n");
        bits_to_bytes(m, m_len, m_bytes, m_bytes_len);
#ifdef PRINT_DEBUG_INFO
        printf("Dec2 m_bytes = %s\n", m_bytes);
#endif
    }
    
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

#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Dec2 end************\n");
    printf("********************************\n");
#endif
    return iRet;
}


/*
uint8_t *pk_j_Hex: input, point to public key Hex string of j(receriver), 
    should not be NULL
int pk_j_Hex_len: indicate the size of pk_j_Hex,
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *sk_i_Hex: input, point to secret key Hex string of i(sender), 
    should not be NULL
int sk_i_Hex_len: indicate the size of sk_i_Hex,
    should be equal to ZR_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *pk_i_Hex: input, point to public key Hex string of i(sender), 
    should not be NULL
int pk_i_Hex_len: indicate the size of pk_i_Hex,
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *w:input, point to the condition, is a normal string
int w_len: input, indicate the length of w, should be greater than 0
uint8_t *rk1_Hex: output, save rk1 with Hex string format in rk1_Hex, should not be NULL
int rk1_Hex_len: input, indicate the size of rk1_Hex, 
    should be greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *rk2_Hex: output, save rk2 with Hex string format in rk2_Hex, should not be NULL
int rk2_Hex_len: input, indicate the size of rk2_Hex, 
    should be greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
*/
int EMSCRIPTEN_KEEPALIVE ReKeyGen(uint8_t *pk_j_Hex, int pk_j_Hex_len, 
    uint8_t *sk_i_Hex, int sk_i_Hex_len, 
    uint8_t *pk_i_Hex, int pk_i_Hex_len, 
    uint8_t *w, int w_len,
    uint8_t *rk1_Hex, int rk1_Hex_len,
    uint8_t *rk2_Hex, int rk2_Hex_len)
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********ReKeyGen start************\n");
    printf("********************************\n");
#endif
    if( NULL == pk_j_Hex || pk_j_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == sk_i_Hex || sk_i_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == pk_i_Hex || pk_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == w || w_len <= 0 ||
        NULL == rk1_Hex || rk1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == rk2_Hex || rk2_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("ReKeyGen input error \n");
        printf("NULL == pk_j_Hex = %d\n", NULL == pk_j_Hex);
        printf("pk_j_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_j_Hex_len = %d\n", 
            pk_j_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_j_Hex_len);
        printf("NULL == sk_i_Hex = %d\n", NULL == sk_i_Hex);
        printf("sk_i_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2 = %d, sk_i_Hex_len = %d\n", 
            sk_i_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2, sk_i_Hex_len);
        printf("NULL == pk_i_Hex = %d\n", NULL == pk_i_Hex);
        printf("pk_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_i_Hex_len = %d\n", 
            pk_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_i_Hex_len);
        printf("NULL == w = %d\n", NULL == w);
        printf("w_len <= 0 = %d, w_len = %d\n", w_len <= 0, w_len);
        printf("NULL == rk1_Hex = %d\n", NULL == rk1_Hex);
        printf("rk1_Hex_len <= G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, rk1_Hex_len = %d\n", 
            rk1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, rk1_Hex_len);
        printf("NULL == rk2_Hex = %d\n", NULL == rk2_Hex);
        printf("rk2_Hex_len <= G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, rk2_Hex_len = %d\n", 
            rk2_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, rk2_Hex_len);
        return -1;
    }

    int iRet = -1;

    pairing_t pairing;
    element_t g;
    element_t Z;
    iRet = Setup(pairing, g, Z);
    if(iRet != 0) 
    {
        printf("ReKeyGen Setup return %d, exit", iRet);
        return -1;
    }

    //import pk, sk，需要先完成初始化
    KeyPair keypair_i, keypair_j;
    element_init_Zr(keypair_i.sk, pairing);
    element_init_G1(keypair_i.pk, pairing);
    element_init_G1(keypair_j.pk, pairing);
    importKeyPair(&keypair_i, pk_i_Hex, pk_i_Hex_len, sk_i_Hex, sk_i_Hex_len);
    importKeyPair(&keypair_j, pk_j_Hex, pk_j_Hex_len, NULL, 0);

    ReKeyPair rk_ij;
    element_init_G1(rk_ij.rk1, pairing);
    element_init_G1(rk_ij.rk2, pairing);
    element_t hash2result, powresult, s, negski;
    element_init_G1(powresult, pairing);
    element_init_G1(hash2result, pairing);
    element_init_Zr(negski, pairing);
    element_init_Zr(s, pairing);
    element_random(s);
    Hash2(hash2result, keypair_i.pk, w, w_len);
    element_pow_zn(powresult, keypair_j.pk, s);
    element_mul(rk_ij.rk1, hash2result, powresult);
    element_neg(negski, keypair_i.sk);
    element_pow_zn(rk_ij.rk1, rk_ij.rk1, negski);
    element_pow_zn(rk_ij.rk2, keypair_i.pk, s);

    //convert rk_ij to Hex
    exportReKeyPair(&rk_ij, rk1_Hex, rk1_Hex_len, rk2_Hex, rk2_Hex_len);


    element_clear(negski);
    element_clear(s);
    element_clear(powresult);
    element_clear(hash2result);
    element_clear(rk_ij.rk1);
    element_clear(rk_ij.rk2);
    element_clear(keypair_i.pk);
    element_clear(keypair_i.sk);
    element_clear(keypair_j.pk);
    element_clear(Z);
    element_clear(g);
    pairing_clear(pairing);	

#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********ReKeyGen end************\n");
    printf("********************************\n");
#endif
    return 0;
}


int EMSCRIPTEN_KEEPALIVE ReKeyGen_debug(uint8_t *pk_j_Hex, int pk_j_Hex_len, 
    uint8_t *sk_i_Hex, int sk_i_Hex_len, 
    uint8_t *pk_i_Hex, int pk_i_Hex_len, 
    uint8_t *w, int w_len,
    uint8_t *rk1_Hex, int rk1_Hex_len,
    uint8_t *rk2_Hex, int rk2_Hex_len)
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********ReKeyGen_debug start************\n");
    printf("********************************\n");
#endif
    if( NULL == pk_j_Hex || pk_j_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == sk_i_Hex || sk_i_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == pk_i_Hex || pk_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == w || w_len <= 0 ||
        NULL == rk1_Hex || rk1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == rk2_Hex || rk2_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("ReKeyGen input error \n");
        printf("NULL == pk_j_Hex = %d\n", NULL == pk_j_Hex);
        printf("pk_j_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_j_Hex_len = %d\n", 
            pk_j_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_j_Hex_len);
        printf("NULL == sk_i_Hex = %d\n", NULL == sk_i_Hex);
        printf("sk_i_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2 = %d, sk_i_Hex_len = %d\n", 
            sk_i_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2, sk_i_Hex_len);
        printf("NULL == pk_i_Hex = %d\n", NULL == pk_i_Hex);
        printf("pk_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_i_Hex_len = %d\n", 
            pk_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_i_Hex_len);
        printf("NULL == w = %d\n", NULL == w);
        printf("w_len <= 0 = %d, w_len = %d\n", w_len <= 0, w_len);
        printf("NULL == rk1_Hex = %d\n", NULL == rk1_Hex);
        printf("rk1_Hex_len <= G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, rk1_Hex_len = %d\n", 
            rk1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, rk1_Hex_len);
        printf("NULL == rk2_Hex = %d\n", NULL == rk2_Hex);
        printf("rk2_Hex_len <= G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, rk2_Hex_len = %d\n", 
            rk2_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, rk2_Hex_len);
        return -1;
    }

    int iRet = -1;

    pairing_t pairing;
    element_t g;
    element_t Z;
    iRet = Setup(pairing, g, Z);
    if(iRet != 0) 
    {
        printf("ReKeyGen_debug Setup return %d, exit", iRet);
        return -1;
    }

    //import pk, sk，需要先完成初始化
    KeyPair keypair_i, keypair_j;
    element_init_Zr(keypair_i.sk, pairing);
    element_init_G1(keypair_i.pk, pairing);
    element_init_G1(keypair_j.pk, pairing);
    importKeyPair(&keypair_i, pk_i_Hex, pk_i_Hex_len, sk_i_Hex, sk_i_Hex_len);
    importKeyPair(&keypair_j, pk_j_Hex, pk_j_Hex_len, NULL, 0);

    ReKeyPair rk_ij;
    element_init_G1(rk_ij.rk1, pairing);
    element_init_G1(rk_ij.rk2, pairing);
    element_t hash2result, powresult, s, negski;
    element_init_G1(powresult, pairing);
    element_init_G1(hash2result, pairing);
    element_init_Zr(negski, pairing);
    element_init_Zr(s, pairing);
    // element_random(s);
    element_set_si(s, 2);
    Hash2(hash2result, keypair_i.pk, w, w_len);
    element_pow_zn(powresult, keypair_j.pk, s);
    element_mul(rk_ij.rk1, hash2result, powresult);
    element_neg(negski, keypair_i.sk);
    element_pow_zn(rk_ij.rk1, rk_ij.rk1, negski);
    element_pow_zn(rk_ij.rk2, keypair_i.pk, s);

    //convert rk_ij to Hex
    exportReKeyPair(&rk_ij, rk1_Hex, rk1_Hex_len, rk2_Hex, rk2_Hex_len);


    element_clear(negski);
    element_clear(s);
    element_clear(powresult);
    element_clear(hash2result);
    element_clear(rk_ij.rk1);
    element_clear(rk_ij.rk2);
    element_clear(keypair_i.pk);
    element_clear(keypair_i.sk);
    element_clear(keypair_j.pk);
    element_clear(Z);
    element_clear(g);
    pairing_clear(pairing);	

#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********ReKeyGen_debug end************\n");
    printf("********************************\n");
#endif
    return 0;
}

/*
reEncrypt c_i to c_j with ReKeyPair rk

uint8_t *c1_i_Hex: input, should not be NULL
int c1_i_Hex_len: input, indicate the length of c1_i_Hex, 
    should equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c2_i_Hex: input, should not be NULL
int c2_i_Hex_len: input, indicate the length of c2_i_Hex, 
    should equal to GT_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c3_i_Hex: input, should not be NULL
int c3_i_Hex_len: input, indicate the length of c3_i_Hex, 
    should equal to SHA256_DIGEST_LENGTH_32 * 8 * 2
uint8_t *c4_i_Hex: input, should not be NULL
int c4_i_Hex_len: input, indicate the length of c4_i_Hex, 
    should equal to G1_ELEMENT_LENGTH_IN_BYTES * 2

uint8_t *rk1_Hex: input, retrieve rk1 with Hex string format from rk1_Hex, should not be NULL
int rk1_Hex_len: input, indicate the size of rk1_Hex, 
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *rk2_Hex: input, retrieve rk2 with Hex string format from rk2_Hex, should not be NULL
int rk2_Hex_len: input, indicate the size of rk2_Hex, 
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2

uint8_t *c1_j_Hex: output, save C1 with Hex string format in c1_j_Hex, should not be NULL
int c1_j_Hex_len: input, indicate the size of c1_j_Hex, 
    should greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c2_Hex: output, save C2 with Hex string format in c2_j_Hex, should not be NULL
int c2_j_Hex_len: input, indicate the size of c2_j_Hex, 
    should greater or equal to GT_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c3_j_Hex: output, save C3 with Hex string format in c3_j_Hex, should not be NULL
int c3_j_Hex_len: input, indicate the size of c3_j_Hex, 
    should greater or equal to SHA256_DIGEST_LENGTH_32 * 8 * 2
uint8_t *c4_j_Hex: output, save C4 with Hex string format in c4_j_Hex, should not be NULL
int c4_j_Hex_len: input, indicate the size of c4_j_Hex, 
    should greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
*/
int EMSCRIPTEN_KEEPALIVE ReEnc(uint8_t *c1_i_Hex, int c1_i_Hex_len,
    uint8_t *c2_i_Hex, int c2_i_Hex_len,
    uint8_t *c3_i_Hex, int c3_i_Hex_len,
    uint8_t *c4_i_Hex, int c4_i_Hex_len,
    uint8_t *rk1_Hex, int rk1_Hex_len,
    uint8_t *rk2_Hex, int rk2_Hex_len,
    uint8_t *c1_j_Hex, int c1_j_Hex_len, 
    uint8_t *c2_j_Hex, int c2_j_Hex_len, 
    uint8_t *c3_j_Hex, int c3_j_Hex_len, 
    uint8_t *c4_j_Hex, int c4_j_Hex_len
    )
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********ReEnc start************\n");
    printf("********************************\n");
#endif
    if( NULL == c1_i_Hex || c1_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c2_i_Hex || c2_i_Hex_len != GT_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c3_i_Hex || c3_i_Hex_len != SHA256_DIGEST_LENGTH_32 * 8 * 2 ||
        NULL == c4_i_Hex || c4_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == rk1_Hex || rk1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == rk2_Hex || rk2_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c1_j_Hex || c1_j_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c2_j_Hex || c2_j_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c3_j_Hex || c3_j_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2 ||
        NULL == c4_j_Hex || c4_j_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("ReKeyGen input error \n");
        printf("NULL == c1_i_Hex = %d\n", NULL == c1_i_Hex);
        printf("c1_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c1_i_Hex_len = %d\n", 
            c1_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, c1_i_Hex_len);
        printf("NULL == c2_i_Hex = %d\n", NULL == c2_i_Hex);
        printf("c2_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c2_i_Hex_len = %d\n", 
            c2_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, c2_i_Hex_len);
        printf("NULL == c3_i_Hex = %d\n", NULL == c3_i_Hex);
        printf("c3_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c3_i_Hex_len = %d\n", 
            c3_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, c3_i_Hex_len);
        printf("NULL == c4_i_Hex = %d\n", NULL == c4_i_Hex);
        printf("c4_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c4_i_Hex_len = %d\n", 
            c4_i_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, c4_i_Hex_len);
        printf("NULL == rk1_Hex = %d\n", NULL == rk1_Hex);
        printf("rk1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, rk1_Hex_len = %d\n", 
            rk1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, rk1_Hex_len);
        printf("NULL == rk2_Hex = %d\n", NULL == rk2_Hex);
        printf("rk2_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, rk2_Hex_len = %d\n", 
            rk2_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, rk2_Hex_len);
        printf("NULL == c1_j_Hex = %d\n", NULL == c1_j_Hex);
        printf("c1_j_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c1_j_Hex_len = %d\n", 
            c1_j_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, c1_j_Hex_len);
        printf("NULL == c2_j_Hex = %d\n", NULL == c2_j_Hex);
        printf("c2_j_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c2_j_Hex_len = %d\n", 
            c2_j_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, c2_j_Hex_len);
        printf("NULL == c3_j_Hex = %d\n", NULL == c3_j_Hex);
        printf("c3_j_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c3_j_Hex_len = %d\n", 
            c3_j_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, c3_j_Hex_len);
        printf("NULL == c4_j_Hex = %d\n", NULL == c4_j_Hex);
        printf("c4_j_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c4_j_Hex_len = %d\n", 
            c4_j_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, c4_j_Hex_len);
        
        return -1;
    }

    int iRet = -1;
    pairing_t pairing;
    element_t g;
    element_t Z;
    iRet = Setup(pairing, g, Z);
    if(iRet != 0) 
    {
        printf("ReEnc Setup return %d, exit", iRet);
        return -1;
    }

    //import ciphertext
    CipherText CT_i;
    element_init_G1(CT_i.c1, pairing);
    element_init_GT(CT_i.c2, pairing);
    element_init_G1(CT_i.c4, pairing);
    // 为 ciphertext.c3 分配内存
    int c3_len = SHA256_DIGEST_LENGTH_32 * 8;
    CT_i.c3 = (uint8_t *) malloc(c3_len);
    iRet = importCipherText(&CT_i, c1_i_Hex, c1_i_Hex_len,
        c2_i_Hex, c2_i_Hex_len, c3_i_Hex, c3_i_Hex_len, 
        c4_i_Hex, c4_i_Hex_len);
    
    //import reKeyPair
    ReKeyPair rk_ij;
    element_init_G1(rk_ij.rk1, pairing);
    element_init_G1(rk_ij.rk2, pairing);
    iRet = importReKeyPair(&rk_ij, rk1_Hex, rk1_Hex_len,
        rk2_Hex, rk2_Hex_len);
    
    //initiate CT_j
    CipherText CT_j;
    element_init_G1(CT_j.c1, pairing);
    element_init_GT(CT_j.c2, pairing);
    element_init_G1(CT_j.c4, pairing);
    // 为 ciphertext.c3 分配内存
    CT_j.c3 = (uint8_t *) malloc(c3_len);

    
    iRet = checkEqual4(pairing, g, &CT_i);
    if(iRet != 0) 
    {
        printf("ReEnc checkEqual4 return %d, exit", iRet);
        element_clear(CT_j.c1);
        element_clear(CT_j.c2);
        free(CT_j.c3);
        element_clear(CT_j.c4);
        element_clear(rk_ij.rk1);
        element_clear(rk_ij.rk2);
        element_clear(CT_i.c1);
        element_clear(CT_i.c2);
        free(CT_i.c3);
        element_clear(CT_i.c4);
        element_clear(Z);
        element_clear(g);
        pairing_clear(pairing);
        return -1;
    }

    // 双线性对匹配，继续重加密
    // C̄1 = C1
    element_set(CT_j.c1, CT_i.c1);

    // C̄2 = C2 · e(C1, rk1)
    element_t pairing3;
    element_init_GT(pairing3, pairing);
    element_pairing(pairing3, CT_i.c1, rk_ij.rk1);
    element_mul(CT_j.c2, CT_i.c2, pairing3);

    // C̄3 = C3 (复制第三部分)
    memcpy(CT_j.c3, CT_i.c3, c3_len);
    // strcpy((char *)CT_j.c3, (char *)CT_i.c3);

    // C̄4 = rk2
    element_set(CT_j.c4, rk_ij.rk2);

    exportCipherText(&CT_j, c1_j_Hex, c1_j_Hex_len, 
        c2_j_Hex, c2_j_Hex_len, 
        c3_j_Hex, c3_j_Hex_len, 
        c4_j_Hex, c4_j_Hex_len);
    

    element_clear(pairing3);
    element_clear(CT_j.c1);
    element_clear(CT_j.c2);
    free(CT_j.c3);
    element_clear(CT_j.c4);
    element_clear(rk_ij.rk1);
    element_clear(rk_ij.rk2);
    element_clear(CT_i.c1);
    element_clear(CT_i.c2);
    free(CT_i.c3);
    element_clear(CT_i.c4);
    element_clear(Z);
    element_clear(g);
    pairing_clear(pairing);	
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********ReEnc end************\n");
    printf("********************************\n");
#endif
    
    return iRet;
    
}


//m是AES-GCM key，长度是256bit，32字节
/*
uint8_t *pk_Hex: input, point to public key Hex string, should not be NULL
int pk_Hex_len: indicate the size of pk_Hex,
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *m_bytes: input, point to the message which need to be encrypt, is a normal string
int m_bytes_len: input, indicate the length of m_bytes, should be equal to SHA256_DIGEST_LENGTH_32
uint8_t *c1_Hex: output, save C1 with Hex string format in c1_Hex, should not be NULL
int c1_Hex_len: input, indicate the size of c1_Hex, 
    should greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c2_Hex: output, save C2 with Hex string format in c2_Hex, should not be NULL
int c2_Hex_len: input, indicate the size of c2_Hex, 
    should greater or equal to GT_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c3_Hex: output, save C3 with Hex string format in c3_Hex, should not be NULL
int c3_Hex_len: input, indicate the size of c3_Hex, 
    should greater or equal to SHA256_DIGEST_LENGTH_32 * 8 * 2
uint8_t *c4_Hex: output, save C4 with Hex string format in c4_Hex, should not be NULL
int c4_Hex_len: input, indicate the size of c4_Hex, 
    should greater or equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
*/
int EMSCRIPTEN_KEEPALIVE Enc1(uint8_t *pk_Hex, int pk_Hex_len, 
    uint8_t *m_bytes, int m_bytes_len, 
    uint8_t *c1_Hex, int c1_Hex_len, 
    uint8_t *c2_Hex, int c2_Hex_len, 
    uint8_t *c3_Hex, int c3_Hex_len, 
    uint8_t *c4_Hex, int c4_Hex_len
    )
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Enc1 start************\n");
    printf("********************************\n");
#endif
    if( NULL == pk_Hex || pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == m_bytes || m_bytes_len != SHA256_DIGEST_LENGTH_32 ||
        NULL == c1_Hex || c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c2_Hex || c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c3_Hex || c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2 ||
        NULL == c4_Hex || c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2)
    {
        printf("Enc1 input error \n");
        printf("NULL == pk_Hex = %d\n", NULL == pk_Hex);
        printf("pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_Hex_len = %d\n", 
            pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_Hex_len);
        printf("NULL == m_bytes = %d\n", NULL == m_bytes);
        printf("m_bytes_len != SHA256_DIGEST_LENGTH_32 = %d, m_bytes_len = %d\n", 
            m_bytes_len != SHA256_DIGEST_LENGTH_32, m_bytes_len);
        printf("NULL == c1_Hex = %d\n", NULL == c1_Hex);
        printf("c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c1_Hex_len = %d\n", 
            c1_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, c1_Hex_len);
        printf("NULL == c2_Hex = %d\n", NULL == c2_Hex);
        printf("c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c2_Hex_len = %d\n", 
            c2_Hex_len < GT_ELEMENT_LENGTH_IN_BYTES * 2, c2_Hex_len);
        printf("NULL == c3_Hex = %d\n", NULL == c3_Hex);
        printf("c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2 = %d, c3_Hex_len = %d\n", 
            c3_Hex_len < SHA256_DIGEST_LENGTH_32 * 8 * 2, c3_Hex_len);
        printf("NULL == c4_Hex = %d\n", NULL == c4_Hex);
        printf("c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c4_Hex_len = %d\n", 
            c4_Hex_len < G1_ELEMENT_LENGTH_IN_BYTES * 2, c4_Hex_len);
        return -1;
    }
    int iRet = -1;

    //先把m_bytes转成bit
    int m_len = m_bytes_len * 8;
    uint8_t *m = (uint8_t *)malloc(m_len);
    bytes_to_bits(m_bytes, m_bytes_len, m, m_len);
#ifdef PRINT_DEBUG_INFO
    printf("Enc1 m=\n");
    for(int i=0;i<m_len;)
    {
        printf("%c%c ", m[i], m[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    pairing_t pairing;
    element_t g;
    element_t Z;
    KeyPair keypair;
    iRet = Setup(pairing, g, Z);
    if(iRet != 0) 
    {
        printf("Enc1 Setup return %d, exit", iRet);
        return -1;
    }

    //import pk
    element_init_G1(keypair.pk, pairing);
    importKeyPair(&keypair, pk_Hex, pk_Hex_len, NULL, 0);

    CipherText ciphertext;
    element_init_G1(ciphertext.c1, pairing);
    element_init_GT(ciphertext.c2, pairing);
    element_init_G1(ciphertext.c4, pairing);

    // 为 ciphertext.c3 分配内存
    int c3_len = SHA256_DIGEST_LENGTH_32 * 8;
    ciphertext.c3 = (uint8_t *) malloc(c3_len);

    element_t R, r, s0, eresult, emuls;
    element_init_GT(R, pairing);
    element_random(R);
    element_init_Zr(s0, pairing);
    element_random(s0);
    element_init_Zr(r, pairing);
    element_init_GT(eresult, pairing);
    element_init_Zr(emuls, pairing);
    Hash1(r, m, m_len, R); 
    element_pow_zn(ciphertext.c1, g, r);
    element_mul(emuls, s0, r);
    element_neg(emuls, emuls);
    element_pairing(eresult, g, keypair.pk);
    element_pow_zn(eresult, eresult, emuls);
    element_mul(ciphertext.c2, R, eresult);
    int hash3result_len = SHA256_DIGEST_LENGTH_32 * 8;
    uint8_t *hash3result = (uint8_t *) malloc(hash3result_len);
    Hash3(hash3result, hash3result_len, R);
    xor_bitstrings(ciphertext.c3, m, m_len,
        hash3result, hash3result_len);
    element_pow_zn(ciphertext.c4, g, s0);

    //export ciphertext
    exportCipherText(&ciphertext, c1_Hex, c1_Hex_len, 
        c2_Hex, c2_Hex_len, 
        c3_Hex, c3_Hex_len, 
        c4_Hex, c4_Hex_len);

    free(hash3result);
    element_clear(emuls);
    element_clear(eresult);
    element_clear(s0);
    element_clear(r);
    element_clear(R);
    element_clear(ciphertext.c1);
    element_clear(ciphertext.c2);
    free(ciphertext.c3);
    element_clear(ciphertext.c4);
    element_clear(keypair.pk);
    free(m);
    element_clear(Z);
    element_clear(g);
    pairing_clear(pairing);	

#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Enc1 end************\n");
    printf("********************************\n");
#endif
    return 0;
}


/*
uint8_t *pk_Hex: input, point to public key Hex string, should not be NULL
int pk_Hex_len: indicate the size of pk_Hex,
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *sk_Hex: input, point to secret key Hex string, should not be NULL
int sk_Hex_len: indicate the size of sk_Hex,
    should be equal to ZR_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c1_Hex: input, retrieve C1 with Hex string format from c1_Hex, should not be NULL
int c1_Hex_len: input, indicate the size of C1, 
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c2_Hex: input, retrieve C2 with Hex string format from c2_Hex, should not be NULL
int c2_Hex_len: input, indicate the size of C2, 
    should be equal to GT_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *c3_Hex: input, retrieve C3 with Hex string format from c3_Hex, should not be NULL 
int c3_Hex_len: input, indicate the size of C3, 
    should be equal to SHA256_DIGEST_LENGTH_32 * 8 * 2
uint8_t *c4_Hex: input, retrieve C4 with Hex string format from c4_Hex, should not be NULL
int c4_Hex_len: input, indicate the size of C4, 
    should be equal to G1_ELEMENT_LENGTH_IN_BYTES * 2
uint8_t *m_bytes:output, save m with a '\0', should not be NULL
int m_bytes_len: input, indicate the size of m_bytes, 
    should be greater or equal to SHA256_DIGEST_LENGTH_32

*/
int EMSCRIPTEN_KEEPALIVE Dec1(uint8_t *pk_Hex, int pk_Hex_len, 
    uint8_t *sk_Hex, int sk_Hex_len, 
    uint8_t *c1_Hex, int c1_Hex_len,
    uint8_t *c2_Hex, int c2_Hex_len,
    uint8_t *c3_Hex, int c3_Hex_len,
    uint8_t *c4_Hex, int c4_Hex_len,
    uint8_t *m_bytes, int m_bytes_len
    )
{
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Dec1 start************\n");
    printf("********************************\n");
#endif
    if( NULL == pk_Hex || pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == sk_Hex || sk_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c1_Hex || c1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c2_Hex || c2_Hex_len != GT_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == c3_Hex || c3_Hex_len != SHA256_DIGEST_LENGTH_32 * 8 * 2 ||
        NULL == c4_Hex || c4_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 ||
        NULL == m_bytes || m_bytes_len < SHA256_DIGEST_LENGTH_32)
    {
        printf("Dec1 input error \n");
        printf("NULL == pk_Hex = %d\n", NULL == pk_Hex);
        printf("pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, pk_Hex_len = %d\n", 
            pk_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, pk_Hex_len);
        printf("NULL == sk_Hex = %d\n", NULL == sk_Hex);
        printf("sk_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2 = %d, sk_Hex_len = %d\n", 
            sk_Hex_len != ZR_ELEMENT_LENGTH_IN_BYTES * 2, sk_Hex_len);
        printf("NULL == c1_Hex = %d\n", NULL == c1_Hex);
        printf("c1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c1_Hex_len = %d\n", 
            c1_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, c1_Hex_len);
        printf("NULL == c2_Hex = %d\n", NULL == c2_Hex);
        printf("c2_Hex_len != GT_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c2_Hex_len = %d\n", 
            c2_Hex_len != GT_ELEMENT_LENGTH_IN_BYTES * 2, c2_Hex_len);
        printf("NULL == c3_Hex = %d\n", NULL == c3_Hex);
        printf("c3_Hex_len != SHA256_DIGEST_LENGTH_32 * 8 * 2 = %d, c3_Hex_len = %d\n", 
            c3_Hex_len != SHA256_DIGEST_LENGTH_32 * 8 * 2, c3_Hex_len);
        printf("NULL == c4_Hex = %d\n", NULL == c4_Hex);
        printf("c4_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2 = %d, c4_Hex_len = %d\n", 
            c4_Hex_len != G1_ELEMENT_LENGTH_IN_BYTES * 2, c4_Hex_len);
        printf("NULL == m_bytes = %d\n", NULL == m_bytes);
        printf("m_bytes_len < SHA256_DIGEST_LENGTH_32 = %d, m_bytes_len = %d\n", 
            m_bytes_len < SHA256_DIGEST_LENGTH_32, m_bytes_len);
        return -1;
    }
    int iRet = -1;

    pairing_t pairing;
    element_t g;
    element_t Z;
    KeyPair keypair;
    iRet = Setup(pairing, g, Z);
    if(iRet != 0) 
    {
        printf("Dec1 Setup return %d, exit", iRet);
        return -1;
    }

    //import ciphertext
    CipherText ciphertext;
    element_init_G1(ciphertext.c1, pairing);
    element_init_GT(ciphertext.c2, pairing);
    element_init_G1(ciphertext.c4, pairing);
    // 为 ciphertext.c3 分配内存
    int c3_len = SHA256_DIGEST_LENGTH_32 * 8;
    ciphertext.c3 = (uint8_t *) malloc(c3_len);
    iRet = importCipherText(&ciphertext, c1_Hex, c1_Hex_len,
        c2_Hex, c2_Hex_len, c3_Hex, c3_Hex_len, 
        c4_Hex, c4_Hex_len);
    
    //import keypair
    element_init_G1(keypair.pk, pairing);
    element_init_Zr(keypair.sk, pairing);
    importKeyPair(&keypair, pk_Hex, pk_Hex_len, sk_Hex, sk_Hex_len);

    element_t R, eresult;
    element_init_GT(R, pairing);
    element_init_GT(eresult, pairing);

    element_pairing(eresult, ciphertext.c1, ciphertext.c4);
    element_pow_zn(eresult, eresult, keypair.sk);
    element_mul(R, ciphertext.c2, eresult);

    int hash3result_len = SHA256_DIGEST_LENGTH_32 * 8;
    uint8_t *hash3result = (uint8_t *) malloc(hash3result_len);
    Hash3(hash3result, hash3result_len, R);
    int m_len = SHA256_DIGEST_LENGTH_32 * 8;
    uint8_t *m = (uint8_t *) malloc(m_len);
    xor_bitstrings(m, ciphertext.c3, c3_len, 
        hash3result, hash3result_len);

    //verify g^H1(m, R) == C1
    element_t hash1result;
    element_init_Zr(hash1result, pairing);
    Hash1(hash1result, m, m_len, R); 
    element_t c1_2;
    element_init_G1(c1_2, pairing);
    element_pow_zn(c1_2, g, hash1result);
    iRet = element_cmp(c1_2, ciphertext.c1);
    if (iRet != 0)
    {
        printf("Dec1 verify g^H1(m, R) == c1 fail\n");
        
    }
    else 
    {
        printf("Dec1 verify g^H1(m, R) == c1 success\n");
        bits_to_bytes(m, m_len, m_bytes, m_bytes_len);
#ifdef PRINT_DEBUG_INFO
        printf("Dec1 m_bytes =\n");
        for(int i=0;i<m_bytes_len;i++)
        {
            printf("%c", m_bytes[i]);
        }
        printf("\n");
#endif
    }

    element_clear(c1_2);
    element_clear(hash1result);
    free(hash3result);
    element_clear(eresult);
    element_clear(R);
    element_clear(ciphertext.c1);
    element_clear(ciphertext.c2);
    free(ciphertext.c3);
    element_clear(ciphertext.c4);
    element_clear(keypair.pk);
    element_clear(keypair.sk);
    element_clear(Z);
    element_clear(g);
    pairing_clear(pairing);	
#ifdef PRINT_DEBUG_INFO
    printf("********************************\n");
    printf("**********Dec1 end************\n");
    printf("********************************\n");
#endif
    return iRet;
}

// #ifdef __cplusplus
// }
// #endif


void Enc2Test()
{
    uint8_t pk_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t sk_Hex[ZR_ELEMENT_LENGTH_IN_BYTES * 2];
    int pk_Hex_len = sizeof(pk_Hex);
    int sk_Hex_len = sizeof(sk_Hex);

    KeyGen(pk_Hex, pk_Hex_len, sk_Hex, sk_Hex_len);
#ifdef PRINT_DEBUG_INFO
    printf("Enc2Test pk_Hex_len = %d, pk_Hex=\n", pk_Hex_len);
    for(int i=0;i<pk_Hex_len;) {
        printf("%c%c ", pk_Hex[i], pk_Hex[i+1]);
        i += 2;
    }
    printf("\n");
    printf("Enc2Test sk_Hex_len = %d, sk_Hex=\n", sk_Hex_len);
    for(int i=0;i<sk_Hex_len;) {
        printf("%c%c ", sk_Hex[i], sk_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    uint8_t *m=(uint8_t *)"ab3456789012345678901234567890cd";
    int m_len = strlen((char *)m);
    uint8_t *w=(uint8_t *)"hello world000";
    int w_len = strlen((char *)w);
    uint8_t c1_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c2_Hex[GT_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c3_Hex[SHA256_DIGEST_LENGTH_32 * 8 * 2];
    uint8_t c4_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    Enc2(pk_Hex, pk_Hex_len, m, m_len, w, w_len,
        c1_Hex, sizeof(c1_Hex), 
        c2_Hex, sizeof(c2_Hex), 
        c3_Hex, sizeof(c3_Hex), 
        c4_Hex, sizeof(c4_Hex));
#ifdef PRINT_DEBUG_INFO
    printf("Enc2Test c1:\n");
    for(int i=0;i<sizeof(c1_Hex);) {
        printf("%c%c ", c1_Hex[i], c1_Hex[i+1]);
        i += 2;
    }
    printf("\n");
    printf("Enc2Test c2:\n");
    for(int i=0;i<sizeof(c2_Hex);) {
        printf("%c%c ", c2_Hex[i], c2_Hex[i+1]);
        i += 2;
    }
    printf("\n");
    printf("Enc2Test c3:\n");
    for(int i=0;i<sizeof(c3_Hex);) {
        printf("%c%c ", c3_Hex[i], c3_Hex[i+1]);
        i += 2;;
    }
    printf("\n");
    printf("Enc2Test c4:\n");
    for(int i=0;i<sizeof(c4_Hex);) {
        printf("%c%c ", c4_Hex[i], c4_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif

    uint8_t m_bytes[SHA256_DIGEST_LENGTH_32 + 1];
    Dec2(pk_Hex, sizeof(pk_Hex), sk_Hex, sizeof(sk_Hex),
        w, w_len, c1_Hex, sizeof(c1_Hex), c2_Hex, sizeof(c2_Hex),
        c3_Hex, sizeof(c3_Hex), c4_Hex, sizeof(c4_Hex),
        m_bytes, sizeof(m_bytes));
    printf("Enc2Test: m_bytes = \n");
    for(int i=0;i<sizeof(m_bytes);i++)
    {
        printf("%c", m_bytes[i]);
    }
    printf("\n");

}



void Enc1Test()
{
    uint8_t pk_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t sk_Hex[ZR_ELEMENT_LENGTH_IN_BYTES * 2];
    int pk_Hex_len = sizeof(pk_Hex);
    int sk_Hex_len = sizeof(sk_Hex);

    KeyGen(pk_Hex, pk_Hex_len, sk_Hex, sk_Hex_len);
#ifdef PRINT_DEBUG_INFO
    printf("Enc1Test pk_Hex_len = %d, pk_Hex=\n", pk_Hex_len);
    for(int i=0;i<pk_Hex_len;) {
        printf("%c%c ", pk_Hex[i], pk_Hex[i+1]);
        i += 2;
    }
    printf("\n");
    printf("Enc1Test sk_Hex_len = %d, sk_Hex=\n", sk_Hex_len);
    for(int i=0;i<sk_Hex_len;) {
        printf("%c%c ", sk_Hex[i], sk_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif
    uint8_t *m=(uint8_t *)"01cdefghijklmnopqrstuvwxyz123456";
    int m_len = strlen((char *)m);
    uint8_t c1_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c2_Hex[GT_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c3_Hex[SHA256_DIGEST_LENGTH_32 * 8 * 2];
    uint8_t c4_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    Enc1(pk_Hex, pk_Hex_len, m, m_len, c1_Hex, sizeof(c1_Hex), 
        c2_Hex, sizeof(c2_Hex), 
        c3_Hex, sizeof(c3_Hex), 
        c4_Hex, sizeof(c4_Hex));
#ifdef PRINT_DEBUG_INFO
    printf("Enc1Test c1:\n");
    for(int i=0;i<sizeof(c1_Hex);) {
        printf("%c%c ", c1_Hex[i], c1_Hex[i+1]);
        i += 2;
    }
    printf("\n");
    printf("Enc1Test c2:\n");
    for(int i=0;i<sizeof(c2_Hex);) {
        printf("%c%c ", c2_Hex[i], c2_Hex[i+1]);
        i += 2;
    }
    printf("\n");
    printf("Enc1Test c3:\n");
    for(int i=0;i<sizeof(c3_Hex);) {
        printf("%c%c ", c3_Hex[i], c3_Hex[i+1]);
        i += 2;
    }
    printf("\n");
    printf("Enc1Test c4:\n");
    for(int i=0;i<sizeof(c4_Hex);i++) {
        printf("%c%c ", c4_Hex[i], c4_Hex[i+1]);
        i += 2;
    }
    printf("\n");
#endif

    uint8_t m_bytes[SHA256_DIGEST_LENGTH_32];
    Dec1(pk_Hex, sizeof(pk_Hex), sk_Hex, sizeof(sk_Hex),
        c1_Hex, sizeof(c1_Hex), c2_Hex, sizeof(c2_Hex),
        c3_Hex, sizeof(c3_Hex), c4_Hex, sizeof(c4_Hex),
        m_bytes, sizeof(m_bytes));
    printf("Enc1Test: m_bytes = \n");
    for(int i=0;i<sizeof(m_bytes);i++)
    {
        printf("%c", m_bytes[i]);
    }
    printf("\n");
}



void ReEncTest() 
{
    //start to test ReKeyGen
    uint8_t pk_i_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t sk_i_Hex[ZR_ELEMENT_LENGTH_IN_BYTES * 2];
    int pk_i_Hex_len = sizeof(pk_i_Hex);
    int sk_i_Hex_len = sizeof(sk_i_Hex);
    KeyGen(pk_i_Hex, pk_i_Hex_len, sk_i_Hex, sk_i_Hex_len);

    uint8_t *m=(uint8_t *)"89cdefghij12345678901234567890ab";
    uint8_t *w=(uint8_t *)"hello world111";
    int m_len = strlen((char *)m);
    int w_len = strlen((char *)w);
    uint8_t c1_i_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c2_i_Hex[GT_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c3_i_Hex[SHA256_DIGEST_LENGTH_32 * 8 * 2];
    uint8_t c4_i_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    Enc2(pk_i_Hex, pk_i_Hex_len, m, m_len, w, w_len,  
        c1_i_Hex, sizeof(c1_i_Hex), 
        c2_i_Hex, sizeof(c2_i_Hex), 
        c3_i_Hex, sizeof(c3_i_Hex), 
        c4_i_Hex, sizeof(c4_i_Hex));

    uint8_t pk_j_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t sk_j_Hex[ZR_ELEMENT_LENGTH_IN_BYTES * 2];
    int pk_j_Hex_len = sizeof(pk_j_Hex);
    int sk_j_Hex_len = sizeof(sk_j_Hex);
    KeyGen(pk_j_Hex, pk_j_Hex_len, sk_j_Hex, sk_j_Hex_len);


    uint8_t rk1_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t rk2_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];

    ReKeyGen(pk_j_Hex, pk_j_Hex_len, sk_i_Hex, sk_i_Hex_len, pk_i_Hex, pk_i_Hex_len, 
            w, w_len, rk1_Hex, sizeof(rk1_Hex), rk2_Hex, sizeof(rk2_Hex));

    uint8_t c1_j_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c2_j_Hex[GT_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c3_j_Hex[SHA256_DIGEST_LENGTH_32 * 8 * 2];
    uint8_t c4_j_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];

    ReEnc(c1_i_Hex, sizeof(c1_i_Hex), 
        c2_i_Hex, sizeof(c2_i_Hex),
        c3_i_Hex, sizeof(c3_i_Hex),
        c4_i_Hex, sizeof(c4_i_Hex),
        rk1_Hex, sizeof(rk1_Hex),
        rk2_Hex, sizeof(rk2_Hex),
        c1_j_Hex, sizeof(c1_j_Hex),
        c2_j_Hex, sizeof(c2_j_Hex),
        c3_j_Hex, sizeof(c3_j_Hex),
        c4_j_Hex, sizeof(c4_j_Hex));
    
    uint8_t m_bytes[SHA256_DIGEST_LENGTH_32];
    Dec1(pk_j_Hex, sizeof(pk_j_Hex), sk_j_Hex, sizeof(sk_j_Hex),
        c1_j_Hex, sizeof(c1_j_Hex), c2_j_Hex, sizeof(c2_j_Hex),
        c3_j_Hex, sizeof(c3_j_Hex), c4_j_Hex, sizeof(c4_j_Hex),
        m_bytes, sizeof(m_bytes));
    printf("ReEncTest: m_bytes = \n");
    for(int i=0;i<sizeof(m_bytes);i++)
    {
        printf("%c", m_bytes[i]);
    }
    printf("\n");

}

void ReEncTest2() 
{
    //start to test ReKeyGen
    uint8_t pk_i_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t sk_i_Hex[ZR_ELEMENT_LENGTH_IN_BYTES * 2];
    int pk_i_Hex_len = sizeof(pk_i_Hex);
    int sk_i_Hex_len = sizeof(sk_i_Hex);
    // KeyGen(pk_i_Hex, pk_i_Hex_len, sk_i_Hex, sk_i_Hex_len);
    memcpy(pk_i_Hex, "6552d0097d1d726d863af0a3a2931d6e13e7e9f8368fac45044ec0437ff2965a337fafbb719b7180dc95b5cef48f823b4e5ecb11113c660c17369403836fbd216b7442d061f0f818cfee493f2f5bf0a2e9bc2bc648003e2ec1f4072c74ebde12cc5cf0901024e3d01f902222bc0c49453af20cd5eae3c3d0e0c5678856cb66b8", G1_ELEMENT_LENGTH_IN_BYTES * 2);
    memcpy(sk_i_Hex, "2bc7881c4cd1dd9eaaf79682b41e53c2662e4149", ZR_ELEMENT_LENGTH_IN_BYTES * 2);
    

    uint8_t *m=(uint8_t *)"89cdefghij12345678901234567890ab";
    uint8_t *w=(uint8_t *)"136test24.txt";
    int m_len = strlen((char *)m);
    int w_len = strlen((char *)w);
    uint8_t c1_i_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c2_i_Hex[GT_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c3_i_Hex[SHA256_DIGEST_LENGTH_32 * 8 * 2];
    uint8_t c4_i_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    Enc2_debug(pk_i_Hex, pk_i_Hex_len, m, m_len, w, w_len,  
        c1_i_Hex, sizeof(c1_i_Hex), 
        c2_i_Hex, sizeof(c2_i_Hex), 
        c3_i_Hex, sizeof(c3_i_Hex), 
        c4_i_Hex, sizeof(c4_i_Hex));

    uint8_t pk_j_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t sk_j_Hex[ZR_ELEMENT_LENGTH_IN_BYTES * 2];
    int pk_j_Hex_len = sizeof(pk_j_Hex);
    int sk_j_Hex_len = sizeof(sk_j_Hex);
    // KeyGen(pk_j_Hex, pk_j_Hex_len, sk_j_Hex, sk_j_Hex_len);
    memcpy(pk_j_Hex, "6552d0097d1d726d863af0a3a2931d6e13e7e9f8368fac45044ec0437ff2965a337fafbb719b7180dc95b5cef48f823b4e5ecb11113c660c17369403836fbd216b7442d061f0f818cfee493f2f5bf0a2e9bc2bc648003e2ec1f4072c74ebde12cc5cf0901024e3d01f902222bc0c49453af20cd5eae3c3d0e0c5678856cb66b8", G1_ELEMENT_LENGTH_IN_BYTES * 2);
    memcpy(sk_j_Hex, "2bc7881c4cd1dd9eaaf79682b41e53c2662e4149", ZR_ELEMENT_LENGTH_IN_BYTES * 2);
    


    uint8_t rk1_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t rk2_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];

    ReKeyGen_debug(pk_j_Hex, pk_j_Hex_len, sk_i_Hex, sk_i_Hex_len, pk_i_Hex, pk_i_Hex_len, 
            w, w_len, rk1_Hex, sizeof(rk1_Hex), rk2_Hex, sizeof(rk2_Hex));

    uint8_t c1_j_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c2_j_Hex[GT_ELEMENT_LENGTH_IN_BYTES * 2];
    uint8_t c3_j_Hex[SHA256_DIGEST_LENGTH_32 * 8 * 2];
    uint8_t c4_j_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];

    ReEnc(c1_i_Hex, sizeof(c1_i_Hex), 
        c2_i_Hex, sizeof(c2_i_Hex),
        c3_i_Hex, sizeof(c3_i_Hex),
        c4_i_Hex, sizeof(c4_i_Hex),
        rk1_Hex, sizeof(rk1_Hex),
        rk2_Hex, sizeof(rk2_Hex),
        c1_j_Hex, sizeof(c1_j_Hex),
        c2_j_Hex, sizeof(c2_j_Hex),
        c3_j_Hex, sizeof(c3_j_Hex),
        c4_j_Hex, sizeof(c4_j_Hex));
    
    uint8_t m_bytes[SHA256_DIGEST_LENGTH_32];
    Dec1(pk_j_Hex, sizeof(pk_j_Hex), sk_j_Hex, sizeof(sk_j_Hex),
        c1_j_Hex, sizeof(c1_j_Hex), c2_j_Hex, sizeof(c2_j_Hex),
        c3_j_Hex, sizeof(c3_j_Hex), c4_j_Hex, sizeof(c4_j_Hex),
        m_bytes, sizeof(m_bytes));
    printf("ReEncTest: m_bytes = \n");
    for(int i=0;i<sizeof(m_bytes);i++)
    {
        printf("%c", m_bytes[i]);
    }
    printf("\n");

}

int main() {

    // printf("main start\n");
    // printf("=============\n");
    // printf("=======Enc2Test======\n");
    // printf("=============\n");
    // Enc2Test();

    // printf("=============\n");
    // printf("=======Enc1Test======\n");
    // printf("=============\n");
    // Enc1Test();

    // printf("=============\n");
    // printf("=======ReEncTest=====\n");
    // printf("=============\n");
    // ReEncTest();
    
    printf("=============\n");
    printf("=======ReEncTest2=====\n");
    printf("=============\n");
    ReEncTest2();

    // printf("main end\n");
    return 0;
}
