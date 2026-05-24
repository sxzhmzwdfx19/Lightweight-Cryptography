#include <iostream>                         // 输入输出库
#include <bitset>                           // bitset位数组库
#include <vector>                           // vector动态数组库
using namespace std;                        // 标准命名空间

// ====================== PRESENT S盒与逆S盒 ======================
static const bitset<4> Sbox[16] = { 0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2 };       // 4bit输入→4bit输出
static const bitset<4> InvSbox[16] = { 0x5,0xE,0xF,0x8,0xC,0x1,0x2,0xD,0xB,0x4,0x6,0x3,0x0,0x7,0x9,0xA };    // PRESENT逆S盒，用于解密

// ====================== 轮密钥加 ======================
void addRoundKey(bitset<64>& state, const bitset<80>& key)
{
    for (int i = 0; i < 64; i++) state[63 - i] = state[63 - i] ^ key[79 - i]; // 明文状态高64位与密钥高64位异或
}

// ====================== S盒替换 ======================
void SubByte(bitset<64>& state)
{
    for (int i = 0; i < 64; i += 4) {                                        // 每4bit作为一个小分组，共16个S盒
        int index = state[i] + (state[i + 1] << 1) + (state[i + 2] << 2) + (state[i + 3] << 3); // 当前4bit转成0~15索引
        bitset<4> s = Sbox[index];                                           // 查S盒，完成非线性替换
        state[i] = s[0]; state[i + 1] = s[1]; state[i + 2] = s[2]; state[i + 3] = s[3]; // 替换回原来的4bit位置
    }
}

// ====================== 逆S盒替换 ======================
void InvSubByte(bitset<64>& state)
{
    for (int i = 0; i < 64; i += 4) {                                        // 每4bit作为一个小分组
        int index = state[i] + (state[i + 1] << 1) + (state[i + 2] << 2) + (state[i + 3] << 3); // 当前4bit转成索引
        bitset<4> s = InvSbox[index];                                        // 查逆S盒，恢复替换前的4bit
        state[i] = s[0]; state[i + 1] = s[1]; state[i + 2] = s[2]; state[i + 3] = s[3]; // 写回状态
    }
}

// ====================== P置换层 ======================
void PSub(bitset<64>& state)
{
    bitset<64> tmp(0);                                                       // 临时状态，用于保存置换结果
    for (int i = 0; i < 63; i++) tmp[(i * 16) % 63] = state[i];              // PRESENT标准P置换：第i位移动到16i mod 63
    tmp[63] = state[63];                                                     // 第63位保持不变
    state = tmp;                                                             // 更新状态
}

// ====================== 逆P置换层 ======================
void InvPSub(bitset<64>& state)
{
    bitset<64> tmp(0);                                                       // 临时状态
    for (int i = 0; i < 63; i++) tmp[i] = state[(i * 16) % 63];              // P置换的逆操作
    tmp[63] = state[63];                                                     // 第63位保持不变
    state = tmp;                                                             // 更新状态
}

// ====================== 密钥更新函数 ======================
void keyUpdate(bitset<80>& key, const bitset<5>& rc)
{
    key = (key << 61) | (key >> 19);                                         // 80bit密钥循环左移61位
    int index = (key[79] << 3) + (key[78] << 2) + (key[77] << 1) + key[76];   // 取最高4bit作为S盒输入
    bitset<4> s = Sbox[index];                                               // 最高4bit经过S盒替换
    key[79] = s[3]; key[78] = s[2]; key[77] = s[1]; key[76] = s[0];           // 替换回最高4bit
    key[19] = key[19] ^ rc[4]; key[18] = key[18] ^ rc[3]; key[17] = key[17] ^ rc[2]; key[16] = key[16] ^ rc[1]; key[15] = key[15] ^ rc[0]; // 轮计数器异或到key[19:15]
}

// ====================== PRESENT加密 ======================
bitset<64> encrypt(bitset<64> state, bitset<80> key)
{
    for (int RC = 1; RC < 32; RC++) {                                       // PRESENT共31轮
        addRoundKey(state, key);                                            // 1. 轮密钥加
        SubByte(state);                                                     // 2. S盒替换
        PSub(state);                                                        // 3. P置换扩散
        keyUpdate(key, RC);                                                  // 4. 更新密钥，生成下一轮轮密钥
    }
    addRoundKey(state, key);                                                 // 最后一轮之后再进行一次轮密钥加
    return state;                                                            // 返回64bit密文
}

// ====================== PRESENT解密 ======================
bitset<64> decrypt(bitset<64> state, bitset<80> key)
{
    vector<bitset<80>> roundKey;                                             // 保存所有轮密钥
    roundKey.push_back(key);                                                 // 保存第1轮密钥
    for (int i = 1; i < 32; i++) { keyUpdate(key, i); roundKey.push_back(key); } // 预先生成32个轮密钥
    for (int i = 31; i >= 1; i--) {                                          // 解密从最后一轮往前推
        addRoundKey(state, roundKey[i]);                                     // 1. 先异或对应轮密钥
        InvPSub(state);                                                      // 2. 逆P置换
        InvSubByte(state);                                                   // 3. 逆S盒替换
    }
    addRoundKey(state, roundKey[0]);                                         // 最后恢复最初的轮密钥加
    return state;                                                            // 返回解密明文
}

// ====================== 主函数 ======================
int main()
{
    bitset<64> plain(0x123456789abcdef0ULL);   // 64bit随机明文
    bitset<80> key("10100111001101010101100101010101010101010101010101010101010101010101010101010101"); // 80bit随机密钥
    bitset<64> cipher = encrypt(plain, key);                                 // 加密得到密文
    bitset<64> decryptText = decrypt(cipher, key);                           // 解密恢复明文
    cout << "Plain  : " << plain << endl;                                    // 输出明文，二进制形式
    cout << "Cipher : " << cipher << endl;                                   // 输出密文，二进制形式
    cout << "Decrypt: " << decryptText << endl;                              // 输出解密结果
    return 0;                                                                // 程序结束
}