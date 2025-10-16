#include <cuda_runtime.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

// 结果数据结构（供主机端读取）
typedef struct {
    int found;          // 1=找到有效哈希，0=未找到
    uint32_t nonce;     // 有效nonce或最后尝试的nonce
    uint8_t hash[32];   // 对应的哈希值
} MiningResult;

// 全局变量：存储计算结果（设备端）
__device__ MiningResult devResult;

// 工具函数：字节序反转
__device__ void reverseBytes(uint8_t *data, int length) {
    for (int i = 0; i < length / 2; i++) {
        uint8_t temp = data[i];
        data[i] = data[length - 1 - i];
        data[length - 1 - i] = temp;
    }
}

// SHA-256常量
__constant__ uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256辅助函数
__device__ uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

__device__ uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__device__ uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

__device__ uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

__device__ uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

__device__ uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

// SHA-256哈希计算（输入数据，长度，输出哈希）
__device__ void sha256(uint8_t *data, int len, uint8_t *hash) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    int numBlocks = (len + 8 + 63) / 64;  // 计算需要的512位块数
    uint8_t block[64];                    // 单个块缓冲区

    for (int b = 0; b < numBlocks; b++) {
        memset(block, 0, 64);  // 初始化块

        // 复制数据到块
        int copyLen = len - b * 64;
        if (copyLen > 0) {
            if (copyLen > 64) copyLen = 64;
            memcpy(block, data + b * 64, copyLen);
        }

        // 填充（最后一个块）
        if (b == numBlocks - 1) {
            // 添加0x80标记
            if (copyLen < 64) {
                block[copyLen] = 0x80;
            }

            // 填充长度（bits）
            if (64 - copyLen >= 9) {  // 确保有空间存放8字节长度
                uint64_t bitsLen = (uint64_t)len * 8;
                for (int i = 0; i < 8; i++) {
                    block[64 - 8 + i] = (bitsLen >> (8 * (7 - i))) & 0xff;
                }
            }
        }

        // 消息调度（扩展为64个字）
        uint32_t w[64];
        for (int t = 0; t < 16; t++) {
            w[t] = (block[t*4] << 24) | (block[t*4+1] << 16) |
                   (block[t*4+2] << 8) | block[t*4+3];
        }
        for (int t = 16; t < 64; t++) {
            w[t] = gamma1(w[t-2]) + w[t-7] + gamma0(w[t-15]) + w[t-16];
        }

        // 压缩循环
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];

        for (int t = 0; t < 64; t++) {
            uint32_t temp1 = h_val + sigma1(e) + ch(e, f, g) + k[t] + w[t];
            uint32_t temp2 = sigma0(a) + maj(a, b, c);
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // 更新哈希值
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
    }

    // 转换为字节数组（大端序）
    for (int i = 0; i < 8; i++) {
        hash[i*4]   = (h[i] >> 24) & 0xff;
        hash[i*4+1] = (h[i] >> 16) & 0xff;
        hash[i*4+2] = (h[i] >> 8) & 0xff;
        hash[i*4+3] = h[i] & 0xff;
    }
}

// 将4字节压缩难度目标转换为256位目标值
__device__ void compactToTarget(uint8_t *compact, uint8_t *target) {
    memset(target, 0, 32);  // 初始化目标值为0

    int exponent = compact[0] & 0xFF;  // 指数（无符号）
    uint8_t coefficient[3] = {compact[1], compact[2], compact[3]};  // 系数

    // 计算目标值在256位数组中的起始位置（右对齐）
    int startIdx = 32 - exponent;
    if (startIdx < 0) startIdx = 0;

    // 复制系数到目标值
    for (int i = 0; i < 3 && (startIdx + i) < 32; i++) {
        target[startIdx + i] = coefficient[i];
    }
}

// 检查哈希是否小于等于目标值
__device__ bool isHashValid(uint8_t *hash, uint8_t *target) {
    for (int i = 0; i < 32; i++) {
        if (hash[i] < target[i]) return true;   // 哈希更小，有效
        if (hash[i] > target[i]) return false;  // 哈希更大，无效
    }
    return true;  // 相等，有效
}

// 内核函数：处理序列化的区块头和nonce范围
extern "C" __global__ void findValidNonceGPU(
    uint8_t *serializedHeader,  // 序列化的区块头（80字节）
    uint32_t startNonce,        // 起始nonce
    uint32_t endNonce           // 结束nonce
) {
    // 初始化结果（仅第一个线程执行）
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        devResult.found = 0;
        devResult.nonce = endNonce;  // 默认最后一个nonce
        memset(devResult.hash, 0, 32);
    }
    __syncthreads();  // 等待初始化完成

    // 计算全局线程ID
    uint32_t globalId = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t totalThreads = gridDim.x * blockDim.x;

    // 若已找到有效结果，直接返回
    if (devResult.found) return;

    // 计算当前线程负责的nonce范围
    uint32_t nonceRange = endNonce - startNonce + 1;
    uint32_t threadsPerNonce = (nonceRange + totalThreads - 1) / totalThreads;  // 向上取整
    uint32_t threadStart = startNonce + globalId * threadsPerNonce;
    uint32_t threadEnd = threadStart + threadsPerNonce - 1;
    if (threadEnd > endNonce) threadEnd = endNonce;

    // 若线程负责的范围无效，返回
    if (threadStart > endNonce) return;

    // 准备计算资源
    uint8_t headerCopy[80];  // 复制区块头（避免多线程冲突）
    memcpy(headerCopy, serializedHeader, 80);

    // 提取难度目标（序列化区块头的72-75字节，小端存储，需反转）
    uint8_t compactTarget[4];
    memcpy(compactTarget, headerCopy + 72, 4);  // 难度目标在序列化头中的位置
    reverseBytes(compactTarget, 4);  // 转为大端用于解析

    // 预计算目标值
    uint8_t target[32];
    compactToTarget(compactTarget, target);

    // 临时变量
    uint8_t hash1[32], hash2[32];  // 双重哈希结果
    uint32_t currentNonce;

    // 遍历线程负责的nonce范围
    for (currentNonce = threadStart; currentNonce <= threadEnd; currentNonce++) {
        // 若已找到结果，退出循环
        if (devResult.found) break;

        // 更新区块头中的nonce（最后4字节，小端存储）
        headerCopy[76] = (currentNonce >> 0) & 0xFF;  // nonce第1字节（小端）
        headerCopy[77] = (currentNonce >> 8) & 0xFF;   // nonce第2字节
        headerCopy[78] = (currentNonce >> 16) & 0xFF;  // nonce第3字节
        headerCopy[79] = (currentNonce >> 24) & 0xFF;  // nonce第4字节

        // 双重SHA-256计算
        sha256(headerCopy, 80, hash1);  // 第一次哈希
        sha256(hash1, 32, hash2);       // 第二次哈希
        // 新增：反转哈希字节序，与CPU端保持一致
        reverseBytes(hash2, 32);  // 关键修改：反转32字节哈希

        // 检查哈希是否有效
        if (isHashValid(hash2, target)) {
            // 原子操作：确保只有第一个找到的结果被记录
            int expected = 0;
            if (atomicCAS(&devResult.found, expected, 1) == expected) {
                devResult.nonce = currentNonce;
                memcpy(devResult.hash, hash2, 32);
            }
            break;  // 找到后退出循环
        }
    }

    // 记录最后尝试的nonce和哈希（仅当未找到有效结果时）
    if (!devResult.found && currentNonce == threadEnd + 1) {
        // 原子操作：确保最后一个nonce被正确记录（取最大的nonce）
        atomicMax((uint32_t*)&devResult.nonce, currentNonce - 1);
        // 仅最后一个线程更新哈希（确保是最后一个nonce的哈希）
        if (globalId == totalThreads - 1) {
            sha256(headerCopy, 80, hash1);
            sha256(hash1, 32, hash2);
            memcpy(devResult.hash, hash2, 32);
        }
    }
}

// 主机端函数：初始化设备并执行内核（供CUDA C调用，Java通过JCUDA间接调用）
extern "C" void launchMining(
    uint8_t *hostHeader,    // 主机端序列化的区块头（80字节）
    uint32_t startNonce,    // 起始nonce
    uint32_t endNonce,      // 结束nonce
    MiningResult *hostResult,  // 主机端结果指针
    int blockSize,          // 线程块大小
    int gridSize            // 网格大小
) {
    // 设备端变量
    uint8_t *d_header;
    MiningResult *d_result;

    // 分配设备内存
    cudaMalloc(&d_header, 80);  // 区块头固定80字节
    cudaMalloc(&d_result, sizeof(MiningResult));

    // 复制区块头到设备
    cudaMemcpy(d_header, hostHeader, 80, cudaMemcpyHostToDevice);

    // 启动内核
    findValidNonceGPU<<<gridSize, blockSize>>>(d_header, startNonce, endNonce);
    cudaDeviceSynchronize();  // 等待内核执行完成

    // 复制结果到主机
    cudaMemcpyFromSymbol(hostResult, devResult, sizeof(MiningResult));

    // 释放设备内存
    cudaFree(d_header);
    cudaFree(d_result);
}