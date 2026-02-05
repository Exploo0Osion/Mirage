#pragma once
#include <stdio.h>

#ifdef _DEBUG
#define LOG(fmt, ...) printf("[+] " fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...) printf("[-] " fmt "\n", ##__VA_ARGS__)
#define WARN(fmt, ...) printf("[!] " fmt "\n", ##__VA_ARGS__)
#else
// Release/Tiny 模式下，这些宏为空，不生成任何代码
#define LOG(fmt, ...)
#define ERR(fmt, ...)
#define WARN(fmt, ...)
#endif

// 常用宏
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
