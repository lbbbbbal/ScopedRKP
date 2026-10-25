#pragma once
#include <cstdio>
#include <cstring>
#include <cerrno>
#define SRKP_PRINT(level, ...) do { fprintf(stderr, "[ScopedRkp " level "] "); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } while (0)
#define LOGV(...) do {} while (0)
#define LOGD(...) do {} while (0)
#define LOGI(...) do {} while (0)
#define LOGW(...) SRKP_PRINT("W", __VA_ARGS__)
#define LOGE(...) SRKP_PRINT("E", __VA_ARGS__)
#define LOGF(...) SRKP_PRINT("F", __VA_ARGS__)
#define PLOGE(fmt, ...) LOGE(fmt ": errno=%d %s", ##__VA_ARGS__, errno, strerror(errno))
