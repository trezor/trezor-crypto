#ifndef __STDC_WANT_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1 // C11's bounds-checking interface.
#endif
#include <string.h>
#include <strings.h>

#ifdef _WIN32
#include <Windows.h>
#endif

// Adapted from https://github.com/jedisct1/libsodium/blob/1647f0d53ae0e370378a9195477e3df0a792408f/src/libsodium/sodium/utils.c#L102-L130

void memzero(void *const pnt, const size_t len)
{
#ifdef _WIN32
    SecureZeroMemory(pnt, len);
#elif defined(__STDC_LIB_EXT1__)
    // C11's bounds-checking interface.
    memset_s(pnt, (rsize_t) len, 0, (rsize_t) len);
#elif __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25)
    // GNU C Library version 2.25 or later.
    explicit_bzero(pnt, len);
#elif defined(__NetBSD__) && __NetBSD_Version__ >= 700000000
    // NetBSD version 7 or later.
    explicit_memset(pnt, 0, len);
#else
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;
    size_t i = (size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
#endif
}
