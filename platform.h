// platform.h — системные заголовки и тонкая прослойка Windows/macOS.
// На Windows — прежние заголовки Win32 как есть. На macOS — POSIX-заголовки
// и замены тех немногих Win32/Winsock-имён, которыми пользуется общий код
// (SOCKET, closesocket, Sleep, localtime_s ...). Всё, что сильно отличается
// (HTTP, ICMP, консоль, окно), разведено по #ifdef прямо в модулях.
#pragma once

#ifdef _WIN32

#ifndef NOMINMAX
#define NOMINMAX            // отключаем макросы min/max из windows.h (ломают std::max)
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <commdlg.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <shellapi.h>
#include <bcrypt.h>         // CNG: HMAC-SHA256 и AES для расшифровки QUIC Initial
#include <conio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "bcrypt.lib")

// connect() неблокирующего сокета ушёл в фон (ждать через select)
inline bool sockConnectPending() { return WSAGetLastError() == WSAEWOULDBLOCK; }
// Таймаут приёма/отправки: на Windows — DWORD в мс
inline void sockSetTimeoutMs(SOCKET s, int opt, int ms) {
    DWORD v = (DWORD)ms;
    setsockopt(s, SOL_SOCKET, opt, (const char*)&v, sizeof(v));
}

#else   // ---------------------------- macOS (POSIX) ----------------------------

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <strings.h>
#include <termios.h>
#include <limits.h>
#include <time.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <mach-o/dyld.h>    // _NSGetExecutablePath
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonCryptor.h>
#include <curl/curl.h>

#include <cstdint>
#include <chrono>
#include <thread>

typedef uint32_t DWORD;
typedef uint32_t ULONG;
typedef uint16_t WORD;
typedef uint8_t  BYTE;
typedef uint8_t  UCHAR;
typedef int      BOOL;
typedef void*    HWND;           // «окно-владелец» диалогов — на macOS не нужно
#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif
#ifndef MAX_PATH
#define MAX_PATH PATH_MAX
#endif

// --- сокеты: Winsock-имена поверх BSD-сокетов ---
typedef int SOCKET;
#define INVALID_SOCKET  (-1)
#define SOCKET_ERROR    (-1)
#define WSAECONNREFUSED ECONNREFUSED
#define WSAECONNRESET   ECONNRESET
#define WSAETIMEDOUT    ETIMEDOUT
#define WSAEWOULDBLOCK  EWOULDBLOCK
#define WSANO_DATA      EAI_NODATA
inline int closesocket(SOCKET s) { return close(s); }
inline int WSAGetLastError() { return errno; }
inline int ioctlsocket(SOCKET s, unsigned long cmd, u_long* arg) {
    if (cmd == (unsigned long)FIONBIO) {
        const int fl = fcntl(s, F_GETFL, 0);
        return fcntl(s, F_SETFL, *arg ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
    }
    return ioctl(s, cmd, arg);
}
inline bool sockConnectPending() { return errno == EINPROGRESS || errno == EWOULDBLOCK; }
inline void sockSetTimeoutMs(SOCKET s, int opt, int ms) {
    timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, opt, &tv, sizeof(tv));
}

// --- время, строки ---
inline void Sleep(DWORD ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }
inline DWORD GetTickCount() {
    return (DWORD)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}
// порядок аргументов — как у MSVC: (результат, время)
inline int localtime_s(struct tm* out, const time_t* t) { return localtime_r(t, out) ? 0 : errno; }
inline int gmtime_s(struct tm* out, const time_t* t) { return gmtime_r(t, out) ? 0 : errno; }
#define _stricmp  strcasecmp
#define _strnicmp strncasecmp

// --- libcurl ---
// На какие протоколы разрешён редирект. По версии curl.h не судим: релиз
// собирается с новым SDK (curl 8), а системный libcurl на macOS 11–12 старше
// 7.85 и опцию _STR не знает (CURLE_UNKNOWN_OPTION) — тогда битовая маска.
// Иначе ограничение молча не действовало бы.
inline void curlRedirProtocols(CURL* c, bool httpsOnly) {
#if LIBCURL_VERSION_NUM >= 0x075500
    if (curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS_STR, httpsOnly ? "https" : "http,https") == CURLE_OK)
        return;
#endif
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    curl_easy_setopt(c, CURLOPT_REDIR_PROTOCOLS,
                     httpsOnly ? (long)CURLPROTO_HTTPS : (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#pragma clang diagnostic pop
}

#endif
