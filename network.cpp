// network.cpp — сетевые запросы: HTTP(S)/JSON, geo/ASN-резолв, трассировка
// (ICMP, Globalping), гео-RTT, проверка порта извне, скан портов, поиск DPI, UDP-пробы.
#include "common.h"
#include <random>

// Внешние зонды (трассировка в режиме 3, проверка порта в режиме 6) — Globalping,
// без ключа. ProbeOps, которым пользовались раньше, приостановлен.

// ------------------------------------------------------------------
// HTTP-запрос к ip-api.com (батч) через WinHTTP
// ------------------------------------------------------------------
// rlRemain/rlTtl (необязательно) — заголовки лимита ip-api: X-Rl (сколько
// запросов осталось в текущем окне) и X-Ttl (секунд до сброса окна).
// Если заголовка нет — остаётся -1.
// Winsock инициализируется один раз на процесс. Статическая переменная
// функции инициализируется потокобезопасно (C++11), в отличие от прежних
// «static bool wsaInit» в каждой функции.
#ifdef _WIN32
static void ensureWsa() {
    static const int once = [] { WSADATA w; return WSAStartup(MAKEWORD(2, 2), &w); }();
    (void)once;
}
#else
// macOS: сокеты готовы сразу, инициализируется только libcurl (HTTP ниже).
static void ensureWsa() {
    static const int once = [] { return (int)curl_global_init(CURL_GLOBAL_DEFAULT); }();
    (void)once;
}
#endif

// Случайный байт для полей проб (nonce, SPI, DCID). rand() без srand давал
// одну и ту же последовательность при каждом запуске; генератор на поток.
static unsigned char rndByte() {
    thread_local std::mt19937 gen{std::random_device{}()};
    return (unsigned char)(gen() & 0xFF);
}

#ifdef _WIN32
// Тело ответа целиком. Ошибка чтения посреди тела (обрыв, таймаут) или ответ
// больше kMaxBody — пустая строка: половина JSON хуже, чем явная ошибка.
static std::string readBody(HINTERNET hRequest) {
    const size_t kMaxBody = 8u << 20;             // ответы API — килобайты
    std::string result;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) return {};
        if (!avail) break;
        std::vector<char> buf(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf.data(), avail, &read)) return {};
        if (!read) break;
        result.append(buf.data(), read);
        if (result.size() > kMaxBody) return {};
    }
    return result;
}

// verb — L"POST" или L"GET" (для GET body пустой).
static std::string httpRequest(const wchar_t* verb, const std::wstring& host,
                               const std::wstring& path, const std::string& body,
                               int* rlRemain = nullptr, int* rlTtl = nullptr) {
    std::string result;
    if (rlRemain) *rlRemain = -1;
    if (rlTtl)    *rlTtl = -1;
    HINTERNET hSession = WinHttpOpen(L"traffic-analyzer/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;
    // таймауты (мс): resolve, connect, send, receive — чтобы запрос не висел вечно
    WinHttpSetTimeouts(hSession, 5000, 5000, 8000, 8000);

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), 80, 0);
    if (hConnect) {
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, verb, path.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (hRequest) {
            BOOL ok;
            if (body.empty()) {
                ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
            } else {
                std::wstring headers = L"Content-Type: application/json";
                ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1,
                    (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
            }
            if (ok && WinHttpReceiveResponse(hRequest, NULL)) {
                auto hdrInt = [&](const wchar_t* name, int* dst) {
                    if (!dst) return;
                    wchar_t v[32] = {0};
                    DWORD sz = sizeof(v);
                    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CUSTOM, name,
                                            v, &sz, WINHTTP_NO_HEADER_INDEX))
                        *dst = _wtoi(v);
                };
                hdrInt(L"X-Rl", rlRemain);
                hdrInt(L"X-Ttl", rlTtl);
                // Не-2xx (429 лимит, 403 бан, страница прокси) = ошибка: иначе
                // тело разбиралось как пустой батч и запасной сервис не включался.
                DWORD status = 0, ssz = sizeof(status);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &status, &ssz, WINHTTP_NO_HEADER_INDEX);
                if (status >= 200 && status < 300) result = readBody(hRequest);
            }
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    return result;
}

static std::string httpPost(const std::wstring& host, const std::wstring& path,
                            const std::string& body,
                            int* rlRemain = nullptr, int* rlTtl = nullptr) {
    return httpRequest(L"POST", host, path, body, rlRemain, rlTtl);
}

// Один HTTPS GET по уже открытому соединению (hConnect). Сессия WinHTTP
// держит keep-alive, поэтому повторные запросы через тот же hConnect не
// платят заново за TCP- и TLS-рукопожатие.
// headers — доп. заголовки ("Name: value\r\n..."), nullptr — без них.
static std::string httpsGetOn(HINTERNET hConnect, const std::wstring& path,
                              const wchar_t* headers = nullptr) {
    std::string result;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) return result;
    BOOL ok = WinHttpSendRequest(hRequest,
        headers ? headers : WINHTTP_NO_ADDITIONAL_HEADERS, headers ? (DWORD)-1 : 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok && WinHttpReceiveResponse(hRequest, NULL)) {
        // Не-2xx = ошибка (пустая строка). Иначе JSON ошибки 429 от ipapi.is
        // разбирался как ответ «все флаги false» и адрес считался проверенным.
        DWORD status = 0, ssz = sizeof(status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &ssz, WINHTTP_NO_HEADER_INDEX);
        if (status >= 200 && status < 300) result = readBody(hRequest);
    }
    WinHttpCloseHandle(hRequest);
    return result;
}

// HTTPS GET — для вторичных источников (ipapi.is) с флагами is_datacenter/is_vpn.
static std::string httpsGet(const std::wstring& host, const std::wstring& path,
                            const wchar_t* headers = nullptr) {
    std::string result;
    HINTERNET hSession = WinHttpOpen(L"traffic-analyzer/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;
    WinHttpSetTimeouts(hSession, 5000, 5000, 8000, 8000);
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), 443, 0);
    if (hConnect) {
        result = httpsGetOn(hConnect, path, headers);
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    return result;
}

// Пакет HTTPS GET к одному хосту в несколько потоков. Раньше запросы шли строго
// по одному, каждый со своим TLS-рукопожатием и паузой — 40 адресов занимали
// до минуты. Каждый поток держит своё соединение и берёт следующий путь из
// общей очереди. Ответ i-го пути кладётся в out[i] (пустая строка — ошибка).
static std::vector<std::string> httpsGetMany(const std::wstring& host,
                                             const std::vector<std::wstring>& paths,
                                             int workers) {
    std::vector<std::string> out(paths.size());
    if (paths.empty()) return out;
    workers = std::max(1, std::min<int>(workers, (int)paths.size()));
    std::atomic<size_t> next{0};
    auto work = [&]() {
        HINTERNET hSession = WinHttpOpen(L"traffic-analyzer/1.0",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return;
        WinHttpSetTimeouts(hSession, 5000, 5000, 8000, 8000);
        HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), 443, 0);
        if (hConnect) {
            for (size_t i; (i = next.fetch_add(1)) < paths.size(); )
                out[i] = httpsGetOn(hConnect, paths[i]);
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    };
    std::vector<std::thread> th;
    for (int w = 0; w < workers; w++) th.emplace_back(work);
    for (auto& t : th) t.join();
    return out;
}

// HTTPS POST с JSON-телом — универсальный: host/path/доп.заголовки задаёт
// вызывающий. Через httpStatus,
// если он не nullptr, возвращается код ответа — нужен, чтобы отличить
// «сервис недоступен» (503) от валидационной ошибки API (400).
static std::string httpsPostJson(const std::wstring& host, const std::wstring& path,
                                 const std::string& body,
                                 const std::wstring& extraHeaders = L"",
                                 DWORD* httpStatus = nullptr) {
    std::string result;
    if (httpStatus) *httpStatus = 0;
    HINTERNET hSession = WinHttpOpen(L"traffic-analyzer/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;
    WinHttpSetTimeouts(hSession, 5000, 5000, 8000, 15000);
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), 443, 0);
    if (hConnect) {
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (hRequest) {
            std::wstring headers = L"Content-Type: application/json";
            if (!extraHeaders.empty()) headers += L"\r\n" + extraHeaders;
            BOOL ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1,
                (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
            if (ok && WinHttpReceiveResponse(hRequest, NULL)) {
                if (httpStatus) {
                    DWORD code = 0, sz = sizeof(code);
                    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
                    *httpStatus = code;
                }
                // тело читается при любом коде: JSON ошибки 400 нужен вызывающему
                result = readBody(hRequest);
            }
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    return result;
}
#else
// ------------------------------------------------------------------
// macOS: те же функции поверх libcurl (есть в системе). Сигнатуры прежние —
// хост и путь в wstring, остальной код не меняется.
// ------------------------------------------------------------------
struct CurlResp {
    std::string body;
    long status = 0;
    bool ok = false;
    bool tooBig = false;
    std::map<std::string, std::string> hdr;    // имена — в нижнем регистре
};

static size_t curlWrite(char* p, size_t sz, size_t n, void* ud) {
    auto* r = (CurlResp*)ud;
    const size_t len = sz * n;
    if (r->body.size() + len > (8u << 20)) { r->tooBig = true; return 0; }   // ответы API — килобайты
    r->body.append(p, len);
    return len;
}

static size_t curlHeader(char* p, size_t sz, size_t n, void* ud) {
    auto* r = (CurlResp*)ud;
    std::string line(p, sz * n);
    const size_t c = line.find(':');
    if (c != std::string::npos) {
        std::string name = line.substr(0, c);
        for (auto& ch : name) ch = (char)tolower((unsigned char)ch);
        r->hdr[name] = trim(line.substr(c + 1));
    }
    return sz * n;
}

// idleSec — сколько секунд без данных считать обрывом (как таймаут приёма WinHTTP)
static CURL* curlNew(long idleSec = 8) {
    ensureWsa();
    CURL* c = curl_easy_init();
    if (!c) return nullptr;
    curl_easy_setopt(c, CURLOPT_USERAGENT, "traffic-analyzer/1.0");
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, idleSec);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);     // WinHTTP тоже идёт по редиректам
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
    return c;
}

// Редиректы — как у WinHTTP по умолчанию: с https на http не переходим
// (иначе подменённый ответ по открытому каналу выдал бы себя за ответ сервиса).
static void curlRedirNoDowngrade(CURL* c, const std::string& url) {
    std::string scheme = url.substr(0, 8);
    for (auto& ch : scheme) ch = (char)tolower((unsigned char)ch);
    curlRedirProtocols(c, scheme == "https://");
}

// headers — "Name: value", несколько через \r\n. body == nullptr — GET.
static CurlResp curlDo(CURL* c, const std::string& url, const std::string* body,
                       const std::string& headers = std::string()) {
    CurlResp r;
    if (!c) return r;
    curl_slist* hl = nullptr;
    for (size_t p = 0; p < headers.size(); ) {
        size_t e = headers.find("\r\n", p);
        if (e == std::string::npos) e = headers.size();
        std::string h = trim(headers.substr(p, e - p));
        if (!h.empty()) hl = curl_slist_append(hl, h.c_str());
        p = e + 2;
    }
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curlRedirNoDowngrade(c, url);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlWrite);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &r);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, curlHeader);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &r);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hl);
    if (body) {
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, body->data());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)body->size());
    } else {
        curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
    }
    const CURLcode rc = curl_easy_perform(c);
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &r.status);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, (curl_slist*)nullptr);
    curl_slist_free_all(hl);
    r.ok = (rc == CURLE_OK) && !r.tooBig;
    if (!r.ok) r.body.clear();
    return r;
}

static std::string httpRequest(const wchar_t* verb, const std::wstring& host,
                               const std::wstring& path, const std::string& body,
                               int* rlRemain = nullptr, int* rlTtl = nullptr) {
    if (rlRemain) *rlRemain = -1;
    if (rlTtl)    *rlTtl = -1;
    CURL* c = curlNew();
    if (!c) return {};
    const bool post = std::wstring(verb) == L"POST";
    CurlResp r = curlDo(c, "http://" + w2u8(host.c_str()) + w2u8(path.c_str()),
                        post ? &body : nullptr,
                        body.empty() ? std::string() : std::string("Content-Type: application/json"));
    curl_easy_cleanup(c);
    if (!r.ok) return {};
    auto hdrInt = [&](const char* name, int* dst) {
        if (!dst) return;
        auto it = r.hdr.find(name);
        if (it != r.hdr.end()) *dst = atoi(it->second.c_str());
    };
    hdrInt("x-rl", rlRemain);
    hdrInt("x-ttl", rlTtl);
    return (r.status >= 200 && r.status < 300) ? r.body : std::string();
}

static std::string httpPost(const std::wstring& host, const std::wstring& path,
                            const std::string& body,
                            int* rlRemain = nullptr, int* rlTtl = nullptr) {
    return httpRequest(L"POST", host, path, body, rlRemain, rlTtl);
}

static std::string httpsGetOn(CURL* c, const std::wstring& host, const std::wstring& path,
                              const wchar_t* headers = nullptr) {
    CurlResp r = curlDo(c, "https://" + w2u8(host.c_str()) + w2u8(path.c_str()), nullptr,
                        headers ? w2u8(headers) : std::string());
    return (r.ok && r.status >= 200 && r.status < 300) ? r.body : std::string();
}

static std::string httpsGet(const std::wstring& host, const std::wstring& path,
                            const wchar_t* headers = nullptr) {
    CURL* c = curlNew();
    if (!c) return {};
    std::string res = httpsGetOn(c, host, path, headers);
    curl_easy_cleanup(c);
    return res;
}

// Каждый поток держит свой CURL (keep-alive) и берёт пути из общей очереди.
static std::vector<std::string> httpsGetMany(const std::wstring& host,
                                             const std::vector<std::wstring>& paths,
                                             int workers) {
    std::vector<std::string> out(paths.size());
    if (paths.empty()) return out;
    workers = std::max(1, std::min<int>(workers, (int)paths.size()));
    std::atomic<size_t> next{0};
    auto work = [&]() {
        CURL* c = curlNew();
        if (!c) return;
        for (size_t i; (i = next.fetch_add(1)) < paths.size(); )
            out[i] = httpsGetOn(c, host, paths[i]);
        curl_easy_cleanup(c);
    };
    std::vector<std::thread> th;
    for (int w = 0; w < workers; w++) th.emplace_back(work);
    for (auto& t : th) t.join();
    return out;
}

static std::string httpsPostJson(const std::wstring& host, const std::wstring& path,
                                 const std::string& body,
                                 const std::wstring& extraHeaders = L"",
                                 DWORD* httpStatus = nullptr) {
    if (httpStatus) *httpStatus = 0;
    CURL* c = curlNew(15);
    if (!c) return {};
    std::string headers = "Content-Type: application/json";
    if (!extraHeaders.empty()) headers += "\r\n" + w2u8(extraHeaders.c_str());
    CurlResp r = curlDo(c, "https://" + w2u8(host.c_str()) + w2u8(path.c_str()), &body, headers);
    curl_easy_cleanup(c);
    if (httpStatus) *httpStatus = (DWORD)r.status;
    return r.body;      // тело при любом коде: JSON ошибки 400 нужен вызывающему
}

// ------------------------------------------------------------------
// macOS: ICMP-эхо без root — датаграммный ICMP-сокет, как у системного ping.
// Замена IcmpSendEcho: статус в тех же кодах, что у Windows (IP_SUCCESS и т.п.).
// ------------------------------------------------------------------
#define IP_SUCCESS              0
#define IP_DEST_NET_UNREACHABLE 11002
#define IP_DEST_HOST_UNREACHABLE 11003
#define IP_TTL_EXPIRED_TRANSIT  11013

struct IcmpReply {
    int status = -1;        // -1 — ответа нет; иначе IP_SUCCESS / IP_TTL_EXPIRED_TRANSIT / ...
    std::string from;       // кто ответил (цель или промежуточный узел)
    double rttMs = -1;
    bool aborted = false;   // прервано флагом abort
    bool noSocket = false;  // сокет не открылся
};

static uint16_t icmpChecksum(const uint8_t* d, size_t n) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < n; i += 2) sum += (uint32_t)(d[i] << 8 | d[i + 1]);
    if (n & 1) sum += (uint32_t)d[n - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

// ttl <= 0 — системный TTL. abort (необязательно) проверяется каждые 50 мс.
static IcmpReply icmpEcho(const std::string& ip, int ttl, int timeoutMs,
                          const char* payload, const std::atomic<bool>* abort = nullptr) {
    IcmpReply r;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &dst.sin_addr) != 1) return r;
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0) { r.noSocket = true; return r; }
    if (ttl > 0) setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));

    // Совпадение ответа — по номеру последовательности (идентификатор ядро
    // может переписать); номер общий на процесс, пробы из разных потоков не путаются.
    static std::atomic<uint16_t> seqGen{(uint16_t)(getpid() * 7919)};
    const uint16_t id = (uint16_t)getpid(), seq = seqGen.fetch_add(1);
    uint8_t pkt[8 + 32] = {0};
    pkt[0] = 8;                                     // echo request
    pkt[4] = (uint8_t)(id >> 8);  pkt[5] = (uint8_t)id;
    pkt[6] = (uint8_t)(seq >> 8); pkt[7] = (uint8_t)seq;
    strncpy((char*)pkt + 8, payload, 31);
    const uint16_t ck = icmpChecksum(pkt, sizeof(pkt));
    pkt[2] = (uint8_t)(ck >> 8); pkt[3] = (uint8_t)ck;

    const auto t0 = std::chrono::steady_clock::now();
    if (sendto(s, pkt, sizeof(pkt), 0, (sockaddr*)&dst, sizeof(dst)) < 0) { close(s); return r; }
    for (;;) {
        const int el = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        if (el >= timeoutMs) break;
        if (abort && *abort) { r.aborted = true; break; }
        pollfd pf{ s, POLLIN, 0 };
        if (poll(&pf, 1, std::min(timeoutMs - el, 50)) <= 0) continue;
        uint8_t buf[1500];
        sockaddr_in from{};
        socklen_t fl = sizeof(from);
        const ssize_t n = recvfrom(s, buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        if (n <= 0) continue;
        size_t off = 0;
        if ((buf[0] >> 4) == 4) off = (size_t)(buf[0] & 0x0F) * 4;   // macOS отдаёт с IP-заголовком
        if ((size_t)n < off + 8) continue;
        const uint8_t* ic = buf + off;
        const size_t icl = (size_t)n - off;
        const uint8_t type = ic[0];
        bool mine = false;
        if (type == 0) {                            // echo reply
            mine = ((ic[6] << 8) | ic[7]) == seq && from.sin_addr.s_addr == dst.sin_addr.s_addr;
            if (mine) r.status = IP_SUCCESS;
        } else if (type == 11 || type == 3) {       // TTL истёк / недоступен: внутри — наш запрос
            if (icl < 8 + 20 + 8) continue;
            const uint8_t* inner = ic + 8;
            const size_t ihl = (size_t)(inner[0] & 0x0F) * 4;
            if (icl < 8 + ihl + 8 || inner[9] != IPPROTO_ICMP) continue;
            const uint8_t* oic = inner + ihl;
            mine = oic[0] == 8 && ((oic[6] << 8) | oic[7]) == seq;
            if (mine) r.status = type == 11 ? IP_TTL_EXPIRED_TRANSIT
                               : ic[1] == 0 ? IP_DEST_NET_UNREACHABLE : IP_DEST_HOST_UNREACHABLE;
        }
        if (!mine) continue;
        r.rttMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        char b[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &from.sin_addr, b, sizeof(b));
        r.from = b;
        break;
    }
    close(s);
    return r;
}
#endif

// Строка для вставки в JSON-тело запроса: кавычки, обратный слеш и управляющие
// символы экранируются — иначе ввод пользователя ломал бы или дописывал JSON.
static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char ch : s) {
        switch (ch) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", ch); out += b; }
            else out += (char)ch;
        }
    }
    return out;
}

// очень простой "вытащить значение строкового поля" из JSON без либ
// раскрывает JSON unicode-escape \uXXXX в UTF-8 (а также \n \t \" \\ \/).
// Нужно, т.к. API иногда отдают org вроде "OOO \u003c\u003cTajmVeb\u003e\u003e".
static std::string jsonUnescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char n = s[i+1];
            if (n == 'u' && i + 5 < s.size()) {
                // 4 hex-цифры -> код символа -> UTF-8
                auto hex = [](char c)->int {
                    if (c>='0'&&c<='9') return c-'0';
                    if (c>='a'&&c<='f') return c-'a'+10;
                    if (c>='A'&&c<='F') return c-'A'+10;
                    return -1;
                };
                auto hex4 = [&](size_t at)->int {   // 4 hex-цифры с позиции at, -1 — не они
                    if (at + 4 > s.size()) return -1;
                    int v = 0;
                    for (size_t k = at; k < at + 4; k++) {
                        int h = hex(s[k]);
                        if (h < 0) return -1;
                        v = (v << 4) | h;
                    }
                    return v;
                };
                int u = hex4(i + 2);
                if (u >= 0) {
                    unsigned cp = (unsigned)u;
                    size_t used = 6;
                    // символ вне BMP (эмодзи и т.п.) приходит суррогатной парой
                    // (D83D + DE00 = U+1F600) — склеиваем в один код; одиночный суррогат — U+FFFD
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        int lo = (i + 7 < s.size() && s[i+6] == '\\' && s[i+7] == 'u')
                                 ? hex4(i + 8) : -1;
                        if (lo >= 0xDC00 && lo <= 0xDFFF) {
                            cp = 0x10000 + ((cp - 0xD800) << 10) + ((unsigned)lo - 0xDC00);
                            used = 12;
                        } else cp = 0xFFFD;
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) cp = 0xFFFD;
                    if (cp < 0x80) out += (char)cp;
                    else if (cp < 0x800) {
                        out += (char)(0xC0 | (cp>>6));
                        out += (char)(0x80 | (cp&0x3F));
                    } else if (cp < 0x10000) {
                        out += (char)(0xE0 | (cp>>12));
                        out += (char)(0x80 | ((cp>>6)&0x3F));
                        out += (char)(0x80 | (cp&0x3F));
                    } else {
                        out += (char)(0xF0 | (cp>>18));
                        out += (char)(0x80 | ((cp>>12)&0x3F));
                        out += (char)(0x80 | ((cp>>6)&0x3F));
                        out += (char)(0x80 | (cp&0x3F));
                    }
                    i += used; continue;
                }
            }
            if (n=='n'){out+='\n';i+=2;continue;}
            if (n=='t'){out+='\t';i+=2;continue;}
            if (n=='r'){i+=2;continue;}
            if (n=='"'||n=='\\'||n=='/'){out+=n;i+=2;continue;}
        }
        out += s[i]; i++;
    }
    return out;
}

static std::string jsonStr(const std::string& obj, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t p = obj.find(pat);
    if (p == std::string::npos) return "";
    p = obj.find(':', p);
    if (p == std::string::npos) return "";
    p++;
    while (p < obj.size() && (obj[p] == ' ' || obj[p] == '\"')) p++;
    std::string out;
    while (p < obj.size() && obj[p] != '\"' && obj[p] != ',' && obj[p] != '}') {
        out += obj[p]; p++;
    }
    return jsonUnescape(trim(out));
}

// извлекает ПОЛНОЕ строковое значение поля (до закрывающей кавычки, с учётом
// экранирования \"). В отличие от jsonStr не режет на запятых — нужно для
// многострочных полей вроде traceroute "output" с запятыми и \n внутри.
static std::string jsonStrFull(const std::string& obj, const std::string& key,
                               size_t from = 0) {
    std::string pat = "\"" + key + "\"";
    size_t p = obj.find(pat, from);
    if (p == std::string::npos) return "";
    p = obj.find(':', p);
    if (p == std::string::npos) return "";
    p++;
    while (p < obj.size() && obj[p] == ' ') p++;
    if (p >= obj.size() || obj[p] != '\"') return "";   // не строковое значение
    p++;                                                 // пропускаем открывающую "
    std::string out;
    while (p < obj.size()) {
        char c = obj[p];
        if (c == '\\' && p + 1 < obj.size()) {           // экранированная пара
            char n = obj[p+1];
            if (n == 'n') out += '\n';
            else if (n == 't') out += '\t';
            else if (n == 'r') { /*skip*/ }
            else out += n;                               // \" \\ \/ и т.п.
            p += 2; continue;
        }
        if (c == '\"') break;                            // конец строки
        out += c; p++;
    }
    return out;
}

// Текстовое поле целиком (названия организаций: "REG.RU, Ltd"), с раскрытием
// \uXXXX. jsonStr режет на запятой, jsonStrFull не знает \u. Если значение
// не строковое (число, true) — как jsonStr.
static std::string jsonText(const std::string& obj, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t p = obj.find(pat);
    if (p == std::string::npos) return "";
    p = obj.find(':', p + pat.size());
    if (p == std::string::npos) return "";
    p++;
    while (p < obj.size() && obj[p] == ' ') p++;
    if (p >= obj.size() || obj[p] != '\"') return jsonStr(obj, key);
    size_t b = ++p;
    while (p < obj.size() && obj[p] != '\"') p += (obj[p] == '\\') ? 2 : 1;
    if (p > obj.size()) p = obj.size();
    return jsonUnescape(trim(obj.substr(b, p - b)));
}

// true, если у ключа значение true (до ближайшей запятой / скобки).
static bool jsonTrue(const std::string& obj, const std::string& key) {
    size_t p = obj.find("\"" + key + "\"");
    if (p == std::string::npos) return false;
    size_t t = obj.find("true", p);
    size_t c = obj.find(',', p);
    size_t b = obj.find('}', p);
    size_t lim = std::min(c, b);
    return t != std::string::npos && t < lim;
}

// ------------------------------------------------------------------
// Своя сеть: AS провайдера по собственному внешнему адресу
// ------------------------------------------------------------------
// Только по кнопке «Определить» в настройках — сама программа в сеть за этим
// не ходит. Уходит лишь свой адрес (ip-api видит его и так), адреса из дампа — нет.
bool ownIspDetect(std::string& msg) {
    const std::string r = httpRequest(L"GET", L"ip-api.com",
        L"/json/?fields=status,message,query,as,hosting,proxy", std::string());
    if (r.empty()) { msg = "нет ответа ip-api.com (нет интернета?)"; return false; }
    if (jsonStr(r, "status") != "success") {
        msg = "ip-api.com: " + jsonText(r, "message");
        return false;
    }
    const std::string as = jsonText(r, "as");          // «AS39709 Extreme Ltd»
    // strtoull: unsigned long на Windows 32-битный, переполнение там не отличить
    unsigned long long n = 0;
    if (as.size() > 2 && (as[0] == 'A' || as[0] == 'a') && (as[1] == 'S' || as[1] == 's'))
        n = strtoull(as.c_str() + 2, nullptr, 10);
    if (n == 0 || n > 0xFFFFFFFFull) { msg = "ip-api.com не назвал AS"; return false; }
    const std::string ip = jsonStr(r, "query");

    OwnIspAuto s;
    s.asn = (unsigned)n;
    s.name = as;
    const bool saved = rememberedSet("OwnIspAsn", std::to_string(n)) &&
                       rememberedSet("OwnIspName", as);
    s.status = "определена по адресу " + ip +
               (saved ? " и запомнена"
                      : ", но не сохранилась (нет записи в реестр / файл настроек) — "
                        "после перезапуска её придётся определить снова");
    // Кнопку нажали сами — запоминаем и хостинг: у оператора бывают сети,
    // которые geo-API считают датацентром. Но через VPN «своей» станет сеть
    // VPN-сервиса, и её адреса в дампах перестанут считаться хостингом.
    if (jsonTrue(r, "hosting") || jsonTrue(r, "proxy"))
        s.status += ". Внимание: ip-api считает эту сеть хостингом/VPN — если программа "
                    "сейчас выходит в интернет через VPN, отключите его и определите заново";
    ownIspAutoSet(s);
    msg = as + " — " + s.status;
    return true;
}

// резолвим набор публичных IP батчами по 100 (лимит ip-api batch)
void resolveIps(const std::vector<std::string>& ipsIn,
                std::unordered_map<std::string, IpInfo>& cache) {
    // Наружу — только настоящие публичные адреса: частные/служебные (LAN, CGNAT,
    // link-local с зоной «%eth0», multicast) и мусор из разбора никуда не шлём.
    std::vector<std::string> ips;
    for (const auto& ip : ipsIn) {
        unsigned char b[16];
        if (inet_pton(AF_INET, ip.c_str(), b) != 1 && inet_pton(AF_INET6, ip.c_str(), b) != 1) continue;
        if (isPrivateIp(ip)) continue;
        ips.push_back(ip);
    }
    const size_t BATCH = 100;
    for (size_t i = 0; i < ips.size(); i += BATCH) {
        size_t end = std::min(ips.size(), i + BATCH);
        std::string body = "[";
        for (size_t j = i; j < end; j++) {
            if (j > i) body += ",";
            body += "{\"query\":\"" + ips[j] +
                    "\",\"fields\":\"status,country,countryCode,as,org,isp,hosting,query\"}";
        }
        body += "]";

        // до 3 попыток к ip-api.com; печатаем номер попытки, при таймауте сообщаем
        std::string resp;
        int rlRemain = -1, rlTtl = -1;
        for (int attempt = 1; attempt <= 3; attempt++) {
            std::cout << "  ip-api.com: запрос " << (i / BATCH + 1)
                      << ", попытка " << attempt << "/3 ..." << std::flush;
            resp = httpPost(L"ip-api.com", L"/batch", body, &rlRemain, &rlTtl);
            // поле query запрошено в fields — без него это не ответ батча
            // (страница провайдера/прокси, обрезанный ответ): не разбираем в пустоту
            if (resp.find("\"query\"") == std::string::npos) resp.clear();
            if (!resp.empty()) { std::cout << " ок\n"; break; }
            if (rlRemain == 0) { std::cout << " лимит запросов\n"; break; }
            std::cout << " таймаут/нет ответа\n";
            if (attempt < 3) Sleep(1000);
        }
        // если ip-api так и не ответил — пробуем запасной сервис (по одному IP,
        // но в несколько потоков)
        if (resp.empty()) {
            std::cout << "  ip-api.com недоступен — переключаюсь на запасной сервис (ipwho.is)\n";
            std::vector<std::wstring> paths;
            for (size_t j = i; j < end; j++)
                paths.push_back(L"/" + std::wstring(ips[j].begin(), ips[j].end()));
            std::vector<std::string> answers = httpsGetMany(L"ipwho.is", paths, 4);
            for (size_t j = i; j < end; j++) {
                const std::string& r = answers[j - i];
                // ошибка / лимит приходят с HTTP 200 и "success":false — в кэш
                // не кладём, иначе адрес навсегда останется «чистым»
                if (r.empty() || !jsonTrue(r, "success")) continue;
                IpInfo info; info.type = "public";
                info.country = jsonStr(r, "country_code");
                if (info.country.empty()) info.country = "-";
                // у ipwho.is ASN/ISP лежат в объекте "connection"
                size_t cp = r.find("\"connection\"");
                std::string sb = (cp != std::string::npos) ? r.substr(cp) : r;
                std::string asn = jsonStr(sb, "asn");
                std::string isp = jsonText(sb, "isp");
                std::string org = jsonText(sb, "org");
                info.asn = asn.empty() ? "-" : ("AS" + asn);
                info.org = !org.empty() ? org : (!isp.empty() ? isp : "-");
                cache[ips[j]] = info;
            }
            continue; // следующий батч
        }

        // делим массив на объекты по верхнеуровневым {...}
        int depth = 0; size_t objStart = std::string::npos;
        for (size_t k = 0; k < resp.size(); k++) {
            char ch = resp[k];
            if (ch == '{') { if (depth == 0) objStart = k; depth++; }
            else if (ch == '}') {
                depth--;
                if (depth == 0 && objStart != std::string::npos) {
                    std::string obj = resp.substr(objStart, k - objStart + 1);
                    IpInfo info;
                    std::string q = jsonStr(obj, "query");
                    std::string as = jsonText(obj, "as");     // "AS15169 Google LLC"
                    std::string org = jsonText(obj, "org");
                    std::string isp = jsonText(obj, "isp");
                    info.country = jsonStr(obj, "countryCode");
                    if (info.country.empty()) info.country = "-";
                    // ASN — первое слово из "as"
                    if (!as.empty()) {
                        size_t sp = as.find(' ');
                        info.asn = (sp == std::string::npos) ? as : as.substr(0, sp);
                        std::string rest = (sp == std::string::npos) ? "" : as.substr(sp + 1);
                        info.org = !org.empty() ? org : (!isp.empty() ? isp : rest);
                    } else {
                        info.org = !org.empty() ? org : isp;
                    }
                    if (info.org.empty()) info.org = "-";
                    if (info.asn.empty()) info.asn = "-";
                    info.type = "public";
                    // поле hosting: true => датацентр/хостинг
                    {
                        size_t hp = obj.find("\"hosting\"");
                        if (hp != std::string::npos) {
                            size_t tp = obj.find("true", hp);
                            size_t cp = obj.find(',', hp);
                            size_t br = obj.find('}', hp);
                            size_t lim = std::min(cp == std::string::npos ? br : cp,
                                                  br == std::string::npos ? cp : br);
                            if (tp != std::string::npos && tp < lim) info.hosting = true;
                        }
                    }
                    if (!q.empty()) cache[q] = info;
                    objStart = std::string::npos;
                }
            }
        }
        // Лимит batch-эндпойнта ip-api — 15 запросов в минуту. Раньше после
        // КАЖДОГО батча (и после последнего тоже) стояла пауза 1,5 с. Теперь
        // ждём, только если есть следующий батч, и только когда ip-api сам
        // сообщил, что окно исчерпано (X-Rl = 0) — ровно X-Ttl секунд.
        bool more = end < ips.size();
        if (more && rlRemain == 0) {
            int waitS = (rlTtl > 0 ? rlTtl : 60) + 1;
            std::cout << "  ip-api.com: исчерпан лимит запросов, жду " << waitS << " с ...\n";
            Sleep((DWORD)waitS * 1000);
        } else if (more && rlRemain < 0) {
            Sleep(1500);   // заголовков нет — прежняя осторожная пауза
        }
    }
}

// ipapi.is с 1 сентября 2026 без ключа API отвечает урезанно: страна, ASN,
// компания — а флагов is_vpn/is_proxy/is_tor/is_datacenter в ответе нет.
// Нет флага — это не «false»: такой ответ о VPN ничего не говорит, и считать
// адрес проверенным («чисто») нельзя.
static bool ipapiHasFlags(const std::string& resp) {
    return resp.find("\"is_datacenter\"") != std::string::npos ||
           resp.find("\"is_vpn\"") != std::string::npos;
}
// Урезанный ответ уже видели — до конца работы программы ipapi.is не спрашиваем:
// адреса туда уходили бы впустую.
static std::atomic<bool> g_ipapiNoFlags{false};

// Вторичная проверка хостинга/VPN через ipapi.is (по одному IP, HTTPS GET).
// Запускаем ТОЛЬКО для адресов, которые ip-api не отметил как hosting и которые
// не являются известными CDN — чтобы добрать пропуски (напр. CGI Global).
// Бесплатный лимит ipapi.is небольшой, поэтому ограничиваем число запросов.
void resolveHostingSecondary(std::unordered_map<std::string, IpInfo>& cache,
                             const std::vector<std::string>& ips) {
    // Сначала локальная база IP2Proxy (если задана): отмеченные ею VPN/прокси/
    // хостинг ipapi.is уже не спрашиваем — экономим его лимит.
    ip2proxyApply(cache, ips);
    int budget = 40; // не злоупотребляем бесплатным лимитом
    // 1) отбираем адреса, которые реально нужно спросить
    std::vector<IpInfo*> todo;
    std::vector<std::wstring> paths;
    for (const auto& ip : ips) {
        if (budget <= 0) break;
        auto it = cache.find(ip);
        if (it == cache.end()) continue;
        IpInfo& info = it->second;
        if (info.hosting) continue;                 // уже знаем — хостинг
        if (looksCdnOrg(info.org)) continue;        // CDN — точно не VPN
        if (looksHostingOrg(info.org, info.asn)) { info.hosting = true; continue; }

        budget--;
        todo.push_back(&info);
        paths.push_back(L"/?q=" + std::wstring(ip.begin(), ip.end()));
    }
    if (todo.empty()) return;
    // printf, а не cout: предупреждение должно попасть и в отчёт рядом с вердиктом
    auto warnNoFlags = [] {
        printf("  %sipapi.is: без ключа API сервис больше не отдаёт флаги VPN/прокси/Tor/"
               "датацентр — вторичная проверка недоступна. Адреса ею НЕ проверены (это не "
               "«чисто»): хостинг/VPN видны только по ip-api и базе IP2Proxy (если подключена).%s\n",
               C::YEL, C::RST);
    };
    if (g_ipapiNoFlags) { warnNoFlags(); return; }
    // 2) первый адрес — отдельно: урезанный ответ без ключа виден сразу, и
    // остальной бюджет на пустые ответы не тратится
    std::cout << "  ipapi.is: проверка " << todo.size() << " адрес(ов) ...\n" << std::flush;
    std::vector<std::string> answers(todo.size());
    answers[0] = httpsGet(L"api.ipapi.is", paths[0]);
    if (!answers[0].empty() && !ipapiHasFlags(answers[0])) {
        g_ipapiNoFlags = true;
        warnNoFlags();
        return;
    }
    // остальные — параллельно (раньше — по одному с паузой 400 мс)
    if (todo.size() > 1) {
        std::vector<std::wstring> rest(paths.begin() + 1, paths.end());
        std::vector<std::string> more = httpsGetMany(L"api.ipapi.is", rest, 6);
        for (size_t n = 0; n < more.size(); n++) answers[n + 1] = std::move(more[n]);
    }
    // 3) разбираем ответы
    size_t noFlags = 0;
    for (size_t n = 0; n < todo.size(); n++) {
        IpInfo& info = *todo[n];
        const std::string& resp = answers[n];
        if (resp.empty()) continue;
        if (!ipapiHasFlags(resp)) { noFlags++; continue; }   // флагов нет — адрес не проверен
        auto isTrue = [&](const char* key) {
            std::string k = std::string("\"") + key + "\"";
            size_t p = resp.find(k);
            if (p == std::string::npos) return false;
            size_t t = resp.find("true", p);
            size_t c = resp.find(',', p);
            size_t b = resp.find('}', p);
            size_t lim = std::min(c == std::string::npos ? b : c,
                                  b == std::string::npos ? c : b);
            return t != std::string::npos && t < lim;
        };
        bool fVpn = isTrue("is_vpn"), fProxy = isTrue("is_proxy"),
             fTor = isTrue("is_tor");
        if (isTrue("is_datacenter") || isTrue("is_hosting") || fVpn || fProxy || fTor)
            info.hosting = true;
        // флаги из базы IP2Proxy не затираем
        info.isVpn = info.isVpn || fVpn; info.isProxy = info.isProxy || fProxy; info.isTor = info.isTor || fTor;
        if (fVpn || fProxy || fTor)
            info.flagSrc = info.flagSrc.empty() ? "ipapi.is" : info.flagSrc + " + ipapi.is";
    }
    // первый адрес не ответил, а остальные пришли урезанными — то же самое
    if (noFlags) {
        g_ipapiNoFlags = true;
        warnNoFlags();
    }
}

// ------------------------------------------------------------------
// Резолв доменного имени в IPv4 через Winsock (getaddrinfo).
// Возвращает первую найденную IPv4-строку, либо пустую строку.
// ------------------------------------------------------------------
std::string resolveHostToIp(const std::string& host) {
    ensureWsa();

    addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return "";

    char buf[64] = {0};
    sockaddr_in* sin = (sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    freeaddrinfo(res);
    return std::string(buf);
}

// ------------------------------------------------------------------
// РЕЖИМ 3: трассировка маршрута (traceroute) через ICMP IcmpSendEcho.
// Для каждого TTL шлём echo-запрос; промежуточный роутер отвечает
// IP_TTL_EXPIRED_TRANSIT, целевой — IP_SUCCESS. Хопы по возможности
// резолвим обратно в домен (reverse DNS), иначе показываем ASN/организацию.
// Параллелизм ограничен пулом потоков (НЕ std::async на каждый хоп).
// ------------------------------------------------------------------

// reverse DNS: IP -> домен (или "" если нет PTR)
static std::string reverseDns(const std::string& ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    char host[NI_MAXHOST] = {0};
    int r = getnameinfo((sockaddr*)&sa, sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD);
    if (r != 0) return "";
    // отбросим, если PTR вернул просто сам IP
    if (std::string(host) == ip) return "";
    return std::string(host);
}

// ASN/организация одного IP через ip-api.com (одиночный запрос).
static std::string asnOf(const std::string& ip) {
    std::string resp = httpPost(L"ip-api.com", L"/batch",
        std::string("[\"") + ip + "\"]"); // используем batch для единообразия
    if (resp.empty()) return "";
    // ВАЖНО: имена ASN часто содержат запятые («REG.RU, Ltd», «..., Inc»).
    // jsonStr режет на запятой -> jsonText (до закрывающей кавычки, с \uXXXX).
    std::string as  = jsonText(resp, "as");
    std::string org = jsonText(resp, "org");
    std::string isp = jsonText(resp, "isp");
    std::string name = !org.empty() ? org : isp;

    // Иногда org сам начинается с номера ASN (напр. as="AS56971",
    // org="AS56971 Cloud (CGI GLOBAL LIMITED)"). Убираем дублирующийся
    // префикс ASNxxxx из имени, чтобы не было "AS56971 AS56971 ...".
    auto stripAsnPrefix = [](std::string s) {
        // срезаем ведущее "ASxxxxx " если есть
        if (s.size() > 2 && (s[0]=='A'||s[0]=='a') && (s[1]=='S'||s[1]=='s')) {
            size_t i = 2; while (i < s.size() && isdigit((unsigned char)s[i])) i++;
            if (i > 2 && i < s.size() && s[i]==' ') return s.substr(i+1);
        }
        return s;
    };

    // as от ip-api обычно вида "AS56971 Имя Организации" (номер + имя сразу).
    // org часто дублирует то же самое. Стратегия: берём номер ASN из as,
    // а человекочитаемое имя — лучшее из (as без номера, org, isp), без повторов.
    auto asnNumber = [](const std::string& s) -> std::string {
        if (s.size() > 2 && (s[0]=='A'||s[0]=='a') && (s[1]=='S'||s[1]=='s')) {
            size_t i = 2; while (i < s.size() && isdigit((unsigned char)s[i])) i++;
            if (i > 2) return s.substr(0, i);   // "AS56971"
        }
        return "";
    };

    std::string num = asnNumber(as);
    std::string asName = stripAsnPrefix(as);     // имя из поля as (без "ASxxxx ")
    // выбираем имя: приоритет org, затем имя из as, затем isp
    std::string nm = !org.empty() ? stripAsnPrefix(org)
                   : (!asName.empty() && asName != as ? asName : stripAsnPrefix(isp));

    std::string out;
    if (!num.empty()) {
        out = num;                                // "AS56971"
        if (!nm.empty()) {
            // не добавляем имя, если оно уже совпадает с номером (нет имени)
            std::string nmLow = nm; for (auto& c: nmLow) c=(char)tolower((unsigned char)c);
            std::string numLow = num; for (auto& c: numLow) c=(char)tolower((unsigned char)c);
            if (nmLow != numLow) out += " " + nm;
        }
    } else {
        out = !nm.empty() ? nm : stripAsnPrefix(name);
    }
    return out;
}

struct TraceHop {
    int ttl = 0;
    std::string ip;       // IP хопа ("" если без ответа)
    double rttMs = -1;    // время ответа, мс с долями (-1 = таймаут)
    int status = 0;       // IP_SUCCESS / IP_TTL_EXPIRED_TRANSIT / ...
    std::string label;    // резолв: домен или ASN/организация
    bool reached = false; // дошли до цели
};

// Хоп из 10.0.0.0/8 — внутренняя адресация оператора на нашем участке пути.
//
// Здесь раньше стояло «распознавание устройства ТСПУ» по последнему октету
// (10.<регион>.<площадка>.Z: .131–.140 балансировщики, .151–.190 фильтры, .254
// криптошлюз «Континент» и т.д. по tspu-docs, раздел 20.1–20.3; до перенумерации
// 2026-09 — гл.10.2). Раскладка переписана из документации верно, но применялась
// неверно, и метка «probably TSPU» в трассе была ложной по существу:
//
//   * раздел 20 описывает СЕГМЕНТ УПРАВЛЕНИЯ — management-интерфейсы устройств за
//     криптошлюзом «Континент» в сторону ЦСУ. Это не тракт абонентского трафика,
//     и на пути абонента такие адреса не появляются;
//   * само оборудование ТСПУ в трассировке не видно в принципе. «Ни LAN-, ни
//     WAN-порты не имеют IP-адресов и не участвуют в маршрутизации» — и это про
//     всю цепочку, от байпасов до балансировщиков и фильтров (гл.2.2). «Фильтр —
//     это L2-устройство, у которого нет IP-интерфейсов для инициирования трафика;
//     ping и traceroute возможны только через management-интерфейс» (раздел 23.8,
//     также 10.2). Без IP в тракте данных устройство не уменьшает TTL и не шлёт
//     ICMP time-exceeded — то есть отдельным хопом стать не может;
//   * диапазон .151–.190 настолько широкий, что обычная 10.x-адресация оператора
//     попадает в него постоянно. Совпадение по октету не значило ничего.
//
// Поэтому 10.x-хоп — только информационная пометка: он говорит ровно одно — мы
// всё ещё внутри сети оператора. Где именно стоит фильтр, показывает не структура
// адреса, а поведение (TTL-развёртка по SNI и детекторы в analyzeConnIssues).
static bool isOperatorPrivateHop(const std::string& addr) {
    if (addr.size() < 8 || addr.size() > 15) return false;
    if (addr.compare(0, 3, "10.") != 0) return false;
    unsigned a = 0, b = 0, c = 0;
    if (sscanf(addr.c_str(), "10.%u.%u.%u", &a, &b, &c) != 3) return false;
    return a <= 255 && b <= 255 && c <= 255;
}

// ------------------------------------------------------------------
// Трассировка С ВНЕШНИХ УЗЛОВ — Globalping (api.globalping.io).
//
// Раньше здесь был ProbeOps. Сервис остановлен: и /api/v1/run, и
// /api/tools/port-check отдают HTTP 503 со страницей «ProbeOps — Paused»
// вместо JSON, поэтому режим молча показывал «пустой ответ».
// Globalping (открытый API jsDelivr) — прямой аналог и работает БЕЗ ключа:
// тысячи зондов по миру, traceroute/mtr/ping/dns, лимит ~250 проб в час на IP.
//
// Протокол двухшаговый (измерение асинхронное):
//   POST /v1/measurements
//        {"type":"traceroute","target":"<host>","limit":N,
//         "locations":[{"continent":"EU"},...]}
//     -> 202 {"id":"<id>","probesCount":N}
//     -> 400 {"error":{"message":"...","params":{...}}}  (напр. приватный IP)
//   GET  /v1/measurements/<id>  — опрашиваем, пока "status":"in-progress"
//     -> {"status":"finished","results":[{"probe":{"country","city","network"},
//         "result":{"status","rawOutput":"traceroute to ...\n 1 ..."}}]}
//
// Запасные варианты, если Globalping тоже отвалится (порядок — по удобству):
//   * RIPE Atlas   — https://atlas.ripe.net/api/v2/measurements/ (нужен ключ+кредиты)
//   * HackerTarget — https://api.hackertarget.com/mtr/?q=<host> (плейн-текст, 1 регион, 100/сут)
//   * check-host.net — /check-ping|tcp с Accept: application/json (без traceroute)
// ------------------------------------------------------------------
static const wchar_t* GLOBALPING_HOST = L"api.globalping.io";

// Ставит измерение в очередь. Возвращает id либо "" (тогда в err — причина).
// type — "traceroute"/"ping"/...; options — готовый JSON-объект
// measurementOptions (собирается в коде, без пользовательских строк) или "".
static std::string globalpingStart(const std::string& type, const std::string& target,
                                   int limit, const std::string& options, std::string& err) {
    // По одному зонду на континент — так регионы не совпадают между собой.
    // Если на континенте нет свободного зонда, API просто вернёт меньше проб.
    static const char* kContinents[] = { "EU", "NA", "AS", "SA", "OC", "AF" };
    std::string locs;
    for (int i = 0; i < limit && i < 6; i++)
        locs += std::string(i ? "," : "") + "{\"continent\":\"" + kContinents[i] + "\"}";
    std::string body = "{\"type\":\"" + type + "\",\"target\":\"" + jsonEscape(target) +
                       "\",\"limit\":" + std::to_string(limit) +
                       ",\"locations\":[" + locs + "]" +
                       (options.empty() ? std::string() : ",\"measurementOptions\":" + options) + "}";
    DWORD status = 0;
    std::string resp = httpsPostJson(GLOBALPING_HOST, L"/v1/measurements", body, L"", &status);
    if (resp.empty()) {
        err = status ? ("сервис ответил HTTP " + std::to_string(status) + " без тела")
                     : "нет связи с api.globalping.io";
        return "";
    }
    if (status >= 400 || resp.find("\"error\"") != std::string::npos) {
        std::string msg = jsonStrFull(resp, "message");
        // params содержит конкретную причину («target must not be a private hostname»)
        std::string tgtErr = jsonStrFull(resp, "target");
        if (!tgtErr.empty()) msg += " (" + tgtErr + ")";
        err = msg.empty() ? ("HTTP " + std::to_string(status)) : msg;
        return "";
    }
    std::string id = jsonStr(resp, "id");
    if (id.empty()) err = "не удалось разобрать ответ (нет поля id)";
    return id;
}

// Опрашивает измерение до статуса finished. Прерывается по Ctrl+C (g_traceAbort).
static std::string globalpingPoll(const std::string& id, std::string& err) {
    std::wstring wpath = L"/v1/measurements/" + std::wstring(id.begin(), id.end());
    for (int i = 0; i < 25; ++i) {           // максимум ~25 с
        if (g_traceAbort) { err = "прервано"; return ""; }
        Sleep(1000);
        std::string resp = httpsGet(GLOBALPING_HOST, wpath);
        if (resp.empty()) continue;
        // верхнеуровневый "status" идёт до массива results — первый в тексте
        std::string st = jsonStr(resp, "status");
        if (st == "finished") return resp;
        printf("."); fflush(stdout);
    }
    err = "измерение не завершилось за 25 с";
    return "";
}

// Печатает готовый ответ Globalping: по одному блоку на зонд.
// Возвращает число разобранных регионов.
static int globalpingPrint(const std::string& resp) {
    int regions = 0;
    size_t pos = 0;
    while (true) {
        size_t pp = resp.find("\"probe\"", pos);
        if (pp == std::string::npos) break;
        size_t ro = resp.find("\"rawOutput\"", pp);
        if (ro == std::string::npos) break;

        // весь блок одного зонда: от "probe" до следующего "probe" (или конца)
        size_t nextProbe = resp.find("\"probe\"", ro);
        std::string block = resp.substr(pp, (nextProbe == std::string::npos
                                             ? resp.size() : nextProbe) - pp);
        // описание зонда — до "result", иначе country/city поймали бы чужие поля
        std::string head = block.substr(0, std::min(block.find("\"result\""), block.size()));
        std::string country = jsonStr(head, "country");
        std::string city    = jsonStr(head, "city");
        std::string net     = jsonStrFull(head, "network");
        // status берём из result-части: API кладёт его то до rawOutput (при
        // ошибке), то после (при успехе) — на порядок полей опираться нельзя
        size_t rr = block.find("\"result\"");
        std::string rstat = jsonStr(rr == std::string::npos ? block : block.substr(rr), "status");
        std::string out   = jsonStrFull(resp, "rawOutput", ro);

        std::string loc = city.empty() ? country : (city + ", " + country);
        if (loc.empty()) loc = "?";
        if (!net.empty()) loc += " [" + net + "]";

        printf("\n%s--- зонд: %s ---%s\n", C::BCYN, loc.c_str(), C::RST);
        if (rstat == "failed")
            printf("%sзонд не смог выполнить трассировку:%s\n", C::YEL, C::RST);
        if (!out.empty()) printf("%s\n", out.c_str());
        else              printf("%s(нет данных по зонду)%s\n", C::GRY, C::RST);

        regions++; pos = ro + 11;
        if (regions >= 8) break;
    }
    return regions;
}

void runTraceMode() {
    ensureWsa();

    std::cout << "Укажите цель трассировки (IP или домен).\nЦель: " << std::flush;
    std::string s; readLine(s);
    s = idnToAscii(trim(s));   // мвд.рф — в punycode
    if (s.empty()) { std::cout << "Цель не указана.\n"; return; }

    std::string targetIp, targetName;

    if (isValidIpv4Str(s)) {
        targetIp = s;                                // корректный IP
    } else if (looksLikeDomainStr(s)) {
        targetName = s;
        targetIp = resolveHostToIp(s);
        if (targetIp.empty() || !isValidIpv4Str(targetIp)) {
            std::cout << "Домен не существует или нет ответа DNS.\n";
            return;
        }
    } else {
        std::cout << "Это не похоже на IP-адрес или доменное имя. Отмена.\n";
        return;
    }

    printf("\n");
    if (!targetName.empty())
        printf("Трассировка маршрута к %s [%s]\n", targetName.c_str(), targetIp.c_str());
    else
        printf("Трассировка маршрута к %s\n", targetIp.c_str());
    printf("Максимум хопов: 30, таймаут: 500 мс\n\n");

#ifndef _WIN32
    const int MAX_HOPS = 30;
    const int TIMEOUT = 500;
    std::vector<TraceHop> hops;
    bool done = false;
    g_traceAbort = false;
    bool sawPrivateHop = false;
    printf("  %-4s %-16s %-10s %s\n", "TTL", "IP", "RTT", "HOP (domain / ASN)");
    for (int ttl = 1; ttl <= MAX_HOPS && !done; ++ttl) {
        if (g_traceAbort) break;
        IcmpReply ir = icmpEcho(targetIp, ttl, TIMEOUT, "maryno-trace", &g_traceAbort);
        if (ir.noSocket) { printf("Не удалось открыть ICMP-сокет.\n"); return; }
        if (ir.aborted) break;
        TraceHop hop; hop.ttl = ttl;
        if (ir.status < 0) {
            hop.rttMs = -1; hop.status = -1;
        } else {
            hop.ip = ir.from;
            hop.rttMs = ir.rttMs;
            hop.status = ir.status;
            if (ir.status == IP_SUCCESS) { hop.reached = true; done = true; }
        }
#else
    IPAddr dest = 0;
    inet_pton(AF_INET, targetIp.c_str(), &dest);

    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        printf("Не удалось создать ICMP-хендл (нужны права?).\n");
        return;
    }

    const int MAX_HOPS = 30;
    // Задержка ожидания ответа на один хоп. 500 мс вместо прежних 1500:
    // трасса на 30 хопов с «дырами» проходит втрое быстрее. Цена — хоп с RTT
    // > 500 мс (спутник, дальняя Азия/Австралия через перегруженный стык)
    // покажется как "* * * *", хотя на самом деле отвечает.
    const DWORD TIMEOUT = 500;
    // шаг ожидания: должен быть заметно меньше TIMEOUT, иначе Ctrl+C
    // отрабатывает грубее самого таймаута
    const DWORD WAIT_STEP = 50;
    char sendData[32] = "maryno-trace";
    std::vector<TraceHop> hops;
    bool done = false;

    g_traceAbort = false; // сбрасываем флаг перед стартом

    // событие для асинхронного ICMP — позволяет ждать ответ прерываемо
    HANDLE hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!hEvent) {
        printf("Не удалось создать событие для ICMP.\n");
        IcmpCloseHandle(hIcmp);
        return;
    }

    // печатаем хопы по мере получения (как tracert/mtr)
    bool sawPrivateHop = false;   // встречался ли 10.x на пути (для пояснения ниже)
    printf("  %-4s %-16s %-10s %s\n", "TTL", "IP", "RTT", "HOP (domain / ASN)");
    for (int ttl = 1; ttl <= MAX_HOPS && !done; ++ttl) {
        if (g_traceAbort) break;
        IP_OPTION_INFORMATION opt{};
        opt.Ttl = (UCHAR)ttl;
        char replyBuf[sizeof(ICMP_ECHO_REPLY) + 64] = {0};

        // асинхронный запрос: возвращается сразу, ответ придёт через hEvent
        LARGE_INTEGER qpcFreq, qpcStart, qpcEnd;
        QueryPerformanceFrequency(&qpcFreq);
        QueryPerformanceCounter(&qpcStart);
        ResetEvent(hEvent);
        DWORD sent = IcmpSendEcho2(hIcmp, hEvent, nullptr, nullptr, dest, sendData, sizeof(sendData),
                                   &opt, replyBuf, sizeof(replyBuf), TIMEOUT);
        // 0 без ERROR_IO_PENDING — запрос не ушёл, событие не придёт
        if (sent == 0 && GetLastError() != ERROR_IO_PENDING) SetEvent(hEvent);

        // ждём ответ короткими интервалами по WAIT_STEP, проверяя флаг отмены —
        // так Ctrl+C прерывает мгновенно, не дожидаясь полного таймаута
        DWORD waited = 0; bool gotReply = false, aborted = false;
        while (waited < TIMEOUT + 200) {
            DWORD w = WaitForSingleObject(hEvent, WAIT_STEP);
            if (w == WAIT_OBJECT_0) { gotReply = true; break; }
            if (g_traceAbort) { aborted = true; break; }
            waited += WAIT_STEP;
        }
        QueryPerformanceCounter(&qpcEnd);
        // Запрос асинхронный: пока он не завершён, драйвер вправе писать в
        // replyBuf (он на стеке этой итерации). Уходить из итерации — и по
        // Ctrl+C тоже — можно только после сигнала события; сам запрос
        // ограничен TIMEOUT, так что ждать недолго. Заодно поздний ответ не
        // «перетечёт» в следующий TTL через то же событие.
        if (!gotReply) WaitForSingleObject(hEvent, TIMEOUT + 2000);
        if (aborted) break;

        // точный RTT в мс с долями (через высокоточный таймер)
        double preciseMs = (qpcFreq.QuadPart > 0)
            ? (double)(qpcEnd.QuadPart - qpcStart.QuadPart) * 1000.0 / (double)qpcFreq.QuadPart
            : -1.0;

        TraceHop hop; hop.ttl = ttl;
        DWORD nReplies = gotReply ? IcmpParseReplies(replyBuf, sizeof(replyBuf)) : 0;
        if (nReplies == 0) {
            hop.rttMs = -1; hop.status = -1;
        } else {
            ICMP_ECHO_REPLY* reply = (ICMP_ECHO_REPLY*)replyBuf;
            in_addr addr; addr.s_addr = reply->Address;
            char ipbuf[64] = {0};
            inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf));
            hop.ip = ipbuf;
            // RoundTripTime даёт только целые мс; берём точный замер таймером,
            // а значение от ICMP — только если таймер не сработал
            hop.rttMs = (preciseMs >= 0) ? preciseMs : (double)reply->RoundTripTime;
            hop.status = (int)reply->Status;
            if (reply->Status == IP_SUCCESS) { hop.reached = true; done = true; }
        }
#endif

        // резолвим этот хоп сразу (reverse DNS, иначе ASN) и печатаем строку
        if (!hop.ip.empty()) {
            if (g_traceAbort) break;
            std::string dom = reverseDns(hop.ip);
            if (!dom.empty()) hop.label = dom;
            else { std::string asn = asnOf(hop.ip); hop.label = asn.empty() ? "no info" : asn; }
        }
        if (g_traceAbort) break;
        if (hop.ip.empty()) {
            printf("  %-4d %-16s %-10s %s\n", hop.ttl, "* * * *", "-", "(timeout)");
            fflush(stdout);
        } else {
            bool privHop = isOperatorPrivateHop(hop.ip);
            if (privHop) sawPrivateHop = true;
            // пометка идёт в колонку HOP перед label/ASN
            std::string hopLabel;
            if (privHop) hopLabel = "[внутр. сеть оператора] ";
            // RTT: если замера нет (узел показался, но не ответил эхо) — ставим "-"
            bool haveRtt = (hop.rttMs > 0.0 || hop.reached);
            char rtt[24];
            if (haveRtt) snprintf(rtt, sizeof(rtt), "%.2f ms", hop.rttMs);
            else         snprintf(rtt, sizeof(rtt), "-");
            // если RTT нет — добавим (timeout) к label
            if (!haveRtt) hopLabel += "(timeout)";
            // для приватного хопа не дублируем неинформативное "no info" из резолва
            else if (!(privHop && (hop.label=="no info" || hop.label.empty())))
                hopLabel += hop.label;
            if (hop.reached) hopLabel += "  <=dest";

            // пометка нейтральная и обычным цветом — это не признак блокировки
            printf("  %-4d %-16s %-10s %s\n",
                   hop.ttl, hop.ip.c_str(), rtt, hopLabel.c_str());
            fflush(stdout);
        }
        hops.push_back(hop);
    }
#ifdef _WIN32
    if (hEvent) CloseHandle(hEvent);
    IcmpCloseHandle(hIcmp);
#endif

    if (g_traceAbort) {
        printf("\n%sТрассировка остановлена (Ctrl+C).%s\n", C::YEL, C::RST);
        return;
    }
    if (done)
        printf("\n%sТрассировка завершена.%s\n", C::GRN, C::RST);
    else
        printf("\n%sТрассировка завершена — цель не достигнута за %d хопов "
               "(возможна фильтрация/блокировка или хост недоступен).%s\n",
               C::YEL, MAX_HOPS, C::RST);

    if (sawPrivateHop)
        printf("%sНа пути есть хопы 10.x — внутренняя адресация оператора. Это не\n"
               "признак фильтрации: оборудование ТСПУ работает на L2, не имеет IP в\n"
               "тракте данных и отдельным хопом в трассировке не видно вообще.%s\n",
               C::GRY, C::RST);

    // --- встречная трассировка с внешних зондов (Globalping) ---
    std::cout << "\nСделать трассировку с внешних зондов (Globalping, из-за рубежа)? "
              << "Сравнить маршрут со стороны [y/N]: " << std::flush;
    std::string yn; readLine(yn);
    if (isYesAnswer(yn)) {
        printf("\n=== ТРАССИРОВКА С ВНЕШНИХ ЗОНДОВ (Globalping) ===\n");
        std::string tgt = !targetName.empty() ? targetName : targetIp;
        g_traceAbort = false;               // Ctrl+C прерывает и ожидание тоже

        std::string err;
        std::string id = globalpingStart("traceroute", tgt, 5, "", err);
        if (id.empty()) {
            printf("%sGlobalping недоступен: %s%s\n", C::YEL, err.c_str(), C::RST);
        } else {
            printf("Измерение %s поставлено в очередь, жду результат", id.c_str());
            fflush(stdout);
            std::string resp = globalpingPoll(id, err);
            printf("\n");
            if (resp.empty()) {
                printf("%sРезультат не получен: %s%s\n", C::YEL, err.c_str(), C::RST);
            } else {
                int regions = globalpingPrint(resp);
                if (regions == 0) {
                    printf("%sНе удалось разобрать ответ. Сырой ответ (начало):%s\n", C::GRY, C::RST);
                    printf("%.1200s\n", resp.c_str());
                }
                printf("\n%sСравните: если ваш маршрут обрывается, а внешний доходит до цели — "
                       "проблема на вашем участке (блокировка/фильтрация).%s\n",
                       C::GRY, C::RST);
            }
        }
        g_traceAbort = false;
    }
}

// ------------------------------------------------------------------
// РЕЖИМ 4: проверка географии по RTT (детект подмены локации).
// Измеряем реальный RTT до IP (ICMP, минимум из нескольких проб) и сравниваем
// с минимально ВОЗМОЖНЫМ RTT для страны из GeoIP. Свет в оптоволокне идёт
// ~200000 км/с, поэтому есть физический «пол» задержки до каждого региона.
// Если измеренный RTT МЕНЬШЕ этого пола — заявленная гео-локация невозможна:
// трафик идёт через локальный прокси/CDN/туннель, а не в ту страну.
// ------------------------------------------------------------------

// Минимально правдоподобный RTT (мс) от РФ (центр) до страны по коду.
// Это нижняя граница с запасом: физика + типичная маршрутизация.
// расстояние по большому кругу между двумя точками (км)
static double greatCircleKm(double lat1, double lon1, double lat2, double lon2) {
    const double R = 6371.0, D2R = 3.14159265358979 / 180.0;
    double dlat = (lat2-lat1)*D2R, dlon = (lon2-lon1)*D2R;
    double a = std::sin(dlat/2)*std::sin(dlat/2) +
               std::cos(lat1*D2R)*std::cos(lat2*D2R)*std::sin(dlon/2)*std::sin(dlon/2);
    return 2.0 * R * std::asin(std::min(1.0, std::sqrt(a)));
}

// физический минимум RTT (мс) по расстоянию: свет в оптике ~200 км/мс в одну
// сторону, туда-обратно ~100 км/мс. Реальный маршрут не прямой — берём фактор
// извилистости 1.4. Итого RTT_min ≈ км / 100 * 1.4. Плюс небольшой пол на
// обработку (~2 мс). Это объективный предел, не зависит от страны.
static int rttFloorFromDistanceKm(double km) {
    double rtt = km / 100.0 * 1.4 + 2.0;
    if (rtt < 1.0) rtt = 1.0;
    return (int)(rtt + 0.5);
}

static int minPlausibleRttForCountry(const std::string& cc) {
    // соседние / в пределах РФ и ближнего зарубежья
    if (cc=="RU"||cc=="BY"||cc=="UA"||cc=="KZ"||cc=="LV"||cc=="LT"||cc=="EE"||
        cc=="FI"||cc=="PL"||cc=="MD"||cc=="GE"||cc=="AM"||cc=="AZ") return 3;
    // Европа
    if (cc=="DE"||cc=="NL"||cc=="SE"||cc=="NO"||cc=="DK"||cc=="CZ"||cc=="AT"||
        cc=="CH"||cc=="FR"||cc=="GB"||cc=="BE"||cc=="LU"||cc=="HU"||cc=="RO"||
        cc=="IT"||cc=="ES"||cc=="PT"||cc=="IE"||cc=="RS"||cc=="BG"||cc=="GR"||
        cc=="SK"||cc=="SI"||cc=="HR") return 18;
    // Ближний Восток / Турция / Сев. Африка
    if (cc=="TR"||cc=="IL"||cc=="AE"||cc=="SA"||cc=="EG"||cc=="IR"||cc=="QA"||
        cc=="CY"||cc=="JO"||cc=="KW") return 25;
    // США восточное / Канада восток / Юж. Америка север
    if (cc=="US"||cc=="CA") return 80;
    // Азия (Индия, Китай, ЮВА)
    if (cc=="IN"||cc=="CN"||cc=="HK"||cc=="SG"||cc=="JP"||cc=="KR"||cc=="TH"||
        cc=="VN"||cc=="MY"||cc=="ID"||cc=="TW"||cc=="PK") return 60;
    // Австралия / Океания / Юж. Америка юг / глубокая Африка
    if (cc=="AU"||cc=="NZ"||cc=="BR"||cc=="AR"||cc=="CL"||cc=="ZA") return 130;
    return 15; // неизвестная страна — мягкий порог
}

void runGeoRttMode() {
    ensureWsa();

    std::cout << "Укажите цель (IP или домен).\n"
              << "Пример: 8.8.8.8   или   youtube.com\nЦель: " << std::flush;
    std::string s; readLine(s);
    s = idnToAscii(trim(s));
    if (s.empty()) { std::cout << "Цель не указана.\n"; return; }

    std::string targetIp, targetName;
    if (isValidIpv4Str(s)) targetIp = s;
    else if (looksLikeDomainStr(s)) {
        targetName = s;
        std::cout << "Резолвлю домен " << s << " ..." << std::flush;
        targetIp = resolveHostToIp(s);
        if (targetIp.empty() || !isValidIpv4Str(targetIp)) { std::cout << " не удалось.\n"; return; }
        std::cout << " -> " << targetIp << "\n";
    } else { std::cout << "Это не похоже на IP или домен. Отмена.\n"; return; }

    printf("\n=================== ПРОВЕРКА ГЕО ПО RTT ===================\n");
    if (!targetName.empty()) printf("Цель: %s [%s]\n", targetName.c_str(), targetIp.c_str());
    else printf("Цель: %s\n", targetIp.c_str());

    // 1) измеряем RTT: 5 ICMP-проб, берём МИНИМУМ (он ближе к физическому пределу)
    double minRtt = -1; int got = 0;
#ifndef _WIN32
    printf("Пингую (5 проб)... ");
    for (int i = 0; i < 5; i++) {
        IcmpReply ir = icmpEcho(targetIp, 0, 2000, "maryno-geo");
        if (ir.noSocket) { printf("Не удалось открыть ICMP-сокет.\n"); return; }
        if (ir.status == IP_SUCCESS) {
            if (minRtt < 0 || ir.rttMs < minRtt) minRtt = ir.rttMs;
            got++;
        }
        Sleep(200);
    }
#else
    IPAddr dest = 0; inet_pton(AF_INET, targetIp.c_str(), &dest);
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) { printf("Не удалось создать ICMP-хендл.\n"); return; }
    char sendData[32] = "maryno-geo";
    printf("Пингую (5 проб)... ");
    for (int i = 0; i < 5; i++) {
        char replyBuf[sizeof(ICMP_ECHO_REPLY)+64] = {0};
        LARGE_INTEGER f,a,b; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&a);
        DWORD r = IcmpSendEcho(hIcmp, dest, sendData, sizeof(sendData), nullptr,
                               replyBuf, sizeof(replyBuf), 2000);
        QueryPerformanceCounter(&b);
        if (r > 0) {
            ICMP_ECHO_REPLY* rep = (ICMP_ECHO_REPLY*)replyBuf;
            if (rep->Status == IP_SUCCESS) {
                double ms = (f.QuadPart>0)? (double)(b.QuadPart-a.QuadPart)*1000.0/(double)f.QuadPart : (double)rep->RoundTripTime;
                if (minRtt < 0 || ms < minRtt) minRtt = ms;
                got++;
            }
        }
        Sleep(200);
    }
    IcmpCloseHandle(hIcmp);
#endif

    if (got == 0) {
        printf("\n%sХост не отвечает на ICMP — измерить RTT нельзя.%s\n", C::YEL, C::RST);
        printf("(многие серверы блокируют ping; проверку гео по RTT провести не удалось)\n");
        return;
    }
    printf("готово. Минимальный RTT: %s%.2f мс%s\n", C::BWHT, minRtt, C::RST);

    // 2) GeoIP через ip-api
    std::string resp = httpPost(L"ip-api.com", L"/batch",
                                std::string("[\"") + targetIp + "\"]");
    std::string cc = jsonStr(resp, "countryCode");
    std::string org = jsonText(resp, "org");
    std::string asn = jsonText(resp, "as");

    // --- сверка по нескольким GeoIP-источникам с полной инфой + security-флаги ---
    // Опрашиваем ip-api, ipwho.is, iplocate.io, ipapi.is. Для каждого показываем
    // страну/город/ASN; ipapi.is даёт флаги is_vpn/proxy/tor/datacenter/abuser
    // (с сентября 2026 — только с ключом API, см. ipapiHasFlags).
    std::string cc2, cc3;
    std::string city1 = jsonStr(resp, "city");
    std::wstring wip(targetIp.begin(), targetIp.end());

    std::string city2, org2, city3, org3;
    {
        std::string r2 = httpsGet(L"ipwho.is", L"/" + wip);
        if (!r2.empty()) {
            cc2 = jsonStr(r2, "country_code");
            city2 = jsonStr(r2, "city");
            // у ipwho.is org/isp в объекте connection
            size_t cp = r2.find("\"connection\"");
            if (cp != std::string::npos) {
                size_t ob = r2.find('{', cp), ce = r2.find('}', ob);
                if (ob!=std::string::npos && ce!=std::string::npos) {
                    std::string sb = r2.substr(ob, ce-ob+1);
                    org2 = jsonText(sb, "isp"); if (org2.empty()) org2 = jsonText(sb, "org");
                }
            }
        }
        std::string r3 = httpsGet(L"iplocate.io", L"/api/lookup/" + wip);
        if (!r3.empty()) {
            cc3 = jsonStr(r3, "country_code");
            city3 = jsonStr(r3, "city");
            org3 = jsonText(r3, "org");
        }
    }

    // security-флаги от ipapi.is
    std::string ccSec, citySec, orgSec;
    bool fVpn=false, fProxy=false, fTor=false, fDc=false, fAbuser=false;
    int secState = 0;   // 0 — нет ответа, 1 — ответ без флагов (нет ключа API), 2 — флаги есть
    {
        std::string rs = httpsGet(L"api.ipapi.is", L"/?q=" + wip);
        if (!rs.empty()) {
            secState = ipapiHasFlags(rs) ? 2 : 1;
            ccSec = jsonStr(rs, "country_code");
            citySec = jsonStr(rs, "city");
            auto bf = [&](const char* k){ return jsonStr(rs, k) == "true"; };
            fVpn=bf("is_vpn"); fProxy=bf("is_proxy"); fTor=bf("is_tor");
            fDc=bf("is_datacenter")||bf("is_hosting"); fAbuser=bf("is_abuser");
            size_t ap = rs.find("\"asn\"");
            if (ap != std::string::npos) {
                size_t ob = rs.find('{', ap), ce = rs.find('}', ob);
                if (ob!=std::string::npos && ce!=std::string::npos)
                    orgSec = jsonText(rs.substr(ob, ce-ob+1), "org");
            }
        }
    }

    const std::string cc1 = cc;   // ответ самого ip-api — для строки таблицы, до подстановки
    if (cc.empty()) { if (!cc2.empty()) cc = cc2; else if (!cc3.empty()) cc = cc3;
                      else if (!ccSec.empty()) cc = ccSec; }

    if (cc.empty()) {
        printf("%sНе удалось определить GeoIP ни по одному источнику.%s\n", C::YEL, C::RST);
        printf("Измеренный RTT: %.2f мс\n", minRtt);
        return;
    }

    // --- полная таблица по источникам ---
    printf("\n%s=== GeoIP по источникам ===%s\n", C::BOLD, C::RST);
    printf("  %-12s %-5s %-16s %s\n", "ИСТОЧНИК", "СТРАНА", "ГОРОД", "ASN / ORG");
    auto srcRow = [&](const char* name, const std::string& c, const std::string& ci,
                      const std::string& o){
        printf("  %-12s %-5s %-16s %s\n", name,
               c.empty()?"-":c.c_str(), ci.empty()?"-":ci.c_str(), o.empty()?"-":o.c_str());
    };
    srcRow("ip-api.com",  cc1,   city1,   org);
    srcRow("ipwho.is",    cc2,   city2,   org2);
    srcRow("iplocate.io", cc3,   city3,   org3);
    srcRow("ipapi.is",    ccSec, citySec, orgSec);

    bool disagree = (!cc2.empty() && cc2 != cc) || (!cc3.empty() && cc3 != cc)
                  || (!ccSec.empty() && ccSec != cc);
    if (disagree)
        printf("  %s[!] Страны расходятся — GeoIP ненадёжен, вердикт ориентировочный.%s\n",
               C::YEL, C::RST);

    // security-флаги
    if (fVpn || fProxy || fTor || fDc || fAbuser) {
        printf("  %sФлаги (ipapi.is):%s ", C::BOLD, C::RST);
        if (fVpn)    printf("%sVPN%s ", C::RED, C::RST);
        if (fProxy)  printf("%sPROXY%s ", C::RED, C::RST);
        if (fTor)    printf("%sTOR%s ", C::RED, C::RST);
        if (fDc)     printf("%sDATACENTER%s ", C::YEL, C::RST);
        if (fAbuser) printf("%sABUSER%s ", C::RED, C::RST);
        printf("\n");
    } else if (secState == 2) {
        printf("  %sФлаги (ipapi.is): чисто (не VPN/proxy/tor/datacenter)%s\n", C::GRY, C::RST);
    } else if (secState == 1) {
        // без флага — не «чисто»: урезанный ответ без ключа о VPN ничего не говорит
        printf("  %sФлаги (ipapi.is): недоступны — без ключа API сервис их больше не отдаёт "
               "(это не «чисто»)%s\n", C::YEL, C::RST);
    } else {
        printf("  %sФлаги (ipapi.is): нет ответа — проверка не выполнена%s\n", C::YEL, C::RST);
    }

    int floorRtt = minPlausibleRttForCountry(cc);
    std::string floorBasis = "оценка по стране";   // как получили порог (для пояснения)

    // --- автоопределение наблюдателя: считаем РЕАЛЬНЫЙ минимум RTT по расстоянию ---
    // Берём координаты цели (из ip-api batch выше) и свои координаты (геолокация
    // нашего публичного IP). Физический минимум = функция расстояния, а не страны
    // цели — поэтому корректно для ЛЮБОГО местоположения наблюдателя (Москва, ДВ и т.д.).
    {
        double tLat = atof(jsonStr(resp, "lat").c_str());
        double tLon = atof(jsonStr(resp, "lon").c_str());
        // свои координаты: ip-api /json без аргумента вернёт данные вызывающего
        std::string self = httpRequest(L"GET", L"ip-api.com", L"/json", std::string());
        double oLat = atof(jsonStr(self, "lat").c_str());
        double oLon = atof(jsonStr(self, "lon").c_str());
        std::string oCity = jsonStr(self, "city");
        std::string oCc   = jsonStr(self, "countryCode");
        bool haveTarget = (tLat != 0.0 || tLon != 0.0);
        bool haveSelf   = (oLat != 0.0 || oLon != 0.0);
        if (haveTarget && haveSelf) {
            double km = greatCircleKm(oLat, oLon, tLat, tLon);
            floorRtt = rttFloorFromDistanceKm(km);
            char basis[160];
            snprintf(basis, sizeof(basis),
                "расстояние ~%.0f км от вас (%s, %s) — реальный наблюдатель",
                km, oCity.empty()?"?":oCity.c_str(), oCc.empty()?"?":oCc.c_str());
            floorBasis = basis;
        }
    }

    const std::string ccName = countryNameRu(cc);
    printf("\nGeoIP (консенсус): %s (%s)%s%s\n", ccName.c_str(), cc.c_str(),
           org.empty()?"":", ", org.c_str());
    printf("Физический минимум RTT для %s: ~%d мс (%s)\n",
           ccName.c_str(), floorRtt, floorBasis.c_str());

    // 3) вердикт
    printf("\n");
    if (minRtt + 1.0 < floorRtt * 0.6) {
        // RTT сильно ниже физического минимума — гео точно подменено
        printf("%s=== ГЕО НЕ СООТВЕТСТВУЕТ ===%s\n", C::RED, C::RST);
        printf("%sИзмеренный RTT (%.1f мс) физически НЕВОЗМОЖЕН для %s (минимум ~%d мс).\n"
               "Трафик идёт НЕ в заявленную страну — между вами и этим IP локальная\n"
               "точка: CDN-узел, прокси или туннель рядом с вами.%s\n",
               C::RED, minRtt, ccName.c_str(), floorRtt, C::RST);
    } else if (minRtt < floorRtt) {
        printf("%s=== ГЕО СОМНИТЕЛЬНО ===%s\n", C::YEL, C::RST);
        printf("%sRTT (%.1f мс) ниже ожидаемого для %s (~%d мс). Возможен ближний\n"
               "CDN-узел или неточный GeoIP. Не однозначно, но стоит проверить.%s\n",
               C::YEL, minRtt, ccName.c_str(), floorRtt, C::RST);
    } else {
        printf("%s=== ГЕО ПРАВДОПОДОБНО ===%s\n", C::GRN, C::RST);
        printf("%sRTT (%.1f мс) согласуется с GeoIP-локацией %s (минимум ~%d мс).\n"
               "Признаков подмены гео по задержке нет.%s\n",
               C::GRN, minRtt, ccName.c_str(), floorRtt, C::RST);
    }
    printf("\n(метод: сравнение задержки с физическим пределом скорости света в оптике;\n"
           " CDN крупных сервисов легитимно держат локальные узлы — это не всегда VPN.)\n");
}

// ------------------------------------------------------------------
// РЕЖИМ 6: проверка TCP-порта ИЗВНЕ — TCP-ping с зондов Globalping на
// разных континентах (ключ не нужен). Раньше режим ходил в ProbeOps, но
// сервис приостановлен (HTTP 503 «ProbeOps — Paused»), и режим был мёртв.
// ------------------------------------------------------------------

// Печатает результаты TCP-ping по зондам. Возвращает число зондов, open —
// сколько из них получили ответ (порт принимает соединения).
static int globalpingPrintTcpPing(const std::string& resp, int& open) {
    int probes = 0; open = 0;
    printf("  %-40s %-10s %s\n", "ЗОНД", "RTT", "ПОРТ");
    size_t pos = 0;
    while (probes < 8) {
        size_t pp = resp.find("\"probe\"", pos);
        if (pp == std::string::npos) break;
        size_t nextProbe = resp.find("\"probe\"", pp + 7);
        std::string block = resp.substr(pp, (nextProbe == std::string::npos
                                             ? resp.size() : nextProbe) - pp);
        size_t rr = block.find("\"result\"");
        std::string head = block.substr(0, std::min(rr, block.size()));
        std::string res  = (rr == std::string::npos) ? std::string() : block.substr(rr);
        std::string country = jsonStr(head, "country");
        std::string city    = jsonStr(head, "city");
        std::string net     = jsonText(head, "network");
        std::string loc = city.empty() ? country : (city + ", " + country);
        if (loc.empty()) loc = "?";
        if (!net.empty()) loc += " [" + net + "]";

        std::string rstat = jsonStr(res, "status");
        size_t st = res.find("\"stats\"");
        std::string stats = (st == std::string::npos) ? std::string() : res.substr(st);
        std::string total = jsonStr(stats, "total"), rcv = jsonStr(stats, "rcv"),
                    avg   = jsonStr(stats, "avg");
        std::string rtt = (avg.empty() || avg == "null") ? "—" : avg + " ms";

        if (rstat == "failed" || total.empty()) {
            std::string raw = jsonStrFull(res, "rawOutput");
            size_t nl = raw.find('\n');
            if (nl != std::string::npos) raw.resize(nl);
            printf("  %-40s %-10s %sзонд не смог проверить%s %s\n", loc.c_str(), "—",
                   C::YEL, C::RST, raw.c_str());
        } else if (atoi(rcv.c_str()) > 0) {
            open++;
            printf("  %-40s %-10s %sОТКРЫТ%s (%s из %s)\n", loc.c_str(), rtt.c_str(),
                   C::GRN, C::RST, rcv.c_str(), total.c_str());
        } else {
            printf("  %-40s %-10s %sнет ответа%s (0 из %s)\n", loc.c_str(), "—",
                   C::RED, C::RST, total.c_str());
        }
        probes++;
        pos = pp + 7;
    }
    return probes;
}

void runPortCheckMode() {
    ensureWsa();
    std::cout << "Проверка доступности TCP-порта ИЗВНЕ (зонды Globalping на разных континентах).\n";
    std::cout << "Цель (IP или домен): " << std::flush;
    std::string host; readLine(host);
    host = idnToAscii(trim(host));
    if (host.empty()) { std::cout << "Цель не указана.\n"; return; }
    for (auto& ch : host) ch = (char)tolower((unsigned char)ch);
    if (!isValidIpv4Str(host) && !looksLikeDomainStr(host)) {
        std::cout << "Это не похоже на IP-адрес или доменное имя. Отмена.\n";
        return;
    }
    if (isValidIpv4Str(host) && isPrivateIp(host)) {
        std::cout << "Это частный адрес — извне он недоступен по определению. Укажите "
                     "внешний (белый) IP абонента.\n";
        return;
    }

    std::cout << "Порт (Enter — 443): " << std::flush;
    std::string portStr; readLine(portStr);
    portStr = trim(portStr);
    long long port = 443;
    if (!portStr.empty()) {
        char* end = nullptr;
        port = strtoll(portStr.c_str(), &end, 10);
        if (!end || *end) port = -1;
    }
    if (port < 1 || port > 65535) { std::cout << "Неверный порт.\n"; return; }

    printf("\n=================== ПРОВЕРКА ПОРТА ИЗВНЕ ===================\n");
    printf("Цель: %s:%lld (TCP)\n", host.c_str(), port);
    g_traceAbort = false;               // Ctrl+C прерывает ожидание

    std::string err;
    std::string opts = "{\"protocol\":\"TCP\",\"port\":" + std::to_string(port) + ",\"packets\":3}";
    std::string id = globalpingStart("ping", host, 6, opts, err);
    if (id.empty()) {
        printf("%sGlobalping недоступен: %s%s\n", C::YEL, err.c_str(), C::RST);
        return;
    }
    printf("Измерение %s поставлено в очередь, жду результат", id.c_str());
    fflush(stdout);
    std::string resp = globalpingPoll(id, err);
    printf("\n\n");
    g_traceAbort = false;
    if (resp.empty()) {
        printf("%sРезультат не получен: %s%s\n", C::YEL, err.c_str(), C::RST);
        return;
    }
    int open = 0;
    int probes = globalpingPrintTcpPing(resp, open);
    if (probes == 0) {
        printf("%sНе удалось разобрать ответ. Сырой ответ (начало):%s\n", C::GRY, C::RST);
        printf("%.1200s\n", resp.c_str());
        return;
    }
    printf("\n");
    if (open == probes)
        printf("%sПорт %lld доступен извне со всех зондов.%s\n", C::GRN, port, C::RST);
    else if (open == 0)
        printf("%sПорт %lld извне недоступен ни с одного зонда: закрыт, фильтруется\n"
               "файрволом/роутером абонента или адрес за NAT (не белый IP).%s\n",
               C::RED, port, C::RST);
    else
        printf("%sПорт %lld доступен частично (%d из %d зондов): потери на пути или\n"
               "фильтрация по стране/сети источника.%s\n", C::YEL, port, open, probes, C::RST);
}

// ------------------------------------------------------------------
// РЕЖИМ 7: локальный скан портов + активные UDP-handshake пробы.
// Сканирует с НАШЕЙ машины. TCP — connect-скан. UDP — шлём настоящие
// handshake-payload'ы протоколов (WireGuard/IKE/OpenVPN/DNS/QUIC) и ждём
// валидный ответ (идея из ByeByeVPN — точнее, чем «порт молчит»).
// ------------------------------------------------------------------

// TCP connect с таймаутом (мс). Возвращает: 1=open, 0=closed(refused), -1=filtered(timeout).
// Разбор баннера -> «продукт версия» (упрощённый аналог nmap -sV).
// Узнаёт распространённые сервисы по характерным сигнатурам в их приветствии.
static std::string parseServiceVersion(const std::string& banner, int port) {
    if (banner.empty()) return "";
    const std::string& b = banner;
    auto has = [&](const char* s){ return b.find(s) != std::string::npos; };
    // вырезает подстроку «после ключа до разделителя» для извлечения версии
    auto after = [&](const char* key, const char* stop)->std::string {
        size_t p = b.find(key); if (p==std::string::npos) return "";
        p += strlen(key);
        size_t e = b.find_first_of(stop, p);
        return b.substr(p, (e==std::string::npos? b.size():e) - p);
    };

    // SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
    if (b.rfind("SSH-",0)==0) {
        std::string v = b.substr(0, b.find_first_of("\r\n"));
        return v;   // вся строка версии информативна (OpenSSH/dropbear + версия)
    }
    // HTTP: "Server: nginx/1.24.0" (после нашего HEAD-запроса)
    if (has("HTTP/") ) {
        std::string srv = trim(after("Server:", "\r\n"));
        if (!srv.empty()) return srv;          // nginx/1.24.0, Apache/2.4.58 и т.п.
        return "HTTP (сервер не представился)";
    }
    // FTP: "220 (vsFTPd 3.0.5)" или "220 ProFTPD 1.3.8"
    if (b.rfind("220",0)==0 && (has("FTP")||has("ftp"))) {
        if (has("vsFTPd"))  return "vsFTPd"  + after("vsFTPd", " )\r\n");
        if (has("ProFTPD")) return "ProFTPD" + after("ProFTPD", " \r\n");
        if (has("FileZilla")) return "FileZilla FTP";
        if (has("Pure-FTPd")) return "Pure-FTPd";
        return "FTP: " + b.substr(0, b.find_first_of("\r\n"));
    }
    // SMTP: "220 mail.example.com ESMTP Postfix"
    if (b.rfind("220",0)==0 && (has("SMTP")||has("ESMTP"))) {
        if (has("Postfix")) return "Postfix SMTP";
        if (has("Exim"))    return "Exim" + after("Exim", " \r\n");
        if (has("Sendmail"))return "Sendmail";
        if (has("Microsoft"))return "Microsoft ESMTP";
        return "SMTP: " + b.substr(0, b.find_first_of("\r\n"));
    }
    // POP3/IMAP
    if (b.rfind("+OK",0)==0) {
        if (has("Dovecot")) return "Dovecot POP3";
        return "POP3";
    }
    if (b.rfind("* OK",0)==0) {
        if (has("Dovecot")) return "Dovecot IMAP";
        return "IMAP";
    }
    // MySQL/MariaDB: бинарный handshake содержит версию в ASCII (напр. "8.0.36" / "5.5.5-10.11")
    if (port==3306 || has("mysql") || has("MariaDB")) {
        // ищем первую похожую на версию подстроку X.Y.Z
        for (size_t i=0;i+2<b.size();++i)
            if (isdigit((unsigned char)b[i]) && b[i+1]=='.' ) {
                size_t e=i; while(e<b.size() && (isdigit((unsigned char)b[e])||b[e]=='.'||b[e]=='-')) e++;
                std::string ver=b.substr(i,e-i);
                if (ver.size()>=3) return (has("MariaDB")?"MariaDB ":"MySQL ")+ver;
            }
        return "MySQL/MariaDB";
    }
    // RDP/прочее — баннер нечитаем, вернём первую печатаемую строку
    {
        std::string line;
        for (char c : b) { if (c=='\r'||c=='\n') break; if (c>=0x20 && c<0x7f) line+=c; }
        if (line.size() >= 3) return line.substr(0, 60);
    }
    return "";
}

#ifdef _WIN32
// Windows, получив RST в ответ на SYN, отдаёт WSAECONNREFUSED не сразу: ещё
// дважды повторяет SYN с паузой ~0,5 с (MS KB175523), и отказ приходит позже
// таймаута скана (800 мс). Закрытые порты выходили «filtered», а :65000 —
// «drop — фаервол». На macOS RST сразу даёт ECONNREFUSED.
// SIO_TCP_INITIAL_RTO (<mstcpip.h>: _WSAIOW(IOC_VENDOR,17)) убирает повторы SYN.
// TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS (0xFE) понимают с Windows 10 1709
// (сборка 16299); на более старых то же значение — 254 повтора, там ставим 1
// (один повтор через ~0,5 с — отказ всё равно успевает до таймаута).
static void tcpNoSynRetries(SOCKET s) {
    static const UCHAR maxSyn = [] {
        // GetVersionEx без манифеста занижает версию — спрашиваем ntdll
        typedef LONG (WINAPI* RtlGetVersionFn)(OSVERSIONINFOW*);
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        auto fn = nt ? reinterpret_cast<RtlGetVersionFn>(GetProcAddress(nt, "RtlGetVersion")) : nullptr;
        OSVERSIONINFOW v{}; v.dwOSVersionInfoSize = sizeof(v);
        if (fn && fn(&v) == 0 &&
            (v.dwMajorVersion > 10 || (v.dwMajorVersion == 10 && v.dwBuildNumber >= 16299)))
            return (UCHAR)0xFE;
        return (UCHAR)1;
    }();
    // как TCP_INITIAL_RTO_PARAMETERS; Rtt = 0xFFFF (UNSPECIFIED) — начальный RTO системный
    struct { USHORT Rtt; UCHAR MaxSynRetransmissions; } p{ (USHORT)0xFFFF, maxSyn };
    DWORD ret = 0;
    WSAIoctl(s, _WSAIOW(IOC_VENDOR, 17), &p, (DWORD)sizeof(p), nullptr, 0, &ret, nullptr, nullptr);
}
#endif

// TCP connect + опциональный баннер-граб. result: 1=open(+banner), 0=refused, -1=filtered.
static int tcpProbeBanner(const std::string& ip, int port, int timeoutMs,
                          long long* connectMs, std::string* banner) {
    auto t0 = std::chrono::steady_clock::now();
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return -1;
#ifdef _WIN32
    tcpNoSynRetries(s);             // до connect: иначе RST ждёт повторов SYN
#endif
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons((u_short)port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    int result = -1;
    int rc = connect(s, (sockaddr*)&addr, sizeof(addr));
    if (rc == 0) {
        result = 1;
    } else if (sockConnectPending()) {
        fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
        fd_set ef; FD_ZERO(&ef); FD_SET(s, &ef);
        timeval tv; tv.tv_sec = timeoutMs/1000; tv.tv_usec = (timeoutMs%1000)*1000;
        int sel = select((int)s + 1, nullptr, &wf, &ef, &tv);
        if (sel > 0 && FD_ISSET(s, &wf)) {
            int err = 0; socklen_t len = sizeof(err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
            result = (err == 0) ? 1 : 0;
        } else if (sel > 0 && FD_ISSET(s, &ef)) result = 0;
        else result = -1;
    } else {
        result = (WSAGetLastError() == WSAECONNREFUSED) ? 0 : -1;
    }

    if (result == 1) {
        if (connectMs) *connectMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::steady_clock::now() - t0).count();
        // вернём сокет в блокирующий и попробуем поймать баннер (SSH/FTP/SMTP говорят первыми)
        u_long bl = 0; ioctlsocket(s, FIONBIO, &bl);
        if (banner) {
            sockSetTimeoutMs(s, SO_RCVTIMEO, 600);
            // веб-порты сами не представляются — подтолкнём HEAD-запросом
            bool webPort = (port==80||port==8080||port==8000||port==8888||
                            port==443||port==8443||port==3000||port==5000);
            if (webPort) {
                std::string req = "HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n";
                send(s, req.c_str(), (int)req.size(), 0);
            }
            char buf[1024]; int n = recv(s, buf, sizeof(buf)-1, 0);
            if (n > 0) {
                buf[n] = 0; banner->assign(buf, n);
                while (!banner->empty() &&
                       (banner->back()=='\r'||banner->back()=='\n'||banner->back()==0))
                    banner->pop_back();
            }
        }
    }
    closesocket(s);
    return result;
}

static int tcpProbe(const std::string& ip, int port, int timeoutMs) {
    return tcpProbeBanner(ip, port, timeoutMs, nullptr, nullptr);
}

// UDP-handshake проба: шлём payload, ждём ЛЮБОЙ ответ в течение timeoutMs.
// Возвращает: 1=получен ответ (порт открыт/сервис живой), 0=нет ответа.
static int udpProbe(const std::string& ip, int port, const unsigned char* payload,
                    int payloadLen, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons((u_short)port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    sendto(s, (const char*)payload, payloadLen, 0, (sockaddr*)&addr, sizeof(addr));

    fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
    timeval tv; tv.tv_sec = timeoutMs/1000; tv.tv_usec = (timeoutMs%1000)*1000;
    int sel = select((int)s + 1, &rf, nullptr, nullptr, &tv);
    int got = 0;
    if (sel > 0 && FD_ISSET(s, &rf)) {
        char buf[1500]; sockaddr_in from{}; socklen_t fl = sizeof(from);
        int n = recvfrom(s, buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        if (n > 0) got = 1;
    }
    closesocket(s);
    return got;
}

// Собирает минимальный валидный TLS 1.2 ClientHello с указанным SNI.
// Именно по SNI в ClientHello фильтр ТСПУ решает блокировать (tspu-docs 17.5.3).
static int buildClientHelloSni(unsigned char* b, const std::string& host) {
    std::vector<unsigned char> ext;
    {   // расширение server_name (0x0000)
        std::vector<unsigned char> sni;
        unsigned hl = (unsigned)host.size();
        sni.push_back(0x00);                       // name_type = host_name
        sni.push_back((unsigned char)(hl>>8)); sni.push_back((unsigned char)(hl&0xFF));
        for (char c : host) sni.push_back((unsigned char)c);
        unsigned listLen = (unsigned)sni.size();
        ext.push_back(0x00); ext.push_back(0x00);  // ext type = server_name
        unsigned extDataLen = listLen + 2;
        ext.push_back((unsigned char)(extDataLen>>8)); ext.push_back((unsigned char)(extDataLen&0xFF));
        ext.push_back((unsigned char)(listLen>>8)); ext.push_back((unsigned char)(listLen&0xFF));
        for (auto x : sni) ext.push_back(x);
    }
    std::vector<unsigned char> ch;
    ch.push_back(0x03); ch.push_back(0x03);        // client_version TLS 1.2
    for (int i=0;i<32;i++) ch.push_back(rndByte()); // random
    ch.push_back(0x00);                            // session_id len = 0
    unsigned char cs[] = {0xc0,0x2b,0xc0,0x2f,0xc0,0x2c,0xc0,0x30,0x00,0x9e,0x00,0x9f,0x00,0x2f,0x00,0x35};
    unsigned csl = sizeof(cs);
    ch.push_back((unsigned char)(csl>>8)); ch.push_back((unsigned char)(csl&0xFF));
    for (unsigned i=0;i<csl;i++) ch.push_back(cs[i]);
    ch.push_back(0x01); ch.push_back(0x00);        // compression: null
    unsigned el = (unsigned)ext.size();
    ch.push_back((unsigned char)(el>>8)); ch.push_back((unsigned char)(el&0xFF));
    for (auto x : ext) ch.push_back(x);
    std::vector<unsigned char> hs;
    hs.push_back(0x01);                            // handshake type = ClientHello
    unsigned chl = (unsigned)ch.size();
    hs.push_back((unsigned char)(chl>>16)); hs.push_back((unsigned char)(chl>>8)); hs.push_back((unsigned char)(chl&0xFF));
    for (auto x : ch) hs.push_back(x);
    std::vector<unsigned char> rec;
    rec.push_back(0x16);                           // content type = handshake
    rec.push_back(0x03); rec.push_back(0x01);      // record version TLS 1.0
    unsigned hl2 = (unsigned)hs.size();
    rec.push_back((unsigned char)(hl2>>8)); rec.push_back((unsigned char)(hl2&0xFF));
    for (auto x : hs) rec.push_back(x);
    memcpy(b, rec.data(), rec.size());
    return (int)rec.size();
}

// Готовые handshake-payload'ы (идея из ByeByeVPN).
static void buildWireGuardInit(unsigned char* b) {
    // 148-байт MessageInitiation: type=1, reserved=0, остальное — случайные
    // (без валидных ключей сервер обычно не ответит, но WG-сканеры так и пробуют)
    memset(b, 0, 148);
    b[0] = 1;                       // message type = 1 (Handshake Initiation)
    b[1] = 0; b[2] = 0; b[3] = 0;   // reserved
    for (int i = 4; i < 148; i++) b[i] = rndByte();
}
static int buildIkeSaInit(unsigned char* b) {
    // минимальный ISAKMP/IKEv2 заголовок (28 байт): нули SPI, версия 2.0, тип SA_INIT
    memset(b, 0, 28);
    for (int i = 0; i < 8; i++) b[i] = rndByte(); // initiator SPI
    b[16] = 0x21;   // next payload = SA
    b[17] = 0x20;   // version 2.0
    b[18] = 0x22;   // exchange type = IKE_SA_INIT
    b[19] = 0x08;   // flags = initiator
    b[24]=0; b[25]=0; b[26]=0; b[27]=28; // length
    return 28;
}
static int buildDnsQuery(unsigned char* b) {
    // DNS-запрос A example.com
    static const unsigned char q[] = {
        0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        7,'e','x','a','m','p','l','e', 3,'c','o','m', 0, 0x00,0x01, 0x00,0x01
    };
    memcpy(b, q, sizeof(q));
    return (int)sizeof(q);
}
static int buildOpenVpnReset(unsigned char* b) {
    // OpenVPN HARD_RESET_CLIENT_V2 (opcode 0x38 = 7<<3): session id (8 байт,
    // случайный) + длина ACK-массива (0) + message packet-id (0). Случайный
    // байт на месте длины ACK делал пакет невалидным — сервер его молча дропал.
    b[0] = 0x38;
    for (int i = 1; i < 9; i++) b[i] = rndByte();
    b[9] = 0;                                   // ACK array length
    b[10] = b[11] = b[12] = b[13] = 0;          // packet-id = 0
    return 14;
}

// AmneziaWG: обфусцированный WireGuard с Sx=8 — 8 случайных junk-байт ПЕРЕД
// WG-заголовком, тип 0x01 смещён на offset 8. Vanilla-WG такой пакет дропнет
// (тип не на нулевом offset), AmneziaWG-листенер с 8-байтным префиксом — примет.
static int buildAmneziaWG(unsigned char* b) {
    memset(b, 0, 156);
    for (int i = 0; i < 8; i++) b[i] = rndByte(); // Sx=8 junk
    b[8] = 0x01;                                                       // WG init type
    for (int i = 12; i < 156; i++) b[i] = rndByte();
    return 156;
}

// Hysteria2 / любой QUIC: long-header Initial (тип 0xC0, 8-байт DCID, пустые
// SCID/token, length-varint), padding до 1200 байт (анти-амплификационный
// минимум). Версия — зарезервированная 0x?a?a?a?a (RFC 9000 §15): её не
// поддерживает никто, и сервер отвечает Version Negotiation (§6.1). С версией 1
// сервер пытался бы расшифровать пустой Initial, получал ошибку AEAD и молча
// дропал пакет — живой QUIC-порт выглядел как мёртвый. Мёртвый порт молчит.
static int buildHysteria2Quic(unsigned char* b) {
    memset(b, 0, 1200);
    static const unsigned char hdr[] = {
        0xC0,                         // long header, Initial
        0x1a, 0x2a, 0x3a, 0x4a,       // версия для принудительного Version Negotiation
        0x08,                         // DCID length
        0,0,0,0,0,0,0,0,              // DCID (рандомизируется ниже)
        0x00,                         // SCID length
        0x00,                         // token length
        0x44, 0x9E                    // length varint: 1182 = 1200 − 18 байт заголовка
    };
    memcpy(b, hdr, sizeof(hdr));
    for (int i = 6; i < 14; i++) b[i] = rndByte(); // random DCID
    return 1200;
}

void runPortScanMode() {
    ensureWsa();

    std::cout << "Скан портов с нашей машины.\nIP цели: " << std::flush;
    std::string ip; readLine(ip);
    ip = idnToAscii(trim(ip));
    if (!isValidIpv4Str(ip)) {
        // допускаем домен — резолвим
        if (looksLikeDomainStr(ip)) {
            std::string r = resolveHostToIp(ip);
            if (r.empty()) { std::cout << "Не удалось разрешить домен.\n"; return; }
            std::cout << ip << " -> " << r << "\n"; ip = r;
        } else { std::cout << "Неверный IP/домен.\n"; return; }
    }

    std::cout << "Диапазон портов: 'full' (1-65535), 'top' (частые),\n"
              << "  'service' (22,80,443,SSH/HTTP/почта/БД...), 'vpn' (VPN-порты),\n"
              << "  диапазон 1-1024 или список 80,443,8080: " << std::flush;
    std::string rng; readLine(rng);
    rng = trim(rng);

    // парсим режим портов
    std::vector<int> ports;
    std::string modeLabel;
    if (rng == "full" || rng == "FULL") {
        for (int p = 1; p <= 65535; p++) ports.push_back(p);
        modeLabel = "FULL 1-65535";
    } else if (rng == "service" || rng == "SERVICE" || rng == "serv") {
        // наборы портов — в конфиге (scan_service_ports / scan_vpn_ports / scan_top_ports)
        ports = cfg().scanServicePorts;
        modeLabel = "SERVICE (сервисные)";
    } else if (rng == "vpn" || rng == "VPN") {
        ports = cfg().scanVpnPorts;
        modeLabel = "VPN (туннельные)";
    } else if (rng == "top" || rng == "TOP" || rng.empty()) {
        ports = cfg().scanTopPorts;
        modeLabel = "TOP (частые)";
    } else if (rng.find('-') != std::string::npos && rng.find(',') == std::string::npos) {
        int a=0,b=0; sscanf(rng.c_str(), "%d-%d", &a, &b);
        if (a<1) a=1; if (b>65535) b=65535;
        if (a<=b) for (int p=a;p<=b;p++) ports.push_back(p);
        else { std::cout << "Пустой диапазон.\n"; return; }
        modeLabel = "диапазон " + rng;
    } else {
        std::stringstream ss(rng); std::string tok;
        while (std::getline(ss, tok, ',')) {
            int p = atoi(tok.c_str());
            if (p>=1 && p<=65535) ports.push_back(p);
        }
        modeLabel = "список";
    }
    if (ports.empty()) { std::cout << "Порты не заданы.\n"; return; }

    const int THREADS = 200;       // параллельных проб
    const int TCP_TO  = 800;       // таймаут на порт, мс

    printf("\n=================== СКАН ПОРТОВ (TCP) ===================\n");
    printf("Цель: %s\n", ip.c_str());
    printf("TCP-скан mode=%s  (%d портов, %d потоков, %dмс таймаут)\n",
           modeLabel.c_str(), (int)ports.size(), THREADS, TCP_TO);
    printf("  %s(Ctrl+C — прервать скан)%s\n", C::GRY, C::RST);

    // --- многопоточный TCP-скан с очередью и баннер-грабом ---
    struct OpenPort { int port; long long ms; std::string banner; };
    std::vector<OpenPort> openPorts;
    std::mutex mx;
    std::atomic<size_t> idx{0};
    std::atomic<int> done{0};
    std::atomic<size_t> tmo{0}, refused{0};
    g_traceAbort = false;             // Ctrl+C выставит этот флаг (см. ctrlHandler)

    auto worker = [&]{
        while (true) {
            if (g_traceAbort.load()) break;
            size_t i = idx.fetch_add(1);
            if (i >= ports.size()) break;
            long long ms=-1; std::string banner;
            int r = tcpProbeBanner(ip, ports[i], TCP_TO, &ms, &banner);
            int d = ++done;
            if (r == 0) ++refused; else if (r < 0) ++tmo;
            if (r == 1) { std::lock_guard<std::mutex> lk(mx);
                openPorts.push_back({ports[i], ms, banner}); }
            if (d % 20 == 0) {
                std::lock_guard<std::mutex> lk(mx);
                printf("\r  сканирую %d/%d  открыто=%d  ", d, (int)ports.size(), (int)openPorts.size());
                fflush(stdout);
            }
        }
    };
    int nthreads = std::max(1, std::min(THREADS, (int)ports.size()));
    std::vector<std::thread> th;
    for (int i=0;i<nthreads;i++) th.emplace_back(worker);
    for (auto& t : th) t.join();

    size_t scanned = std::min(idx.load(), ports.size());
    bool wasSkipped = (scanned < ports.size());
    if (wasSkipped)
        printf("\r  скан ПРЕРВАН на %d/%d (открыто=%d)            \n",
               (int)scanned, (int)ports.size(), (int)openPorts.size());
    else
        printf("\r  скан завершён (%d портов, открыто=%d)            \n",
               (int)ports.size(), (int)openPorts.size());

    std::sort(openPorts.begin(), openPorts.end(),
              [](const OpenPort&a, const OpenPort&b){ return a.port < b.port; });
    for (auto& o : openPorts) {
        const char* app = appByPort(o.port, "TCP");
        // если appByPort не знает — пробуем portService (шире покрытие сервисов)
        const char* svc = (app && app[0]) ? app : portService(o.port);
        printf("  %s:%-6d%s %lldms  %s", C::GRN, o.port, C::RST, o.ms, (svc && svc[0]) ? svc : "-");
        // приоритет: показываем сырой баннер; version detection — запасной
        // вариант, если баннер пуст/нечитаем (порт открылся, но сервис молчит).
        bool bannerShown = false;
        if (!o.banner.empty()) {
            std::string b; for (char c : o.banner) { if (c>=32 && c<127) b+=c; if (b.size()>=60) break; }
            if (!b.empty()) {
                printf("  %sbanner:%s %s", C::GRY, C::RST, b.c_str());
                bannerShown = true;
            }
        }
        if (!bannerShown) {
            std::string ver = parseServiceVersion(o.banner, o.port);
            if (!ver.empty()) {
                std::string vp; for (char c : ver) { if (c>=32 && c<127) vp+=c; if (vp.size()>=50) break; }
                printf("  %s[%s]%s", C::BWHT, vp.c_str(), C::RST);
            }
        }
        printf("\n");
    }
    printf("  итог: открыто=%d, закрыто(refused)=%d, без ответа(filtered)=%d\n",
           (int)openPorts.size(), (int)refused.load(), (int)tmo.load());

    int openCount = (int)openPorts.size();

    // --- TCP fingerprint: распределение времени рукопожатия по нижнему открытому порту ---
    if (!openPorts.empty() && !g_traceAbort.load()) {
        int fpPort = openPorts.front().port;
        std::vector<long long> hs;
        for (int k = 0; k < 6 && !g_traceAbort.load(); k++) {
            long long ms=-1;
            if (tcpProbeBanner(ip, fpPort, TCP_TO, &ms, nullptr) == 1 && ms >= 0) hs.push_back(ms);
        }
        if (hs.size() >= 2) {
            std::sort(hs.begin(), hs.end());
            long long med = hs[hs.size()/2], mn = hs.front(), mx2 = hs.back();
            double mean=0; for (long long v:hs) mean+=v; mean/=hs.size();
            double var=0; for (long long v:hs) var+=(v-mean)*(v-mean); var/=hs.size();
            double sd = std::sqrt(var);
            printf("\n%sTCP fingerprint (распределение рукопожатия)%s\n", C::BOLD, C::RST);
            printf("  handshake медиана=%lldms мин=%lldms макс=%lldms разброс=%.1fms (%d проб, порт %d)\n",
                   med, mn, mx2, sd, (int)hs.size(), fpPort);
            // таймаут — как у скана: на старых Windows отказ приходит через ~0,5 с
            int closedBehavior = tcpProbe(ip, 65000, TCP_TO);
            printf("  закрытый порт :65000 — %s\n",
                   closedBehavior==0 ? "RST (refused, обычный стек)"
                   : closedBehavior<0 ? "молчит (drop — фаервол/фильтр)" : "открыт?!");
        }
    }

    printf("\n%sГотово.%s TCP: %d открытых портов.\n", C::GRN, C::RST, openCount);
    printf("(скан с локальной машины; фаервол/NAT провайдера может влиять. "
           "UDP-пробы — отдельный режим 8)\n");
}

// ------------------------------------------------------------------
// РЕЖИМ 9: TSPU DPI Locator — поиск хопа, где фильтр режет по SNI.
// Идея (как в check-TSPU-block-traceroute): TCP-рукопожатие идёт с обычным
// TTL (SYN обязан дойти до сервера, иначе сессии нет и DPI нечего смотреть),
// а ClientHello с заблокированным SNI уходит с ограниченным TTL. Пока TTL не
// дотягивает до фильтра, CH умирает по дороге — тишина. С TTL, на котором CH
// проходит через фильтр, тот вбрасывает RST. Минимальный такой TTL = участок
// фильтра. Таймаут здесь — «не дошли», а не блокировка. Если фильтр режет
// дропом (без RST), TTL-метод хоп не различает: тишина с обеих сторон.
// Параллельно ICMP-traceroute сопоставляет TTL -> IP хопа.
// ------------------------------------------------------------------
// Возвращает IP хопа на заданном TTL (ICMP-проба с ограниченным TTL).
// Используется DPI-локатором для сопоставления TTL -> адрес узла.
static std::string icmpHopAtTtl(const std::string& targetIp, int ttl) {
#ifndef _WIN32
    IcmpReply ir = icmpEcho(targetIp, ttl, 1500, "hop");
    return ir.status >= 0 ? ir.from : std::string();
#else
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return "";
    IPAddr dest = inet_addr(targetIp.c_str());
    char sendData[8] = "hop";
    IP_OPTION_INFORMATION opt{}; opt.Ttl = (UCHAR)ttl;
    char replyBuf[sizeof(ICMP_ECHO_REPLY) + 64] = {0};
    std::string hop;
    DWORD r = IcmpSendEcho(hIcmp, dest, sendData, sizeof(sendData), &opt,
                           replyBuf, sizeof(replyBuf), 1500);
    if (r > 0) {
        ICMP_ECHO_REPLY* rep = (ICMP_ECHO_REPLY*)replyBuf;
        // при истечении TTL Status = IP_TTL_EXPIRED_TRANSIT, адрес = промежуточный узел
        struct in_addr a; a.s_addr = rep->Address;
        char buf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &a, buf, sizeof(buf));
        hop = buf;
    }
    IcmpCloseHandle(hIcmp);
    return hop;
#endif
}

// Результат одной TLS-пробы DPI-локатора.
enum class DpiProbe { NoTcp, SendFail, Reply, Reset, Closed, Timeout };

// TCP-рукопожатие с обычным TTL, затем TTL сокета снижается до ttl (0 — не
// трогать) и отправляется ClientHello. Ограничен только пакет с SNI.
static DpiProbe dpiTlsProbe(const std::string& ip, int port, const unsigned char* ch,
                            int chLen, int ttl, int timeoutMs) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return DpiProbe::NoTcp;
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons((u_short)port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    // неблокирующий connect с таймаутом; на Windows неудачный connect
    // сигналится через exceptfds, а не writefds
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    connect(s, (sockaddr*)&sa, sizeof(sa));
    fd_set wf, ef; FD_ZERO(&wf); FD_ZERO(&ef); FD_SET(s, &wf); FD_SET(s, &ef);
    timeval tv{}; tv.tv_sec = 2; tv.tv_usec = 0;
    int sel = select((int)s + 1, nullptr, &wf, &ef, &tv);
    if (sel <= 0 || !FD_ISSET(s, &wf)) { closesocket(s); return DpiProbe::NoTcp; }
    // на macOS неудачный connect тоже «готов к записи» — причина в SO_ERROR
    int cerr = 0; socklen_t clen = sizeof(cerr);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&cerr, &clen);
    if (cerr != 0) { closesocket(s); return DpiProbe::NoTcp; }
    nb = 0; ioctlsocket(s, FIONBIO, &nb);

    if (ttl > 0) {
        DWORD ttlv = (DWORD)ttl;
        setsockopt(s, IPPROTO_IP, IP_TTL, (char*)&ttlv, sizeof(ttlv));
    }
    sockSetTimeoutMs(s, SO_RCVTIMEO, timeoutMs);
    sockSetTimeoutMs(s, SO_SNDTIMEO, timeoutMs);

    DpiProbe r;
    if (send(s, (const char*)ch, chLen, 0) <= 0) r = DpiProbe::SendFail;
    else {
        char buf[512];
        int n = recv(s, buf, sizeof(buf), 0);
        if (n > 0) r = DpiProbe::Reply;
        else if (n == 0) r = DpiProbe::Closed;
        else r = (WSAGetLastError() == WSAECONNRESET) ? DpiProbe::Reset : DpiProbe::Timeout;
    }
    // abortive close: без этого стек продолжит ретрансмитить неподтверждённый CH
    linger lg{}; lg.l_onoff = 1; lg.l_linger = 0;
    setsockopt(s, SOL_SOCKET, SO_LINGER, (char*)&lg, sizeof(lg));
    closesocket(s);
    return r;
}

void runDpiLocatorMode() {
    ensureWsa();

    std::cout << "TSPU DPI Locator — поиск хопа, где режется по SNI.\n";
    std::cout << "Заблокированный домен (SNI), напр. rutracker.org: " << std::flush;
    std::string host; readLine(host);
    host = idnToAscii(trim(host));   // SNI — только ASCII (punycode)
    if (host.empty()) { std::cout << "Домен не задан.\n"; return; }
    // имя длиннее 253 символов невалидно и не влезло бы в буфер ClientHello ниже
    if (host.size() > 253) { std::cout << "Слишком длинный домен.\n"; return; }

    // целевой IP: можно ввести явно (IP сервера домена) или разрешить домен
    std::cout << "IP сервера (Enter — разрешить домен через DNS): " << std::flush;
    std::string ip; readLine(ip);
    ip = trim(ip);
    if (ip.empty()) {
        ip = resolveHostToIp(host);
        if (ip.empty()) { std::cout << "Не удалось разрешить домен.\n"; return; }
        std::cout << host << " -> " << ip << "\n";
    }
    if (!isValidIpv4Str(ip)) { std::cout << "Неверный IP.\n"; return; }

    // защита: если домен резолвится в приватный/заглушечный IP — это локальная
    // подмена DNS (антивирус/прокси/VPN-клиент), а НЕ реальный сервер. Диапазон
    // 198.18.0.0/15 (RFC 2544) часто используют локальные перехватчики.
    // (isPrivateIp уже покрывает 127/8 и 0/8)
    bool stubIp = isPrivateIp(ip) || ip.rfind("198.18.",0)==0 ||
                  ip.rfind("198.19.",0)==0;
    if (stubIp) {
        printf("\n%sВНИМАНИЕ: домен резолвится в %s — это локальная заглушка\n"
               "(антивирус/прокси/VPN-клиент перехватывает DNS), а НЕ настоящий\n"
               "сервер. Трассировка до неё бессмысленна — задайте реальный IP\n"
               "сервера вручную или отключите перехват DNS.%s\n",
               C::YEL, ip.c_str(), C::RST);
        std::cout << "Продолжить всё равно? [y/N]: " << std::flush;
        std::string yn; readLine(yn);
        if (!isYesAnswer(yn)) return;
    }

    const int PORT = 443;
    printf("\n=================== TSPU DPI LOCATOR ===================\n");
    printf("Домен (SNI): %s%s%s   Сервер: %s%s:%d%s\n",
           C::BWHT, host.c_str(), C::RST, C::BWHT, ip.c_str(), PORT, C::RST);
    printf("  %sМетод: TCP-рукопожатие с обычным TTL, затем ClientHello с растущим\n"
           "  TTL. Пока CH не доходит до фильтра — тишина; первый TTL, на котором\n"
           "  приходит RST, — участок фильтра.%s\n", C::GRY, C::RST);
    printf("  %s(Ctrl+C — прервать)%s\n\n", C::GRY, C::RST);
    g_traceAbort = false;

    unsigned char ch[1024], chCtl[1024];
    int chLen = buildClientHelloSni(ch, host);
    int chCtlLen = buildClientHelloSni(chCtl, "example.com");
    const int PROBE_TO = 2000;   // мс ожидания реакции на ClientHello в пошаговом замере

    auto probeName = [](DpiProbe r) -> const char* {
        switch (r) {
            case DpiProbe::NoTcp:    return "TCP не установился";
            case DpiProbe::SendFail: return "не удалось отправить CH";
            case DpiProbe::Reply:    return "ответ сервера";
            case DpiProbe::Reset:    return "RST после ClientHello";
            case DpiProbe::Closed:   return "обрыв (FIN) после CH";
            default:                 return "тишина";
        }
    };

    // 1) контроль: TCP и TLS до сервера вообще работают (нейтральный SNI, обычный TTL)
    DpiProbe ctl = dpiTlsProbe(ip, PORT, chCtl, chCtlLen, 0, 3000);
    printf("  Контроль, SNI example.com, полный TTL: %s\n", probeName(ctl));
    if (ctl == DpiProbe::NoTcp) {
        printf("\n%sTCP до %s:%d не устанавливается — сервер недоступен или блокировка\n"
               "по IP (режется SYN). SNI-локатор тут неприменим — нужна трассировка.%s\n",
               C::YEL, ip.c_str(), PORT, C::RST);
        return;
    }
    if (ctl != DpiProbe::Reply) {
        printf("\n%sСервер не отвечает на ClientHello даже с нейтральным SNI — на порту %d\n"
               "нет TLS или режется весь TLS к этому IP. Локализовать фильтр по SNI нельзя.%s\n",
               C::YEL, PORT, C::RST);
        return;
    }

    // 2) базовая проба: заблокированный SNI с обычным TTL — есть ли блокировка вообще
    DpiProbe base = dpiTlsProbe(ip, PORT, ch, chLen, 0, 3000);
    printf("  SNI %s, полный TTL: %s\n\n", host.c_str(), probeName(base));
    if (base == DpiProbe::Reply) {
        printf("=================== ВЫВОД ===================\n");
        printf("%sClientHello с SNI «%s» дошёл до сервера — блокировки по SNI "
               "на маршруте НЕ обнаружено.%s\n", C::GRN, host.c_str(), C::RST);
        return;
    }
    if (base == DpiProbe::Timeout) {
        printf("=================== ВЫВОД ===================\n");
        printf("%sС этим SNI сервер молчит, с нейтральным — отвечает: блокировка по SNI\n"
               "ЕСТЬ, но фильтр режет дропом (без RST).%s\n", C::RED, C::RST);
        printf("  TTL-методом хоп в этом случае не найти: «CH не дошёл до фильтра» и\n"
               "  «фильтр съел ответ» выглядят одинаково — тишиной.\n");
        return;
    }
    if (base != DpiProbe::Reset && base != DpiProbe::Closed) {
        printf("%sБазовая проба не удалась (%s) — возможно, фильтр временно\n"
               "заблокировал IP после контрольной пробы. Повторите позже.%s\n",
               C::YEL, probeName(base), C::RST);
        return;
    }

    // 3) поиск участка: CH с растущим TTL, первый RST = фильтр
    const int kMaxTtl = 30;   // не MAXTTL: это макрос из <netinet/ip.h> (macOS)
    int blockTtl = -1;          // TTL, на котором впервые пришёл RST
    std::string blockHop;       // ближайший видимый хоп на этом TTL
    bool reachedServer = false; // CH прошёл, и сервер ответил
    int noTcpStreak = 0;

    printf("  %-4s %-16s %-22s %s\n", "TTL", "ХОП (ICMP)", "TLS-РЕАКЦИЯ", "ВЕРДИКТ");
    for (int ttl = 1; ttl <= kMaxTtl && !g_traceAbort; ttl++) {
        std::string hopIp = icmpHopAtTtl(ip, ttl);
        DpiProbe r = dpiTlsProbe(ip, PORT, ch, chLen, ttl, PROBE_TO);

        const char* verdict = "?";
        const char* vcol = C::GRY;
        if (r == DpiProbe::Timeout) {
            verdict = "до фильтра";             // CH умер раньше, чем дошёл до DPI
        } else if (r == DpiProbe::Reset || r == DpiProbe::Closed) {
            verdict = "DPI!"; vcol = C::RED;
            blockTtl = ttl; blockHop = hopIp;
        } else if (r == DpiProbe::Reply) {
            verdict = "ПРОШЛО"; vcol = C::GRN;
            reachedServer = true;
        }
        noTcpStreak = (r == DpiProbe::NoTcp) ? noTcpStreak + 1 : 0;

        printf("  %-4d %s%-16s%s %-22s %s%s%s\n",
               ttl, C::CYN, hopIp.empty()?"*":hopIp.c_str(), C::RST,
               probeName(r), vcol, verdict, C::RST);

        if (blockTtl > 0 || reachedServer || noTcpStreak >= 3) break;
        // ICMP уже дошёл до самого сервера — CH с этим TTL тоже до него доставал,
        // наращивать дальше бессмысленно
        if (hopIp == ip && r == DpiProbe::Timeout) break;
    }

    printf("\n=================== ВЫВОД ===================\n");
    if (g_traceAbort) { printf("%sПрервано.%s\n", C::YEL, C::RST); g_traceAbort=false; return; }
    if (blockTtl > 0) {
        printf("%sDPI-фильтр срабатывает на TTL=%d", C::RED, blockTtl);
        if (!blockHop.empty()) printf(" (хоп %s)", blockHop.c_str());
        printf(".%s\n", C::RST);
        if (blockHop == ip) {
            // RST появился, лишь когда CH доставал до самого сервера
            printf("  RST пришёл, только когда ClientHello дошёл до самого сервера:\n"
                   "  это либо фильтр вплотную к серверу, либо сам сервер не обслуживает\n"
                   "  этот SNI. TTL-методом их не отличить.\n");
        } else {
            // Локализуем УЧАСТОК, а не устройство: сам фильтр прозрачен на L2 и хопом
            // не отображается, поэтому blockHop — это ближайший видимый маршрутизатор,
            // ответивший на данном TTL, а фильтр стоит где-то за ним.
            printf("  Соединение с SNI «%s» обрывается на этом участке маршрута.\n"
                   "  Фильтр стоит не дальше него — но сам он в трассировке не виден\n"
                   "  (L2, без IP в тракте данных), так что хоп выше — лишь ориентир.\n",
                   host.c_str());
        }
    } else if (reachedServer) {
        printf("%sНа этот раз ClientHello с SNI «%s» дошёл до сервера, хотя с полным\n"
               "TTL соединение рвалось, — блокировка нестабильна (балансировка, разные\n"
               "маршруты или фильтр срабатывает не на каждую сессию).%s\n",
               C::YEL, host.c_str(), C::RST);
    } else if (noTcpStreak >= 3) {
        printf("%sTCP до сервера перестал устанавливаться посреди замера — вероятно,\n"
               "фильтр временно заблокировал IP после срабатывания. Повторите позже.%s\n",
               C::YEL, C::RST);
    } else {
        printf("%sС полным TTL соединение рвётся, но при пошаговом TTL RST не\n"
               "воспроизвёлся — фильтр реагирует нестабильно. Повторите замер.%s\n",
               C::YEL, C::RST);
    }
    printf("  %sПрим.: метод активный (шлёт реальный трафик). TTL-хоп DPI может\n"
           "  отличаться от ICMP-хопа на 1 из-за асимметрии маршрутов.%s\n", C::GRY, C::RST);
}

// ------------------------------------------------------------------
// РЕЖИМ 8: активные UDP-handshake пробы (WireGuard/IKE/OpenVPN/DNS).
// ------------------------------------------------------------------
void runUdpProbeMode() {
    ensureWsa();

    std::cout << "UDP handshake-пробы.\nIP цели: " << std::flush;
    std::string ip; readLine(ip);
    ip = idnToAscii(trim(ip));
    if (!isValidIpv4Str(ip)) {
        if (looksLikeDomainStr(ip)) {
            std::string r = resolveHostToIp(ip);
            if (r.empty()) { std::cout << "Не удалось разрешить домен.\n"; return; }
            std::cout << ip << " -> " << r << "\n"; ip = r;
        } else { std::cout << "Неверный IP/домен.\n"; return; }
    }

    std::cout << "Порты (список 51820,500,1194,53 или 'vpn' для типичных VPN): " << std::flush;
    std::string rng; readLine(rng);
    rng = trim(rng);

    std::vector<int> ports;
    if (rng == "vpn" || rng == "VPN" || rng.empty()) {
        int vpn[] = {51820,51821,55555,2408,1637,500,4500,1194,1195,36712,1935,443,53};
        for (int p : vpn) ports.push_back(p);
    } else {
        std::stringstream ss(rng); std::string tok;
        while (std::getline(ss, tok, ',')) {
            int p = atoi(tok.c_str());
            if (p>=1 && p<=65535) ports.push_back(p);
        }
    }
    if (ports.empty()) { std::cout << "Порты не заданы.\n"; return; }

    printf("\n=================== UDP HANDSHAKE-ПРОБЫ ===================\n");
    printf("Цель: %s\n", ip.c_str());
    printf("  %s(Ctrl+C — прервать)%s\n\n", C::GRY, C::RST);

    g_traceAbort = false;
    unsigned char buf[1300];
    bool anyUdp = false;

    for (int p : ports) {
        if (g_traceAbort.load()) { printf("(прервано)\n"); break; }

        // выбор проб по порту
        std::vector<const char*> kinds;
        if (p==51820 || p==51821) { kinds = {"WireGuard", "AmneziaWG"}; }
        else if (p==55555)        { kinds = {"AmneziaWG", "WireGuard"}; }
        else if (p==2408 || p==1637) { kinds = {"WireGuard(WARP)"}; }
        else if (p==36712 || p==1935) { kinds = {"Hysteria2 QUIC"}; }
        else if (p==443)          { kinds = {"Hysteria2 QUIC"}; }
        else if (p==500 || p==4500) { kinds = {"IKE/IPsec"}; }
        else if (p==1194 || p==1195) { kinds = {"OpenVPN"}; }
        else if (p==53)           { kinds = {"DNS"}; }
        else                      { kinds = {"WireGuard", "Hysteria2 QUIC", "DNS"}; }

        for (const char* kind : kinds) {
            if (g_traceAbort.load()) break;
            int len = 0;
            std::string k = kind;
            if (k.rfind("WireGuard",0)==0)      { buildWireGuardInit(buf); len=148; }
            else if (k=="AmneziaWG")            { len=buildAmneziaWG(buf); }
            else if (k.rfind("Hysteria2",0)==0) { len=buildHysteria2Quic(buf); }
            else if (k=="IKE/IPsec")            { len=buildIkeSaInit(buf); }
            else if (k=="OpenVPN")              { len=buildOpenVpnReset(buf); }
            else if (k=="DNS")                  { len=buildDnsQuery(buf); }
            else                                { len=buildDnsQuery(buf); }

            int got = udpProbe(ip, p, buf, len, 1200);
            if (got) {
                printf("  UDP:%-6d %s%-16s%s %sОТВЕТ — сервис активен%s\n",
                       p, C::BWHT, kind, C::RST, C::GRN, C::RST);
                anyUdp = true;
            } else {
                printf("  UDP:%-6d %-16s %sтихо (no-reply / filtered)%s\n",
                       p, kind, C::GRY, C::RST);
            }
        }
    }

    printf("\n%sГотово.%s ОТВЕТ = сервис подтверждён живым.\n", C::GRN, C::RST);
    if (!anyUdp)
        printf("%sНи один порт не ответил. Для WireGuard/AmneziaWG это норма "
               "(молчат без валидного ключа) — тишина не значит отсутствие. "
               "Ответ = точное подтверждение.%s\n", C::GRY, C::RST);
}

// ==================================================================
// Общие мелочи для режимов 11/12
// ==================================================================

static std::vector<std::string> splitInput(const std::string& s) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == ',' || c == ';' || c == ' ') { cur = trim(cur); if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    cur = trim(cur); if (!cur.empty()) out.push_back(cur);
    return out;
}

static std::string joinIps(const std::vector<std::string>& v, size_t maxShow = 3) {
    std::string s;
    for (size_t i = 0; i < v.size() && i < maxShow; i++) { if (i) s += ", "; s += v[i]; }
    if (v.size() > maxShow) s += " (+" + std::to_string(v.size() - maxShow) + ")";
    return s;
}

// ==================================================================
// РЕЖИМ 11: честность DNS.
// Один и тот же домен спрашиваем у системного резолвера, у DNS провайдера
// напрямую (UDP), у публичных резолверов (UDP) и через DoH (HTTPS — его
// ТСПУ не подменяет, это эталон). Расхождения показывают, кто врёт:
//   - адрес-заглушка (частный / 0.0.0.0 / 127.x / одинаковый для разных сайтов);
//   - NXDOMAIN там, где DoH видит адреса — подмена ответа;
//   - два разных ответа на один запрос — DPI вбрасывает свой ответ быстрее
//     настоящего;
//   - UDP-запрос к 8.8.8.8 и т.п. тихо перехвачен и обслужен чужим
//     резолвером (проверка по o-o.myaddr.l.google.com: TXT-ответ содержит
//     IP, с которого резолвер ходил к авторитетному серверу Google).
// ==================================================================

struct DnsAns {
    bool got = false;
    int rcode = -1;                 // 0 = NOERROR, 3 = NXDOMAIN, ...
    std::vector<std::string> a;     // A-записи (отсортированы)
    std::vector<std::string> txt;   // TXT-записи
};

struct DnsProbe {
    DnsAns first;                   // первый пришедший ответ
    DnsAns second;                  // второй, ОТЛИЧАЮЩИЙСЯ ответ (если был)
    bool twoDifferent = false;
    int ms = -1;                    // время до первого ответа
};

static int buildDnsQueryFor(unsigned char* b, int cap, const std::string& nameIn,
                            uint16_t id, uint16_t qtype) {
    std::string name = nameIn;
    while (!name.empty() && name.back() == '.') name.pop_back();
    if (name.empty() || (int)name.size() + 18 > cap) return 0;
    int p = 0;
    b[p++] = (unsigned char)(id >> 8); b[p++] = (unsigned char)(id & 0xFF);
    b[p++] = 0x01; b[p++] = 0x00;           // RD = 1
    b[p++] = 0; b[p++] = 1;                 // QDCOUNT = 1
    b[p++] = 0; b[p++] = 0; b[p++] = 0; b[p++] = 0; b[p++] = 0; b[p++] = 0;
    size_t s = 0;
    while (s < name.size()) {
        size_t d = name.find('.', s);
        if (d == std::string::npos) d = name.size();
        size_t L = d - s;
        if (L == 0 || L > 63) return 0;
        b[p++] = (unsigned char)L;
        memcpy(b + p, name.data() + s, L); p += (int)L;
        s = d + 1;
    }
    b[p++] = 0;
    b[p++] = (unsigned char)(qtype >> 8); b[p++] = (unsigned char)(qtype & 0xFF);
    b[p++] = 0; b[p++] = 1;                 // QCLASS IN
    return p;
}

static bool dnsSkipName(const unsigned char* b, int n, int& p) {
    while (p < n) {
        unsigned char l = b[p];
        if (l == 0) { p++; return true; }
        if ((l & 0xC0) == 0xC0) { if (p + 1 >= n) return false; p += 2; return true; }
        if (l & 0xC0) return false;
        p += 1 + l;
    }
    return false;
}

static bool parseDnsResp(const unsigned char* b, int n, uint16_t id, DnsAns& r) {
    if (n < 12) return false;
    if ((uint16_t)((b[0] << 8) | b[1]) != id) return false;
    if (!(b[2] & 0x80)) return false;       // не ответ
    r.rcode = b[3] & 0x0F;
    int qd = (b[4] << 8) | b[5];
    int an = (b[6] << 8) | b[7];
    int p = 12;
    for (int i = 0; i < qd; i++) { if (!dnsSkipName(b, n, p)) return false; p += 4; }
    for (int i = 0; i < an; i++) {
        if (!dnsSkipName(b, n, p) || p + 10 > n) break;
        int type  = (b[p] << 8) | b[p + 1];
        int rdlen = (b[p + 8] << 8) | b[p + 9];
        p += 10;
        if (p + rdlen > n) break;
        if (type == 1 && rdlen == 4) {
            char s[16];
            snprintf(s, sizeof(s), "%u.%u.%u.%u", b[p], b[p+1], b[p+2], b[p+3]);
            r.a.push_back(s);
        } else if (type == 16) {
            std::string t;
            int q = p, end = p + rdlen;
            while (q < end) {
                int l = b[q++];
                if (q + l > end) break;
                t.append((const char*)b + q, l); q += l;
            }
            r.txt.push_back(t);
        }
        p += rdlen;
    }
    std::sort(r.a.begin(), r.a.end());
    r.got = true;
    return true;
}

// UDP-запрос к серверу server:53. После первого ответа ещё ~400 мс слушаем
// сокет: если придёт второй ответ с тем же id, но другим содержимым — ответ
// вбрасывается «по пути» (DPI успевает раньше настоящего резолвера).
static DnsProbe udpDnsQuery(const std::string& server, const std::string& name,
                            uint16_t qtype, int timeoutMs) {
    static std::atomic<unsigned> ctr{(unsigned)GetTickCount()};
    DnsProbe r;
    unsigned char q[512];
    uint16_t id = (uint16_t)((ctr.fetch_add(1) * 2654435761u) >> 16);
    int len = buildDnsQueryFor(q, sizeof(q), name, id, qtype);
    if (!len) return r;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return r;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(53);
    inet_pton(AF_INET, server.c_str(), &addr.sin_addr);
    auto t0 = std::chrono::steady_clock::now();
    sendto(s, (const char*)q, len, 0, (sockaddr*)&addr, sizeof(addr));
    auto deadline = t0 + std::chrono::milliseconds(timeoutMs);
    bool haveFirst = false;
    for (;;) {
        long long left = std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) break;
        fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
        timeval tv; tv.tv_sec = (long)(left / 1000); tv.tv_usec = (long)((left % 1000) * 1000);
        if (select((int)s + 1, &rf, nullptr, nullptr, &tv) <= 0) break;
        unsigned char buf[4096]; sockaddr_in from{}; socklen_t fl = sizeof(from);
        int n = recvfrom(s, (char*)buf, sizeof(buf), 0, (sockaddr*)&from, &fl);
        if (n <= 0) break;
        DnsAns a;
        if (!parseDnsResp(buf, n, id, a)) continue;
        if (!haveFirst) {
            haveFirst = true;
            r.first = a;
            r.ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();
            deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(400);
        } else if (a.rcode != r.first.rcode || a.a != r.first.a) {
            r.second = a; r.twoDifferent = true;
            break;
        }
    }
    closesocket(s);
    return r;
}

// DNS-серверы, выданные системе (DHCP / настройки адаптера).
static std::vector<std::string> systemDnsServers() {
    std::vector<std::string> out;
#ifndef _WIN32
    // macOS: /etc/resolv.conf ведёт configd — там серверы основного интерфейса
    std::ifstream f("/etc/resolv.conf");
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream ls(line);
        std::string kw, s;
        if (!(ls >> kw >> s) || kw != "nameserver") continue;
        if (isValidIpv4Str(s) && s != "0.0.0.0" &&
            std::find(out.begin(), out.end(), s) == out.end())
            out.push_back(s);
    }
    return out;
#else
    ULONG sz = 0;
    GetNetworkParams(nullptr, &sz);
    if (!sz) sz = sizeof(FIXED_INFO);
    std::vector<char> buf(sz);
    FIXED_INFO* fi = (FIXED_INFO*)buf.data();
    if (GetNetworkParams(fi, &sz) != NO_ERROR) return out;
    for (IP_ADDR_STRING* a = &fi->DnsServerList; a; a = a->Next) {
        std::string s = a->IpAddress.String;
        if (isValidIpv4Str(s) && s != "0.0.0.0" &&
            std::find(out.begin(), out.end(), s) == out.end())
            out.push_back(s);
    }
    return out;
#endif
}

// Системный резолвер (getaddrinfo, с кешем Windows).
// 0 = адреса есть, 1 = NXDOMAIN / нет A-записей, 2 = ошибка/таймаут.
static int sysResolveAll(const std::string& name, std::vector<std::string>& ips) {
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(name.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) return (rc == EAI_NONAME || rc == WSANO_DATA) ? 1 : 2;
    for (addrinfo* p = res; p; p = p->ai_next) {
        char b[64] = {0};
        inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, b, sizeof(b));
        if (std::find(ips.begin(), ips.end(), b) == ips.end()) ips.push_back(b);
    }
    freeaddrinfo(res);
    std::sort(ips.begin(), ips.end());
    return 0;
}

struct DohRes { bool ok = false; int status = -1; std::vector<std::string> ips; };

// DoH (JSON API) — Google или Cloudflare. HTTPS, поэтому ТСПУ ответ не подменит
// (может только заблокировать сам DoH — тогда ok=false).
static DohRes dohResolve(bool cloudflare, const std::string& name) {
    DohRes d;
    std::wstring path = std::wstring(cloudflare ? L"/dns-query?name=" : L"/resolve?name=")
                        + u8w(name) + L"&type=A";
    std::string r = cloudflare
        ? httpsGet(L"cloudflare-dns.com", path, L"accept: application/dns-json\r\n")
        : httpsGet(L"dns.google", path);
    size_t sp = r.find("\"Status\"");
    if (sp == std::string::npos) return d;
    sp += 8;
    while (sp < r.size() && (r[sp] == ':' || r[sp] == ' ')) sp++;
    // не число — ответ битый; atoi дал бы 0, т.е. «NOERROR» на пустом месте
    if (sp >= r.size() || !isdigit((unsigned char)r[sp])) return d;
    d.status = atoi(r.c_str() + sp);
    d.ok = true;
    size_t p = 0;
    while ((p = r.find("\"data\"", p)) != std::string::npos) {
        p += 6;
        while (p < r.size() && (r[p] == ':' || r[p] == ' ')) p++;
        if (p >= r.size() || r[p] != '"') continue;
        size_t e = r.find('"', p + 1);
        if (e == std::string::npos) break;
        std::string v = r.substr(p + 1, e - p - 1);
        if (isValidIpv4Str(v) && std::find(d.ips.begin(), d.ips.end(), v) == d.ips.end())
            d.ips.push_back(v);
        p = e + 1;
    }
    std::sort(d.ips.begin(), d.ips.end());
    return d;
}

static bool isStubAddr(const std::string& ip) {
    return ip.rfind("0.", 0) == 0 || ip.rfind("127.", 0) == 0 || isPrivateIp(ip);
}

// Ответ одного резолвера на один домен + вердикт.
struct DnsResolverAns {
    std::string label;              // «система», «DNS 10.0.0.1», «8.8.8.8 (UDP)» ...
    bool viaUdp = true;
    DnsProbe probe;                 // для UDP
    int sysRc = -1;                 // для системного резолвера
    std::vector<std::string> ips;
    int sev = 0;                    // 0 ок, 1 мягко (другие адреса), 2 плохо
    std::string verdict;
};

struct DnsDomainRes {
    std::string name;
    bool control = false;
    DohRes dohG, dohC;
    std::vector<std::string> ref;   // эталонные адреса (DoH)
    bool refOk = false, refNx = false;
    std::vector<DnsResolverAns> rs;
};

void runDnsHonestyMode() {
    ensureWsa();

    static const char* kControl[] = { "example.com", "ya.ru", "gosuslugi.ru" };
    static const char* kTest[] = { "rutracker.org", "linkedin.com", "instagram.com",
        "facebook.com", "x.com", "torproject.org", "protonvpn.com", "nnmclub.to", "kinozal.tv" };

    std::cout << "Проверка честности DNS.\n"
                 "Домены через запятую (Enter — стандартный набор: контрольные + "
                 "часто блокируемые): " << std::flush;
    std::string line; readLine(line);
    line = trim(line);

    std::vector<DnsDomainRes> doms;
    if (line.empty()) {
        for (const char* d : kControl) { DnsDomainRes r; r.name = d; r.control = true; doms.push_back(r); }
        for (const char* d : kTest)    { DnsDomainRes r; r.name = d; doms.push_back(r); }
    } else {
        // контрольный домен нужен, чтобы отличить «DNS врёт» от «DNS не работает»
        DnsDomainRes c; c.name = "example.com"; c.control = true; doms.push_back(c);
        for (auto& d : splitInput(line)) {
            std::string n = idnToAscii(d);
            for (auto& ch : n) ch = (char)tolower((unsigned char)ch);
            if (!looksLikeDomainStr(n)) { printf("  %sпропуск «%s» — не домен%s\n", C::GRY, d.c_str(), C::RST); continue; }
            if (n == "example.com") continue;
            DnsDomainRes r; r.name = n; doms.push_back(r);
            if (doms.size() >= 30) break;
        }
        if (doms.size() < 2) { std::cout << "Домены не заданы.\n"; return; }
    }

    std::vector<std::string> sysDns = systemDnsServers();
    static const char* kPublic[] = { "8.8.8.8", "1.1.1.1", "9.9.9.9" };

    printf("\n=================== ЧЕСТНОСТЬ DNS ===================\n");
    printf("DNS системы: %s%s%s\n", C::BWHT,
           sysDns.empty() ? "не найдены" : joinIps(sysDns, 4).c_str(), C::RST);
    printf("Эталон: DoH (dns.google, cloudflare-dns.com) — HTTPS, ТСПУ его не подменяет.\n");
    printf("%sОпрашиваю %zu доменов...%s\n\n", C::GRY, doms.size(), C::RST);

    g_traceAbort = false;

    // --- опрос: домены параллельно, внутри домена — последовательно ---
    {
        std::vector<std::thread> th;
        for (size_t i = 0; i < doms.size(); i++) {
            th.emplace_back([&, i]() {
                DnsDomainRes& d = doms[i];
                d.dohG = dohResolve(false, d.name);
                d.dohC = dohResolve(true, d.name);
                for (const DohRes* x : { &d.dohG, &d.dohC }) {
                    if (!x->ok) continue;
                    d.refOk = true;
                    if (x->status == 3) d.refNx = true;
                    for (auto& ip : x->ips)
                        if (std::find(d.ref.begin(), d.ref.end(), ip) == d.ref.end()) d.ref.push_back(ip);
                }
                if (!d.ref.empty()) d.refNx = false;

                DnsResolverAns sr; sr.label = "система (кеш Windows)"; sr.viaUdp = false;
                sr.sysRc = sysResolveAll(d.name, sr.ips);
                d.rs.push_back(sr);
                for (auto& s : sysDns) {
                    DnsResolverAns a; a.label = "DNS " + s;
                    a.probe = udpDnsQuery(s, d.name, 1, 2500);
                    a.ips = a.probe.first.a;
                    d.rs.push_back(a);
                }
                for (const char* s : kPublic) {
                    DnsResolverAns a; a.label = std::string(s) + " (UDP)";
                    a.probe = udpDnsQuery(s, d.name, 1, 2500);
                    a.ips = a.probe.first.a;
                    d.rs.push_back(a);
                }
            });
        }
        for (auto& t : th) t.join();
    }

    // Адрес, который один и тот же резолвер вернул для 2+ НЕСВЯЗАННЫХ доменов и
    // которого нет в эталоне, — типичная заглушка провайдера. Несвязанные — их
    // эталонные (DoH) адреса не пересекаются даже по /16 (IPv6 — по /32). Иначе
    // facebook.com и instagram.com (обе в сети Meta), сайты за одним CDN или
    // кеш-узел CDN у провайдера (FNA, GGC), законно отдающий один адрес на
    // несколько доменов, получали красное «ЗАГЛУШКА».
    auto netOf = [](const std::string& ip) -> std::string {
        unsigned char b[16];
        if (inet_pton(AF_INET, ip.c_str(), b) == 1)
            return std::to_string(b[0]) + "." + std::to_string(b[1]);
        if (inet_pton(AF_INET6, ip.c_str(), b) == 1) {
            char s[16];
            snprintf(s, sizeof(s), "%02x%02x:%02x%02x", b[0], b[1], b[2], b[3]);
            return s;
        }
        return ip;
    };
    std::vector<std::set<std::string>> refNets(doms.size());
    for (size_t i = 0; i < doms.size(); i++)
        for (auto& ip : doms[i].ref) refNets[i].insert(netOf(ip));
    // без эталона связь доменов неизвестна — такой домен заглушку не доказывает
    auto unrelated = [&](size_t x, size_t y) {
        if (refNets[x].empty() || refNets[y].empty()) return false;
        for (auto& n : refNets[x]) if (refNets[y].count(n)) return false;
        return true;
    };
    std::map<std::string, std::map<std::string, std::vector<size_t>>> ipDoms;   // label -> ip -> домены
    for (size_t i = 0; i < doms.size(); i++)
        for (auto& r : doms[i].rs)
            for (auto& ip : r.ips)
                if (std::find(doms[i].ref.begin(), doms[i].ref.end(), ip) == doms[i].ref.end()) {
                    auto& v = ipDoms[r.label][ip];
                    if (v.empty() || v.back() != i) v.push_back(i);
                }
    std::map<std::string, std::set<std::string>> sharedStub;   // label -> адреса-заглушки
    for (auto& byLabel : ipDoms)
        for (auto& ipv : byLabel.second) {
            const auto& v = ipv.second;
            bool stub = false;
            for (size_t x = 0; x < v.size() && !stub; x++)
                for (size_t y = x + 1; y < v.size() && !stub; y++)
                    stub = unrelated(v[x], v[y]);
            if (stub) sharedStub[byLabel.first].insert(ipv.first);
        }

    // --- вердикты ---
    std::set<std::string> foreignIps;   // «другие адреса» — покажем владельца
    for (auto& d : doms) {
        for (auto& r : d.rs) {
            bool nx, noAns;
            if (r.viaUdp) {
                nx = r.probe.first.got && r.probe.first.rcode == 3;
                noAns = !r.probe.first.got;
            } else {
                nx = r.sysRc == 1;
                noAns = r.sysRc == 2;
            }
            std::string stub;
            for (auto& ip : r.ips) if (isStubAddr(ip)) { stub = ip; break; }
            std::string shared;
            for (auto& ip : r.ips) if (sharedStub[r.label].count(ip)) { shared = ip; break; }
            bool overlap = false;
            for (auto& ip : r.ips)
                if (std::find(d.ref.begin(), d.ref.end(), ip) != d.ref.end()) { overlap = true; break; }

            if (r.viaUdp && r.probe.twoDifferent) {
                r.sev = 2;
                r.verdict = "ДВА РАЗНЫХ ОТВЕТА — ответ вбрасывает DPI по пути (второй: " +
                    (r.probe.second.a.empty()
                        ? std::string(r.probe.second.rcode == 3 ? "NXDOMAIN" : "без адресов")
                        : joinIps(r.probe.second.a, 2)) + ")";
            } else if (!stub.empty()) {
                r.sev = 2; r.verdict = "ЗАГЛУШКА — адрес " + stub;
            } else if (nx && !d.ref.empty()) {
                r.sev = 2; r.verdict = "NXDOMAIN, хотя домен существует — подмена ответа";
            } else if (noAns && (!d.ref.empty() || d.refNx)) {
                r.sev = 2; r.verdict = "нет ответа — запрос/ответ дропается";
            } else if (!shared.empty() && !d.ref.empty() && !overlap) {
                r.sev = 2; r.verdict = "ЗАГЛУШКА — " + shared + " выдаётся для разных сайтов";
            } else if (!r.ips.empty() && !d.ref.empty() && !overlap) {
                r.sev = 1; r.verdict = "другие адреса, чем у DoH (CDN/гео или подмена)";
                for (auto& ip : r.ips) foreignIps.insert(ip);
            } else if (nx && d.refNx) {
                r.sev = 0; r.verdict = "NXDOMAIN (домена нет и по DoH)";
            } else if (nx && !d.refOk) {
                r.sev = 1; r.verdict = "NXDOMAIN (эталона нет — DoH недоступен)";
            } else if (noAns) {
                r.sev = 1; r.verdict = "нет ответа (эталон тоже недоступен)";
            } else {
                r.sev = 0; r.verdict = "ок";
            }
        }
    }

    // --- перехват UDP:53: кто на самом деле ходит к авторитетному серверу ---
    struct Egress { std::string server, label, ip; std::vector<const char*> expect; };
    std::vector<Egress> eg;
    eg.push_back({ "8.8.8.8", "8.8.8.8", "", { "google", "as15169" } });
    eg.push_back({ "1.1.1.1", "1.1.1.1", "", { "cloudflare", "as13335" } });
    eg.push_back({ "9.9.9.9", "9.9.9.9", "", { "quad9", "as19281", "woodynet", "packet clearing", "as3856" } });
    for (auto& s : sysDns) eg.push_back({ s, "DNS " + s + " (системный)", "", {} });
    {
        std::vector<std::thread> et;
        for (auto& e : eg)
            et.emplace_back([&e]() {
                DnsProbe p = udpDnsQuery(e.server, "o-o.myaddr.l.google.com", 16, 3000);
                // резолвер мог сходить к Google и по IPv6 — это тоже адрес выхода
                // (вторая TXT-запись «edns0-client-subnet …» не адрес — пропускаем)
                for (auto& t : p.first.txt) {
                    in6_addr a6;
                    if (isValidIpv4Str(t) || inet_pton(AF_INET6, t.c_str(), &a6) == 1) { e.ip = t; break; }
                }
            });
        for (auto& t : et) t.join();
    }

    std::unordered_map<std::string, IpInfo> info;
    {
        std::vector<std::string> q;
        for (auto& e : eg) if (!e.ip.empty()) q.push_back(e.ip);
        for (auto& ip : foreignIps) if (q.size() < 90 && !isStubAddr(ip)) q.push_back(ip);
        if (!q.empty()) resolveIps(q, info);
        printf("\n");
    }
    auto ownerOf = [&](const std::string& ip) -> std::string {
        auto it = info.find(ip);
        if (it == info.end()) return "";
        std::string s = it->second.asn != "-" ? it->second.asn : "";
        if (it->second.org != "-") s += (s.empty() ? "" : " ") + it->second.org;
        return s;
    };

    // --- вывод по доменам ---
    int bad = 0, soft = 0, badCtl = 0;
    for (auto& d : doms) {
        int worst = 0;
        for (auto& r : d.rs) worst = std::max(worst, r.sev);
        if (worst == 2) { bad++; if (d.control) badCtl++; }
        else if (worst == 1) soft++;
        const char* col = worst == 2 ? C::RED : worst == 1 ? C::YEL : C::GRN;
        printf("%s%s%s%s  %s\n", C::BOLD, col, d.name.c_str(), C::RST,
               d.control ? "[контрольный]" : "");
        std::string refTxt = !d.refOk ? "DoH недоступен — эталона нет"
                           : d.refNx ? "NXDOMAIN" : joinIps(d.ref);
        printf("    %s: %s%s%s\n", u8pad("эталон DoH", 22).c_str(), C::CYN, refTxt.c_str(), C::RST);
        for (auto& r : d.rs) {
            std::string val;
            if (r.viaUdp) {
                if (!r.probe.first.got) val = "—";
                else if (r.probe.first.rcode == 3) val = "NXDOMAIN";
                else if (r.probe.first.rcode != 0) val = "rcode " + std::to_string(r.probe.first.rcode);
                else val = r.ips.empty() ? "(пусто)" : joinIps(r.ips);
                if (r.probe.ms >= 0) val += "  " + std::to_string(r.probe.ms) + " мс";
            } else {
                val = r.sysRc == 1 ? "NXDOMAIN" : r.sysRc == 2 ? "—" : joinIps(r.ips);
            }
            const char* vc = r.sev == 2 ? C::RED : r.sev == 1 ? C::YEL : C::GRY;
            std::string owner;
            if (r.sev == 1 && !r.ips.empty()) {
                std::string o = ownerOf(r.ips[0]);
                if (!o.empty()) owner = " [" + o + "]";
            }
            printf("    %s: %s  %s%s%s%s\n", u8pad(r.label, 22).c_str(), val.c_str(),
                   vc, r.verdict.c_str(), owner.c_str(), C::RST);
        }
        printf("\n");
    }

    // --- перехват ---
    printf("%s--- Перехват DNS (кто реально ходит к авторитетному серверу) ---%s\n", C::BCYN, C::RST);
    bool intercepted = false;
    std::string sysEgressOwner;
    for (auto& e : eg) if (e.expect.empty() && !e.ip.empty()) { sysEgressOwner = ownerOf(e.ip); break; }
    for (auto& e : eg) {
        std::string own = e.ip.empty() ? "" : ownerOf(e.ip);
        std::string low = own; for (auto& ch : low) ch = (char)tolower((unsigned char)ch);
        std::string verdict; const char* col = C::GRY;
        if (e.ip.empty()) {
            verdict = "нет ответа на TXT-запрос";
        } else if (e.expect.empty()) {
            verdict = "резолвер из настроек системы";
        } else if (own.empty()) {
            verdict = "владелец не определён";
        } else {
            bool okOwner = false;
            for (const char* k : e.expect) if (low.find(k) != std::string::npos) { okOwner = true; break; }
            if (okOwner) { verdict = "честно"; col = C::GRN; }
            else {
                verdict = "ПЕРЕХВАТ — запрос обслужил не " + e.server;
                if (!sysEgressOwner.empty() && own == sysEgressOwner)
                    verdict += " (а тот же резолвер, что в системе)";
                col = C::RED; intercepted = true;
            }
        }
        std::string ownTxt = own.empty() ? "" : "  [" + own + "]";
        printf("  %s -> %s%s  %s%s%s\n", u8pad(e.label, 26).c_str(),
               e.ip.empty() ? "—" : e.ip.c_str(), ownTxt.c_str(),
               col, verdict.c_str(), C::RST);
    }

    // --- итог ---
    printf("\n%s=== ИТОГ ===%s\n", C::BOLD, C::RST);
    if (badCtl > 0) {
        printf("%sДаже контрольные домены отвечают неверно — проблема с DNS/сетью в целом, "
               "а не блокировка отдельных сайтов. Проверьте настройки DNS у клиента, "
               "роутер, доступность резолвера.%s\n", C::YEL, C::RST);
    } else if (bad > 0) {
        printf("%sDNS врёт по %d домен(ам): заглушки/подмена/дроп.%s\n", C::RED, bad, C::RST);
        printf("Что сказать/сделать: блокировка на уровне DNS (реестр РКН / ТСПУ). "
               "Смена DNS в системе на 8.8.8.8/1.1.1.1 поможет, только если UDP:53 не "
               "перехватывается (см. блок «Перехват»); надёжно — DoH/DoT в браузере или ОС. "
               "Если сайт по верному IP всё равно не открывается — блокировка ещё и по SNI/IP.\n");
    } else {
        printf("%sПодмены DNS не видно.%s", C::GRN, C::RST);
        if (soft) printf(" %d домен(ов) с «другими адресами» — чаще всего это CDN/гео-балансировка, "
                         "сверьте владельца в скобках.", soft);
        printf("\nЕсли сайт всё равно не открывается — блокировка не в DNS, а по SNI/IP "
               "(режим «Поиск DPI» или анализ дампа).\n");
    }
    if (intercepted)
        printf("%sUDP-запросы к публичным DNS перехватываются по пути: менять DNS в "
               "настройках бесполезно, нужен DoH/DoT.%s\n", C::RED, C::RST);
}

// ==================================================================
// РЕЖИМ 12: тест «16 КБ» по зарубежным хостингам.
// ТСПУ на соединениях к части зарубежных хостингов/CDN пропускает первые
// ~16 КБ от сервера и дальше замораживает поток (пакеты молча дропаются).
// Качаем с каждого сервера до 256 КБ напрямую (без прокси) и смотрим, на
// каком объёме поток встал. Контроль — российские серверы: если и они
// встают, это проблема линии, а не ТСПУ.
// ==================================================================

struct T16Target { std::string name; std::string url; bool control; };

struct T16Result {
    int status = 0;
    long long body = 0;             // байт тела получено
    int lastDataMs = -1;            // когда пришли последние данные
    int totalMs = 0;
    bool completed = false;         // сервер сам закончил отдачу / набрали лимит
    DWORD err = 0;
    std::string ip;
};

#ifndef _WIN32
// macOS: ошибки libcurl переводятся в коды WinHTTP — классификация ниже общая
#define ERROR_WINHTTP_TIMEOUT                 12002
#define ERROR_WINHTTP_INVALID_URL             12005
#define ERROR_WINHTTP_UNRECOGNIZED_SCHEME     12006
#define ERROR_WINHTTP_NAME_NOT_RESOLVED       12007
#define ERROR_WINHTTP_CANNOT_CONNECT          12029
#define ERROR_WINHTTP_CONNECTION_ERROR        12030
#define ERROR_WINHTTP_INVALID_SERVER_RESPONSE 12152
#define ERROR_WINHTTP_SECURE_FAILURE          12175

static DWORD curlToWinHttpErr(CURLcode c) {
    switch (c) {
    case CURLE_OK:                    return 0;
    case CURLE_OPERATION_TIMEDOUT:    return ERROR_WINHTTP_TIMEOUT;
    case CURLE_COULDNT_RESOLVE_HOST:  return ERROR_WINHTTP_NAME_NOT_RESOLVED;
    case CURLE_COULDNT_CONNECT:       return ERROR_WINHTTP_CANNOT_CONNECT;
    case CURLE_URL_MALFORMAT:         return ERROR_WINHTTP_INVALID_URL;
    case CURLE_UNSUPPORTED_PROTOCOL:  return ERROR_WINHTTP_UNRECOGNIZED_SCHEME;
    case CURLE_WEIRD_SERVER_REPLY:    return ERROR_WINHTTP_INVALID_SERVER_RESPONSE;
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_PEER_FAILED_VERIFICATION:
    case CURLE_SSL_CERTPROBLEM:
    case CURLE_SSL_CIPHER:
    case CURLE_SSL_CACERT_BADFILE:    return ERROR_WINHTTP_SECURE_FAILURE;
    default:                          return ERROR_WINHTTP_CONNECTION_ERROR;
    }
}
#endif

static const char* winHttpErrText(DWORD e) {
    switch (e) {
    case ERROR_WINHTTP_TIMEOUT:                 return "таймаут";
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:       return "домен не резолвится";
    case ERROR_WINHTTP_CANNOT_CONNECT:          return "TCP-соединение не установлено";
    case ERROR_WINHTTP_CONNECTION_ERROR:        return "соединение сброшено";
    case ERROR_WINHTTP_SECURE_FAILURE:          return "ошибка TLS";
    case ERROR_WINHTTP_INVALID_SERVER_RESPONSE: return "некорректный ответ сервера";
    case ERROR_WINHTTP_INVALID_URL:
    case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:     return "неверный URL";
    default:                                    return "ошибка WinHTTP";
    }
}

#ifndef _WIN32
struct Fetch16Ctx {
    T16Result* r;
    std::chrono::steady_clock::time_point t0;
    long long limit;
    bool hitLimit = false;
};

static size_t fetch16Write(char*, size_t sz, size_t n, void* ud) {
    auto* c = (Fetch16Ctx*)ud;
    c->r->body += (long long)(sz * n);
    c->r->lastDataMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - c->t0).count();
    if (c->r->body >= c->limit) { c->hitLimit = true; return 0; }   // набрали — хватит
    return sz * n;
}

static T16Result fetch16(const std::string& url) {
    T16Result r;
    ensureWsa();
    Fetch16Ctx ctx{ &r, std::chrono::steady_clock::now(), 256 * 1024 };
    CURL* c = curl_easy_init();
    if (!c) { r.err = ERROR_WINHTTP_CONNECTION_ERROR; return r; }
    curl_slist* hl = nullptr;
    hl = curl_slist_append(hl, "Range: bytes=0-262143");
    hl = curl_slist_append(hl, "Accept-Encoding: identity");
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_USERAGENT, "Mozilla/5.0 traffic-analyzer/1.0");
    curl_easy_setopt(c, CURLOPT_PROXY, "");           // без прокси: нужен прямой путь через ТСПУ
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hl);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
    curlRedirNoDowngrade(c, url);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    // замороженный поток не шлёт ничего — через 6 с считаем, что встал
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, 6L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, fetch16Write);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
    const CURLcode rc = curl_easy_perform(c);
    long st = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &st);
    r.status = (int)st;
    char* ip = nullptr;
    if (curl_easy_getinfo(c, CURLINFO_PRIMARY_IP, &ip) == CURLE_OK && ip && isValidIpv4Str(ip)) r.ip = ip;
    if (rc == CURLE_OK || ctx.hitLimit) r.completed = true;
    else r.err = curlToWinHttpErr(rc);
    curl_easy_cleanup(c);
    curl_slist_free_all(hl);
    r.totalMs = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - ctx.t0).count();
    return r;
}
#else
static T16Result fetch16(const std::string& url) {
    T16Result r;
    const long long kLimit = 256 * 1024;
    std::wstring w = u8w(url);
    wchar_t host[256] = {0}, path[2048] = {0}, extra[2048] = {0};
    URL_COMPONENTS uc{}; uc.dwStructSize = sizeof(uc);
    uc.lpszHostName  = host;  uc.dwHostNameLength  = 256;
    uc.lpszUrlPath   = path;  uc.dwUrlPathLength   = 2048;
    uc.lpszExtraInfo = extra; uc.dwExtraInfoLength = 2048;
    if (!WinHttpCrackUrl(w.c_str(), 0, 0, &uc)) { r.err = GetLastError(); return r; }
    bool https = uc.nScheme == INTERNET_SCHEME_HTTPS;
    std::wstring fullPath = std::wstring(path) + extra;
    if (fullPath.empty()) fullPath = L"/";

    auto t0 = std::chrono::steady_clock::now();
    auto msNow = [&]() {
        return (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - t0).count();
    };

    // без прокси: интересует именно прямой путь через ТСПУ
    HINTERNET hS = WinHttpOpen(L"Mozilla/5.0 traffic-analyzer/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { r.err = GetLastError(); return r; }
    // receive 6 с: замороженный поток не шлёт ничего — через 6 с считаем, что встал
    WinHttpSetTimeouts(hS, 5000, 5000, 6000, 6000);
    HINTERNET hC = WinHttpConnect(hS, host, uc.nPort, 0);
    HINTERNET hR = hC ? WinHttpOpenRequest(hC, L"GET", fullPath.c_str(), NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, https ? WINHTTP_FLAG_SECURE : 0) : NULL;
    if (hR) {
        const wchar_t* hdr = L"Range: bytes=0-262143\r\nAccept-Encoding: identity\r\n";
        if (WinHttpSendRequest(hR, hdr, (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(hR, NULL)) {
            DWORD st = 0, sz = sizeof(st);
            WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &st, &sz, WINHTTP_NO_HEADER_INDEX);
            r.status = (int)st;
            WINHTTP_CONNECTION_INFO ci{}; ci.cbSize = sizeof(ci); DWORD cis = sizeof(ci);
            if (WinHttpQueryOption(hR, WINHTTP_OPTION_CONNECTION_INFO, &ci, &cis) &&
                ci.RemoteAddress.ss_family == AF_INET) {
                char b[64] = {0};
                inet_ntop(AF_INET, &((sockaddr_in*)&ci.RemoteAddress)->sin_addr, b, sizeof(b));
                r.ip = b;
            }
            std::vector<char> buf(65536);
            for (;;) {
                DWORD avail = 0;
                if (!WinHttpQueryDataAvailable(hR, &avail)) { r.err = GetLastError(); break; }
                if (!avail) { r.completed = true; break; }
                DWORD rd = 0;
                if (!WinHttpReadData(hR, buf.data(), std::min<DWORD>(avail, (DWORD)buf.size()), &rd)) {
                    r.err = GetLastError(); break;
                }
                if (!rd) { r.completed = true; break; }
                r.body += rd;
                r.lastDataMs = msNow();
                if (r.body >= kLimit) { r.completed = true; break; }
            }
        } else {
            r.err = GetLastError();
        }
        WinHttpCloseHandle(hR);
    } else {
        r.err = GetLastError();
    }
    if (hC) WinHttpCloseHandle(hC);
    WinHttpCloseHandle(hS);
    r.totalMs = msNow();
    return r;
}
#endif

// 0 = ок, 1 = не показательно, 2 = заморозка 16 КБ, 3 = другая беда
static int t16Classify(const T16Result& r, std::string& text) {
    const long long KB = 1024;
    if (r.status == 0) {
        text = std::string(winHttpErrText(r.err)) + " — до ответа сервера";
        if (r.err == ERROR_WINHTTP_TIMEOUT)
            text += " (зависло на TLS-рукопожатии или дроп)";
        return 3;
    }
    if (r.status != 200 && r.status != 206) {
        text = "ответ HTTP " + std::to_string(r.status) + " — цель не подходит, замените URL";
        return 1;
    }
    if (r.completed && r.body >= 200 * KB) { text = "ок, поток не режется"; return 0; }
    if (r.completed) {
        text = "ок, но файл маленький (" + std::to_string(r.body / KB) + " КБ) — тест не показателен";
        return 1;
    }
    if (r.body >= 1 && r.body <= 40 * KB) {
        text = "ЗАМОРОЗКА на " + std::to_string((r.body + KB / 2) / KB) +
               " КБ — поток встал (признак ТСПУ «16 КБ»)";
        return 2;
    }
    if (r.body == 0) {
        text = "заголовки пришли, данных нет — " + std::string(winHttpErrText(r.err));
        return 2;
    }
    text = "обрыв на " + std::to_string(r.body / KB) + " КБ — " + winHttpErrText(r.err) +
           " (не похоже на 16 КБ)";
    return 3;
}

void runTcp16Mode() {
    ensureWsa();

    // URL-ы тестовых файлов хостингов со временем меняются — при «HTTP 404»
    // или «домен не резолвится» замените на актуальные.
    std::vector<T16Target> tg = {
        { "Hetzner (DE)",        "https://fsn1-speed.hetzner.com/100MB.bin", false },
        { "Hetzner (FI)",        "https://hel1-speed.hetzner.com/100MB.bin", false },
        { "OVH (FR)",            "https://proof.ovh.net/files/10Mb.dat", false },
        { "DigitalOcean (DE)",   "https://speedtest-fra1.digitalocean.com/10mb.test", false },
        { "Vultr (DE)",          "https://fra-de-ping.vultr.com/vultr.com.100MB.bin", false },
        { "Linode (DE)",         "https://speedtest.frankfurt.linode.com/100MB-frankfurt.bin", false },
        { "Cloudflare (CDN)",    "https://speed.cloudflare.com/__down?bytes=262144", false },
        { "Яндекс-зеркало (RU)", "https://mirror.yandex.ru/ubuntu/ls-lR.gz", true },
        { "yastatic (RU)",       "https://yastatic.net/jquery/3.3.1/jquery.min.js", true },
    };

    std::cout << "Тест «16 КБ» по зарубежным хостингам.\n"
                 "Свои URL через запятую (добавятся к стандартным; Enter — только стандартные): "
              << std::flush;
    std::string line; readLine(line);
    for (auto& u : splitInput(trim(line))) {
        std::string url = u;
        if (url.find("://") == std::string::npos) url = "https://" + url;
        tg.push_back({ "свой: " + u8prefix(u, 30), url, false });
        if (tg.size() >= 30) break;
    }

    printf("\n=================== ТЕСТ «16 КБ» ===================\n");
    printf("Качаем до 256 КБ с каждого сервера напрямую (без прокси), параллельно.\n");
    printf("%s(ждать до ~20 с)%s\n\n", C::GRY, C::RST);

    std::vector<T16Result> res(tg.size());
    {
        std::vector<std::thread> th;
        for (size_t i = 0; i < tg.size(); i++)
            th.emplace_back([&, i]() { res[i] = fetch16(tg[i].url); });
        for (auto& t : th) t.join();
    }

    // failHost — зарубежные, где «другая беда» (cls 3: TCP/TLS не установились,
    // обрыв): они «проверены», но ни заморозки, ни нормальной закачки не дали
    int frozen = 0, okHost = 0, failHost = 0, ctlOk = 0, ctlBad = 0, testedHost = 0;
    printf("  %s %s %s %s  %s\n", u8pad("Сервер", 24).c_str(), u8pad("IP", 16).c_str(),
           u8pad("Получено", 10).c_str(), u8pad("Время", 8).c_str(), "Итог");
    for (size_t i = 0; i < tg.size(); i++) {
        const T16Result& r = res[i];
        std::string text;
        int cls = t16Classify(r, text);
        if (tg[i].control) { if (cls == 0 || cls == 1) ctlOk++; else ctlBad++; }
        else {
            if (cls != 1) testedHost++;
            if (cls == 2) frozen++;
            if (cls == 0) okHost++;
            if (cls == 3) failHost++;
        }
        const char* col = cls == 0 ? C::GRN : cls == 1 ? C::GRY : cls == 2 ? C::RED : C::YEL;
        char got[32], tm[32];
        snprintf(got, sizeof(got), "%lld КБ", r.body / 1024);
        int shownMs = (!r.completed && r.lastDataMs >= 0) ? r.lastDataMs : r.totalMs;
        snprintf(tm, sizeof(tm), "%.1f с", shownMs / 1000.0);
        printf("  %s %s %s %s  %s%s%s\n",
               u8pad(std::string(tg[i].control ? "[к] " : "") + tg[i].name, 24).c_str(),
               u8pad(r.ip.empty() ? "—" : r.ip, 16).c_str(),
               u8pad(got, 10).c_str(), u8pad(tm, 8).c_str(),
               col, text.c_str(), C::RST);
    }
    printf("  %s[к] — контрольный российский сервер; «Время» у зависших — момент последних данных.%s\n",
           C::GRY, C::RST);

    printf("\n%s=== ИТОГ ===%s\n", C::BOLD, C::RST);
    if (ctlBad > 0 && ctlOk == 0) {
        printf("%sКонтрольные российские серверы тоже не качаются — проблема на линии/у "
               "клиента (обрывы, MTU, перегрузка), а не ТСПУ. Сначала чиним связь.%s\n",
               C::YEL, C::RST);
    } else if (frozen > 0) {
        printf("%sЗаморозка ~16 КБ на %d из %d зарубежных серверов при рабочих контрольных — "
               "похоже на ТСПУ.%s\n", C::RED, frozen, testedHost, C::RST);
        printf("Что сказать/сделать: ограничение на стороне ТСПУ (не на нашем оборудовании), "
               "касается соединений к зарубежным хостингам — сайты/VPN на этих хостингах "
               "открываются частично или «висят». Обходы: VPN-протокол с маскировкой, "
               "сервер у другого хостера / в РФ, CDN.\n");
        if (ctlBad > 0)
            printf("%sЧасть контрольных тоже с ошибками — перепроверьте позже.%s\n", C::YEL, C::RST);
    } else if (testedHost == 0) {
        printf("%sНи один зарубежный сервер не дал пригодного ответа — URL-ы, возможно, "
               "устарели. Добавьте свои (большой файл по HTTPS).%s\n", C::YEL, C::RST);
    } else if (okHost == 0) {
        // Раньше сюда шёл зелёный «заморозки не видно (0 из N…)»: ни один зарубежный
        // не скачался, но и 16 КБ не было. Так выглядят «белые списки» мобильных
        // сетей и блокировка хостингов по IP/TLS при живых российских контролях.
        printf("%sНи один зарубежный сервер не скачался (%d из %d — ошибка соединения или обрыв, "
               "см. таблицу) при рабочих контрольных. Это не «16 КБ»: зарубежные хостинги "
               "недоступны совсем — блокировка по IP/TLS или «белые списки».%s\n",
               C::RED, failHost, testedHost, C::RST);
        printf("Если в таблице «домен не резолвится» или «неверный URL» — скорее устарели "
               "URL-ы: добавьте свои (большой файл по HTTPS) и повторите.\n");
        if (ctlBad > 0)
            printf("%sЧасть контрольных тоже с ошибками — перепроверьте позже.%s\n", C::YEL, C::RST);
    } else {
        printf("%sЗаморозки на 16 КБ не видно (%d из %d зарубежных серверов качаются нормально).%s\n",
               C::GRN, okHost, testedHost, C::RST);
        if (failHost > 0)
            printf("%sНо %d зарубежных не скачались совсем (ошибка соединения/обрыв, см. таблицу) — "
                   "это не 16 КБ, а недоступность этих хостингов (блокировка по IP или сбой).%s\n",
                   C::YEL, failHost, C::RST);
    }
}

// ==================================================================
// РЕЖИМ 13: кому принадлежит IP / домен.
// Домен резолвится во все A/AAAA. Для каждого публичного адреса:
//   - ip-api.com (батч, lang=ru): страна, город, провайдер, организация,
//     ASN, PTR, флаги хостинг / прокси / мобильный; запасной — ipwho.is;
//   - RDAP (rdap.org перенаправляет в нужный RIR): диапазон сети из реестра,
//     её имя (netname) и регистратор (RIPE NCC, ARIN, ...).
// Для домена ещё таблица: какие A-адреса отдают система, DNS провайдера,
// ns1/ns2.maryno.net, публичные резолверы (Google, Cloudflare, Quad9, Яндекс, ...) и DoH-эталон.
// ==================================================================

// Значение ключа ВЕРХНЕГО уровня объекта. В RDAP одни и те же ключи ("name",
// "handle", "country") есть и во вложенных entities — там уже не сеть, а
// контакты, поэтому первое вхождение по тексту брать нельзя.
static std::string jsonTopField(const std::string& s, const std::string& key) {
    int depth = 0;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        if (c == '{' || c == '[') depth++;
        else if (c == '}' || c == ']') depth--;
        else if (c == '"') {
            size_t b = i + 1;
            size_t e = b;
            while (e < s.size() && s[e] != '"') e += (s[e] == '\\') ? 2 : 1;
            if (e >= s.size()) return "";
            if (depth == 1 && e - b == key.size() && s.compare(b, key.size(), key) == 0) {
                size_t p = e + 1;
                while (p < s.size() && isspace((unsigned char)s[p])) p++;
                if (p < s.size() && s[p] == ':') return jsonText(s.substr(i), key);
            }
            i = e;
        }
    }
    return "";
}

// Все адреса домена: сначала IPv4, потом IPv6.
// 0 = адреса есть, 1 = NXDOMAIN / нет записей, 2 = ошибка резолва.
int resolveAllAddrs(const std::string& name, std::vector<std::string>& out) {
    ensureWsa();                           // зовётся и из режима 2 (report.cpp)
    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(name.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) return (rc == EAI_NONAME || rc == WSANO_DATA) ? 1 : 2;
    std::vector<std::string> v4, v6;
    for (addrinfo* p = res; p; p = p->ai_next) {
        char b[INET6_ADDRSTRLEN] = {0};
        if (p->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((sockaddr_in*)p->ai_addr)->sin_addr, b, sizeof(b));
            if (std::find(v4.begin(), v4.end(), b) == v4.end()) v4.push_back(b);
        } else if (p->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((sockaddr_in6*)p->ai_addr)->sin6_addr, b, sizeof(b));
            if (std::find(v6.begin(), v6.end(), b) == v6.end()) v6.push_back(b);
        }
    }
    freeaddrinfo(res);
    out = v4;
    out.insert(out.end(), v6.begin(), v6.end());
    return out.empty() ? 1 : 0;
}

// Диапазон IPv4 «a - b» как префикс «a/N», если он ровно один CIDR-блок.
static std::string rangeToCidr4(const std::string& a, const std::string& b) {
    in_addr x{}, y{};
    if (inet_pton(AF_INET, a.c_str(), &x) != 1 || inet_pton(AF_INET, b.c_str(), &y) != 1) return "";
    uint32_t s = ntohl(x.s_addr), e = ntohl(y.s_addr);
    if (e < s) return "";
    uint64_t n = (uint64_t)e - s + 1;
    if (n & (n - 1)) return "";            // размер не степень двойки
    if (s % n) return "";                  // не выровнен по границе блока
    int len = 32;
    while (n > 1) { n >>= 1; len--; }
    return a + "/" + std::to_string(len);
}

struct OwnerRes {
    std::string ip;
    std::vector<std::string> hosts;        // домены из ввода, указывающие сюда
    bool geoOk = false;
    std::string geoErr;
    std::string country, countryCode, region, city, isp, org, as, asname, ptr;
    bool hosting = false, proxy = false, mobile = false;
    bool netOk = false;
    std::string netStart, netEnd, netCidr, netName, netHandle, netCountry, rir;
};

// Ответ одного резолвера на домен (сравнение резолверов в режиме 13).
struct ResolverAns {
    std::string label, server;
    int kind = 1;                          // 0 система, 1 UDP, 2 DoH Google, 3 DoH Cloudflare
    bool ok = false;                       // ответ получен
    int rcode = -1;                        // 0 NOERROR, 3 NXDOMAIN, 2 SERVFAIL, ...
    int ms = -1;
    bool injected = false;                 // на один запрос пришли два разных ответа
    std::vector<std::string> ips, ips2;    // ips2 — второй (вброшенный) ответ
};

struct DomainResolvers {
    std::string name;
    std::vector<ResolverAns> rs;
};

// Публичные резолверы для сравнения. AdGuard — адрес без фильтрации рекламы.
static const std::pair<const char*, const char*> kPublicResolvers[] = {
    { "Google",     "8.8.8.8" },
    { "Cloudflare", "1.1.1.1" },
    { "Quad9",      "9.9.9.9" },
    { "Яндекс",     "77.88.8.8" },
    { "OpenDNS",    "208.67.222.222" },
    { "AdGuard",    "94.140.14.140" },
};

static void queryResolver(ResolverAns& a, const std::string& name) {
    auto t0 = std::chrono::steady_clock::now();
    auto msSince = [&]() {
        return (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - t0).count();
    };
    if (a.kind == 0) {
        int rc = sysResolveAll(name, a.ips);
        a.ms = msSince();
        a.ok = rc != 2;
        a.rcode = rc == 1 ? 3 : 0;
    } else if (a.kind == 1) {
        DnsProbe p = udpDnsQuery(a.server, name, 1, 2500);
        a.ok = p.first.got;
        a.ms = p.ms;
        a.rcode = p.first.rcode;
        a.ips = p.first.a;
        a.injected = p.twoDifferent;
        if (p.twoDifferent) a.ips2 = p.second.a;
    } else {
        DohRes r = dohResolve(a.kind == 3, name);
        a.ms = msSince();
        a.ok = r.ok;
        a.rcode = r.status;
        a.ips = r.ips;
    }
}

static std::string rcodeName(int rc) {
    switch (rc) {
    case 2: return "SERVFAIL";
    case 3: return "NXDOMAIN";
    case 5: return "REFUSED";
    default: return "код " + std::to_string(rc);
    }
}

void runIpOwnerMode() {
    std::cout << "Кому принадлежит IP / домен.\n"
                 "IP или домен (можно несколько через запятую или пробел): " << std::flush;
    std::string line; readLine(line);
    runIpOwnerFor(line);
}

// Сама проверка — без ввода с консоли: её же зовёт GUI (поле на вкладке «Инструменты»).
void runIpOwnerFor(const std::string& input) {
    ensureWsa();
    std::string line = trim(input);
    if (line.empty()) { std::cout << "Ничего не введено.\n"; return; }

    const size_t kMaxIps = 40;
    std::vector<OwnerRes> res;
    std::vector<std::string> privateIps;
    bool truncated = false;
    const size_t kMaxDomains = 5;          // сравнение резолверов — не больше 5 доменов
    std::vector<DomainResolvers> domains;
    auto addIp = [&](const std::string& ip, const std::string& host) {
        if (isPrivateIp(ip)) {
            if (std::find(privateIps.begin(), privateIps.end(), ip) == privateIps.end())
                privateIps.push_back(ip);
            return;
        }
        for (auto& r : res)
            if (r.ip == ip) {
                if (!host.empty() && std::find(r.hosts.begin(), r.hosts.end(), host) == r.hosts.end())
                    r.hosts.push_back(host);
                return;
            }
        if (res.size() >= kMaxIps) { truncated = true; return; }
        OwnerRes r; r.ip = ip;
        if (!host.empty()) r.hosts.push_back(host);
        res.push_back(r);
    };

    for (const auto& tok : splitInput(line)) {
        // вставленная ссылка «https://site.ru/path» или «host:443» — берём только хост
        std::string t = tok;
        for (auto& ch : t) ch = (char)tolower((unsigned char)ch);
        for (const char* sch : { "http://", "https://" })
            if (t.compare(0, strlen(sch), sch) == 0) { t = t.substr(strlen(sch)); break; }
        size_t cut = t.find_first_of("/?#");
        if (cut != std::string::npos) t = t.substr(0, cut);
        if (!t.empty() && t[0] == '[') {                       // [IPv6]:порт
            size_t rb = t.find(']');
            t = t.substr(1, rb == std::string::npos ? std::string::npos : rb - 1);
        } else if (std::count(t.begin(), t.end(), ':') == 1) {  // хост:порт
            t = t.substr(0, t.find(':'));
        }
        while (!t.empty() && t.back() == '.') t.pop_back();
        if (t.empty()) continue;

        unsigned char a6[16];
        if (isValidIpv4Str(t)) { addIp(t, ""); continue; }
        if (inet_pton(AF_INET6, t.c_str(), a6) == 1) {
            char b[INET6_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET6, a6, b, sizeof(b));
            addIp(b, "");
            continue;
        }
        t = idnToAscii(t);                                      // мвд.рф — в punycode
        if (!looksLikeDomainStr(t)) {
            printf("  %sпропуск «%s» — не IP и не домен%s\n", C::GRY, tok.c_str(), C::RST);
            continue;
        }
        // домен всё равно идёт в сравнение резолверов: NXDOMAIN у системы при
        // живом ответе DoH — как раз то, что нужно увидеть
        bool known = false;
        for (auto& d : domains) known = known || d.name == t;
        if (!known && domains.size() < kMaxDomains) { DomainResolvers d; d.name = t; domains.push_back(d); }
        std::vector<std::string> ips;
        int rc = resolveAllAddrs(t, ips);
        if (rc != 0) {
            printf("  %s%s — %s%s\n", C::YEL, t.c_str(),
                   rc == 1 ? "система: домен не существует или у него нет адресов (NXDOMAIN)"
                           : "система: не удалось разрезолвить (ошибка DNS)", C::RST);
            continue;
        }
        printf("  %s → %s\n", t.c_str(), joinIps(ips, 6).c_str());
        for (auto& ip : ips) addIp(ip, t);
    }

    // --- что отвечают разные резолверы (все запросы параллельно) ---
    if (!domains.empty()) {
        std::vector<std::string> sysDns = systemDnsServers();
        // DNS-серверы MARYNONET — адреса узнаём по имени (могут смениться)
        static const char* kOwnNs[] = { "ns1.maryno.net", "ns2.maryno.net" };
        std::vector<std::pair<std::string, std::string>> ownNs;   // имя, адрес
        for (const char* n : kOwnNs) {
            std::vector<std::string> ips;
            if (sysResolveAll(n, ips) == 0)
                for (auto& ip : ips) ownNs.push_back({ n, ip });
            else
                printf("  %sне удалось узнать адрес %s — этот сервер пропущен%s\n", C::GRY, n, C::RST);
        }
        for (auto& d : domains) {
#ifdef _WIN32
            ResolverAns s; s.label = "система (Windows)"; s.kind = 0; d.rs.push_back(s);
#else
            ResolverAns s; s.label = "система (macOS)"; s.kind = 0; d.rs.push_back(s);
#endif
            for (auto& ip : sysDns) {
                ResolverAns a; a.label = "DNS провайдера " + ip; a.server = ip;
                // системный DNS и есть ns1/ns2 — подписываем именем, второй строкой не дублируем
                for (auto& ns : ownNs) if (ns.second == ip) a.label = ns.first + " " + ip;
                d.rs.push_back(a);
            }
            for (auto& ns : ownNs) {
                if (std::find(sysDns.begin(), sysDns.end(), ns.second) != sysDns.end()) continue;
                ResolverAns a; a.label = ns.first + " " + ns.second; a.server = ns.second;
                d.rs.push_back(a);
            }
            for (auto& pr : kPublicResolvers) {
                ResolverAns a; a.label = std::string(pr.first) + " " + pr.second; a.server = pr.second;
                d.rs.push_back(a);
            }
            ResolverAns g; g.label = "DoH Google (HTTPS)"; g.kind = 2; d.rs.push_back(g);
            ResolverAns c; c.label = "DoH Cloudflare (HTTPS)"; c.kind = 3; d.rs.push_back(c);
        }
        printf("%s\nОпрашиваю резолверы (%zu домен(ов))...%s\n", C::GRY, domains.size(), C::RST);
        std::vector<std::thread> th;
        for (auto& d : domains)
            for (auto& a : d.rs)
                th.emplace_back([&a, &d]() { queryResolver(a, d.name); });
        for (auto& x : th) x.join();
        // адреса от резолверов тоже проверяем на владельца (заглушки — нет:
        // они и так помечены в таблице)
        for (auto& d : domains)
            for (auto& a : d.rs) {
                for (auto& ip : a.ips)  if (!isStubAddr(ip)) addIp(ip, d.name);
                for (auto& ip : a.ips2) if (!isStubAddr(ip)) addIp(ip, d.name);
            }
    }

    for (auto& ip : privateIps)
        printf("  %s%s — частный / служебный адрес (LAN, CGNAT, loopback): во внешних базах "
               "владельца нет, это адрес внутри чьей-то сети%s\n", C::GRY, ip.c_str(), C::RST);
    if (res.empty() && domains.empty()) { std::cout << "Нет публичных адресов для проверки.\n"; return; }
    if (truncated)
        printf("  %sпроверяю первые %zu адресов%s\n", C::GRY, kMaxIps, C::RST);

    if (!res.empty())
        printf("%s\nЗапрашиваю геобазу и реестры (RDAP) для %zu адрес(ов)...%s\n",
               C::GRY, res.size(), C::RST);

    // --- RDAP параллельно с геобазой: диапазон и имя сети из реестра ---
    std::vector<std::wstring> rdapPaths;
    for (auto& r : res) rdapPaths.push_back(L"/ip/" + std::wstring(r.ip.begin(), r.ip.end()));
    std::vector<std::string> rdap;
    std::thread rdapTh([&]() { rdap = httpsGetMany(L"rdap.org", rdapPaths, 3); });

    // --- ip-api.com: один батч (до 100 адресов), названия по-русски ---
    std::string body = "[";
    for (size_t i = 0; i < res.size(); i++) body += (i ? ",\"" : "\"") + res[i].ip + "\"";
    body += "]";
    const std::wstring path = L"/batch?lang=ru&fields=status,message,country,countryCode,"
                              L"regionName,city,isp,org,as,asname,reverse,mobile,proxy,hosting,query";
    std::string resp;
    for (int attempt = 1; attempt <= 2 && resp.empty() && !res.empty(); attempt++) {
        resp = httpPost(L"ip-api.com", path, body);
        if (resp.find("\"query\"") == std::string::npos) resp.clear();
        if (resp.empty() && attempt < 2) Sleep(1000);
    }
    if (!resp.empty()) {
        int depth = 0; size_t objStart = std::string::npos;
        for (size_t k = 0; k < resp.size(); k++) {
            char ch = resp[k];
            if (ch == '{') { if (depth == 0) objStart = k; depth++; }
            else if (ch == '}') {
                depth--;
                if (depth != 0 || objStart == std::string::npos) continue;
                std::string obj = resp.substr(objStart, k - objStart + 1);
                objStart = std::string::npos;
                std::string q = jsonStr(obj, "query");
                for (auto& r : res) {
                    if (r.ip != q) continue;
                    if (jsonStr(obj, "status") != "success") {
                        r.geoErr = jsonText(obj, "message");
                        break;
                    }
                    r.geoOk = true;
                    r.country = jsonText(obj, "country");
                    r.countryCode = jsonStr(obj, "countryCode");
                    r.region = jsonText(obj, "regionName");
                    r.city = jsonText(obj, "city");
                    r.isp = jsonText(obj, "isp");
                    r.org = jsonText(obj, "org");
                    r.as = jsonText(obj, "as");
                    r.asname = jsonText(obj, "asname");
                    r.ptr = jsonText(obj, "reverse");
                    r.hosting = jsonTrue(obj, "hosting");
                    r.proxy = jsonTrue(obj, "proxy");
                    r.mobile = jsonTrue(obj, "mobile");
                    break;
                }
            }
        }
    } else if (!res.empty()) {
        // запасной сервис: ipwho.is (по одному адресу, в несколько потоков)
        std::cout << "  ip-api.com недоступен — запасной сервис ipwho.is\n";
        std::vector<std::wstring> paths;
        for (auto& r : res) paths.push_back(L"/" + std::wstring(r.ip.begin(), r.ip.end()) + L"?lang=ru");
        std::vector<std::string> answers = httpsGetMany(L"ipwho.is", paths, 4);
        std::vector<size_t> needPtr;               // PTR ipwho.is не отдаёт — спросим сами
        for (size_t i = 0; i < res.size(); i++) {
            OwnerRes& r = res[i];
            const std::string& a = answers[i];
            if (a.empty()) continue;
            if (!jsonTrue(a, "success")) { r.geoErr = jsonText(a, "message"); continue; }
            r.geoOk = true;
            r.country = jsonTopField(a, "country");
            r.countryCode = jsonTopField(a, "country_code");
            r.region = jsonTopField(a, "region");
            r.city = jsonTopField(a, "city");
            size_t cp = a.find("\"connection\"");
            std::string sb = (cp != std::string::npos) ? a.substr(cp) : "";
            std::string asn = jsonStr(sb, "asn");
            r.isp = jsonText(sb, "isp");
            r.org = jsonText(sb, "org");
            if (!asn.empty()) r.as = "AS" + asn;
            if (isValidIpv4Str(r.ip)) needPtr.push_back(i);   // только IPv4
        }
        // до kMaxIps запросов по нескольку секунд каждый — не по очереди
        std::atomic<size_t> next{0};
        std::vector<std::thread> th;
        for (size_t w = 0; w < std::min<size_t>(8, needPtr.size()); w++)
            th.emplace_back([&]() {
                for (size_t k; (k = next.fetch_add(1)) < needPtr.size(); )
                    res[needPtr[k]].ptr = reverseDns(res[needPtr[k]].ip);
            });
        for (auto& t : th) t.join();
    }
    rdapTh.join();

    // --- разбор RDAP ---
    static const std::pair<const char*, const char*> kRir[] = {
        { "ripe", "RIPE NCC" }, { "arin", "ARIN" }, { "apnic", "APNIC" },
        { "lacnic", "LACNIC" }, { "afrinic", "AFRINIC" } };
    for (size_t i = 0; i < res.size() && i < rdap.size(); i++) {
        OwnerRes& r = res[i];
        const std::string& d = rdap[i];
        if (d.empty()) continue;
        r.netStart = jsonTopField(d, "startAddress");
        r.netEnd = jsonTopField(d, "endAddress");
        r.netName = jsonTopField(d, "name");
        r.netHandle = jsonTopField(d, "handle");
        r.netCountry = jsonTopField(d, "country");
        r.netOk = !r.netStart.empty() && !r.netEnd.empty();
        if (!r.netOk) continue;
        r.netCidr = rangeToCidr4(r.netStart, r.netEnd);
        if (r.netCidr.empty() && r.ip.find(':') != std::string::npos) {
            // IPv6: префикс из расширения cidr0 («v6prefix» + «length»)
            std::string pfx = jsonStr(d, "v6prefix"), len = jsonStr(d, "length");
            if (!pfx.empty() && !len.empty()) r.netCidr = pfx + "/" + len;
        }
        std::string whois = jsonTopField(d, "port43");        // whois.ripe.net и т.п.
        for (auto& k : kRir)
            if (whois.find(k.first) != std::string::npos) { r.rir = k.second; break; }
        if (r.rir.empty()) r.rir = whois;
    }

    // --- вывод: что отвечают резолверы ---
    // Эталон — объединение ответов DoH (HTTPS по пути не подменить). Адреса
    // резолвера сверяются с ним, а если не совпали — по ASN из геобазы:
    // CDN и гео-балансировка отдают разным резолверам разные узлы одной сети.
    std::map<std::string, const OwnerRes*> byIp;
    for (auto& r : res) byIp[r.ip] = &r;
    auto asnOfRes = [&](const std::string& ip) -> std::string {
        auto it = byIp.find(ip);
        if (it == byIp.end() || it->second->as.empty()) return "";
        const std::string& as = it->second->as;
        return as.substr(0, as.find(' '));
    };
    auto ispOfRes = [&](const std::string& ip) -> std::string {
        auto it = byIp.find(ip);
        if (it == byIp.end()) return "";
        return !it->second->isp.empty() ? it->second->isp : it->second->org;
    };
    bool anyBadDns = false;
    for (auto& d : domains) {
        std::vector<std::string> ref;
        for (auto& a : d.rs)
            if (a.kind >= 2 && a.ok)
                for (auto& ip : a.ips)
                    if (std::find(ref.begin(), ref.end(), ip) == ref.end()) ref.push_back(ip);
        std::set<std::string> refAsn;
        for (auto& ip : ref) { std::string n = asnOfRes(ip); if (!n.empty()) refAsn.insert(n); }

        printf("\n============ %s: ЧТО ОТВЕЧАЮТ РЕЗОЛВЕРЫ ============\n", d.name.c_str());
        printf("  %s %s %s %s\n", u8pad("Резолвер", 30).c_str(), u8pad("Время", 7).c_str(),
               u8pad("Адреса (A)", 34).c_str(), "Итог");
        for (auto& a : d.rs) {
            std::string verdict;
            const char* col = "";
            bool stub = false;
            for (auto& ip : a.ips) stub = stub || isStubAddr(ip);
            if (!a.ok) {
                verdict = a.kind >= 2 ? "DoH недоступен (заблокирован?)" : "нет ответа";
                col = C::GRY;
            } else if (a.injected) {
                verdict = "два разных ответа — вброс по пути (DPI), второй: " +
                          (a.ips2.empty() ? std::string("пусто") : joinIps(a.ips2, 2));
                col = C::RED; anyBadDns = true;
            } else if (stub) {
                verdict = "ЗАГЛУШКА (адрес-блокировка)";
                col = C::RED; anyBadDns = true;
            } else if (a.rcode != 0 && a.rcode != 3) {
                verdict = "ошибка сервера: " + rcodeName(a.rcode);
                col = C::YEL;
            } else if (a.ips.empty()) {
                std::string what = a.rcode == 3 ? "NXDOMAIN" : "нет A-записей";
                if (!ref.empty()) { verdict = what + ", а DoH видит адреса — подмена / блок"; col = C::RED; anyBadDns = true; }
                else              { verdict = what; col = C::GRY; }
            } else if (a.kind >= 2) {
                verdict = "эталон (HTTPS, не подменить)";
                col = C::GRN;
            } else if (!ref.empty()) {
                bool same = false;
                for (auto& ip : a.ips) same = same || std::find(ref.begin(), ref.end(), ip) != ref.end();
                bool sameNet = !refAsn.empty();
                for (auto& ip : a.ips) {
                    std::string n = asnOfRes(ip);
                    sameNet = sameNet && !n.empty() && refAsn.count(n);
                }
                std::string asn = asnOfRes(a.ips[0]), who = ispOfRes(a.ips[0]);
                if (same)         { verdict = "как у DoH"; col = C::GRN; }
                else if (sameNet) { verdict = "другой узел той же сети (" + asn + ")"; col = C::GRN; }
                else {
                    verdict = "ДРУГИЕ адреса: " + (who.empty() ? std::string("?") : who) +
                              (asn.empty() ? std::string() : " (" + asn + ")");
                    col = C::YEL;
                }
            }
            std::string tm = (a.ok && a.ms >= 0) ? std::to_string(a.ms) + " мс" : "—";
            std::string ips = a.ips.empty() ? "—" : joinIps(a.ips, 2);
            printf("  %s %s %s %s%s%s\n", u8pad(a.label, 30).c_str(), u8pad(tm, 7).c_str(),
                   u8pad(ips, 34).c_str(), col, verdict.c_str(), *col ? C::RST : "");
        }
    }
    if (!domains.empty()) {
        printf("\n%sРазные адреса у разных резолверов — нормально для CDN и сайтов с гео-балансировкой: "
               "каждый резолвер отдаёт ближайший к себе узел. Плохо — заглушка, NXDOMAIN при "
               "живом DoH, два ответа на один запрос.%s\n", C::GRY, C::RST);
        if (anyBadDns)
            printf("%sDNS подменяет ответ. Подробно (перехват UDP:53, вброс DPI) — режим 11 "
                   "«Честность DNS».%s\n", C::RED, C::RST);
    }
    if (res.empty()) return;

    // --- вывод: владельцы адресов ---
    auto row = [](const char* label, const std::string& val, const char* color = "") {
        printf("  %s: %s%s%s\n", u8pad(label, 12).c_str(), color,
               val.empty() ? "—" : val.c_str(), *color ? C::RST : "");
    };
    bool anyCdn = false;
    printf("\n=================== ВЛАДЕЛЕЦ АДРЕСА ===================\n");
    const bool pxOn = ip2proxyEnabled();
    if (pxOn) printf("%sЛокальная база IP2Proxy: %s%s\n", C::GRY, ip2proxyDbInfo().c_str(), C::RST);
    for (auto& r : res) {
        printf("\n%s── %s ──%s\n", C::BWHT, r.ip.c_str(), C::RST);
        std::string hosts;
        for (size_t i = 0; i < r.hosts.size(); i++) hosts += (i ? ", " : "") + r.hosts[i];
        if (!hosts.empty()) row("Хост", hosts);
        row("PTR", r.ptr);
        if (r.geoOk) {
            std::string city = r.city;
            if (!r.region.empty() && r.region != r.city) city += (city.empty() ? "" : ", ") + r.region;
            std::string country = r.country;
            if (!r.countryCode.empty()) country += (country.empty() ? "" : " ") + ("(" + r.countryCode + ")");
            row("Город", city);
            row("Страна", country);
        } else {
            row("Геобаза", r.geoErr.empty() ? std::string("нет ответа") : r.geoErr, C::YEL);
        }
        if (r.netOk) {
            std::string rng = r.netStart + " - " + r.netEnd;
            if (!r.netCidr.empty()) rng += "  (" + r.netCidr + ")";
            row("IP диапазон", rng, C::BWHT);
            std::string net = r.netName;
            // у RIPE handle — это сам диапазон «a - b», он уже выведен выше
            if (!r.netHandle.empty() && r.netHandle != r.netName &&
                r.netHandle.find(" - ") == std::string::npos)
                net += (net.empty() ? "" : "  ") + ("[" + r.netHandle + "]");
            if (!r.netCountry.empty()) net += (net.empty() ? "" : ", ") + ("страна " + r.netCountry);
            if (!r.rir.empty()) net += (net.empty() ? "" : ", ") + ("реестр " + r.rir);
            row("Сеть", net);
        } else {
            row("IP диапазон", "реестр (RDAP) не ответил", C::GRY);
        }
        row("Провайдер", r.isp, C::BWHT);
        if (!r.org.empty() && r.org != r.isp) row("Организация", r.org);
        {
            std::string as = r.as;
            if (!r.asname.empty() && as.find(r.asname) == std::string::npos)
                as += (as.empty() ? "" : "  ") + ("[" + r.asname + "]");
            row("ASN", as);
        }
        if (r.geoOk) {
            bool cdn = looksCdnOrg(r.isp) || looksCdnOrg(r.org) || looksCdnOrg(r.asname);
            anyCdn = anyCdn || cdn;
            std::vector<std::string> tags;
            if (cdn)       tags.push_back("CDN");
            if (r.hosting) tags.push_back("хостинг / дата-центр");
            if (r.mobile)  tags.push_back("мобильный оператор");
            if (r.proxy)   tags.push_back("прокси / VPN / Tor");
            std::string t;
            for (size_t i = 0; i < tags.size(); i++) t += (i ? ", " : "") + tags[i];
            if (t.empty()) t = "провайдер доступа / организация (не хостинг по базе ip-api)";
            row("Тип", t, (r.proxy || (r.hosting && !cdn)) ? C::YEL : "");
        }
        Ip2ProxyRec px;
        if (pxOn && ip2proxyLookup(r.ip, px)) {
            std::string t = ip2proxyTypeName(px.type);
            if (t.empty()) t = px.type;
            if (px.type != "-" && px.type != "?") t += " [" + px.type + "]";
            if (!px.provider.empty()) t += ", сервис " + px.provider;
            if (!px.usage.empty()) t += ", использование " + px.usage;
            if (!px.threat.empty()) t += ", угроза " + px.threat;
            if (!px.lastSeen.empty()) t += ", замечен " + px.lastSeen + " дн. назад";
            const bool strong = px.type == "VPN" || px.type == "TOR" || px.type == "PUB" || px.type == "WEB";
            const bool soft = px.type == "RES" || px.type == "CPN" || px.type == "EPN" || px.type == "?";
            row("IP2Proxy", t, strong ? C::RED : soft ? C::YEL : "");
        }
    }

    printf("\n");
    if (anyCdn)
        printf("%sАдрес принадлежит CDN (Cloudflare и т.п.): сайт спрятан за ним, город и страна — "
               "это CDN, а не настоящий сервер сайта. Где стоит сам сервер, по IP не узнать.%s\n",
               C::YEL, C::RST);
    printf("%sГород по IP приблизительный: геобазы часто ошибаются (особенно для CDN/anycast "
           "и мобильных сетей). Диапазон и имя сети берутся из реестра (RDAP) и надёжнее.%s\n",
           C::GRY, C::RST);
}
