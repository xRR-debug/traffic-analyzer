// common.h — общее для всех модулей TrafficAnalyzer: системные заголовки,
// цвета консоли, глобальное состояние, структуры пакета/IP-информации и
// объявления функций, которыми модули пользуются друг у друга.
//
// Модули:
//   parser.cpp   — разбор дампов (текст tcpdump, pcap/pcapng, TLS/JA4, QUIC)
//   analyzer.cpp — ядро анализа: адреса, порты, организации, потоки, TCP-таблица
//   detector_dpi.cpp — детекторы блокировок/DPI/ТСПУ, DNS, UDP/QUIC, «16 КБ»
//   detector_vpn.cpp — JA4, VLESS/Reality, признаки VPN, режим 1
//   report.cpp   — режим 2 (анализ соединений), сводка и сравнение дампов
//   (общие для этих четырёх структуры и функции — analyzer_internal.h)
//   network.cpp  — HTTP/ICMP-запросы, трассировка, geo, скан портов, пробы
//   ui.cpp       — вывод, меню, ввод, main
//   capture.cpp  — захват через Npcap (режим 5)
//   config.cpp   — настройки: analyzer.ini + переменные окружения (config.h)
//   ip2proxy.cpp — локальная база IP2Proxy .BIN (VPN/Tor/прокси без сети)
//
// Сборка (MSVC, x64, /std:c++17 /utf-8): проект TrafficAnalyzer.vcxproj, или
//   cl /EHsc /O2 /std:c++17 /utf-8 parser.cpp analyzer.cpp detector_dpi.cpp
//      detector_vpn.cpp report.cpp network.cpp ui.cpp capture.cpp config.cpp ip2proxy.cpp ws2_32.lib winhttp.lib comdlg32.lib iphlpapi.lib
// (для захвата — ещё /DHAVE_NPCAP, include/lib из npcap-sdk, wpcap.lib Packet.lib).
// Запуск: analyzer.exe [путь_к_дампу]   (без аргумента — откроется окно выбора файла)
#pragma once

#include "platform.h"     // системные заголовки Windows / macOS

#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>
#include <deque>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <iterator>
#include <thread>
#include <chrono>
#include <cmath>
#include <mutex>
#include <atomic>

#include "config.h"

// ------------------------------------------------------------------
// ANSI-цвета для консоли (зелёный=не VPN, красный=VPN, жёлтый=подозрительно)
// ------------------------------------------------------------------
namespace C {
    inline const char* const RST = "\x1b[0m";
    inline const char* const BOLD= "\x1b[1m";
    inline const char* const RED = "\x1b[31m";
    inline const char* const GRN = "\x1b[32m";
    inline const char* const YEL = "\x1b[33m";
    inline const char* const CYN = "\x1b[36m";
    inline const char* const WHT = "\x1b[37m";
    inline const char* const GRY = "\x1b[90m";
    // яркие варианты для оформления меню/баннера
    inline const char* const BCYN = "\x1b[96m";  // ярко-голубой
    inline const char* const BBLU = "\x1b[94m";  // ярко-синий
    inline const char* const BGRN = "\x1b[92m";  // ярко-зелёный
    inline const char* const BYEL = "\x1b[93m";  // ярко-жёлтый
    inline const char* const BMAG = "\x1b[95m";  // ярко-пурпурный
    inline const char* const BWHT = "\x1b[97m";  // ярко-белый
}

// --- глобальное состояние (inline — одна копия на всю программу) ---
// Файл-отчёт: весь аналитический вывод идёт через printf (= rprintf, см. ниже),
// который печатает в консоль и, если отчёт открыт, пишет туда копию без ANSI-кодов.
inline FILE* g_report = nullptr;
// Ctrl+C НИКОГДА не закрывает программу. Он только взводит флаг прерывания
// трассировки/захвата. Во всех остальных режимах просто игнорируется.
inline std::atomic<bool> g_traceAbort{false};
// Переключатель записи лога-отчёта (Delete в меню). При включённом — анализ
// режимов 1/2 дублируется в файл-отчёт; при выключенном файл не создаётся.
inline std::atomic<bool> g_logEnabled{false};
// Детектированный локальный адрес абонента (может быть ПУБЛИЧНЫМ).
// Заполняется после разбора пакетов (loadDumpSet). Используется везде, где нужно
// отличить «свою» сторону от удалённой (серверной).
inline std::string g_localIp;
// При dual-stack у абонента два «своих» адреса: IPv4 (часто приватный) и
// глобальный IPv6. Второй храним отдельно, иначе весь IPv6-трафик абонента
// выглядел бы как чужой.
inline std::string g_localIp6;

// Пути в программе хранятся в UTF-8 (так их отдают диалог и командная строка),
// а std::ifstream(std::string)/fopen на MSVC понимают только ANSI-кодовую
// страницу — файл в папке с кириллицей не открылся бы. Открываем по wstring.
#ifdef _WIN32
inline std::wstring u8w(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n > 0 ? n : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}
inline std::string w2u8(const wchar_t* w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n - 1 : 0, '\0');
    if (n > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}
// Путь для std::ifstream и fopen: на Windows — wstring, на macOS — UTF-8 как есть.
inline std::wstring upath(const std::string& s) { return u8w(s); }
inline FILE* ufopen(const std::string& path, const char* mode) {
    return _wfopen(u8w(path).c_str(), u8w(mode).c_str());
}
#else
// macOS: wchar_t 32-битный, UTF-8 <-> UTF-32 вручную (нужно для wstring-путей HTTP)
inline std::wstring u8w(const std::string& s) {
    std::wstring w;
    w.reserve(s.size());
    for (size_t i = 0; i < s.size(); ) {
        const unsigned char c = (unsigned char)s[i];
        uint32_t cp; int extra;
        if (c < 0x80)              { cp = c; extra = 0; }
        else if ((c >> 5) == 0x6)  { cp = c & 0x1F; extra = 1; }
        else if ((c >> 4) == 0xE)  { cp = c & 0x0F; extra = 2; }
        else if ((c >> 3) == 0x1E) { cp = c & 0x07; extra = 3; }
        else { w.push_back(0xFFFD); i++; continue; }
        if (extra && i + extra >= s.size()) { w.push_back(0xFFFD); break; }
        for (int k = 1; k <= extra; k++) cp = (cp << 6) | ((unsigned char)s[i + k] & 0x3F);
        w.push_back((wchar_t)cp);
        i += 1 + extra;
    }
    return w;
}
inline std::string w2u8(const wchar_t* w) {
    std::string s;
    for (; w && *w; ++w) {
        const uint32_t cp = (uint32_t)*w;
        if (cp < 0x80) s.push_back((char)cp);
        else if (cp < 0x800) { s.push_back((char)(0xC0 | (cp >> 6))); s.push_back((char)(0x80 | (cp & 0x3F))); }
        else if (cp < 0x10000) {
            s.push_back((char)(0xE0 | (cp >> 12)));
            s.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            s.push_back((char)(0x80 | (cp & 0x3F)));
        } else {
            s.push_back((char)(0xF0 | (cp >> 18)));
            s.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
            s.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
            s.push_back((char)(0x80 | (cp & 0x3F)));
        }
    }
    return s;
}
inline const std::string& upath(const std::string& s) { return s; }
inline FILE* ufopen(const std::string& path, const char* mode) { return fopen(path.c_str(), mode); }
#endif
// Число символов в UTF-8 строке (байты продолжения 10xxxxxx не считаются).
inline size_t u8len(const std::string& s) {
    size_t n = 0;
    for (unsigned char c : s) if ((c & 0xC0) != 0x80) n++;
    return n;
}
// Первые maxChars символов UTF-8 строки — не режет символ посередине.
inline std::string u8prefix(const std::string& s, size_t maxChars) {
    size_t n = 0, i = 0;
    for (; i < s.size(); i++)
        if (((unsigned char)s[i] & 0xC0) != 0x80 && n++ == maxChars) break;
    return s.substr(0, i);
}
// Дополняет UTF-8 строку пробелами до w символов (printf «%-Ns» считает байты,
// и кириллица сдвигала бы колонки). Длиннее w — не режет.
inline std::string u8pad(const std::string& s, size_t w) {
    const size_t n = u8len(s);
    return n >= w ? s : s + std::string(w - n, ' ');
}

// GUI-режим: весь вывод rprintf (и std::cout — через перехват потока в gui)
// дополнительно отдаётся в этот приёмник (журнал в окне). Вызывается под
// g_printMx, текст — как есть, с ANSI-кодами. nullptr = консольный режим.
inline std::atomic<void(*)(const char*, size_t)> g_outputSink{nullptr};
// false = не дублировать вывод в консоль (консоль скрыта, всё идёт в окно).
inline std::atomic<bool> g_consoleEcho{true};

// printf во всех модулях — это rprintf (ui.cpp): консоль + копия в отчёт.
// std::cout в отчёт не попадает (в GUI попадает в журнал окна).
int rprintf(const char* fmt, ...);
#define printf rprintf


// ------------------------------------------------------------------
// Протокол по СОДЕРЖИМОМУ (сигнатуре payload), а не по порту — как эвристики
// Wireshark/nDPI. Парсер ставит код на пакет с сигнатурой, loadDumpSet
// переносит его на весь поток (флоу-маркировка после WireGuard).
// ------------------------------------------------------------------
enum L7Proto : uint8_t {
    L7_NONE = 0,
    L7_TLS, L7_HTTP, L7_HTTP_PROXY, L7_SSH, L7_BITTORRENT, L7_BT_DHT,
    L7_SOCKS5, L7_SOCKS4, L7_RDP, L7_TELNET, L7_SMB, L7_STUN, L7_DNS,
    L7_OPENVPN,
    // только на пакете, до сборки потока: OpenVPN засчитываем, лишь когда в
    // потоке есть и сброс клиента, и ответ сервера (одиночный байт — не сигнатура),
    // а по UDP — ещё и управляющий пакет (P_CONTROL_V1/P_ACK_V1) с session id сброса
    L7_OVPN_CLIENT, L7_OVPN_SERVER, L7_OVPN_CTRL,
};
const char* l7Name(int code);            // "SSH", "BitTorrent", ...; "" для L7_NONE
inline bool l7IsProxy(int c) { return c == L7_SOCKS5 || c == L7_SOCKS4 || c == L7_HTTP_PROXY; }

// ------------------------------------------------------------------
// модель одного пакета
// ------------------------------------------------------------------
struct Packet {
    std::string ts;          // "18:11:00.417785"
    std::string srcIp, dstIp;
    int         srcPort = -1;
    int         dstPort = -1;
    std::string proto = "TCP";   // TCP / UDP / ICMP
    std::string flags;           // "[P.]" и т.п.
    long long   seq = -1;        // конец диапазона (для RTT seq->ack)
    long long   seqStart = -1;   // начало диапазона (для детекта ретрансмиссий)
    long long   ack = -1;
    bool        seqRelFixed = false; // текстовый tcpdump: первый пакет беседы напечатан
                                     // абсолютным, переведён в относительный (fixFirstAbsoluteSeq)
    long long   win = -1;
    long long   length = 0;
    std::string appHint;         // "HTTP" если в дампе помечено
    std::string sni;             // имя сервера из TLS ClientHello (только pcap; для UDP — из QUIC Initial)
    // JA4-отпечаток ClientHello (только pcap, только если ClientHello собран целиком)
    std::string ja4;
    std::string tlsClient;       // догадка о клиенте по ClientHello (см. ja4FromHello)
    int         ja4Kind = 0;     // JA4K_* : браузер / библиотека / подделка под браузер
    bool        ech = false;     // в ClientHello есть encrypted_client_hello (0xfe0d)
    int         quic = 0;       // QUIC long header в датаграмме: 1 = есть Initial, 2 = Handshake/0-RTT
    int         ttl = -1;        // IP TTL (только pcap; -1 = неизвестно)
    int         ipId = -1;       // IPv4 Identification (только pcap; -1 — нет/IPv6)
    // отпечаток датаграммы (только pcap, 0 — нет): IP-заголовок без TTL, DSCP и
    // контрольной суммы + неизменяемая часть L4. Совпадает у копий одного пакета,
    // снятых в двух точках, — по нему loadDumpSet склеивает дубли из двух файлов
    uint32_t    wireHash = 0;
    int         wgType = 0;      // WireGuard по сигнатуре payload: 1=init(148B), 2=response(92B), 0=нет
    // IPsec (UDP 500/4500): 1 = IKE_SA_INIT / открытая фаза 1 IKEv1, 2 = IKE дальше
    // (IKE_AUTH, CHILD_SA, INFORMATIONAL, шифрованный IKEv1), 3 = ESP-данные в UDP; 0 = нет/не видно
    int         ipsec = 0;
    // заголовок IKE: бит 0 — IKEv1, бит 1 — IKEv2, бит 2 — отправитель начинает
    // новый IKE SA (первый запрос IKE_SA_INIT / Main Mode — он инициатор)
    uint8_t     ike = 0;
    // вывод по всему дампу об IPsec-адресе (markIpsecPeers): 1 — IPsec-VPN точно,
    // 2 — VoWiFi точно (звонки по Wi-Fi через ePDG оператора), 0 — не ясно
    uint8_t     ipsecPeer = 0;
    uint8_t     l7 = L7_NONE;    // протокол потока по содержимому (L7Proto), только pcap
    // OpenVPN по UDP (L7_OVPN_*): 8 байт session id за опкодом, как есть; 0 — нет
    uint64_t    ovpnSid = 0;
    // рукопожатие TLS открытым текстом (TLSHS_*): что началось в этом сегменте; только pcap
    uint8_t     tlsHs = 0;
    int         tlsAlert = -1;   // код открытого TLS Alert (при TLSHS_ALERT), -1 — нет
    // DNS (из текстового tcpdump: "A? domain" / "id 1/0/0 A 1.2.3.4" / NXDomain,
    // либо из UDP-payload бинарного дампа — поля заполняются в том же виде)
    std::string dnsQuery;        // запрашиваемый домен (если это DNS-запрос)
    std::string dnsAnswerIp;     // IP из ответа A/AAAA (если это DNS-ответ с записью)
    std::vector<std::string> dnsAnswers; // все A/AAAA из ответа (dnsAnswerIp — первый)
    // цели CNAME из ответа по порядку: fl.yoomoney.ru → fp-back.facct.ru — видно,
    // чей на самом деле адрес (антифрод, CDN), когда имя сайта «своё»
    std::vector<std::string> dnsCnames;
    std::string dnsId;           // transaction id (для сопоставления запрос<->ответ)
    uint16_t    dnsQtype = 0;    // тип запроса: 1=A, 28=AAAA, 65=HTTPS…; 0 = не распознан
    bool        dnsIsResponse = false; // true = ответ, false = запрос
    bool        dnsNxdomain = false;   // ответ NXDomain (домена нет)
    // TCP-опции (pcap/pcapng или «options [...]» текстового tcpdump; -1 = опции не было)
    int         mss = -1;        // MSS из SYN/SYN-ACK
    int         wscale = -1;     // window scale (сдвиг) из SYN/SYN-ACK
    int         sackBlocks = 0;  // число SACK-блоков (>0 = получатель сообщает о дырах)
    long long   tsVal = -1, tsEcr = -1;   // TCP timestamps (RFC 7323): TSval / TSecr
    bool        tcpMd5 = false;  // опция MD5 (19, только pcap): ею zapret метит фейки (fooling=md5sig)
    // HTTP без TLS (только pcap, первый сегмент с данными):
    int         httpStatus = 0;  // код ответа "HTTP/1.x NNN" (0 = не ответ)
    std::string httpHost;        // Host: из запроса
    std::string httpUa;          // User-Agent: из запроса
    std::string httpPath;        // путь из строки запроса (до 200 символов)
    std::string httpLocation;    // Location: из ответа (редирект)
    std::string httpBlockMark;   // признак страницы-заглушки о блокировке (что нашли)
    // направление кадра по заголовку SLL/SLL2: -1 неизвестно, 0 входящий, 1 исходящий
    int         dir = -1;
    bool        valid = false;
};

// Packet::tlsHs. До ChangeCipherSpec записи TLS 1.2 идут открытым текстом; в
// TLS 1.3 всё после ServerHello зашифровано, и запрос сертификата не виден.
enum : uint8_t {
    TLSHS_CERT_REQ   = 1,    // CertificateRequest: сервер просит сертификат клиента (mTLS)
    TLSHS_CERT_EMPTY = 2,    // Certificate без сертификатов («сертификата нет»)
    TLSHS_CERT       = 4,    // Certificate с сертификатом
    TLSHS_CCS        = 8,    // ChangeCipherSpec: дальше записи шифрованы
    TLSHS_ALERT      = 16,   // открытый Alert (код — Packet::tlsAlert)
};
// Alert, которым сервер отвергает сертификат клиента: handshake_failure,
// bad/unsupported/revoked/expired/unknown certificate, unknown_ca,
// access_denied, certificate_required
inline bool tlsAlertCertReject(int a) {
    return a == 40 || (a >= 42 && a <= 46) || a == 48 || a == 49 || a == 116;
}
// mTLS без сертификата: сервер запросил сертификат клиента, а абонент прислал
// пустой (clientCert 0) или предъявленный (1) сервер отверг открытым Alert.
// Пустой сертификат при необязательной проверке сервер принимает и отдаёт
// данные как обычно — поэтому без Alert проблема, только если после рукопожатия
// абонент отправил запрос (reqSeen: простаивающий preconnect ответа и не ждёт),
// а сервер прислал немного (страница/код ошибки, а не содержимое). Сервер,
// обслуживший пустой сертификат на другом соединении (clientCertServed), —
// тоже не проблема: это вызывающие сверяют по всем соединениям сами.
// inAppBytes — байт данных от сервера после его ChangeCipherSpec.
// Общее для причины TLS_CLIENT_CERT и таблицы соединений GUI.
inline bool clientCertProblem(bool certReq, int clientCert, int alertIn, long long inAppBytes,
                              bool reqSeen) {
    if (!certReq || clientCert < 0) return false;
    if (tlsAlertCertReject(alertIn)) return true;
    return clientCert == 0 && reqSeen && inAppBytes <= 8192;
}
// Сервер принял пустой сертификат и отдал больше 8 КБ — проверка у него
// необязательная. Тогда и соседние соединения к тому же имени или адресу без
// Alert (короткий ответ, простаивающий HTTP/2-сокет) — не отказ
inline bool clientCertServed(bool certReq, int clientCert, int alertIn, long long inAppBytes) {
    return certReq && clientCert == 0 && !tlsAlertCertReject(alertIn) && inAppBytes > 8192;
}

// IP ID отправителя — счётчик (Linux, Windows): у каждого следующего пакета на
// 1 больше. 0 — счётчика нет (DF без счётчика: PS5, часть стеков), -1 — неизвестно.
// id продолжает счётчик после prev (с запасом на пару пакетов, не попавших в захват)
inline bool ipIdNext(int prev, int id) {
    if (prev <= 0 || id <= 0) return false;
    const int d = (id - prev) & 0xFFFF;
    return d >= 1 && d <= 4;
}
// id отправлен РАНЬШЕ ref (тот же счётчик, отставание до 64 пакетов)
inline bool ipIdBefore(int id, int ref) {
    if (id <= 0 || ref <= 0) return false;
    const int d = (ref - id) & 0xFFFF;
    return d >= 1 && d <= 64;
}

// Пакет с тем же IP ID и seq, что и предыдущий, через dtUs — копия захвата: один
// пакет снят дважды в одном файле (единицы мкс; копии из двух файлов loadDumpSet
// уже убрал). Позже — настоящий повтор: инжектор шлёт одинаковые RST пачкой.
// seq обязателен: пачку RST с РАЗНЫМИ seq инжектор шлёт подряд, за доли мкс,
// и IP ID у неё бывает один на всех (константа инжектора)
inline bool ipIdCaptureCopy(int id, int prevId, long long seq, long long prevSeq, long long dtUs) {
    return id > 0 && id == prevId && seq == prevSeq && dtUs >= 0 && dtUs < 20;
}

// UDP-сессия (один 4-tuple), где сервер отвечал, а потом замолчал насовсем,
// хотя абонент шлёт дальше и переподключается (игры, голос). Одно правило для
// причины UDP_SESSION (collectBlockReasons) и таблицы соединений GUI. DNS и QUIC
// отсекают вызывающие: браузер с QUIC сам уйдёт на новое соединение.
struct UdpSessStat {
    long long in = 0, lastIn = -1;      // ответов сервера / время последнего, мкс
    long long outAfter = 0;             // пакетов абонента после последнего ответа
    long long lastOut = -1;             // время последнего из них
    void add(bool out, long long t) {
        if (t < 0) return;
        if (!out) { in++; lastIn = t; outAfter = 0; }
        else if (in > 0) { outAfter++; lastOut = t; }
    }
    long long silenceUs() const { return lastOut - lastIn; }
    // ≥3 ответов, затем ≥5 с тишины и ≥10 пакетов абонента. lastInAny —
    // последний входящий пакет дампа (любой протокол, та же шкала времени):
    // входящий захват шёл и после конца сессии, иначе это просто конец записи
    bool died(long long lastInAny) const {
        return in >= 3 && outAfter >= 10 && silenceUs() >= 5000000LL && lastInAny >= lastOut;
    }
};

// ------------------------------------------------------------------
// сведения об IP (из ip-api.com)
// ------------------------------------------------------------------
struct IpInfo {
    std::string type = "public"; // public / private
    std::string country = "-";
    std::string asn = "-";
    std::string org = "-";
    bool hosting = false;        // датацентр/хостинг (из ip-api поля hosting)
    bool isVpn = false;          // is_vpn от ipapi.is или тип VPN в базе IP2Proxy
    bool isProxy = false;        // is_proxy / PUB, WEB
    bool isTor = false;          // is_tor / TOR
    std::string flagSrc;         // откуда флаги VPN/proxy/Tor: "ipapi.is", "IP2Proxy" ("" — флагов нет)
    std::string pxType;          // тип по базе IP2Proxy: VPN, TOR, PUB, WEB, DCH, RES, CPN, EPN, SES,
                                 // AIC; "-" — в базе, но не прокси; "" — базы нет или не спрашивали
    // Белый список VPN (vpn_whitelist_*): крупный сервис — баллов VPN не даёт и
    // VPN не называется. Ставится только в копии кэша для анализа VPN
    // (withVpnWhitelist), проверки соединения видят адрес как обычно.
    bool vpnWhite = false;
    std::string whiteWhy;        // почему: «AS15169» или «youtube.com по DNS»
};

// ------------------------------------------------------------------
// JA4 — отпечаток TLS-клиента по ClientHello (FoxIO, открытая спецификация):
//   a — t/q (TCP/QUIC) + версия TLS (13, 12, …) + d/i (SNI есть / нет)
//       + число шифров и число расширений (по 2 цифры) + первая и последняя
//       буквы первого ALPN ("h2", "h1", "h3"; "00" — ALPN нет);
//   b — sha256 отсортированного списка шифров, первые 12 hex;
//   c — sha256 «отсортированные расширения без SNI и ALPN _ алгоритмы подписи
//       в исходном порядке», первые 12 hex.
// GREASE (0x?a?a) везде отбрасывается. Порядок расширений JA4 не учитывает,
// поэтому Chrome, перемешивающий их в каждом соединении, даёт один отпечаток.
// Отпечаток считаем ТОЛЬКО по целому ClientHello: по обрывку он был бы
// просто другим (неверным) значением.
// ------------------------------------------------------------------
enum { JA4K_UNKNOWN = 0, JA4K_BROWSER = 1, JA4K_LIBRARY = 2, JA4K_FAKE = 3 };

// ------------------------------------------------------------------
// РЕЖИМ 10: СРАВНЕНИЕ ДВУХ ДАМПОВ («было / стало»). Типичные случаи: до и
// после замены роутера или смены тарифа, «вчера работало — сегодня нет»,
// с VPN и без. По каждому дампу собирается сводка без печати, затем
// выводятся показатели рядом и то, что появилось/пропало между A и B.
// ------------------------------------------------------------------
// Причина недоступности одного ресурса — итог по всем его соединениям в дампе.
// code: HTTP_STUB, TLS_RST_FORGED, TLS_RST, TLS_DROP, TCP16, SYN_DROP, UDP_DROP;
// UDP_SESSION (оборвавшаяся UDP-сессия игры/голоса) и TLS_CLIENT_CERT (сервер
// требует сертификат клиента, mTLS) — не блокировки, см. blockReasonIsBlock.
struct BlockReason {
    std::string target;     // домен (SNI / Host / DNS) или IP
    std::string ip;         // удалённый адрес (первый, если их несколько)
    std::string code;
    std::string detail;     // что именно видно в дампе
    int conns = 0;          // сколько соединений/потоков с этим признаком
};

struct DumpSummary {
    std::string name, localIp, localIp6;
    long long packets = 0; double durSec = 0;
    long long tcpConns = 0, tcpNoAnswer = 0;               // по соединениям с SYN в дампе
    bool noInboundTcp = false;   // входящего TCP нет (дамп односторонний) — «без ответа» н/д
    long long silentDrops = 0, sniRsts = 0, ttlInj = 0;
    long long forgedRsts = 0;                                // RST, подделанные «посредником»
    long long httpStubs = 0;                                 // HTTP-заглушки о блокировке
    long long outDataSegs = 0, outRetrans = 0;
    std::vector<long long> hsRtt;                            // SYN -> SYN-ACK, мкс
    long long dnsQueries = 0, dnsNoAnswer = 0, dnsNx = 0;
    std::set<std::string> blockedIps;
    std::map<std::string,std::string> blockedSnis;
    std::vector<BlockReason> blockReasons;
    std::map<std::string,long long> bytesByIp;              // удалённый IP -> байт (bytesByRemote)
    std::set<std::string> snis;
    long long ja4Fake = 0, ja4Lib = 0;
    std::set<std::string> wgPeers, realityIps;
    // вердикт VPN — тот же расчёт, что в режиме 1 (computeVpnVerdict), и разбивка баллов
    int vpnScore = 0; std::vector<std::string> vpnReasons;
    int vpnPortScore = 0, vpnShapeScore = 0, vpnFlowScore = 0, vpnMssScore = 0;
};
// Пороги вердикта VPN (kVpnLikelyScore/kVpnPossibleScore) — в config.h.

// ---- ui.cpp ----
std::string trim(const std::string& s);
std::string regionName(const std::string& cc);    // "RUSSIA" (колонка REGION)
std::string countryNameRu(const std::string& cc); // "Россия" (режим гео-RTT)
std::string fixPad(const std::string& s);
bool isYesAnswer(const std::string& s);
bool readLine(std::string& s);   // строка с консоли; false — Ctrl+C или конец ввода
bool isValidIpv4Str(const std::string& str);
bool looksLikeDomainStr(const std::string& str);
std::string askTargetIp();
void rawOutput(const char* s, size_t n);
std::vector<std::string> pickDumpFiles(HWND owner);
bool addSiblingDump(std::vector<std::string>& paths);
std::string dumpSetName(const std::vector<std::string>& paths);
std::string openReport(const std::string& basePath, const char* kind);
void closeReport();
#ifndef _WIN32
// macOS: системные диалоги и Терминал — через AppleScript (osascript без shell).
// Возвращает stdout скрипта; exitCode (если задан) — код выхода, 1 = «Отмена».
std::string macOsascript(const std::string& script, int* exitCode = nullptr);
std::string asQuote(const std::string& s);   // "строка" для AppleScript
std::string shQuote(const std::string& s);   // 'строка' для sh/zsh
#endif
// загруженный набор для сравнения (указатели — владеет вызывающий)
struct DumpRef {
    const std::vector<std::string>* paths = nullptr;
    const std::vector<Packet>* packets = nullptr;
    std::string localIp, localIp6;
};
void compareDumpSets(const DumpRef& a, const DumpRef& b);
// ---- analyzer.cpp ----
// время пакетов в мкс с поправкой на полночь; -1 — время не разобрано
std::vector<long long> absTimes(const std::vector<Packet>& packets);

// ---- parser.cpp ----
std::string siblingDumpPath(const std::string& path);
long long tsToMicros(const std::string& ts);
bool loadDumpSet(const std::vector<std::string>& paths,
                 std::vector<Packet>& packets, std::vector<int>& origin);

// ---- analyzer.cpp ----
bool isPrivateIp(const std::string& ip);
bool isLocalIp(const std::string& ip);
const char* localRoleLabel(const std::string& ip);   // «MainIP» (абонент) / «LocalIP» (прочая лок. сеть)
// Внешний SNI настоящего ECH (cloudflare-ech.com и т.п.). Само расширение ECH
// в ClientHello ещё не ECH — Chrome шлёт его холостым (GREASE) всегда.
bool isEchPublicName(const std::string& sni);
const char* portService(int p);
const char* appByPort(int port, const std::string& proto);
bool looksHostingOrg(const std::string& org, const std::string& /*asn*/);
bool looksCdnOrg(const std::string& org);
// Хостинг «по-настоящему»: флаг ip-api/ipapi.is или имя организации, но не CDN/
// крупный сервис (Google, Microsoft, Yandex…) и не сеть самого оператора.
bool isHostingNonCdn(const IpInfo* i);
// AS адреса в белом списке VPN (vpn_whitelist_asn). Белый список по DNS так не
// проверить — для него нужен дамп (withVpnWhitelist).
bool inVpnWhitelistAsn(const std::string& asn);
// Фоновая загрузка Windows/Microsoft (Windows Update, Delivery Optimization,
// BITS, Office, Store, Defender, Edge…) по имени (SNI/Host/DNS), User-Agent или
// пути HTTP. Скорость такой загрузки Windows ограничивает сама — «низкая
// полка» тут не шейпинг. Возвращает, что именно найдено, или nullptr.
const char* msBackgroundDownload(const std::string& host, const std::string& ua = "",
                                 const std::string& path = "");
// ---- report.cpp ----
void runConnAnalysis(const std::vector<Packet>& packets,
                     const std::vector<std::string>& paths);
void runConnAnalysisFor(const std::vector<Packet>& packets,
                        const std::vector<std::string>& paths,
                        const std::string& target);
void runConnAnalysisBody(const std::vector<Packet>& packets, const std::string& target);
DumpSummary summarizeDump(const std::vector<Packet>& packets, const std::string& name,
                          const std::unordered_map<std::string, IpInfo>* ipCache);
void printDumpCompare(const DumpSummary& a, const DumpSummary& b,
                      const std::unordered_map<std::string, IpInfo>& ipCache);
// ---- detector_vpn.cpp ----
void runVpnAnalysis(std::vector<Packet>& packets, const std::vector<std::string>& paths);
// ---- detector_dpi.cpp ----
const char* blockReasonTitle(const std::string& code);   // «Молчаливый дроп после ClientHello»
const char* blockReasonAdvice(const std::string& code);  // подсказка для техподдержки
// false — проблема связи, а не признак блокировки (UDP_SESSION, TLS_CLIENT_CERT): показывать
// отдельно от «Признаков блокировок»
bool blockReasonIsBlock(const std::string& code);

// ---- network.cpp ----
// AS своей сети по своему внешнему адресу (ip-api.com): запоминает его
// (config.h, OwnIspAuto). Кнопка «Определить» в настройках GUI; блокирует
// до ответа. msg — что определено или почему не вышло.
bool ownIspDetect(std::string& msg);
void resolveIps(const std::vector<std::string>& ips,
                std::unordered_map<std::string, IpInfo>& cache);
void resolveHostingSecondary(std::unordered_map<std::string, IpInfo>& cache,
                             const std::vector<std::string>& ips);

// ---- ip2proxy.cpp ----
// Локальная база IP2Proxy (файл .BIN, ключ ip2proxy_db в analyzer.ini):
// тип адреса без запросов в интернет.
struct Ip2ProxyRec {
    std::string type;        // VPN, TOR, PUB, WEB, DCH, SES, RES, CPN, EPN, AIC; "-" — не прокси;
                             // "?" — в базе PX1 (тип не хранится)
    std::string country, isp, domain, usage, asn, as, lastSeen, threat, provider;
};
bool ip2proxyEnabled();                                     // ключ задан (база может не открыться)
bool ip2proxyLookup(const std::string& ip, Ip2ProxyRec& r); // false — базы нет / адрес не разобран
std::string ip2proxyDbInfo();                               // «PX2, от 2026-09-01» или текст ошибки
const char* ip2proxyTypeName(const std::string& type);      // «VPN-сервис», «выход Tor»…
// Дописывает в кэш тип по базе и флаги VPN/proxy/Tor (зовётся из resolveHostingSecondary).
void ip2proxyApply(std::unordered_map<std::string, IpInfo>& cache,
                   const std::vector<std::string>& ips);
std::string resolveHostToIp(const std::string& host);
void runTraceMode();
void runGeoRttMode();
void runPortCheckMode();
void runPortScanMode();
void runDpiLocatorMode();
void runUdpProbeMode();
void runDnsHonestyMode();   // режим 11: честность DNS (подмена/перехват)
void runTcp16Mode();        // режим 12: тест обрыва на ~16 КБ по хостингам
void runIpOwnerMode();      // режим 13: кому принадлежит IP / домен (геобаза + RDAP)
void runIpOwnerFor(const std::string& input);   // то же без ввода с консоли (для GUI)

// ---- capture.cpp ----
void runCaptureMode();
