// config.cpp — значения по умолчанию и загрузка analyzer.ini.
#include <string>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#pragma comment(lib, "advapi32.lib")   // реестр: запомненная своя сеть
typedef std::wstring NativePath;   // пути Windows — UTF-16
#define NP(s) L##s
#else
#include <mach-o/dyld.h>           // _NSGetExecutablePath
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>                // getcwd
typedef std::string NativePath;    // macOS — UTF-8
#define NP(s) s
#endif

#include "config.h"

#include <atomic>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cwchar>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <utility>
#ifndef _WIN32
#include <sys/stat.h>              // mkdir
#endif

namespace {

void setDefaults(AppConfig& c) {
    c.vpnUdpPorts = {
        {51820, "WireGuard"},        {51821, "WireGuard/Amnezia"}, {55555, "AmneziaWG"},
        {500,   "IKE/IPsec"},        {4500,  "IPsec NAT-T"},
        {1194,  "OpenVPN(udp)"},     {1195,  "OpenVPN(udp)"},      {1701,  "L2TP"},
        {4790,  "OpenConnect/ESP"},  {8388,  "Shadowsocks(udp)"},
        {8443,  "Hysteria2/QUIC"},   {36712, "Hysteria"},          {1935,  "Hysteria"},
        {2408,  "WARP/WireGuard"},   {1637,  "WARP"},
    };
    // 9000 («Trojan/alt») намеренно нет: это и PHP-FPM, и игровые серверы, и
    // десятки веб-панелей — порт сам по себе VPN не означает.
    c.vpnTcpPorts = {
        {1194,  "OpenVPN(tcp)"},     {1195,  "OpenVPN(tcp)"},      {1723,  "PPTP"},
        {8388,  "Shadowsocks"},      {8389,  "Shadowsocks"},
        {10808, "v2ray/xray SOCKS"}, {10809, "v2ray/xray HTTP"},
    };
    c.proxyPorts = {
        {1080,  "SOCKS5"},           {3128,  "Squid/HTTP-proxy"},  {8080,  "HTTP-proxy"},
        {8118,  "Privoxy"},          {8123,  "Polipo-proxy"},      {8888,  "HTTP-proxy-alt"},
        {9050,  "Tor"},              {9051,  "Tor-control"},
        {4433,  "XTLS/Reality"},     {4443,  "XTLS/Reality"},
        {10810, "v2ray/xray"},       {41641, "Tailscale"},
    };
    // классические сервисные порты (SSH/HTTP/почта/FTP/БД/RDP/...)
    c.scanServicePorts = {21,22,23,25,53,80,110,111,135,139,143,389,443,445,
        465,587,636,993,995,1433,1521,2049,3306,3389,5432,5900,5985,5986,6379,
        8000,8080,8443,8888,9000,9090,9200,11211,27017};
    // типичные VPN/туннельные порты
    c.scanVpnPorts = {500,1194,1195,1637,1701,1723,4500,2408,36712,
        51820,51821,55555,8388,8443,4433,4443,2052,2053,2082,2083,2086,2087,
        2095,2096,9000};
    c.scanTopPorts = {21,22,23,25,53,80,110,143,443,445,465,587,993,995,
        1194,1195,1701,1723,1935,2052,2053,2082,2083,2086,2087,2095,2096,2121,2122,
        2408,3128,3389,3724,4244,4500,5060,5938,6379,8000,8080,8388,8443,8800,
        9000,10000,18080,19132,27015,27036,28015,30000,30120,36712,44405,
        500,1637,51820,51821,55555,1080,3306,5432,5900,8089};
    // Своя сеть оператора не зашита: AS определяется кнопкой «Определить» в
    // настройках и запоминается (ownIspDetect, network.cpp); own_isp_* в ini — вручную.
    // Белый список VPN. Облака (Google Cloud AS396982, Yandex Cloud AS200350,
    // VK Cloud) сюда намеренно не входят: там стоят обычные VPS, в том числе с VPN.
    c.vpnWhitelistDomains = {
        // Google / YouTube
        "google.com", "google.ru", "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
        // (googleusercontent.com нет: *.bc.googleusercontent.com — имена VM Google Cloud)
        "ggpht.com", "gstatic.com", "googleapis.com", "gvt1.com",
        // Википедия
        "wikipedia.org", "wikimedia.org", "wikidata.org", "wiktionary.org",
        // VK, ОК, Mail.ru, MAX
        "vk.com", "vk.ru", "vk.me", "userapi.com", "vkuser.net", "vkuseraudio.net",
        "vkuservideo.net", "vk-cdn.net", "mycdn.me", "ok.ru", "mail.ru", "imgsmail.ru",
        "max.ru", "oneme.ru",
        // госсервисы
        "gosuslugi.ru", "gov.ru", "mos.ru",
        // Яндекс
        "yandex.ru", "yandex.net", "yandex.com", "ya.ru", "yastatic.net", "dzen.ru",
        // крупные российские сервисы и банки
        "rutube.ru", "ozon.ru", "wildberries.ru", "wb.ru", "avito.ru",
        "sberbank.ru", "sber.ru", "tbank.ru", "tinkoff.ru", "vtb.ru",
    };
    c.vpnWhitelistAsns = {
        "15169",   // Google
        "36040",   // YouTube
        "43515",   // YouTube (Google)
        "14907",   // Wikimedia Foundation
        "47541",   // VKontakte
        "47764",   // VK (Mail.ru)
        "13238",   // Яндекс
    };
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && ::isspace((unsigned char)s[a])) ++a;
    while (b > a && ::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

std::string lower(std::string s) {
    for (auto& ch : s) ch = (char)::tolower((unsigned char)ch);
    return s;
}

std::vector<std::string> splitList(const std::string& v) {
    std::vector<std::string> out;
    std::stringstream ss(v);
    std::string tok;
    while (std::getline(ss, tok, ',')) {
        tok = trim(tok);
        if (!tok.empty()) out.push_back(tok);
    }
    return out;
}

bool parseLL(const std::string& v, long long& out) {
    if (v.empty()) return false;
    char* end = nullptr;
    long long x = std::strtoll(v.c_str(), &end, 10);
    if (!end || *end != '\0' || x < 0) return false;
    out = x;
    return true;
}

bool validPort(long long p) { return p >= 1 && p <= 65535; }

// «51820:WireGuard, 1194:OpenVPN» -> map. Пустое значение — пустая таблица.
bool parsePortMap(const std::string& v, std::map<int, std::string>& out) {
    std::map<int, std::string> m;
    for (const auto& item : splitList(v)) {
        size_t colon = item.find(':');
        std::string num = trim(item.substr(0, colon));
        std::string name = colon == std::string::npos ? "" : trim(item.substr(colon + 1));
        long long p;
        if (!parseLL(num, p) || !validPort(p)) return false;
        m[(int)p] = name.empty() ? ("port " + num) : name;
    }
    out.swap(m);
    return true;
}

bool parsePortList(const std::string& v, std::vector<int>& out) {
    std::vector<int> l;
    for (const auto& item : splitList(v)) {
        long long p;
        if (!parseLL(item, p) || !validPort(p)) return false;
        l.push_back((int)p);
    }
    out.swap(l);
    return true;
}

// Одна строка «ключ = значение». Имена ключей не зависят от секции —
// [секции] в файле только для удобства чтения.
// iniDir — папка, откуда прочитан analyzer.ini (UTF-8, со слешем на конце).
void applyKey(AppConfig& c, const std::string& key, const std::string& val,
              const std::string& where, const std::string& iniDir) {
    auto bad = [&] { c.warnings.push_back(where + ": не разобрано значение «" + key + "»"); };
    // Отрицательные и переполняющиеся значения отвергаем: tail_ms = -1 снимал
    // бы отсечку хвоста дампа, а x * mul мог уйти за LLONG_MAX.
    auto num = [&](long long& dst, long long mul) {
        long long x;
        if (parseLL(val, x) && x >= 0 && x <= LLONG_MAX / mul) dst = x * mul; else bad();
    };
    // lo — нижняя граница: у счётчиков-порогов 0 выключил бы проверку
    // (split_min_conns = 0 — раздел «обход DPI» в каждом отчёте).
    auto inum = [&](int& dst, int lo) {
        long long x;
        if (parseLL(val, x) && x >= lo && x <= 1000000) dst = (int)x; else bad();
    };
    // Потолки баллов VPN: сверху ограничены порогами вердикта (config.h).
    // Слишком большое значение не отвергаем, а урезаем с предупреждением.
    auto capped = [&](int& dst, int hi, const char* why) {
        long long x;
        if (!parseLL(val, x) || x < 0 || x > 1000000) { bad(); return; }
        if (x > hi) {
            c.warnings.push_back(where + ": " + key + " = " + std::to_string(x) +
                                 " — больше " + std::to_string(hi) + " нельзя (" + why +
                                 "), взято " + std::to_string(hi));
            x = hi;
        }
        dst = (int)x;
    };

    // Значение ключа не сохраняем и не выводим — только просим убрать строку.
    if      (key == "probeops_api_key")
        c.warnings.push_back(where + ": ключ probeops_api_key больше не нужен (режим 6 "
                             "работает через Globalping без ключа) — удалите строку");
    else if (key == "auto_resolve") {
        if (val == "1" || val == "true" || val == "yes")     c.autoResolve = true;
        else if (val == "0" || val == "false" || val == "no") c.autoResolve = false;
        else bad();
    }
    else if (key == "ip2proxy_db") {
        // относительный путь — от папки, где лежит сам analyzer.ini (рядом с
        // программой или в текущем каталоге), чтобы база рядом с ini находилась
#ifdef _WIN32
        const bool abs = (val.size() >= 2 && val[1] == ':') || (!val.empty() && (val[0] == '\\' || val[0] == '/'));
#else
        const bool abs = !val.empty() && val[0] == '/';
#endif
        c.ip2proxyDb = (val.empty() || abs) ? val : iniDir + val;
    }
    else if (key == "tail_ms")              num(c.tailUs, 1000);
    else if (key == "freeze_min_kb")        num(c.freezeMinBytes, 1024);
    else if (key == "freeze_max_kb")        num(c.freezeMaxBytes, 1024);
    else if (key == "freeze_silence_ms")    num(c.freezeSilenceUs, 1000);
    else if (key == "freeze_later_pkts")    inum(c.freezeLaterPkts, 1);
    else if (key == "tspu_min_syn")         inum(c.tspuMinSyn, 1);
    else if (key == "split_min_conns")      inum(c.splitMinConns, 1);
    else if (key == "shape_cap")            capped(c.shapeCap, kShapeCapMax,
                                                   "одна форма трафика дала бы «ВЕРОЯТНО VPN»");
    else if (key == "flow_score_cap")       capped(c.flowScoreCap, kFlowScoreCapMax,
                                                   "больше потоковые признаки набрать не могут");
    else if (key == "long_flow_sec")        num(c.longFlowUs, 1000000);
    else if (key == "long_flow_min_in_kb")  num(c.longFlowMinIn, 1024);
    else if (key == "long_flow_min_out_kb") num(c.longFlowMinOut, 1024);
    else if (key == "vpn_udp_ports")        { if (!parsePortMap(val, c.vpnUdpPorts)) bad(); }
    else if (key == "vpn_tcp_ports")        { if (!parsePortMap(val, c.vpnTcpPorts)) bad(); }
    else if (key == "proxy_ports")          { if (!parsePortMap(val, c.proxyPorts)) bad(); }
    else if (key == "scan_top_ports")       { if (!parsePortList(val, c.scanTopPorts)) bad(); }
    else if (key == "scan_service_ports")   { if (!parsePortList(val, c.scanServicePorts)) bad(); }
    else if (key == "scan_vpn_ports")       { if (!parsePortList(val, c.scanVpnPorts)) bad(); }
    else if (key == "own_isp_org") {
        c.ownIspOrgKeywords.clear();
        for (const auto& s : splitList(val)) c.ownIspOrgKeywords.push_back(lower(s));
    }
    else if (key == "own_isp_asn") {
        c.ownIspAsns.clear();
        for (const auto& s : splitList(val)) c.ownIspAsns.push_back(lower(s));
        c.ownIspAsnFromIni = !c.ownIspAsns.empty();   // пустое значение — снова автоматически
    }
    // Белый список VPN: значение заменяет встроенный список; «+» в начале —
    // дополняет его («vpn_whitelist_domains = + example.ru, example.com»).
    else if (key == "vpn_whitelist_domains" || key == "vpn_whitelist_asn") {
        std::vector<std::string>& dst = key == "vpn_whitelist_asn" ? c.vpnWhitelistAsns
                                                                   : c.vpnWhitelistDomains;
        std::string v = val;
        if (!v.empty() && v[0] == '+') v.erase(0, 1);
        else dst.clear();
        for (auto s : splitList(v)) {
            s = lower(s);
            while (!s.empty() && (s.back() == '.')) s.pop_back();
            if (!s.empty() && s[0] == '.') s.erase(0, 1);
            if (!s.empty()) dst.push_back(s);
        }
    }
    else c.warnings.push_back(where + ": неизвестный ключ «" + key + "»");
}

bool readIni(AppConfig& c, const NativePath& path, const std::string& shownPath,
             const std::string& iniDir) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) return false;
    std::string line;
    int ln = 0;
    while (std::getline(f, line)) {
        ++ln;
        if (ln == 1 && line.size() >= 3 && (unsigned char)line[0] == 0xEF &&
            (unsigned char)line[1] == 0xBB && (unsigned char)line[2] == 0xBF)
            line.erase(0, 3);                                   // UTF-8 BOM
        line = trim(line);
        // Комментарии — только целой строкой: в ключах API бывают ';' и '#'.
        if (line.empty() || line[0] == '#' || line[0] == ';' || line[0] == '[') continue;
        size_t eq = line.find('=');
        std::string where = shownPath + ":" + std::to_string(ln);
        if (eq == std::string::npos) {
            c.warnings.push_back(where + ": строка без «=»");
            continue;
        }
        std::string key = lower(trim(line.substr(0, eq)));
        std::string val = trim(line.substr(eq + 1));
        if (val.size() >= 2 && ((val.front() == '"' && val.back() == '"') ||
                                (val.front() == '\'' && val.back() == '\'')))
            val = val.substr(1, val.size() - 2);
        applyKey(c, key, val, where, iniDir);
    }
    c.loadedFrom = shownPath;
    return true;
}

#ifdef _WIN32
std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring exeDir() {
    wchar_t buf[MAX_PATH * 4];
    DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0])) return {};
    std::wstring p(buf, n);
    size_t slash = p.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : p.substr(0, slash + 1);
}

// Текущий каталог со слешем на конце: пути из ini, найденного здесь, фиксируем
// сразу — диалог открытия файла может потом сменить текущий каталог.
std::wstring cwdDir() {
    wchar_t buf[MAX_PATH * 4];
    DWORD n = GetCurrentDirectoryW((DWORD)(sizeof(buf) / sizeof(buf[0])), buf);
    if (n == 0 || n >= sizeof(buf) / sizeof(buf[0])) return {};
    std::wstring p(buf, n);
    if (p.back() != L'\\' && p.back() != L'/') p += L'\\';
    return p;
}
#else
std::string narrow(const std::string& s) { return s; }

std::string exeDir() {
    char buf[PATH_MAX * 2];
    uint32_t sz = sizeof(buf);
    if (_NSGetExecutablePath(buf, &sz) != 0) return {};
    char real[PATH_MAX];
    std::string p = realpath(buf, real) ? real : buf;   // без симлинков и «..»
    size_t slash = p.find_last_of('/');
    return slash == std::string::npos ? std::string() : p.substr(0, slash + 1);
}

std::string cwdDir() {
    char buf[PATH_MAX];
    if (!getcwd(buf, sizeof(buf))) return {};
    std::string p(buf);
    if (p.empty() || p.back() != '/') p += '/';
    return p;
}
#endif

// Локальная статика, а не глобальная переменная: не зависит от порядка
// инициализации единиц трансляции.
AppConfig& store() {
    static AppConfig c = [] { AppConfig d; setDefaults(d); return d; }();
    return c;
}

} // namespace

const AppConfig& cfg() { return store(); }

std::string exeDirUtf8() { return narrow(exeDir()); }

void loadConfig() {
    AppConfig c;
    setDefaults(c);

    // Сначала рядом с exe, потом в текущем каталоге (запуск из VS / из папки с дампами).
    NativePath dir = exeDir();
    bool found = false;
    if (!dir.empty())
        found = readIni(c, dir + NP("analyzer.ini"), narrow(dir + NP("analyzer.ini")), narrow(dir));
    if (!found)
        readIni(c, NP("analyzer.ini"), "analyzer.ini", narrow(cwdDir()));

    if (c.freezeMinBytes > c.freezeMaxBytes) {
        c.warnings.push_back("freeze_min_kb больше freeze_max_kb — оставлены значения по умолчанию");
        AppConfig d;
        c.freezeMinBytes = d.freezeMinBytes;
        c.freezeMaxBytes = d.freezeMaxBytes;
    }

    store() = std::move(c);

    // Запомненная своя сеть (кнопка «Определить» в настройках) — без сети.
    OwnIspAuto s;
    // strtoull: unsigned long на Windows 32-битный, переполнение там не отличить
    const unsigned long long n = strtoull(rememberedGet("OwnIspAsn").c_str(), nullptr, 10);
    if (n > 0 && n <= 0xFFFFFFFFull) {
        s.asn = (unsigned)n;
        s.name = rememberedGet("OwnIspName");
        s.status = "запомнена";
    }
    ownIspAutoSet(s);
}

// ------------------------------------------------------------------
// Запомненные значения между запусками
// ------------------------------------------------------------------
// Windows — строковые значения в том же ключе реестра, что и настройки GUI.
// macOS — отдельный state.ini: gui.ini GUI переписывает целиком из памяти и
// затёр бы чужие строки.
namespace {
std::mutex& rememberedMutex() { static std::mutex* m = new std::mutex; return *m; }   // см. ниже

#ifdef _WIN32
const wchar_t kStateRegKey[] = L"Software\\MARYNONET\\TrafficAnalyzer";

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n > 0 ? n : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
#else
std::string statePath() {
    const char* home = getenv("HOME");
    if (!home || !*home) return "";
    return std::string(home) + "/Library/Application Support/TrafficAnalyzer/state.ini";
}

std::map<std::string, std::string> readState() {
    std::map<std::string, std::string> m;
    std::ifstream in(statePath());
    std::string line;
    while (std::getline(in, line)) {
        const size_t eq = line.find('=');
        if (eq != std::string::npos && eq > 0) m[line.substr(0, eq)] = line.substr(eq + 1);
    }
    return m;
}
#endif
} // namespace

std::string rememberedGet(const char* name) {
    std::lock_guard<std::mutex> lk(rememberedMutex());
#ifdef _WIN32
    const std::wstring wn = widen(name);
    DWORD sz = 0;
    if (RegGetValueW(HKEY_CURRENT_USER, kStateRegKey, wn.c_str(), RRF_RT_REG_SZ, nullptr, nullptr,
                     &sz) != ERROR_SUCCESS || sz < sizeof(wchar_t) || sz > 64 * 1024)
        return {};
    std::wstring s(sz / sizeof(wchar_t), L'\0');
    if (RegGetValueW(HKEY_CURRENT_USER, kStateRegKey, wn.c_str(), RRF_RT_REG_SZ, nullptr, &s[0],
                     &sz) != ERROR_SUCCESS)
        return {};
    s.resize(wcsnlen(s.c_str(), s.size()));
    return narrow(s);
#else
    const auto m = readState();
    const auto it = m.find(name);
    return it == m.end() ? std::string() : it->second;
#endif
}

bool rememberedSet(const char* name, const std::string& v) {
    std::lock_guard<std::mutex> lk(rememberedMutex());
#ifdef _WIN32
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kStateRegKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k,
                        nullptr) != ERROR_SUCCESS)
        return false;
    const std::wstring wn = widen(name), wv = widen(v);
    LSTATUS rc;
    if (wv.empty()) {
        rc = RegDeleteValueW(k, wn.c_str());
        if (rc == ERROR_FILE_NOT_FOUND) rc = ERROR_SUCCESS;   // и так нет
    } else {
        rc = RegSetValueExW(k, wn.c_str(), 0, REG_SZ, (const BYTE*)wv.c_str(),
                            (DWORD)((wv.size() + 1) * sizeof(wchar_t)));
    }
    RegCloseKey(k);
    return rc == ERROR_SUCCESS;
#else
    const std::string path = statePath();
    if (path.empty()) return false;
    auto m = readState();
    std::string clean = v;                      // значение — одна строка
    for (auto& ch : clean) if (ch == '\n' || ch == '\r') ch = ' ';
    if (clean.empty()) m.erase(name); else m[name] = clean;
    mkdir(path.substr(0, path.rfind('/')).c_str(), 0755);
    std::ofstream out(path, std::ios::trunc);
    for (const auto& kv : m) out << kv.first << '=' << kv.second << '\n';
    out.close();
    return !out.fail();
#endif
}

// ------------------------------------------------------------------
// Своя сеть, определённая автоматически
// ------------------------------------------------------------------
// Не разрушаются при выходе: фоновая задача «Определить» может
// закончиться, когда программа уже закрывается.
namespace {
std::mutex& ownIspMutex() { static std::mutex* m = new std::mutex; return *m; }
OwnIspAuto& ownIspState() { static OwnIspAuto* s = new OwnIspAuto; return *s; }
std::atomic<unsigned> g_ownIspAsn{0};
} // namespace

OwnIspAuto ownIspAuto() {
    std::lock_guard<std::mutex> lk(ownIspMutex());
    return ownIspState();
}

unsigned ownIspAutoAsn() { return g_ownIspAsn.load(std::memory_order_relaxed); }

void ownIspAutoSet(const OwnIspAuto& v) {
    std::lock_guard<std::mutex> lk(ownIspMutex());
    ownIspState() = v;
    g_ownIspAsn.store(v.asn, std::memory_order_relaxed);
}
