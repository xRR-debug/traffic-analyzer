// ip2proxy.cpp — локальная база IP2Proxy (IP2Location.com, файл .BIN): тип
// адреса (VPN-сервис, выход Tor, открытый прокси, дата-центр…) без запросов
// в интернет. Путь — ключ ip2proxy_db в analyzer.ini.
//
// Формат файла описан по открытой библиотеке ip2proxy-c (MIT):
//   заголовок: [0] тип базы (PX1…PX12), [1] число колонок, [2..4] год-2000,
//     месяц, день; дальше uint32 little-endian: [5] строк IPv4, [9] начало
//     IPv4, [13] строк IPv6, [17] начало IPv6, [21] индекс IPv4, [25] индекс
//     IPv6; [29] код продукта (2 — IP2Proxy). Эти адреса считаются с единицы.
//   строка IPv4: ip_from (4 байта) и (колонок − 1) указателей по 4 байта;
//     ip_to строки — это ip_from следующей. У IPv6 ip_from — 16 байт.
//   указатель (от нуля) ведёт на строку: байт длины + текст.
//   индекс: по старшим 16 битам адреса — пара uint32 (low, high) номеров строк.
#include "analyzer_internal.h"

namespace {

// Номер колонки поля по типу базы (1..12); 0 — в этом типе поля нет.
// Колонка 1 — сам ip_from, поэтому указатель поля P лежит на 4 * (P − 2)
// от начала данных строки.
const uint8_t kColCountry[13]  = {0, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
const uint8_t kColType[13]     = {0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
const uint8_t kColIsp[13]      = {0, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6, 6};
const uint8_t kColDomain[13]   = {0, 0, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7};
const uint8_t kColUsage[13]    = {0, 0, 0, 0, 0, 0, 8, 8, 8, 8, 8, 8, 8};
const uint8_t kColAsn[13]      = {0, 0, 0, 0, 0, 0, 0, 9, 9, 9, 9, 9, 9};
const uint8_t kColAs[13]       = {0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 10, 10, 10};
const uint8_t kColLastSeen[13] = {0, 0, 0, 0, 0, 0, 0, 0, 11, 11, 11, 11, 11};
const uint8_t kColThreat[13]   = {0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 12, 12, 12};
const uint8_t kColProvider[13] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 13, 13};

struct Db {
    FILE* f = nullptr;
    uint8_t type = 0, cols = 0, year = 0, month = 0, day = 0;
    uint32_t count4 = 0, base4 = 0, count6 = 0, base6 = 0, index4 = 0, index6 = 0;
};

std::mutex g_mx;
Db g_db;
std::string g_openedPath;     // для какого пути пробовали открыть (смена ini — переоткрыть)
std::string g_err;            // почему не открылась ("" — открыта или не задана)
bool g_errShown = false;

uint32_t le32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Прочитать до n байт с позиции pos (от нуля). Возвращает, сколько прочитано.
size_t readAt(uint64_t pos, uint8_t* buf, size_t n) {
#ifdef _WIN32
    if (_fseeki64(g_db.f, (long long)pos, SEEK_SET) != 0) return 0;
#else
    if (fseeko(g_db.f, (off_t)pos, SEEK_SET) != 0) return 0;
#endif
    return fread(buf, 1, n, g_db.f);
}

std::string readStr(uint32_t pos) {
    uint8_t b[256];
    size_t got = readAt(pos, b, sizeof(b));
    if (got == 0) return "";
    size_t len = std::min<size_t>(b[0], got - 1);
    return std::string((const char*)b + 1, len);
}

void closeLocked() {
    if (g_db.f) fclose(g_db.f);
    g_db = Db();
}

// Открывает базу по текущему cfg().ip2proxyDb. true — база готова.
bool ensureOpenLocked() {
    const std::string want = cfg().ip2proxyDb;   // копия: «Перечитать настройки» заменяет cfg()
    if (want == g_openedPath) return g_db.f != nullptr;
    closeLocked();
    g_openedPath = want;
    g_err.clear();
    g_errShown = false;
    if (want.empty()) return false;

    FILE* f = ufopen(want, "rb");
    if (!f) { g_err = "не открывается файл " + want; return false; }
    uint8_t h[64] = {0};
    size_t got = fread(h, 1, sizeof(h), f);
    auto fail = [&](const std::string& why) { fclose(f); g_err = why + " (" + want + ")"; return false; };
    if (got >= 2 && h[0] == 'P' && h[1] == 'K')
        return fail("это ZIP-архив — распакуйте из него файл .BIN");
    if (got < 35) return fail("файл слишком короткий для базы IP2Proxy");
    Db d;
    d.type = h[0]; d.cols = h[1]; d.year = h[2]; d.month = h[3]; d.day = h[4];
    d.count4 = le32(h + 5);  d.base4 = le32(h + 9);
    d.count6 = le32(h + 13); d.base6 = le32(h + 17);
    d.index4 = le32(h + 21); d.index6 = le32(h + 25);
    const uint8_t product = h[29];
    if (product == 1)
        return fail("это база IP2Location (геобаза), а нужна IP2Proxy");
    // старые базы (до 2021 г.) кода продукта не имели — как в библиотеке
    if (!(product == 2 || (product == 0 && d.year <= 20)))
        return fail("файл не похож на базу IP2Proxy .BIN");
    if (d.type < 1 || d.type > 12)
        return fail("неизвестный тип базы PX" + std::to_string(d.type) + " — нужна новая версия программы");
    if (d.cols < 2 || d.cols > 40 || d.count4 == 0 || d.base4 == 0)
        return fail("повреждённый заголовок базы IP2Proxy");
    d.f = f;
    g_db = d;
    return true;
}

std::string fieldAt(const uint8_t* row, const uint8_t* table) {
    uint8_t col = table[g_db.type];
    if (col < 2 || col > g_db.cols) return "";
    return readStr(le32(row + 4 * (col - 2)));
}

void fillRec(const uint8_t* row, Ip2ProxyRec& r) {
    r.country = fieldAt(row, kColCountry);
    if (r.country.empty() || r.country == "-") { r.type = "-"; return; }   // в базе, но не прокси
    r.type = kColType[g_db.type] ? fieldAt(row, kColType) : std::string("?");
    if (r.type.empty()) r.type = "?";
    r.isp      = fieldAt(row, kColIsp);
    r.domain   = fieldAt(row, kColDomain);
    r.usage    = fieldAt(row, kColUsage);
    r.asn      = fieldAt(row, kColAsn);
    r.as       = fieldAt(row, kColAs);
    r.lastSeen = fieldAt(row, kColLastSeen);
    r.threat   = fieldAt(row, kColThreat);
    r.provider = fieldAt(row, kColProvider);
    for (std::string* s : { &r.isp, &r.domain, &r.usage, &r.asn, &r.as, &r.lastSeen, &r.threat, &r.provider })
        if (*s == "-") s->clear();
}

// Номера строк [low, high] для двоичного поиска: по индексу, если он есть.
void indexRange(uint32_t index, uint32_t key16, uint32_t count, uint32_t& low, uint32_t& high) {
    low = 0; high = count;
    if (!index) return;
    uint8_t b[8];
    if (readAt((uint64_t)index - 1 + (uint64_t)key16 * 8, b, 8) != 8) return;
    uint32_t lo = le32(b), hi = le32(b + 4);
    if (hi > count) hi = count;
    // битый индекс — ищем по всей таблице, а не молча «не нашли»
    if (lo > hi) return;
    low = lo; high = hi;
}

bool lookup4Locked(uint32_t ip, Ip2ProxyRec& r) {
    if (ip == 0xFFFFFFFFu) ip--;
    const uint32_t rowSize = (uint32_t)g_db.cols * 4;
    uint32_t low, high;
    indexRange(g_db.index4, ip >> 16, g_db.count4, low, high);
    uint8_t buf[40 * 4 + 4];
    while (low <= high) {
        uint32_t mid = low + (high - low) / 2;
        uint64_t off = (uint64_t)g_db.base4 - 1 + (uint64_t)mid * rowSize;
        if (readAt(off, buf, rowSize + 4) != rowSize + 4) return false;
        uint32_t from = le32(buf), to = le32(buf + rowSize);
        if (ip >= from && ip < to) { fillRec(buf + 4, r); return true; }
        if (ip < from) { if (mid == 0) break; high = mid - 1; }
        else low = mid + 1;
    }
    return false;
}

// В файле 128-битный адрес лежит little-endian — разворачиваем для memcmp.
void be128(const uint8_t* le, uint8_t* be) { for (int i = 0; i < 16; i++) be[i] = le[15 - i]; }

bool lookup6Locked(const uint8_t ip[16], Ip2ProxyRec& r) {
    if (!g_db.count6 || !g_db.base6) return false;      // база только IPv4
    const uint32_t rowSize = (uint32_t)g_db.cols * 4 + 12;
    uint32_t low, high;
    indexRange(g_db.index6, ((uint32_t)ip[0] << 8) | ip[1], g_db.count6, low, high);
    uint8_t buf[40 * 4 + 12 + 16];
    while (low <= high) {
        uint32_t mid = low + (high - low) / 2;
        uint64_t off = (uint64_t)g_db.base6 - 1 + (uint64_t)mid * rowSize;
        if (readAt(off, buf, rowSize + 16) != rowSize + 16) return false;
        uint8_t from[16], to[16];
        be128(buf, from);
        be128(buf + rowSize, to);
        int cf = memcmp(ip, from, 16);
        if (cf >= 0 && memcmp(ip, to, 16) < 0) { fillRec(buf + 16, r); return true; }
        if (cf < 0) { if (mid == 0) break; high = mid - 1; }
        else low = mid + 1;
    }
    return false;
}

bool lookupLocked(const std::string& ipStr, Ip2ProxyRec& r) {
    r = Ip2ProxyRec();
    uint8_t a[16];
    if (inet_pton(AF_INET, ipStr.c_str(), a) == 1)
        return lookup4Locked(((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | a[3], r);
    if (inet_pton(AF_INET6, ipStr.c_str(), a) != 1) return false;
    // IPv4 внутри IPv6 (как в библиотеке): ::ffff:a.b.c.d, 6to4 2002::/16, Teredo 2001:0::/32
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (memcmp(a, mapped, 12) == 0)
        return lookup4Locked(((uint32_t)a[12] << 24) | ((uint32_t)a[13] << 16) | ((uint32_t)a[14] << 8) | a[15], r);
    if (a[0] == 0x20 && a[1] == 0x02)
        return lookup4Locked(((uint32_t)a[2] << 24) | ((uint32_t)a[3] << 16) | ((uint32_t)a[4] << 8) | a[5], r);
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0 && a[3] == 0)
        return lookup4Locked(~(((uint32_t)a[12] << 24) | ((uint32_t)a[13] << 16) | ((uint32_t)a[14] << 8) | a[15]), r);
    return lookup6Locked(a, r);
}

} // namespace

bool ip2proxyEnabled() { return !cfg().ip2proxyDb.empty(); }

bool ip2proxyLookup(const std::string& ip, Ip2ProxyRec& r) {
    std::lock_guard<std::mutex> lk(g_mx);
    if (!ensureOpenLocked()) return false;
    return lookupLocked(ip, r);
}

std::string ip2proxyDbInfo() {
    std::lock_guard<std::mutex> lk(g_mx);
    if (!ensureOpenLocked()) return g_err;
    char b[96];
    snprintf(b, sizeof(b), "PX%d%s, от %04d-%02d-%02d", g_db.type, g_db.count6 ? "" : " (только IPv4)",
             2000 + g_db.year, g_db.month, g_db.day);
    return b;
}

const char* ip2proxyTypeName(const std::string& t) {
    if (t == "VPN") return "VPN-сервис";
    if (t == "TOR") return "выход Tor";
    if (t == "PUB") return "открытый прокси";
    if (t == "WEB") return "веб-прокси";
    if (t == "DCH") return "хостинг / дата-центр";
    if (t == "SES") return "поисковый робот";
    if (t == "RES") return "резидентный прокси (домашний адрес, сдаётся под прокси)";
    if (t == "CPN") return "сеть приватности (iCloud Private Relay и т.п.)";
    if (t == "EPN") return "корпоративная частная сеть (Zscaler и т.п.)";
    if (t == "AIC") return "ИИ-краулер";
    if (t == "?")   return "есть в базе прокси (тип в базе PX1 не хранится)";
    if (t == "-")   return "не прокси";
    return "";
}

// Засчитываем в вердикт только прямые признаки: VPN, Tor, открытый/веб-прокси.
// DCH — только «хостинг» (как флаг hosting от ip-api). RES/CPN/EPN — лишь
// показываем: у резидентных прокси адрес домашний, а Private Relay / Zscaler —
// не «VPN абонента» для техподдержки.
void ip2proxyApply(std::unordered_map<std::string, IpInfo>& cache,
                   const std::vector<std::string>& ips) {
    std::lock_guard<std::mutex> lk(g_mx);
    if (!ensureOpenLocked()) {
        if (!g_err.empty() && !g_errShown) {
            std::cout << "  IP2Proxy: " << g_err << " — проверка по базе пропущена\n";
            g_errShown = true;
        }
        return;
    }
    size_t checked = 0, flagged = 0, added = 0;
    for (const auto& ip : ips) {
        if (isPrivateIp(ip)) continue;
        Ip2ProxyRec r;
        if (!lookupLocked(ip, r)) continue;
        checked++;
        auto it = cache.find(ip);
        if (it == cache.end()) {
            // онлайн-сервисы не ответили — страну/провайдера берём из базы
            if (r.type == "-") continue;
            IpInfo ni;
            ni.country = r.country;
            ni.org = !r.as.empty() ? r.as : (!r.isp.empty() ? r.isp : "-");
            ni.asn = r.asn.empty() ? "-" : "AS" + r.asn;
            it = cache.emplace(ip, ni).first;
            added++;
        }
        IpInfo& i = it->second;
        i.pxType = r.type;
        const bool vpn = r.type == "VPN", tor = r.type == "TOR",
                   proxy = r.type == "PUB" || r.type == "WEB";
        if (vpn || tor || proxy || r.type == "DCH") i.hosting = true;
        if (!(vpn || tor || proxy)) continue;
        // CDN и своя сеть — без флагов (как у ipapi.is, который их не спрашивает)
        if (looksCdnOrg(i.org) || isOwnIspOrg(i.org, i.asn)) continue;
        i.isVpn = i.isVpn || vpn;
        i.isTor = i.isTor || tor;
        i.isProxy = i.isProxy || proxy;
        if (i.flagSrc.empty()) i.flagSrc = "IP2Proxy";
        else if (i.flagSrc.find("IP2Proxy") == std::string::npos) i.flagSrc += " + IP2Proxy";
        flagged++;
    }
    std::cout << "  IP2Proxy (PX" << (int)g_db.type << "): проверено по базе " << checked
              << " адрес(ов), VPN/Tor/прокси " << flagged;
    if (added) std::cout << ", только по базе (сервисы не ответили) " << added;
    std::cout << "\n";
}
