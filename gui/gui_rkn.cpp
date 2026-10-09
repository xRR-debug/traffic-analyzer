// gui_rkn.cpp — вкладка «Проверка РКН»: ручная проверка домена, IP-адреса,
// подсети или автономной системы через cheburcheck.ru.
//
// API сайта неофициальное (документации нет, сверено с версией 1.4.x):
//   GET /api/v1/check?target=X — проверка по спискам: реестр РКН,
//       заблокированные подсети, диапазоны CDN, гео, белый список, жалобы;
//   GET /api/v1/probe/<id>     — поток событий (SSE) от сканеров в регионах
//       России: started → result (по одному на сканер) → done;
//   GET /api/v1/status         — размер и дата обновления базы.
// Вердикты и подписи — как на сайте. Поля, которых программа не знает,
// всё равно видны в разделах «Все поля ответа» и «Сырые данные».
//
// Приватность: запрос уходит ТОЛЬКО по кнопке (или пункту меню соединения)
// и содержит только введённую цель. Из дампа сама вкладка ничего не берёт.
// Проверка идёт в своём потоке и не занимает очередь фоновых задач.
#include "gui_app.h"
#include <functional>

namespace {

using Clock = std::chrono::steady_clock;
double secsSince(Clock::time_point t) {
    return std::chrono::duration<double>(Clock::now() - t).count();
}

GuiColors K;                              // цвета темы текущего кадра
ImVec4 withAlpha(ImVec4 c, float a) { c.w *= a; return c; }

const size_t kMaxBody = 32u << 20;        // ответ по AS бывает на мегабайты
const size_t kMaxShow = 1u << 20;         // столько текста JSON показываем в окне

// ------------------------------------------------------------------
// JSON: небольшой разборщик в дерево (порядок ключей как в ответе)
// ------------------------------------------------------------------
struct JVal {
    enum Type : uint8_t { NUL, BOOL, NUM, STR, ARR, OBJ };
    Type t = NUL;
    bool b = false;
    double n = 0;
    std::string s;                        // строка; у числа — запись как в ответе
    std::vector<std::string> keys;        // ключи объекта
    std::vector<JVal> items;              // элементы массива / значения объекта

    const JVal& operator[](const char* k) const {
        static const JVal none;
        if (t == OBJ)
            for (size_t i = 0; i < keys.size(); i++)
                if (keys[i] == k) return items[i];
        return none;
    }
    bool has(const char* k) const {
        if (t == OBJ)
            for (const auto& x : keys) if (x == k) return true;
        return false;
    }
    size_t size() const { return (t == ARR || t == OBJ) ? items.size() : 0; }
    // строка, число или булево — текстом; остальное — пусто
    std::string str() const {
        switch (t) {
        case STR: case NUM: return s;
        case BOOL: return b ? "true" : "false";
        default: return std::string();
        }
    }
    long long num(long long def = -1) const {
        if (t == NUM) return (long long)n;
        if (t == STR && !s.empty() && isdigit((unsigned char)s[0])) return atoll(s.c_str());
        return def;
    }
    bool truthy() const { return t == BOOL ? b : t == NUM ? n != 0 : false; }
};

bool isScalar(const JVal& v) { return v.t != JVal::ARR && v.t != JVal::OBJ; }
// есть что показать: не null, не пустая строка, не пустой массив/объект
bool filled(const JVal& v) {
    switch (v.t) {
    case JVal::NUL: return false;
    case JVal::STR: return !v.s.empty();
    case JVal::ARR: case JVal::OBJ: return !v.items.empty();
    default: return true;
    }
}

void appendUtf8(std::string& o, unsigned cp) {
    if (cp < 0x80) o += (char)cp;
    else if (cp < 0x800) {
        o += (char)(0xC0 | (cp >> 6));
        o += (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        o += (char)(0xE0 | (cp >> 12));
        o += (char)(0x80 | ((cp >> 6) & 0x3F));
        o += (char)(0x80 | (cp & 0x3F));
    } else {
        o += (char)(0xF0 | (cp >> 18));
        o += (char)(0x80 | ((cp >> 12) & 0x3F));
        o += (char)(0x80 | ((cp >> 6) & 0x3F));
        o += (char)(0x80 | (cp & 0x3F));
    }
}

int hex4(const char* p) {
    int v = 0;
    for (int i = 0; i < 4; i++) {
        const char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= c - '0';
        else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        else return -1;
    }
    return v;
}

class JParser {
public:
    explicit JParser(const std::string& s) : p_(s.data()), e_(s.data() + s.size()) {}
    bool parse(JVal& v) {
        ws();
        if (!value(v, 0)) return false;
        ws();
        return p_ == e_;
    }

private:
    const char* p_;
    const char* e_;

    void ws() { while (p_ < e_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\n' || *p_ == '\r')) p_++; }
    bool lit(const char* w) {
        const size_t n = strlen(w);
        if ((size_t)(e_ - p_) < n || memcmp(p_, w, n) != 0) return false;
        p_ += n;
        return true;
    }
    bool string(std::string& out) {
        p_++;                                             // открывающая "
        while (p_ < e_) {
            const char c = *p_++;
            if (c == '"') return true;
            if (c != '\\') { out += c; continue; }
            if (p_ >= e_) return false;
            switch (*p_++) {
            case '"':  out += '"'; break;
            case '\\': out += '\\'; break;
            case '/':  out += '/'; break;
            case 'b':  out += '\b'; break;
            case 'f':  out += '\f'; break;
            case 'n':  out += '\n'; break;
            case 'r':  out += '\r'; break;
            case 't':  out += '\t'; break;
            case 'u': {
                if (e_ - p_ < 4) return false;
                int cp = hex4(p_);
                if (cp < 0) return false;
                p_ += 4;
                // суррогатная пара: 😀
                if (cp >= 0xD800 && cp <= 0xDBFF && e_ - p_ >= 6 && p_[0] == '\\' && p_[1] == 'u') {
                    const int lo = hex4(p_ + 2);
                    if (lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        p_ += 6;
                    }
                }
                if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0xFFFD;
                appendUtf8(out, (unsigned)cp);
                break;
            }
            default: return false;
            }
        }
        return false;
    }
    bool value(JVal& v, int depth) {
        if (depth > 64 || p_ >= e_) return false;
        const char c = *p_;
        if (c == '{' || c == '[') {
            const bool obj = c == '{';
            v.t = obj ? JVal::OBJ : JVal::ARR;
            p_++;
            ws();
            if (p_ < e_ && *p_ == (obj ? '}' : ']')) { p_++; return true; }
            for (;;) {
                ws();
                if (obj) {
                    std::string k;
                    if (p_ >= e_ || *p_ != '"' || !string(k)) return false;
                    ws();
                    if (p_ >= e_ || *p_ != ':') return false;
                    p_++;
                    ws();
                    v.keys.push_back(std::move(k));
                }
                v.items.emplace_back();
                if (!value(v.items.back(), depth + 1)) return false;
                ws();
                if (p_ >= e_) return false;
                if (*p_ == ',') { p_++; continue; }
                if (*p_ == (obj ? '}' : ']')) { p_++; return true; }
                return false;
            }
        }
        if (c == '"') { v.t = JVal::STR; return string(v.s); }
        if (lit("true"))  { v.t = JVal::BOOL; v.b = true; return true; }
        if (lit("false")) { v.t = JVal::BOOL; v.b = false; return true; }
        if (lit("null"))  { v.t = JVal::NUL; return true; }
        if (c == '-' || (c >= '0' && c <= '9')) {
            const char* b = p_;
            while (p_ < e_ && ((*p_ >= '0' && *p_ <= '9') || *p_ == '-' || *p_ == '+' ||
                               *p_ == '.' || *p_ == 'e' || *p_ == 'E')) p_++;
            v.t = JVal::NUM;
            v.s.assign(b, p_);
            v.n = strtod(v.s.c_str(), nullptr);
            return true;
        }
        return false;
    }
};

bool parseJson(const std::string& s, JVal& v) {
    v = JVal();
    if (JParser(s).parse(v)) return true;
    v = JVal();
    return false;
}

void jsonQuote(std::string& o, const std::string& s) {
    o += '"';
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += (char)c; }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); o += b; }
        else o += (char)c;
    }
    o += '"';
}

// JSON с отступами; короткие массивы простых значений — в одну строку.
void jsonPretty(const JVal& v, std::string& o, int ind = 0) {
    switch (v.t) {
    case JVal::NUL:  o += "null"; return;
    case JVal::BOOL: o += v.b ? "true" : "false"; return;
    case JVal::NUM:  o += v.s; return;
    case JVal::STR:  jsonQuote(o, v.s); return;
    default: break;
    }
    const bool obj = v.t == JVal::OBJ;
    if (v.items.empty()) { o += obj ? "{}" : "[]"; return; }
    bool flat = !obj && v.items.size() <= 8;
    for (const auto& x : v.items) if (!isScalar(x)) flat = false;
    if (flat) {
        o += '[';
        for (size_t i = 0; i < v.items.size(); i++) {
            if (i) o += ", ";
            jsonPretty(v.items[i], o, ind);
        }
        o += ']';
        return;
    }
    o += obj ? "{\n" : "[\n";
    for (size_t i = 0; i < v.items.size(); i++) {
        o.append((size_t)(ind + 1) * 2, ' ');
        if (obj) { jsonQuote(o, v.keys[i]); o += ": "; }
        jsonPretty(v.items[i], o, ind + 1);
        if (i + 1 < v.items.size()) o += ',';
        o += '\n';
    }
    o.append((size_t)ind * 2, ' ');
    o += obj ? '}' : ']';
}

// Длинный текст — до границы строки не дальше cap, с пометкой.
void capText(std::string& s, size_t cap, const char* note) {
    if (s.size() <= cap) return;
    const size_t cut = s.rfind('\n', cap);
    s.resize(cut == std::string::npos ? cap : cut);
    s += note;
}

// Значение одной строкой: простое как есть, массив/объект — первые элементы.
std::string brief(const JVal& v, size_t maxItems = 12) {
    if (isScalar(v)) return v.t == JVal::NUL ? "—" : v.str();
    const size_t n = v.items.size();
    if (!n) return v.t == JVal::OBJ ? "{}" : "нет";
    std::string o;
    for (size_t i = 0; i < n && i < maxItems; i++) {
        if (i) o += ", ";
        if (v.t == JVal::OBJ) { o += v.keys[i]; o += ": "; }
        const JVal& x = v.items[i];
        if (isScalar(x)) o += x.t == JVal::NUL ? "—" : x.str();
        else if (x.t == JVal::OBJ) o += "{" + brief(x, 4) + "}";
        else o += "[" + std::to_string(x.items.size()) + "]";
    }
    if (n > maxItems) o += ", … (ещё " + std::to_string(n - maxItems) + ")";
    return o;
}

std::string fmtCount(long long v) {
    const std::string s = std::to_string(v < 0 ? -v : v);
    std::string o;
    for (size_t i = 0; i < s.size(); i++) {
        if (i && (s.size() - i) % 3 == 0) o += ' ';
        o += s[i];
    }
    return v < 0 ? "-" + o : o;
}

std::string asnText(const JVal& v) {
    std::string s = v.str();
    if (s.empty()) return "—";
    if (isdigit((unsigned char)s[0])) s = "AS" + s;
    return s;
}

// ------------------------------------------------------------------
// HTTPS к cheburcheck.ru с чтением по мере прихода (нужно для SSE)
// ------------------------------------------------------------------
using Sink = std::function<bool(const char*, size_t)>;

// GET https://cheburcheck.ru<path>. Тело отдаётся кусками в onData по мере
// прихода; onData вернул false — чтение прекращается (это не ошибка).
// idleMs — сколько ждать очередной порции. Возвращает код HTTP (0 — до ответа
// не дошло), err — причина сетевой ошибки.
#ifdef _WIN32
std::string winHttpError(DWORD e) {
    switch (e) {
    case ERROR_WINHTTP_TIMEOUT:           return "нет ответа (таймаут)";
    case ERROR_WINHTTP_NAME_NOT_RESOLVED: return "имя cheburcheck.ru не найдено (DNS)";
    case ERROR_WINHTTP_CANNOT_CONNECT:    return "не удалось подключиться к cheburcheck.ru";
    case ERROR_WINHTTP_CONNECTION_ERROR:  return "соединение оборвалось";
    case ERROR_WINHTTP_SECURE_FAILURE:    return "ошибка TLS (сертификат не прошёл проверку)";
    default: return "ошибка WinHTTP " + std::to_string(e);
    }
}

int httpsGetStream(const std::string& path, const char* accept, int idleMs,
                   const std::atomic<bool>& abort, const Sink& onData, std::string& err) {
    int status = 0;
    HINTERNET ses = WinHttpOpen(L"traffic-analyzer/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) { err = winHttpError(GetLastError()); return 0; }
    WinHttpSetTimeouts(ses, 5000, 10000, 10000, idleMs);
    HINTERNET con = WinHttpConnect(ses, L"cheburcheck.ru", INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET req = con ? WinHttpOpenRequest(con, L"GET", u8w(path).c_str(), nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             WINHTTP_FLAG_SECURE)
                        : nullptr;
    const std::wstring hdr = L"Accept: " + u8w(accept);
    if (!req) {
        err = winHttpError(GetLastError());
    } else if (!WinHttpSendRequest(req, hdr.c_str(), (DWORD)-1, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
               !WinHttpReceiveResponse(req, nullptr)) {
        err = winHttpError(GetLastError());
    } else {
        DWORD code = 0, sz = sizeof(code);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
        status = (int)code;
        std::vector<char> buf(16384);
        while (!abort) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req, &avail)) { err = winHttpError(GetLastError()); break; }
            if (!avail) break;
            DWORD rd = 0;
            if (!WinHttpReadData(req, buf.data(), std::min<DWORD>(avail, (DWORD)buf.size()), &rd)) {
                err = winHttpError(GetLastError());
                break;
            }
            if (!rd) break;
            if (!onData(buf.data(), rd)) break;
        }
    }
    if (req) WinHttpCloseHandle(req);
    if (con) WinHttpCloseHandle(con);
    WinHttpCloseHandle(ses);
    return status;
}
#else
struct CurlCtx {
    const Sink* sink;
    const std::atomic<bool>* abort;
    bool stopped = false;                 // остановил сам onData — не ошибка
};

size_t curlSink(char* p, size_t sz, size_t n, void* ud) {
    auto* c = (CurlCtx*)ud;
    if (*c->abort || !(*c->sink)(p, sz * n)) { c->stopped = true; return 0; }
    return sz * n;
}

int curlAbortCb(void* ud, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    return ((CurlCtx*)ud)->abort->load() ? 1 : 0;
}

int httpsGetStream(const std::string& path, const char* accept, int idleMs,
                   const std::atomic<bool>& abort, const Sink& onData, std::string& err) {
    static const int once = [] { return (int)curl_global_init(CURL_GLOBAL_DEFAULT); }();
    (void)once;
    CURL* c = curl_easy_init();
    if (!c) { err = "libcurl не запустился"; return 0; }
    CurlCtx ctx{&onData, &abort};
    const std::string url = "https://cheburcheck.ru" + path;
    curl_slist* hl = curl_slist_append(nullptr, (std::string("Accept: ") + accept).c_str());
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_USERAGENT, "traffic-analyzer/1.0");
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, 10000L);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, (long)std::max(1, idleMs / 1000));
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 180L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
    // редирект только на https — как WinHTTP, который не уходит с https на http
    curlRedirProtocols(c, true);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hl);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curlSink);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &ctx);
    curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, curlAbortCb);
    curl_easy_setopt(c, CURLOPT_XFERINFODATA, &ctx);
    const CURLcode rc = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if (rc != CURLE_OK && !ctx.stopped && !abort)
        err = rc == CURLE_OPERATION_TIMEDOUT ? "нет ответа (таймаут)" : curl_easy_strerror(rc);
    curl_easy_cleanup(c);
    curl_slist_free_all(hl);
    return (int)code;
}
#endif

std::string urlEnc(const std::string& s) {
    static const char* hx = "0123456789ABCDEF";
    std::string o;
    for (unsigned char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~') o += (char)c;
        else { o += '%'; o += hx[c >> 4]; o += hx[c & 15]; }
    }
    return o;
}

std::string httpErrText(int code, const std::string& info) {
    std::string s = "сервис ответил HTTP " + std::to_string(code);
    if (!info.empty()) s += " (" + info + ")";
    if (code == 500 || code == 400 || code == 422)
        s += ". Сервис не понял цель (нужен домен, IPv4/IPv6, подсеть вида 1.2.3.0/24 "
             "или AS13335) или временно не работает.";
    else if (code == 429) s += ". Слишком много запросов — подождите минуту.";
    else if (code == 403) s += ". Доступ отклонён (возможно, сайт требует проверку в браузере).";
    else if (code == 404) s += ". Адрес API не найден — возможно, API сайта изменилось.";
    else if (code >= 502) s += ". Сервис временно недоступен.";
    return s;
}

// Ссылка, host:порт, [IPv6], точка в конце — к виду, который понимает сервис.
std::string normTarget(const std::string& in) {
    std::string s = trim(in);
    const size_t sch = s.find("://");
    if (sch != std::string::npos) {
        s = s.substr(sch + 3);
        const size_t e = s.find_first_of("/?#");
        if (e != std::string::npos) s.resize(e);
        const size_t at = s.rfind('@');
        if (at != std::string::npos) s = s.substr(at + 1);
    }
    if (!s.empty() && s[0] == '[') {                             // [2001:db8::1]:443
        const size_t e = s.find(']');
        s = e == std::string::npos ? s.substr(1) : s.substr(1, e - 1);
    } else if (std::count(s.begin(), s.end(), ':') == 1) {      // host:порт
        s.resize(s.find(':'));
    }
    while (!s.empty() && s.back() == '.') s.pop_back();
    bool asn = s.size() > 2 && (s[0] == 'a' || s[0] == 'A') && (s[1] == 's' || s[1] == 'S');
    for (size_t i = 2; asn && i < s.size(); i++)
        if (!isdigit((unsigned char)s[i])) asn = false;
    if (asn) { s[0] = 'A'; s[1] = 'S'; }
    else for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

// ------------------------------------------------------------------
// Состояние проверки: пишет поток проверки, читает окно (всё под mx)
// ------------------------------------------------------------------
struct ProbeResult {
    JVal j;
    std::string raw;
    double at = 0;                        // секунд от начала опроса сканеров
};
struct OtherEvent { std::string name, data; };

struct RknState {
    std::atomic<bool> abort{false};
    std::atomic<bool> running{true};
    std::mutex mx;
    // ниже — под mx
    std::string target;
    bool withProbe = true;
    Clock::time_point t0, probeT0;
    std::time_t when = 0;
    int stage = 0;                        // 0 — проверка по спискам, 1 — сканеры, 2 — готово
    double elapsed = 0;
    int checkStatus = 0;
    bool checkOk = false;
    std::string checkErr, checkRaw, checkPretty;
    JVal check, status;
    int probeStatus = 0;
    std::string probeErr, probePretty;
    JVal started, done;
    bool gotStarted = false, gotDone = false;
    std::vector<ProbeResult> results;
    std::vector<OtherEvent> other;
};

void finishLocked(RknState& st) {
    st.stage = 2;
    st.elapsed = secsSince(st.t0);
    st.running = false;
}

// Один блок SSE: строки «event: …» и «data: …» (data — в несколько строк).
void sseBlock(const std::string& block, std::string& name, std::string& data) {
    size_t p = 0;
    while (p <= block.size()) {
        size_t e = block.find('\n', p);
        if (e == std::string::npos) e = block.size();
        const std::string line = block.substr(p, e - p);
        p = e + 1;
        if (line.empty() || line[0] == ':') continue;
        const size_t c = line.find(':');
        const std::string field = c == std::string::npos ? line : line.substr(0, c);
        std::string val = c == std::string::npos ? std::string() : line.substr(c + 1);
        if (!val.empty() && val[0] == ' ') val.erase(0, 1);
        if (field == "event") name = val;
        else if (field == "data") { if (!data.empty()) data += '\n'; data += val; }
    }
}

void worker(std::shared_ptr<RknState> st) {
    std::string target;
    bool withProbe;
    {
        std::lock_guard<std::mutex> lk(st->mx);
        target = st->target;
        withProbe = st->withProbe;
    }

    // 1. проверка по спискам
    std::string body, err;
    bool tooBig = false;
    const int code = httpsGetStream("/api/v1/check?target=" + urlEnc(target), "application/json",
        30000, st->abort, [&](const char* d, size_t n) {
            body.append(d, n);
            if (body.size() > kMaxBody) { tooBig = true; return false; }
            return true;
        }, err);
    JVal j;
    const bool parsed = !tooBig && !body.empty() && parseJson(body, j) && j.t == JVal::OBJ;
    std::string cerr;
    if (st->abort) cerr = "остановлено";
    else if (tooBig) cerr = "ответ больше 32 МБ — слишком большой для показа";
    else if (code == 0) cerr = err.empty() ? "нет ответа" : err;
    else if (code < 200 || code >= 300) cerr = httpErrText(code, parsed ? j["info"].str() : std::string());
    else if (!err.empty()) cerr = "ответ оборвался: " + err;
    else if (!parsed) cerr = "ответ не похож на JSON — возможно, API сайта изменилось";
    std::string pretty;
    if (parsed) {
        jsonPretty(j, pretty);
        capText(pretty, kMaxShow, "\n… (обрезано для показа; «Копировать JSON» копирует ответ целиком)");
    }

    // размер базы сервиса — не обязательно, при ошибке просто не показываем
    JVal status;
    if (cerr.empty() && !st->abort) {
        std::string sb, se;
        const int sc = httpsGetStream("/api/v1/status", "application/json", 10000, st->abort,
            [&](const char* d, size_t n) { sb.append(d, n); return sb.size() < 65536; }, se);
        if (sc < 200 || sc >= 300 || !parseJson(sb, status) || status.t != JVal::OBJ) status = JVal();
    }

    const std::string id = cerr.empty() ? j["id"].str() : std::string();
    {
        std::lock_guard<std::mutex> lk(st->mx);
        st->checkStatus = code;
        st->checkErr = cerr;
        st->checkOk = cerr.empty();
        st->checkRaw = std::move(body);
        st->checkPretty = std::move(pretty);
        if (st->checkOk) st->check = std::move(j);
        st->status = std::move(status);
        if (!st->checkOk || !withProbe || st->abort) { finishLocked(*st); return; }
        if (id.empty()) {
            st->probeErr = "в ответе нет id — проверка сканерами недоступна";
            finishLocked(*st);
            return;
        }
        st->stage = 1;
        st->probeT0 = Clock::now();
    }

    // 2. сканеры: поток событий SSE, блоки разделены пустой строкой
    std::string buf, head, perr;
    // buf[bufPos..] — ещё не разобранное; "\n\n" ищем с scanFrom, а не с начала,
    // и сдвигаем буфер, только когда разобранное заняло больше половины, —
    // иначе длинное событие по кускам разбиралось бы за квадратичное время
    size_t bufPos = 0, scanFrom = 0;
    bool done = false;
    auto handle = [&](const std::string& block) -> bool {      // false — пришёл итог
        std::string name, data;
        sseBlock(block, name, data);
        if (name.empty() && data.empty()) return true;
        JVal ev;
        const bool ok = parseJson(data, ev) && ev.t == JVal::OBJ;
        if (name.empty() && ok) {                              // без «event:» — по полям
            if (ev.has("verdicts") || ev.has("host_results")) name = "result";
            else if (ev.has("response_count") || ev["status"].str() == "done") name = "done";
            else if (ev.has("online_probes")) name = "started";
        }
        std::lock_guard<std::mutex> lk(st->mx);
        std::string& rp = st->probePretty;
        if (rp.size() < kMaxShow) {
            rp += "event: " + (name.empty() ? std::string("?") : name) + "\n";
            if (ok) jsonPretty(ev, rp); else rp += data;
            rp += "\n\n";
        }
        if (name == "result" && ok) {
            ProbeResult r;
            r.raw = data;
            r.at = secsSince(st->probeT0);
            r.j = std::move(ev);
            st->results.push_back(std::move(r));
        } else if (name == "started" && ok) {
            st->started = std::move(ev);
            st->gotStarted = true;
        } else if (name == "done") {
            if (ok) st->done = std::move(ev);
            st->gotDone = true;
            return false;
        } else if (st->other.size() < 50) {
            st->other.push_back({name.empty() ? std::string("?") : name, data.substr(0, 2000)});
        }
        return true;
    };
    const int pcode = httpsGetStream("/api/v1/probe/" + urlEnc(id), "text/event-stream", 60000,
        st->abort, [&](const char* d, size_t n) {
            if (head.size() < 400) head.append(d, std::min(n, 400 - head.size()));
            for (size_t i = 0; i < n; i++) if (d[i] != '\r') buf += d[i];
            for (size_t e; (e = buf.find("\n\n", scanFrom)) != std::string::npos; ) {
                const std::string block = buf.substr(bufPos, e - bufPos);
                bufPos = scanFrom = e + 2;
                if (!handle(block)) { done = true; return false; }
            }
            // "\n\n" может разрезаться между кусками — последний '\n' смотрим ещё раз
            scanFrom = std::max(bufPos, buf.empty() ? size_t(0) : buf.size() - 1);
            if (bufPos > 0 && bufPos * 2 >= buf.size()) {
                buf.erase(0, bufPos);
                scanFrom -= bufPos;
                bufPos = 0;
            }
            return buf.size() - bufPos < kMaxBody;
        }, perr);
    if (!done && bufPos < buf.size() && !st->abort) done = !handle(buf.substr(bufPos));   // хвост без пустой строки

    std::lock_guard<std::mutex> lk(st->mx);
    st->probeStatus = pcode;
    if (!st->gotDone) {
        const char* partial = st->results.empty() ? "" : " (показаны пришедшие ответы)";
        if (st->abort) st->probeErr = "остановлено";
        else if (pcode == 0) st->probeErr = perr.empty() ? "нет ответа от сервиса" : perr;
        else if (pcode < 200 || pcode >= 300) {
            JVal ej;
            st->probeErr = httpErrText(pcode, parseJson(head, ej) ? ej["info"].str() : std::string());
        } else if (!perr.empty()) st->probeErr = "поток событий прервался: " + perr + partial;
        else st->probeErr = std::string("поток событий закончился без итога") + partial;
    }
    finishLocked(*st);
}

// ------------------------------------------------------------------
// Вердикты и подписи — как на cheburcheck.ru
// ------------------------------------------------------------------
struct Verdict { const char* key; const char* title; const char* desc; const char* label; int sev; };
// по приоритету: у сканера с несколькими вердиктами берётся первый из списка
const Verdict kVerdicts[] = {
    {"tspu_block",   "Заблокирован", "Сканеры обнаружили блокировку TCP на уровне ТСПУ", "Блок на ТСПУ", 2},
    {"sni_block",    "Заблокирован", "Сканеры обнаружили блокировку по имени домена в SNI", "Блок по SNI", 2},
    {"dns_spoofing", "Заблокирован", "Сканеры обнаружили подмену ответов DNS", "Подмена DNS", 2},
    {"whitelist",    "Исключение для CDN",
     "Домен снимает ограничение 16–20 КБ при подключении к заблокированным CDN", "Исключение CDN", 1},
    {"cdn_block",    "Недоступен", "Сканеры обнаружили блокировку CDN (16–20 КБ)", "CDN блок (16–20)", 2},
    {"ok",           "Не ограничен", "Ограничений не обнаружено", "Доступен", 0},
    {"uncertain",    "Неясно", "Сканеры не пришли к однозначному выводу", "Неясно", -1},
};
const size_t kVerdictCount = sizeof(kVerdicts) / sizeof(kVerdicts[0]);

const Verdict* verdictInfo(const std::string& k) {
    for (const auto& v : kVerdicts) if (k == v.key) return &v;
    return nullptr;
}
int verdictPrio(const std::string& k) {
    for (size_t i = 0; i < kVerdictCount; i++) if (k == kVerdicts[i].key) return (int)i;
    return 99;
}
std::string verdictLabel(const std::string& k) {
    const Verdict* v = verdictInfo(k);
    return v ? v->label : k;
}
ImVec4 sevColor(int sev) {
    return sev >= 2 ? K.bad : sev == 1 ? K.warn : sev == 0 ? K.good : K.dim;
}
ImVec4 verdictColor(const std::string& k) {
    const Verdict* v = verdictInfo(k);
    return sevColor(v ? v->sev : -1);
}

// Итог сканера. Как на сайте: «ok» при цели в диапазонах CDN, когда сканер
// проверял серверы CDN и ограничение не снялось, — это «CDN блок».
std::string topVerdict(const JVal& r, bool hasCdn) {
    std::vector<std::string> vs;
    for (const auto& v : r["verdicts"].items) if (v.t == JVal::STR) vs.push_back(v.s);
    if (hasCdn && !r["cdn_unblocked"].truthy() && r["host_results"].size() > 0)
        for (auto& v : vs) if (v == "ok") v = "cdn_block";
    for (const auto& k : kVerdicts)
        if (std::find(vs.begin(), vs.end(), k.key) != vs.end()) return k.key;
    return vs.empty() ? "uncertain" : vs[0];
}

struct Tally { std::string key; int n; };
// Сколько сканеров с каким итогом; первым — самый частый (при равенстве — серьёзнее).
std::vector<Tally> tally(const std::vector<ProbeResult>& rs, bool hasCdn) {
    std::vector<Tally> t;
    for (const auto& r : rs) {
        const std::string k = topVerdict(r.j, hasCdn);
        auto it = std::find_if(t.begin(), t.end(), [&](const Tally& x) { return x.key == k; });
        if (it != t.end()) it->n++;
        else t.push_back({k, 1});
    }
    std::stable_sort(t.begin(), t.end(), [](const Tally& a, const Tally& b) {
        return a.n != b.n ? a.n > b.n : verdictPrio(a.key) < verdictPrio(b.key);
    });
    return t;
}

// Самый частый прыжок, после которого ТСПУ рвёт соединение (-1 — нет данных).
int commonDpiHop(const std::vector<ProbeResult>& rs) {
    std::map<long long, int> cnt;
    for (const auto& r : rs) {
        bool tspu = false;
        for (const auto& v : r.j["verdicts"].items) if (v.s == "tspu_block") tspu = true;
        const long long h = r.j["dpi_hop"].num(-1);
        if (tspu && h >= 0) cnt[h]++;
    }
    int best = -1, bestN = 0;
    for (const auto& kv : cnt) if (kv.second > bestN) { best = (int)kv.first; bestN = kv.second; }
    return best;
}

struct Evid { const char* key; const char* label; const char* shortLbl; int sev; };
const Evid kEvid[] = {
    {"Good",            "Доступно",           "ОК",  0},
    {"ClientHello",     "После ClientHello",  "CH",  2},
    {"DataTimeout",     "Таймаут данных",     "ТО",  1},
    {"ConnectionError", "Ошибка соединения",  "ERR", -1},
};
const Evid* evidInfo(const std::string& k) {
    for (const auto& e : kEvid) if (k == e.key) return &e;
    return nullptr;
}
std::string evLabel(const JVal& e) {
    const std::string k = e["type"].str();
    const Evid* ei = evidInfo(k);
    std::string s = ei ? ei->label : (k.empty() ? "?" : k);
    const long long b = e["bytes"].num(-1);
    if (b >= 0) s += " (" + fmtBytes(b) + ")";
    return s;
}
std::string evShort(const JVal& e) {
    const std::string k = e["type"].str();
    const Evid* ei = evidInfo(k);
    std::string s = ei ? ei->shortLbl : (k.empty() ? "?" : k);
    const long long b = e["bytes"].num(-1);
    if (b >= 0) { char t[24]; snprintf(t, sizeof(t), " %.0fК", b / 1024.0); s += t; }
    return s;
}
ImVec4 evColor(const JVal& e) {
    const Evid* ei = evidInfo(e["type"].str());
    return sevColor(ei ? ei->sev : -1);
}

// Контрольные серверы CDN: строка — сервер, ev[i] — ответ i-го сканера.
struct HostRow { std::string id, group; std::vector<const JVal*> ev; };
std::vector<HostRow> hostRows(const std::vector<ProbeResult>& rs) {
    std::vector<HostRow> out;
    for (size_t i = 0; i < rs.size(); i++)
        for (const auto& h : rs[i].j["host_results"].items) {
            const std::string id = h["host_id"].str();
            auto it = std::find_if(out.begin(), out.end(), [&](const HostRow& x) { return x.id == id; });
            if (it == out.end()) {
                out.push_back({id, h["host"].str(), std::vector<const JVal*>(rs.size(), nullptr)});
                it = out.end() - 1;
            }
            it->ev[i] = &h["probe_evidence"];
        }
    return out;
}
// «Доступно ×3, Таймаут данных ×10»
std::vector<std::pair<std::string, int>> evCounts(const HostRow& h) {
    std::vector<std::pair<std::string, int>> c;
    for (const JVal* e : h.ev) {
        if (!e) continue;
        const std::string k = (*e)["type"].str();
        auto it = std::find_if(c.begin(), c.end(), [&](const std::pair<std::string, int>& x) { return x.first == k; });
        if (it != c.end()) it->second++;
        else c.push_back({k, 1});
    }
    return c;
}
std::string evCountsText(const HostRow& h) {
    std::string s;
    for (const auto& x : evCounts(h)) {
        if (!s.empty()) s += ", ";
        const Evid* ei = evidInfo(x.first);
        s += (ei ? ei->label : x.first) + std::string(" ×") + std::to_string(x.second);
    }
    return s;
}

// Подмена DNS: провайдер × протокол по всем сканерам.
struct DnsCell {
    int ok = 0, spoof = 0;
    std::set<std::string> addrs, codes;
    std::vector<int> spoofBy;             // номера сканеров
};
struct DnsAgg {
    std::vector<std::string> providers, protocols;
    std::map<std::pair<std::string, std::string>, DnsCell> cells;
    int scanners = 0, spoofScanners = 0;
};
DnsAgg dnsAgg(const std::vector<ProbeResult>& rs) {
    DnsAgg a;
    a.protocols = {"Udp", "Tcp", "Doh", "Dot"};
    std::vector<bool> seen(4, false);
    for (size_t i = 0; i < rs.size(); i++) {
        const JVal& d = rs[i].j["dns"];
        if (d.t != JVal::OBJ) continue;
        a.scanners++;
        if (d["spoofing_detected"].truthy()) a.spoofScanners++;
        for (const auto& o : d["observations"].items) {
            const std::string prov = o["provider"].str(), proto = o["protocol"].str();
            if (std::find(a.providers.begin(), a.providers.end(), prov) == a.providers.end())
                a.providers.push_back(prov);
            auto pit = std::find(a.protocols.begin(), a.protocols.end(), proto);
            if (pit == a.protocols.end()) { a.protocols.push_back(proto); seen.push_back(true); }
            else seen[(size_t)(pit - a.protocols.begin())] = true;
            DnsCell& c = a.cells[{prov, proto}];
            if (o["suspected_spoofing"].truthy()) { c.spoof++; c.spoofBy.push_back((int)i + 1); }
            else c.ok++;
            const JVal& out = o["outcome"];
            for (const auto& x : out["addresses"].items) c.addrs.insert(x.str());
            const std::string ot = out["type"].str();
            if (!ot.empty() && ot != "Answer") c.codes.insert(ot);
            for (const auto& x : o["metadata"]["response_codes"].items) c.codes.insert(x.str());
        }
    }
    // протоколы, которых не было ни у одного сканера, — не показываем
    std::vector<std::string> used;
    for (size_t i = 0; i < a.protocols.size(); i++) if (seen[i]) used.push_back(a.protocols[i]);
    a.protocols = used;
    return a;
}
const char* protoName(const std::string& p) {
    if (p == "Udp") return "UDP";
    if (p == "Tcp") return "TCP";
    if (p == "Doh") return "DoH";
    if (p == "Dot") return "DoT";
    return p.c_str();
}
std::string provName(const std::string& p) {
    if (p == "google") return "Google";
    if (p == "cloudflare") return "Cloudflare";
    if (p == "quad9") return "Quad9";
    if (p == "yandex") return "Яндекс";
    return p;
}

std::string whitelistText(const JVal& w) {
    if (w.t != JVal::OBJ) return brief(w);
    std::string s;
    if (filled(w["domain"])) s += "домен " + w["domain"].str();
    if (filled(w["rank"])) s += (s.empty() ? "" : ", ") + std::string("ранг ") + w["rank"].str();
    if (filled(w["last_ok"])) s += (s.empty() ? "" : ", ") + std::string("последний успешный ответ ") + w["last_ok"].str();
    for (size_t i = 0; i < w.keys.size(); i++) {
        const std::string& k = w.keys[i];
        if (k == "domain" || k == "rank" || k == "last_ok" || !filled(w.items[i])) continue;
        s += (s.empty() ? "" : ", ") + k + ": " + brief(w.items[i]);
    }
    return s.empty() ? "да" : s;
}

std::string cdnNames(const JVal& cp) {
    std::string s;
    for (const auto& k : cp.keys) { if (!s.empty()) s += ", "; s += k; }
    return s;
}

std::string joinList(const JVal& arr, const char* sep = ", ") {
    std::string s;
    for (const auto& x : arr.items) { if (!s.empty()) s += sep; s += brief(x); }
    return s;
}

std::string scannerRegion(const JVal& r) {
    const std::string s = r["region"].str();
    return s.empty() ? "Регион не указан" : s;
}

// ------------------------------------------------------------------
// Текст для буфера обмена
// ------------------------------------------------------------------
std::string reportText(const RknState& st, bool hasCdn) {
    std::string o;
    auto line = [&](const std::string& s) { o += s; o += '\n'; };
    char ts[32] = "";
    {
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &st.when);
#else
        localtime_r(&st.when, &tm);
#endif
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M", &tm);
    }
    const JVal& ck = st.check;
    std::string type = ck["target_type"].str();
    line("Проверка в cheburcheck.ru: " + st.target + (type.empty() ? "" : " (" + type + ")") + ", " + ts);
    if (!st.checkOk) { line("Ошибка: " + st.checkErr); return o; }

    line(std::string("Списки блокировок: ") + (ck["blocked"].truthy() ? "НАЙДЕН в списках блокировок" : "не найден"));
    line("  Реестр РКН: " + (filled(ck["rkn_domain"]) ? brief(ck["rkn_domain"]) : std::string("нет")));
    const JVal& bs = ck["blocked_subnets"];
    if (bs.size()) line("  Заблокированные подсети (" + std::to_string(bs.size()) + "): " + brief(bs, 30));
    const JVal& cp = ck["cdn_providers"];
    // по ключам «провайдер → подсети»: у ответа другого вида (массив) их нет
    for (size_t i = 0; i < cp.keys.size(); i++) {
        std::string s;
        const JVal& arr = cp.items[i];
        for (const auto& e : arr.items) {
            if (!s.empty()) s += ", ";
            s += e["cidr"].str();
            if (filled(e["region"])) s += " (" + e["region"].str() + ")";
        }
        line("  Диапазон CDN " + cp.keys[i] + ": " + (s.empty() ? brief(arr) : s));
    }
    if (filled(ck["whitelist"])) line("  Белый список CDN: " + whitelistText(ck["whitelist"]));

    const JVal& ips = ck["ips"];
    if (ips.size()) line("IP (" + std::to_string(ips.size()) + "): " + brief(ips, 30));
    if (filled(ck["subnet_size"])) line("Размер подсети: " + ck["subnet_size"].str());
    const JVal& geo = ck["geo"];
    if (geo.t == JVal::OBJ)
        line("Сеть: " + asnText(geo["asn"]) + ", " + geo["organisation"].str() + ", " + geo["country_code"].str());
    if (ck["reverse_lookup"].size()) line("PTR: " + joinList(ck["reverse_lookup"]));
    const JVal& ai = ck["asn_info"];
    for (size_t i = 0; i < ai.keys.size(); i++) {
        const JVal& x = ai.items[i];
        line("AS " + ai.keys[i] + ": " + (x.t == JVal::ARR ? std::to_string(x.size()) + " — " + brief(x, 20) : brief(x)));
    }
    const JVal& cm = ck["complaints"];
    if (cm.t == JVal::ARR) {
        long long total = 0;
        for (const auto& x : cm.items) total += std::max(0LL, x["count"].num(0));
        line("Жалобы за " + std::to_string(cm.size()) + " дн.: " + std::to_string(total));
    }

    if (!st.withProbe) { line("Сканеры: не запускались"); return o; }
    if (st.results.empty()) {
        line("Сканеры: нет данных" + (st.probeErr.empty() ? std::string() : " — " + st.probeErr));
        return o;
    }
    const auto tl = tally(st.results, hasCdn);
    const Verdict* vi = verdictInfo(tl[0].key);
    long long online = st.started["online_probes"].num(-1);
    line("Сканеры: " + std::string(vi ? vi->title : tl[0].key.c_str()) + " — " + (vi ? vi->desc : "") +
         " (ответили " + std::to_string(st.results.size()) +
         (online >= 0 ? " из " + std::to_string(online) : std::string()) + ")");
    const int hop = commonDpiHop(st.results);
    if (tl[0].key == "tspu_block" && hop >= 0)
        line("  Блокировка на ТСПУ обнаружена после " + std::to_string(hop) + " прыжка");
    {
        std::string s;
        for (const auto& t : tl) { if (!s.empty()) s += ", "; s += verdictLabel(t.key) + " — " + std::to_string(t.n); }
        line("  " + s);
    }
    for (size_t i = 0; i < st.results.size(); i++) {
        const JVal& r = st.results[i].j;
        std::string s = "  " + std::to_string(i + 1) + ". " + scannerRegion(r) + " · " + r["provider"].str() +
                        " · " + asnText(r["asn"]) + " — " + verdictLabel(topVerdict(r, hasCdn));
        if (r["dpi_hop"].num(-1) >= 0) s += ", ТСПУ после прыжка " + r["dpi_hop"].str();
        if (r["dns"]["spoofing_detected"].truthy()) s += ", подмена DNS";
        line(s);
    }
    const auto hosts = hostRows(st.results);
    if (!hosts.empty()) {
        line("Контрольные серверы CDN:");
        for (const auto& h : hosts)
            line("  " + h.id + (h.group.empty() ? "" : " (" + h.group + ")") + ": " + evCountsText(h));
    }
    const DnsAgg da = dnsAgg(st.results);
    if (da.scanners) {
        line("DNS: подмену заметили " + std::to_string(da.spoofScanners) + " из " + std::to_string(da.scanners) + " сканеров");
        for (const auto& kv : da.cells)
            if (kv.second.spoof)
                line("  " + provName(kv.first.first) + " " + protoName(kv.first.second) + ": подмена у " +
                     std::to_string(kv.second.spoof) + " из " + std::to_string(kv.second.spoof + kv.second.ok));
    }
    if (!st.probeErr.empty()) line("Примечание: " + st.probeErr);
    return o;
}

// ------------------------------------------------------------------
// Отрисовка
// ------------------------------------------------------------------
std::shared_ptr<RknState> s_st;           // последняя проверка (только поток окна)
char s_input[256] = "";
bool s_withProbe = true;

void startCheck(const std::string& raw) {
    if (s_st) s_st->abort = true;         // прежняя проверка — бросить
    auto st = std::make_shared<RknState>();
    st->target = normTarget(raw);
    st->withProbe = s_withProbe;
    st->t0 = Clock::now();
    st->when = std::time(nullptr);
    s_st = st;
    std::string bad;
    if (st->target.empty())
        bad = "Введите домен, IP-адрес, подсеть (1.2.3.0/24) или номер AS (AS13335).";
    else if (st->target.find_first_of(" \t,;") != std::string::npos)
        bad = "По одной цели за раз: уберите пробелы и запятые.";
    else if (st->target.size() > 253)
        bad = "Слишком длинная строка для домена или адреса.";
    else if (isPrivateIp(st->target))
        bad = "Это частный (локальный) адрес — в реестрах его нет, проверять нечего.";
    if (!bad.empty()) {
        st->checkErr = bad;
        finishLocked(*st);
        return;
    }
    try {
        std::thread(worker, st).detach();
    } catch (...) {
        st->checkErr = "не удалось запустить поток проверки";
        finishLocked(*st);
    }
}

float rowHeight() { return ImGui::GetTextLineHeight() + ImGui::GetStyle().CellPadding.y * 2; }

void bigText(const char* s, const ImVec4& col) {
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 1.35f);
    ImGui::TextColored(col, "%s", s);
    ImGui::PopFont();
}

void hint(const char* s) {
    ImGui::PushStyleColor(ImGuiCol_Text, K.dim);
    ImGui::TextWrapped("%s", s);
    ImGui::PopStyleColor();
}

void tip(const std::string& s) {
    if (s.empty() || !ImGui::BeginItemTooltip()) return;
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 36);
    ImGui::TextUnformatted(s.c_str());
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
}

// Таблица «название — значение».
bool beginKv(const char* id) {
    if (!ImGui::BeginTable(id, 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH)) return false;
    ImGui::TableSetupColumn("k", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 13);
    ImGui::TableSetupColumn("v", ImGuiTableColumnFlags_WidthStretch);
    return true;
}
void kv(const char* k, const std::string& v, const ImVec4* col = nullptr, const std::string& tipText = std::string()) {
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    ImGui::TextColored(K.dim, "%s", k);
    ImGui::TableNextColumn();
    ImGui::PushTextWrapPos(0);
    if (col) ImGui::PushStyleColor(ImGuiCol_Text, *col);
    ImGui::TextUnformatted(v.empty() ? "—" : v.c_str());
    if (col) ImGui::PopStyleColor();
    ImGui::PopTextWrapPos();
    tip(tipText);
}

// Длинный список — в окошке с прокруткой и кнопкой «копировать».
void bigList(const char* id, const JVal& arr, const char* copyLabel) {
    const size_t n = arr.items.size();
    ImGui::PushID(id);
    const float h = ImGui::GetTextLineHeightWithSpacing() * (float)std::min<size_t>(n, 12) +
                    ImGui::GetStyle().WindowPadding.y * 2;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, K.panelBg);
    ImGui::BeginChild("##list", ImVec2(std::min(ImGui::GetContentRegionAvail().x, ImGui::GetFontSize() * 30), h),
                      ImGuiChildFlags_Borders);
    ImGui::PopStyleColor();
    ImGuiListClipper clip;
    clip.Begin((int)n);
    while (clip.Step())
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++)
            ImGui::TextUnformatted(brief(arr.items[(size_t)i]).c_str());
    ImGui::EndChild();
    if (ImGui::SmallButton(copyLabel)) {
        const std::string s = joinList(arr, "\n");
        ImGui::SetClipboardText(s.c_str());
    }
    ImGui::PopID();
}

void drawHeader(RknState& st, bool live, bool hasCdn) {
    const float em = ImGui::GetFontSize();
    bigText(st.target.empty() ? "(пусто)" : st.target.c_str(), K.accent);
    if (st.checkOk && filled(st.check["target_type"])) {
        ImGui::SameLine();
        ImGui::AlignTextToFramePadding();
        ImGui::TextColored(K.dim, "%s", st.check["target_type"].str().c_str());
    }
    if (live) {
        if (st.stage == 0) {
            ImGui::TextColored(K.warn, "Проверка по спискам… %.0f с", secsSince(st.t0));
        } else {
            const long long online = st.started["online_probes"].num(-1);
            const size_t n = st.results.size();
            ImGui::TextColored(K.warn, "Опрос сканеров… %.0f с", secsSince(st.probeT0));
            ImGui::SameLine();
            char lbl[64];
            if (online > 0) snprintf(lbl, sizeof(lbl), "%zu из %lld", n, online);
            else snprintf(lbl, sizeof(lbl), "%zu", n);
            ImGui::ProgressBar(online > 0 ? std::min(1.0f, (float)n / (float)online) : 0.0f,
                               ImVec2(em * 14, 0), lbl);
        }
    } else if (st.abort) {
        ImGui::TextColored(K.dim, "Остановлено.");
    } else if (st.checkOk) {
        char ts[32] = "";
        std::tm tm{};
#ifdef _WIN32
        localtime_s(&tm, &st.when);
#else
        localtime_r(&st.when, &tm);
#endif
        strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
        ImGui::TextColored(K.dim, "Проверено в %s за %.1f с", ts, st.elapsed);
    }
    if (st.status.t == JVal::OBJ) {
        const JVal& s = st.status;
        std::string t = "База сервиса:";
        if (filled(s["domain_count"])) t += " доменов " + fmtCount(s["domain_count"].num(0)) + ",";
        if (filled(s["v4_count"])) t += " IPv4 " + fmtCount(s["v4_count"].num(0)) + ",";
        if (filled(s["last_update"])) t += " обновлена " + s["last_update"].str() + ",";
        if (filled(s["version"])) t += " версия " + s["version"].str();
        if (!t.empty() && t.back() == ',') t.pop_back();
        ImGui::TextColored(K.dim, "%s", t.c_str());
    }
    if (!st.checkErr.empty() && !st.abort) {
        ImGui::PushTextWrapPos(0);
        ImGui::TextColored(K.bad, "Ошибка: %s", st.checkErr.c_str());
        ImGui::PopTextWrapPos();
    }
    if (st.checkOk && !live) {
        if (ImGui::Button("Копировать как текст")) {
            const std::string s = reportText(st, hasCdn);
            ImGui::SetClipboardText(s.c_str());
        }
        ImGui::SameLine();
        if (ImGui::Button("Копировать JSON")) ImGui::SetClipboardText(st.checkRaw.c_str());
    }
}

void drawStaticCard(const RknState& st, bool hasCdn) {
    const JVal& ck = st.check;
    ImGui::TextColored(K.dim, "Списки блокировок");
    const bool blocked = ck["blocked"].truthy();
    bigText(blocked ? "Заблокирован" : "Не найден в списках", blocked ? K.bad : K.good);
    ImGui::PushTextWrapPos(0);
    ImGui::TextUnformatted(blocked ? "Ресурс был найден в списках блокировок."
                                   : "Ресурс не найден в списках блокировок.");
    const JVal& rd = ck["rkn_domain"];
    if (filled(rd)) ImGui::TextColored(K.bad, "• В реестре РКН: %s", brief(rd).c_str());
    else if (ck["target_type"].str() == "Домен") ImGui::TextColored(K.dim, "• Домена нет в реестре РКН");
    if (const size_t n = ck["blocked_subnets"].size())
        ImGui::TextColored(K.bad, "• В заблокированных подсетях: %zu", n);
    if (hasCdn) {
        ImGui::TextColored(K.warn, "• Адреса в диапазонах CDN: %s", cdnNames(ck["cdn_providers"]).c_str());
        tip("ТСПУ ограничивает соединения с такими адресами: после первых 16–20 КБ данные перестают приходить.");
    }
    if (filled(ck["whitelist"]))
        ImGui::TextColored(K.good, "• В белом списке CDN: %s", whitelistText(ck["whitelist"]).c_str());
    ImGui::PopTextWrapPos();
}

void drawProbeCard(const RknState& st, bool hasCdn, bool live) {
    ImGui::TextColored(K.dim, "Сканеры в регионах России");
    ImGui::PushTextWrapPos(0);
    if (!st.withProbe) {
        bigText("Не запускались", K.dim);
        ImGui::TextUnformatted("Включите «Сканеры из регионов» и проверьте ещё раз.");
    } else if (st.results.empty()) {
        if (live) bigText(st.stage == 0 ? "Ждём списки…" : "Ждём ответы…", K.dim);
        else {
            bigText("Нет данных", K.dim);
            if (!st.probeErr.empty() && !st.abort) ImGui::TextColored(K.warn, "%s", st.probeErr.c_str());
        }
    } else {
        const auto tl = tally(st.results, hasCdn);
        const Verdict* vi = verdictInfo(tl[0].key);
        bigText(vi ? vi->title : tl[0].key.c_str(), verdictColor(tl[0].key));
        if (vi) ImGui::TextUnformatted(vi->desc);
        const int hop = commonDpiHop(st.results);
        if (tl[0].key == "tspu_block" && hop >= 0)
            ImGui::Text("Блокировка на ТСПУ обнаружена после %d прыжка", hop);
        const long long online = st.started["online_probes"].num(-1);
        if (online >= 0) ImGui::TextColored(K.dim, "Ответили %zu из %lld сканеров%s", st.results.size(), online,
                                            live ? " (ещё идёт)" : "");
        else ImGui::TextColored(K.dim, "Ответили %zu сканеров%s", st.results.size(), live ? " (ещё идёт)" : "");
        if (!live && !st.probeErr.empty() && !st.abort) ImGui::TextColored(K.warn, "%s", st.probeErr.c_str());
    }
    ImGui::PopTextWrapPos();
}

void drawCards(const RknState& st, bool hasCdn, bool live) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, K.panelBg);
    const bool vis = ImGui::BeginChild("##cards", ImVec2(0, 0),
        ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY | ImGuiChildFlags_AlwaysUseWindowPadding);
    ImGui::PopStyleColor();
    if (vis && ImGui::BeginTable("##ct", 2, ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingStretchSame)) {
        ImGui::TableNextColumn();
        drawStaticCard(st, hasCdn);
        ImGui::TableNextColumn();
        drawProbeCard(st, hasCdn, live);
        ImGui::EndTable();
    }
    ImGui::EndChild();
}

// Поля объекта, которых нет в known, — строками «название — значение».
void kvRest(const char* prefix, const JVal& obj, std::initializer_list<const char*> known) {
    for (size_t i = 0; i < obj.keys.size(); i++) {
        bool k = false;
        for (const char* x : known) if (obj.keys[i] == x) k = true;
        if (k) continue;
        const std::string name = std::string(prefix) + obj.keys[i];
        kv(name.c_str(), brief(obj.items[i]));
    }
}

void drawNet(const RknState& st) {
    if (!ImGui::CollapsingHeader("Сетевые данные", ImGuiTreeNodeFlags_DefaultOpen)) return;
    const JVal& ck = st.check;
    const JVal& ips = ck["ips"];
    const JVal& geo = ck["geo"];
    const JVal& ai = ck["asn_info"];
    const size_t kInline = 24;
    if (beginKv("##net")) {
        kv("Тип цели", ck["target_type"].str());
        if (ips.size() <= kInline) kv("IP-адреса", ips.size() ? joinList(ips) : "нет");
        else kv("IP-адреса", fmtCount((long long)ips.size()) + " — список ниже");
        // сервис отдаёт размер и строкой в сокращённой записи («65.5K», «79228162.5Z»):
        // её — как есть (как в reportText), число через num() обрезалось бы до «65»
        const JVal& ssz = ck["subnet_size"];
        if (filled(ssz))
            kv("Размер подсети", (ssz.t == JVal::NUM && ssz.n >= 0 && ssz.n < 1e15
                                      ? fmtCount((long long)ssz.n) : brief(ssz)) + " адресов");
        if (geo.t == JVal::OBJ) {
            kv("AS", asnText(geo["asn"]));
            kv("Организация", geo["organisation"].str());
            kv("Страна", geo["country_code"].str());
            if (filled(geo["city_geo_name_id"])) kv("Город (GeoNames id)", geo["city_geo_name_id"].str());
            if (filled(geo["location"])) kv("Координаты", brief(geo["location"]));
            kvRest("geo.", geo, {"asn", "organisation", "country_code", "city_geo_name_id", "location"});
        }
        const JVal& ptr = ck["reverse_lookup"];
        kv("Обратные имена (PTR)", ptr.size() ? joinList(ptr) : "нет");
        if (ai.t == JVal::OBJ)
            for (size_t i = 0; i < ai.keys.size(); i++) {
                const std::string& k = ai.keys[i];
                const JVal& x = ai.items[i];
                const std::string name = k == "prefixes" ? "Префиксы AS" :
                                         k == "blocked_prefixes" ? "Заблокированные префиксы" : "asn_info." + k;
                const ImVec4* col = (k == "blocked_prefixes" && filled(x)) ? &K.bad : nullptr;
                if (x.t == JVal::ARR && x.size() > kInline) kv(name.c_str(), fmtCount((long long)x.size()) + " — список ниже", col);
                else if (x.t == JVal::ARR) kv(name.c_str(), x.size() ? joinList(x) : "нет", col);
                else kv(name.c_str(), brief(x), col);
            }
        ImGui::EndTable();
    }
    if (ips.size() > kInline) {
        ImGui::TextColored(K.dim, "Все IP-адреса (%zu):", ips.size());
        bigList("##ips", ips, "Копировать все IP");
    }
    if (ai.t == JVal::OBJ)
        for (size_t i = 0; i < ai.keys.size(); i++)
            if (ai.items[i].t == JVal::ARR && ai.items[i].size() > kInline) {
                ImGui::TextColored(K.dim, "%s (%zu):", ai.keys[i].c_str(), ai.items[i].size());
                bigList(ai.keys[i].c_str(), ai.items[i], "Копировать список");
            }
}

void drawLists(const RknState& st, bool hasCdn) {
    if (!ImGui::CollapsingHeader("Нахождение в списках", ImGuiTreeNodeFlags_DefaultOpen)) return;
    const JVal& ck = st.check;
    const JVal& bs = ck["blocked_subnets"];
    const JVal& cp = ck["cdn_providers"];
    const size_t kInline = 24;
    if (beginKv("##lists")) {
        const bool blocked = ck["blocked"].truthy();
        kv("Найден в списках", blocked ? "да" : "нет", blocked ? &K.bad : &K.good,
           "Поле blocked: цель есть в реестре, в заблокированной подсети или в диапазоне CDN под ограничением.");
        const JVal& rd = ck["rkn_domain"];
        kv("Реестр РКН", filled(rd) ? brief(rd) : "нет в реестре", filled(rd) ? &K.bad : nullptr);
        if (!bs.size()) kv("Заблокированные подсети", "нет");
        else if (bs.size() <= kInline) kv("Заблокированные подсети", joinList(bs), &K.bad);
        else kv("Заблокированные подсети", fmtCount((long long)bs.size()) + " — список ниже", &K.bad);
        const JVal& wl = ck["whitelist"];
        kv("Белый список CDN", filled(wl) ? whitelistText(wl) : "нет", filled(wl) ? &K.good : nullptr,
           "Домены из белого списка снимают ограничение 16–20 КБ при подключении к заблокированным CDN.");
        kv("Диапазоны CDN", hasCdn ? cdnNames(cp) : filled(cp) ? brief(cp) : "нет", hasCdn ? &K.warn : nullptr,
           "ТСПУ ограничивает соединения с адресами этих CDN: после первых 16–20 КБ данные перестают приходить.");
        kvRest("", ck, {"id", "target", "target_type", "blocked", "rkn_domain", "ips", "subnet_size",
                        "blocked_subnets", "cdn_providers", "geo", "whitelist", "reverse_lookup",
                        "asn_info", "complaints"});
        ImGui::EndTable();
    }
    if (bs.size() > kInline) {
        ImGui::TextColored(K.dim, "Заблокированные подсети (%zu):", bs.size());
        bigList("##bs", bs, "Копировать подсети");
    }
    if (!hasCdn) return;

    // провайдер → [{provider, cidr, region}] (по ключам, как в reportText)
    std::vector<std::pair<const std::string*, const JVal*>> rows;
    for (size_t i = 0; i < cp.keys.size(); i++) {
        const JVal& arr = cp.items[i];
        if (arr.t == JVal::ARR) for (const auto& e : arr.items) rows.push_back({&cp.keys[i], &e});
        else rows.push_back({&cp.keys[i], &arr});
    }
    ImGui::Spacing();
    ImGui::TextColored(K.dim, "Диапазоны CDN, в которые попали адреса цели (%zu):", rows.size());
    ImGuiTableFlags f = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp;
    ImVec2 sz(0, 0);
    if (rows.size() > 15) { f |= ImGuiTableFlags_ScrollY; sz.y = rowHeight() * 16; }
    if (ImGui::BeginTable("##cdn", 3, f, sz)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Провайдер");
        ImGui::TableSetupColumn("Подсеть (CIDR)");
        ImGui::TableSetupColumn("Регион");
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin((int)rows.size());
        while (clip.Step())
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
                const JVal& e = *rows[(size_t)i].second;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                const std::string prov = filled(e["provider"]) ? e["provider"].str() : *rows[(size_t)i].first;
                ImGui::TextUnformatted(prov.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(e.t == JVal::OBJ ? e["cidr"].str().c_str() : brief(e).c_str());
                ImGui::TableNextColumn();
                const std::string reg = e["region"].str();
                ImGui::TextUnformatted(reg.empty() ? "—" : reg.c_str());
            }
        ImGui::EndTable();
    }
}

void drawComplaints(const RknState& st) {
    const JVal& cm = st.check["complaints"];
    if (cm.t != JVal::ARR) return;
    long long total = 0, mx = 0;
    for (const auto& x : cm.items) {
        const long long c = std::max(0LL, x["count"].num(0));
        total += c;
        mx = std::max(mx, c);
    }
    char hdr[128];
    snprintf(hdr, sizeof(hdr), "Жалобы пользователей — %lld за %zu дн.###compl", total, cm.size());
    if (!ImGui::CollapsingHeader(hdr, ImGuiTreeNodeFlags_DefaultOpen)) return;
    hint("Сколько раз пользователи сервиса сообщали, что ресурс у них не открывается.");
    if (cm.items.empty()) return;
    if (!total) { ImGui::TextColored(K.good, "За этот период жалоб нет."); return; }

    const float em = ImGui::GetFontSize();
    const float W = std::min(ImGui::GetContentRegionAvail().x, em * 40), H = em * 4;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton("##compl", ImVec2(W, H + em * 1.3f));
    const bool hov = ImGui::IsItemHovered();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const size_t n = cm.items.size();
    const float bw = W / (float)n;
    const float mxX = ImGui::GetIO().MousePos.x;
    for (size_t i = 0; i < n; i++) {
        const long long c = std::max(0LL, cm.items[i]["count"].num(0));
        const float h = mx ? H * (float)c / (float)mx : 0;
        const float x0 = p.x + bw * (float)i, x1 = x0 + bw;
        const bool on = hov && mxX >= x0 && mxX < x1;
        if (on) dl->AddRectFilled(ImVec2(x0, p.y), ImVec2(x1, p.y + H), ImGui::GetColorU32(withAlpha(K.dim, 0.15f)));
        if (c) dl->AddRectFilled(ImVec2(x0 + 1, p.y + H - std::max(h, 2.0f)), ImVec2(x1 - 1, p.y + H),
                                 ImGui::GetColorU32(withAlpha(K.warn, on ? 1.0f : 0.75f)), 2);
        if (on) {
            ImGui::BeginTooltip();
            ImGui::Text("%s: %lld", cm.items[i]["date"].str().c_str(), c);
            ImGui::EndTooltip();
        }
    }
    dl->AddLine(ImVec2(p.x, p.y + H), ImVec2(p.x + W, p.y + H), ImGui::GetColorU32(K.dim));
    const std::string d0 = cm.items.front()["date"].str(), d1 = cm.items.back()["date"].str();
    dl->AddText(ImVec2(p.x, p.y + H + em * 0.15f), ImGui::GetColorU32(K.dim), d0.c_str());
    const float w1 = ImGui::CalcTextSize(d1.c_str()).x;
    dl->AddText(ImVec2(p.x + W - w1, p.y + H + em * 0.15f), ImGui::GetColorU32(K.dim), d1.c_str());
}

void drawScanners(const RknState& st, bool hasCdn, bool live) {
    if (!st.withProbe) return;
    const size_t n = st.results.size();
    long long online = st.started["online_probes"].num(-1);
    if (online < 0) online = st.done["online_probes"].num(-1);
    char hdr[128];
    if (online >= 0) snprintf(hdr, sizeof(hdr), "Проверка сканерами — ответили %zu из %lld###scan", n, online);
    else snprintf(hdr, sizeof(hdr), "Проверка сканерами — ответили %zu###scan", n);
    if (!ImGui::CollapsingHeader(hdr, ImGuiTreeNodeFlags_DefaultOpen)) return;
    hint("Сканеры — серверы у провайдеров в регионах России. Каждый подключается к цели и смотрит, "
         "где рвётся соединение, подменяется ли DNS и режутся ли CDN.");
    if (st.gotStarted || st.gotDone) {
        std::string s;
        if (filled(st.started["id"])) s += "id проверки: " + st.started["id"].str();
        if (st.gotDone) {
            if (!s.empty()) s += " · ";
            s += "итог сервиса: " + (filled(st.done["status"]) ? st.done["status"].str() : std::string("?"));
            if (filled(st.done["response_count"])) s += ", ответов " + st.done["response_count"].str();
        }
        if (!s.empty()) ImGui::TextColored(K.dim, "%s", s.c_str());
    }
    if (!st.probeErr.empty() && !st.abort) {
        ImGui::PushTextWrapPos(0);
        ImGui::TextColored(K.warn, "%s", st.probeErr.c_str());
        ImGui::PopTextWrapPos();
    }
    for (const auto& e : st.other)
        ImGui::TextColored(K.dim, "Событие «%s»: %s", e.name.c_str(), e.data.substr(0, 200).c_str());
    if (!n) {
        if (live) ImGui::TextColored(K.dim, "Ждём первые ответы…");
        return;
    }

    // распределение итогов
    const float em = ImGui::GetFontSize();
    const float lh = ImGui::GetTextLineHeight();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    for (const auto& t : tally(st.results, hasCdn)) {
        const ImVec4 col = verdictColor(t.key);
        const float W = em * 12, w = std::max(2.0f, W * (float)t.n / (float)n);
        const ImVec2 p = ImGui::GetCursorScreenPos();
        dl->AddRectFilled(ImVec2(p.x, p.y + lh * 0.2f), ImVec2(p.x + W, p.y + lh * 0.85f),
                          ImGui::GetColorU32(withAlpha(K.dim, 0.15f)), 2);
        dl->AddRectFilled(ImVec2(p.x, p.y + lh * 0.2f), ImVec2(p.x + w, p.y + lh * 0.85f),
                          ImGui::GetColorU32(withAlpha(col, 0.85f)), 2);
        ImGui::Dummy(ImVec2(W, lh));
        ImGui::SameLine();
        ImGui::TextColored(col, "%s — %d", verdictLabel(t.key).c_str(), t.n);
        const Verdict* vi = verdictInfo(t.key);
        tip(vi ? vi->desc : t.key);
    }
    ImGui::Spacing();

    enum { C_N, C_REG, C_PROV, C_ASN, C_TOP, C_ALL, C_DPI, C_HOP, C_CDN, C_DNS, C_AT, C_COUNT };
    const float h = rowHeight() * (float)(n + 1) + ImGui::GetStyle().ScrollbarSize + em * 0.4f;
    const ImGuiTableFlags f = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollX |
                              ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("##scan", C_COUNT, f, ImVec2(0, h))) return;
    ImGui::TableSetupScrollFreeze(1, 1);
    ImGui::TableSetupColumn("#");
    ImGui::TableSetupColumn("Регион");
    ImGui::TableSetupColumn("Провайдер");
    ImGui::TableSetupColumn("ASN");
    ImGui::TableSetupColumn("Итог");
    ImGui::TableSetupColumn("Вердикты сканера");
    ImGui::TableSetupColumn("ТСПУ после прыжка");
    ImGui::TableSetupColumn("Прыжок цели");
    ImGui::TableSetupColumn("CDN");
    ImGui::TableSetupColumn("DNS");
    ImGui::TableSetupColumn("Ответ через");
    ImGui::TableHeadersRow();
    for (size_t i = 0; i < n; i++) {
        const ProbeResult& pr = st.results[i];
        const JVal& r = pr.j;
        ImGui::PushID((int)i);
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(C_N);
        char num[16];
        snprintf(num, sizeof(num), "%zu", i + 1);
        ImGui::Selectable(num, false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap);
        if (ImGui::BeginPopupContextItem("##ctx")) {
            if (ImGui::MenuItem("Копировать JSON сканера")) ImGui::SetClipboardText(pr.raw.c_str());
            ImGui::EndPopup();
        }
        ImGui::TableSetColumnIndex(C_REG);
        if (filled(r["region"])) ImGui::TextUnformatted(r["region"].str().c_str());
        else ImGui::TextColored(K.dim, "Регион не указан");
        ImGui::TableSetColumnIndex(C_PROV);
        ImGui::TextUnformatted(r["provider"].str().c_str());
        ImGui::TableSetColumnIndex(C_ASN);
        ImGui::TextUnformatted(asnText(r["asn"]).c_str());
        ImGui::TableSetColumnIndex(C_TOP);
        const std::string top = topVerdict(r, hasCdn);
        ImGui::TextColored(verdictColor(top), "%s", verdictLabel(top).c_str());
        ImGui::TableSetColumnIndex(C_ALL);
        {
            std::string s, raw;
            for (const auto& v : r["verdicts"].items) {
                if (!s.empty()) { s += ", "; raw += ", "; }
                s += verdictLabel(v.str());
                raw += v.str();
            }
            ImGui::TextUnformatted(s.empty() ? "—" : s.c_str());
            tip(raw.empty() ? std::string() : "verdicts: " + raw);
        }
        ImGui::TableSetColumnIndex(C_DPI);
        if (r["dpi_hop"].num(-1) >= 0) ImGui::TextColored(K.bad, "%s", r["dpi_hop"].str().c_str());
        else ImGui::TextColored(K.dim, "—");
        ImGui::TableSetColumnIndex(C_HOP);
        if (r["target_hop"].num(-1) >= 0) ImGui::TextUnformatted(r["target_hop"].str().c_str());
        else ImGui::TextColored(K.dim, "—");
        ImGui::TableSetColumnIndex(C_CDN);
        if (!r["host_results"].size()) ImGui::TextColored(K.dim, "—");
        else if (r["cdn_unblocked"].truthy()) ImGui::TextColored(K.good, "без ограничения");
        else ImGui::TextColored(K.bad, "ограничен");
        tip("cdn_unblocked: " + (r.has("cdn_unblocked") ? r["cdn_unblocked"].str() : std::string("нет")) +
            ", серверов CDN проверено: " + std::to_string(r["host_results"].size()));
        ImGui::TableSetColumnIndex(C_DNS);
        const JVal& d = r["dns"];
        if (d.t != JVal::OBJ) ImGui::TextColored(K.dim, "—");
        else {
            if (d["spoofing_detected"].truthy()) ImGui::TextColored(K.bad, "подмена");
            else ImGui::TextColored(K.good, "норма");
            std::string t = "spoofing_detected: " + d["spoofing_detected"].str();
            if (filled(d["suspicious_provider_count"])) t += "\nподозрительных DNS-сервисов: " + d["suspicious_provider_count"].str();
            if (filled(d["verdict_threshold"])) t += "\nпорог вердикта: " + d["verdict_threshold"].str();
            if (filled(d["samples_per_protocol"])) t += "\nзапросов на протокол: " + d["samples_per_protocol"].str();
            t += "\nответов: " + std::to_string(d["observations"].size());
            tip(t);
        }
        ImGui::TableSetColumnIndex(C_AT);
        ImGui::Text("%.1f с", pr.at);
        ImGui::PopID();
    }
    ImGui::EndTable();
}

void drawCdnHosts(const RknState& st) {
    const auto rows = hostRows(st.results);
    if (rows.empty()) return;
    if (!ImGui::CollapsingHeader("Контрольные серверы CDN###cdnh", ImGuiTreeNodeFlags_DefaultOpen)) return;
    hint("Сканеры скачивают данные с серверов в сетях CDN. «Таймаут данных» — после первых килобайт данные "
         "перестали приходить (так выглядит ограничение 16–20 КБ), «После ClientHello» — соединение "
         "оборвалось сразу после TLS ClientHello. Номера столбцов — сканеры из таблицы выше; "
         "группа — как её называет сервис.");
    const size_t n = std::min<size_t>(st.results.size(), 200);
    const float em = ImGui::GetFontSize();
    const float h = rowHeight() * (float)(rows.size() + 1) + ImGui::GetStyle().ScrollbarSize + em * 0.4f;
    const ImGuiTableFlags f = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollX |
                              ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##hosts", 3 + (int)n, f, ImVec2(0, h))) return;
    ImGui::TableSetupScrollFreeze(3, 1);
    ImGui::TableSetupColumn("Сервер");
    ImGui::TableSetupColumn("Группа");
    ImGui::TableSetupColumn("Итог");
    for (size_t i = 0; i < n; i++) {
        char nm[16];
        snprintf(nm, sizeof(nm), "%zu", i + 1);
        ImGui::TableSetupColumn(nm);
    }
    ImGui::TableHeadersRow();
    for (size_t r = 0; r < rows.size(); r++) {
        const HostRow& hr = rows[r];
        ImGui::PushID((int)r);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hr.id.c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(hr.group.empty() ? "—" : hr.group.c_str());
        ImGui::TableNextColumn();
        const auto cnt = evCounts(hr);
        if (cnt.size() == 1) {
            const Evid* ei = evidInfo(cnt[0].first);
            ImGui::TextColored(sevColor(ei ? ei->sev : -1), "%s", ei ? ei->label : cnt[0].first.c_str());
        } else if (cnt.empty()) {
            ImGui::TextColored(K.dim, "—");
        } else {
            ImGui::TextColored(K.warn, "Разные ответы");
        }
        tip(evCountsText(hr));
        for (size_t i = 0; i < n; i++) {
            ImGui::TableNextColumn();
            const JVal* e = hr.ev[i];
            if (!e) { ImGui::TextColored(K.dim, "·"); continue; }
            ImGui::TextColored(evColor(*e), "%s", evShort(*e).c_str());
            const JVal& sr = st.results[i].j;
            tip(evLabel(*e) + "\nСканер " + std::to_string(i + 1) + ": " + scannerRegion(sr) + " · " +
                sr["provider"].str());
        }
        ImGui::PopID();
    }
    ImGui::EndTable();
}

void drawDns(const RknState& st) {
    const DnsAgg a = dnsAgg(st.results);
    if (!a.scanners) return;
    char hdr[128];
    snprintf(hdr, sizeof(hdr), "Подмена DNS — заметили %d из %d сканеров###dns", a.spoofScanners, a.scanners);
    if (!ImGui::CollapsingHeader(hdr, ImGuiTreeNodeFlags_DefaultOpen)) return;
    hint("Каждый сканер спрашивает адрес цели у публичных DNS-сервисов по UDP, TCP, DoH и DoT. "
         "Подмена — ответ не похож на настоящий (обычно заглушка провайдера). В ячейке — сколько "
         "сканеров получили нормальный и подменённый ответ; наведите мышь — адреса и коды ответа.");
    if (a.providers.empty() || a.protocols.empty()) return;
    const int cols = 1 + (int)a.protocols.size();
    if (!ImGui::BeginTable("##dnst", cols, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                           ImGuiTableFlags_SizingFixedFit)) return;
    ImGui::TableSetupColumn("DNS-сервис");
    for (const auto& p : a.protocols) ImGui::TableSetupColumn(protoName(p));
    ImGui::TableHeadersRow();
    for (size_t pi = 0; pi < a.providers.size(); pi++) {
        const std::string& prov = a.providers[pi];
        ImGui::PushID((int)pi);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(provName(prov).c_str());
        for (size_t qi = 0; qi < a.protocols.size(); qi++) {
            ImGui::TableNextColumn();
            auto it = a.cells.find({prov, a.protocols[qi]});
            if (it == a.cells.end() || it->second.ok + it->second.spoof == 0) {
                ImGui::TextColored(K.dim, "—");
                continue;
            }
            const DnsCell& c = it->second;
            if (c.spoof) ImGui::TextColored(K.bad, "подмена %d / %d", c.spoof, c.spoof + c.ok);
            else ImGui::TextColored(K.good, "норма %d", c.ok);
            std::string t = "Нормальных ответов: " + std::to_string(c.ok) + ", подменённых: " + std::to_string(c.spoof);
            if (!c.spoofBy.empty()) {
                t += "\nПодмену заметили сканеры:";
                for (int s : c.spoofBy) t += " " + std::to_string(s);
            }
            if (!c.addrs.empty()) {
                t += "\nАдреса в ответах:";
                size_t k = 0;
                for (const auto& x : c.addrs) {
                    if (++k > 30) { t += "\n  … ещё " + std::to_string(c.addrs.size() - 30); break; }
                    t += "\n  " + x;
                }
            }
            if (!c.codes.empty()) {
                t += "\nКоды ответа:";
                for (const auto& x : c.codes) t += " " + x;
            }
            ImGui::PushID((int)qi);
            tip(t);
            ImGui::PopID();
        }
        ImGui::PopID();
    }
    ImGui::EndTable();
}

// Дерево JSON: все поля, в том числе те, о которых программа не знает.
void jsonTree(const std::string& key, const JVal& v) {
    if (v.t == JVal::OBJ || v.t == JVal::ARR) {
        const bool obj = v.t == JVal::OBJ;
        const ImGuiTreeNodeFlags tf = v.items.empty() ? ImGuiTreeNodeFlags_Leaf : 0;
        if (ImGui::TreeNodeEx("##n", tf, obj ? "%s  {%zu}" : "%s  [%zu]", key.c_str(), v.items.size())) {
            const size_t lim = 300;
            for (size_t i = 0; i < v.items.size() && i < lim; i++) {
                ImGui::PushID((int)i);
                jsonTree(obj ? v.keys[i] : "[" + std::to_string(i) + "]", v.items[i]);
                ImGui::PopID();
            }
            if (v.items.size() > lim)
                ImGui::TextColored(K.dim, "… ещё %zu (полностью — в «Сырые данные»)", v.items.size() - lim);
            ImGui::TreePop();
        }
        return;
    }
    ImGui::TreeNodeEx("##l", ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen |
                             ImGuiTreeNodeFlags_Bullet, "%s:", key.c_str());
    ImGui::SameLine();
    ImGui::PushTextWrapPos(0);
    switch (v.t) {
    case JVal::NUL:  ImGui::TextColored(K.dim, "null"); break;
    case JVal::BOOL: ImGui::TextColored(v.b ? K.good : K.dim, "%s", v.b ? "true" : "false"); break;
    case JVal::NUM:  ImGui::TextColored(K.accent, "%s", v.s.c_str()); break;
    default:         ImGui::TextUnformatted(v.s.empty() ? "\"\"" : v.s.c_str()); break;
    }
    ImGui::PopTextWrapPos();
}

void drawTree(const RknState& st) {
    if (!ImGui::CollapsingHeader("Все поля ответа")) return;
    hint("Ответ сервиса как есть, деревом — в том числе поля, которые программа не разбирает.");
    ImGui::PushID("tree");
    ImGui::PushID(0); jsonTree("check", st.check); ImGui::PopID();
    if (st.status.t == JVal::OBJ) { ImGui::PushID(1); jsonTree("status", st.status); ImGui::PopID(); }
    if (st.gotStarted) { ImGui::PushID(2); jsonTree("probe: started", st.started); ImGui::PopID(); }
    for (size_t i = 0; i < st.results.size(); i++) {
        ImGui::PushID(100 + (int)i);
        jsonTree("probe: result " + std::to_string(i + 1) + " — " + scannerRegion(st.results[i].j), st.results[i].j);
        ImGui::PopID();
    }
    if (st.gotDone) { ImGui::PushID(3); jsonTree("probe: done", st.done); ImGui::PopID(); }
    ImGui::PopID();
}

void rawBox(const char* id, const std::string& text) {
    const float em = ImGui::GetFontSize();
    ImGui::PushID(id);
    if (g_fontMono) ImGui::PushFont(g_fontMono, g_fontMono->LegacySize);
    // только чтение: ImGui буфер не меняет, const_cast безопасен
    ImGui::InputTextMultiline("##raw", const_cast<char*>(text.c_str()), text.size() + 1,
                              ImVec2(-FLT_MIN, em * 18), ImGuiInputTextFlags_ReadOnly);
    if (g_fontMono) ImGui::PopFont();
    ImGui::PopID();
}

void drawRaw(const RknState& st) {
    if (!ImGui::CollapsingHeader("Сырые данные (JSON)")) return;
    if (ImGui::TreeNode("##rc", "Ответ /api/v1/check (%s)", fmtBytes((long long)st.checkRaw.size()).c_str())) {
        if (ImGui::SmallButton("Копировать")) ImGui::SetClipboardText(st.checkRaw.c_str());
        rawBox("check", st.checkPretty);
        ImGui::TreePop();
    }
    if (!st.probePretty.empty() &&
        ImGui::TreeNode("##rp", "События сканеров /api/v1/probe (%zu)", st.results.size())) {
        if (ImGui::SmallButton("Копировать")) ImGui::SetClipboardText(st.probePretty.c_str());
        rawBox("probe", st.probePretty);
        ImGui::TreePop();
    }
}

void drawIntro() {
    ImGui::Spacing();
    hint("Проверка домена, IP-адреса, подсети или автономной системы по базе cheburcheck.ru: "
         "реестр РКН, заблокированные подсети, диапазоны CDN под ограничением 16–20 КБ, белый "
         "список CDN, жалобы пользователей.");
    hint("С галочкой «Сканеры из регионов» сервис ещё и проверяет цель с серверов у провайдеров в "
         "разных регионах России: блокировка на ТСПУ, по SNI, подмена DNS, ограничение CDN "
         "(занимает до минуты).");
    hint("Цель можно подставить из таблицы «Соединения»: правый щелчок по строке → «Проверить … в cheburcheck.ru».");
}

} // namespace

void rknCheck(const std::string& target) {
    snprintf(s_input, sizeof(s_input), "%s", target.c_str());
    startCheck(target);
}

bool rknDrawTab(const GuiColors& c) {
    K = c;
    const float em = ImGui::GetFontSize();
    std::shared_ptr<RknState> sp = s_st;
    const bool live = sp && sp->running && !sp->abort;

    ImGui::SetNextItemWidth(std::min(em * 24, ImGui::GetContentRegionAvail().x * 0.5f));
    const bool enter = ImGui::InputTextWithHint("##rkntarget", "домен, IP, подсеть 1.2.3.0/24 или AS13335",
                                                s_input, sizeof(s_input), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Проверить") || enter) {
        startCheck(s_input);
        sp = s_st;
    }
    if (live) {
        ImGui::SameLine();
        if (ImGui::Button("Остановить")) sp->abort = true;
    }
    ImGui::SameLine();
    ImGui::Checkbox("Сканеры из регионов", &s_withProbe);
    tip("Кроме проверки по спискам — активная проверка с серверов у провайдеров в регионах России "
        "(около 16 сканеров, до минуты).");
    ImGui::TextColored(K.dim, "Запрос уходит на cheburcheck.ru (сторонний сервис, API неофициальное): "
                              "отправляется только введённая цель, данные дампа — нет.");
    ImGui::Separator();

    if (!sp) { drawIntro(); return false; }

    const bool liveNow = sp->running && !sp->abort;
    ImGui::BeginChild("##rknbody");
    {
        std::lock_guard<std::mutex> lk(sp->mx);
        RknState& st = *sp;
        // диапазоны CDN — объект «провайдер → подсети»; массив (API сменило формат,
        // ответ подменён) не разбираем: в нём нет ключей-провайдеров
        const JVal& cdn = st.check["cdn_providers"];
        const bool hasCdn = cdn.t == JVal::OBJ && cdn.size() > 0;
        drawHeader(st, liveNow, hasCdn);
        if (st.checkOk) {
            ImGui::Spacing();
            drawCards(st, hasCdn, liveNow);
            ImGui::Spacing();
            drawNet(st);
            drawLists(st, hasCdn);
            drawComplaints(st);
            drawScanners(st, hasCdn, liveNow);
            drawCdnHosts(st);
            drawDns(st);
            drawTree(st);
            drawRaw(st);
        } else if (!st.checkRaw.empty() && !liveNow) {
            // ошибка, но сервис что-то ответил — покажем
            ImGui::TextColored(K.dim, "Ответ сервиса:");
            std::string head = st.checkRaw.substr(0, 4000);
            rawBox("err", head);
        }
    }
    ImGui::EndChild();
    return liveNow;
}
