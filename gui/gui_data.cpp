// gui_data.cpp — данные GUI: загруженный набор дампов и таблица соединений,
// фоновые задачи анализа (по одной за раз, вывод — в журнал окна) и запуск
// интерактивных инструментов отдельным процессом в своей консоли.
#include "gui_app.h"

namespace {

// ---- текущий набор (читает поток окна, заменяют фоновые задачи) ----
std::mutex g_mx;
std::shared_ptr<Dataset> g_ds;
std::shared_ptr<const DumpSummary> g_summary;
std::shared_ptr<const IpCache> g_ipCache;
unsigned g_gen = 0;

// ---- фоновая задача ----
std::atomic<bool> g_busy{false};
std::atomic<bool> g_jobFailed{false};  // последняя задача закончилась ошибкой
std::mutex g_titleMx;
std::string g_title;
std::thread g_job;

// ---- запущенные инструменты ----
#ifdef _WIN32
struct ToolEntry { HANDLE h; int mode; std::string title; };
#else
// macOS: инструмент идёт в окне Терминала; пока жив файл-метка — считаем запущенным
// (оболочка удаляет его при выходе, в том числе при закрытии окна)
struct ToolEntry { std::string marker; int mode; std::string title; };
#endif
std::mutex g_toolMx;
std::vector<ToolEntry> g_tools;

std::string lowerAscii(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

void publish(std::shared_ptr<Dataset> ds) {
    std::lock_guard<std::mutex> lk(g_mx);
    g_summary = ds->summary;
    g_ipCache = ds->ipCache;
    g_ds = std::move(ds);
    ++g_gen;
}

// Детекторы анализа опираются на глобальный g_localIp — перед работой с
// набором ставим его адреса (другой набор мог их перезаписать).
void selectLocal(const Dataset& ds) {
    g_localIp = ds.localIp;
    g_localIp6 = ds.localIp6;
}

// Колонка «Приложение». Сначала — по содержимому (сигнатуры WireGuard,
// L7Proto, DNS, QUIC): это факт. Иначе — догадка по порту, со знаком «?».
// Входящее соединение (SYN к абоненту) подписываем портом абонента: к
// роутеру стучатся сканеры на 23/22/…, и «Telnet» без «?» вводил в заблуждение.
std::string flowApp(FlowRow& r) {
    const bool incoming = r.proto == "TCP" && r.synIn > 0 && r.synOut == 0;
    const char* byRemote = appByPort(r.remotePort, r.proto);
    std::string s;
    if (r.wg) s = "WireGuard";
    else if (r.l7 == L7_TLS) {
        // TLS не на своём порту (22, 1194, …) показываем вместе с портом —
        // это само по себе интересно (обёртка VPN/прокси в TLS)
        if (r.remotePort == 443 || r.remotePort == 8443) s = "HTTPS";
        else s = byRemote ? std::string(byRemote) + " (TLS)" : "TLS";
    }
    else if (r.l7 != L7_NONE) s = l7Name(r.l7);
    else if (r.dns) s = "DNS";
    else if (r.quic) s = "QUIC";
    r.appByContent = !s.empty();
    if (!s.empty()) return incoming ? s + " (входящее)" : s;

    if (incoming) {
        const char* loc = appByPort(r.localPort, r.proto);
        return "входящее на :" + std::to_string(r.localPort) +
               (loc ? std::string(" (") + loc + "?)" : std::string());
    }
    return byRemote ? std::string(byRemote) + "?" : std::string();
}

// ---- временной профиль TCP-соединения (FlowRow::wf) ----
const size_t kWfMaxEvents = 400;
const long long kWfDataGapUs = 1000000;    // пауза ≥1 с разрывает серию данных — тишина видна
const long long kWfRetxGapUs = 30000000;   // повторы с нарастающей паузой (1, 2, 4… с) — одна серия
const long long kWfRstBurstUs = 200000;    // пачка RST (DPI шлёт несколько с разными seq)

// Состояние сборки на время прохода по пакетам (параллельно rows).
struct WfBuild {
    long long maxEnd[2] = { -1, -1 };  // [out]: конец уже виденных данных по seq
    int openData[2] = { -1, -1 };      // [out]: индекс последней серии данных в r.wf
    int openRetx[2] = { -1, -1 };      // [out]: индекс последней серии повторов
    int lastPoint = -1;                // индекс последнего точечного события (SYN, RST, …)
    // эталон TTL сервера — как в buildTcpConnTable / connTtlInjection
    int synAckTtl = -1, dataTtl = -1;
    long long serverBytes = 0;
    int lastInId = -1, lastInTtl = -1;   // IP ID и TTL последнего входящего не-RST до первого RST
    int rstEv = -1;                      // событие последнего входящего RST
    long long rstUs = -1;
    int rstId = -1;
    long long rstLastUs = -1;            // последний входящий RST (любой): время, IP ID и seq
    int rstLastId = -1;
    long long rstLastSeq = -1;
    bool inRst = false;                  // входящий RST уже был
    // «заморозка ~16 КБ» — как в buildTcpConnTable (см. frzAdd)
    long long frzInEnd = -1, frzOutEnd = -1;   // правый край принятых / отправленных данных (seq)
    long long frzLastIn = -1;                  // последний входящий пакет (любой)
    long long frzProbeOut = -1;                // последний исходящий ACK/keepalive/FIN (0–1 байт)
    long long frzLastNew = -1;                 // последние новые данные сервера
};

// a не дальше b по seq (с переполнением 32 бит)
bool seqLE(long long a, long long b) { return (int32_t)((uint32_t)a - (uint32_t)b) <= 0; }

// позади правого края больше чем на 2^30 — не повтор, а смена базы номеров
// (как seqRebased в analyzer.cpp)
bool seqRebased(long long maxEnd, long long seq) {
    return maxEnd >= 0 && (int32_t)((uint32_t)seq - (uint32_t)maxEnd) < -(1 << 30);
}

int wfPush(FlowRow& r, const FlowEvent& e) {
    if (r.wf.size() >= kWfMaxEvents) { r.wfDropped++; return -1; }
    r.wf.push_back(e);
    return (int)r.wf.size() - 1;
}

// Дописать пакет в событие i, если пауза после него не больше gap.
bool wfExtend(FlowRow& r, int i, long long rel, long long bytes, long long gap) {
    if (i < 0 || (size_t)i >= r.wf.size()) return false;
    FlowEvent& e = r.wf[(size_t)i];
    if (rel - e.endUs > gap) return false;
    e.endUs = std::max(e.endUs, rel);
    e.bytes += bytes;
    e.count++;
    return true;
}

// Пакет TCP в профиль потока. Чистые ACK пропускаем: профиль — о том, кто
// что прислал и где тишина.
void wfAdd(FlowRow& r, WfBuild& b, const Packet& p, bool out, long long rel) {
    const int d = out ? 1 : 0;
    const bool S = p.flags.find('S') != std::string::npos;
    const bool A = p.flags.find('.') != std::string::npos;
    const bool R = p.flags.find('R') != std::string::npos;
    const bool F = p.flags.find('F') != std::string::npos;
    FlowEvent e;
    e.us = e.endUs = rel; e.out = out; e.ttl = p.ttl; e.bytes = p.length;
    auto point = [&](uint8_t kind) {
        e.kind = kind;
        const int i = wfPush(r, e);
        if (i >= 0) b.lastPoint = i;
    };
    // то же событие сразу перед этим (повтор SYN, пачка RST) — дописываем в него
    auto repeatOfLast = [&](uint8_t kind, long long gap) {
        return b.lastPoint >= 0 && (size_t)b.lastPoint + 1 == r.wf.size() &&
               r.wf[(size_t)b.lastPoint].kind == kind && r.wf[(size_t)b.lastPoint].out == out &&
               wfExtend(r, b.lastPoint, rel, p.length, gap);
    };

    // как в buildTcpConnTable: эталон счётчика — пакеты сервера ДО первого RST
    if (!out && !R && !b.inRst) { b.lastInId = p.ipId; b.lastInTtl = p.ttl; }
    // ответ сервера после RST (не SYN, не пакет, отправленный раньше RST)
    if (!out && !R && !S && b.rstEv >= 0 && rel - b.rstUs <= 2000000 &&
        !ipIdBefore(p.ipId, b.rstId))
        r.wf[(size_t)b.rstEv].afterRst++;
    if (S) {
        const uint8_t k = A ? FE_SYNACK : FE_SYN;
        if (!out && A && p.ttl >= 0 && b.synAckTtl < 0) b.synAckTtl = p.ttl;
        if (!repeatOfLast(k, LLONG_MAX)) point(k);
        return;
    }
    if (R) {
        if (out) {
            if (!repeatOfLast(FE_RST, kWfRstBurstUs)) point(FE_RST);
            return;
        }
        b.inRst = true;
        // одинаковые RST от инжектора — пачка; копия захвата — нет
        const bool copy = ipIdCaptureCopy(p.ipId, b.rstLastId, p.seqStart, b.rstLastSeq, rel - b.rstLastUs);
        b.rstLastUs = rel; b.rstLastId = p.ipId; b.rstLastSeq = p.seqStart;
        if (repeatOfLast(FE_RST, kWfRstBurstUs)) {
            if (b.rstEv == b.lastPoint && !copy) r.wf[(size_t)b.rstEv].burst++;
            return;
        }
        // как rstServerId в buildTcpConnTable
        e.serverId = ipIdNext(b.lastInId, p.ipId) && p.ttl == b.lastInTtl;
        e.burst = 1;
        const size_t n0 = r.wf.size();
        point(FE_RST);
        if (r.wf.size() > n0) { b.rstEv = (int)n0; b.rstUs = rel; b.rstId = p.ipId; }
        return;
    }
    if (p.length > 0) {
        if (!out) {
            b.serverBytes += p.length;
            if (p.ttl >= 0 && b.dataTtl < 0) b.dataTtl = p.ttl;
        }
        bool retx = false;
        if (p.seq >= 0) {
            // позади больше чем на 2^30 — не повтор, а сменилась база номеров
            // (как seqRebased в buildTcpConnTable)
            if (b.maxEnd[d] >= 0 && seqLE(p.seq, b.maxEnd[d]) &&
                (int32_t)((uint32_t)p.seq - (uint32_t)b.maxEnd[d]) >= -(1 << 30)) retx = true;
            else b.maxEnd[d] = p.seq;
        }
        if (retx) {
            // серия повторов — пока между ними не было новых данных и точечных событий
            if (!(b.openRetx[d] > b.lastPoint && b.openRetx[d] > b.openData[d] &&
                  wfExtend(r, b.openRetx[d], rel, p.length, kWfRetxGapUs))) {
                e.kind = FE_RETX;
                b.openRetx[d] = wfPush(r, e);
            }
        } else if (out && !p.sni.empty()) point(FE_HELLO);
        else if (out && !p.httpHost.empty()) point(FE_HTTPREQ);
        else if (!out && p.httpStatus > 0) { e.code = p.httpStatus; point(FE_HTTPRESP); }
        else if (!(b.openData[d] > b.lastPoint && b.openData[d] > b.openRetx[d] &&
                   wfExtend(r, b.openData[d], rel, p.length, kWfDataGapUs))) {
            e.kind = FE_DATA;
            b.openData[d] = wfPush(r, e);
        }
    }
    if (F) { e.bytes = 0; point(FE_FIN); }
}

// «Заморозка ~16 КБ»: счётчики по тем же правилам, что inUniqBytes / lastNewData /
// laterPkts в buildTcpConnTable, — подсказка в профиле не расходится с режимом 2.
// Отдельно от wfAdd: у профиля свои правила (1 байт — тоже данные).
void frzAdd(FlowRow& r, WfBuild& b, const Packet& p, bool out, long long rel) {
    const bool S = p.flags.find('S') != std::string::npos;
    const bool R = p.flags.find('R') != std::string::npos;
    bool repeat = false;   // повтор уже отправленного/принятого
    if (out) {
        if (S || R) return;
        if (p.length > 1) {
            // данные: повтор, если этот seq уже уходил (без seq повтор не отличить)
            if (p.seq < 0 || (b.frzOutEnd >= 0 && seqLE(p.seq, b.frzOutEnd) && !seqRebased(b.frzOutEnd, p.seq)))
                repeat = true;
            else b.frzOutEnd = p.seq;
        } else {
            // ACK, keepalive, FIN: повтор, только если на прошлый такой сервер не ответил
            // ничем — простаивающее keep-alive-соединение не «заморозка»
            if (b.frzProbeOut >= 0 && b.frzLastIn < b.frzProbeOut) repeat = true;
            b.frzProbeOut = rel;
        }
    } else {
        b.frzLastIn = rel;
        if (p.length > 0 && !R) {
            // новые данные или повтор уже принятого; перекрытие с принятым не в счёт
            bool fresh = true;
            long long add = p.length;
            if (p.seq >= 0) {
                const long long maxEnd = seqRebased(b.frzInEnd, p.seq) ? -1 : b.frzInEnd;
                if (maxEnd >= 0 && seqLE(p.seq, maxEnd)) fresh = false;
                else if (maxEnd >= 0)
                    add = std::min(add, (long long)(uint32_t)((uint32_t)p.seq - (uint32_t)maxEnd));
                if (fresh) b.frzInEnd = p.seq;
            }
            if (fresh) { r.frzBytes += add; b.frzLastNew = rel; r.frzLater = 0; return; }
            repeat = true;
        }
    }
    // повтор (в любую сторону) спустя ≥1 с после последних новых данных
    if (repeat && b.frzLastNew >= 0 && rel - b.frzLastNew >= 1000000) r.frzLater++;
}

// После прохода: эталонный TTL сервера для входящих RST — данные сервера
// (если их ≥200 Б), иначе SYN-ACK. Правило то же, что в connTtlInjection.
void wfFinish(FlowRow& r, const WfBuild& b) {
    for (FlowEvent& e : r.wf) {
        if (e.kind != FE_RST || e.out) continue;
        if (b.dataTtl >= 0 && b.serverBytes >= 200) { e.ttlRef = b.dataTtl; e.code = 1; }
        else if (b.synAckTtl >= 0)                  { e.ttlRef = b.synAckTtl; e.code = 2; }
    }
}

// Таблица соединений: агрегат пакетов по proto + локальный + удалённый конец.
void buildFlows(Dataset& ds) {
    const std::vector<Packet>& pk = ds.packets;
    std::vector<long long> ts = absTimes(pk);
    long long t0 = -1, t1 = -1;
    for (long long v : ts) if (v >= 0) { if (t0 < 0) t0 = v; t1 = std::max(t1, v); }
    ds.durSec = (t0 >= 0 && t1 > t0) ? (t1 - t0) / 1e6 : 0;

    // имена адресов: из ответов DNS (запрос сопоставляем по id — в ответе
    // текстового tcpdump имени нет), затем HTTP Host и SNI поверх (они точнее)
    std::map<std::string, std::string> dnsById;
    std::map<std::string, std::string> sniByIp, hostByIp;

    std::unordered_map<std::string, size_t> idx;
    std::vector<FlowRow>& rows = ds.flows;
    rows.clear();
    ds.totalBytes = 0;
    std::vector<WfBuild> wb;                    // параллельно rows (до сортировки)
    std::vector<UdpSessStat> us;                // тоже: оборвавшаяся UDP-сессия, как UDP_SESSION
    long long lastInAny = -1;                   // последний входящий из интернета (rel)

    for (size_t i = 0; i < pk.size(); i++) {
        const Packet& p = pk[i];
        ds.totalBytes += p.length;

        // запрос и ответ — по (IP клиента, порт клиента, id): один id у разных
        // программ/устройств совпадает, и по одному id имя доставалось чужое
        if (!p.dnsQuery.empty() && !p.dnsIsResponse && !p.dnsId.empty())
            dnsById[p.srcIp + "|" + std::to_string(p.srcPort) + "|" + p.dnsId] = p.dnsQuery;
        if (p.dnsIsResponse && !p.dnsAnswers.empty()) {
            std::string name = p.dnsQuery;
            if (name.empty()) {
                auto it = dnsById.find(p.dstIp + "|" + std::to_string(p.dstPort) + "|" + p.dnsId);
                if (it != dnsById.end()) name = it->second;
            }
            if (!name.empty())
                for (const auto& a : p.dnsAnswers) ds.ipName.emplace(a, name);
            if (!name.empty() && !p.dnsCnames.empty()) {
                std::string chain = name;
                for (const auto& c : p.dnsCnames) chain += " → " + c;
                for (const auto& a : p.dnsAnswers) ds.ipCname.emplace(a, chain);
            }
        }

        const bool srcLocal = isLocalIp(p.srcIp), dstLocal = isLocalIp(p.dstIp);
        // исходящий = от абонента; если оба конца свои (или оба чужие) —
        // клиентом считаем сторону с большим (эфемерным) портом. Порты равны
        // (53↔53, 123, 500) — сторона абонента, иначе меньший IP: правило не
        // должно зависеть от направления пакета, иначе ответы уходили в
        // отдельную строку и обе строки выглядели «в одну сторону»
        auto isSub = [&](const std::string& ip) { return ip == ds.localIp || ip == ds.localIp6; };
        bool out;
        if (srcLocal != dstLocal) out = srcLocal;
        else if (p.srcPort != p.dstPort) out = p.srcPort > p.dstPort;
        else if (isSub(p.srcIp) != isSub(p.dstIp)) out = isSub(p.srcIp);
        else out = p.srcIp < p.dstIp;
        const std::string& lip = out ? p.srcIp : p.dstIp;
        const std::string& rip = out ? p.dstIp : p.srcIp;
        int lport = out ? p.srcPort : p.dstPort;
        int rport = out ? p.dstPort : p.srcPort;

        std::string key = p.proto + '|' + lip + '|' + std::to_string(lport) + '|' +
                          rip + '|' + std::to_string(rport);
        auto ins = idx.emplace(key, rows.size());
        if (ins.second) {
            FlowRow r;
            r.proto = p.proto; r.localIp = lip; r.remoteIp = rip;
            r.localPort = lport; r.remotePort = rport;
            rows.push_back(std::move(r));
            wb.emplace_back();
            us.emplace_back();
        }
        FlowRow& r = rows[ins.first->second];

        if (ts[i] >= 0 && t0 >= 0) {
            long long rel = ts[i] - t0;
            if (r.firstUs < 0) r.firstUs = rel;
            r.lastUs = std::max(r.lastUs, rel);
        }
        if (out) { r.pktsOut++; r.bytesOut += p.length; }
        else     { r.pktsIn++;  r.bytesIn += p.length; }

        if (p.proto == "TCP") {
            const bool syn = p.flags.find('S') != std::string::npos;
            const bool ack = p.flags.find('.') != std::string::npos;
            const bool rst = p.flags.find('R') != std::string::npos;
            const bool fin = p.flags.find('F') != std::string::npos;
            if (syn && !ack) { if (out) r.synOut++; else r.synIn++; }
            if (syn && ack)  { if (out) r.synAckOut++; else r.synAckIn++; }
            if (rst) { if (out) r.rstOut++; else r.rstIn++; }
            if (fin) { if (out) r.finOut++; else r.finIn++; }
        }
        if (!out && p.ttl >= 0) {
            if (r.ttlMin < 0 || p.ttl < r.ttlMin) r.ttlMin = p.ttl;
            if (p.ttl > r.ttlMax) r.ttlMax = p.ttl;
        }
        if (out && !p.sni.empty()) {
            r.sni = p.sni;
            sniByIp[rip] = p.sni;
        }
        if (out && !p.ja4.empty()) {
            r.ja4 = p.ja4; r.tlsClient = p.tlsClient; r.ja4Kind = p.ja4Kind;
        }
        const long long rel = (ts[i] >= 0 && t0 >= 0) ? ts[i] - t0 : -1;
        // первые данные абонента — как firstOutDataTime в buildTcpConnTable (>1 байта:
        // keep-alive не в счёт)
        if (out && p.length > 1 && rel >= 0 && r.firstOutDataUs < 0) r.firstOutDataUs = rel;
        if (srcLocal != dstLocal) {
            if (!out && rel > lastInAny) lastInAny = rel;
            if (p.proto == "UDP") us[ins.first->second].add(out, rel);
        }
        if (p.proto == "TCP" && (p.tlsHs || r.certReq)) {
            // mTLS: запрос сертификата клиента и что было дальше (как в buildTcpConnTable)
            const bool rst = p.flags.find('R') != std::string::npos;
            if (out) {
                if (p.tlsHs & TLSHS_CERT) r.clientCert = 1;
                else if (p.tlsHs & TLSHS_CERT_EMPTY) r.clientCert = 0;
                if (p.tlsHs & TLSHS_CCS) r.outCcs = true;
                else if (r.certReq && r.outCcs && r.mtlsReqUs < 0 && rel >= 0 && p.length > 1 && !rst &&
                         p.flags.find('S') == std::string::npos)
                    r.mtlsReqUs = rel;
            } else {
                if (p.tlsHs & TLSHS_CERT_REQ) r.certReq = true;
                if ((p.tlsHs & TLSHS_ALERT) && r.tlsAlertIn < 0) r.tlsAlertIn = p.tlsAlert;
                if (r.inCcs && p.length > 0 && !rst) {
                    r.inAppBytes += p.length;
                    if (r.mtlsReqUs >= 0 && r.mtlsRespUs < 0) r.mtlsRespUs = rel;
                }
                if (p.tlsHs & TLSHS_CCS) r.inCcs = true;
            }
        }
        if (out && !p.httpHost.empty() && r.httpHost.empty()) {
            r.httpHost = p.httpHost;
            r.httpReqUs = rel;
            hostByIp[rip] = p.httpHost;
        }
        if (out && r.msBg.empty() && (!p.httpHost.empty() || !p.httpUa.empty() || !p.httpPath.empty() ||
                                      !p.sni.empty())) {
            const char* w = msBackgroundDownload(p.httpHost, p.httpUa, p.httpPath);
            if (!w && !p.sni.empty()) w = msBackgroundDownload(p.sni);
            if (w) r.msBg = w;
        }
        if (!out && p.httpStatus > 0 && r.httpStatus == 0) {
            r.httpStatus = p.httpStatus;
            r.httpLocation = p.httpLocation;
            r.httpRespUs = rel;
        }
        if (!out && !p.httpBlockMark.empty() && r.httpBlockMark.empty())
            r.httpBlockMark = p.httpBlockMark;
        if (p.proto == "TCP" && rel >= 0) {
            wfAdd(r, wb[ins.first->second], p, out, rel);
            frzAdd(r, wb[ins.first->second], p, out, rel);
        }
        if (p.ech) r.ech = true;
        if (p.quic) r.quic = true;
        if (p.wgType) r.wg = true;
        if (p.l7 != L7_NONE && r.l7 == L7_NONE) r.l7 = p.l7;
        if (!p.dnsId.empty()) r.dns = true;
    }
    for (auto& kv : hostByIp) ds.ipName[kv.first] = kv.second;
    for (auto& kv : sniByIp) ds.ipName[kv.first] = kv.second;
    for (size_t i = 0; i < rows.size(); i++) wfFinish(rows[i], wb[i]);
    // сервер, обслуживший пустой сертификат клиента (clientCertServed), проверяет
    // его необязательно — его соседние соединения без Alert проблемой не считаем
    // (как в collectBlockReasons: по адресу и по имени)
    std::set<std::string> certServed;
    for (const FlowRow& r : rows)
        if (clientCertServed(r.certReq, r.clientCert, r.tlsAlertIn, r.inAppBytes)) {
            certServed.insert(r.remoteIp);
            if (!r.sni.empty()) certServed.insert(r.sni);
        }

    const long long durUs = (t0 >= 0 && t1 > t0) ? t1 - t0 : 0;
    const long long tail = cfg().tailUs;
    for (size_t ri = 0; ri < rows.size(); ri++) {
        FlowRow& r = rows[ri];
        auto nm = ds.ipName.find(r.remoteIp);
        if (nm != ds.ipName.end()) r.dnsName = nm->second;
        auto cn = ds.ipCname.find(r.remoteIp);
        if (cn != ds.ipCname.end()) r.dnsCname = cn->second;
        if (r.msBg.empty() && !r.dnsName.empty()) {
            const char* w = msBackgroundDownload(r.dnsName);
            if (w) r.msBg = w;
        }
        if (r.msBg.empty() && !r.dnsCname.empty()) {
            // цепочка «имя → cname → …»: проверяем каждое звено
            const std::string sep = " → ";
            size_t b = 0;
            while (r.msBg.empty() && b <= r.dnsCname.size()) {
                size_t e = r.dnsCname.find(sep, b);
                if (e == std::string::npos) e = r.dnsCname.size();
                const char* w = msBackgroundDownload(r.dnsCname.substr(b, e - b));
                if (w) r.msBg = w;
                b = e + sep.size();
            }
        }
        r.app = flowApp(r);
        // ECH показываем только настоящий: внешний SNI — публичное имя провайдера.
        // Иначе расширение холостое (GREASE ECH браузера), и SNI — сам домен.
        r.ech = r.ech && isEchPublicName(r.sni);
        // «заморозка ~16 КБ»: тишина от последних новых данных сервера до конца записи
        // (как tEnd − lastNewData в connFreeze16k)
        if (wb[ri].frzLastNew >= 0) r.frzSilenceUs = durUs - wb[ri].frzLastNew;

        // SYN в самом конце дампа: ответ мог просто не попасть в запись
        const bool inTail = durUs > 0 && r.firstUs >= 0 && r.firstUs > durUs - tail;
        if (r.proto != "TCP") {
            r.state = FS_UDP;
            r.problem = r.pktsOut >= 3 && r.pktsIn == 0 && !inTail;
            // сервер отвечал, потом замолчал, абонент шлёт дальше (игра, голос);
            // DNS и QUIC не берём — как в collectBlockReasons
            if (!r.problem && !r.dns && !r.quic && r.remotePort != 53 && r.remotePort != 443 &&
                r.localPort != 53 && us[ri].died(lastInAny))
                r.problem = true;
        } else if (r.synIn > 0 && r.synOut == 0) {
            // Входящее соединение к абоненту — обычно сканер из интернета. Порт
            // закрыт (RST) или файрвол молчит — это норма, а не проблема связи.
            // Принятые входящие тоже не помечаем: абонент здесь сервер, а
            // проблемы, которые ищет поддержка, — в его исходящих соединениях.
            if (r.synAckOut == 0) r.state = FS_IN_REFUSED;
            else r.state = (r.rstIn > 0 && r.finIn == 0 && r.finOut == 0) ? FS_RST : FS_OK;
            r.problem = false;
        } else if (r.synOut > 0 && r.synAckIn == 0 && r.rstIn == 0 && r.bytesIn == 0) {
            // ни SYN-ACK, ни RST, ни данных сервера — как «нет ответа» в «Обзоре»
            // (!inRst) и synFail в режиме 2 (!sawData). RST на SYN (порт закрыт, ТСПУ) —
            // «сброс» ниже; данные без SYN-ACK — его просто нет в записи, дальше как обычно
            r.state = FS_NO_ANSWER;
            r.problem = !inTail;
        } else if (r.rstIn > 0) {
            r.state = FS_RST;
            // RST после обмена FIN — обычное закрытие, не проблема
            r.problem = r.finIn == 0 && r.finOut == 0;
        } else if (r.synOut == 0 && r.synIn == 0) {
            r.state = FS_MIDSTREAM;
            r.problem = r.pktsOut >= 3 && r.pktsIn == 0;
        } else if (r.bytesIn == 0 && r.finIn == 0 && r.firstOutDataUs >= 0) {
            // рукопожатие прошло, абонент шлёт данные, а сервер — ни байта, без RST и
            // FIN: запрос до него не дошёл или ответ отброшен по пути (OpenVPN-TCP под
            // ТСПУ и т.п.). Как connSilentDrop в режиме 2, но на любом порту; «хвост» —
            // от первых данных абонента: отправлены в самом конце — ответ мог не попасть
            r.state = FS_ONE_WAY;
            r.problem = durUs - r.firstOutDataUs >= tail;
        } else {
            r.state = FS_OK;
        }
        if (!r.httpBlockMark.empty()) r.problem = true;   // страница-заглушка о блокировке
        // сервер требует сертификат клиента (TLS_CLIENT_CERT) — не блокировка, но
        // приложение с ним не работает
        r.certProblem = clientCertProblem(r.certReq, r.clientCert, r.tlsAlertIn, r.inAppBytes,
                                          r.mtlsReqUs >= 0) &&
                        (tlsAlertCertReject(r.tlsAlertIn) ||
                         (!certServed.count(r.remoteIp) && !certServed.count(r.sni)));
        if (r.certProblem) r.problem = true;

        r.search = lowerAscii(r.proto + " " + r.localIp + ":" + std::to_string(r.localPort) +
                              " " + r.remoteIp + ":" + std::to_string(r.remotePort) + " " +
                              r.sni + " " + r.httpHost + " " + r.dnsName + " " + r.app + " " +
                              r.tlsClient + " " + r.ja4 + " " + r.dnsCname + " " + r.msBg +
                              (r.certReq ? " mtls" : ""));
    }
    std::sort(rows.begin(), rows.end(), [](const FlowRow& a, const FlowRow& b) {
        return a.bytesIn + a.bytesOut > b.bytesIn + b.bytesOut;
    });
}

// Загрузка набора в новый Dataset (без публикации). nullptr — не удалось.
std::shared_ptr<Dataset> loadDataset(std::vector<std::string> paths) {
    addSiblingDump(paths);
    auto ds = std::make_shared<Dataset>();
    std::vector<int> origin;
    if (!loadDumpSet(paths, ds->packets, origin)) return nullptr;
    ds->paths = paths;
    ds->name = dumpSetName(paths);
    ds->localIp = g_localIp;       // loadDumpSet определил адреса абонента
    ds->localIp6 = g_localIp6;
    buildFlows(*ds);
    ds->summary = std::make_shared<const DumpSummary>(
        summarizeDump(ds->packets, ds->name, nullptr));
    return ds;
}

void setTitle(const std::string& t) {
    std::lock_guard<std::mutex> lk(g_titleMx);
    g_title = t;
}

// Сообщение об ошибке задачи: в журнал красным, уведомление — «Ошибка», а не «Завершено».
void jobFail(const std::string& msg) {
    logLine(C::RED, msg);
    g_jobFailed = true;
}

// Запуск задачи в фоне. false — уже идёт другая.
bool startJob(const std::string& title, std::function<void()> fn) {
    bool expected = false;
    if (!g_busy.compare_exchange_strong(expected, true)) return false;
    g_jobFailed = false;
    if (g_job.joinable()) g_job.join();     // предыдущая уже закончилась
    setTitle(title);
    guiRequestLogTab();
    g_job = std::thread([title, fn = std::move(fn)] {
        g_traceAbort = false;
        std::cout << "\n" << C::BCYN << ">>> " << title << C::RST << "\n";
        try {
            fn();
        } catch (const std::exception& e) {
            jobFail(std::string("Ошибка: ") + e.what());
        } catch (...) {
            jobFail("Неизвестная ошибка во время анализа.");
        }
        if (g_report) { closeReport(); std::cout << "Отчёт сохранён.\n"; }
        std::cout.flush();
        logLine(C::GRY, "--- готово ---");
        setTitle("");
        g_busy = false;
    });
    return true;
}

std::shared_ptr<Dataset> currentDs() {
    std::lock_guard<std::mutex> lk(g_mx);
    return g_ds;
}

// Страна/ASN/хостинг для публичных адресов набора (внутри фоновой задачи).
void resolveDataset(const std::shared_ptr<Dataset>& ds) {
    selectLocal(*ds);
    std::shared_ptr<const IpCache> old;
    { std::lock_guard<std::mutex> lk(g_mx); old = g_ipCache; }
    auto cache = std::make_shared<IpCache>(old ? *old : IpCache{});

    std::set<std::string> pub, recheck;
    for (const auto& r : ds->flows) {
        if (isLocalIp(r.remoteIp) || isPrivateIp(r.remoteIp)) continue;
        auto it = cache->find(r.remoteIp);
        if (it == cache->end()) pub.insert(r.remoteIp);
        else if (it->second.pxType.empty()) recheck.insert(r.remoteIp);
    }
    // адреса из кэша, которые ещё не сверяли с IP2Proxy (базу подключили
    // после первого резолва) — сверяем: это локальный файл, лимитов нет
    if (!recheck.empty() && ip2proxyEnabled())
        ip2proxyApply(*cache, std::vector<std::string>(recheck.begin(), recheck.end()));
    std::vector<std::string> list(pub.begin(), pub.end());
    if (!list.empty()) {
        std::cout << "Резолвлю " << list.size() << " адрес(ов)...\n";
        resolveIps(list, *cache);
        resolveHostingSecondary(*cache, list);
        size_t got = 0;
        for (const auto& ip : list) if (cache->count(ip)) got++;
        if (got < list.size())
            logLine(C::YEL, "Не определено " + std::to_string(list.size() - got) + " из " +
                    std::to_string(list.size()) + " адресов — сервисы не ответили, "
                    "повторите «Резолв ASN» позже.");
    } else {
        std::cout << "Новых публичных адресов нет.\n";
    }
    // сводка с учётом ASN (детекторы Reality/хостинга без неё слепые)
    auto sum = std::make_shared<const DumpSummary>(
        summarizeDump(ds->packets, ds->name, cache.get()));
    std::lock_guard<std::mutex> lk(g_mx);
    if (g_ds == ds) {
        g_ipCache = cache;
        g_summary = sum;
        ++g_gen;
    }
}

} // namespace

View snapshot() {
    std::lock_guard<std::mutex> lk(g_mx);
    View v;
    v.ds = g_ds;
    v.summary = g_summary;
    v.ipCache = g_ipCache;
    v.generation = g_gen;
    return v;
}

bool jobBusy() { return g_busy; }
bool jobFailed() { return g_jobFailed; }

std::string jobTitle() {
    std::lock_guard<std::mutex> lk(g_titleMx);
    return g_title;
}

bool jobMustAbortOnExit() {
    if (g_busy) return true;
    if (g_job.joinable()) g_job.join();
    return false;
}

void startLoad(std::vector<std::string> paths) {
    if (paths.empty()) return;
    startJob("Загрузка: " + dumpSetName(paths), [paths] {
        auto ds = loadDataset(paths);
        if (!ds) { jobFail("Дамп не загружен."); return; }
        size_t problems = 0;
        for (const auto& r : ds->flows) if (r.problem) problems++;
        publish(ds);
        char buf[256];
        snprintf(buf, sizeof(buf), "Загружено: %zu пакетов, %zu соединений (%zu с признаками проблем), %.1f с.",
                 ds->packets.size(), ds->flows.size(), problems, ds->durSec);
        logLine(C::GRN, buf);
        // таблица уже показана; страну/ASN дорезолвим в той же задаче
        if (cfg().autoResolve) {
            resolveDataset(ds);
            logLine(C::GRY, "Подробный разбор — «VPN/прокси» и «Блокировки».");
        } else {
            logLine(C::GRY, "Для страны/ASN адресов — «Резолв ASN»; подробный разбор — «VPN/прокси» и «Блокировки».");
        }
    });
}

void startResolve() {
    auto ds = currentDs();
    if (!ds) return;
    startJob("Резолв адресов (страна / ASN / хостинг)", [ds] { resolveDataset(ds); });
}

void startVpnAnalysis() {
    auto ds = currentDs();
    if (!ds) return;
    startJob("Анализ на VPN / прокси: " + ds->name, [ds] {
        selectLocal(*ds);
        openReport(ds->paths.front(), "report");
        runVpnAnalysis(ds->packets, ds->paths);
    });
}

void startConnAnalysis(const std::string& target) {
    auto ds = currentDs();
    if (!ds) return;
    std::string t = trim(target);
    startJob("Блокировки и проблемы соединения: " + ds->name, [ds, t] {
        selectLocal(*ds);
        openReport(ds->paths.front(), "report");
        runConnAnalysisFor(ds->packets, ds->paths, t);
    });
}

// Режим 13 прямо в окне: вывод — в журнал. Дамп не нужен.
void startIpOwner(const std::string& target) {
    std::string t = trim(target);
    if (t.empty()) return;
    startJob("Кому принадлежит: " + t, [t] { runIpOwnerFor(t); });
}

void startCompare(std::vector<std::string> pathsA, std::vector<std::string> pathsB) {
    if (pathsB.empty()) return;
    auto cur = currentDs();
    if (pathsA.empty() && !cur) return;
    startJob("Сравнение дампов (было / стало)", [pathsA, pathsB, cur] {
        std::shared_ptr<Dataset> a = cur;
        if (!pathsA.empty()) {
            std::cout << "Дамп A:\n";
            a = loadDataset(pathsA);
            if (!a) { jobFail("Дамп A не загружен."); return; }
        }
        std::cout << "Дамп B:\n";
        auto b = loadDataset(pathsB);
        if (!b) { jobFail("Дамп B не загружен."); return; }
        DumpRef ra{ &a->paths, &a->packets, a->localIp, a->localIp6 };
        DumpRef rb{ &b->paths, &b->packets, b->localIp, b->localIp6 };
        compareDumpSets(ra, rb);
    });
}

// Перечитывание analyzer.ini. Делается в потоке окна и только без фоновой
// задачи: cfg() читают и анализ, и отрисовка вкладки настроек.
void startReloadConfig() {
    if (g_busy) return;
    loadConfig();
    const AppConfig& c = cfg();
    logLine(C::GRN, "Настройки перечитаны: " +
            (c.loadedFrom.empty() ? std::string("analyzer.ini не найден, значения по умолчанию")
                                  : c.loadedFrom));
    for (const auto& w : c.warnings) logLine(C::YEL, "  " + w);
}

// Кнопка «Определить» (своя сеть) — фоновой задачей, чтобы номер не сменился
// посреди анализа. Обзор открытого дампа сразу пересчитываем с новым номером.
void startOwnIspDetect() {
    startJob("Определение своей сети (AS)", [] {
        std::string msg;
        if (!ownIspDetect(msg)) { jobFail("Своя сеть не определена: " + msg); return; }
        logLine(C::GRN, "Своя сеть: " + msg);
        auto ds = currentDs();
        std::shared_ptr<const IpCache> cache;
        { std::lock_guard<std::mutex> lk(g_mx); cache = g_ipCache; }
        if (!ds || !cache) return;
        selectLocal(*ds);   // после сравнения g_localIp мог остаться от другого набора
        auto sum = std::make_shared<const DumpSummary>(
            summarizeDump(ds->packets, ds->name, cache.get()));
        {
            std::lock_guard<std::mutex> lk(g_mx);
            if (g_ds == ds) { g_summary = sum; ++g_gen; }
        }
        logLine(C::GRY, "Обзор пересчитан. «VPN/прокси» и «Блокировки» запустите заново — "
                        "прежние отчёты сделаны со старой своей сетью.");
    });
}

// ------------------------------------------------------------------
// Интерактивные инструменты — отдельный процесс «exe --tool N» в своей консоли
// ------------------------------------------------------------------
const char* toolTitle(int mode) {
    switch (mode) {
    case 3:  return "Трассировка маршрута";
    case 4:  return "Проверка гео по RTT";
    case 5:  return "Захват трафика в .pcap";
    case 6:  return "Проверка порта извне (Globalping)";
    case 7:  return "Скан TCP-портов";
    case 8:  return "UDP handshake-пробы";
    case 9:  return "TSPU DPI Locator";
    case 10: return "Сравнение дампов (в консоли)";
    case 11: return "Честность DNS";
    case 12: return "Тест «16 КБ» по хостингам";
    case 13: return "Кому принадлежит IP";
    default: return "?";
    }
}

#ifndef _WIN32
bool launchConsoleTool(int mode) {
    const std::string dir = exeDirUtf8();
    if (dir.empty()) return false;
    static int s_seq = 0;
    const char* tmp = getenv("TMPDIR");
    std::string marker = std::string(tmp && *tmp ? tmp : "/tmp/");
    if (marker.back() != '/') marker += '/';
    marker += "trafficanalyzer-tool-" + std::to_string((long)getpid()) + "-" +
              std::to_string(++s_seq);
    if (FILE* f = fopen(marker.c_str(), "w")) fclose(f);
    else marker.clear();

    // имя исполняемого файла — как его запустили (argv[0] может быть относительным)
    char exe[PATH_MAX * 2];
    uint32_t sz = sizeof(exe);
    std::string exePath = _NSGetExecutablePath(exe, &sz) == 0 ? exe : dir + "TrafficAnalyzer";

    std::string cmd;
    // Ctrl+C (INT) не ловим: он только прерывает трассировку, инструмент живёт дальше
    if (!marker.empty())
        cmd = "trap " + shQuote("rm -f " + shQuote(marker)) + " EXIT; trap " +
              shQuote("rm -f " + shQuote(marker) + "; exit 1") + " HUP TERM; ";
    cmd += shQuote(exePath) + " --tool " + std::to_string(mode == 10 ? 0 : mode);
    if (g_logEnabled) cmd += " --log";
    cmd += "; exit";

    int rc = -1;
    macOsascript("tell application \"Terminal\"\n"
                 "activate\n"
                 "do script " + asQuote(cmd) + "\n"
                 "end tell", &rc);
    if (rc != 0) {
        if (!marker.empty()) remove(marker.c_str());
        logLine(C::RED, std::string("Не удалось открыть Терминал для инструмента: ") +
                toolTitle(mode) + " (разрешите управление Терминалом в «Конфиденциальность и "
                "безопасность → Автоматизация»)");
        return false;
    }
    if (!marker.empty()) {
        std::lock_guard<std::mutex> lk(g_toolMx);
        g_tools.push_back({ marker, mode, toolTitle(mode) });
    }
    return true;
}

std::vector<ToolProc> runningTools() {
    std::lock_guard<std::mutex> lk(g_toolMx);
    std::vector<ToolProc> out;
    for (size_t i = 0; i < g_tools.size();) {
        if (access(g_tools[i].marker.c_str(), F_OK) != 0) {
            g_tools.erase(g_tools.begin() + (ptrdiff_t)i);
            continue;
        }
        out.push_back({ g_tools[i].mode, g_tools[i].title });
        i++;
    }
    return out;
}
#else
bool launchConsoleTool(int mode) {
    wchar_t exe[4096];
    DWORD n = GetModuleFileNameW(nullptr, exe, (DWORD)(sizeof(exe) / sizeof(exe[0])));
    if (n == 0 || n >= sizeof(exe) / sizeof(exe[0])) return false;
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --tool " +
                       std::to_wstring(mode == 10 ? 0 : mode);
    if (g_logEnabled) cmd += L" --log";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE,
                        nullptr, nullptr, &si, &pi)) {
        logLine(C::RED, std::string("Не удалось запустить инструмент: ") + toolTitle(mode) +
                " (ошибка " + std::to_string(GetLastError()) + ")");
        return false;
    }
    CloseHandle(pi.hThread);
    std::lock_guard<std::mutex> lk(g_toolMx);
    g_tools.push_back({ pi.hProcess, mode, toolTitle(mode) });
    return true;
}

std::vector<ToolProc> runningTools() {
    std::lock_guard<std::mutex> lk(g_toolMx);
    std::vector<ToolProc> out;
    for (size_t i = 0; i < g_tools.size();) {
        if (WaitForSingleObject(g_tools[i].h, 0) == WAIT_OBJECT_0) {
            CloseHandle(g_tools[i].h);
            g_tools.erase(g_tools.begin() + (ptrdiff_t)i);
            continue;
        }
        out.push_back({ g_tools[i].mode, g_tools[i].title });
        i++;
    }
    return out;
}
#endif
