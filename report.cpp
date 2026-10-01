// report.cpp — отчёты: режим 2 (анализ соединений, скорость потоков, печать
// причин блокировок) и режим 10 (сводка и сравнение двух дампов).
#include "analyzer_internal.h"

// ------------------------------------------------------------------
// СКОРОСТЬ ПОТОКОВ ВО ВРЕМЕНИ (аналог Statistics → I/O Graphs в Wireshark).
// Для крупнейших потоков объём раскладывается по интервалам и рисуется
// строкой-спарклайном. Ровная «полка» — много интервалов на одном уровне
// без провалов — почерк шейпера/полисера: скорость режут искусственно, а не
// теряют пакеты (потери дают «пилу» с провалами). targetIp — необязательный фильтр.
// ------------------------------------------------------------------
void analyzeThroughput(const std::vector<Packet>& packets,
                       const std::string& localIp,
                       const std::string& targetIp /*= ""*/) {
    auto isLocal = [&](const std::string& ip) {
        return isLocalIp(ip) || (!localIp.empty() && ip == localIp);
    };
    std::vector<long long> absT = absTimes(packets);
    struct TFlow {
        std::string rip, proto; int rport = 0, lport = 0; bool vpn = false;
        long long bytesIn = 0, bytesOut = 0, tFirst = -1, tLast = -1;
        std::string ms;   // фоновая загрузка Windows/Microsoft: что это (см. msBackgroundDownload)
    };
    std::map<std::string, TFlow> flows;
    auto keyOf = [](const std::string& proto, const std::string& rip, int rport, int lport) {
        return proto + "|" + rip + "|" + std::to_string(rport) + "|" + std::to_string(lport);
    };
    for (size_t i = 0; i < packets.size(); i++) {
        const Packet& p = packets[i];
        if (p.proto != "TCP" && p.proto != "UDP") continue;
        if (!targetIp.empty() && p.srcIp != targetIp && p.dstIp != targetIp) continue;
        if (absT[i] < 0 || p.length <= 0) continue;
        bool sLoc = isLocal(p.srcIp), dLoc = isLocal(p.dstIp);
        if (sLoc == dLoc) continue;
        std::string rip = sLoc ? p.dstIp : p.srcIp;
        int rport = sLoc ? p.dstPort : p.srcPort, lport = sLoc ? p.srcPort : p.dstPort;
        TFlow& f = flows[keyOf(p.proto, rip, rport, lport)];
        f.rip = rip; f.proto = p.proto; f.rport = rport; f.lport = lport;
        // VoWiFi (UDP 500/4500) — звонок: его ровный поток и есть битрейт приложения;
        // 500/4500 — VPN, только если это IPsec-VPN точно (ipsecClass)
        if (p.wgType != 0) f.vpn = true;
        else if (vpnPortName(rport, p.proto)) {
            const IpsecClass ic = ipsecClass(p, rport, nullptr);
            if (ic == IPSEC_NONE || ic == IPSEC_VPN) f.vpn = true;
        }
        if (sLoc) f.bytesOut += p.length; else f.bytesIn += p.length;
        if (f.tFirst < 0) f.tFirst = absT[i];
        f.tLast = absT[i];
        if (sLoc && f.ms.empty()) {
            const char* w = nullptr;
            if (!p.httpHost.empty() || !p.httpUa.empty() || !p.httpPath.empty())
                w = msBackgroundDownload(p.httpHost, p.httpUa, p.httpPath);
            if (!w && !p.sni.empty()) w = msBackgroundDownload(p.sni);
            if (w) f.ms = w;
        }
    }
    // нет ни SNI, ни HTTP (дамп начат посреди загрузки) — по имени из DNS/CNAME
    {
        std::map<std::string, std::string> qByKey;
        std::map<std::string, std::string> msByIp;
        for (const Packet& p : packets) {
            if (p.dnsId.empty()) continue;
            if (!p.dnsIsResponse) {
                if (!p.dnsQuery.empty())
                    qByKey[p.srcIp + "|" + std::to_string(p.srcPort) + "|" + p.dnsId] = p.dnsQuery;
                continue;
            }
            std::string q = p.dnsQuery;
            if (q.empty()) {
                auto it = qByKey.find(p.dstIp + "|" + std::to_string(p.dstPort) + "|" + p.dnsId);
                if (it != qByKey.end()) q = it->second;
            }
            const char* w = q.empty() ? nullptr : msBackgroundDownload(q);
            for (size_t k = 0; !w && k < p.dnsCnames.size(); k++) w = msBackgroundDownload(p.dnsCnames[k]);
            if (!w) continue;
            for (const auto& ip : p.dnsAnswers) msByIp.emplace(ip, w);
            if (!p.dnsAnswerIp.empty()) msByIp.emplace(p.dnsAnswerIp, w);
        }
        for (auto& kv : flows) {
            if (!kv.second.ms.empty()) continue;
            auto it = msByIp.find(kv.second.rip);
            if (it != msByIp.end()) kv.second.ms = it->second;
        }
    }
    // кандидаты: крупные и достаточно длинные потоки, по объёму
    std::vector<std::pair<std::string, TFlow>> cand;
    for (auto& kv : flows) {
        const TFlow& f = kv.second;
        if (f.tLast - f.tFirst < 3LL * 1000000) continue;
        if (std::max(f.bytesIn, f.bytesOut) < 256 * 1024) continue;
        cand.push_back(kv);
    }
    if (cand.empty()) return;
    std::sort(cand.begin(), cand.end(), [](auto& a, auto& b) {
        return std::max(a.second.bytesIn, a.second.bytesOut) > std::max(b.second.bytesIn, b.second.bytesOut);
    });
    if (cand.size() > 5) cand.resize(5);

    auto fmtRate = [](double kbps) {
        char o[32];
        if (kbps >= 1000) snprintf(o, sizeof(o), "%.1f Мбит/с", kbps / 1000);
        else              snprintf(o, sizeof(o), "%.0f кбит/с", kbps);
        return std::string(o);
    };
    auto fmtBytes = [](long long b) {
        char o[32];
        if (b >= 1048576) snprintf(o, sizeof(o), "%.1f МБ", b / 1048576.0);
        else              snprintf(o, sizeof(o), "%lld КБ", (b + 512) / 1024);
        return std::string(o);
    };
    // только символы, которые есть в Consolas/Lucida Console: «▁▂▃▅▆▇» там
    // нет, и консоль рисовала вместо них «?» в рамке
    static const char* bars[] = { "░", "▒", "▓", "█" };
    const int nBars = (int)(sizeof(bars) / sizeof(bars[0]));

    printf("\n%s=== СКОРОСТЬ ПОТОКОВ ВО ВРЕМЕНИ (аналог IO Graph) ===%s\n", C::BOLD, C::RST);
    int idx = 0;
    for (auto& kv : cand) {
        const TFlow& f = kv.second;
        bool down = (f.bytesIn >= f.bytesOut);     // смотрим преобладающее направление
        long long dur = f.tLast - f.tFirst;
        // интервал: 0,5 с для коротких потоков, иначе так, чтобы вышло ~60 столбиков
        long long bw = (dur < 15LL * 1000000) ? 500000
                     : ((dur / 60 + 999999) / 1000000) * 1000000;
        size_t nb = (size_t)(dur / bw) + 1;
        std::vector<long long> bucket(nb, 0);
        long long dataPkts = 0, retr = 0;
        std::unordered_set<long long> seen;        // начала сегментов — грубый счёт ретрансмиссий
        for (size_t i = 0; i < packets.size(); i++) {
            const Packet& p = packets[i];
            if (p.proto != f.proto || p.length <= 0 || absT[i] < 0) continue;
            bool sLoc = isLocal(p.srcIp);
            if (sLoc == isLocal(p.dstIp) || sLoc == down) continue;   // только нужное направление
            const std::string& rip = sLoc ? p.dstIp : p.srcIp;
            if (rip != f.rip) continue;
            if ((sLoc ? p.dstPort : p.srcPort) != f.rport || (sLoc ? p.srcPort : p.dstPort) != f.lport) continue;
            long long t = absT[i] - f.tFirst;
            if (t < 0) continue;
            size_t b = (size_t)(t / bw);
            if (b >= nb) b = nb - 1;
            bucket[b] += p.length;
            if (f.proto == "TCP" && p.seqStart >= 0) {
                dataPkts++;
                if (!seen.insert(p.seqStart).second) retr++;
            }
        }
        double secs = bw / 1e6;
        std::vector<double> rate(nb);
        double peak = 0;
        for (size_t b = 0; b < nb; b++) { rate[b] = bucket[b] * 8.0 / secs / 1000.0; peak = std::max(peak, rate[b]); }

        char hdr[384];
        snprintf(hdr, sizeof(hdr), "  %d) %s:%d ↔ локальный порт %d, %s — %s %s за %.0f с (интервал %.1f с)",
                 ++idx, f.rip.c_str(), f.rport, f.lport, f.proto.c_str(),
                 down ? "принято" : "отдано", fmtBytes(down ? f.bytesIn : f.bytesOut).c_str(),
                 dur / 1e6, secs);
        printf("%s%s%s\n", C::BWHT, hdr, C::RST);
        if (!f.ms.empty())
            printf("     %sфоновая загрузка Windows/Microsoft: %s%s\n", C::GRY, f.ms.c_str(), C::RST);
        // спарклайн, по 60 столбиков в строке; пустой интервал — «·»
        std::string line;
        for (size_t b = 0; b < nb; b++) {
            if (b > 0 && b % 60 == 0) { printf("     %s%s%s\n", C::CYN, line.c_str(), C::RST); line.clear(); }
            if (bucket[b] == 0 || peak <= 0) line += "·";
            else line += bars[std::min(nBars - 1, (int)(rate[b] / peak * (nBars - 0.001)))];
        }
        if (!line.empty()) printf("     %s%s%s\n", C::CYN, line.c_str(), C::RST);

        // крайние интервалы неполные — в статистику полки их не берём
        std::vector<double> act;
        for (size_t b = 1; b + 1 < nb; b++) act.push_back(rate[b]);
        double med = 0;
        if (!act.empty()) {
            std::vector<double> s = act;
            std::sort(s.begin(), s.end());
            med = s[s.size() / 2];
        }
        double retrPct = dataPkts ? 100.0 * retr / dataPkts : 0.0;
        printf("     %sмедиана %s, пик %s", C::GRY, fmtRate(med).c_str(), fmtRate(peak).c_str());
        if (f.proto == "TCP" && dataPkts > 0) printf(", повторов сегментов ~%.1f%%", retrPct);
        printf("%s\n", C::RST);

        if (act.size() >= 5 && med > 0) {
            // не "near": в windows.h есть пустой макрос near (как и far)
            size_t nearCnt = 0, idleCnt = 0;
            for (double r : act) {
                if (std::fabs(r - med) <= med * 0.12) nearCnt++;
                if (r < med * 0.05) idleCnt++;
            }
            bool plateau = (nearCnt * 10 >= act.size() * 7) && (idleCnt * 10 <= act.size());
            // «сначала быстро, потом полка»: полисер пропускает всплеск (запас
            // жетонов) и лишь затем режет до лимита. Обычный TCP так не делает —
            // он, наоборот, разгоняется постепенно.
            double early = 0;
            for (size_t b = 0; b < std::max<size_t>(2, nb / 5) && b < nb; b++) early = std::max(early, rate[b]);
            bool burstThenCap = plateau && early > med * 2.5;
            if (plateau) {
                std::string m;
                const char* col = C::WHT;
                if (f.proto == "UDP" && !f.vpn) {
                    m = "ровный поток ~" + fmtRate(med) + " — для UDP это обычно битрейт "
                        "самого приложения (звонок, игра, стрим), а не ограничение.";
                } else if (!f.ms.empty()) {
                    // DO/BITS в фоне сами держат низкую ровную скорость, чтобы не
                    // мешать остальному трафику, — это не шейпер оператора
                    m = "ровная полка ~" + fmtRate(med) + " — это фоновая загрузка "
                        "Windows/Microsoft (" + f.ms + "): скорость ограничивает сама "
                        "Windows, чтобы не мешать остальному трафику. На тариф и канал "
                        "по ней не судить.";
                } else if (med < 2000) {
                    col = C::YEL;
                    m = "ровная полка ~" + fmtRate(med) + " — похоже на искусственное "
                        "ограничение скорости (шейпинг/замедление), а не на потери";
                    m += (retrPct >= 2.0)
                        ? ": повторов много — полисер отбрасывает всё сверх лимита."
                        : ": повторов почти нет — шейпер сглаживает очередью.";
                    if (burstThenCap)
                        m += " Сначала скорость была выше (" + fmtRate(early) + "), затем "
                             "упёрлась в полку — типичный почерк замедления после всплеска.";
                } else {
                    m = "скорость ровная ~" + fmtRate(med) + " — упор в тариф/канал или "
                        "шейпер; сама по себе не проблема.";
                    if (burstThenCap)
                        m += " Начало было быстрее (" + fmtRate(early) + ") — возможно "
                             "ограничение после всплеска.";
                }
                printf("     %s→ %s%s\n", col, m.c_str(), C::RST);
            } else if (f.proto == "TCP" && retrPct >= 3.0) {
                printf("     %s→ скорость «пилой» при ~%.1f%% повторов — это потери на "
                       "линии, а не ограничение скорости.%s\n", C::YEL, retrPct, C::RST);
            }
        }
        printf("     %sWireshark: %s  (Statistics → I/O Graphs)%s\n", C::GRY,
               wsFilter(f.rip, f.rport, f.proto == "TCP" ? "tcp" : "udp").c_str(), C::RST);
    }
    printf("  %sГрафик: один символ — один интервал; «·» — данных не было,\n"
           "  ░ ▒ ▓ █ — скорость по возрастанию (█ — пик потока).\n"
           "  Полка — много интервалов на одном уровне без провалов. Для TCP она\n"
           "  бывает и при упоре в тариф; подозрительна низкая полка (< 2 Мбит/с)\n"
           "  на крупной загрузке, особенно если в начале скорость была выше.\n"
           "  Исключение — фоновые загрузки Windows (обновления, Delivery\n"
           "  Optimization, BITS, Office, Store): их скорость Windows режет сама.%s\n",
           C::GRY, C::RST);
}

void printBlockReasons(const std::vector<BlockReason>& rs) {
    if (rs.empty()) return;
    printf("\n%s=== ПРИЧИНЫ БЛОКИРОВОК ===%s\n", C::BOLD, C::RST);
    size_t i = 0;
    while (i < rs.size()) {
        size_t j = i;
        while (j < rs.size() && rs[j].code == rs[i].code) j++;
        const bool hard = rs[i].code != "TLS_RST" && rs[i].code != "UDP_DROP";
        printf("  %s[%s] %s%s — ресурсов: %d\n", hard ? C::RED : C::YEL, rs[i].code.c_str(),
               blockReasonTitle(rs[i].code), C::RST, (int)(j - i));
        for (size_t k = i; k < j; k++) {
            if (k - i >= 12) { printf("      ... ещё %d\n", (int)(j - k)); break; }
            const BlockReason& r = rs[k];
            std::string ipPart = r.target != r.ip ? "  " + r.ip : std::string();
            printf("    %s%s%s%s  (соед.: %d)\n      %s%s%s\n",
                   C::BWHT, r.target.c_str(), C::RST, ipPart.c_str(),
                   r.conns, C::GRY, r.detail.c_str(), C::RST);
        }
        printf("    %sЧто сказать/сделать:%s %s\n", C::CYN, C::RST, blockReasonAdvice(rs[i].code));
        i = j;
    }
}

// Список доменов, заблокированных по SNI (tspu-docs гл.17.5.3: HTTPS режется
// по домену из ClientHello), с фильтром Wireshark для каждого.
static void printBlockedSniList(const std::map<std::string, std::string>& snis) {
    if (snis.empty()) return;
    printf("%s  Заблокировано по SNI (домен из TLS ClientHello):%s\n", C::BYEL, C::RST);
    for (const auto& kv : snis)
        printf("    %s%s%s — %s  %s[tls.handshake.extensions_server_name==\"%s\"]%s\n",
               C::BWHT, kv.first.c_str(), C::RST, kv.second.c_str(),
               C::GRY, kv.first.c_str(), C::RST);
}

static void analyzeConnIssues(const std::vector<Packet>& packets,
                              const std::string& localIp,
                              const std::string& targetIp = "",
                              const std::unordered_map<std::string, IpInfo>* ipCache = nullptr,
                              const TcpConnTable* ttIn = nullptr) {
    auto isLocal = [&](const std::string& ip) {
        return isLocalIp(ip) || (!localIp.empty() && ip == localIp);
    };
    struct Conn {
        long long syn = 0, synack = 0, rst = 0, rstEarly = 0, synRetrans = 0;
        long long rstRem = 0;                     // RST от удалённой стороны
        long long retrans = 0, dupAck = 0, zeroWin = 0, total = 0;
        std::map<long long, long long> seqSeen;  // dirKey -> время последнего появления (мкс)
        std::map<long long, long long> seqLen;    // dirKey -> длина сегмента (для сверки «тот же сегмент»)
        std::vector<long long> retrGaps;          // интервалы повторов seq (для адаптивного порога)
        std::string remoteIp;                     // адрес удалённой стороны (для группировки byIp)
        int remotePort = 0;                       // порт удалённой стороны (для byPort-учёта)
        long long firstSynT = -1;                 // время первого чистого SYN (мкс) — для отсечки хвоста дампа
        long long lastSynT = -1;                  // время ПОСЛЕДНЕГО чистого SYN (мкс) — база для SYN-RTT
        long long synRtt = -1;                    // RTT рукопожатия SYN->SYN-ACK (мкс)
        long long maxSeqIn = -1;                  // наибольший seq входящих данных (для реордеринга)
        // повторы ACK — по направлениям: дубли от сервера говорят о потере НАШИХ
        // сегментов, наши — о потере входящих; общий счётчик сбивался при чередовании
        long long lastAck[2] = { -1, -1 }; int ackRepeat[2] = { 0, 0 };   // [0] от абонента, [1] от сервера
        bool sawData = false;
        // RTT: ждём ACK на отправленный seq
        // ключ = ожидаемый ack (seq + length), значение = время отправки
        std::map<long long, long long> awaitingAck;
        long long rttMin = -1, rttMax = -1, rttSum = 0, rttCnt = 0;
        std::vector<long long> rttSamples;   // выборка RTT для медианы
        long long dataPkts = 0;              // пакетов с данными в ОБОИХ направлениях — знаменатель % повторов
                                             // (ретрансмиссии тоже считаются в обе стороны)
        // MTU/MSS-эвристика — максимальная длина payload в потоке
        long long maxPayload = 0;
        // TCP-опции из SYN / SYN-ACK (только бинарный дамп)
        bool synLocSeen = false, synRemSeen = false;
        int  mssLoc = -1, mssRem = -1;       // MSS, объявленный каждой стороной
        int  wsLoc = -1, wsRem = -1;         // window scale каждой стороны (-1 = не прислал)
        long long sackFromRem = 0;           // пакетов удалённой стороны с SACK-блоками
        long long sackFromLoc = 0;           // пакетов абонента с SACK-блоками
        long long maxWinLoc = -1;            // макс. реальное окно приёма абонента, байт
        long long bytesIn = 0, bytesOut = 0; // payload по направлениям
        // RTT по TCP-таймстемпам (RFC 7323): TSval абонента -> время ПЕРВОГО пакета
        // с этим значением; сервер возвращает его в TSecr. Замеры идут и на загрузке,
        // где абонент шлёт одни ACK и RTT по данным (awaitingAck) не набирается.
        std::deque<std::pair<long long, long long>> tsOut;
        std::vector<long long> tsRtt;
    };
    // сравнение 32-битных отметок TS с учётом перехода через 0 (как у seq)
    auto tsLess = [](long long a, long long b) {
        return (int32_t)((uint32_t)a - (uint32_t)b) < 0;
    };
    std::map<std::string, Conn> conns;
    long long synNoReply = 0, totalRst = 0, totalRetrans = 0,
              totalDupAck = 0, totalZeroWin = 0, matched = 0, totalSynRetr = 0,
              synRetrLocal = 0;   // повторы SYN к локальным адресам (в totalSynRetr не входят)
    long long lastTsUs = -1;      // время последнего пакета дампа (мкс) — граница захвата
    long long synTailSkipped = 0; // соединений, отброшенных как «SYN на самом хвосте»
    long long totalReorder = 0;   // входящих сегментов, пришедших не по порядку
    // RTT рукопожатия — отдельная выборка от RTT по данным (см. ниже, у SYN-ACK)
    long long synRttCnt = 0, synRttSum = 0, synRttMin = -1, synRttMax = -1;
    // потери по протоколу/порту: порт -> {ретрансмиссии, RST}
    struct PortLoss { long long retr = 0, rst = 0, syn = 0, synack = 0; std::string proto; };
    std::map<int, PortLoss> byPort;

    // время с поправкой на полночь: дамп, склеенный из файлов, может её пересекать
    const std::vector<long long> absT = absTimes(packets);
    for (size_t pi = 0; pi < packets.size(); pi++) {
        const Packet& p = packets[pi];
        if (p.proto != "TCP") continue;
        // если задан целевой IP — анализируем только пакеты к/от него
        if (!targetIp.empty() && p.srcIp != targetIp && p.dstIp != targetIp) continue;
        matched++;
        bool sLoc = isLocal(p.srcIp), dLoc = isLocal(p.dstIp);
        // Ключ соединения — полный 4-кортеж, а НЕ "удалённый ip:порт". Локальный
        // эфемерный порт обязателен: без него все параллельные соединения к одному
        // серверу сливаются в одну запись, и тогда 6 обычных соединений браузера к
        // одному HTTPS-узлу дают c.syn=6 => 5 фальшивых «повторов SYN» (а это порог
        // hardBlock), тогда как RST по 2-му и далее соединениям перестают попадать
        // в rstEarly из-за счётчика c.total. Повторное использование эфемерного порта
        // к тому же серверу в пределах одного дампа маловероятно — ОС перебирает
        // диапазон, — так что склейка разных соединений в один ключ практически
        // исключена.
        std::string remoteIp;
        int remotePort, localPort;
        if (sLoc != dLoc) {
            remoteIp   = sLoc ? p.dstIp   : p.srcIp;
            remotePort = sLoc ? p.dstPort : p.srcPort;
            localPort  = sLoc ? p.srcPort : p.dstPort;
        } else {
            // обе стороны локальные (или обе внешние) — направление не определить,
            // считаем инициатором источник
            remoteIp   = p.dstIp;
            remotePort = p.dstPort;
            localPort  = p.srcPort;
        }
        std::string remote = remoteIp + ":" + std::to_string(remotePort) +
                             ":" + std::to_string(localPort);
        Conn& c = conns[remote];
        c.total++;
        c.remoteIp = remoteIp;
        c.remotePort = remotePort;
        const long long tPkt = absT[pi];
        if (tPkt >= 0 && tPkt > lastTsUs) lastTsUs = tPkt;
        PortLoss& pl = byPort[remotePort];
        pl.proto = p.proto;

        bool S = flagHas(p.flags, 'S');
        bool R = flagHas(p.flags, 'R');
        bool dot = flagHas(p.flags, '.'); // ACK-бит
        // Рукопожатие считаем только для ИСХОДЯЩИХ соединений: SYN от абонента,
        // SYN-ACK и ранний RST — с удалённой стороны. Входящие SYN (сканы
        // портов, пиры торрента) без ответа — это наш файрвол, а не «сервер
        // лежит». Если направление не определить — считаем всё, как раньше.
        const bool dirKnown = (sLoc != dLoc);
        const bool fromLoc = !dirKnown || sLoc;
        const bool fromRem = !dirKnown || !sLoc;

        if (S && !dot && fromLoc) {
            c.syn++; pl.syn++;
            if (c.firstSynT < 0 && tPkt >= 0) c.firstSynT = tPkt;
            // База для SYN-RTT — именно ПОСЛЕДНИЙ SYN, а не первый. Если первый
            // SYN потерялся, отсчёт от него дал бы не RTT, а весь RTO (~1 с).
            if (tPkt >= 0) c.lastSynT = tPkt;
            // теперь ключ = 4-кортеж, поэтому c.syn > 1 — действительно повтор SYN
            // в рамках ОДНОГО соединения, а не второе соединение к тому же серверу
            // в итог (и в вердикт) — только внешние адреса: роутер/принтер в LAN,
            // не принимающий TCP на порту, — не проблема канала (как synNoReplyExt)
            if (c.syn > 1) {
                c.synRetrans++;
                if (isPrivateIp(remoteIp)) synRetrLocal++; else totalSynRetr++;
            }
        }
        if (S && dot && fromRem) {
            c.synack++; pl.synack++;
            // RTT рукопожатия. Ценно тем, что доступно для любого соединения,
            // дошедшего до SYN-ACK, — в том числе для тех, которые потом сразу
            // умерли и данных не передали: у них RTT по данным (awaitingAck ниже)
            // не набирается вообще, а диагностируем мы как раз их. Плюс замер
            // чистый: SYN-ACK порождает стек ядра из listen-backlog, время
            // обработки в приложении в него не входит.
            // Только SYN-ACK С УДАЛЁННОЙ стороны: если захват сделан на сервере,
            // ответ отдаём мы сами и разница была бы нашим временем отклика.
            if (!sLoc && c.synRtt < 0 && c.lastSynT >= 0 && tPkt >= 0) {
                long long d = tPkt - c.lastSynT;
                if (d >= 0 && d < 60LL*1000000) c.synRtt = d;   // отсекаем мусор/полночь
            }
        }
        if (R) {
            c.rst++; totalRst++; pl.rst++;
            // «ранний» — только если начало соединения (наш SYN) есть в дампе: у
            // соединения, начатого до захвата, первые увиденные пакеты — середина
            // сессии, и RST среди них ничего не говорит о старте
            if (fromRem) { c.rstRem++; if (c.total <= 3 && c.syn > 0) c.rstEarly++; }
        }

        // TCP-опции. MSS и window scale передаются только в SYN/SYN-ACK; масштаб
        // окна действует, лишь если его прислали ОБЕ стороны (RFC 7323), и
        // применяется к окну всех последующих (не-SYN) пакетов.
        if (S) {
            if (sLoc) { c.synLocSeen = true; if (p.mss > 0) c.mssLoc = p.mss; c.wsLoc = p.wscale; }
            else      { c.synRemSeen = true; if (p.mss > 0) c.mssRem = p.mss; c.wsRem = p.wscale; }
        } else if (sLoc && p.win >= 0 && c.synLocSeen && c.synRemSeen) {
            // масштаб больше 14 RFC 7323 велит считать за 14 (и сдвиг на ≥ 64 — UB)
            long long eff = (c.wsLoc >= 0 && c.wsRem >= 0)
                ? ((long long)p.win << std::min(c.wsLoc, 14)) : (long long)p.win;
            if (eff > c.maxWinLoc) c.maxWinLoc = eff;
        }
        if (p.sackBlocks > 0) { if (sLoc) c.sackFromLoc++; else c.sackFromRem++; }

        // RTT по таймстемпам. Замер = от первого пакета абонента с TSval=Y до
        // первого пакета сервера с TSecr=Y. Повторы отправки неоднозначности не
        // дают (у копии свой TSval), поэтому правило Карна здесь не нужно.
        // Точность — такт часов TS абонента (1 мс у Linux/Windows).
        if (dirKnown && p.tsVal >= 0 && tPkt >= 0) {
            if (sLoc) {
                if (c.tsOut.empty() || tsLess(c.tsOut.back().first, p.tsVal))
                    c.tsOut.push_back({ p.tsVal, tPkt });
                if (c.tsOut.size() > 4096) c.tsOut.pop_front();   // сервер не отвечает эхом
            } else if (p.tsEcr > 0 && !R) {
                // сервер эхом отдаёт самую свежую ОТМЕТКУ абонента, что до него дошла:
                // всё, что левее, эха уже не получит
                while (!c.tsOut.empty() && tsLess(c.tsOut.front().first, p.tsEcr))
                    c.tsOut.pop_front();
                if (!c.tsOut.empty() && c.tsOut.front().first == p.tsEcr) {
                    long long d = tPkt - c.tsOut.front().second;
                    if (d >= 0 && d < 60LL*1000000) c.tsRtt.push_back(d);
                    c.tsOut.pop_front();
                }
            }
        }
        if (p.length > 0) { if (sLoc) c.bytesOut += p.length; else c.bytesIn += p.length; }

        if (p.length > 0) {
            c.sawData = true;
            c.dataPkts++;
            if (p.length > c.maxPayload) c.maxPayload = p.length;
            // Ретрансмиссия = ПОВТОРНАЯ отправка ТОГО ЖЕ сегмента: совпадает
            // направление, начальный seq И длина payload, и повтор пришёл спустя
            // время (адаптивный порог по RTT — решаем позже). Проверка длины и
            // направления отсекает ложные срабатывания на keep-alive и на разных
            // сегментах со случайно близким seq.
            long long rkey = (p.seqStart >= 0) ? p.seqStart : p.seq;
            // ключ с направлением: исходящие и входящие считаем раздельно
            long long dirKey = rkey * 2 + (sLoc ? 0 : 1);
            long long tnow = tPkt;
            bool isNewSeg = false;   // сегмент с таким seq в этом направлении ещё не встречался
            if (rkey >= 0) {
                auto it = c.seqSeen.find(dirKey);
                if (it == c.seqSeen.end()) {
                    isNewSeg = true;
                    c.seqSeen[dirKey] = tnow;
                    c.seqLen[dirKey] = p.length;            // запоминаем длину сегмента
                } else {
                    // только если ТА ЖЕ длина (тот же сегмент, не новый с тем же seq);
                    // 1 байт — keep-alive-проба (seq = snd.nxt-1), не повтор
                    if (p.length > 1 && tnow >= 0 && it->second >= 0 && c.seqLen[dirKey] == p.length)
                        c.retrGaps.push_back(tnow - it->second);
                    it->second = tnow;
                    c.seqLen[dirKey] = p.length;
                }
            }
            // --- переупорядочивание пути (только ВХОДЯЩИЙ поток) ---
            // Признак: сегмент НОВЫЙ (повтор уже учтён выше как ретрансмиссия),
            // но его seq лежит левее максимума, виденного в этом направлении.
            // Считаем только входящее: в исходящем «сегмент из прошлого» на своей
            // же машине — почти всегда артефакт разгрузки NIC (TSO/GSO), а не сеть.
            // p.length > 1 отсекает keep-alive-пробы: они шлются с seq = snd.nxt-1
            // и одним мусорным байтом, то есть всегда «левее» максимума, хотя
            // никакого переупорядочивания в них нет.
            if (!sLoc && isNewSeg && rkey >= 0 && p.length > 1) {
                if (c.maxSeqIn < 0)                    c.maxSeqIn = rkey;
                else if (seqLess(rkey, c.maxSeqIn))    totalReorder++;
                else                                   c.maxSeqIn = rkey;
            }
            // если это пакет ОТ ЛОКАЛЬНОЙ стороны — запоминаем ожидаемый ack.
            // p.seq уже КОНЕЦ сегмента (tcpdump «A:B» -> B, pcap: seqStart+length),
            // то есть ровно то число, которое удалённая сторона пришлёт в ack.
            if (sLoc && p.seq >= 0) {
                long long expectAck = p.seq;
                // правило Карна: по повторно отправленному сегменту RTT не меряем —
                // непонятно, на какую из копий пришёл ACK, и замер включал бы RTO
                if (rkey >= 0 && !isNewSeg) c.awaitingAck.erase(expectAck);
                else if (tPkt >= 0 && c.awaitingAck.find(expectAck) == c.awaitingAck.end())
                    c.awaitingAck[expectAck] = tPkt;
            }
        } else {
            if (p.ack >= 0) {
                const int d = sLoc ? 0 : 1;
                if (p.ack == c.lastAck[d]) { c.ackRepeat[d]++; if (c.ackRepeat[d] >= 2) { c.dupAck++; totalDupAck++; } }
                else { c.lastAck[d] = p.ack; c.ackRepeat[d] = 0; }
            }
        }
        // ACK с удалённой стороны: сопоставляем с ожидаемым ack для RTT
        if (!sLoc && p.ack >= 0) {
            auto it = c.awaitingAck.find(p.ack);
            if (it != c.awaitingAck.end()) {
                if (tPkt >= 0) {
                    long long rtt = tPkt - it->second;
                    if (rtt >= 0 && rtt < 60LL*1000000) { // отсекаем явный мусор
                        if (c.rttMin < 0 || rtt < c.rttMin) c.rttMin = rtt;
                        if (rtt > c.rttMax) c.rttMax = rtt;
                        c.rttSum += rtt; c.rttCnt++;
                        c.rttSamples.push_back(rtt);
                    }
                }
                c.awaitingAck.erase(it);
            }
            // кумулятивный ACK подтверждает и все сегменты левее: без этого
            // ожидания, на которые пришёл не точный, а общий ACK, копились бы
            // до конца дампа
            c.awaitingAck.erase(c.awaitingAck.begin(), c.awaitingAck.upper_bound(p.ack));
        }
        if (p.win == 0 && !R) { c.zeroWin++; totalZeroWin++; }
    }
    // «SYN без ответа» = соединение не поднялось. Но соединение, начатое в самом
    // конце захвата, физически не успело получить SYN-ACK: дамп оборвался раньше.
    // При склейке по серверу такой хвост растворялся в общей записи, где данные
    // были; после перехода на 4-кортеж он стал бы отдельным «неподнявшимся»
    // соединением — и synNoReply > 0 сразу даёт hardBlock. Поэтому SYN в последние
    // TAIL_US захвата не считаем (время — с поправкой на полночь, см. absTimes).
    // Порог общий с остальными детекторами (cfg().tailUs, tail_ms в конфиге).
    const long long TAIL_US = cfg().tailUs;
    // для итогового вывода — только внешние адреса: роутер/LAN часто не
    // принимают TCP на служебных портах, это не блокировка (как DOWN в таблице)
    long long synNoReplyExt = 0;
    for (auto& kv : conns) {
        const Conn& c = kv.second;
        if (!(c.syn > 0 && c.synack == 0 && !c.sawData)) continue;
        if (c.firstSynT >= 0 && lastTsUs >= 0) {
            long long tail = lastTsUs - c.firstSynT;
            if (tail >= 0 && tail < TAIL_US) { synTailSkipped++; continue; }
        }
        synNoReply++;
        if (!isPrivateIp(c.remoteIp)) synNoReplyExt++;
    }

    // --- адаптивный подсчёт ретрансмиссий по интервалам повторов ---
    // Порог = max(15 мс, 2×RTT соединения). Реальный ретрай ждёт ~RTO (>= 2×RTT),
    // offload-дубли приходят почти мгновенно. Привязка к RTT делает грань точной:
    // для близких серверов (малый пинг) порог ниже, для далёких — выше.
    for (auto& kv : conns) {
        Conn& c = kv.second;
        // заодно собираем выборку RTT рукопожатия — она независима от RTT по данным
        if (c.synRtt >= 0) {
            synRttCnt++; synRttSum += c.synRtt;
            if (synRttMin < 0 || c.synRtt < synRttMin) synRttMin = c.synRtt;
            if (c.synRtt > synRttMax) synRttMax = c.synRtt;
        }
        long long rttUs = (c.rttCnt > 0) ? (c.rttSum / c.rttCnt) : -1;  // средний RTT соединения, мкс
        long long thr = 15000;                       // нижняя граница 15 мс
        if (rttUs > 0) { long long t2 = rttUs * 2; if (t2 > thr) thr = t2; }
        if (thr > 1000000) thr = 1000000;            // потолок 1 с (RTO редко больше)
        for (long long gap : c.retrGaps) {
            if (gap > thr) { c.retrans++; totalRetrans++; byPort[c.remotePort].retr++; }
        }
    }

    printf("\n=================== ДИАГНОСТИКА СОЕДИНЕНИЙ ===================\n");
    if (!targetIp.empty()) {
        printf("Фильтр: только трафик к/от %s\n", targetIp.c_str());
        if (matched == 0) {
            printf("%sTCP-трафика по этому IP в дампе нет. Если ниже есть UDP-секция "
                   "— смотрите её (туннели/VPN идут по UDP).%s\n", C::YEL, C::RST);
            return;
        }
        printf("Найдено пакетов с этим IP: %lld\n", matched);
    }
    // conns теперь по 4-кортежу, поэтому отдельно показываем число удалённых точек:
    // «10 соединений к 2 серверам» и «10 соединений к 10 серверам» — разные картины
    std::set<std::string> endpoints;
    for (auto& kv : conns)
        endpoints.insert(kv.second.remoteIp + ":" + std::to_string(kv.second.remotePort));
    printf("Всего TCP-соединений: %lld (удалённых точек: %lld)\n",
           (long long)conns.size(), (long long)endpoints.size());
    printf("  SYN без ответа (нет SYN-ACK, нет данных): %s%lld%s\n",
           synNoReply ? C::YEL : C::GRN, synNoReply, C::RST);
    if (synTailSkipped > 0)
        printf("%s    (+%lld не учтено: SYN в последние %.0f с захвата — дамп оборвался "
               "раньше возможного ответа)%s\n", C::GRY, synTailSkipped, TAIL_US / 1e6, C::RST);
    printf("  Повторы SYN (рукопожатие не прошло сразу): %s%lld%s",
           totalSynRetr >= 3 ? C::YEL : C::GRN, totalSynRetr, C::RST);
    if (synRetrLocal > 0)
        printf("  %s(+%lld к локальным адресам — не учитываются)%s", C::GRY, synRetrLocal, C::RST);
    printf("\n");
    printf("  RST (сбросы соединения):                 %s%lld%s\n",
           totalRst > 5 ? C::YEL : C::GRN, totalRst, C::RST);
    printf("  Ретрансмиссии (повтор сегмента):          %s%lld%s\n",
           totalRetrans > 5 ? C::YEL : C::GRN, totalRetrans, C::RST);
    // «пропуск», а не «потеря»: дубликат ACK означает лишь дыру в последовательности,
    // а она бывает и от потери, и от переупорядочивания — что именно, показывает
    // следующая строка
    printf("  Дубликаты ACK (пропуск в потоке):         %s%lld%s\n",
           totalDupAck > 5 ? C::YEL : C::GRN, totalDupAck, C::RST);
    printf("  Не по порядку (реордеринг пути):          %s%lld%s\n",
           totalReorder > 5 ? C::YEL : C::GRN, totalReorder, C::RST);
    printf("  Zero-window (приёмник захлебнулся):       %s%lld%s\n",
           totalZeroWin > 0 ? C::YEL : C::GRN, totalZeroWin, C::RST);
    if (synRttCnt > 0)
        printf("  RTT рукопожатия (SYN→SYN-ACK):            %sмин %lld / сред %lld / макс %lld мс "
               "(проб: %lld)%s\n", C::GRY, synRttMin/1000, (synRttSum/synRttCnt)/1000,
               synRttMax/1000, synRttCnt, C::RST);

    // RTT по таймстемпам: общая выборка + рост RTT под нагрузкой ВНУТРИ соединения.
    // Рост считаем по каждому соединению отдельно: в общей выборке разница мин/медиана
    // даёт просто разные расстояния до разных серверов, а не очередь.
    {
        std::vector<long long> all;
        long long tsConns = 0;
        const Conn* worst = nullptr; long long worstMin = 0, worstMed = 0;
        long long bloatConns = 0;
        for (auto& kv : conns) {
            const Conn& c = kv.second;
            if (c.tsRtt.empty()) continue;
            tsConns++;
            all.insert(all.end(), c.tsRtt.begin(), c.tsRtt.end());
            if (c.tsRtt.size() < 20) continue;               // мало замеров для вывода о росте
            std::vector<long long> s = c.tsRtt;
            std::sort(s.begin(), s.end());
            const long long mn = s.front(), med = s[s.size() / 2];
            // медиана вдвое выше минимума и не меньше чем на 30 мс
            if (med >= 2 * mn && med - mn >= 30000) {
                bloatConns++;
                if (!worst || med - mn > worstMed - worstMin) { worst = &c; worstMin = mn; worstMed = med; }
            }
        }
        if (!all.empty()) {
            std::sort(all.begin(), all.end());
            const long long p90 = all[std::min(all.size() - 1, all.size() * 9 / 10)];
            printf("  RTT по таймстемпам (TSval→TSecr):         %sмин %lld / медиана %lld / 90%% %lld / "
                   "макс %lld мс (замеров: %zu, соединений: %lld)%s\n",
                   C::GRY, all.front()/1000, all[all.size()/2]/1000, p90/1000, all.back()/1000,
                   all.size(), tsConns, C::RST);
            if (worst)
                printf("  %sRTT растёт под нагрузкой в %lld соедин.: сильнее всего %s:%d — "
                       "мин %lld, медиана %lld мс.\n"
                       "    Пакеты стоят в очереди: канал загружен (bufferbloat на роутере/линии) "
                       "либо сервер отвечает с задержкой.%s\n",
                       C::YEL, bloatConns, worst->remoteIp.c_str(), worst->remotePort,
                       worstMin/1000, worstMed/1000, C::RST);
        }
    }

    // Группируем по удалённому IP (не IP:порт) чтобы не было 10 строк одного сервера
    struct IpRow {
        std::string ip;
        long long score = 0, syn = 0, synack = 0, rst = 0, retr = 0, dup = 0, zw = 0;
        long long synRetr = 0;
        // соединений, сброшенных СЕРВЕРОМ на старте или до прихода данных.
        // Просто число RST для вердикта не годится: многие серверы и приложения
        // штатно закрывают соединения через RST после обмена данными.
        long long rstBadConns = 0;
        long long rttMin = -1, rttMax = -1, rttSum = 0, rttCnt = 0;
        long long synRttMin = -1;               // RTT рукопожатия — запасной источник для колонки RTT
        long long maxPayload = 0;
        long long dataPkts = 0;                 // пакетов с данными (для % потерь)
        long long bytesOut = 0, bytesIn = 0;    // объём (из flows)
        std::vector<long long> rttSamples;      // для медианы
        std::set<int> ports;
        bool sawData = false;
    };
    std::map<std::string, IpRow> byIp;
    for (auto& kv : conns) {
        // ключ conns теперь "ip:rport:lport" — не разбираем его строкой, берём
        // адрес и порт из самой записи (заодно корректно для IPv6-адресов)
        const Conn& c = kv.second;
        const std::string& ip = c.remoteIp;
        int port = c.remotePort;
        IpRow& r = byIp[ip];
        r.ip = ip;
        r.syn += c.syn; r.synack += c.synack; r.rst += c.rst;
        r.retr += c.retrans; r.dup += c.dupAck; r.zw += c.zeroWin;
        r.synRetr += c.synRetrans; r.dataPkts += c.dataPkts;
        if (c.rstRem > 0 && (c.rstEarly > 0 || c.bytesIn == 0)) r.rstBadConns++;
        if (c.sawData) r.sawData = true;
        if (c.maxPayload > r.maxPayload) r.maxPayload = c.maxPayload;
        if (port > 0) r.ports.insert(port);
        if (c.rttCnt > 0) {
            r.rttCnt += c.rttCnt; r.rttSum += c.rttSum;
            if (r.rttMin < 0 || c.rttMin < r.rttMin) r.rttMin = c.rttMin;
            if (c.rttMax > r.rttMax) r.rttMax = c.rttMax;
            for (long long v : c.rttSamples) r.rttSamples.push_back(v);
        }
        if (c.synRtt >= 0 && (r.synRttMin < 0 || c.synRtt < r.synRttMin))
            r.synRttMin = c.synRtt;
    }
    // Пакеты целевого IP — один раз: нужны и flow-builder'у, и таблице ниже.
    // Без цели работаем прямо по packets, без копии всего дампа.
    std::vector<Packet> targetScope;
    if (!targetIp.empty())
        for (const auto& p : packets)
            if (p.srcIp == targetIp || p.dstIp == targetIp) targetScope.push_back(p);
    const std::vector<Packet>& dpiScope = targetIp.empty() ? packets : targetScope;

    // байты по IP — из flow-builder (один проход)
    {
        for (const auto& f : buildFlows(dpiScope)) {
            // байты — только удалённой стороне. Если локальный адрес тоже попал в
            // byIp (ему что-то слал роутер по LAN), иначе в его строку легли бы
            // все потоки абонента. Направление не определить — к обоим, как раньше
            bool sL = isLocal(f.srcIp), dL = isLocal(f.dstIp);
            auto it = byIp.find(f.dstIp);
            if (it != byIp.end() && (sL == dL || !dL))
                { it->second.bytesOut += f.bytesOut; it->second.bytesIn += f.bytesIn; }
            auto it2 = byIp.find(f.srcIp);
            if (it2 != byIp.end() && (sL == dL || !sL))
                { it2->second.bytesOut += f.bytesIn; it2->second.bytesIn += f.bytesOut; }
        }
    }
    // пересчитаем score по агрегату
    std::vector<IpRow> rows;
    for (auto& kv : byIp) {
        IpRow& r = kv.second;
        // SYN без ответа — только если нет данных вообще (иначе просто асимметрия дампа)
        bool synFail = (r.syn > 0 && r.synack == 0 && !r.sawData);
        r.score = (synFail ? 5 : 0) + r.rst * 2 + r.retr + r.dup + r.zw + r.synRetr;
        // в таблицу: проблемные (score>0) ВСЕГДА; а если задан конкретный target —
        // показываем и его (даже если он чистый, score=0) — карточка по запросу.
        bool isTarget = (!targetIp.empty() && r.ip == targetIp);
        if (r.score > 0 || isTarget) rows.push_back(r);
    }
    std::sort(rows.begin(), rows.end(), [](const IpRow& a, const IpRow& b){ return a.score > b.score; });

    // IP с признаками блокировки на ТСПУ (TCP-DPI + UDP-WireGuard) — для пометки в таблице
    // Таблица 4-кортежей строится один раз: на весь дамп и (если задан целевой
    // IP) отдельно на его пакеты — все детекторы ниже смотрят в одни и те же данные.
    TcpConnTable ttOwn;
    if (!ttIn) ttOwn = buildTcpConnTable(packets, localIp);
    const TcpConnTable& ttAll = ttIn ? *ttIn : ttOwn;
    TcpConnTable ttTarget;
    if (!targetIp.empty()) ttTarget = buildTcpConnTable(targetScope, localIp);
    const TcpConnTable& ttScope = targetIp.empty() ? ttAll : ttTarget;

    std::set<std::string> tspuBlocked = collectTspuBlockedIps(packets, localIp, &ttAll, ipCache);
    // Домены, заблокированные по SNI, и адреса, где они встретились. Если такой
    // адрес не попал в tspuBlocked — он общий (CDN): другие сайты на нём
    // работают, заблокировано только имя. В таблице это SNI-BLOCK, а не TSPU?.
    const auto blockedSnisAll = collectBlockedSnis(packets, localIp, &ttAll);
    std::set<std::string> sniBlockIps;
    for (const auto& kv : ttAll.conns)
        if (!kv.second.sni.empty() && blockedSnisAll.count(kv.second.sni) &&
            !tspuBlocked.count(kv.second.ip))
            sniBlockIps.insert(kv.second.ip);

    // Причины блокировок — те же, что в разделе «ПРИЧИНЫ БЛОКИРОВОК» ниже, чтобы
    // ВЫВОД им не противоречил: «~16 КБ» — не «проблема канала», а UDP без
    // ответа — не «проблем нет».
    const std::vector<BlockReason> blockReasons =
        collectBlockReasons(packets, ttAll, ipCache, localIp, targetIp);
    std::vector<const BlockReason*> frz16;
    for (const auto& r : blockReasons) if (r.code == "TCP16") frz16.push_back(&r);
    // UDP без ответа, которого нет среди tspuIps (туннель без ответа туда уже
    // попал): чаще всего QUIC на :443 — браузер или Hysteria2
    auto udpOtherOf = [&](const std::set<std::string>& tspuIps) {
        std::vector<const BlockReason*> v;
        for (const auto& r : blockReasons)
            if (r.code == "UDP_DROP" && !tspuIps.count(r.ip)) v.push_back(&r);
        return v;
    };
    auto listOf = [](const std::vector<const BlockReason*>& v) {
        std::string s; std::set<std::string> seen; int col = 0;
        for (const BlockReason* r : v) {
            if (!seen.insert(r->ip).second) continue;
            if (!s.empty()) s += ", ";
            if (col >= 6) { s += "\n     "; col = 0; }
            s += r->ip;
            if (r->target != r->ip) s += " (" + r->target + ")";
            col++;
        }
        return s;
    };
    auto printFreeze = [&](bool also) {
        printf("%s%sОБРЫВ ПОСЛЕ ~16 КБ к зарубежному хостингу: %s\n"
               "Соединение встаёт, начало ответа приходит, дальше данные не идут —\n"
               "ни RST, ни FIN. Почерк ограничения ТСПУ к зарубежным хостингам: сайт\n"
               "грузится частично, VPN подключается, но не работает. Повторы и потери\n"
               "по этим адресам — попытки дослать данные в зависшие соединения, а не\n"
               "плохой канал. Подтвердите режимом «Тест 16 КБ».%s\n",
               C::RED, also ? "Также: " : "", listOf(frz16).c_str(), C::RST);
    };
    auto printUdpOther = [&](const std::vector<const BlockReason*>& udp, bool also) {
        bool quic = false, other = false;
        for (const BlockReason* r : udp)
            (r->detail.rfind("QUIC:", 0) == 0 ? quic : other) = true;
        printf("%s%sUDP БЕЗ ОТВЕТА: %s\n", C::YEL, also ? "Также: " : "", listOf(udp).c_str());
        if (quic)
            printf("QUIC (UDP/443) уходит, в ответ ничего. Браузер сам перейдёт на TCP,\n"
                   "и сайт откроется; если это VPN поверх QUIC (Hysteria2 и т.п.) —\n"
                   "протокол, скорее всего, режется ТСПУ или сервер не отвечает.\n");
        if (other)
            printf("UDP-туннель: пакеты уходят, ответов нет — протокол режется по пути\n"
                   "или сервер недоступен.\n");
        printf("%s", C::RST);
    };

    if (rows.empty()) {
        if (!targetIp.empty())
            printf("\n%sПо адресу %s в дампе нет трафика (или только приватные пакеты).%s\n",
                   C::YEL, targetIp.c_str(), C::RST);
        else {
            // Ретрансмиссий/сбросов по счётчикам нет, но блокировка бывает и без
            // них: молчаливый дроп после ClientHello, RST по SNI, UDP/WireGuard.
            std::vector<std::string> dpiFindings = detectDpiInjection(ttAll);
            if (!dpiFindings.empty()) {
                printf("\n%s=== Признаки DPI-блокировки (RST-инъекция / дроп) ===%s\n", C::BOLD, C::RST);
                for (auto& f : dpiFindings) printf("  %s!%s %s\n", C::RED, C::RST, f.c_str());
            }
            const auto udpOther = udpOtherOf(tspuBlocked);
            const bool anyBlock = !tspuBlocked.empty() || !blockedSnisAll.empty() || !dpiFindings.empty();
            // таблицы проблем нет, но блокировка найдена — ВЫВОД всё равно печатаем
            if (anyBlock || !frz16.empty() || !udpOther.empty())
                printf("\n=================== ВЫВОД ===================");
            if (!tspuBlocked.empty()) {
                std::set<std::string> tcpIps;
                for (const auto& kv : ttAll.conns) tcpIps.insert(kv.second.ip);
                bool anyTcp = false;
                std::string lst;
                for (const auto& ip : tspuBlocked) {
                    if (tcpIps.count(ip)) anyTcp = true;
                    if (!lst.empty()) lst += ", ";
                    lst += ip;
                }
                printf("\n%sВОЗМОЖНО БЛОКИРОВКА НА ТСПУ (%d адр.): %s%s\n",
                       C::RED, (int)tspuBlocked.size(), lst.c_str(), C::RST);
                if (anyTcp)
                    printf("%sПотерь и сбросов по ходу сессий нет, но часть соединений "
                           "режется на старте (дроп после ClientHello или RST по SNI).%s\n",
                           C::GRY, C::RST);
                else
                    printf("%sTCP-трафик чист, но UDP/WireGuard-туннель не работает "
                           "(handshake уходит, ответа нет — почерк ТСПУ).%s\n", C::GRY, C::RST);
                printBlockedSniList(blockedSnisAll);
            } else if (!blockedSnisAll.empty()) {
                printf("\n%sЗАБЛОКИРОВАНЫ ОТДЕЛЬНЫЕ ДОМЕНЫ (по SNI). Адреса у них общие "
                       "(CDN/хостинг):\nдругие сайты на тех же IP работают, "
                       "поэтому адреса целиком не помечаются.%s\n", C::RED, C::RST);
                printBlockedSniList(blockedSnisAll);
            } else if (!dpiFindings.empty()) {
                printf("\n%sОбнаружены прямые признаки DPI-блокировки — см. раздел выше.%s\n",
                       C::RED, C::RST);
            } else if (!frz16.empty()) {
                printf("\n");
                printFreeze(false);
            } else if (!udpOther.empty()) {
                printf("\n");
                printUdpOther(udpOther, false);
            } else {
                printf("\n%sЯвных проблем соединения не обнаружено.%s\n", C::GRN, C::RST);
            }
            if (anyBlock && !frz16.empty()) printFreeze(true);
            if ((anyBlock || !frz16.empty()) && !udpOther.empty()) printUdpOther(udpOther, true);
        }
    } else {
        printf("\n%s=== ПРОБЛЕМНЫЕ АДРЕСА (единая таблица) ===%s\n", C::BOLD, C::RST);
        printf("  %-16s %-9s %3s %3s %3s %4s %4s %3s %-17s %6s %-10s %-10s %-8s %-32s %-14s %s\n",
               "IP", "PORTS", "SYN", "SA", "RST", "RETR", "SYNr", "ZW",
               "RTT mn/md/mx", "LOSS", "BYTE i/o", "VERDICT", "TAG", "ORG", "REGION", "APP");
        // белый список VPN — только для тега; вердикт по соединению не меняется
        const auto ipW = withVpnWhitelist(packets, ipCache);
        int shown = 0;
        for (auto& r : rows) {
            if (shown++ >= 15) break;
            // порты (не больше 3)
            std::string portsStr; int pc = 0;
            for (int p : r.ports) {
                if (pc++ >= 3) { portsStr += ".."; break; }
                if (!portsStr.empty()) portsStr += ",";
                portsStr += std::to_string(p);
            }
            // RTT мин/мед/макс (мс)
            std::string rttStr = "-";
            if (r.rttCnt > 0) {
                long long med = r.rttMin;
                if (!r.rttSamples.empty()) {
                    std::sort(r.rttSamples.begin(), r.rttSamples.end());
                    med = r.rttSamples[r.rttSamples.size()/2];
                }
                char b[64];
                snprintf(b, sizeof(b), "%lld/%lld/%lld", r.rttMin/1000, med/1000, r.rttMax/1000);
                rttStr = b;
            } else if (r.synRttMin >= 0) {
                // RTT по данным не набрался (соединение не передавало или ответы
                // не подтверждались) — показываем RTT рукопожатия. Помечаем «hs»,
                // чтобы не путали с обычной тройкой мин/мед/макс: это один замер.
                char b[64];
                snprintf(b, sizeof(b), "%lld hs", r.synRttMin/1000);
                rttStr = b;
            }
            // потери
            double lossPct = r.dataPkts ? (100.0 * r.retr / r.dataPkts) : 0.0;
            char lossStr[24];
            if (r.dataPkts < 20)        snprintf(lossStr, sizeof(lossStr), "-");      // мало данных — % недостоверен
            else if (r.dataPkts < 50)   snprintf(lossStr, sizeof(lossStr), "%.0f%%~", lossPct);
            else                        snprintf(lossStr, sizeof(lossStr), "%.1f%%", lossPct);
            // байты человекочитаемо
            auto human = [](long long b)->std::string {
                char o[24];
                if (b >= 1048576) snprintf(o,sizeof(o),"%.1fM", b/1048576.0);
                else if (b >= 10240) snprintf(o,sizeof(o),"%lldk", (b+512)/1024);   // >10К: целое, к ближайшему
                else if (b >= 1024)  snprintf(o,sizeof(o),"%.1fk", b/1024.0);        // 1-10К: с десятой
                else snprintf(o,sizeof(o),"%lld", b);
                return o;
            };
            std::string bytesStr = human(r.bytesIn) + "/" + human(r.bytesOut);
            // вердикт по адресу
            bool hardFail = (r.syn > 0 && r.synack == 0 && !r.sawData);
            bool tspu = tspuBlocked.count(r.ip) > 0;
            bool sniBlk = sniBlockIps.count(r.ip) > 0;   // общий адрес, блок по имени
            // повторы SYN — проблема, ТОЛЬКО если соединения реально не встают.
            // Если SYN-ACK приходят (synack>0) и данные идут, повтор SYN = просто
            // потеря первого пакета на старте, не блокировка. Считаем проблемой,
            // когда повторов много И заметная доля не получила SYN-ACK.
            bool synRetrProblem = (r.synRetr >= 3) &&
                                  (r.synack == 0 || r.synack * 2 < r.syn);
            // локальные адреса (роутер, шлюз) часто не принимают TCP на служебных
            // портах (53) — это не блокировка оператора, не пугаем ISSUES по SYN.
            bool isLocalAddr = isPrivateIp(r.ip);
            // сбросы как проблема — только если сервер рвёт соединения на старте
            // или до данных (порог как у sumRstEarly в итоговом выводе)
            bool rstProblem = r.rstBadConns >= 4;
            const char* verdict; const char* col;
            if (tspu) { verdict = "TSPU?"; col = C::RED; }   // возможна блокировка на ТСПУ
            else if (sniBlk) { verdict = "SNI-BLOCK"; col = C::YEL; }
            else if (hardFail && !isLocalAddr) { verdict = "DOWN"; col = C::RED; }
            else if (!isLocalAddr && (synRetrProblem || rstProblem || r.zw >= 5 ||
                     (r.dataPkts>=50 && lossPct>=5.0))) {
                verdict = "ISSUES"; col = C::YEL;
            } else if (isLocalAddr && (rstProblem || (r.dataPkts>=50 && lossPct>=5.0))) {
                verdict = "ISSUES"; col = C::YEL;   // для локальных — только явные потери/RST
            } else { verdict = "ok"; col = C::WHT; }

            // ASN-имя + тег (VPN/PROXY/TOR/HOSTING) — справа в таблице
            std::string asnStr = "-";
            std::string tag; const char* tagCol = C::GRY;
            if (ipCache) {
                auto it = ipCache->find(r.ip);
                if (it != ipCache->end()) {
                    const IpInfo& info = it->second;
                    // предпочитаем читаемое имя организации; если пусто — берём поле as
                    std::string name;
                    if (!info.org.empty() && info.org != "-") name = info.org;
                    else if (!info.asn.empty() && info.asn != "-") {
                        // "AS15169 Google LLC" -> "Google LLC"; если только номер — оставим номер
                        name = info.asn;
                        size_t sp = name.find(' ');
                        if (sp != std::string::npos) name = name.substr(sp + 1);
                    }
                    if (!name.empty()) asnStr = name;   // полное имя, без обрезки
                    bool cdn = looksCdnOrg(info.org);
                    // хостинг определяем и по флагу, и по названию org (надёжнее)
                    bool host = (info.hosting || looksHostingOrg(info.org, info.asn)) && !isOwnIspOrg(info.org, info.asn);
                    const IpInfo* wi = ipInfoOf(&ipW, r.ip);
                    if (wi && wi->vpnWhite) { tag = "WHITE"; tagCol = C::GRY; }   // белый список: не VPN
                    else if (info.isVpn)   { tag = "VPN";    tagCol = C::RED; }
                    else if (info.isProxy) { tag = "PROXY";  tagCol = C::RED; }
                    else if (info.isTor)   { tag = "TOR";    tagCol = C::RED; }
                    // только показ (в вердикт не идут): резидентный прокси, Private Relay, Zscaler
                    else if (info.pxType == "RES" || info.pxType == "CPN" || info.pxType == "EPN")
                                           { tag = info.pxType; tagCol = C::YEL; }
                    else if (host && !cdn) { tag = "HOSTING"; tagCol = C::YEL; }
                }
            }

            // регион (полное название страны) — из geo-кэша
            std::string regionStr = "-";
            if (ipCache) {
                auto it = ipCache->find(r.ip);
                if (it != ipCache->end() && !it->second.country.empty() && it->second.country != "-")
                    regionStr = regionName(it->second.country);
            }

            // APP — приложение по известному порту (Battle.net, Steam, RDP и т.п.)
            // generic-протоколы (HTTP/HTTPS/DNS) не показываем — они малоинформативны.
            std::string appStr = "-";
            for (int p : r.ports) {
                const char* a = appByPort(p, "TCP");
                if (!a) a = appByPort(p, "UDP");
                if (!a) continue;
                std::string s = a;
                // пропускаем общие веб/DNS-метки
                if (s.find("HTTP")!=std::string::npos || s.find("HTTPS")!=std::string::npos ||
                    s.find("DNS")!=std::string::npos  || s.find("веб")!=std::string::npos)
                    continue;
                appStr = s; break;
            }

            // ORG обрезаем до фиксированной ширины, иначе длинные имена
            // («Autonomous Nonprofit Organisation») ломают выравнивание REGION/APP.
            // Ширина — в символах: printf «%-Ns» считает байты, и кириллица
            // (2 байта на букву) сдвигала бы колонки.
            auto padU8 = [](const std::string& s, size_t w) {
                return u8len(s) > w ? u8prefix(s, w - 1) + "~" : u8pad(s, w);
            };
            std::string orgCol = padU8(asnStr, 32);
            regionStr = padU8(regionStr, 14);

            printf("  %s%-16s %-9s %3lld %3lld %3lld %4lld %4lld %3lld %-17s %6s %-10s %-10s%s %s%-8s%s %s%s%s %s%s%s %s%s%s\n",
                   col, r.ip.c_str(), portsStr.c_str(),
                   r.syn, r.synack, r.rst, r.retr, r.synRetr, r.zw,
                   rttStr.c_str(), lossStr, bytesStr.c_str(), verdict, C::RST,
                   tagCol, tag.empty() ? "-" : tag.c_str(), C::RST,
                   C::CYN, orgCol.c_str(), C::RST,
                   C::GRY, regionStr.c_str(), C::RST,
                   C::BWHT, appStr.c_str(), C::RST);
        }
        printf("  %sRTT мс (hs = по рукопожатию SYN→SYN-ACK, данных не было); "
               "LOSS=ретр/пакеты(~=мало); SYNr=повторы SYN; BYTE вх/исх;\n  "
               "RST — все сбросы, но ISSUES по ним — только от 4 соединений, сброшенных "
               "сервером на старте или до данных; "
               "ASN/тег — ip-api+ipapi.is (VPN/PROXY/TOR/HOSTING)%s\n", C::GRY, C::RST);
        if (!sniBlockIps.empty())
            printf("  %sTSPU? — признаки блокировки всего адреса; SNI-BLOCK — адрес общий "
                   "(CDN), на нём заблокирован\n  отдельный домен, а другие сайты работают "
                   "(список доменов — в выводе ниже).%s\n", C::GRY, C::RST);

        // фильтры Wireshark для тех же строк — чтобы сразу открыть узел в дампе
        printf("\n  %sФильтры для Wireshark (вставить в строку фильтра):%s\n", C::BOLD, C::RST);
        {
            int shownF = 0;
            for (auto& r : rows) {
                if (shownF++ >= 15) break;
                std::string f = wsFilter(r.ip);
                if (!r.ports.empty() && r.ports.size() <= 3) {
                    std::string pp;
                    for (int p : r.ports) {
                        if (!pp.empty()) pp += " || ";
                        pp += "tcp.port==" + std::to_string(p);
                    }
                    f += (r.ports.size() == 1) ? " && " + pp : " && (" + pp + ")";
                } else {
                    f += " && tcp";
                }
                printf("  %-16s %s%s%s\n", r.ip.c_str(), C::CYN, f.c_str(), C::RST);
            }
            printf("  %sдобавьте «&& tcp.analysis.flags» — останутся только аномалии "
                   "(ретрансмиссии, dup ACK, zero window); «&& tcp.flags.syn==1» — "
                   "только рукопожатия.%s\n", C::GRY, C::RST);
        }

        // если запрашивали конкретный IP и он чистый — скажем явно
        if (!targetIp.empty()) {
            for (auto& r : rows) {
                if (r.ip == targetIp && r.score == 0) {
                    printf("\n%sПо адресу %s проблем не выявлено: рукопожатие "
                           "проходит, потерь/сбросов нет. Соединение в норме.%s\n",
                           C::GRN, targetIp.c_str(), C::RST);
                    break;
                }
            }
        }

        printf("\n%sДетали:%s\n", C::BOLD, C::RST);

        // соберём суммарные счётчики по всем (или отфильтрованным) соединениям
        long long sumSyn=0, sumSA=0, sumRst=0, sumRstEarly=0, sumRetr=0,
                  sumDup=0, sumZw=0, sumRttCnt=0, sumRttSum=0,
                  rttMinAll=-1, rttMaxAll=-1;
        // сброшены сервером ПОСЛЕ рукопожатия, но до первых его данных (этап
        // TLS/запроса) — и RTT рукопожатия именно этих соединений
        long long rstNoData = 0, rstNoDataRttSum = 0, rstNoDataRttCnt = 0;
        for (auto& kv : conns) {
            const Conn& c = kv.second;
            // ранние сбросы — по СОЕДИНЕНИЯМ (не по пакетам RST) и только к внешним
            // адресам: так же, как rstBadConns в таблице
            const bool ext = !isPrivateIp(c.remoteIp);
            if (ext && c.rstEarly > 0) sumRstEarly++;
            if (ext && c.syn > 0 && c.synack > 0 && c.rstRem > 0 && c.bytesIn == 0) {
                rstNoData++;
                if (c.synRtt >= 0) { rstNoDataRttSum += c.synRtt; rstNoDataRttCnt++; }
            }
            sumSyn += c.syn; sumSA += c.synack; sumRst += c.rst;
            sumRetr += c.retrans; sumDup += c.dupAck; sumZw += c.zeroWin;
            if (c.rttCnt > 0) {
                sumRttCnt += c.rttCnt; sumRttSum += c.rttSum;
                if (rttMinAll < 0 || c.rttMin < rttMinAll) rttMinAll = c.rttMin;
                if (c.rttMax > rttMaxAll) rttMaxAll = c.rttMax;
            }
        }
        bool anyFinding = false;
        auto say = [&](const char* color, const std::string& msg) {
            printf("  %s• %s%s\n", color, msg.c_str(), C::RST);
            anyFinding = true;
        };

        // SYN-ретрансмиссии — клиент повторяет SYN, соединение не начинается.
        // 1–2 повтора — единичная потеря пакета на старте, не проблема (порог
        // тот же, что у вердикта по адресу: synRetrProblem).
        if (totalSynRetr >= 3) {
            char b[512];
            snprintf(b, sizeof(b),
                "%lld повторов SYN (клиент пересылал SYN) — соединение не "
                "устанавливается с первой попытки: цель не отвечает на SYN, "
                "потеря на пути или блокировка на этапе рукопожатия.", totalSynRetr);
            say(C::RED, b);
        } else if (totalSynRetr > 0) {
            char b[512];
            snprintf(b, sizeof(b),
                "%lld повтор(а) SYN — единичная потеря пакета на старте "
                "соединения, само по себе это норма.", totalSynRetr);
            say(C::WHT, b);
        }

        // SYN без SYN-ACK
        if (synNoReply > 0) {
            char b[512];   // кириллица в UTF-8 — 2 байта на букву
            snprintf(b, sizeof(b),
                "%lld соединений не установились (SYN ушёл, SYN-ACK не пришёл) — "
                "сервер недоступен, порт закрыт или возможна блокировка.", synNoReply);
            if (synNoReplyExt < synNoReply) {
                char l[160];
                snprintf(l, sizeof(l), " Из них к локальным адресам (роутер/LAN): %lld "
                         "— это не блокировка.", synNoReply - synNoReplyExt);
                say(synNoReplyExt > 0 ? C::RED : C::YEL, std::string(b) + l);
            } else {
                say(C::RED, b);
            }
        }

        // RST: ранние vs обычные
        if (sumRstEarly > 0) {
            char b[512];
            snprintf(b, sizeof(b),
                "%lld соедин. сброшены сервером сразу при подключении (RST в ответ "
                "на SYN) — порт закрыт, сервис не запущен или отказ файрвола.", sumRstEarly);
            say(sumRstEarly >= 4 ? C::RED : C::YEL, b);
        } else if (sumRst >= 10) {
            char b[512];
            snprintf(b, sizeof(b),
                "%lld RST по ходу сессий — много сбросов, но не на старте "
                "(сервер сам закрывает или таймауты).", sumRst);
            say(C::YEL, b);
        } else if (sumRst > 0) {
            char b[512];
            snprintf(b, sizeof(b),
                "%lld RST — небольшое число сбросов, в пределах нормы.", sumRst);
            say(C::WHT, b);
        }

        // Рукопожатие проходит штатно, но соединения рвут в начале. Разделяет два
        // диагноза, которые раньше выглядели одинаково: если SYN-ACK приходит
        // быстро — путь до сервера цел и узел доступен, значит рвут уже ПОСЛЕ
        // установки, на этапе TLS. Это фильтрация по содержимому (SNI), а не
        // недоступность адреса. При недоступности SYN-RTT вообще не набирается.
        // Считается по ТЕМ ЖЕ соединениям, что сброшены (а не по всем подряд):
        // раньше RTT брался со всех соединений, а «ранние RST» — это в основном
        // RST на SYN (закрытый порт), и вывод про TLS получался ложным.
        if (rstNoData > 0) {
            char b[768];
            std::string rttPart;
            if (rstNoDataRttCnt > 0) {
                char r[160];
                snprintf(r, sizeof(r), " Рукопожатие у них прошло (RTT SYN→SYN-ACK ~%lld мс) "
                         "— путь до узла цел, узел отвечает.",
                         (rstNoDataRttSum / rstNoDataRttCnt) / 1000);
                rttPart = r;
            }
            snprintf(b, sizeof(b),
                "%lld соедин. сброшены ПОСЛЕ установки, до первых данных сервера "
                "(этап TLS/запроса).%s Так выглядит фильтрация по содержимому (SNI), "
                "но и сервер, отвергший запрос, — поддельные RST ТСПУ выделены в разделе "
                "DPI ниже.", rstNoData, rttPart.c_str());
            say(rstNoData >= 4 ? C::RED : C::YEL, b);
        }

        // ретрансмиссии — оценим долю от пакетов с данными
        long long dataPkts = 0;
        for (auto& kv : conns) dataPkts += (long long)kv.second.seqSeen.size() + kv.second.retrans;
        double retrRate = dataPkts > 0 ? 100.0 * sumRetr / dataPkts : 0.0;
        if (sumRetr >= 50 || retrRate >= 5.0) {
            char b[512];
            // если data-пакетов много (крупная передача УСПЕШНО прошла), высокий
            // % ретрансмиссий часто = артефакт offload (TSO/GRO/LRO) в захвате,
            // а не реальные потери — иначе передача бы не завершилась.
            if (dataPkts >= 500) {
                snprintf(b, sizeof(b),
                    "%lld повторов сегментов (~%.1f%%) при крупной передаче (%lld "
                    "data-пакетов). На больших успешных загрузках это чаще артефакт "
                    "сетевой разгрузки (TSO/GRO) в дампе, чем реальные потери; "
                    "трактовать как блокировку НЕ стоит.",
                    sumRetr, retrRate, dataPkts);
                say(C::YEL, b);
            } else {
                snprintf(b, sizeof(b),
                    "%lld ретрансмиссий (~%.1f%% data-пакетов) — заметные потери: "
                    "плохой канал, перегрузка или фильтрация трафика.",
                    sumRetr, retrRate);
                say(C::RED, b);
            }
        } else if (sumRetr >= 10) {
            char b[512];
            snprintf(b, sizeof(b),
                "%lld ретрансмиссий (~%.1f%%) — умеренные потери на линии.",
                sumRetr, retrRate);
            say(C::YEL, b);
        } else if (sumRetr > 0) {
            char b[120];
            snprintf(b, sizeof(b), "%lld ретрансмиссий — единичные, в пределах нормы.", sumRetr);
            say(C::GRN, b);
        }

        // что именно теряется/режется — разбивка по протоколу (порту)
        {
            // соберём порты с заметными потерями или сбросами
            std::vector<std::pair<int, PortLoss>> hot;
            for (auto& kv : byPort)
                if (kv.second.retr >= 5 || kv.second.rst >= 5 ||
                    (kv.second.syn > 0 && kv.second.synack == 0))
                    hot.push_back(kv);
            std::sort(hot.begin(), hot.end(),
                [](auto& a, auto& b){ return (a.second.retr + a.second.rst) > (b.second.retr + b.second.rst); });
            int shownP = 0;
            for (auto& kv : hot) {
                if (shownP++ >= 5) break;
                int port = kv.first; const PortLoss& pl = kv.second;
                const char* app = appByPort(port, pl.proto);
                std::string appName = app ? app : "сервис";
                char b[512];   // кириллица в UTF-8 — 2 байта на букву
                if (pl.syn > 0 && pl.synack == 0)
                    snprintf(b, sizeof(b),
                        "Не подключается %s (порт %d/%s): SYN без ответа.",
                        appName.c_str(), port, pl.proto.c_str());
                else
                    snprintf(b, sizeof(b),
                        "Страдает %s (порт %d/%s): %lld ретрансмиссий, %lld RST.",
                        appName.c_str(), port, pl.proto.c_str(), pl.retr, pl.rst);
                say((pl.syn > 0 && pl.synack == 0) ? C::RED : C::YEL,
                    std::string(b) + "  [tcp.port==" + std::to_string(port) + "]");
            }
        }

        // Переупорядочивание — отдельным пунктом. Само по себе не потери и не
        // блокировка, но завышает и ретрансмиссии (fast retransmit по трём
        // дубликатам ACK), и сами дубликаты ACK, — поэтому о нём надо сказать.
        if (totalReorder >= 10) {
            char b[512];
            snprintf(b, sizeof(b),
                "%lld входящих сегментов пришли не по порядку — путь переупорядочивает "
                "пакеты (балансировка ECMP/LAG или разные маршруты внутри туннеля). "
                "Данные при этом доходят; часть ретрансмиссий и дубликатов ACK выше "
                "вызвана именно этим, а не потерями.", totalReorder);
            say(C::WHT, b);
        }

        // dup-ACK
        if (sumDup >= 20) {
            char b[512];
            // Дубликат ACK = приёмник увидел ПРОПУСК в последовательности. Пропуск
            // бывает от потери, а бывает от переупорядочивания — тогда «потерянный»
            // сегмент приходит следом и терять ничего не пришлось. Одно событие
            // реордеринга даёт порядка одного-трёх дубликатов ACK, поэтому если
            // сегментов не по порядку хотя бы вдвое меньше числа дубликатов —
            // картину объясняет реордеринг, а не потери.
            if (totalReorder * 2 >= sumDup)
                snprintf(b, sizeof(b),
                    "%lld дубликатов ACK при %lld сегментах не по порядку — пропуски в "
                    "потоке объясняются переупорядочиванием пути, а не потерями. "
                    "Данные доходят, чинить нечего.", sumDup, totalReorder);
            else
                snprintf(b, sizeof(b),
                    "%lld дубликатов ACK — приёмник многократно просит потерянный "
                    "сегмент (переупорядочивание пути картину не объясняет: %lld).",
                    sumDup, totalReorder);
            say(C::YEL, b);
        } else if (sumDup > 0) {
            char b[120];
            snprintf(b, sizeof(b), "%lld дубликатов ACK — единичные.", sumDup);
            say(C::WHT, b);
        }

        // zero-window
        if (sumZw > 0) {
            char b[512];
            snprintf(b, sizeof(b),
                "%lld пакетов с zero-window — приёмник захлёбывался "
                "(не успевал читать).", sumZw);
            say(sumZw >= 10 ? C::YEL : C::WHT, b);
        }

        // RTT
        if (sumRttCnt > 0) {
            long long avg = sumRttSum / sumRttCnt;
            char b[512];
            if (avg >= 500000) {
                snprintf(b, sizeof(b),
                    "RTT очень высокий: avg %lld мс (min %lld, max %lld) — "
                    "сервер далеко или сильно перегружен.",
                    avg/1000, rttMinAll/1000, rttMaxAll/1000);
                say(C::RED, b);
            } else if (avg >= 300000) {
                snprintf(b, sizeof(b),
                    "RTT повышенный: avg %lld мс (min %lld, max %lld) — "
                    "маршрут не лучший.",
                    avg/1000, rttMinAll/1000, rttMaxAll/1000);
                say(C::YEL, b);
            } else if (avg >= 100000) {
                snprintf(b, sizeof(b),
                    "RTT в норме: avg %lld мс (min %lld, max %lld).",
                    avg/1000, rttMinAll/1000, rttMaxAll/1000);
                say(C::GRN, b);
            } else {
                snprintf(b, sizeof(b),
                    "RTT низкий: avg %lld мс (min %lld, max %lld) — близкий сервер.",
                    avg/1000, rttMinAll/1000, rttMaxAll/1000);
                say(C::GRN, b);
            }
        }

        // MTU / MSS по опции MSS из SYN. Это точнее макс. размера сегмента:
        // сегменты бывают мельче MSS (мало данных) или крупнее (TSO/GRO в дампе),
        // а MSS в SYN — прямо объявленный стеком предел = MTU интерфейса - 40/60.
        // Для IPv6 заголовок на 20 байт больше, поэтому приводим к «IPv4-эквиваленту».
        bool mssKnown = false;
        {
            std::map<int, long long> locMss;             // MSS абонента (экв. IPv4) -> соединений
            std::map<std::string, int> lowRem;           // удалённый IP -> его MSS (экв.), если < 1400
            for (auto& kv : conns) {
                const Conn& c = kv.second;
                int add = (c.remoteIp.find(':') != std::string::npos) ? 20 : 0;
                if (c.mssLoc > 0) locMss[c.mssLoc + add]++;
                // у CDN/крупных сервисов малый MSS штатный (Google GFE — всегда 1380)
                const IpInfo* ri = ipInfoOf(ipCache, c.remoteIp);
                if (ri && looksCdnOrg(ri->org)) continue;
                if (c.mssRem > 0 && c.mssRem + add < 1400) lowRem[c.remoteIp] = c.mssRem + add;
            }
            if (!locMss.empty()) {
                mssKnown = true;
                int mss = 0; long long best = -1;
                for (auto& kv : locMss) if (kv.second > best) { best = kv.second; mss = kv.first; }
                int over = 1460 - mss;
                char b[640];
                if (mss >= 1460) {
                    snprintf(b, sizeof(b),
                        "MSS абонента в SYN: %d — MTU 1500, туннеля/урезания на стороне "
                        "абонента нет.", mss);
                    say(C::GRN, b);
                } else if (mss >= 1452) {
                    snprintf(b, sizeof(b),
                        "MSS абонента в SYN: %d (на %d меньше 1460) — PPPoE или похожая "
                        "лёгкая инкапсуляция у провайдера, это норма.", mss, over);
                    say(C::WHT, b);
                } else if (mss >= 1400) {
                    snprintf(b, sizeof(b),
                        "MSS абонента в SYN: %d (на %d меньше 1460) — MTU урезан: между "
                        "абонентом и точкой съёма туннель/оверлей (L2TP, GRE, IPsec, VPN) "
                        "или MSS-clamping на роутере.", mss, over);
                    say(C::YEL, b);
                } else {
                    snprintf(b, sizeof(b),
                        "MSS абонента в SYN: %d (на %d меньше 1460) — сильно урезанный "
                        "MTU, характерный для VPN (WireGuard ~1380, OpenVPN ~1360): "
                        "трафик абонента идёт через туннель. Слишком малый MTU без "
                        "PMTUD ломает QUIC и медиа.", mss, over);
                    say(C::RED, b);
                }
                if (locMss.size() > 1) {
                    std::string lst;
                    for (auto& kv : locMss) {
                        if (!lst.empty()) lst += ", ";
                        lst += std::to_string(kv.first) + "×" + std::to_string(kv.second);
                    }
                    say(C::GRY, "Разные MSS у соединений абонента (MSS×соед.): " + lst +
                                " — несколько устройств/интерфейсов или часть трафика в туннеле.");
                }
            }
            if (!lowRem.empty()) {
                std::string lst; int n = 0;
                for (auto& kv : lowRem) {
                    if (n++ >= 5) { lst += ", ..."; break; }
                    if (!lst.empty()) lst += ", ";
                    lst += kv.first + " (" + std::to_string(kv.second) + ")";
                }
                char b[160];
                snprintf(b, sizeof(b), "%d сервер(ов) объявили MSS < 1400: ", (int)lowRem.size());
                say(C::WHT, std::string(b) + lst +
                    " — узел за туннелем/оверлеем или урезает MSS сам; для "
                    "VPN/прокси-узлов это ещё один признак туннеля.");
            }
        }

        // SACK: получатель сообщает, какие куски дошли в обход дыры. По тому,
        // КТО шлёт SACK, видно направление потерь — чего не дают ретрансмиссии.
        {
            long long sackLoc = 0, sackRem = 0;
            for (auto& kv : conns) { sackLoc += kv.second.sackFromLoc; sackRem += kv.second.sackFromRem; }
            if (sackLoc + sackRem >= 5) {
                char b[640];
                const char* where =
                    (sackLoc > sackRem * 3) ? "потери в основном на пути К абоненту (загрузка)" :
                    (sackRem > sackLoc * 3) ? "потери в основном на пути ОТ абонента (отдача)" :
                                              "потери в обоих направлениях";
                snprintf(b, sizeof(b),
                    "SACK: абонент %lld раз сообщил о дырах во входящем потоке, "
                    "удалённая сторона — %lld раз в исходящем: %s.",
                    sackLoc, sackRem, where);
                say((sackLoc + sackRem) >= 50 ? C::YEL : C::WHT, b);
            }
        }

        // Масштабирование окна. Без window scale окно не больше 64 КБ, и
        // скорость одного соединения упирается в 64К/RTT, как бы широк ни был канал.
        {
            long long noScale = 0, smallWin = 0, smallWinMax = 0;
            for (auto& kv : conns) {
                const Conn& c = kv.second;
                if (!c.synLocSeen || !c.synRemSeen) continue;   // масштаб неизвестен
                if (c.bytesIn + c.bytesOut < 256 * 1024) continue; // мелкие не ограничены окном
                if (c.wsLoc < 0 || c.wsRem < 0) noScale++;
                else if (c.bytesIn >= 1024 * 1024 && c.maxWinLoc > 0 && c.maxWinLoc <= 65535) {
                    smallWin++;
                    if (c.maxWinLoc > smallWinMax) smallWinMax = c.maxWinLoc;
                }
            }
            long long rtt = (sumRttCnt > 0) ? sumRttSum / sumRttCnt : -1;
            auto capStr = [&](long long win) {
                if (rtt <= 0) return std::string();
                char o[96];
                snprintf(o, sizeof(o), " (потолок ≈ %.1f Мбит/с при RTT %lld мс)",
                         win * 8.0 / (rtt / 1e6) / 1e6, rtt / 1000);
                return std::string(o);
            };
            if (noScale > 0) {
                char b[512];
                snprintf(b, sizeof(b),
                    "%lld крупных соединений без масштабирования окна (window scale "
                    "не прислала одна из сторон или его вырезал middlebox): окно ≤ 64 КБ",
                    noScale);
                say(C::YEL, std::string(b) + capStr(65535) +
                    ". Скорость ограничена окном, а не каналом.");
            }
            if (smallWin > 0) {
                char b[512];
                snprintf(b, sizeof(b),
                    "%lld загрузок, где окно приёма абонента не выросло выше %lld КБ",
                    smallWin, smallWinMax / 1024);
                say(C::YEL, std::string(b) + capStr(smallWinMax) +
                    " — тормозит приёмник (в Windows проверьте "
                    "netsh int tcp show global: autotuninglevel).");
            }
        }

        // MTU / MSS по макс. сегменту — запасной вариант, когда SYN с опциями
        // в дампе нет (текстовый tcpdump или захват начат посреди сессий)
        long long globalMaxSeg = 0;
        for (auto& kv : conns) if (kv.second.maxPayload > globalMaxSeg) globalMaxSeg = kv.second.maxPayload;
        if (globalMaxSeg > 0 && !mssKnown) {
            char b[512];
            if (globalMaxSeg < 1300) {
                snprintf(b, sizeof(b),
                    "Макс. TCP-сегмент %lld байт — заметно ниже 1460. "
                    "Сильно укороченный MTU: PPPoE с потерей, двойная инкапсуляция, "
                    "VPN/GRE-туннель — типовая причина обрыва медиа и QUIC.",
                    globalMaxSeg);
                say(C::RED, b);
            } else if (globalMaxSeg < 1400) {
                snprintf(b, sizeof(b),
                    "Макс. TCP-сегмент %lld байт — ниже стандартных 1460. "
                    "Возможна проблема MTU/MSS на пути (PPPoE/VPN-оверлей).",
                    globalMaxSeg);
                say(C::YEL, b);
            } else if (globalMaxSeg < 1460) {
                snprintf(b, sizeof(b),
                    "Макс. TCP-сегмент %lld байт — чуть ниже 1460, лёгкая инкапсуляция, не критично.",
                    globalMaxSeg);
                say(C::WHT, b);
            } else {
                snprintf(b, sizeof(b),
                    "Макс. TCP-сегмент %lld байт — полный Ethernet MSS, MTU в норме.", globalMaxSeg);
                say(C::GRN, b);
            }
        }

        if (!anyFinding)
            printf("  %sПо собранным признакам проблем не выявлено.%s\n", C::GRN, C::RST);

        // ---- ДЕТЕКТ RST-ИНЪЕКЦИИ / DPI (доказательство блокировки) ----
        std::vector<std::string> dpiFindings = detectDpiInjection(ttScope);
        if (!dpiFindings.empty()) {
            printf("\n%s=== Признаки DPI-блокировки (RST-инъекция / дроп) ===%s\n", C::BOLD, C::RST);
            for (auto& f : dpiFindings) printf("  %s!%s %s\n", C::RED, C::RST, f.c_str());
        }

        // ---- ИТОГОВЫЙ ВЫВОД о состоянии соединений ----
        printf("\n=================== ВЫВОД ===================\n");
        {
            long long avgRtt = (sumRttCnt > 0) ? sumRttSum / sumRttCnt : -1;
            bool dpiDetected = !dpiFindings.empty();

            // все IP с признаками блокировки на ТСПУ (TCP-DPI/SYN-блок + UDP-WG)
            std::set<std::string> tspuIps = targetIp.empty()
                ? tspuBlocked : collectTspuBlockedIps(dpiScope, localIp, &ttScope, ipCache);
            bool tspuBlock = !tspuIps.empty();
            // домены, заблокированные по SNI (в т.ч. на общих адресах CDN)
            const auto blockedSnis = targetIp.empty()
                ? blockedSnisAll : collectBlockedSnis(dpiScope, localIp, &ttScope);

            // доля ретрансмиссий от data-пакетов (процент важнее абсолюта:
            // 300 ретр. на мегабайтах — норма, а 30 на 100 пакетах — проблема)
            double retrPct = (dataPkts > 0) ? (100.0 * sumRetr / dataPkts) : 0.0;

            // hardBlock — действительно серьёзные признаки: SYN без ответа,
            // МНОГО ранних RST (одиночный RST = норм. закрытие/закрытый порт),
            // прямой DPI или упорные повторы SYN. Одиночный RST больше не триггер.
            bool hardBlock = (synNoReplyExt > 0 || sumRstEarly >= 4 || dpiDetected || totalSynRetr >= 5);
            // тяжёлые потери — высокая ДОЛЯ при умеренном объёме. На очень
            // крупных передачах (>=500 data-пакетов) высокий % обычно offload-
            // артефакт, а не потери, поэтому туда heavyLoss не распространяем.
            bool heavyLoss = (dataPkts >= 100 && dataPkts < 500 && retrPct >= 10.0);
            bool slowRoute = (avgRtt >= 500000);
            // одиночный повтор SYN — потеря одного пакета, не «потери» (порог 3)
            bool someLoss  = (retrPct >= 3.0 || sumDup >= 20 || sumZw >= 10 || totalSynRetr >= 3);
            bool elevated  = (avgRtt >= 300000 && avgRtt < 500000);
            const auto udpOther = udpOtherOf(tspuIps);
            const bool anyBlock = tspuBlock || !blockedSnis.empty() || dpiDetected;

            if (tspuBlock) {
                // список ВСЕХ адресов для вывода (с переносом строк для читаемости)
                std::string lst; int col=0;
                for (const auto& ip : tspuIps) {
                    if (!lst.empty()) lst+=", ";
                    if (col >= 6) { lst+="\n     "; col=0; }   // перенос каждые 6 адресов
                    lst+=ip; col++;
                }
                printf("%sВОЗМОЖНО БЛОКИРОВКА НА ТСПУ (%d адр.): %s\n"
                       "Признаки: рукопожатие не проходит (SYN без ответа/повторы), "
                       "RST-инъекция,\nмолчаливый дроп по SNI или дроп обратного трафика WireGuard.\n"
                       "Похоже на блокировку узлом фильтрации оператора (ТСПУ),\n"
                       "но по дампу нельзя на 100%% отличить от недоступности самих\n"
                       "серверов. Подозрительные адреса помечены TSPU? в таблице выше.%s\n",
                       C::RED, (int)tspuIps.size(), lst.c_str(), C::RST);
                printBlockedSniList(blockedSnis);
            } else if (!blockedSnis.empty()) {
                // адреса общие (CDN): на них работают другие сайты, режется имя
                printf("%sЗАБЛОКИРОВАНЫ ОТДЕЛЬНЫЕ ДОМЕНЫ по SNI (имя сайта в TLS ClientHello).\n"
                       "Адреса у них общие (CDN/хостинг): другие сайты на тех же IP\n"
                       "работают — значит, режется конкретное имя, а не адрес. Похоже\n"
                       "на блокировку по реестру на узле фильтрации (ТСПУ). В таблице\n"
                       "такие адреса помечены SNI-BLOCK.%s\n", C::RED, C::RST);
                printBlockedSniList(blockedSnis);
            } else if (dpiDetected) {
                printf("%sОбнаружены прямые признаки DPI-блокировки (RST-инъекция или\n"
                       "молчаливый дроп после ClientHello) — см. раздел выше. Это\n"
                       "указывает на блокировку оператором, а не на проблему сервера.%s\n",
                       C::RED, C::RST);
            } else if (!frz16.empty()) {
                // повторы в зависшие соединения — не «потери канала»
                printFreeze(false);
            } else if (hardBlock && heavyLoss) {
                printf("%sСоединение работает плохо: часть подключений не\n"
                       "устанавливается, плюс большие потери пакетов. Похоже на\n"
                       "блокировку/фильтрацию или серьёзную проблему канала.%s\n",
                       C::RED, C::RST);
            } else if (hardBlock) {
                printf("%sЕсть неустановленные соединения (SYN без ответа) или ранние\n"
                       "сбросы. Часть ресурсов недоступна — возможна блокировка,\n"
                       "закрытый порт или недоступный сервер.%s\n", C::RED, C::RST);
            } else if (heavyLoss || slowRoute) {
                printf("%sСоединения устанавливаются, но качество плохое: %s%s. Это\n"
                       "указывает на проблему канала/маршрута, а не на блокировку.%s\n",
                       C::YEL,
                       heavyLoss ? "много потерь пакетов" : "",
                       slowRoute ? (heavyLoss ? " и высокий RTT" : "очень высокий RTT (медленный ответ)") : "",
                       C::RST);
            } else if (!udpOther.empty()) {
                // TCP в порядке (или умеренные потери), но UDP без ответа — не «норма»
                printUdpOther(udpOther, false);
                if (someLoss || elevated)
                    printf("%sTCP-соединения в целом рабочие, есть умеренные потери или "
                           "повышенный RTT.%s\n", C::YEL, C::RST);
            } else if (someLoss || elevated) {
                printf("%sСоединения в целом рабочие, есть умеренные потери или\n"
                       "повышенный RTT. Возможны кратковременные подтормаживания,\n"
                       "но явной блокировки не видно.%s\n", C::YEL, C::RST);
            } else {
                printf("%sСоединения в норме: подключения устанавливаются, потерь\n"
                       "мало, время ответа приемлемое. Явных проблем с сетью нет.%s\n",
                       C::GRN, C::RST);
            }
            // вторичные находки, если ВЫВОД выбрал другую ветку
            if (anyBlock && !frz16.empty()) printFreeze(true);
            const bool udpShown = !anyBlock && frz16.empty() && !(hardBlock || heavyLoss || slowRoute);
            if (!udpOther.empty() && !udpShown) printUdpOther(udpOther, true);
            // оговорка одной строкой, без отдельного блока «Важно»
            printf("(по дампу нельзя на 100%% отличить блокировку провайдером от\n"
                   " недоступности сервера — это признаки для проверки.)\n");
        }
    }
}

static void printDumpHeader(const std::vector<Packet>& packets,
                            const std::vector<std::string>& paths) {
    for (const auto& pp : paths) std::cout << "Файл: " << pp << "\n";
    std::cout << "Пакетов разобрано: " << packets.size() << "\n";
    if (!g_localIp.empty())
        std::cout << "MainIP: " << g_localIp
                  << (isPrivateIp(g_localIp) ? " (приватный)" : " (публичный)") << "\n";
    if (!g_localIp6.empty())
        std::cout << "MainIP IPv6: " << g_localIp6 << "\n";
}

// Режим 2: диагностика блокировок и проблем соединения по загруженному дампу.
// Консольный вариант: спрашивает цель у пользователя.
void runConnAnalysis(const std::vector<Packet>& packets,
                     const std::vector<std::string>& paths) {
    printDumpHeader(packets, paths);
    std::string target = askTargetIp();
    runConnAnalysisBody(packets, target);
}

// То же без консольного ввода: цель передаётся готовой (GUI). Пустая = все.
void runConnAnalysisFor(const std::vector<Packet>& packets,
                        const std::vector<std::string>& paths,
                        const std::string& target) {
    printDumpHeader(packets, paths);
    if (!target.empty()) std::cout << "Цель: " << target << "\n";
    runConnAnalysisBody(packets, target);
}

void runConnAnalysisBody(const std::vector<Packet>& packets, const std::string& target) {
    if (target.empty())
        std::cout << "Цель не указана — анализирую все TCP-соединения в дампе.\n";

    // резолвим публичные удалённые IP (ASN/org/флаги) для блока «Инфо по адресам»
    std::unordered_map<std::string, IpInfo> ipCache;
    {
        std::set<std::string> pubIps;
        for (auto& p : packets) {
            if (target.empty() || p.srcIp == target || p.dstIp == target) {
                for (const std::string& ip : { p.srcIp, p.dstIp })
                    if (!isLocalIp(ip)) pubIps.insert(ip);
            }
        }
        std::vector<std::string> ipList(pubIps.begin(), pubIps.end());
        if (!ipList.empty()) {
            std::cout << "Резолвлю " << ipList.size() << " адрес(ов) (ASN/флаги)...\n";
            resolveIps(ipList, ipCache);
            resolveHostingSecondary(ipCache, ipList);
        }
    }

    const TcpConnTable tt = buildTcpConnTable(packets, g_localIp);
    analyzeConnIssues(packets, g_localIp, target, &ipCache, &tt);
    analyzeFreeze16k(tt, &ipCache);
    printBlockReasons(collectBlockReasons(packets, tt, &ipCache, g_localIp, target));
    analyzeDpiBypass(tt);
    printRealitySuspects(collectRealitySuspects(packets, tt, &ipCache), &ipCache);
    analyzeUdpConns(packets, g_localIp, target, &ipCache);
    analyzeQuic(packets, g_localIp, target);
    analyzeJa4(packets, &ipCache, target);
    analyzeThroughput(packets, g_localIp, target);
    analyzeDnsAnomalies(packets);
    // Отдельный блок: DNS работает, а полезных соединений нет.
    // Ловит ситуацию «в роутере настроен обход блокировок, но не работает»,
    // NCSI-failure у Windows, split DNS query, DNS-retry шторм и т.п.
    analyzeConnectivityFailure(packets, g_localIp);
}

// Сводка по уже загруженному дампу. g_localIp/g_localIp6 должны указывать
// на абонента ЭТОГО дампа (runCompareMode выставляет их перед вызовом).
DumpSummary summarizeDump(const std::vector<Packet>& packets, const std::string& name,
                          const std::unordered_map<std::string, IpInfo>* ipCache) {
    DumpSummary s;
    s.name = name; s.localIp = g_localIp; s.localIp6 = g_localIp6;
    s.packets = (long long)packets.size();
    std::vector<long long> absT = absTimes(packets);
    long long t0 = -1, t1 = -1;
    for (long long t : absT)
        if (t >= 0) { if (t0 < 0 || t < t0) t0 = t; if (t > t1) t1 = t; }
    if (t0 >= 0) s.durSec = (t1 - t0) / 1e6;

    const TcpConnTable tt = buildTcpConnTable(packets, g_localIp);
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        if (!c.sni.empty()) s.snis.insert(c.sni);
        if (c.ja4Kind == JA4K_FAKE) s.ja4Fake++;
        else if (c.ja4Kind == JA4K_LIBRARY) s.ja4Lib++;
        int ref; const char* refWhat;
        if (connSilentDrop(tt, c)) s.silentDrops++;
        if (connSniRst(c)) s.sniRsts++;
        // «по TTL» — часть поддельных: разница TTL посреди сессии в одиночку
        // подделкой не считается (см. connForgedRst)
        if (connIsForgedRst(c)) {
            s.forgedRsts++;
            if (connTtlInjection(c, ref, refWhat)) s.ttlInj++;
        }
        if (!c.httpBlockMark.empty()) s.httpStubs++;
        if (c.syn == 0) continue;              // соединение началось до захвата
        s.tcpConns++;
        if (c.synack == 0 && !c.inRst && tt.anyInboundTcp && c.firstTime >= 0 &&
            tt.tEnd - c.firstTime >= cfg().tailUs) s.tcpNoAnswer++;
    }
    // «н/д» — только когда SYN были, а входящего TCP нет; без TCP вовсе «0» честный
    s.noInboundTcp = !tt.anyInboundTcp && s.tcpConns > 0;

    std::map<std::string,long long> synT;       // rip|rport|lport -> время первого SYN
    // Ретрансмиссии — по тому же правилу, что в analyzeTcp (режим 2): повтор
    // сегмента с тем же начальным seq и той же длиной, пришедший позже порога
    // max(15 мс, 2×RTT). Отличия: здесь только исходящие, и RTT — рукопожатия
    // (в режиме 2 — средний по данным, он обычно чуть больше из-за отложенного
    // ACK), так что на пограничных повторах числа могут немного разойтись.
    // «Правый край не дальше максимума» ловил и
    // переупорядочивание, и дубли TSO/GRO, которые приходят почти мгновенно.
    struct SegSeen { long long t; long long len; };
    std::map<std::string, std::map<long long, SegSeen>> outSeg;   // поток -> seq начала -> последний
    std::map<std::string, std::vector<long long>> retrGaps;       // поток -> интервалы повторов
    std::map<std::string, long long> hsRttByConn;                 // поток -> RTT рукопожатия
    std::map<std::string,long long> dnsQ;       // клиент|порт|id -> время запроса
    std::set<std::string> dnsR;
    std::set<std::string> dnsNxKeys;            // NXDOMAIN — по запросу, не по ответу:
                                                // повторные ответы на один запрос не множим
    long long tEnd = t1;
    for (size_t i = 0; i < packets.size(); i++) {
        const Packet& p = packets[i];
        long long t = absT[i];
        if (!p.dnsId.empty()) {
            if (!p.dnsIsResponse) {
                std::string k = p.srcIp + "|" + std::to_string(p.srcPort) + "|" + p.dnsId;
                if (!dnsQ.count(k)) dnsQ[k] = t;
            } else {
                std::string k = p.dstIp + "|" + std::to_string(p.dstPort) + "|" + p.dnsId;
                if (p.dnsNxdomain) dnsNxKeys.insert(k);
                dnsR.insert(std::move(k));
            }
        }
        bool sLoc = isLocalIp(p.srcIp), dLoc = isLocalIp(p.dstIp);
        if (sLoc == dLoc) continue;
        std::string rip = sLoc ? p.dstIp : p.srcIp;
        if (p.proto == "UDP") {
            if (p.wgType != 0) s.wgPeers.insert(rip);
            continue;
        }
        if (p.proto != "TCP") continue;
        int rport = sLoc ? p.dstPort : p.srcPort;
        int lport = sLoc ? p.srcPort : p.dstPort;
        std::string ck = rip + "|" + std::to_string(rport) + "|" + std::to_string(lport);
        bool S = flagHas(p.flags, 'S'), A = flagHas(p.flags, '.');
        if (sLoc) {
            if (S && !A && t >= 0 && !synT.count(ck)) synT[ck] = t;
            if (p.length > 0 && p.seq >= 0) {
                s.outDataSegs++;
                const long long rkey = p.seqStart >= 0 ? p.seqStart : p.seq;
                auto& seen = outSeg[ck];
                auto it = seen.find(rkey);
                if (it == seen.end()) seen[rkey] = {t, p.length};
                else {
                    // 1 байт — keep-alive (seq = snd.nxt-1), не повтор
                    if (p.length > 1 && t >= 0 && it->second.t >= 0 && it->second.len == p.length)
                        retrGaps[ck].push_back(t - it->second.t);
                    it->second = {t, p.length};
                }
            }
        } else if (S && A && t >= 0) {
            auto it = synT.find(ck);
            if (it != synT.end()) {
                if (t >= it->second) {
                    s.hsRtt.push_back(t - it->second);
                    hsRttByConn[ck] = t - it->second;
                }
                synT.erase(it);                 // считаем только первый SYN-ACK
            }
        }
    }
    for (const auto& kv : dnsQ) {
        if (kv.second >= 0 && tEnd >= 0 && tEnd - kv.second < cfg().tailUs) continue;
        s.dnsQueries++;
        if (!dnsR.count(kv.first)) s.dnsNoAnswer++;
    }
    s.dnsNx = (long long)dnsNxKeys.size();
    for (const auto& kv : retrGaps) {
        // порог как в analyzeTcp; RTT — по рукопожатию этого потока
        long long thr = 15000;
        auto r = hsRttByConn.find(kv.first);
        if (r != hsRttByConn.end() && r->second * 2 > thr) thr = r->second * 2;
        if (thr > 1000000) thr = 1000000;
        for (long long gap : kv.second) if (gap > thr) s.outRetrans++;
    }

    s.blockedIps  = collectTspuBlockedIps(packets, g_localIp, &tt, ipCache);
    s.blockedSnis = collectBlockedSnis(packets, g_localIp, &tt);
    s.blockReasons = collectBlockReasons(packets, tt, ipCache, g_localIp);
    // объём по адресам и вердикт VPN — те же функции, что в режиме 1
    s.bytesByIp = bytesByRemote(packets);
    const VpnVerdict vv = computeVpnVerdict(packets, tt, ipCache);
    for (const auto& r : vv.reality) s.realityIps.insert(r.ip);
    s.vpnScore = vv.score; s.vpnReasons = vv.reasons;
    s.vpnPortScore = vv.portScore; s.vpnShapeScore = vv.shapeScore;
    s.vpnFlowScore = vv.flowScore; s.vpnMssScore = vv.mssScore;
    return s;
}

void printDumpCompare(const DumpSummary& a, const DumpSummary& b,
                      const std::unordered_map<std::string, IpInfo>& ipCache) {
    auto pct = [](long long x, long long n) { return n > 0 ? 100.0 * x / n : 0.0; };
    auto median = [](std::vector<long long> v) -> long long {
        if (v.empty()) return -1;
        std::nth_element(v.begin(), v.begin() + v.size() / 2, v.end());
        return v[v.size() / 2];
    };
    auto fmtBytes = [](long long b) {
        char t[32];
        if (b >= 1048576) snprintf(t, sizeof(t), "%.1f МБ", b / 1048576.0);
        else if (b >= 1024) snprintf(t, sizeof(t), "%.1f КБ", b / 1024.0);
        else snprintf(t, sizeof(t), "%lld Б", b);
        return std::string(t);
    };
    auto who = [&](const std::string& ip) {
        auto it = ipCache.find(ip);
        if (it == ipCache.end()) return ip;
        return ip + " (" + it->second.country + ", " + it->second.org + ")";
    };
    // worse: 1 — рост значения в B плохо, -1 — хорошо, 0 — нейтрально
    auto row = [&](const char* what, const std::string& va, const std::string& vb,
                   double na, double nb, int worse) {
        const char* col = C::RST; const char* mark = "  ";
        if (worse != 0 && na != nb) {
            bool bad = (nb > na) == (worse > 0);
            col = bad ? C::RED : C::GRN;
            mark = (nb > na) ? " ▲" : " ▼";     // стрелка — направление, цвет — хорошо/плохо
        }
        printf("  %s%s  %s%s%s%s\n", u8pad(what, 34).c_str(), u8pad(va, 16).c_str(),
               col, u8pad(vb, 16).c_str(), mark, C::RST);
    };
    auto num = [](long long v) { return std::to_string(v); };
    auto pstr = [](double v) { char t[32]; snprintf(t, sizeof(t), "%.1f%%", v); return std::string(t); };

    printf("\n%s=== СРАВНЕНИЕ ДАМПОВ ===%s\n", C::BOLD, C::RST);
    printf("  %sA:%s %s  (MainIP %s%s%s)\n", C::BWHT, C::RST, a.name.c_str(), a.localIp.c_str(),
           a.localIp6.empty() ? "" : ", ", a.localIp6.c_str());
    printf("  %sB:%s %s  (MainIP %s%s%s)\n", C::BWHT, C::RST, b.name.c_str(), b.localIp.c_str(),
           b.localIp6.empty() ? "" : ", ", b.localIp6.c_str());
    if (!a.localIp.empty() && !b.localIp.empty() && a.localIp != b.localIp)
        printf("  %s[i] MainIP в дампах разные — это нормально при смене роутера/сети,\n"
               "      но убедитесь, что дампы сняты у одного и того же абонента.%s\n", C::GRY, C::RST);
    printf("\n  %s%s  %s  %s%s\n", C::GRY, u8pad("показатель", 34).c_str(),
           u8pad("A", 16).c_str(), u8pad("B", 16).c_str(), C::RST);

    char t[64];
    snprintf(t, sizeof(t), "%.0f с", a.durSec); std::string da = t;
    snprintf(t, sizeof(t), "%.0f с", b.durSec); std::string db = t;
    row("Пакетов", num(a.packets), num(b.packets), 0, 0, 0);
    row("Длительность захвата", da, db, 0, 0, 0);
    row("TCP-соединений (SYN в дампе)", num(a.tcpConns), num(b.tcpConns), 0, 0, 0);
    // в одностороннем дампе ответов не видно вовсе — «0 (0%)» было бы враньём
    double naA = pct(a.tcpNoAnswer, a.tcpConns), naB = pct(b.tcpNoAnswer, b.tcpConns);
    auto naStr = [&](const DumpSummary& d, double v) {
        return d.noInboundTcp ? std::string("н/д (нет входящих)") : num(d.tcpNoAnswer) + " (" + pstr(v) + ")";
    };
    row("  без ответа на SYN", naStr(a, naA), naStr(b, naB), naA, naB,
        (a.noInboundTcp || b.noInboundTcp) ? 0 : 1);
    double rtA = pct(a.outRetrans, a.outDataSegs), rtB = pct(b.outRetrans, b.outDataSegs);
    row("Ретрансмиссии исходящих", pstr(rtA), pstr(rtB), rtA, rtB, 1);
    long long mA = median(a.hsRtt), mB = median(b.hsRtt);
    auto ms = [](long long us) {
        if (us < 0) return std::string("-");
        char x[32]; snprintf(x, sizeof(x), "%.1f мс", us / 1000.0); return std::string(x);
    };
    row("RTT рукопожатия (медиана)", ms(mA), ms(mB), (double)mA, (double)mB,
        (mA >= 0 && mB >= 0) ? 1 : 0);
    row("Молчаливые дропы после ClientHello", num(a.silentDrops), num(b.silentDrops),
        (double)a.silentDrops, (double)b.silentDrops, 1);
    row("RST до ответа сервера (по SNI)", num(a.sniRsts), num(b.sniRsts),
        (double)a.sniRsts, (double)b.sniRsts, 1);
    row("RST-инъекции по TTL", num(a.ttlInj), num(b.ttlInj), (double)a.ttlInj, (double)b.ttlInj, 1);
    row("Поддельные RST (все признаки)", num(a.forgedRsts), num(b.forgedRsts),
        (double)a.forgedRsts, (double)b.forgedRsts, 1);
    row("HTTP-заглушки о блокировке", num(a.httpStubs), num(b.httpStubs),
        (double)a.httpStubs, (double)b.httpStubs, 1);
    row("IP с признаками блокировки", num((long long)a.blockedIps.size()),
        num((long long)b.blockedIps.size()),
        (double)a.blockedIps.size(), (double)b.blockedIps.size(), 1);
    row("Домены, заблокированные по SNI", num((long long)a.blockedSnis.size()),
        num((long long)b.blockedSnis.size()),
        (double)a.blockedSnis.size(), (double)b.blockedSnis.size(), 1);
    row("DNS-запросов", num(a.dnsQueries), num(b.dnsQueries), 0, 0, 0);
    double dA = pct(a.dnsNoAnswer, a.dnsQueries), dB = pct(b.dnsNoAnswer, b.dnsQueries);
    row("  без ответа", num(a.dnsNoAnswer) + " (" + pstr(dA) + ")",
        num(b.dnsNoAnswer) + " (" + pstr(dB) + ")", dA, dB, 1);
    row("  NXDomain", num(a.dnsNx), num(b.dnsNx), 0, 0, 0);
    row("Удалённых адресов", num((long long)a.bytesByIp.size()),
        num((long long)b.bytesByIp.size()), 0, 0, 0);
    row("Разных SNI", num((long long)a.snis.size()), num((long long)b.snis.size()), 0, 0, 0);
    // строки «фейк под браузер» нет: JA4K_FAKE не присваивается (uTLS с GREASE
    // от браузера по ClientHello не отличить), и там всегда был бы честный с виду «0»
    row("ClientHello библиотек", num(a.ja4Lib), num(b.ja4Lib), 0, 0, 0);
    row("WireGuard-пиров", num((long long)a.wgPeers.size()), num((long long)b.wgPeers.size()), 0, 0, 0);
    row("Похоже на VLESS/Reality (IP)", num((long long)a.realityIps.size()),
        num((long long)b.realityIps.size()), 0, 0, 0);
    row("Признаки VPN (баллы, как в режиме 1)", num(a.vpnScore), num(b.vpnScore), 0, 0, 0);
    if (mA >= 0 && mB >= 0 && (a.hsRtt.size() < 5 || b.hsRtt.size() < 5))
        printf("  %s(RTT по %zu / %zu рукопожатиям — мало для уверенных выводов)%s\n",
               C::GRY, a.hsRtt.size(), b.hsRtt.size(), C::RST);

    // --- что появилось / пропало ---
    auto diffSet = [&](const char* title, const std::set<std::string>& from,
                       const std::set<std::string>& to, bool asIp, const char* col) {
        std::vector<std::string> v;
        for (const auto& x : to) if (!from.count(x)) v.push_back(x);
        if (v.empty()) return;
        printf("\n  %s%s (%zu):%s\n", col, title, v.size(), C::RST);
        size_t shown = 0;
        for (const auto& x : v) {
            if (++shown > 15) { printf("    ... и ещё %zu\n", v.size() - 15); break; }
            printf("    %s\n", (asIp ? who(x) : x).c_str());
        }
    };
    std::set<std::string> bsA, bsB;
    for (const auto& kv : a.blockedSnis) bsA.insert(kv.first);
    for (const auto& kv : b.blockedSnis) bsB.insert(kv.first);
    diffSet("Новые блокировки по SNI в B", bsA, bsB, false, C::RED);
    diffSet("Блокировки по SNI из A, которых нет в B", bsB, bsA, false, C::GRN);
    diffSet("Новые IP с признаками блокировки в B", a.blockedIps, b.blockedIps, true, C::RED);
    diffSet("IP с признаками блокировки из A, которых нет в B", b.blockedIps, a.blockedIps, true, C::GRN);
    diffSet("Новые адреса, похожие на VLESS/Reality, в B", a.realityIps, b.realityIps, true, C::YEL);
    diffSet("Новые WireGuard-пиры в B", a.wgPeers, b.wgPeers, true, C::YEL);

    // крупные собеседники (≥100 КБ), которых в другом дампе не было вовсе
    auto bigNew = [&](const char* title, const DumpSummary& from, const DumpSummary& to) {
        std::vector<std::pair<long long,std::string>> v;
        for (const auto& kv : to.bytesByIp)
            if (kv.second >= 100 * 1024 && !from.bytesByIp.count(kv.first))
                v.push_back(std::make_pair(kv.second, kv.first));
        if (v.empty()) return;
        std::sort(v.rbegin(), v.rend());
        printf("\n  %s%s:%s\n", C::BWHT, title, C::RST);
        for (size_t i = 0; i < v.size() && i < 10; i++)
            printf("    %s %s\n", u8pad(fmtBytes(v[i].first), 10).c_str(), who(v[i].second).c_str());
        if (v.size() > 10) printf("    ... и ещё %zu\n", v.size() - 10);
    };
    bigNew("Крупные адреса только в B (≥100 КБ)", a, b);
    bigNew("Крупные адреса только в A (≥100 КБ)", b, a);

    std::vector<std::string> newSni;
    for (const auto& x : b.snis) if (!a.snis.count(x)) newSni.push_back(x);
    if (!newSni.empty()) {
        printf("\n  %sSNI, которых не было в A (%zu):%s ", C::GRY, newSni.size(), C::RST);
        for (size_t i = 0; i < newSni.size() && i < 20; i++)
            printf("%s%s", i ? ", " : "", newSni[i].c_str());
        if (newSni.size() > 20) printf(", ...");
        printf("\n");
    }

    // --- итог ---
    printf("\n%s--- Итог сравнения ---%s\n", C::BOLD, C::RST);
    int lines = 0;
    size_t newBlocks = 0;
    for (const auto& x : bsB) if (!bsA.count(x)) newBlocks++;
    for (const auto& x : b.blockedIps) if (!a.blockedIps.count(x)) newBlocks++;
    if (newBlocks > 0) {
        printf("  %s• В B появились признаки блокировок (%zu шт., списки выше).%s\n",
               C::RED, newBlocks, C::RST); lines++;
    }
    if (rtB >= 3.0 && rtB > rtA * 2) {
        printf("  %s• Ретрансмиссий в B заметно больше (%.1f%% против %.1f%%) — потери на линии\n"
               "    или перегрузка; проверьте Wi-Fi/кабель и загрузку канала.%s\n",
               C::YEL, rtB, rtA, C::RST); lines++;
    }
    if (mA > 0 && mB > 0 && mB > mA * 2 && mB - mA > 20000) {
        printf("  %s• Задержка рукопожатия в B выросла: %s против %s.%s\n",
               C::YEL, ms(mB).c_str(), ms(mA).c_str(), C::RST); lines++;
    }
    if (dB >= 10.0 && dB > dA * 2) {
        printf("  %s• В B чаще нет ответа на DNS (%.1f%% против %.1f%%) — проверьте DNS-сервер\n"
               "    в настройках роутера/ПК.%s\n", C::YEL, dB, dA, C::RST); lines++;
    }
    // односторонний дамп: «без ответа» там не посчитан (0) — сравнение было бы ложным
    if (naB >= 10.0 && naB > naA * 2 && !a.noInboundTcp && !b.noInboundTcp) {
        printf("  %s• В B больше TCP-соединений без ответа (%.1f%% против %.1f%%).%s\n",
               C::YEL, naB, naA, C::RST); lines++;
    }
    if (b.vpnScore > a.vpnScore || b.wgPeers.size() > a.wgPeers.size() ||
        b.realityIps.size() > a.realityIps.size()) {
        printf("  %s• В B больше признаков VPN/прокси, чем в A (баллы %d против %d);\n"
               "    причины по пунктам — режим [1] на дампе B.%s\n",
               C::YEL, b.vpnScore, a.vpnScore, C::RST); lines++;
    }
    if (lines == 0)
        printf("  %sСущественной разницы по ключевым показателям не видно.%s\n", C::GRN, C::RST);
    printf("  %sДамп A считается «эталоном» (было), B — «проверяемым» (стало).%s\n", C::GRY, C::RST);
}
