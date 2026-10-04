// detector_dpi.cpp — детекторы блокировок и DPI: DNS-аномалии, поддельные и
// ранние RST, молчаливые дропы после ClientHello, блоки ТСПУ по IP/SNI, UDP и
// QUIC без ответа, недоступность интернета, «заморозка» на ~16 КБ, сводные
// причины блокировок, обходчики DPI у абонента.
#include "analyzer_internal.h"

// Анализ DNS-аномалий по дампу (текстовый tcpdump или pcap/pcapng — DNS
// разбирается в обоих). Детектит два класса по tspu-docs/практике ТСПУ:
//  1) запрос есть, ОТВЕТА НЕТ (полная тишина) — возможна DNS-фильтрация. NXDomain
//     и пустые ответы НЕ считаем блокировкой (сервер ответил, просто отрицательно).
//  2) DNS-ПОДМЕНА — домен резолвится в приватный/заглушечный IP (DPI вернул фейк).
void analyzeDnsAnomalies(const std::vector<Packet>& packets) {
    // --- детект ШИФРОВАННОГО DNS (DoT/DoH) ---
    // DoT = порт 853 (DNS over TLS). DoH = порт 443 к известным DNS-провайдерам
    // (домен запроса зашифрован, в дампе не виден — поэтому обычных DNS-записей
    // мало/нет). Определяем сам факт DoT/DoH и работает ли он (есть ли обмен).
    auto isKnownDohIp = [](const std::string& ip)->const char* {
        if (ip=="8.8.8.8"||ip=="8.8.4.4"||ip=="2001:4860:4860::8888"||ip=="2001:4860:4860::8844")
            return "Google DNS";
        if (ip.rfind("1.1.1.",0)==0||ip.rfind("1.0.0.",0)==0||ip.rfind("2606:4700:4700::",0)==0)
            return "Cloudflare DNS";
        if (ip=="9.9.9.9"||ip=="149.112.112.112"||ip=="2620:fe::fe"||ip=="2620:fe::9") return "Quad9";
        if (ip.rfind("94.140.14.",0)==0||ip.rfind("94.140.15.",0)==0) return "AdGuard DNS";
        if (ip.rfind("77.88.8.",0)==0) return "Yandex DNS";
        if (ip=="208.67.222.222"||ip=="208.67.220.220") return "OpenDNS";
        return nullptr;
    };
    // Имена DoH-серверов. Список IP выше устаревает и не знает свои/частные
    // DoH, поэтому DoH узнаём ещё и по имени: SNI в ClientHello или обычный
    // DNS-запрос этого имени (браузер резолвит DoH-сервер открыто) — адреса
    // из ответа тоже считаем DoH.
    auto dohNameProv = [](const std::string& host)->const char* {
        std::string h = host;
        for (auto& c : h) c = (char)::tolower((unsigned char)c);
        struct N { const char* suffix; const char* prov; };
        // только имена самих DNS-серверов: сайт провайдера (www.quad9.net,
        // my.nextdns.io) — обычный HTTPS, не DoH
        static const N kNames[] = {
            {"dns.google", "Google DNS"}, {"cloudflare-dns.com", "Cloudflare DNS"},
            {"dns.quad9.net", "Quad9"}, {"dns9.quad9.net", "Quad9"}, {"dns10.quad9.net", "Quad9"},
            {"dns11.quad9.net", "Quad9"}, {"dns12.quad9.net", "Quad9"},
            {"adguard-dns.com", "AdGuard DNS"}, {"dns.adguard.com", "AdGuard DNS"},
            {"dns.yandex.net", "Yandex DNS"}, {"dns.nextdns.io", "NextDNS"}, {"doh.opendns.com", "OpenDNS"},
            {"doh.dns.sb", "DNS.SB"}, {"dns.alidns.com", "AliDNS"}, {"doh.pub", "DNSPod"},
            {"dns.mullvad.net", "Mullvad DNS"}, {"dns.controld.com", "Control D"},
            {"freedns.controld.com", "Control D"},
        };
        for (const N& n : kNames)   // само имя или его поддомен, не просто подстрока
            if (domainEndsWith(h, n.suffix)) return n.prov;
        // doh.* своих и частных серверов — без названия провайдера
        if (h.rfind("doh.", 0) == 0) return "DoH-сервер";
        return nullptr;
    };
    auto isLocal2 = [&](const std::string& ip){ return isLocalIp(ip); };
    std::map<std::string, const char*> dohIpByName;   // адрес -> провайдер (по SNI / DNS)
    // В текстовом tcpdump у ответа нет имени из вопроса — берём его из запроса
    // с тем же ключом (клиент|порт|id); в pcap оно есть в самом ответе.
    std::map<std::string, std::string> dnsNameByKey;
    for (const auto& p : packets) {
        if (!p.dnsId.empty() && !p.dnsIsResponse && !p.dnsQuery.empty())
            dnsNameByKey[p.srcIp + "|" + std::to_string(p.srcPort) + "|" + p.dnsId] = p.dnsQuery;
        if (!p.sni.empty() && (p.dstPort == 443 || p.srcPort == 443)) {
            if (const char* prov = dohNameProv(p.sni)) {
                const bool sLoc = isLocal2(p.srcIp), dLoc = isLocal2(p.dstIp);
                if (sLoc != dLoc) dohIpByName[sLoc ? p.dstIp : p.srcIp] = prov;
            }
        }
        if (p.dnsIsResponse && !p.dnsAnswers.empty()) {
            std::string qname = p.dnsQuery;
            if (qname.empty() && !p.dnsId.empty()) {
                auto q = dnsNameByKey.find(p.dstIp + "|" + std::to_string(p.dstPort) + "|" + p.dnsId);
                if (q != dnsNameByKey.end()) qname = q->second;
            }
            if (const char* prov = qname.empty() ? nullptr : dohNameProv(qname))
                for (const auto& a : p.dnsAnswers) if (!isPrivateIp(a)) dohIpByName.emplace(a, prov);
        }
    }
    struct Enc { long long out=0, in=0; const char* prov=nullptr; bool dot=false; };
    std::map<std::string, Enc> enc;   // ip -> статистика шифр. DNS
    for (const auto& p : packets) {
        bool sLoc = isLocal2(p.srcIp), dLoc = isLocal2(p.dstIp);
        if (sLoc == dLoc) continue;
        std::string rip = sLoc ? p.dstIp : p.srcIp;
        int rport = sLoc ? p.dstPort : p.srcPort;
        bool isDot = (rport == 853);
        const char* prov = isKnownDohIp(rip);
        if (!prov) {
            auto it = dohIpByName.find(rip);
            if (it != dohIpByName.end()) prov = it->second;
        }
        bool isDoh = (rport == 443 && prov != nullptr);
        if (!isDot && !isDoh) continue;
        Enc& e = enc[rip];
        // накапливаем: один адрес бывает и DoT (853), и DoH (443) — не затирать
        if (prov) e.prov = prov;
        e.dot = e.dot || isDot;
        if (sLoc) e.out += (p.length>0?p.length:1); else e.in += (p.length>0?p.length:1);
    }
    if (!enc.empty()) {
        printf("\n%s=== ШИФРОВАННЫЙ DNS (DoT/DoH) ===%s\n", C::BOLD, C::RST);
        for (auto& kv : enc) {
            const Enc& e = kv.second;
            const char* kind = e.dot ? "DoT(853)" : "DoH(443)";
            bool works = (e.in > 0);   // есть ответный трафик
            printf("  %s%-15s%s %s%s%s  %s — %s\n",
                   C::BWHT, kv.first.c_str(), C::RST,
                   C::CYN, e.prov ? e.prov : "DNS-сервер", C::RST, kind,
                   works ? "обмен есть (работает)"
                         : "ответа нет — возможно шифр. DNS режется ТСПУ");
        }
        printf("  %sПрим.: при DoT/DoH сами домены зашифрованы и в дампе не видны —\n"
               "  поэтому обычных DNS-запросов мало. Если шифр. DNS заблокирован,\n"
               "  у абонента ломается резолвинг (сайты не открываются по имени).%s\n",
               C::GRY, C::RST);
    }

    // Запрос и ответ сопоставляем по (IP клиента, порт клиента, id): один id
    // (16 бит) у разных программ/портов совпадает часто, и сопоставление по
    // одному id склеивало чужие ответы. Повтор того же ключа после ответа —
    // уже новый запрос (id переиспользуется).
    struct Ans { long long t = -1; std::vector<std::string> ips; bool nx = false; };
    struct Q { std::string domain; long long tq = -1; int sent = 1; std::vector<Ans> answers; };
    std::vector<Q> qs;
    std::map<std::string, size_t> open;      // ключ -> индекс в qs
    std::vector<long long> absT = absTimes(packets);
    long long tEnd = -1;
    for (long long t : absT) if (t > tEnd) tEnd = t;
    for (size_t i = 0; i < packets.size(); i++) {
        const Packet& p = packets[i];
        if (p.dnsId.empty()) continue;
        if (!p.dnsIsResponse && !p.dnsQuery.empty()) {
            std::string key = p.srcIp + "|" + std::to_string(p.srcPort) + "|" + p.dnsId;
            auto it = open.find(key);
            if (it != open.end() && qs[it->second].answers.empty() &&
                qs[it->second].domain == p.dnsQuery) {
                qs[it->second].sent++;           // ретрансмит того же запроса
                continue;
            }
            Q q; q.domain = p.dnsQuery; q.tq = absT[i];
            qs.push_back(q);
            open[key] = qs.size() - 1;
        } else if (p.dnsIsResponse) {
            std::string key = p.dstIp + "|" + std::to_string(p.dstPort) + "|" + p.dnsId;
            auto it = open.find(key);
            if (it == open.end()) continue;
            Ans a; a.t = absT[i]; a.nx = p.dnsNxdomain; a.ips = p.dnsAnswers;
            if (a.ips.empty() && !p.dnsAnswerIp.empty()) a.ips.push_back(p.dnsAnswerIp);
            std::sort(a.ips.begin(), a.ips.end());
            qs[it->second].answers.push_back(a);
        }
    }
    if (qs.empty()) return;

    // «регистрируемая» часть домена (грубо: 2 последние метки, 3 — для co.uk/com.ru)
    auto sld = [](const std::string& d) {
        std::string s = d; while (!s.empty() && s.back() == '.') s.pop_back();
        size_t p1 = s.rfind('.');
        if (p1 == std::string::npos || p1 == 0) return s;
        size_t p2 = s.rfind('.', p1 - 1);
        if (p2 == std::string::npos) return s;
        std::string mid = s.substr(p2 + 1, p1 - p2 - 1);
        if (mid.size() <= 3 && (mid == "co" || mid == "com" || mid == "net" || mid == "org")) {
            size_t p3 = s.rfind('.', p2 - 1);
            return p3 == std::string::npos || p2 == 0 ? s : s.substr(p3 + 1);
        }
        return s.substr(p2 + 1);
    };

    // Локальные/служебные имена законно резолвятся в приватные адреса: роутер
    // (router.lan, fritz.box), mDNS (.local), домашние/корпоративные зоны,
    // Tailscale MagicDNS (*.ts.net -> 100.x), Plex (*.plex.direct -> LAN-IP),
    // имя без точки (поиск по суффиксу домена). Это не подмена.
    auto localName = [](std::string d) {
        while (!d.empty() && d.back() == '.') d.pop_back();
        for (auto& ch : d) ch = (char)tolower((unsigned char)ch);
        if (d.empty() || d.find('.') == std::string::npos) return true;
        static const char* sfx[] = {
            "local", "lan", "home", "home.arpa", "internal", "intranet", "corp",
            "localdomain", "localhost", "router", "box", "test", "invalid",
            "in-addr.arpa", "ip6.arpa", "ts.net", "plex.direct", "nip.io", "sslip.io",
        };
        for (const char* s : sfx) if (domainEndsWith(d, s)) return true;
        return false;
    };
    // 0.0.0.0 / 127.x / :: / ::1 — так отвечают блок-листы DNS (AdGuard, Pi-hole,
    // NextDNS, родительский контроль, антивирус): рекламу и трекеры «в ноль»
    auto nullAddr = [](const std::string& ip) {
        return ip == "0.0.0.0" || ip.rfind("127.", 0) == 0 || ip == "::" || ip == "::1";
    };
    std::vector<std::string> noAnswer, spoofed, doubleAns;
    int nullAnswers = 0;                                      // из spoofed — «нулевых»
    std::map<std::string, std::set<std::string>> ipDomains;   // публичный IP -> домены (SLD)
    std::map<std::string, std::set<std::string>> ipFull;      // публичный IP -> полные имена
    int tailSkipped = 0;
    for (const auto& q : qs) {
        if (q.domain.empty()) continue;
        if (q.answers.empty()) {
            // запрос в хвосте дампа (tailUs) — ответ мог просто не успеть попасть
            if (q.tq >= 0 && tEnd >= 0 && tEnd - q.tq < cfg().tailUs) { tailSkipped++; continue; }
            noAnswer.push_back(q.domain);
            continue;
        }
        const Ans& a0 = q.answers.front();
        if (!localName(q.domain)) {
            for (const auto& ip : a0.ips) {
                if (isPrivateIp(ip)) {               // включая 127/8 и 0.0.0.0
                    spoofed.push_back(q.domain + " -> " + ip);
                    if (nullAddr(ip)) nullAnswers++;
                    break;
                }
            }
        }
        for (const auto& ip : a0.ips)
            if (!isPrivateIp(ip)) { ipDomains[ip].insert(sld(q.domain)); ipFull[ip].insert(q.domain); }
        // ДВА РАЗНЫХ ответа на один запрос — классика DNS-инъекции: ТСПУ/DPI
        // отвечает раньше настоящего сервера, второй (настоящий) ответ приходит следом.
        // Если запрос отправлялся повторно, сервер честно ответит на каждую копию,
        // а у CDN с большим пулом адреса в ответах разные. Поэтому разные адреса
        // считаем признаком, только когда ответов больше, чем отправленных копий.
        if (q.answers.size() >= 2) {
            const Ans& a1 = q.answers[1];
            const bool extra = q.answers.size() > (size_t)q.sent;
            if (a0.nx != a1.nx || (extra && a0.ips != a1.ips)) {
                char b[512];
                long long d0 = (q.tq >= 0 && a0.t >= 0) ? (a0.t - q.tq) / 1000 : -1;
                long long d1 = (q.tq >= 0 && a1.t >= 0) ? (a1.t - q.tq) / 1000 : -1;
                bool fastFirst = d0 >= 0 && d1 >= 0 && d0 * 2 < d1;
                snprintf(b, sizeof(b), "%s: 1-й ответ %s через %lld мс, 2-й %s через %lld мс%s",
                         q.domain.c_str(),
                         a0.nx ? "NXDomain" : (a0.ips.empty() ? "пустой" : a0.ips.front().c_str()), d0,
                         a1.nx ? "NXDomain" : (a1.ips.empty() ? "пустой" : a1.ips.front().c_str()), d1,
                         fastFirst ? " — первый подозрительно быстрый (ответ «ближе» сервера)" : "");
                doubleAns.push_back(b);
            }
        }
    }
    // заглушка на ПУБЛИЧНОМ IP: разные несвязанные домены резолвятся в один
    // адрес, и среди них — заведомо ограниченные в РФ. Без ограниченных порог
    // выше: общий адрес бывает и у CDN/хостинга с виртуальными хостами.
    std::vector<std::string> stubs;
    for (const auto& kv : ipDomains) {
        bool anyBlocked = false;
        for (const auto& d : ipFull[kv.first]) if (isCommonlyBlockedDomain(d)) { anyBlocked = true; break; }
        bool strong = anyBlocked && kv.second.size() >= 2;
        bool weak = kv.second.size() >= 5;
        if (!strong && !weak) continue;
        std::string s = kv.first + " <- ";
        int n = 0;
        for (const auto& d : kv.second) { if (n++ >= 5) { s += ", …"; break; } s += (n > 1 ? ", " : "") + d; }
        s += strong ? "  (среди них ограниченные в РФ — похоже на заглушку)"
                    : "  (возможно заглушка, либо общий адрес CDN/хостинга)";
        stubs.push_back(s);
    }
    if (noAnswer.empty() && spoofed.empty() && doubleAns.empty() && stubs.empty()) return;

    printf("\n%s=== DNS-АНОМАЛИИ ===%s\n", C::BOLD, C::RST);
    // имя для фильтра Wireshark: без завершающей точки (текстовый tcpdump её пишет)
    auto qn = [](std::string s) { if (!s.empty() && s.back() == '.') s.pop_back(); return s; };
    if (!doubleAns.empty()) {
        printf("%sДва разных ответа на один DNS-запрос (признак DNS-инъекции):%s\n", C::RED, C::RST);
        int n = 0;
        for (const auto& s : doubleAns) {
            if (n++ >= 10) { printf("  ... ещё %d\n", (int)doubleAns.size() - 10); break; }
            printf("  %s%s%s\n", C::BWHT, s.c_str(), C::RST);
        }
        printf("  %sНастоящий сервер отвечает один раз. Первый, более быстрый ответ обычно\n"
               "  подставлен по пути (ТСПУ/DPI), второй — настоящий.%s\n", C::GRY, C::RST);
    }
    if (!stubs.empty()) {
        printf("%sМного доменов резолвятся в один публичный IP:%s\n", C::YEL, C::RST);
        for (const auto& s : stubs) printf("  %s%s%s\n", C::BWHT, s.c_str(), C::RST);
    }
    if (!spoofed.empty()) {
        printf("%sПубличные имена резолвятся в приватный/нулевой адрес:%s\n", C::YEL, C::RST);
        int n = 0;
        for (const auto& s : spoofed) {
            if (n++ >= 15) { printf("  ... ещё %d\n", (int)spoofed.size() - 15); break; }
            printf("  %s%s%s  %s[dns.qry.name==\"%s\"]%s\n", C::BWHT, s.c_str(), C::RST,
                   C::GRY, qn(s.substr(0, s.find(" -> "))).c_str(), C::RST);
        }
        // Оператор/ТСПУ подменяет DNS обычно на ПУБЛИЧНУЮ заглушку (см. «много
        // доменов в один IP» выше), а 0.0.0.0/127.x почти всегда — фильтр DNS
        // на стороне абонента. Поэтому здесь не «подмена», а варианты.
        if (nullAnswers > 0)
            printf("  %s0.0.0.0 / 127.x / :: — так отвечает блок-лист DNS (AdGuard, Pi-hole,\n"
                   "  NextDNS, родительский контроль, антивирус) на рекламу и трекеры. Если\n"
                   "  в списке нужный сайт — проверить DNS в роутере/ПК; подмена по пути\n"
                   "  тоже возможна, но реже.%s\n", C::GRY, C::RST);
        if (nullAnswers < (int)spoofed.size())
            printf("  %sАдрес из локальной сети для публичного имени — внутренний DNS\n"
                   "  (корпоративная сеть, split-horizon, роутер с локальной записью)\n"
                   "  либо подмена DNS. Сравнить с ответом 8.8.8.8 / 1.1.1.1.%s\n", C::GRY, C::RST);
    }
    if (!noAnswer.empty()) {
        printf("%sЗапросы DNS без ответа (ВОЗМОЖНА фильтрация домена):%s\n", C::YEL, C::RST);
        int n=0;
        for (const auto& d : noAnswer) { if (n++>=12){ printf("  ... ещё %d\n",(int)noAnswer.size()-12); break; }
            printf("  %s%s%s  %s[dns.qry.name==\"%s\"]%s\n", C::BWHT, d.c_str(), C::RST,
                   C::GRY, qn(d).c_str(), C::RST); }
        printf("  %sОговорка: DNS по UDP может теряться, а дамп — обрываться. Это\n"
               "  ПОДОЗРЕНИЕ, не факт: NXDomain/пустой ответ блокировкой НЕ считаются.%s\n", C::GRY, C::RST);
        if (tailSkipped > 0)
            printf("  %s(%d запрос(ов) в последние %.1f с дампа не учтены — ответ мог не успеть.)%s\n",
                   C::GRY, tailSkipped, cfg().tailUs / 1e6, C::RST);
    }
}

// ------------------------------------------------------------------
// Детект RST-инъекции / DPI-блокировки (доказательство блокировки).
// Пассивные признаки вмешательства DPI:
//   (A) RST пришёл ПОСЛЕ TLS ClientHello (с известным SNI) до данных сервера —
//       сервер ответил бы ServerHello, а не сбросом => блокировка по SNI;
//   (B) TTL у RST заметно больше TTL данных того же сервера — RST сгенерирован
//       ближе к абоненту, чем реальный сервер (только pcap, где TTL виден);
//   (C) молчаливый дроп: соединение поднялось, ClientHello ушёл, а от сервера
//       ни данных, ни RST.
// Возвращает список находок (строк) для печати. localIp — адрес абонента.
// ------------------------------------------------------------------
// Условия по одному соединению — общие для detectDpiInjection,
// collectTspuBlockedIps и collectBlockedSnis, чтобы три отчёта не расходились.

// (C) молчаливый дроп: соединение поднялось (SYN-ACK был), ушёл ClientHello
// с SNI, а сервер не прислал НИЧЕГО (ни данных, ни RST). ClientHello в
// последние 3 с захвата не берём.
// Текстовый дамп (tcpdump без содержимого) ClientHello не показывает: там
// тот же признак — первый сегмент данных на :443 после SYN-ACK и полная
// тишина сервера. Имени (SNI) у такого соединения нет — c.sni пустой, и
// отличить «режут этот сайт» от одиночного зависания нечем: если к тому же
// адресу другое соединение нормально работало, дропом не считаем.
bool connSilentDrop(const TcpConnTable& tt, const TcpConnState& c) {
    if (!tt.anyInboundTcp || c.synack <= 0 || c.firstData >= 0 || c.inRst || c.inFin ||
        tt.tEnd < 0)
        return false;
    long long t0 = -1;
    if (c.ch && !c.sni.empty()) t0 = c.chTime;
    else if (!c.ch && c.rport == 443 && !tt.workedIps.count(c.ip)) t0 = c.firstOutDataTime;
    return t0 >= 0 && tt.tEnd - t0 >= cfg().tailUs;
}
// (A) RST после ClientHello, пока сервер ещё не отдал данных (<200 Б).
// Если сервер уже успел переслать существенный объём — это рабочая сессия,
// а RST в конце — норма, НЕ блокировка.
bool connSniRst(const TcpConnState& c) {
    if (!c.ch || c.sni.empty() || !c.inRst) return false;
    bool rstBeforeData = (c.firstData < 0) || (c.rstTime >= 0 && c.rstTime <= c.firstData);
    bool afterHello = (c.chTime < 0 || c.rstTime < 0 || c.rstTime >= c.chTime);
    return rstBeforeData && afterHello && c.serverBytes < 200;
}
// (B) TTL входящего RST заметно БОЛЬШЕ TTL настоящих пакетов сервера — RST
// сгенерирован ближе к абоненту (DPI). Эталон — TTL данных сервера (если их
// ≥200 Б), иначе TTL SYN-ACK: инъекция обычно прилетает ДО любых данных.
// Возвращает разницу (≥5 — инъекция) или 0; ref — эталонный TTL, refWhat — чей.
int connTtlInjection(const TcpConnState& c, int& ref, const char*& refWhat) {
    ref = -1; refWhat = "";
    if (c.rstTtl < 0) return 0;
    if (c.dataTtl >= 0 && c.serverBytes >= 200) { ref = c.dataTtl; refWhat = "данные сервера"; }
    else if (c.synAckTtl >= 0)                  { ref = c.synAckTtl; refWhat = "SYN-ACK сервера"; }
    else return 0;
    int diff = c.rstTtl - ref;
    return diff >= 5 ? diff : 0;
}

// Поддельный RST — прислал не сервер, а кто-то по пути (DPI/ТСПУ). Сумма
// независимых признаков; ≥2 — считаем подделкой:
//   +2 TTL у RST заметно больше, чем у пакетов сервера (connTtlInjection) —
//      если сервер ещё не отдал данных; посреди сессии только +1;
//   +1 RST пришёл после ClientHello быстрее половины RTT рукопожатия — сервер
//      физически не успел бы ответить (RTT берём только без повторов SYN).
//      Только +1: RTT рукопожатия бывает завышен (SYN задержался в Wi-Fi
//      power-save, медленный SYN-ACK под нагрузкой), и настоящий RST сервера
//      тогда выглядит «слишком быстрым» — нужен ещё хотя бы один признак;
//   +2 после RST сервер продолжал слать пакеты — он RST не посылал и о нём не знает;
//   +1 пачка RST в пределах 200 мс (DPI часто шлёт несколько с разными seq).
//   −2 IP ID у RST продолжает счётчик сервера при том же TTL — скорее всего,
//      RST послал сам сервер (инъекция по пути счётчика не знает). Только −2,
//      а не «не подделка»: совпасть может и случайно (общий счётчик у сервера,
//      инжектор, копирующий ID). Не вычитается, если сервер слал и после RST:
//      сам пославший RST сервер дальше молчит, значит, IP ID подобран.
// why (необязательно) — человекочитаемые причины.
static int connForgedRst(const TcpConnState& c, std::vector<std::string>* why = nullptr) {
    if (!c.inRst) return 0;
    int score = 0;
    auto add = [&](int s, const std::string& w) { score += s; if (why) why->push_back(w); };
    int ref; const char* refWhat;
    // TTL в одиночку решает только для РАННЕГО RST (сервер ещё не отдал
    // данных): так режет DPI. Посреди рабочей сессии RST с другим TTL часто
    // шлёт балансировщик или файрвол самого сервера на соседнем хопе — там
    // TTL даёт +1 и нужен ещё хотя бы один признак.
    if (int diff = connTtlInjection(c, ref, refWhat))
        add(c.serverBytes < 200 ? 2 : 1,
            "TTL у RST " + std::to_string(c.rstTtl) + ", а у " + refWhat + " " +
            std::to_string(ref) + " (на " + std::to_string(diff) + " хопов ближе)");
    if (c.syn == 1 && c.synTime >= 0 && c.synAckTime > c.synTime &&
        c.chTime >= 0 && c.rstTime >= c.chTime) {
        long long rtt = c.synAckTime - c.synTime;
        long long dt = c.rstTime - c.chTime;
        if (rtt >= 3000 && dt * 2 < rtt) {
            char b[200];
            snprintf(b, sizeof(b), "RST через %.1f мс после ClientHello при RTT %.1f мс — "
                     "быстрее, чем мог ответить сервер", dt / 1000.0, rtt / 1000.0);
            add(1, b);
        }
    }
    if (c.inAfterRst >= 2)
        add(2, "после RST сервер прислал ещё " + std::to_string(c.inAfterRst) +
               " пакет(ов) — сам он соединение не сбрасывал");
    if (c.rstBurst >= 2)
        add(1, std::to_string(c.rstBurst) + " RST подряд за 200 мс");
    // IP ID продолжает счётчик сервера, TTL тот же — инъекция по пути счётчика
    // не знает, так что это почти наверняка RST самого сервера. Но если сервер
    // слал и после RST (пакеты, отправленные раньше RST, inAfterRst уже отсеял),
    // RST послал не он — IP ID подобран, и −2 погасило бы самый сильный признак
    if (c.rstServerId && score > 0 && c.inAfterRst < 2)
        add(-2, "но IP ID продолжает счётчик сервера и TTL тот же — похоже на RST самого сервера");
    return std::max(score, 0);
}
bool connIsForgedRst(const TcpConnState& c) { return connForgedRst(c) >= 2; }

std::vector<std::string> detectDpiInjection(const TcpConnTable& tt) {
    std::vector<std::string> findings;
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        std::string who = c.ip + ":" + std::to_string(c.rport) +
                          " (лок. порт " + std::to_string(c.lport) + ")";
        // настоящий ECH (внешнее имя провайдера) — ТСПУ режет его как класс
        bool realEch = c.ech && isEchPublicName(c.sni);
        const char* echNote = realEch
            ? "\n    ClientHello с ECH (внешнее имя " : nullptr;

        if (connSilentDrop(tt, c)) {
            char b[640];   // кириллица в UTF-8 — 2 байта на букву
            if (c.sni.empty())
                snprintf(b, sizeof(b),
                    "К %s: соединение установлено, первый сегмент данных (обычно "
                    "ClientHello) ушёл, но сервер не ответил ничем (ни данных, ни RST) — "
                    "молчаливый дроп, характерный для блокировки ТСПУ. SNI в дампе не "
                    "виден (запись без содержимого пакетов).",
                    who.c_str());
            else
                snprintf(b, sizeof(b),
                    "К %s (SNI: %s): соединение установлено, ClientHello отправлен, но "
                    "сервер не ответил ничем (ни данных, ни RST) — молчаливый дроп, "
                    "характерный для блокировки по SNI (способ ТСПУ).",
                    who.c_str(), c.sni.c_str());
            std::string s = b;
            if (echNote) s += std::string(echNote) + c.sni + ") — похоже на блокировку ECH.";
            findings.push_back(s + "\n    Wireshark: " + wsFilter(c.ip, c.rport));
        }
        if (!c.inRst) continue;                 // дальше — только разбор входящего RST

        if (connSniRst(c)) {
            char b[640];
            snprintf(b, sizeof(b),
                "Соединение к %s (SNI: %s) сброшено RST до ответа сервера — "
                "возможна блокировка по SNI.",
                who.c_str(), c.sni.c_str());
            std::string s = b;
            if (echNote) s += std::string(echNote) + c.sni + ") — похоже на блокировку ECH.";
            findings.push_back(s + "\n    Wireshark: " + wsFilter(c.ip, c.rport));
        }

        std::vector<std::string> why;
        if (connForgedRst(c, &why) >= 2) {
            std::string s = "К " + who + " пришёл ПОДДЕЛЬНЫЙ RST — его сгенерировал "
                            "не сервер, а оборудование по пути (признак DPI-инъекции):";
            for (const auto& w : why) s += "\n    - " + w;
            findings.push_back(s + "\n    Wireshark: " + wsFilter(c.ip, c.rport));
        }
    }
    return findings;
}
std::vector<std::string> detectDpiInjection(const std::vector<Packet>& packets,
                                            const std::string& localIp) {
    return detectDpiInjection(buildTcpConnTable(packets, localIp));
}

// ---- UDP-туннели: общее для журнала (analyzeUdpConns), таблицы
// (collectTspuBlockedIps) и обзора (collectBlockReasons) — одно опознание
// туннеля и одно правило «ответа нет», чтобы три отчёта не расходились.

// Что за туннель на этом UDP-адресе; nullptr — не туннель. *port — порт,
// по которому опознан. ii — сведения об удалённом адресе, если есть.
// IKE/NAT-T (500/4500) — туннель, только если это точно IPsec-VPN (ipsecClass):
// VoWiFi и «не ясно» VPN не называем.
static const char* udpTunnelKind(const Packet& p, int rport, int lport,
                                 const IpInfo* ii, int* port) {
    *port = rport;
    if (p.wgType != 0) return "WireGuard";   // сигнатура в payload — самый надёжный признак
    if (p.l7 == L7_OPENVPN) return "OpenVPN";
    if (const char* v = vpnPortName(rport, "UDP")) {
        const IpsecClass ic = ipsecClass(p, rport, ii);
        return (ic == IPSEC_NONE || ic == IPSEC_VPN) ? v : nullptr;
    }
    // листенер на нашей стороне — абонент сам держит WG/AmneziaWG-сервер
    if (lport == 51820 || lport == 51821 || lport == 55555) {
        *port = lport;
        const char* v = vpnPortName(lport, "UDP");
        return v ? v : "WireGuard";
    }
    return nullptr;
}

namespace {  // имя не должно столкнуться с другими единицами трансляции
struct UdpTunnelStat {
    const char* kind = nullptr;         // udpTunnelKind; nullptr — не туннель
    int kindPort = 0;
    long long out = 0, in = 0;          // пакетов от абонента / к абоненту
    long long espOut = 0, espIn = 0;    // из них ESP-данные (IPsec)
    long long t0 = -1, t1 = -1;         // первый / последний исходящий
    long long lastIn = -1;              // последний входящий
    void add(const Packet& p, bool outbound, long long t, int rport, int lport,
             const IpInfo* ii) {
        if (outbound) {
            out++; if (p.ipsec == 3) espOut++;
            if (t >= 0) { if (t0 < 0) t0 = t; t1 = t; }
        } else {
            in++; if (p.ipsec == 3) espIn++;
            if (t >= 0) lastIn = t;
        }
        // сигнатура WireGuard перекрывает догадку по порту
        if (!kind || p.wgType != 0) {
            int port = 0;
            if (const char* k = udpTunnelKind(p, rport, lport, ii, &port)) { kind = k; kindPort = port; }
        }
    }
};
}  // namespace

// Туннель «шлём — в ответ почти ничего». Вызывать, только если входящий UDP
// в дампе вообще есть (иначе дамп однонаправленный). Условия:
//  - попытки идут ≥10 с (WireGuard повторяет handshake раз в 5 с);
//  - IPsec: судим по ESP-данным — ESP уходит (≥3), в ответ ESP нет;
//  - иначе ≥10 пакетов ушло, ≤2 пришло. Не строго 0: ТСПУ часто пропускает
//    первое рукопожатие и режет поток уже после него. Но пара ответов бывает
//    и у РАБОЧЕГО WG-туннеля, по которому только отдаём: получатель шлёт
//    keepalive раз в 10 с. Поэтому при ответах нужна ещё тишина ≥15 с между
//    последним ответом и последней попыткой — у живого туннеля её не бывает.
static bool udpTunnelStarved(const UdpTunnelStat& s) {
    if (s.t0 < 0 || s.t1 - s.t0 < 10000000LL) return false;
    if (s.espOut + s.espIn > 0) return s.espOut >= 3 && s.espIn == 0;
    if (s.out < 10 || s.in > 2) return false;
    return s.in == 0 || s.t1 - s.lastIn >= 15000000LL;
}

// Собирает множество IP (без порта) с признаками блокировки на ТСПУ:
//  - TCP: RST-инъекция / молчаливый дроп после ClientHello (по SNI) — только
//    если на этом адресе не работал другой сайт (иначе адрес общий, CDN);
//  - TCP: рукопожатие не проходит (много SYN, ни одного SYN-ACK/RST);
//  - UDP: VPN-туннель, в который долго шлём, а в ответ почти ничего (udpTunnelStarved).
// Используется чтобы пометить такие адреса прямо в единой таблице.
std::set<std::string> collectTspuBlockedIps(const std::vector<Packet>& packets,
                                            const std::string& localIp,
                                            const TcpConnTable* ttIn /*= nullptr*/,
                                            const std::unordered_map<std::string, IpInfo>* ipCache /*= nullptr*/) {
    auto isLocal = [&](const std::string& ip) {
        return isLocalIp(ip) || (!localIp.empty() && ip == localIp);
    };
    std::set<std::string> blocked;

    // TCP-часть: те же условия, что в detectDpiInjection, по 4-tuple
    TcpConnTable ttOwn;
    if (!ttIn) ttOwn = buildTcpConnTable(packets, localIp);
    const TcpConnTable& tt = ttIn ? *ttIn : ttOwn;
    struct PerIp { long long syn = 0, synack = 0, data = 0; bool rst = false;
                   long long firstSyn = -1; };
    std::map<std::string, PerIp> perIp;
    // IP|SNI, по которым хоть одно соединение получило нормальный ответ:
    // одиночный обрыв среди рабочих параллельных соединений — не блокировка
    // (дроп без SNI гасится рабочим адресом в самом connSilentDrop)
    std::set<std::string> workedSni;
    // по каждому IP — SNI соединений, получивших нормальный ответ ("" — без SNI)
    std::map<std::string, std::set<std::string>> workedByIp;
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        if (c.serverBytes < 200) continue;
        if (c.ch) workedSni.insert(c.ip + "|" + c.sni);
        workedByIp[c.ip].insert(c.sni);
    }
    // Адрес общий (CDN, хостинг): по нему нормально работал ДРУГОЙ сайт.
    // Тогда блокировка — по имени, а не по адресу: помечать весь IP нельзя,
    // иначе красными станут все сайты за этим CDN. Такое имя попадёт в
    // collectBlockedSnis, и в таблице пометятся только строки с ним.
    auto otherSiteWorked = [&](const TcpConnState& c) {
        auto it = workedByIp.find(c.ip);
        if (it == workedByIp.end()) return false;
        for (const auto& s : it->second) if (s != c.sni) return true;
        return false;
    };
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        bool sniBlock = (connSniRst(c) || connSilentDrop(tt, c)) &&
                        !workedSni.count(c.ip + "|" + c.sni);
        if ((sniBlock || connIsForgedRst(c)) && !otherSiteWorked(c))
            blocked.insert(c.ip);
        PerIp& pi = perIp[c.ip];
        pi.syn += c.syn; pi.synack += c.synack; pi.data += c.serverBytes;
        if (c.inRst) pi.rst = true;
        if (c.syn > 0 && c.firstTime >= 0 && (pi.firstSyn < 0 || c.firstTime < pi.firstSyn))
            pi.firstSyn = c.firstTime;
    }
    // блокировка рукопожатия: МНОГО SYN ушло (упорные повторы, суммарно по
    // всем соединениям к адресу), НИ ОДНОГО SYN-ACK и RST, данных нет. Так
    // ТСПУ режет Telegram. Порог высокий (tspu_min_syn, по умолчанию 6), чтобы не путать с одиночным
    // недоступным хостом; закрытый порт ответил бы RST. Если входящих TCP в дампе
    // нет вовсе — дамп однонаправленный, и отсутствие SYN-ACK ничего не значит.
    if (tt.anyInboundTcp) {
        for (const auto& kv : perIp) {
            const PerIp& pi = kv.second;
            if (pi.syn >= cfg().tspuMinSyn && pi.synack == 0 && pi.data == 0 && !pi.rst &&
                pi.firstSyn >= 0 && tt.tEnd - pi.firstSyn >= cfg().tailUs)
                blocked.insert(kv.first);
        }
    }

    // UDP-часть: VPN-туннель, в который долго шлём, а в ответ почти ничего
    // (udpTunnelStarved). Помечаем мягко (в таблице — «ТСПУ?»): то же самое
    // дают неверный ключ и лежащий сервер. 500/4500 считаем VPN, только если
    // это точно IPsec-VPN (ipsecClass: по самому дампу или хостинг из ipCache);
    // иначе это может быть VoWiFi, и «ТСПУ?» на ePDG оператора было бы ложным.
    std::map<std::string, UdpTunnelStat> uc;
    bool anyInboundUdp = false;
    std::vector<long long> absT = absTimes(packets);
    for (size_t i = 0; i < packets.size(); i++) {
        const Packet& p = packets[i];
        if (p.proto != "UDP") continue;
        bool sLoc = isLocal(p.srcIp), dLoc = isLocal(p.dstIp);
        if (sLoc == dLoc) continue;
        if (!sLoc) anyInboundUdp = true;
        std::string ip = sLoc ? p.dstIp : p.srcIp;
        int rport = sLoc ? p.dstPort : p.srcPort;
        int lport = sLoc ? p.srcPort : p.dstPort;
        uc[ip].add(p, sLoc, absT[i], rport, lport, ipInfoOf(ipCache, ip));
    }
    if (anyInboundUdp)
        for (const auto& kv : uc)
            if (kv.second.kind && udpTunnelStarved(kv.second)) blocked.insert(kv.first);

    return blocked;
}

// Собирает ДОМЕНЫ (из SNI), заблокированные по характерному почерку ТСПУ.
// По tspu-docs (гл.17.5.3): HTTPS режется по домену из SNI/Client Hello —
// фильтр видит ClientHello, узнаёт домен из списка РКН и дропает/шлёт RST.
// Возвращает map<домен, способ> для явного отчёта «заблокировано по SNI».
std::map<std::string,std::string> collectBlockedSnis(
        const std::vector<Packet>& packets, const std::string& localIp,
        const TcpConnTable* ttIn /*= nullptr*/) {
    TcpConnTable ttOwn;
    if (!ttIn) ttOwn = buildTcpConnTable(packets, localIp);
    const TcpConnTable& tt = ttIn ? *ttIn : ttOwn;
    // домен считаем заблокированным, только если НИ ОДНО соединение с этим SNI
    // не получило нормальный ответ: браузер открывает несколько параллельных
    // соединений, и одно оборванное среди рабочих — не блокировка
    std::map<std::string,std::string> out;
    std::set<std::string> worked;
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        if (!c.ch || c.sni.empty()) continue;
        if (c.serverBytes >= 200) { worked.insert(c.sni); continue; }
        bool echTag = c.ech && isEchPublicName(c.sni);
        if (connSniRst(c)) {
            out[c.sni] = echTag ? "RST после ClientHello с ECH" : "RST после ClientHello";
            if (connIsForgedRst(c)) out[c.sni] += " (поддельный — инъекция DPI)";
        }
        else if (connSilentDrop(tt, c) && !out.count(c.sni))
            out[c.sni] = echTag ? "молчаливый дроп ClientHello с ECH" : "молчаливый дроп";
    }
    for (const auto& s : worked) out.erase(s);
    return out;
}
// UDP-диагностика для режима 2. У UDP нет SYN/RST/ретрансмиссий, поэтому
// оцениваем по-другому: односторонний поток (шлём — ответа нет), соотношение
// исходящих/входящих пакетов, грубый RTT по парам, и VPN-порты (WireGuard,
// WARP, Hysteria и т.п.). targetIp — необязательный фильтр.
// ------------------------------------------------------------------
void analyzeUdpConns(const std::vector<Packet>& packets,
                     const std::string& localIp,
                     const std::string& targetIp /*= ""*/,
                     const std::unordered_map<std::string, IpInfo>* ipCache /*= nullptr*/) {
    auto isLocal = [&](const std::string& ip) {
        return isLocalIp(ip) || (!localIp.empty() && ip == localIp);
    };
    struct UConn : UdpTunnelStat {        // out/in, espOut/espIn, время — в базе
        long long outBytes = 0, inBytes = 0;
        std::set<int> ports;
        bool vpn = false; std::string vpnName; int vpnPort = 0;
        int ipsecPort = 0;                // 500/4500, не опознанный как IPsec-VPN
        IpsecClass ipsecCls = IPSEC_NONE; //   VoWiFi точно или не ясно
        long long rttSum = 0, rttCnt = 0, rttMin = -1, rttMax = -1;
        long long lastOutTime = -1;
        // IPsec по стадиям (Packet::ipsec): IKE_SA_INIT, IKE дальше (ESP — в базе)
        long long ikeInit = 0, ikeMore = 0;
    };
    std::map<std::string, UConn> conns;
    long long matched = 0;

    const std::vector<long long> absT = absTimes(packets);
    for (size_t i = 0; i < packets.size(); i++) {
        const Packet& p = packets[i];
        if (p.proto != "UDP") continue;
        if (!targetIp.empty() && p.srcIp != targetIp && p.dstIp != targetIp) continue;
        bool sLoc = isLocal(p.srcIp), dLoc = isLocal(p.dstIp);
        if (sLoc == dLoc) continue;
        matched++;
        std::string remote = sLoc ? p.dstIp : p.srcIp;
        int rport = sLoc ? p.dstPort : p.srcPort;
        int lport = sLoc ? p.srcPort : p.dstPort;
        UConn& c = conns[remote];
        c.ports.insert(rport);
        const long long t = absT[i];
        // опознание туннеля и счёт пакетов — общие с таблицей и обзором
        const IpInfo* ii = ipInfoOf(ipCache, remote);
        c.add(p, sLoc, t, rport, lport, ii);
        // IPsec-разбор (ESP/IKE) нужен и для VoWiFi, но VPN его называем только
        // точно (ipsecClass): VoWiFi — «звонки по Wi-Fi», не ясно — с оговоркой
        if (!c.kind && !c.ipsecPort && vpnPortName(rport, "UDP")) {
            c.ipsecPort = rport;
            c.ipsecCls = ipsecClass(p, rport, ii);
        }
        if (p.ipsec == 1) c.ikeInit++;
        else if (p.ipsec == 2) c.ikeMore++;
        if (sLoc) {
            c.outBytes += p.length;
            c.lastOutTime = t;
        } else {
            c.inBytes += p.length;
            // грубый RTT: ответ после нашего последнего исходящего
            if (c.lastOutTime >= 0 && t > c.lastOutTime) {
                long long rtt = t - c.lastOutTime;
                if (rtt < 5LL*1000000) { // <5с, отсекаем мусор
                    if (c.rttMin < 0 || rtt < c.rttMin) c.rttMin = rtt;
                    if (rtt > c.rttMax) c.rttMax = rtt;
                    c.rttSum += rtt; c.rttCnt++;
                }
            }
        }
    }

    if (conns.empty()) return; // нет UDP — ничего не печатаем
    for (auto& kv : conns) {
        UConn& c = kv.second;
        if (c.kind) { c.vpn = true; c.vpnName = c.kind; c.vpnPort = c.kindPort; }
        else if (c.ipsecPort) {
            c.vpn = true; c.vpnPort = c.ipsecPort;
            c.vpnName = c.ipsecCls == IPSEC_VOWIFI
                ? std::string("VoWiFi (звонки по Wi-Fi)")
                : std::string(vpnPortName(c.ipsecPort, "UDP")) + " — IPsec-VPN или VoWiFi";
        }
    }

    printf("\n=================== UDP-СОЕДИНЕНИЯ ===================\n");
    if (!targetIp.empty()) printf("Фильтр: только %s\n", targetIp.c_str());
    printf("Всего UDP-точек: %lld\n", (long long)conns.size());

    // сортируем по объёму
    std::vector<std::pair<std::string, UConn>> rows(conns.begin(), conns.end());
    std::sort(rows.begin(), rows.end(),
        [](auto& a, auto& b){ return (a.second.outBytes+a.second.inBytes) > (b.second.outBytes+b.second.inBytes); });

    printf("  %-16s %-6s %-6s %-9s %-8s %s\n",
           "IP", "→пак", "←пак", "RTT мс", "порты", "примечание");
    // входящий UDP в дампе вообще есть? Если нет — дамп снят в одну сторону,
    // и «ответа нет» ничего не доказывает (как anyInboundUdp в analyzeQuic)
    bool anyInboundUdp = false;
    for (auto& kv : conns) if (kv.second.in > 0) { anyInboundUdp = true; break; }

    const int kShowRows = 12;                  // в таблице — только крупнейшие
    int shown = 0;
    std::vector<std::string> notes;
    // вердикты по VPN-туннелям — по ВСЕМ туннелям, не только попавшим в таблицу
    enum VLevel { V_BAD, V_OK, V_INFO };
    std::vector<std::pair<VLevel, std::string>> vpnVerdicts;
    for (auto& kv : rows) {
        const UConn& c = kv.second;
        bool inTable = (shown++ < kShowRows);
        std::string portsStr; int pc = 0;
        for (int p : c.ports) { if (pc++ >= 3) { portsStr += ".."; break; }
            if (!portsStr.empty()) portsStr += ","; portsStr += std::to_string(p); }

        // односторонний поток: шлём, ответа нет -> порт закрыт/фильтр/блокировка
        bool oneWay = (c.out >= 3 && c.in == 0);
        if (inTable) {
            std::string rttStr = "-";
            if (c.rttCnt > 0) { char b[48]; snprintf(b,sizeof(b),"%lld",(c.rttSum/c.rttCnt)/1000); rttStr=b; }
            const char* col = (oneWay && anyInboundUdp) ? C::RED : (c.vpn ? C::YEL : C::WHT);
            std::string note;
            if (oneWay) note = anyInboundUdp ? "нет ответа (порт закрыт/фильтр?)"
                                             : "нет ответа (дамп в одну сторону?)";
            else if (c.vpn) {
                note = (c.kind ? "VPN: " : "") + c.vpnName;   // VoWiFi / не ясно — не «VPN:»
                if (c.espOut > 0 && c.espIn > 0)            note += " (ESP в обе стороны)";
                else if (c.espOut + c.espIn > 0)            note += " (ESP в одну сторону)";
                else if (c.ikeMore > 0)                     note += " (IKE без ESP)";
                else if (c.ikeInit > 0)                     note += " (только IKE_SA_INIT)";
            }
            printf("  %s%-16s %-6lld %-6lld %-9s %-8s %s%s\n",
                   col, kv.first.c_str(), c.out, c.in, rttStr.c_str(),
                   portsStr.c_str(), note.c_str(), C::RST);
            if (shown == kShowRows && (int)rows.size() > kShowRows)
                printf("  %s... ещё %d UDP-точек не показано (VPN-итог ниже — по всем)%s\n",
                       C::GRY, (int)rows.size() - kShowRows, C::RST);
        }

        if (inTable && oneWay && !c.vpn && anyInboundUdp) {
            char b[512];
            snprintf(b, sizeof(b),
                "UDP к %s (порт %s): %lld пакетов ушло, ответа нет — порт закрыт, "
                "фильтрация или блокировка.", kv.first.c_str(), portsStr.c_str(), c.out);
            notes.push_back(std::string(b) + "\n    Wireshark: " +
                wsFilter(kv.first, c.ports.size() == 1 ? *c.ports.begin() : -1, "udp"));
        }
        if (c.vpn) {
            char b[768];
            VLevel lvl = V_INFO;
            // Шлём, а в ответ почти ничего. Пассивно НЕ отличить блокировку от
            // неверного ключа/конфига (WireGuard молча игнорирует чужой handshake)
            // и от лежащего сервера — поэтому не «ЗАБЛОКИРОВАН», а перечень причин.
            // То же правило, что в таблице и обзоре, — иначе отчёты разойдутся.
            const bool starved = anyInboundUdp && udpTunnelStarved(c);
            // IPsec: судим по ESP-данным, IKE — лишь уточнение. Туннель, поднятый до
            // начала съёма, в дампе виден одним ESP, без IKE, — это норма.
            const bool espSeen = c.espOut + c.espIn > 0;
            const bool ikeSeen = c.ikeInit + c.ikeMore > 0;
            // ответа нет, но попыток мало или они шли меньше 10 с — для «НЕ работает» мало
            const bool weakOneWay = anyInboundUdp &&
                (espSeen ? (c.espOut >= 3 && c.espIn == 0) : (c.out >= 3 && c.in == 0));
            const double span = c.t0 >= 0 ? (c.t1 - c.t0) / 1e6 : 0.0;
            // как назвать IPsec в итоге: VoWiFi точно — только VoWiFi, не ясно — оба
            const char* ipsecTag = c.ipsecCls == IPSEC_VOWIFI ? "VoWiFi"
                                 : c.ipsecCls == IPSEC_UNSURE ? "IPsec/VoWiFi" : "IPsec";
            if (c.espOut > 0 && c.espIn > 0) {
                lvl = V_OK;
                snprintf(b, sizeof(b),
                    "%s (%s): ESP-данные идут в обе стороны (%lld↑/%lld↓) — туннель РАБОТАЕТ.%s",
                    ipsecTag, kv.first.c_str(), c.espOut, c.espIn,
                    ikeSeen ? "" : " IKE в дампе нет — туннель подняли до начала съёма, это нормально.");
            } else if (starved && espSeen) {
                lvl = V_BAD;
                snprintf(b, sizeof(b),
                    "%s (%s): ESP уходит (%lld пак. за %.0f с), в ответ ESP нет — туннель НЕ "
                    "работает: сервер не отвечает, ESP режут по пути или сессия на сервере уже закрыта.",
                    ipsecTag, kv.first.c_str(), c.espOut, span);
            } else if (weakOneWay && espSeen) {
                snprintf(b, sizeof(b),
                    "%s (%s): ESP уходит (%lld пак. за %.0f с), в ответ ESP нет, но попытки "
                    "шли меньше 10 с — вывод ненадёжен, снимите дамп подольше.",
                    ipsecTag, kv.first.c_str(), c.espOut, span);
            } else if (c.ikeInit > 0 && c.ikeMore == 0 && !espSeen && c.in > 0) {
                // клиент, получив нормальный ответ, сразу идёт в IKE_AUTH; повтор
                // SA_INIT раз за разом — рукопожатие дальше первого шага не идёт
                if (c.ikeInit >= 6) {
                    lvl = V_BAD;
                    snprintf(b, sizeof(b),
                        "%s, IKE (%s): только IKE_SA_INIT (%lld↑/%lld↓), до IKE_AUTH и ESP "
                        "не дошло — подключение НЕ устанавливается. Сервер отвечает, адрес "
                        "доступен; причина — отказ сервера (шифры, cookie), настройки клиента "
                        "или искажение ответа по пути.",
                        ipsecTag, kv.first.c_str(), c.out, c.in);
                } else {
                    snprintf(b, sizeof(b),
                        "%s, IKE (%s): в дампе только начало рукопожатия (IKE_SA_INIT, "
                        "%lld↑/%lld↓) — съём мог закончиться раньше, вывод невозможен.",
                        ipsecTag, kv.first.c_str(), c.out, c.in);
                }
            } else if (c.ikeMore > 0 && !espSeen) {
                snprintf(b, sizeof(b),
                    "%s, IKE (%s): рукопожатие дошло дальше IKE_SA_INIT (%lld↑/%lld↓), но "
                    "ESP-данных в UDP нет — аутентификация не прошла, в туннеле не было "
                    "трафика или ESP идёт без NAT-T (IP-протокол 50 программа не разбирает).",
                    ipsecTag, kv.first.c_str(), c.out, c.in);
            } else if (!anyInboundUdp && c.in == 0) {
                snprintf(b, sizeof(b),
                    "%s (порт %d, %s): %lld пакетов ушло, ответов нет, но входящего UDP "
                    "в дампе нет вовсе — похоже, дамп снят в одну сторону; вывод невозможен.",
                    c.vpnName.c_str(), c.vpnPort, kv.first.c_str(), c.out);
            } else if (starved) {
                lvl = V_BAD;
                snprintf(b, sizeof(b),
                    "%s (порт %d, %s): %lld пакетов ушло за %.0f с, %lld в ответ — нет ответа: "
                    "блокировка, неверный ключ или сервер недоступен. Блокировку "
                    "подтвердит проверка того же сервера с другой сети (режим 8 — UDP-проба).",
                    c.vpnName.c_str(), c.vpnPort, kv.first.c_str(), c.out, span, c.in);
            } else if (weakOneWay) {
                snprintf(b, sizeof(b),
                    "%s (порт %d, %s): %lld пакетов ушло за %.0f с, ответа нет, но для вывода "
                    "мало (нужно ≥10 пакетов за ≥10 с) — снимите дамп подольше.",
                    c.vpnName.c_str(), c.vpnPort, kv.first.c_str(), c.out, span);
            } else if (!espSeen && c.out >= 10 && c.in <= 2) {
                // пара ответов на много исходящих, но без долгой тишины в конце или
                // за короткое время — так выглядит и keepalive рабочего WG-туннеля,
                // по которому только отдаём (см. udpTunnelStarved)
                snprintf(b, sizeof(b),
                    "%s (порт %d, %s): %lld↑/%lld↓ за %.0f с — ответы редкие. Так бывает и при "
                    "обрыве после рукопожатия, и у рабочего туннеля, по которому только отдают "
                    "данные (keepalive раз в 10 с); однозначный вывод невозможен.",
                    c.vpnName.c_str(), c.vpnPort, kv.first.c_str(), c.out, c.in, span);
            } else if (c.out > 0 && c.in > 0) {
                lvl = V_OK;
                snprintf(b, sizeof(b),
                    "%s (порт %d, %s): обмен двусторонний (%lld↑/%lld↓) — туннель РАБОТАЕТ.",
                    c.vpnName.c_str(), c.vpnPort, kv.first.c_str(), c.out, c.in);
            } else if (c.out == 0 && c.in > 0) {
                snprintf(b, sizeof(b),
                    "%s (порт %d, %s): только входящие пакеты (%lld↑/%lld↓) — исходящих "
                    "в дампе нет (дамп снят однонаправленно или туннель отвечает на чужой запрос); "
                    "однозначный вывод невозможен.",
                    c.vpnName.c_str(), c.vpnPort, kv.first.c_str(), c.out, c.in);
            } else {
                snprintf(b, sizeof(b),
                    "%s (порт %d, %s): слишком мало пакетов для вывода (%lld↑/%lld↓).",
                    c.vpnName.c_str(), c.vpnPort, kv.first.c_str(), c.out, c.in);
            }
            vpnVerdicts.push_back({ lvl, std::string(b) + "\n    Wireshark: " +
                                         wsFilter(kv.first, c.vpnPort, "udp") });
        }
    }

    if (!notes.empty()) {
        printf("\nЗаметки по UDP:\n");
        for (auto& n : notes) printf("  • %s\n", n.c_str());
    }

    // ЯВНЫЙ ИТОГ ПО VPN/UDP-ТУННЕЛЯМ
    if (!vpnVerdicts.empty()) {
        printf("\n%s=== ИТОГ ПО VPN/UDP-ТУННЕЛЯМ ===%s\n", C::BOLD, C::RST);
        for (auto& v : vpnVerdicts) {
            const char* col = v.first == V_BAD ? C::RED : (v.first == V_OK ? C::GRN : C::YEL);
            printf("  %s• %s%s\n", col, v.second.c_str(), C::RST);
        }
    }
}

// ------------------------------------------------------------------
// QUIC (HTTP/3): ответил ли сервер на Initial клиента.
// SNI берётся из расшифрованного Initial (QuicHelloCollector). ТСПУ режет
// QUIC молча: Initial уходит, ответа нет, браузер через пару секунд
// откатывается на TCP — сайт открывается, и блокировку никто не замечает.
// Два почерка: не отвечает ни один QUIC-сервер (UDP/443 закрыт целиком) и
// не отвечают только отдельные имена при работающих остальных (фильтр по SNI).
// ------------------------------------------------------------------
void analyzeQuic(const std::vector<Packet>& packets,
                 const std::string& localIp,
                 const std::string& targetIp /*= ""*/) {
    auto isLocal = [&](const std::string& ip) {
        return isLocalIp(ip) || (!localIp.empty() && ip == localIp);
    };
    std::vector<long long> absT = absTimes(packets);
    struct QF {
        std::string rip, sni; int rport = 0, lport = 0;
        int initOut = 0; long long out = 0, in = 0;
        long long tFirst = -1;
    };
    std::map<std::string, QF> flows;          // rip|rport|lport; порядок вставки не важен
    std::set<std::string> tcpSni;             // имена из TCP ClientHello
    std::set<std::string> tcpAnsweredIp;      // серверы, приславшие данные по TCP
    bool anyInboundUdp = false;
    long long tEnd = -1;
    for (size_t i = 0; i < packets.size(); i++) {
        const Packet& p = packets[i];
        if (absT[i] > tEnd) tEnd = absT[i];
        bool sLoc = isLocal(p.srcIp), dLoc = isLocal(p.dstIp);
        if (sLoc == dLoc) continue;
        if (p.proto == "TCP") {
            if (sLoc && !p.sni.empty()) tcpSni.insert(p.sni);
            if (!sLoc && p.length > 0) tcpAnsweredIp.insert(p.srcIp);
            continue;
        }
        if (p.proto != "UDP") continue;
        if (!sLoc) anyInboundUdp = true;
        if (!targetIp.empty() && p.srcIp != targetIp && p.dstIp != targetIp) continue;
        std::string rip = sLoc ? p.dstIp : p.srcIp;
        int rport = sLoc ? p.dstPort : p.srcPort, lport = sLoc ? p.srcPort : p.dstPort;
        std::string key = rip + "|" + std::to_string(rport) + "|" + std::to_string(lport);
        auto it = flows.find(key);
        if (it == flows.end()) {
            // поток считаем, только если видели его начало — Initial от клиента
            if (!(sLoc && p.quic == 1)) continue;
            it = flows.emplace(key, QF()).first;
            it->second.rip = rip; it->second.rport = rport; it->second.lport = lport;
            it->second.tFirst = absT[i];
        }
        QF& f = it->second;
        if (sLoc) {
            f.out++;
            if (p.quic == 1) f.initOut++;
            if (f.sni.empty() && !p.sni.empty()) f.sni = p.sni;
        } else {
            f.in++;
        }
    }
    if (flows.empty()) return;

    printf("\n%s=== QUIC (HTTP/3): ОТВЕТ СЕРВЕРА НА INITIAL ===%s\n", C::BOLD, C::RST);
    if (!anyInboundUdp) {
        printf("  %sQUIC-соединений: %d, но входящего UDP в дампе нет вовсе — похоже,\n"
               "  записано одно направление. О блокировке QUIC судить нельзя.%s\n",
               C::GRY, (int)flows.size(), C::RST);
        return;
    }
    // группируем по имени (без SNI — по адресу), чтобы повторы не множили строки
    struct G { std::string name, ip; int port = 0; int answered = 0, inits = 0; bool undecided = true; };
    std::map<std::string, G> groups;
    int nAns = 0, nDrop = 0, nWait = 0, noSni = 0;
    for (auto& kv : flows) {
        const QF& f = kv.second;
        std::string name = f.sni.empty() ? f.rip : f.sni;
        G& g = groups[name];
        g.name = name; g.ip = f.rip; g.port = f.rport;
        g.inits += f.initOut;
        if (f.sni.empty()) noSni++;
        if (f.in > 0) { g.answered++; g.undecided = false; nAns++; continue; }
        // «нет ответа» засчитываем, если клиент повторял Initial или дамп
        // шёл ещё хотя бы 2 с — иначе запись просто оборвалась раньше ответа
        if (f.initOut >= 2 || (tEnd >= 0 && f.tFirst >= 0 && tEnd - f.tFirst >= 2000000)) {
            g.undecided = false; nDrop++;
        } else {
            nWait++;
        }
    }
    printf("  QUIC-соединений: %d — сервер ответил: %s%d%s, без ответа: %s%d%s",
           (int)flows.size(), C::GRN, nAns, C::RST, nDrop ? C::YEL : C::GRY, nDrop, C::RST);
    if (nWait) printf(", не успели выяснить (конец дампа): %d", nWait);
    printf("\n");
    if (noSni)
        printf("  %sSNI не извлечён у %d: ECH, обрезанный snaplen или незнакомая версия QUIC.%s\n",
               C::GRY, noSni, C::RST);

    std::vector<const G*> ok, bad;
    for (auto& kv : groups) {
        const G& g = kv.second;
        if (g.undecided) continue;
        (g.answered > 0 ? ok : bad).push_back(&g);
    }
    if (!ok.empty()) {
        std::string s;
        size_t shown = 0;
        for (const G* g : ok) {
            if (shown == 8) { s += ", …ещё " + std::to_string(ok.size() - shown); break; }
            if (shown++) s += ", ";
            s += g->name;
        }
        printf("  %sРаботает по QUIC:%s %s\n", C::GRN, C::RST, s.c_str());
    }
    int fallback = 0;
    if (!bad.empty()) {
        printf("  %sБез ответа на Initial:%s\n", C::YEL, C::RST);
        size_t shown = 0;
        for (const G* g : bad) {
            if (shown++ == 15) { printf("  ... ещё %d\n", (int)(bad.size() - 15)); break; }
            bool isName = (g->name != g->ip);
            bool viaTcp = (isName && tcpSni.count(g->name)) || tcpAnsweredIp.count(g->ip);
            if (viaTcp) fallback++;
            printf("  %s%s%s (%s:%d) — Initial ×%d%s\n", C::BWHT, g->name.c_str(), C::RST,
                   g->ip.c_str(), g->port, g->inits,
                   viaTcp ? ", по TCP открылся (откат браузера)" : "");
            std::string flt = isName
                ? "quic && tls.handshake.extensions_server_name==\"" + g->name + "\""
                : "quic && " + wsFilter(g->ip, g->port, "udp");
            printf("    %s[%s]%s\n", C::GRY, flt.c_str(), C::RST);
        }
    }

    // вердикт — по именам: имя, ответившее хоть раз, заблокированным не считаем
    if (bad.empty()) {
        if (!ok.empty()) printf("  %s→ QUIC-рукопожатия проходят.%s\n", C::GRN, C::RST);
    } else if (ok.empty() && nDrop >= 3) {
        printf("  %s→ Ни один QUIC-сервер не ответил: UDP/443 не проходит целиком —\n"
               "    режет провайдер (ТСПУ), роутер или файрвол. Браузеры откатываются\n"
               "    на TCP, поэтому сайты открываются, но первый заход медленнее,\n"
               "    а видео/звонки поверх QUIC работают хуже.%s\n", C::RED, C::RST);
    } else if (!ok.empty()) {
        printf("  %s→ QUIC работает выборочно: одни имена отвечают, другие — нет.\n"
               "    Похоже на фильтрацию QUIC по SNI: ТСПУ расшифровывает Initial\n"
               "    так же, как эта программа, и молча дропает запрещённые имена.%s\n",
               C::YEL, C::RST);
        if (fallback)
            printf("  %s  %d из них по TCP открылись — блокируется именно QUIC, а не сайт.%s\n",
                   C::GRY, fallback, C::RST);
    } else {
        printf("  %s→ Ответа на QUIC нет (%d соед.) — мало данных для вывода; стоит\n"
               "    повторить запись подольше.%s\n", C::YEL, nDrop, C::RST);
    }
    printf("  %sWireshark: quic.long.packet_type==0 — только Initial; поле\n"
           "  tls.handshake.extensions_server_name работает и для QUIC.%s\n", C::GRY, C::RST);
}

// ------------------------------------------------------------------
// ДЕТЕКТ БЛОКИРОВКИ/ОТСУТСТВИЯ ИНТЕРНЕТА
//
// Мотивация: если в роутере абонента настроен антицензурный сервис (AntiZapret
// и подобные), а сам туннель не поднялся, картина в дампе очень характерная —
// много DNS-запросов и ответов, но ни одного полезного TCP/UDP-соединения к
// разрешённым IP. Штатный analyzeConnIssues такую ситуацию не отмечает: у него
// просто «нет проблемных TCP-соединений» (их вообще нет).
//
// Что детектируется:
//   1) DNS-only паттерн: DNS работает, но соединений на разрешённые IP нет.
//   2) Домены сервисов обхода блокировок (AntiZapret и производные).
//   3) NCSI probe без последующего HTTP — Windows покажет «нет интернета».
//   4) Split DNS query — тот же id ушёл на два DNS-сервера почти одновременно
//      (типично для настроек защиты от DNS-подмены).
//   5) DNS-retry шторм — приложения многократно переспрашивают домены, а
//      ответа нет или по полученным адресам не подключиться.
//   6) Запросы к ресурсам, ограниченным в РФ (справочно).
// ------------------------------------------------------------------

// Возвращает slug сервиса обхода блокировок, если домен на него похож.
// Специфический шаблон таких сервисов — kws1..kwsN.<slug>.co.uk / .ru,
// где slug — русская транслитерация ("noskomnadzor","pomogite" и т.д.).
static const char* antiCensorshipSlug(const std::string& domain) {
    static const char* slugs[] = {
        "noskomnadzor", "notelega", "antizapret", "antifilter",
        "pyatdesyatdva", "sorokodin", "sadnews", "pomogite", "cakeisalie",
        "ebally", "pclead", "nocensor", "nomessages", "obhod", "obojti",
        nullptr
    };
    for (int i = 0; slugs[i]; ++i)
        if (domain.find(slugs[i]) != std::string::npos) return slugs[i];
    return nullptr;
}

void analyzeConnectivityFailure(const std::vector<Packet>& packets,
                                const std::string& localIp) {
    auto isLocal = [&](const std::string& ip) {
        return isLocalIp(ip) || (!localIp.empty() && ip == localIp);
    };

    std::set<std::string>            resolvedIps;      // IP из ответов A/AAAA
    std::map<std::string, std::set<std::string>> domainIps; // домен -> адреса
    std::map<std::string, int>       domainQueries;    // домен -> сколько раз запрошен
    // Повтор — запрос того же клиента на то же имя и тот же тип не позже 5 с
    // после предыдущего. Просто «запросов ≥ N» не годится: браузер на каждое
    // имя шлёт A + AAAA + HTTPS, а в дампе с роутера одно имя спрашивают
    // несколько устройств; при коротком TTL имя переспрашивают и штатно.
    struct LastQ { long long t = -1; std::string id, dst; };
    std::map<std::string, LastQ>     lastQ;            // клиент|домен|тип -> прошлый запрос
    std::map<std::string, int>       domainRepeats;    // домен -> число повторов
    // запросы по ключу клиент|порт|id: когда ушёл и пришёл ли ответ — повтор
    // без ответа и повтор при исправном ответе означают разное
    struct QInfo { std::string domain; long long t = -1; bool answered = false; };
    std::map<std::string, QInfo>     queries;
    std::vector<std::string>         queryOrder;
    std::set<std::string>            dnsServers;
    std::map<std::string, std::string> idDomain;          // клиент|порт|id -> домен
    std::map<std::string, std::map<std::string, long long>> idToDsts; // клиент|порт|id -> dst -> t
    std::map<std::string, long long> domainFirstQ;        // домен -> время первого запроса
    std::map<std::string, int>       antiCensDomains;
    std::set<std::string>            blockedDomains;

    long long dnsQ = 0, dnsResp = 0, dnsTcpPkts = 0, ntpPkts = 0;

    std::set<std::string> peerIpsTcpAny;    // куда клиент пытался подключиться (TCP)
    std::set<std::string> peerIpsUdpAny;    // куда клиент слал UDP (кроме 53/123)
    std::set<std::string> peerIpsWithData;  // соединения с полезной нагрузкой
    std::set<std::string> peerIpsDataIn;    // от кого пришли данные (соединение работает)
    std::set<std::string> peerIpsTried;     // куда клиент сам что-то слал (TCP/UDP/ICMP)

    // время с поправкой на полночь: иначе запрос после 00:00 выглядел бы
    // «раньше» предыдущего и считался повтором, а хвост дампа — не хвостом
    const std::vector<long long> absT = absTimes(packets);
    long long tLast = -1;
    for (long long t : absT) if (t > tLast) tLast = t;

    for (size_t pi = 0; pi < packets.size(); pi++) {
        const Packet& p = packets[pi];
        if (!p.valid) continue;

        // ==== DNS ====
        if (p.srcPort == 53 || p.dstPort == 53) {
            // TCP/53: сообщения собирает DnsTcpReassembler и кладёт в пакет, которым
            // сообщение завершилось (лишние — в пакеты-копии нулевой длины); сегменты
            // без готового сообщения (ACK, куски, рукопожатие) пропускаем
            if (p.proto == "TCP") {
                if (p.length > 0) dnsTcpPkts++;
                if (p.dnsQuery.empty() && !p.dnsIsResponse) continue;
            }
            // ключ запроса — (IP клиента, порт клиента, id), см. analyzeDnsAnomalies
            if (!p.dnsIsResponse && !p.dnsQuery.empty()) {
                dnsQ++;
                dnsServers.insert(p.dstIp);
                std::string key = p.srcIp + "|" + std::to_string(p.srcPort) + "|" + p.dnsId;
                idDomain[key] = p.dnsQuery;
                if (domainQueries.find(p.dnsQuery) == domainQueries.end())
                    queryOrder.push_back(p.dnsQuery);
                domainQueries[p.dnsQuery]++;
                const long long t = absT[pi];
                idToDsts[key][p.dstIp] = t;
                if (!p.dnsId.empty()) {
                    QInfo& qi = queries[key];
                    qi.domain = p.dnsQuery;
                    qi.t = t;                  // тот же id повторно — считаем от последней отправки
                }
                LastQ& lq = lastQ[p.srcIp + "|" + p.dnsQuery + "|" + std::to_string(p.dnsQtype)];
                if (lq.t >= 0 && t >= 0 && t - lq.t < 5000000LL) {
                    const bool sameId = lq.id == p.dnsId;
                    // тот же id на другой сервер — это «сплит» (считается ниже), тот же
                    // id туда же через ≤2 мс — пакет, записанный дважды (захват с «any»)
                    const bool split = sameId && lq.dst != p.dstIp;
                    const bool dup = sameId && lq.dst == p.dstIp && t - lq.t <= 2000;
                    if (!split && !dup) domainRepeats[p.dnsQuery]++;
                }
                lq.t = t; lq.id = p.dnsId; lq.dst = p.dstIp;
                if (domainFirstQ.find(p.dnsQuery) == domainFirstQ.end()) domainFirstQ[p.dnsQuery] = t;
                if (auto s = antiCensorshipSlug(p.dnsQuery))
                    antiCensDomains[std::string(s)]++;
                if (isCommonlyBlockedDomain(p.dnsQuery))
                    blockedDomains.insert(p.dnsQuery);
            } else if (p.dnsIsResponse) {
                dnsResp++;
                const std::string key = p.dstIp + "|" + std::to_string(p.dstPort) + "|" + p.dnsId;
                auto qa = queries.find(key);
                if (qa != queries.end()) qa->second.answered = true;   // любой ответ, и NXDomain
                std::vector<std::string> ans = p.dnsAnswers;
                if (ans.empty() && !p.dnsAnswerIp.empty()) ans.push_back(p.dnsAnswerIp);
                if (!ans.empty()) {
                    auto it = idDomain.find(key);
                    for (const auto& ip : ans) {
                        resolvedIps.insert(ip);
                        if (it != idDomain.end()) domainIps[it->second].insert(ip);
                    }
                }
            }
            continue;
        }

        // ==== NTP ====
        if (p.srcPort == 123 || p.dstPort == 123) { ntpPkts++; continue; }

        // ==== остальной трафик — потенциальные полезные соединения ====
        // Смотрим на peer со стороны абонента (наружу). Ровно одна сторона
        // должна быть своей: транзит и чужие хосты в записи иначе выглядели бы
        // как «ответ абоненту» от их отправителя.
        const bool sLoc = isLocal(p.srcIp), dLoc = isLocal(p.dstIp);
        if (sLoc == dLoc) continue;
        std::string peer = sLoc ? p.dstIp : p.srcIp;
        if (isPrivateIp(peer)) continue;

        if (p.proto == "TCP") {
            peerIpsTcpAny.insert(peer);
            if (p.length > 0) peerIpsWithData.insert(peer);
        } else if (p.proto == "UDP") {
            peerIpsUdpAny.insert(peer);
            if (p.length > 0) peerIpsWithData.insert(peer);
        }
        if (peer == p.dstIp) peerIpsTried.insert(peer);
        // ICMP от самого адреса (эхо-ответ на ping) — хост досягаем; отказы от
        // промежуточных роутеров приходят с их адресов и сюда не попадают
        else if (((p.proto == "TCP" || p.proto == "UDP") && p.length > 0) || p.proto == "ICMP")
            peerIpsDataIn.insert(peer);
    }

    if (dnsQ == 0) return; // без DNS не с чем сравнивать

    // Считаем split-queries: тот же transaction id ушёл на >=2 DNS в окне <500мс
    long long splitCount = 0;
    for (auto& kv : idToDsts) {
        auto& dsts = kv.second;
        if (dsts.size() < 2) continue;
        long long mn = LLONG_MAX, mx = LLONG_MIN;
        for (auto& kv2 : dsts) { if (kv2.second < mn) mn = kv2.second; if (kv2.second > mx) mx = kv2.second; }
        if (mx - mn < 500000) splitCount++;
    }

    // Сколько разрешённых ДОМЕНОВ не получили соединения ни к одному из своих
    // адресов. Считаем по доменам и по всем A/AAAA: раньше брались отдельные IP
    // и только первая A-запись, а клиент часто идёт на вторую — отсюда ложные
    // «недоступные». Домены, запрошенные в последние секунды (tailUs), не считаем.
    long long resolvedDomains = 0, resolvedNoConn = 0;
    for (const auto& kv : domainIps) {
        auto fq = domainFirstQ.find(kv.first);
        if (fq != domainFirstQ.end() && fq->second >= 0 && tLast >= 0 &&
            tLast - fq->second < cfg().tailUs) continue;
        resolvedDomains++;
        bool conn = false;
        for (const auto& ip : kv.second)
            if (peerIpsTcpAny.count(ip) || peerIpsUdpAny.count(ip)) { conn = true; break; }
        if (!conn) resolvedNoConn++;
    }

    // NCSI probe (Windows-check интернета). 131.107.255.255 — это лишь ожидаемый
    // DNS-ОТВЕТ для dns.msftncsi.com, HTTP туда не ходит. Сама HTTP-проба идёт
    // на www.msftconnecttest.com / www.msftncsi.com, а они живут на CDN с
    // меняющимися адресами — поэтому берём их IP из DNS-ответов этого же дампа.
    bool ncsiDns = false, ncsiHttp = false;
    std::set<std::string> ncsiHttpIps;
    for (const auto& d : queryOrder) {
        if (!domainEndsWith(d, "msftncsi.com") && !domainEndsWith(d, "msftconnecttest.com"))
            continue;
        ncsiDns = true;
        if (domainEndsWith(d, "dns.msftncsi.com")) continue;   // DNS-проверка, не HTTP
        auto it = domainIps.find(d);
        if (it != domainIps.end()) ncsiHttpIps.insert(it->second.begin(), it->second.end());
    }
    // успех = сервер пробы прислал данные (HTTP-ответ)
    for (const auto& p : packets)
        if (p.proto == "TCP" && p.length > 0 && ncsiHttpIps.count(p.srcIp))
            { ncsiHttp = true; break; }
    // адресов пробы не знаем (DNS-ответа нет в дампе / не разобран) — судить
    // о результате нельзя, и ложная тревога хуже молчания
    if (ncsiHttpIps.empty()) ncsiHttp = true;

    // Retry-шторм: имя переспрашивают раз за разом с интервалом до 5 с. Делим
    // по исходу: 1) ответа нет — приложение переспрашивает по таймауту, это и
    // есть проблема; 2) ответ есть, но ни с одного адреса имени не пришло
    // данных — приложение не может подключиться и пробует снова; 3) ответ есть
    // и соединение работает (или имени нет — NXDomain) — так ведёт себя само
    // приложение (короткий TTL, нет кэша), о связи это ничего не говорит.
    std::map<std::string, int> unanswered;      // домен -> запросов без ответа
    for (const auto& kv : queries) {
        const QInfo& q = kv.second;
        if (q.answered) continue;
        // запрос в самом конце дампа: ответ мог просто не попасть в запись
        if (q.t >= 0 && tLast >= 0 && tLast - q.t < cfg().tailUs) continue;
        unanswered[q.domain]++;
    }
    struct Retry { std::string domain; int repeats = 0, noAnswer = 0; };
    std::vector<Retry> retryNoAnswer, retryNoConn;
    int retryOk = 0;
    for (auto& kv : domainRepeats) {
        if (kv.second < 3) continue;
        auto ua = unanswered.find(kv.first);
        const int na = ua == unanswered.end() ? 0 : ua->second;
        // единичная потеря UDP среди десятков отвеченных повторов — не причина шторма
        if (na > 0 && na * 3 >= kv.second) { retryNoAnswer.push_back({kv.first, kv.second, na}); continue; }
        // «не подключиться» — только если клиент действительно ходил на адреса
        // имени и ни один не ответил; адреса получил, но не ходил (проверки
        // связности Android/Windows, префетч браузера) — это не отказ
        bool tried = false, works = false;
        auto di = domainIps.find(kv.first);
        if (di != domainIps.end())
            for (const auto& ip : di->second) {
                if (peerIpsTried.count(ip)) tried = true;
                if (peerIpsDataIn.count(ip)) { works = true; break; }
            }
        if (tried && !works) retryNoConn.push_back({kv.first, kv.second, na});
        else retryOk++;
    }
    auto byRepeats = [](const Retry& a, const Retry& b) { return a.repeats > b.repeats; };
    std::sort(retryNoAnswer.begin(), retryNoAnswer.end(), byRepeats);
    std::sort(retryNoConn.begin(), retryNoConn.end(), byRepeats);

    // Ограниченные в РФ домены — только те, к адресам которых соединений не
    // было (запросы к YouTube есть почти в каждом дампе, а сами по себе они
    // ничего не значат). Запрошенные в последние секунды записи не берём.
    std::vector<std::string> blockedNoConn;
    for (const auto& d : blockedDomains) {
        auto fq = domainFirstQ.find(d);
        if (fq != domainFirstQ.end() && fq->second >= 0 && tLast >= 0 &&
            tLast - fq->second < cfg().tailUs) continue;
        bool conn = false;
        auto di = domainIps.find(d);
        if (di != domainIps.end())
            for (const auto& ip : di->second)
                if (peerIpsTcpAny.count(ip) || peerIpsUdpAny.count(ip)) { conn = true; break; }
        if (!conn) blockedNoConn.push_back(d);
    }

    long long totalConnPeers = (long long)peerIpsTcpAny.size() + (long long)peerIpsUdpAny.size();
    bool dnsOnly = (dnsResp >= 5 && resolvedIps.size() >= 3 && totalConnPeers == 0);
    bool almostDnsOnly = (!dnsOnly && dnsResp >= 20 && resolvedIps.size() >= 10
                          && totalConnPeers <= 2 && peerIpsWithData.empty());

    // Печатаем блок только если есть о чём говорить. Сплит DNS — особенность
    // настройки, а не проблема: сам по себе блок не открывает.
    bool anyFinding = dnsOnly || almostDnsOnly ||
                      !antiCensDomains.empty() ||
                      (ncsiDns && !ncsiHttp) ||
                      !retryNoAnswer.empty() || !retryNoConn.empty() ||
                      !blockedNoConn.empty();
    if (!anyFinding) return;

    printf("\n%s=== ДЕТЕКТ БЛОКИРОВКИ / ПРОБЛЕМ ИНТЕРНЕТА ===%s\n", C::BOLD, C::RST);
    printf("  DNS-запросов: %lld  (уникальных доменов: %d)   DNS-ответов: %lld  (разрешено IP: %d)\n",
           dnsQ, (int)queryOrder.size(), dnsResp, (int)resolvedIps.size());
    if (dnsTcpPkts > 0) printf("  DNS over TCP: %lld пакетов (ответ по UDP не влез/обрезан или UDP/53 режется — резерв на TCP/53)\n", dnsTcpPkts);
    if (ntpPkts > 0)    printf("  NTP-обмен:   %lld пакетов (сверка времени работает)\n", ntpPkts);

    if (dnsOnly || almostDnsOnly) {
        // Дамп, снятый с фильтром захвата («port 53», «udp port 53»), выглядит
        // точно так же: DNS есть, остального нет. Если в дампе вообще нет ничего,
        // кроме DNS/NTP/DHCP/mDNS, — вывод почти наверняка ложный.
        long long otherPkts = 0;
        for (const Packet& p : packets) {
            if (p.proto != "TCP" && p.proto != "UDP") { otherPkts++; continue; }
            const int a = p.srcPort, b = p.dstPort;
            auto svc = [&](int x) { return a == x || b == x; };
            if (svc(53) || svc(123) || svc(67) || svc(68) || svc(5353) || svc(5355)) continue;
            otherPkts++;
        }
        if (otherPkts == 0) {
            printf("\n%s[?] В дампе ТОЛЬКО DNS/NTP/DHCP — ни одного другого пакета.%s\n", C::YEL, C::RST);
            printf("      Скорее всего, захват сделан с фильтром (например «port 53»), и тогда\n");
            printf("      вывод «DNS работает, а соединений нет» ложный. Попросите снять дамп\n");
            printf("      без фильтра. Если фильтра не было — см. причины ниже.\n");
        }
        printf("\n%s[!!!] DNS работает, но интернет-соединений нет.%s\n",
               otherPkts == 0 ? C::YEL : C::RED, C::RST);
        printf("      Резолв доменов идёт, а к разрешённым IP (%d шт.) не ушёл ни один\n", (int)resolvedIps.size());
        printf("      полезный пакет TCP/UDP. Клиент как будто «выпущен» только в DNS.\n");
        printf("      %sЧастые причины:%s\n", C::BOLD, C::RST);
        printf("        • В роутере настроен обход блокировок (VPN/anti-censorship),\n");
        printf("          но сам туннель не поднялся — трафик уходит в мёртвый интерфейс.\n");
        printf("        • Роутер выпускает наружу только 53/udp и 123/udp (жёсткий firewall).\n");
        printf("        • Провайдер режет соединения на транспорте (SNI/DPI/blackhole).\n");
    } else if (totalConnPeers > 0 && resolvedDomains >= 10 &&
               resolvedNoConn * 10 > resolvedDomains * 7) {
        // Только справка: браузер резолвит ссылки заранее (DNS-prefetch) и
        // часто так и не подключается, а приложения берут адрес из кэша.
        printf("\n%s[i] Из %lld разрешённых доменов к %lld соединений не было.%s\n",
               C::GRY, resolvedDomains, resolvedNoConn, C::RST);
        printf("%s    Чаще всего это DNS-prefetch браузера; сама по себе блокировку НЕ\n"
               "    доказывает. Смотрите «SYN без ответа» и SNI-блокировки выше.%s\n", C::GRY, C::RST);
    }

    if (!antiCensDomains.empty()) {
        printf("\n%s[!] Обнаружены запросы к доменам сервисов обхода блокировок:%s\n", C::YEL, C::RST);
        for (auto& kv : antiCensDomains)
            printf("      *.%s.* — %d запрос(ов)\n", kv.first.c_str(), kv.second);
        printf("    Признак того, что у абонента настроен AntiZapret VPN или подобный\n");
        printf("    антицензурный сервис (в роутере или на устройстве). Если при этом\n");
        printf("    полезного трафика к разрешённым IP нет — %sсервис у него НЕ РАБОТАЕТ.%s\n",
               C::RED, C::RST);
    }

    if (ncsiDns && !ncsiHttp) {
        printf("\n%s[!] Windows проверяла интернет (dns.msftncsi.com / msftconnecttest.com),%s\n",
               C::YEL, C::RST);
        printf("    адрес пробы разрешился, но HTTP-ответа от него в дампе нет. Windows\n");
        printf("    покажет пользователю «Нет подключения к Интернету» в трее.\n");
    }

    if (splitCount > 0) {
        printf("\n%s[i] Клиент шлёт один и тот же DNS-запрос сразу на 2 сервера (%lld раз).%s\n",
               C::GRY, splitCount, C::RST);
        printf("%s    Особенность настройки (роутерные обходчики, резолвер с несколькими\n"
               "    апстримами), а не проблема.%s\n", C::GRY, C::RST);
    }

    // повтор — запрос того же имени и типа не позже 5 с после прошлого
    if (!retryNoAnswer.empty()) {
        printf("\n%s[!] Имя переспрашивают снова и снова, а ответа DNS нет%s (повтор — не\n",
               C::YEL, C::RST);
        printf("    позже 5 с после прошлого запроса того же типа): DNS-сервер не отвечает\n");
        printf("    на эти имена или ответы теряются по пути.\n");
        int sh = 0;
        for (const auto& r : retryNoAnswer) {
            if (sh++ >= 6) { printf("      ... ещё %d\n", (int)retryNoAnswer.size() - 6); break; }
            // в фильтре Wireshark имя без точки в конце, иначе он ничего не найдёт
            std::string q = r.domain;
            if (!q.empty() && q.back() == '.') q.pop_back();
            printf("      %-42s повторов: %d, запросов без ответа: %d  [dns.qry.name==\"%s\"]\n",
                   r.domain.c_str(), r.repeats, r.noAnswer, q.c_str());
        }
    }
    if (!retryNoConn.empty()) {
        printf("\n%s[!] Имя переспрашивают снова и снова: DNS отвечает, но ни с одного из%s\n",
               C::YEL, C::RST);
        printf("    полученных адресов, куда ходил клиент, не пришло ответа — приложение не\n");
        printf("    может подключиться и пробует заново. В скобках — адреса, на которые\n");
        printf("    были попытки; их соединения смотрите выше.\n");
        int sh = 0;
        for (const auto& r : retryNoConn) {
            if (sh++ >= 6) { printf("      ... ещё %d\n", (int)retryNoConn.size() - 6); break; }
            std::string ips;
            auto di = domainIps.find(r.domain);
            if (di != domainIps.end()) {
                int n = 0;
                for (const auto& ip : di->second) {
                    if (!peerIpsTried.count(ip)) continue;
                    if (n++ >= 3) { ips += ", ..."; break; }
                    ips += (ips.empty() ? "" : ", ") + ip;
                }
            }
            printf("      %-42s повторов: %d  (%s)\n", r.domain.c_str(), r.repeats, ips.c_str());
        }
    }
    if (retryOk > 0)
        printf("\n%s[i] Часто переспрашивают%s имён: %d, но DNS на них отвечает, а соединение\n"
               "    работает или его и не открывали (проверки связи системы, префетч; или\n"
               "    имени нет) — так ведёт себя само приложение (короткий TTL, нет кэша),\n"
               "    не проблема связи.%s\n", C::GRY,
               (retryNoAnswer.empty() && retryNoConn.empty()) ? "" : " ещё", retryOk, C::RST);

    if (!blockedNoConn.empty()) {
        printf("\n  Ресурсы, ограниченные в РФ: имя запрашивали, а соединений не было:\n");
        int sh = 0;
        for (const auto& d : blockedNoConn) {
            if (sh++ >= 8) { printf("      ... ещё %d\n", (int)blockedNoConn.size() - 8); break; }
            printf("      %s\n", d.c_str());
        }
        printf("  Для них это ожидаемый эффект блокировки.\n");
    }
}

// ------------------------------------------------------------------
// «Заморозка» после ~16 КБ. На части направлений (зарубежный хостинг:
// Hetzner, DigitalOcean, OVH и т.п.) ТСПУ пропускает первые ~15–20 КБ ответа
// сервера, а дальше молча отбрасывает его пакеты. В дампе: рукопожатие и
// начало ответа прошли, затем новые входящие данные обрываются, клиент ещё
// шлёт ACK/повторы (или сервер — повторы уже принятого), и соединение так и
// висит без RST/FIN.
// ------------------------------------------------------------------
// Соединение «встало» после freeze_min..freeze_max КБ ответа: без RST/FIN,
// новых данных нет дольше freeze_silence, а повторы без ответа ещё идут
// (ретрансмиты, неотвеченные keepalive/FIN — см. laterPkts в buildTcpConnTable).
// Возвращает длительность тишины (мкс) или -1. Хостинг здесь не проверяется.
static long long connFreeze16k(const TcpConnTable& tt, const TcpConnState& c) {
    const AppConfig& k = cfg();
    if (!tt.anyInboundTcp || tt.tEnd < 0) return -1;
    if (!c.ch && c.rport != 443) return -1;
    if (c.inRst || c.inFin) return -1;
    if (c.inUniqBytes < k.freezeMinBytes || c.inUniqBytes > k.freezeMaxBytes) return -1;
    if (c.lastNewData < 0) return -1;
    long long silence = tt.tEnd - c.lastNewData;
    if (silence < k.freezeSilenceUs || c.laterPkts < k.freezeLaterPkts) return -1;
    return silence;
}

void analyzeFreeze16k(const TcpConnTable& tt,
                      const std::unordered_map<std::string, IpInfo>* ipCache) {
    if (!tt.anyInboundTcp || tt.tEnd < 0) return;
    const AppConfig& k = cfg();
    struct Hit { const TcpConnState* c; long long silence; };
    std::map<std::string, std::vector<Hit>> byIp;
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        long long silence = connFreeze16k(tt, c);
        if (silence < 0) continue;
        if (!isForeignHosting(ipInfoOf(ipCache, c.ip))) continue;
        byIp[c.ip].push_back({ &c, silence });
    }
    if (byIp.empty()) return;

    bool strong = false;
    for (const auto& kv : byIp) if (kv.second.size() >= 2) strong = true;

    printf("\n%s=== ЗАМОРОЗКА ПОСЛЕ ~16 КБ (зарубежный хостинг) ===%s\n", C::BOLD, C::RST);
    int shownIp = 0;
    for (const auto& kv : byIp) {
        if (shownIp++ >= 8) { printf("  ... ещё адресов: %d\n", (int)byIp.size() - 8); break; }
        const IpInfo* ii = ipInfoOf(ipCache, kv.first);
        printf("  %s%s%s  (%s, %s %s) — зависших соединений: %d\n",
               C::BWHT, kv.first.c_str(), C::RST, ii->country.c_str(),
               ii->asn.c_str(), ii->org.c_str(), (int)kv.second.size());
        int sh = 0;
        for (const auto& h : kv.second) {
            if (sh++ >= 4) { printf("      ... ещё %d\n", (int)kv.second.size() - 4); break; }
            printf("      :%d лок. порт %d%s%s — принято %.1f КБ, затем %.0f с без новых данных,"
                   " %d повторов без ответа\n",
                   h.c->rport, h.c->lport,
                   h.c->sni.empty() ? "" : "  SNI ", h.c->sni.c_str(),
                   h.c->inUniqBytes / 1024.0, h.silence / 1e6, h.c->laterPkts);
        }
        printf("      %sWireshark: %s%s\n", C::GRY, connWsFilter(*kv.second.front().c).c_str(), C::RST);
    }
    if (strong)
        printf("  %sК одному адресу несколько соединений встали на одном объёме — характерный\n"
               "  почерк ограничения ТСПУ «~16 КБ к зарубежному хостингу» (сайты/VPN на Hetzner,\n"
               "  DigitalOcean, OVH… открываются частично или не грузятся вовсе).%s\n",
               C::RED, C::RST);
    else
        printf("  %sСоединение встало, получив %lld–%lld КБ, без RST/FIN. Похоже на ограничение ТСПУ\n"
               "  «~16 КБ к зарубежному хостингу», но одиночный случай может быть и зависанием\n"
               "  самого сервера — сравните с другими ресурсами на том же хостинге.%s\n",
               C::YEL, k.freezeMinBytes / 1024, k.freezeMaxBytes / 1024, C::RST);
}

// ------------------------------------------------------------------
// ПРИЧИНЫ БЛОКИРОВОК. По каждому ресурсу (домен из SNI/Host/DNS, иначе IP)
// сводим все его соединения к ОДНОМУ коду — самому конкретному из найденных,
// и к нему — готовая подсказка для техподдержки.
// ------------------------------------------------------------------
// block = false — не признак блокировки, выводится отдельно (blockReasonIsBlock)
struct ReasonDef { const char* code; int prio; const char* title; const char* advice; bool block = true; };
static const ReasonDef kReasonDefs[] = {
    { "HTTP_STUB", 0, "HTTP-заглушка о блокировке",
      "Вместо сайта пришла страница-заглушка (реестр РКН). Сеть исправна, ресурс ограничен "
      "по закону; по HTTPS тот же сайт обычно режется уже по SNI." },
    { "TLS_RST_FORGED", 1, "Поддельный RST (инъекция DPI)",
      "Соединение рвёт оборудование по пути, а не сервер (TTL/время/поведение сервера это "
      "показывают). Ресурс ограничен на ТСПУ; авария на нашей сети тут ни при чём." },
    { "TLS_RST", 2, "RST сразу после ClientHello",
      "Сброс сразу после ClientHello, но признаков подделки нет — возможна блокировка по SNI "
      "либо отказ самого сервера. Проверьте ресурс с другой сети (мобильный интернет)." },
    { "TLS_DROP", 3, "Молчаливый дроп после ClientHello",
      "TCP поднялся, ClientHello ушёл, в ответ — тишина. Почерк блокировки по SNI на ТСПУ. "
      "Если с других сетей открывается — это блокировка, а не проблема у абонента." },
    { "TCP16", 4, "Обрыв после ~16 КБ",
      "Начало ответа проходит, дальше данные перестают идти без RST/FIN. Типично для "
      "ограничения ТСПУ к зарубежным хостингам (Hetzner, DigitalOcean, OVH…): сайт грузится "
      "частично, VPN подключается, но не работает. Подтвердите режимом «Тест 16 КБ»." },
    { "SYN_DROP", 5, "Нет ответа на SYN",
      "Ни SYN-ACK, ни RST на повторные попытки — адрес недоступен целиком: блокировка по IP "
      "или лежит сервер/маршрут. Сравните трассировкой (режим 3) и с другой сети." },
    { "UDP_DROP", 6, "UDP без ответа (QUIC / VPN)",
      "UDP уходит, ответов нет. Для QUIC браузер сам откатится на TCP; для VPN "
      "(WireGuard, AmneziaWG и т.п.) — протокол, скорее всего, режется ТСПУ." },
    { "UDP_SESSION", 7, "UDP-сессия оборвалась (игра / голос)",
      "Сервер сначала отвечал, потом замолчал, а абонент шлёт дальше и переподключается — "
      "игра в это время выдаёт ошибку подключения. Это не блокировка по реестру: ответы "
      "теряются дальше по пути (CGNAT, транзит) или сервер сбросил сессию. Проверить с "
      "другим внешним адресом / без CGNAT.", false },
};
static const ReasonDef* reasonDef(const std::string& code) {
    for (const auto& d : kReasonDefs) if (code == d.code) return &d;
    return nullptr;
}
const char* blockReasonTitle(const std::string& code) {
    const ReasonDef* d = reasonDef(code);
    return d ? d->title : code.c_str();
}
const char* blockReasonAdvice(const std::string& code) {
    const ReasonDef* d = reasonDef(code);
    return d ? d->advice : "";
}
bool blockReasonIsBlock(const std::string& code) {
    const ReasonDef* d = reasonDef(code);
    return !d || d->block;
}

// onlyIp — ограничиться одним удалённым адресом (режим 2 с целью).
std::vector<BlockReason> collectBlockReasons(
        const std::vector<Packet>& packets, const TcpConnTable& tt,
        const std::unordered_map<std::string, IpInfo>* ipCache,
        const std::string& localIp, const std::string& onlyIp /*= ""*/) {
    auto isLocal = [&](const std::string& ip) {
        return isLocalIp(ip) || (!localIp.empty() && ip == localIp);
    };
    // имя адреса по DNS-ответам из того же дампа; запрос и ответ — по
    // (IP клиента, порт клиента, id), см. analyzeDnsAnomalies
    std::map<std::string, std::string> dnsName, dnsByKey;
    for (const auto& p : packets) {
        if (p.dnsId.empty()) continue;
        if (!p.dnsIsResponse) {
            if (!p.dnsQuery.empty())
                dnsByKey[p.srcIp + "|" + std::to_string(p.srcPort) + "|" + p.dnsId] = p.dnsQuery;
            continue;
        }
        std::string q = p.dnsQuery;
        if (q.empty()) {
            auto it = dnsByKey.find(p.dstIp + "|" + std::to_string(p.dstPort) + "|" + p.dnsId);
            if (it != dnsByKey.end()) q = it->second;
        }
        if (q.empty()) continue;
        for (const auto& a : p.dnsAnswers) dnsName.emplace(a, q);
        if (p.dnsAnswers.empty() && !p.dnsAnswerIp.empty()) dnsName.emplace(p.dnsAnswerIp, q);
    }
    auto ipName = [&](const std::string& ip) {
        auto it = dnsName.find(ip);
        return it != dnsName.end() ? it->second : ip;
    };
    auto connName = [&](const TcpConnState& c) {
        if (!c.sni.empty()) return c.sni;
        if (!c.httpHost.empty()) return c.httpHost;
        return ipName(c.ip);
    };

    struct Agg { std::string ip, code, detail; int prio = 99, n = 0; };
    std::map<std::string, Agg> agg;
    auto put = [&](const std::string& target, const std::string& ip, const char* code,
                   const std::string& detail) {
        const ReasonDef* d = reasonDef(code);
        int pr = d ? d->prio : 50;
        Agg& a = agg[target];
        if (a.ip.empty()) a.ip = ip;
        if (pr < a.prio) { a.prio = pr; a.code = code; a.detail = detail; a.n = 0; }
        if (pr == a.prio) a.n++;
    };
    char b[400];

    std::set<std::string> worked, workedIp;         // получили нормальный ответ
    std::set<std::string> ipWithSynAck;
    struct SynAgg { long long syn = 0; int conns = 0; };
    std::map<std::string, SynAgg> synDrop;
    struct FrzAgg { std::vector<const TcpConnState*> c; long long silence = 0; };
    std::map<std::string, FrzAgg> frz;

    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        if (!onlyIp.empty() && c.ip != onlyIp) continue;
        if (c.synack > 0) ipWithSynAck.insert(c.ip);
        std::string name = connName(c);
        long long fz = -1;
        bool forged = connIsForgedRst(c);

        if (!c.httpBlockMark.empty()) {
            std::string d = "ответ HTTP " + std::to_string(c.httpStatus);
            if (!c.httpLocation.empty()) d += " -> " + c.httpLocation;
            d += "; признак заглушки: «" + c.httpBlockMark + "»";
            put(name, c.ip, "HTTP_STUB", d);
        } else if (connSniRst(c)) {
            if (forged) {
                std::vector<std::string> why; connForgedRst(c, &why);
                std::string d;
                for (const auto& w : why) d += (d.empty() ? "" : "; ") + w;
                put(name, c.ip, "TLS_RST_FORGED", d);
            } else {
                double ms = (c.chTime >= 0 && c.rstTime >= c.chTime) ? (c.rstTime - c.chTime) / 1000.0 : -1;
                if (ms >= 0) snprintf(b, sizeof(b), "RST через %.1f мс после ClientHello, данных от сервера нет", ms);
                else snprintf(b, sizeof(b), "RST после ClientHello, данных от сервера нет");
                put(name, c.ip, "TLS_RST", b);
            }
        } else if (connSilentDrop(tt, c)) {
            if (c.sni.empty()) {
                // текстовый дамп: ClientHello не виден
                put(name, c.ip, "TLS_DROP",
                    "SYN-ACK был, первый сегмент данных на :443 ушёл, ответа нет — ни данных, "
                    "ни RST (SNI в дампе не виден)");
            } else {
                put(name, c.ip, "TLS_DROP", c.ech && isEchPublicName(c.sni)
                    ? "SYN-ACK был, ClientHello (с ECH) ушёл, ответа нет — ни данных, ни RST"
                    : "SYN-ACK был, ClientHello ушёл, ответа нет — ни данных, ни RST");
            }
        } else if (forged) {
            std::vector<std::string> why; connForgedRst(c, &why);
            std::string d = "посреди соединения (принято " + std::to_string(c.serverBytes / 1024) + " КБ)";
            for (const auto& w : why) d += "; " + w;
            put(name, c.ip, "TLS_RST_FORGED", d);
        } else if ((fz = connFreeze16k(tt, c)) >= 0) {
            FrzAgg& f = frz[c.ip];
            f.c.push_back(&c);
            f.silence = std::max(f.silence, fz);
        } else if (c.syn > 0 && c.synack == 0 && !c.inRst && tt.anyInboundTcp &&
                   c.firstTime >= 0 && tt.tEnd - c.firstTime >= cfg().tailUs) {
            SynAgg& s = synDrop[c.ip];
            s.syn += c.syn; s.conns++;
        }
        if (c.serverBytes >= 200 && fz < 0 && c.httpBlockMark.empty() && !forged) {
            worked.insert(name); workedIp.insert(c.ip);
        }
    }
    // «заморозка»: к зарубежному хостингу (если адреса резолвились), иначе —
    // только если к адресу встали хотя бы два соединения
    for (const auto& kv : frz) {
        const IpInfo* ii = ipInfoOf(ipCache, kv.first);
        bool ok = ii ? isForeignHosting(ii) : kv.second.c.size() >= 2;
        if (!ok) continue;
        const TcpConnState& c0 = *kv.second.c.front();
        snprintf(b, sizeof(b), "принято %.1f КБ, затем %.0f с без новых данных; зависших соединений: %d",
                 c0.inUniqBytes / 1024.0, kv.second.silence / 1e6, (int)kv.second.c.size());
        std::string d = b;
        if (ii) d += " (" + ii->country + ", " + ii->org + ")";
        std::string name = connName(c0);
        for (size_t i = 0; i < kv.second.c.size(); i++) put(name, kv.first, "TCP16", d);
    }
    for (const auto& kv : synDrop) {
        if (kv.second.syn < 3 || ipWithSynAck.count(kv.first) || workedIp.count(kv.first)) continue;
        snprintf(b, sizeof(b), "%lld SYN в %d соединени(ях) — ни SYN-ACK, ни RST",
                 kv.second.syn, kv.second.conns);
        put(ipName(kv.first), kv.first, "SYN_DROP", b);
    }

    // UDP: QUIC без единого ответа или VPN-туннель, где ответов почти нет
    // (туннель — то же правило, что в журнале и таблице: udpTunnelStarved)
    struct U : UdpTunnelStat { bool quic = false; std::string sni; };
    std::map<std::string, U> uc;
    // UDP-сессия по 4-tuple, оборвавшаяся со стороны сервера (UdpSessStat).
    // Туннель без ответов — правило выше; работавший и замолчавший — здесь
    struct Sess : UdpSessStat { int rport = 0, lport = 0; bool quic = false; };
    std::map<std::string, Sess> sess;       // "ip|rport|lport"
    long long lastInAny = -1;               // последний входящий пакет любого протокола
    bool anyInboundUdp = false;
    std::vector<long long> absT = absTimes(packets);
    for (size_t i = 0; i < packets.size(); i++) {
        const Packet& p = packets[i];
        bool sLoc = isLocal(p.srcIp), dLoc = isLocal(p.dstIp);
        if (sLoc == dLoc) continue;
        if (!sLoc && absT[i] > lastInAny) lastInAny = absT[i];
        if (p.proto != "UDP") continue;
        std::string ip = sLoc ? p.dstIp : p.srcIp;
        if (!onlyIp.empty() && ip != onlyIp) continue;
        // ответ DNS тоже доказывает, что входящее направление в дампе есть
        if (!sLoc) anyInboundUdp = true;
        if (p.srcPort == 53 || p.dstPort == 53) continue;
        int rport = sLoc ? p.dstPort : p.srcPort;
        int lport = sLoc ? p.srcPort : p.dstPort;
        U& u = uc[ip];
        u.add(p, sLoc, absT[i], rport, lport, ipInfoOf(ipCache, ip));
        if (absT[i] >= 0) {
            Sess& s = sess[ip + "|" + std::to_string(rport) + "|" + std::to_string(lport)];
            s.rport = rport; s.lport = lport;
            s.add(sLoc, absT[i]);
            if (sLoc && (p.quic || rport == 443)) s.quic = true;
        }
        if (!sLoc) continue;
        if (p.quic || rport == 443) u.quic = true;
        if (u.sni.empty() && !p.sni.empty()) u.sni = p.sni;
    }
    if (anyInboundUdp) {
        for (const auto& kv : uc) {
            const U& u = kv.second;
            if (u.t0 < 0) continue;
            std::string name = !u.sni.empty() ? u.sni : ipName(kv.first);
            if (u.kind && udpTunnelStarved(u)) {
                if (u.espOut + u.espIn > 0)
                    snprintf(b, sizeof(b), "%s: ESP уходит (%lld пак. за %.0f с), ESP в ответ нет",
                             u.kind, u.espOut, (u.t1 - u.t0) / 1e6);
                else
                    snprintf(b, sizeof(b), "%s: %lld пакетов за %.0f с, ответов %lld",
                             u.kind, u.out, (u.t1 - u.t0) / 1e6, u.in);
                put(name, kv.first, "UDP_DROP", b);
            } else if (u.in == 0 && u.quic && !u.kind && u.out >= 3 && tt.tEnd - u.t0 >= cfg().tailUs &&
                       !worked.count(name)) {
                snprintf(b, sizeof(b), "QUIC: %lld датаграмм, ответов 0 (по TCP не открылось)", u.out);
                put(name, kv.first, "UDP_DROP", b);
            }
        }
        // Оборвавшаяся UDP-сессия (UdpSessStat::died)
        for (const auto& kv : sess) {
            const Sess& s = kv.second;
            if (s.quic || !s.died(lastInAny)) continue;
            const long long silence = s.silenceUs();
            const std::string ip = kv.first.substr(0, kv.first.find('|'));
            auto ut = uc.find(ip);
            // туннель «почти без ответов» уже выведен правилом выше (UDP_DROP). Туннель,
            // который работал и замолчал, под него не попадает (ответов > 2) — он здесь
            if (ut != uc.end() && ut->second.kind && udpTunnelStarved(ut->second)) continue;
            // название туннеля — только если опознан по порту этой же сессии
            const char* tun = (ut != uc.end() && ut->second.kind &&
                               (ut->second.kindPort == s.rport || ut->second.kindPort == s.lport))
                              ? ut->second.kind : nullptr;
            snprintf(b, sizeof(b), "%s%s: сервер ответил %lld раз, затем замолчал; абонент "
                     "ещё %.0f с слал на порт %d (%lld пак.) — ответов нет",
                     tun ? tun : "UDP-сессия", tun ? " (туннель)" : "",
                     s.in, silence / 1e6, s.rport, s.outAfter);
            put(ipName(ip), ip, "UDP_SESSION", b);
        }
    }

    std::vector<BlockReason> out;
    for (const auto& kv : agg) {
        const Agg& a = kv.second;
        // ресурс, который по другим соединениям работал, — не блокировка
        // (кроме заглушки и «16 КБ»: там мелкие ответы как раз проходят).
        // Рабочий IP гасит только причины уровня адреса: на общем IP CDN
        // соседний домен открывается, а заблокированный по SNI — нет
        // Оборвавшаяся UDP-сессия — тоже: TCP к тому же серверу (вход в игру)
        // работает, а игровой UDP глохнет
        const bool ipLevel = a.code == "SYN_DROP" || a.code == "UDP_DROP";
        if ((worked.count(kv.first) || (ipLevel && workedIp.count(a.ip))) &&
            a.code != "HTTP_STUB" && a.code != "TCP16" && a.code != "UDP_SESSION")
            continue;
        BlockReason r; r.target = kv.first; r.ip = a.ip; r.code = a.code; r.detail = a.detail; r.conns = a.n;
        out.push_back(r);
    }
    std::sort(out.begin(), out.end(), [&](const BlockReason& x, const BlockReason& y) {
        int px = reasonDef(x.code) ? reasonDef(x.code)->prio : 50;
        int py = reasonDef(y.code) ? reasonDef(y.code)->prio : 50;
        return px != py ? px < py : x.target < y.target;
    });
    return out;
}

// ------------------------------------------------------------------
// Средства обхода DPI на стороне абонента (zapret, GoodbyeDPI, ByeDPI,
// SpoofDPI и т.п.). Их приёмы видны в исходящем трафике:
//  • split/disorder — ClientHello режется на крошечный первый сегмент;
//  • fake — перед настоящим ClientHello уходит фейковый с чужим SNI
//    (в одном TCP-соединении два разных SNI);
//  • фейки с малым TTL — пакет доживает до DPI, но не до сервера.
// ------------------------------------------------------------------
void analyzeDpiBypass(const TcpConnTable& tt) {
    std::vector<const TcpConnState*> splitC, multiC, lowTtlC;
    long long lowTtlPkts = 0;
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        bool webish = c.ch || c.rport == 443 || c.rport == 80;
        if (webish && c.firstOutDataLen >= 1 && c.firstOutDataLen <= 5) splitC.push_back(&c);
        if (c.snis.size() > 1) multiC.push_back(&c);
        if (c.lowTtlOut > 0) { lowTtlC.push_back(&c); lowTtlPkts += c.lowTtlOut; }
    }
    // одиночный крошечный сегмент бывает и у обычных программ — нужен повтор
    bool splitSig = (int)splitC.size() >= cfg().splitMinConns;
    if (!splitSig && multiC.empty() && lowTtlC.empty()) return;

    printf("\n%s=== СРЕДСТВА ОБХОДА DPI У АБОНЕНТА ===%s\n", C::BOLD, C::RST);
    auto examples = [](const std::vector<const TcpConnState*>& v, bool withSnis) {
        int sh = 0;
        for (const auto* c : v) {
            if (sh++ >= 3) { printf("      ... ещё %d\n", (int)v.size() - 3); break; }
            std::string s;
            if (withSnis) { for (const auto& x : c->snis) { if (!s.empty()) s += ", "; s += x; } }
            else s = c->sni;
            printf("      %s:%d лок. порт %d%s%s\n", c->ip.c_str(), c->rport, c->lport,
                   s.empty() ? "" : "  SNI ", s.c_str());
        }
    };
    if (splitSig) {
        printf("  %s[!]%s Разрезанный ClientHello: в %d соединениях первый сегмент 1–5 байт\n"
               "      (браузер отправляет ClientHello целиком) — приём split/disorder.\n",
               C::YEL, C::RST, (int)splitC.size());
        examples(splitC, false);
    }
    if (!multiC.empty()) {
        printf("  %s[!]%s Несколько разных SNI в одном TCP-соединении (%d): перед настоящим\n"
               "      ClientHello уходит фейковый с чужим доменом — приём fake.\n",
               C::YEL, C::RST, (int)multiC.size());
        examples(multiC, true);
    }
    if (!lowTtlC.empty()) {
        printf("  %s[!]%s Исходящие пакеты с данными и TTL ≤12 при обычном %d: %lld шт. в %d\n"
               "      соединениях — фейки с малым TTL (доходят до DPI, но не до сервера).\n",
               C::YEL, C::RST, tt.outTtlTypical, lowTtlPkts, (int)lowTtlC.size());
        examples(lowTtlC, false);
    }
    printf("  %sУ абонента, похоже, работает обходчик DPI (zapret / GoodbyeDPI / ByeDPI /\n"
           "  SpoofDPI и т.п.). Он сам может ломать соединения: при жалобах на «не\n"
           "  открываются сайты» попросите временно его отключить и повторить дамп.%s\n",
           C::GRY, C::RST);
}
