// detector_vpn.cpp — признаки VPN/прокси: TLS-клиенты по JA4, VLESS/Reality,
// потоковые признаки туннеля и режим 1 (анализ на VPN с вердиктом).
#include "analyzer_internal.h"

// ------------------------------------------------------------------
// TLS-КЛИЕНТЫ ПО ОТПЕЧАТКУ JA4.
// Группируем ClientHello по JA4: сколько раз встретился, к каким именам и
// серверам. Главный практический сигнал — НЕ-браузерный клиент (или подделка
// под браузер), который ходит на хостинг-серверы: так выглядят Xray/V2Ray/
// sing-box без uTLS и прочие прокси-клиенты. uTLS с fingerprint=chrome
// копирует ClientHello браузера, и по одному JA4 его не отличить — это
// честно пишем в подсказке. targetIp — необязательный фильтр по адресу.
// ------------------------------------------------------------------
void analyzeJa4(const std::vector<Packet>& packets,
                const std::unordered_map<std::string, IpInfo>* ipCache,
                const std::string& targetIp /*= ""*/) {
    struct Agg {
        std::string client; int kind = JA4K_UNKNOWN; long long hellos = 0;
        std::set<std::string> snis, servers, hostingSrv;
    };
    std::map<std::string, Agg> by;
    // адреса из белого списка VPN в «хостинг-серверы» не попадают
    const auto ipW = withVpnWhitelist(packets, ipCache);
    if (ipCache || !ipW.empty()) ipCache = &ipW;
    for (const auto& p : packets) {
        if (p.ja4.empty()) continue;
        if (!targetIp.empty() && p.srcIp != targetIp && p.dstIp != targetIp) continue;
        Agg& a = by[p.ja4];
        a.client = p.tlsClient; a.kind = p.ja4Kind; a.hellos++;
        if (!p.sni.empty()) a.snis.insert(p.sni);
        a.servers.insert(p.dstIp);
        if (ipCache) {
            auto it = ipCache->find(p.dstIp);
            if (it != ipCache->end()) {
                const IpInfo& ii = it->second;
                if ((ii.hosting || looksHostingOrg(ii.org, ii.asn)) && !looksCdnOrg(ii.org) &&
                    !ii.vpnWhite)
                    a.hostingSrv.insert(p.dstIp);
            }
        }
    }
    if (by.empty()) return;

    std::vector<std::pair<std::string, const Agg*>> rows;
    for (auto& kv : by) rows.push_back({ kv.first, &kv.second });
    std::sort(rows.begin(), rows.end(), [](const auto& x, const auto& y) {
        return x.second->hellos > y.second->hellos; });

    printf("\n%s=== TLS-КЛИЕНТЫ (ОТПЕЧАТКИ JA4) ===%s\n", C::BOLD, C::RST);
    auto listSome = [](const std::set<std::string>& s, size_t lim) {
        std::string r; size_t k = 0;
        for (const auto& x : s) {
            if (k == lim) { r += ", … (+" + std::to_string(s.size() - lim) + ")"; break; }
            if (k++) r += ", ";
            r += x;
        }
        return r;
    };
    int suspicious = 0;
    for (const auto& row : rows) {
        const Agg& a = *row.second;
        const char* col = a.kind == JA4K_BROWSER ? C::GRN
                        : a.kind == JA4K_FAKE    ? C::RED
                        : a.kind == JA4K_LIBRARY ? C::YEL : C::GRY;
        printf("  %s%s%s  ClientHello: %lld, серверов: %d\n", C::BWHT, row.first.c_str(), C::RST,
               a.hellos, (int)a.servers.size());
        printf("    %s%s%s\n", col, a.client.c_str(), C::RST);
        if (!a.snis.empty())
            printf("    SNI: %s\n", listSome(a.snis, 4).c_str());
        // «неизвестный» клиент (Android-приложение на OkHttp, QUIC curl и т.п.) —
        // не повод подозревать прокси; метим только явно не-браузерные
        if ((a.kind == JA4K_LIBRARY || a.kind == JA4K_FAKE) && !a.hostingSrv.empty()) {
            suspicious++;
            printf("    %s! не браузер -> хостинг-серверы (%d): %s\n"
                   "      похоже на прокси/VPN-клиент (Xray, V2Ray, sing-box и т.п.)%s\n",
                   a.kind == JA4K_FAKE ? C::RED : C::YEL, (int)a.hostingSrv.size(),
                   listSome(a.hostingSrv, 3).c_str(), C::RST);
        }
    }
    if (suspicious == 0 && ipCache)
        printf("  %sНе-браузерных TLS-клиентов, ходящих на хостинг-серверы, не видно.%s\n",
               C::GRY, C::RST);
    printf("  %sОтпечаток можно проверить в базе ja4db.com. uTLS (Xray/sing-box с\n"
           "  fingerprint=chrome/firefox) копирует ClientHello браузера — по JA4 его не\n"
           "  отличить; выдаёт его скорее хостинг-сервер вместо сайта из SNI.\n"
           "  Wireshark: tls.handshake.type==1 — ClientHello (поле JA4 есть в 4.2+).%s\n",
           C::GRY, C::RST);
}

// ------------------------------------------------------------------
// VLESS/Reality: сервер Reality выдаёт себя за чужой крупный сайт — в SNI
// стоит www.microsoft.com, dl.google.com, www.lovelive-anime.jp и т.п., а
// соединение идёт на обычный VPS. Признаки:
//  • известный «маскировочный» SNI на хостинге (не CDN, не своя сеть бренда);
//  • в этом же дампе DNS резолвил домен из SNI в ДРУГИЕ адреса — клиент
//    ходит не по DNS, а по IP из конфига.
// ------------------------------------------------------------------
static bool isRealityCoverSni(const std::string& sni) {
    static const char* brands[] = {
        "microsoft.com", "apple.com", "icloud.com", "cdn-apple.com", "google.com",
        "yahoo.com", "amazon.com", "cloudflare.com", "samsung.com", "nvidia.com",
        "intel.com", "asus.com", "mozilla.org", "lovelive-anime.jp", "speedtest.net",
        "discord.com", "github.com", "bing.com", "tesla.com", "twitch.tv", "oracle.com",
        "cisco.com", "dell.com", "hp.com", "sony.com",
        // российские домены — маскировка под «белые списки»
        "yandex.ru", "ya.ru", "vk.com", "gosuslugi.ru", "ozon.ru", "wildberries.ru",
        "max.ru", "sberbank.ru", "mail.ru", "rutube.ru"
    };
    std::string s = sni; for (auto& c : s) c = (char)::tolower((unsigned char)c);
    for (auto* b : brands) if (domainEndsWith(s, b)) return true;
    return false;
}

std::vector<RealitySuspect> collectRealitySuspects(
        const std::vector<Packet>& packets, const TcpConnTable& tt,
        const std::unordered_map<std::string, IpInfo>* ipCache) {
    // домен -> все адреса из DNS-ответов (запрос/ответ по клиент|порт|id)
    std::map<std::string, std::string> qByKey;
    std::map<std::string, std::set<std::string>> dnsMap;
    for (const auto& p : packets) {
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
        if (q.empty()) continue;
        for (auto& c : q) c = (char)::tolower((unsigned char)c);
        if (!q.empty() && q.back() == '.') q.pop_back();
        for (const auto& ip : p.dnsAnswers) dnsMap[q].insert(ip);
        if (p.dnsAnswers.empty() && !p.dnsAnswerIp.empty()) dnsMap[q].insert(p.dnsAnswerIp);
    }

    // Белый список проверяем по адресу (AS или DNS), а не по SNI: чужой SNI
    // vk.com на VPS — как раз Reality, и он в список не попадает
    const auto ipW = withVpnWhitelist(packets, ipCache);
    std::map<std::string, RealitySuspect> agg;   // ip|sni
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        if (!c.ch || c.sni.empty() || isEchPublicName(c.sni)) continue;
        const IpInfo* ii = ipInfoOf(&ipW, c.ip);
        if (!isHostingNonCdn(ii) || ii->vpnWhite) continue;
        std::string s = c.sni; for (auto& ch : s) ch = (char)::tolower((unsigned char)ch);
        bool famous = isRealityCoverSni(s);
        auto d = dnsMap.find(s);
        bool mismatch = d != dnsMap.end() && !d->second.empty() && !d->second.count(c.ip);
        if (!famous && !mismatch) continue;
        RealitySuspect& r = agg[c.ip + "|" + s];
        if (r.ip.empty()) { r.ip = c.ip; r.sni = c.sni; r.example = &c; }
        r.famous = r.famous || famous;
        if (mismatch) { r.dnsMismatch = true; r.dnsIps = d->second; }
        r.conns++;
        r.bytes += c.serverBytes + c.outBytes;
    }
    std::vector<RealitySuspect> out;
    for (auto& kv : agg) out.push_back(kv.second);
    std::sort(out.begin(), out.end(),
              [](const RealitySuspect& a, const RealitySuspect& b) { return a.bytes > b.bytes; });
    return out;
}

void printRealitySuspects(const std::vector<RealitySuspect>& rs,
                          const std::unordered_map<std::string, IpInfo>* ipCache) {
    if (rs.empty()) return;
    printf("\n%s=== ПОХОЖЕ НА VLESS/REALITY (чужой SNI на хостинге) ===%s\n", C::BOLD, C::RST);
    int sh = 0;
    for (const auto& r : rs) {
        if (sh++ >= 8) { printf("  ... ещё %d\n", (int)rs.size() - 8); break; }
        const IpInfo* ii = ipInfoOf(ipCache, r.ip);
        printf("  %s%s%s  SNI %s%s%s  (%s, %s %s) — соединений %d, %.1f КБ\n",
               C::BWHT, r.ip.c_str(), C::RST, C::BYEL, r.sni.c_str(), C::RST,
               ii ? ii->country.c_str() : "?", ii ? ii->asn.c_str() : "?",
               ii ? ii->org.c_str() : "?", r.conns, r.bytes / 1024.0);
        if (r.famous)
            printf("      домен крупного сервиса, а адрес — обычный хостинг/VPS\n");
        if (r.dnsMismatch) {
            std::string l; int n = 0;
            for (const auto& ip : r.dnsIps) { if (n++ >= 4) { l += ", …"; break; } if (!l.empty()) l += ", "; l += ip; }
            printf("      DNS в этом дампе резолвил домен в другие адреса (%s) — клиент\n"
                   "      идёт не по DNS, а по IP из своего конфига\n", l.c_str());
        }
        if (r.example)
            printf("      %sWireshark: %s%s\n", C::GRY, connWsFilter(*r.example).c_str(), C::RST);
    }
    printf("  %sТак выглядит VLESS+Reality (Xray/sing-box): сервер «прикидывается» чужим\n"
           "  сайтом. Оба признака сразу — почти наверняка туннель.%s\n", C::GRY, C::RST);
}

FlowEvidence flowVpnEvidence(const TcpConnTable& tt,
                             const std::vector<RealitySuspect>& reality,
                             const std::unordered_map<std::string, IpInfo>* ipCache) {
    FlowEvidence ev;
    // 1) Reality
    {
        int n = 0; long long bytes = 0; std::string first;
        bool both = false;
        for (const auto& r : reality) {
            n++; bytes += r.bytes;
            if (first.empty()) first = r.ip + " (SNI " + r.sni + ")";
            if (r.famous && r.dnsMismatch) both = true;
        }
        if (n > 0) {
            char buf[512];
            snprintf(buf, sizeof(buf),
                "Чужой SNI на хостинге (VLESS/Reality): %s%s, %.0f КБ%s",
                first.c_str(), n > 1 ? " и др." : "", bytes / 1024.0,
                both ? " — известный домен + DNS указывает на другие адреса" : "");
            ev.reasons.push_back(buf);
            ev.score += (both || bytes >= 100 * 1024) ? 2 : 1;
        }
    }
    // 2) JA4 не-браузера к хостингу и 3) долгий двусторонний поток
    struct Rem { long long in = 0, out = 0, dur = 0; int fake = 0, lib = 0; std::string lib4; };
    std::map<std::string, Rem> rem;
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        const IpInfo* ii = ipInfoOf(ipCache, c.ip);   // из computeVpnVerdict — с белым списком
        if (!isHostingNonCdn(ii) || ii->vpnWhite) continue;
        Rem& r = rem[c.ip];
        r.in += c.serverBytes; r.out += c.outBytes;
        if (c.firstTime >= 0 && c.lastTime >= c.firstTime && c.lastTime - c.firstTime > r.dur)
            r.dur = c.lastTime - c.firstTime;
        if (c.ja4Kind == JA4K_FAKE) r.fake++;
        else if (c.ja4Kind == JA4K_LIBRARY) { r.lib++; if (r.lib4.empty()) r.lib4 = c.ja4; }
    }
    int jaScore = 0, longScore = 0;
    for (const auto& kv : rem) {
        const Rem& r = kv.second;
        long long tot = r.in + r.out;
        if (r.fake > 0 && tot >= 20 * 1024 && jaScore < 2) {
            ev.reasons.push_back("К хостингу " + kv.first + " идёт TLS с поддельным «браузерным» "
                                 "отпечатком (uTLS: Xray/sing-box и т.п.)");
            jaScore = 2;
        } else if (r.lib > 0 && tot >= 100 * 1024 && jaScore < 1) {
            ev.reasons.push_back("К хостингу " + kv.first + " идёт TLS не из браузера (JA4 " +
                                 r.lib4 + ") — программа-клиент, возможно VPN/прокси");
            jaScore = 1;
        }
        if (longScore == 0 && r.dur >= cfg().longFlowUs && r.in >= cfg().longFlowMinIn &&
            r.out >= cfg().longFlowMinOut && r.out * 100 >= r.in * 3) {
            char buf[512];
            snprintf(buf, sizeof(buf),
                "Долгий двусторонний поток к хостингу %s: %.0f с, вниз %.1f МБ / вверх %.1f МБ "
                "— для скачивания слишком много исходящего, похоже на туннель",
                kv.first.c_str(), r.dur / 1e6, r.in / 1e6, r.out / 1e6);
            ev.reasons.push_back(buf);
            longScore = 1;
        }
    }
    ev.onlyJa4Lib = ev.score == 0 && jaScore == 1 && longScore == 0;   // Reality не было, uTLS тоже
    ev.score += jaScore + longScore;
    if (ev.score > cfg().flowScoreCap) ev.score = cfg().flowScoreCap;
    return ev;
}

// Сведения об адресе для guessKind: локальный — заглушка «private», без резолва — пустые.
// (org заглушки на экран не выводится: подписи — через localRoleLabel.)
// Ссылка, а не копия: зовётся дважды на каждый пакет, а копия IpInfo —
// это четыре строки. ipCache после резолва не меняется, ссылки стабильны.
static const IpInfo& vpnInfoFor(const std::unordered_map<std::string, IpInfo>* ipCache,
                                const std::string& ip) {
    static const IpInfo kLocalInfo = [] {
        IpInfo i; i.type = "private"; i.country = "-"; i.asn = "-"; i.org = "LocalIP"; return i;
    }();
    static const IpInfo kUnknownInfo;   // public, неизвестно
    if (isLocalIp(ip)) return kLocalInfo;
    if (ipCache) {
        auto it = ipCache->find(ip);
        if (it != ipCache->end()) return it->second;
    }
    return kUnknownInfo;
}

// QUIC-потоки по отпечатку Initial (JA4 'q'). JA4K_LIBRARY у QUIC — стек Go/rustls
// без GREASE (quic-go: Hysteria2/TUIC/Juicity), см. ja4FromHello; браузеры
// (GREASE у Chromium/Safari, метки NSS у Firefox) и curl/OpenSSL — другие виды.
// guessKind видит один пакет и метит весь UDP/443 к хостингу как Hysteria2 —
// уточняем по потоку. Ключ — rip|rport|lport со стороны абонента.
static std::map<std::string, int> quicFlowKinds(const std::vector<Packet>& packets) {
    std::map<std::string, int> quicKind;
    for (const auto& p : packets) {
        if (p.proto != "UDP" || p.ja4.empty()) continue;
        if (!isLocalIp(p.srcIp) || isLocalIp(p.dstIp)) continue;
        std::string k = p.dstIp + "|" + std::to_string(p.dstPort) + "|" + std::to_string(p.srcPort);
        auto it = quicKind.find(k);
        // несколько Initial в потоке и хоть один не Go-стек — поток не VPN
        if (it == quicKind.end() || p.ja4Kind != JA4K_LIBRARY) quicKind[k] = p.ja4Kind;
    }
    return quicKind;
}

// Метка пакета режима 1: guessKind + уточнение UDP/443 по отпечатку QUIC-потока.
// В quicUnknownIp кладётся адрес, если Initial этого потока в дамп не попал.
static std::string vpnPacketKind(const Packet& p, const IpInfo& si, const IpInfo& di,
                                 const std::map<std::string, int>& quicKind,
                                 std::string* quicUnknownIp = nullptr) {
    std::string kind = guessKind(p, si, di);
    if (p.proto == "UDP" && kind.find("Hysteria2/QUIC") != std::string::npos) {
        bool sL = isLocalIp(p.srcIp), dL = isLocalIp(p.dstIp);
        int rp = sL ? p.dstPort : p.srcPort;
        if (sL != dL && rp == 443) {
            std::string rip = sL ? p.dstIp : p.srcIp;
            int lp = sL ? p.srcPort : p.dstPort;
            auto it = quicKind.find(rip + "|443|" + std::to_string(lp));
            if (it == quicKind.end()) {
                kind = "(probably Hysteria2/QUIC)";   // Initial не попал в дамп
                if (quicUnknownIp) *quicUnknownIp = rip;
            } else if (it->second != JA4K_LIBRARY) {
                kind = "(udp/quic)";                  // браузер (GREASE/NSS), curl и т.п. — не Go-стек
            }
        }
    }
    return kind;
}

// «Популярные VPN-страны» — туда чаще всего смотрят туннели/хостинги.
// Один список и для балла гео в вердикте, и для пометки в выводе режима 1.
static bool isVpnCountry(const std::string& c) {
    return c=="NL"||c=="DE"||c=="FI"||c=="FR"||c=="US"||c=="GB"||c=="SE"||c=="LU";
}

// Полный вердикт VPN по дампу (без печати). ipCache может быть nullptr —
// тогда признаки хостинга, гео, CDN и Reality не видны, и баллы могут
// отличаться от режима с резолвом в обе стороны.
VpnVerdict computeVpnVerdict(const std::vector<Packet>& packets, const TcpConnTable& tt,
                             const std::unordered_map<std::string, IpInfo>* ipCache) {
    VpnVerdict v;
    // Белый список VPN (Google, YouTube, Википедия, VK, Госуслуги…): у таких
    // адресов vpnWhite — ни портов, ни флагов баз, ни «формы» трафика. Дальше
    // всё (guessKind, Reality, потоковые признаки) видит уже эту копию.
    const auto ipW = withVpnWhitelist(packets, ipCache);
    if (ipCache || !ipW.empty()) ipCache = &ipW;
    auto infoFor = [&](const std::string& ip) -> const IpInfo& { return vpnInfoFor(ipCache, ip); };
    const std::map<std::string, int> quicKind = quicFlowKinds(packets);

    // агрегация по удалённому (не локальному) IP
    long long vlessBytes = 0; // объём «похоже на vless/туннель поверх 443»
    struct QuicUpDown { long long up = 0, down = 0; };
    std::map<std::string, QuicUpDown> quicUnknownBytes; // UDP/443 к хостингу без разобранного Initial: IP -> байт
    // Совпадения по ТАБЛИЦЕ портов (vpn_*_ports / proxy_ports) на удалённой стороне.
    // Сам номер порта — не доказательство: у P2P-пира (торрент, игра) случайный
    // порт бывает 51820 или 55555, а 8080/8888/4433 слушают обычные веб-сервисы.
    // Поэтому копим по соединению, кто его открыл и сколько через него прошло,
    // и решаем после цикла. Сигнатуры (WireGuard, OpenVPN, прокси по L7,
    // Hysteria2 по QUIC-отпечатку) сюда не входят — они засчитываются сразу.
    struct PortHit {
        std::string ip, proto, name; int rport = 0; bool vpn = false;
        int init = -1;                // 1 — открыл абонент, 0 — удалённая сторона
        bool synSeen = false;         // инициатор по SYN (надёжно), а не по первому пакету
        long long firstUs = -1, bytes = 0;
    };
    std::map<std::string, PortHit> portHits;   // ключ "ip|rport|lport|proto"
    // время — с поправкой на полночь (absTimes): от начала суток поток после 00:00
    // оказывался «раньше» начала записи и шёл за «с начала записи» (midStream)
    const std::vector<long long> absT = absTimes(packets);
    long long captureStartUs = -1;
    for (long long t : absT) if (t >= 0) { captureStartUs = t; break; }
    auto normName = [](std::string s) {
        for (auto& c : s) c = (char)::tolower((unsigned char)c);
        while (!s.empty() && s.back() == '.') s.pop_back();
        return s;
    };
    // адрес -> имена, для которых DNS в дампе вернул этот адрес
    const std::map<std::string, std::set<std::string>> dnsNamesOfIp = dnsNamesByIp(packets);
    // Адреса, где SNI соединения — имя, которое абонент сам разрезолвил в этот
    // же адрес: обычный сайт на хостинге. У Reality SNI чужой, и DNS его на VPS
    // не ведёт. Такой TLS в долю «похоже на VLESS» не идёт.
    std::set<std::string> siteByDns;
    for (const auto& kv : tt.conns) {
        const TcpConnState& c = kv.second;
        if (c.sni.empty()) continue;
        auto dn = dnsNamesOfIp.find(c.ip);
        if (dn != dnsNamesOfIp.end() && dn->second.count(normName(c.sni))) siteByDns.insert(c.ip);
    }
    long long vlessDnsBytes = 0;   // TLS к хостингу, но к сайту по DNS (siteByDns)
    for (size_t i = 0; i < packets.size(); i++) {
        const Packet& p = packets[i];
        const std::string* rip = remoteSideOf(p);   // ровно одна сторона локальная
        if (!rip) continue;
        const std::string& remote = *rip;
        const bool srcLocal = isLocalIp(p.srcIp);
        const int remotePort = srcLocal ? p.dstPort : p.srcPort;
        std::string qUnknown;
        const std::string kind = vpnPacketKind(p, infoFor(p.srcIp), infoFor(p.dstIp),
                                               quicKind, &qUnknown);
        if (!qUnknown.empty()) {
            QuicUpDown& q = quicUnknownBytes[qUnknown];
            (srcLocal ? q.up : q.down) += p.length;
        }

        VpnRemote& fl = v.byRemote[remote];
        fl.bytes += p.length;                       // то же правило, что bytesByRemote
        // MSS из SYN-ACK удалённой стороны: у IPv6 заголовок на 20 байт больше — приводим к IPv4
        if (p.proto == "TCP" && p.mss > 0 && flagHas(p.flags, 'S') && !srcLocal)
            fl.synMss = p.mss + ((remote.find(':') != std::string::npos) ? 20 : 0);
        if (remotePort > 0) fl.remotePorts.insert(remotePort);
        if (!p.sni.empty() && srcLocal) fl.snis.insert(normName(p.sni));
        // «probably vless» (хостинг на 443) — копим объём таких потоков
        if (kind.find("vless") != std::string::npos)
            (siteByDns.count(remote) ? vlessDnsBytes : vlessBytes) += p.length;
        // VPN/прокси-порт засчитываем ТОЛЬКО если он на удалённой (серверной) стороне.
        // (IPsec, не опознанный как VPN точно, guessKind пометил «(ipsec: …)» —
        // VoWiFi или не ясно; это не VPN-порт, см. ipsecClass.) Адрес из белого
        // списка по номеру порта не судим — только по сигнатурам ниже.
        // Поток, опознанный по содержимому как BitTorrent, DHT или STUN (метка на
        // всём потоке), — P2P или звонок, а не туннель: случайный порт пира
        // (10808, 51820, 500…) VPN-портом не считаем, как и guessKind («(torrent)»)
        const bool white = infoFor(remote).vpnWhite;
        const bool p2p = p.l7 == L7_BITTORRENT || p.l7 == L7_BT_DHT || p.l7 == L7_STUN;
        const char* vp = (white || p2p || kind.rfind("(ipsec:", 0) == 0) ? nullptr
                                                                         : vpnPortName(remotePort, p.proto);
        const char* px = (white || p2p) ? nullptr : proxyPortName(remotePort);
        if (vp || px) {
            const int localPort = srcLocal ? p.srcPort : p.dstPort;
            PortHit& h = portHits[remote + "|" + std::to_string(remotePort) + "|" +
                                  std::to_string(localPort) + "|" + p.proto];
            if (h.init < 0) {
                h.ip = remote; h.proto = p.proto; h.rport = remotePort;
                h.vpn = vp != nullptr; h.name = vp ? vp : px;
                h.init = srcLocal ? 1 : 0; h.firstUs = absT[i];
            }
            if (p.proto == "TCP" && flagHas(p.flags, 'S') && !flagHas(p.flags, '.') && !h.synSeen) {
                h.init = srcLocal ? 1 : 0; h.synSeen = true;
            }
            h.bytes += p.length;
        }
        // WireGuard по сигнатуре payload (включая флоу-метку wgType=4 для data-
        // пакетов) — надёжный VPN-признак на ЛЮБОМ порту (напр. 50468).
        if (p.wgType != 0) {
            fl.vpnPort = true; fl.vpnName = "WireGuard";
            fl.vpnPortNum = remotePort; fl.vpnProto = "UDP";
        }
        // OpenVPN и прокси по сигнатуре содержимого — тоже на любом порту
        if (p.l7 == L7_OPENVPN) {
            fl.vpnPort = true; fl.vpnName = "OpenVPN (по сигнатуре)";
            fl.vpnPortNum = remotePort; fl.vpnProto = p.proto;
        }
        if (l7IsProxy(p.l7)) {
            fl.proxyPort = true; fl.proxyName = std::string(l7Name(p.l7)) + " (по сигнатуре)";
            fl.proxyPortNum = remotePort; fl.proxyProto = p.proto;
        }
        // Hysteria2: UDP/443 к хостинг-IP, и QUIC-отпечаток потока — стек Go/rustls
        // (без GREASE, с Ed25519, без меток NSS/OpenSSL). Браузеры, curl и поток
        // без Initial в дампе — не VPN-порт (последний разбирается ниже).
        if (p.proto == "UDP" && remotePort == 443 &&
            kind.find("VPN: Hysteria2") != std::string::npos) {
            fl.vpnPort = true; fl.vpnName = "Hysteria2/QUIC (QUIC-клиент на Go без GREASE: quic-go)";
            fl.vpnPortNum = 443; fl.vpnProto = "UDP";
        }
    }

    // Решение по таблице портов. Сильный признак (VPN-порт +3, прокси-порт +2):
    //  - соединение открыл абонент: по SYN, без SYN — по первому пакету; если
    //    поток шёл уже в первые 2 с записи, открывшего не видно — в пользу порта;
    //  - через соединение прошло ≥ 50 КБ (не одиночный пинг/проба);
    //  - прокси-порт и UDP 8443/1935 — только к хостингу (не CDN, не своя сеть):
    //    8080/8888/4433 бывают у обычных сайтов и камер, HTTP/3 на 8443 — у CDN.
    // Остальные совпадения VPN-порта — слабый признак (+1 на все), прокси — без баллов.
    const long long kPortHitBytes = 50 * 1024;
    const long long kCaptureHeadUs = 2 * 1000000LL;
    std::vector<std::pair<std::string, std::string>> weakVpnPorts;   // ip -> описание
    std::vector<std::string> ignoredPorts;
    for (const auto& kv : portHits) {
        const PortHit& h = kv.second;
        VpnRemote& fl = v.byRemote[h.ip];
        const IpInfo& i = infoFor(h.ip);
        const bool host = (i.hosting || looksHostingOrg(i.org, i.asn)) &&
                          !isOwnIspOrg(i.org, i.asn) && !looksCdnOrg(i.org);
        const bool midStream = !h.synSeen && h.firstUs >= 0 && captureStartUs >= 0 &&
                               h.firstUs - captureStartUs < kCaptureHeadUs;
        const bool byUser = h.init == 1 || midStream;
        const bool big = h.bytes >= kPortHitBytes;
        const bool needHost = !h.vpn || (h.proto == "UDP" && (h.rport == 8443 || h.rport == 1935));
        char d[256];
        snprintf(d, sizeof(d), "%s:%d/%s %s (%.0f КБ%s%s)", h.ip.c_str(), h.rport,
                 h.proto.c_str(), h.name.c_str(), h.bytes / 1024.0,
                 byUser ? "" : ", соединение открыл удалённый узел",
                 (needHost && !host) ? ", не хостинг" : "");
        if (byUser && big && (!needHost || host)) {
            // сигнатура (WireGuard, OpenVPN, прокси по L7) точнее имени порта — её не затираем
            if (h.vpn && !fl.vpnPort) {
                fl.vpnPort = true; fl.vpnName = h.name;
                fl.vpnPortNum = h.rport; fl.vpnProto = h.proto;
            } else if (!h.vpn && !fl.proxyPort) {
                fl.proxyPort = true; fl.proxyName = h.name;
                fl.proxyPortNum = h.rport; fl.proxyProto = h.proto;
            }
        } else if (h.vpn && (!needHost || host)) {
            weakVpnPorts.push_back({h.ip, d});
        } else {
            ignoredPorts.push_back(d);
        }
    }

    // UDP/443 к хостингу, начало QUIC-сессии в дамп не попало: по отпечатку браузер
    // и Hysteria2 не различить. Мелкий поток — скорее HTTP/3 к сайту на VPS. Одного
    // объёма мало: HTTP/3-видео с сайта на VPS, начатое до записи, тоже даёт сотни
    // КБ, но вверх при скачивании идут только ACK (Chrome прореживает их — меньше
    // 3% от входящего). Туннель — от kQuicUnknownVpnBytes на адрес И исходящий
    // от 3% входящего (тот же порог, что у долгого потока в flowVpnEvidence).
    const long long kQuicUnknownVpnBytes = 500 * 1024;
    std::set<std::string> quicUnknownSmall;
    for (const auto& q : quicUnknownBytes) {
        VpnRemote& fl = v.byRemote[q.first];
        if (fl.vpnPort) continue;                   // уже VPN по другому потоку
        const long long up = q.second.up, down = q.second.down;
        if (up + down < kQuicUnknownVpnBytes || up * 100 < down * 3) {
            quicUnknownSmall.insert(q.first); continue;
        }
        char nm[192];
        snprintf(nm, sizeof(nm), "Hysteria2/QUIC (QUIC к хостингу: вниз %.0f КБ / вверх %.0f КБ; "
                 "начало сессии не в дампе)", down / 1024.0, up / 1024.0);
        fl.vpnPort = true; fl.vpnName = nm;
        fl.vpnPortNum = 443; fl.vpnProto = "UDP";
    }

    // 1) явные VPN-порты
    std::vector<std::pair<std::string, VpnRemote>> vpnFlows;
    std::vector<std::pair<std::string, VpnRemote>> proxyFlows;
    long long& sumRemoteBytes = v.sumRemoteBytes;
    std::pair<std::string, VpnRemote> topFlow{"", {}};
    long long whiteBytes = 0;             // объём к адресам из белого списка
    std::vector<std::string> whiteIps;
    for (auto& kv : v.byRemote) {
        sumRemoteBytes += kv.second.bytes;
        if (kv.second.bytes > topFlow.second.bytes) topFlow = kv;
        if (kv.second.vpnPort) vpnFlows.push_back(kv);
        else if (kv.second.proxyPort) proxyFlows.push_back(kv);
        // гео: суммируем объём по стране удалённого IP. CDN не считаем: узел
        // Cloudflare/Akamai «в Нидерландах» говорит о CDN, а не о направлении туннеля.
        // Белый список — тоже (YouTube из Франкфурта — не туннель в DE).
        const IpInfo& gi = infoFor(kv.first);
        if (gi.vpnWhite) { whiteBytes += kv.second.bytes; whiteIps.push_back(kv.first); continue; }
        if (looksCdnOrg(gi.org)) continue;
        std::string cc = (gi.country.empty() || gi.country == "-") ? "??" : gi.country;
        v.bytesByCountry[cc] += kv.second.bytes;
    }

    // «Форма» трафика — доля одного узла, мало хостов, доля «vless», гео — это
    // разные описания ОДНОГО и того же большого потока к хостингу. Раньше они
    // суммировались (до 8 баллов за одно скачивание с Hetzner). Теперь копятся
    // отдельно и дают не больше kShapeCap; для «вероятно VPN» нужен хотя бы
    // один независимый признак (порт, JA4, Reality, MSS, долгий поток).
    int shape = 0;
    const int kShapeCap = cfg().shapeCap;
    std::vector<std::string>& reasons = v.reasons;

    // Белый список: баллов не дают ни порт, ни база, ни доля/гео/MSS. Сигнатуры
    // (WireGuard, OpenVPN, прокси по содержимому) засчитываются и здесь: VPS в
    // облаке Google сидит в той же AS15169.
    if (!whiteIps.empty()) {
        std::sort(whiteIps.begin(), whiteIps.end(), [&](const std::string& a, const std::string& b) {
            return v.byRemote.at(a).bytes > v.byRemote.at(b).bytes;
        });
        std::string l; int n = 0;
        for (const auto& ip : whiteIps) {
            if (n++ >= 3) { l += "; …"; break; }
            const IpInfo& i = infoFor(ip);
            if (!l.empty()) l += "; ";
            l += ip + " (" + i.whiteWhy;
            if (!i.org.empty() && i.org != "-") l += ", " + i.org;
            l += ")";
        }
        char pct[48];
        snprintf(pct, sizeof(pct), " — %.0f%% трафика",
                 sumRemoteBytes > 0 ? 100.0 * whiteBytes / sumRemoteBytes : 0.0);
        reasons.push_back("Адреса из белого списка (баллов VPN не дают, проверяются только "
                          "проблемы соединения): " + l + pct);
    }

    if (!vpnFlows.empty()) {
        v.portScore += 3;
        for (auto& f : vpnFlows) {
            const IpInfo& i = infoFor(f.first);
            char portbuf[48] = "";
            if (f.second.vpnPortNum > 0)
                snprintf(portbuf, sizeof(portbuf), " [порт %d/%s]",
                         f.second.vpnPortNum,
                         f.second.vpnProto.empty() ? "?" : f.second.vpnProto.c_str());
            reasons.push_back("Трафик на VPN-порт " + f.second.vpnName + portbuf +
                              " к " + f.first + " (" + i.org + ", " + i.asn + ")" +
                              "\n    Wireshark: " + wsFilter(f.first, f.second.vpnPortNum,
                                  f.second.vpnProto == "TCP" ? "tcp" : "udp"));
        }
    }

    // VPN-порт без подтверждения (открыл удалённый узел или мало данных):
    // +1 на все такие, и только если явного VPN-порта нет
    {
        std::vector<std::string> weak;
        for (const auto& w : weakVpnPorts) {
            auto it = v.byRemote.find(w.first);
            if (it == v.byRemote.end() || !it->second.vpnPort) weak.push_back(w.second);
        }
        if (!weak.empty() && vpnFlows.empty()) {
            v.portScore += 1;
            std::string l; int n = 0;
            for (const auto& s : weak) { if (n++ >= 3) { l += "; …"; break; } if (!l.empty()) l += "; "; l += s; }
            reasons.push_back("VPN-порт на удалённой стороне, но соединение открыл не абонент или "
                              "прошло меньше " + std::to_string(kPortHitBytes / 1024) + " КБ — "
                              "так бывает у P2P (торрент, игры); слабый признак (+1): " + l);
        }
    }
    if (!ignoredPorts.empty()) {
        std::string l; int n = 0;
        for (const auto& s : ignoredPorts) { if (n++ >= 3) { l += "; …"; break; } if (!l.empty()) l += "; "; l += s; }
        reasons.push_back("Порты из списка прокси/VPN не к хостингу, с малым объёмом или открытые "
                          "удалённым узлом — обычные сервисы (баллов не даёт): " + l);
    }

    if (!proxyFlows.empty()) {
        v.portScore += 2;
        for (auto& f : proxyFlows) {
            const IpInfo& i = infoFor(f.first);
            char portbuf[48] = "";
            // таблица proxy_ports не знает протокола: порт 1080 бывает и у UDP —
            // показываем протокол, на котором порт реально встретился
            if (f.second.proxyPortNum > 0)
                snprintf(portbuf, sizeof(portbuf), " [порт %d/%s]",
                         f.second.proxyPortNum,
                         f.second.proxyProto.empty() ? "?" : f.second.proxyProto.c_str());
            reasons.push_back("Трафик на прокси/обход-порт " + f.second.proxyName + portbuf +
                              " к " + f.first + " (" + i.org + ", " + i.asn + ")" +
                              "\n    Wireshark: " + wsFilter(f.first, f.second.proxyPortNum,
                                  f.second.proxyProto == "UDP" ? "udp" : "tcp"));
        }
    }

    // 1б) адрес из базы VPN/прокси/Tor (флаги ipapi.is или база IP2Proxy) с заметным объёмом.
    //     +2, а не +3: флаг бывает и у хостинга, который просто продаёт VPN, —
    //     для «вероятно» нужен ещё хоть один признак.
    {
        int n = 0;
        for (const auto& kv : v.byRemote) {
            const IpInfo& i = infoFor(kv.first);
            if (i.vpnWhite) continue;
            if (!(i.isVpn || i.isProxy || i.isTor) || kv.second.bytes < 100 * 1024) continue;
            if (n++ >= 3) continue;   // баллы одни на всех, в причинах — первые три
            char buf[512];
            snprintf(buf, sizeof(buf), "Адрес %s (%s, %s) в базе %s помечен как %s, через него %.0f КБ",
                     kv.first.c_str(), i.org.c_str(), i.asn.c_str(),
                     i.flagSrc.empty() ? "ipapi.is" : i.flagSrc.c_str(),
                     i.isVpn ? "VPN" : i.isTor ? "Tor" : "прокси", kv.second.bytes / 1024.0);
            reasons.push_back(buf);
        }
        if (n > 0) v.portScore += 2;
    }

    // 2) один удалённый IP забирает почти весь трафик (туннель «всё через одну точку»)
    double topShare = (sumRemoteBytes > 0)
        ? (double)topFlow.second.bytes / (double)sumRemoteBytes : 0.0;
    // SNI этого адреса — имя, которое абонент сам разрезолвил в этот же адрес:
    // обычный сайт (у Reality SNI чужой, и DNS его на VPS не ведёт)
    std::string dnsSite;
    {
        auto dn = dnsNamesOfIp.find(topFlow.first);
        if (dn != dnsNamesOfIp.end())
            for (const auto& s : topFlow.second.snis)
                if (dn->second.count(s)) { dnsSite = s; break; }
    }
    const IpInfo& topInfo = infoFor(topFlow.first);
    const bool topHost = (topInfo.hosting || looksHostingOrg(topInfo.org, topInfo.asn)) &&
                         !isOwnIspOrg(topInfo.org, topInfo.asn);
    // не хостинг + сайт по DNS (скачали файл с static.yoomoney.ru у МТС) — не туннель
    const bool plainSite = !dnsSite.empty() && !topHost;
    const bool looksCdn  = looksCdnOrg(topInfo.org) || !dnsSite.empty();   // сайт по DNS на хостинге — как CDN
    // Российский не хостинг и не CDN (банк, магазин, оператор) — баллов нет:
    // VPN-серверы стоят на VPS, а дамп проверки одного ресурса и так почти весь
    // уходит в один адрес. Туннель к домашнему роутеру ловят сигнатуры и порты.
    // Только RU: зарубежный адрес, который база не опознала как хостинг
    // (мелкий VPS-провайдер, домашний сервер за границей), — как раньше, с баллами.
    // Адрес не резолвился (org неизвестна) — судить не по чему, считаем как раньше.
    const bool topKnown = !topInfo.org.empty() && topInfo.org != "-";
    const bool plainService = topKnown && topInfo.country == "RU" && !topHost && !looksCdn;
    // основной адрес из белого списка — «один узел» и «мало хостов» не считаем
    // (весь трафик в YouTube — это просмотр видео)
    const bool topWhite = topInfo.vpnWhite;
    if (!topFlow.first.empty() && topShare >= 0.80 && topFlow.second.bytes > 200000 && !plainSite &&
        !topWhite) {
        const IpInfo& i = topInfo;
        char buf[512];
        if (plainService)
            snprintf(buf, sizeof(buf),
                "Один IP %s (%s, %s) забирает %.0f%% трафика, но это не хостинг — "
                "обычный сервис (баллов не даёт)",
                topFlow.first.c_str(), i.org.c_str(), i.asn.c_str(), topShare * 100.0);
        else if (!dnsSite.empty())
            snprintf(buf, sizeof(buf),
                "Один IP %s (%s, %s) забирает %.0f%% трафика — это сайт %s (адрес из DNS "
                "совпадает с SNI) на хостинге; слабый признак",
                topFlow.first.c_str(), i.org.c_str(), i.asn.c_str(), topShare * 100.0,
                dnsSite.c_str());
        else
            snprintf(buf, sizeof(buf),
                "Один IP %s (%s, %s)%s забирает %.0f%% трафика — похоже на туннель",
                topFlow.first.c_str(), i.org.c_str(), i.asn.c_str(),
                (topHost && !looksCdn) ? " [хостинг]" : "", topShare * 100.0);
        reasons.push_back(buf);
        // Концентрация трафика на хостинге (или неизвестном адресе) — признак туннеля:
        //   >=95%  -> +3 (почти весь трафик в одну точку, классический VPN/туннель)
        //   >=80%  -> +2
        // CDN снижает значимость (легитимный CDN может давать большую долю): максимум +1.
        if (!plainService) {
            if (looksCdn)               shape += 1;
            else if (topShare >= 0.95)  shape += 3;
            else                        shape += 2;
            // хостинг/датацентр в роли единственной точки — добавочный балл
            if (topHost && !looksCdn && topShare < 0.95) shape += 1;
        }
    }

    // 3) низкое разнообразие удалённых хостов при большом объёме. Если основной
    //    адрес — обычный сервис или сайт по DNS, это просто проверка одного ресурса
    if (v.byRemote.size() <= 2 && sumRemoteBytes > 500000 && !plainService && !plainSite &&
        !topWhite) {
        shape += 1;
        reasons.push_back("Мало удалённых хостов при большом объёме — нетипично для обычного сёрфинга");
    }

    // 4) значительная доля трафика — «probably vless» (TLS на 443 к хостингу).
    //    Это основной пассивный признак VLESS/Reality-туннеля. Оцениваем по объёму:
    double vlessShare = (sumRemoteBytes > 0)
        ? (double)vlessBytes / (double)sumRemoteBytes : 0.0;
    if (vlessBytes > 100000 && vlessShare >= 0.15) {
        char buf[512];
        snprintf(buf, sizeof(buf),
            "%.0f%% трафика — TLS на :443 к хостингу (похоже на VLESS/Reality-туннель)",
            vlessShare * 100.0);
        reasons.push_back(buf);
        // чем больше доля vless-потока, тем увереннее признак туннеля:
        //   >=50% -> +3, >=30% -> +2, >=15% -> +1
        if      (vlessShare >= 0.50) shape += 3;
        else if (vlessShare >= 0.30) shape += 2;
        else                         shape += 1;
    }
    // TLS к хостингу, где SNI абонент сам разрезолвил в этот адрес, — сайт на
    // VPS (Википедия, форум), а не Reality: только пояснение, без баллов
    if (vlessDnsBytes > 100000 && sumRemoteBytes > 0 && vlessDnsBytes * 100 >= sumRemoteBytes * 15) {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "%.0f%% трафика — TLS на :443 к хостингу, но к сайтам по DNS (SNI разрезолвлен "
            "в тот же адрес) — обычные сайты (баллов не даёт)",
            100.0 * vlessDnsBytes / sumRemoteBytes);
        reasons.push_back(buf);
    }

    // 5) геораспределение: трафик преимущественно в «популярную VPN-страну».
    //    Нидерланды (NL), Германия (DE), Финляндия (FI), плюс часто Франция (FR),
    //    США (US), Великобритания (GB) — туда чаще всего смотрят туннели/хостинги.
    {
        std::string topCc; long long topCcBytes = 0;
        for (auto& kv : v.bytesByCountry)
            if (kv.first != "??" && kv.second > topCcBytes) { topCcBytes = kv.second; topCc = kv.first; }
        double ccShare = (sumRemoteBytes > 0) ? (double)topCcBytes / sumRemoteBytes : 0.0;
        // только если есть заметный иностранный объём в одну страну
        if (!topCc.empty() && ccShare >= 0.50 && topCcBytes > 200000 && isVpnCountry(topCc)) {
            const char* cname =
                topCc=="NL"?"Нидерланды": topCc=="DE"?"Германия": topCc=="FI"?"Финляндия":
                topCc=="FR"?"Франция": topCc=="US"?"США": topCc=="GB"?"Великобритания":
                topCc=="SE"?"Швеция": topCc=="LU"?"Люксембург": topCc.c_str();
            char buf[512];
            snprintf(buf, sizeof(buf),
                "%.0f%% всего трафика (без CDN) идёт в %s (%s) — частое направление VPN/туннелей",
                ccShare*100.0, cname, topCc.c_str());
            reasons.push_back(buf);
            shape += 1; // мягкий сигнал — гео само по себе не доказательство
        }
    }
    v.shapeScore = std::min(shape, kShapeCap);
    if (shape > kShapeCap)
        reasons.push_back("(признаки выше описывают один и тот же поток и вместе дают не более " +
                          std::to_string(kShapeCap) + " баллов)");

    // 5б) потоковые признаки: Reality, отпечаток клиента, долгий двусторонний поток
    v.reality = collectRealitySuspects(packets, tt, ipCache);
    bool flowOnlyJa4Lib = false;
    {
        FlowEvidence ev = flowVpnEvidence(tt, v.reality, ipCache);
        v.flowScore = ev.score;
        flowOnlyJa4Lib = ev.onlyJa4Lib;
        for (auto& r : ev.reasons) reasons.push_back(r);
    }
    if (!quicUnknownSmall.empty()) {
        std::string l; int n = 0;
        for (const auto& ip : quicUnknownSmall) { if (n++ >= 3) { l += ", …"; break; } if (!l.empty()) l += ", "; l += ip; }
        reasons.push_back("UDP/443 (QUIC) к хостингу " + l + ": начало сессии не попало в дамп, "
                          "меньше " + std::to_string(kQuicUnknownVpnBytes / 1024) + " КБ на адрес "
                          "или почти нет исходящего (как у скачивания) — похоже на HTTP/3 к сайту "
                          "(баллов не даёт)");
    }

    // 6) MSS из SYN-ACK удалённой стороны. Низкий MSS у крупного удалённого
    //    узла — узел сам за туннелем/оверлеем.
    //    MSS в SYN самого абонента в вердикт НЕ входит: 1360 и ниже дают и
    //    обычные роутеры/Wi-Fi-стеки с урезанным MTU, признак срабатывал
    //    на абонентах без всякого VPN.
    {
        // Узлов с долей ≥20% может быть до пяти, и по +1 за каждый MSS один
        // давал бы «ВЕРОЯТНО VPN». Узлы за одним оверлеем (CDN, облако) — один
        // признак, поэтому в сумме не больше +2; остальные узлы только в списке.
        const int kRemoteMssCap = 2;
        int remoteMssScore = 0;
        for (auto& kv : v.byRemote) {
            const VpnRemote& fl = kv.second;
            if (fl.synMss <= 0 || fl.synMss >= 1400) continue;
            if (sumRemoteBytes <= 0 || fl.bytes * 5 < sumRemoteBytes) continue;  // только узлы с >=20% трафика
            // CDN и облачные балансировщики урезают MSS у себя (свой оверлей,
            // туннели между PoP) — у скачивания с CDN это не признак VPN
            if (looksCdnOrg(infoFor(kv.first).org) || infoFor(kv.first).vpnWhite) continue;
            const bool counted = remoteMssScore < kRemoteMssCap;
            char buf[512];
            snprintf(buf, sizeof(buf),
                "Узел %s объявил MSS %d — сам за туннелем/оверлеем, при его доле "
                "трафика %.0f%% это признак VPN-узла%s", kv.first.c_str(), fl.synMss,
                100.0 * fl.bytes / sumRemoteBytes,
                counted ? "" : " (баллов не даёт: за MSS узлов уже +2)");
            reasons.push_back(buf);
            if (counted) { v.mssScore += 1; remoteMssScore++; }
        }
    }

    // «TLS не из браузера» к хостингу чаще всего описывает тот же большой поток,
    // что уже дал «форму» (апдейтер, Steam, игра качают с VPS). Если других
    // признаков нет, он не поднимает вердикт до «вероятно».
    if (flowOnlyJa4Lib && v.portScore == 0 && v.mssScore == 0 &&
        v.shapeScore + v.flowScore >= kVpnLikelyScore) {
        v.flowScore = std::max(0, kVpnLikelyScore - 1 - v.shapeScore);
        reasons.push_back("(«TLS не из браузера» без других признаков не поднимает вердикт "
                          "выше «возможно»: апдейтеры и игры тоже качают с хостингов)");
    }
    v.score = v.portScore + v.shapeScore + v.flowScore + v.mssScore;
    return v;
}

// Режим 1: анализ на VPN / прокси (резолв адресов, построчный разбор, вердикт).
void runVpnAnalysis(std::vector<Packet>& packets, const std::vector<std::string>& paths) {
    // 3) собираем уникальные публичные IP для резолва (локальный адрес исключаем)
    std::set<std::string> publicIps;
    for (auto& p : packets) {
        if (!isLocalIp(p.srcIp)) publicIps.insert(p.srcIp);
        if (!isLocalIp(p.dstIp)) publicIps.insert(p.dstIp);
    }

    std::unordered_map<std::string, IpInfo> ipCache;
    for (const auto& pp : paths) std::cout << "Файл: " << pp << "\n";
    std::cout << "Пакетов разобрано: " << packets.size()
              << " | уникальных публичных IP: " << publicIps.size() << "\n";
    if (!g_localIp.empty())
        std::cout << "MainIP: " << g_localIp
                  << (isPrivateIp(g_localIp) ? " (приватный)" : " (публичный)") << "\n";
    if (!g_localIp6.empty())
        std::cout << "MainIP IPv6: " << g_localIp6 << "\n";
    std::cout << "Резолвлю IP через ip-api.com ...\n\n";

    std::vector<std::string> ipList(publicIps.begin(), publicIps.end());
    resolveIps(ipList, ipCache);
    // добор хостинга через вторичный источник (ipapi.is) для непомеченных IP
    resolveHostingSecondary(ipCache, ipList);

    // Подписи и метки — по копии с белым списком (YouTube не «probably vless»).
    // Проверки соединения (16 КБ, причины блокировки) ниже — по исходному ipCache.
    const auto ipW = withVpnWhitelist(packets, &ipCache);
    auto infoFor = [&](const std::string& ip) -> const IpInfo& { return vpnInfoFor(&ipW, ip); };

    // 4) построчный вывод в стиле tcpdump + подпись + догадка
    std::map<std::string, long long> tally; // тип трафика -> счётчик
    long long tcp = 0, udp = 0, icmp = 0;
    long long totalPayload = 0;
    const std::map<std::string, int> quicKind = quicFlowKinds(packets);

    for (auto& p : packets) {
        const IpInfo& si = infoFor(p.srcIp);
        const IpInfo& di = infoFor(p.dstIp);
        const std::string kind = vpnPacketKind(p, si, di, quicKind);
        // к типу трафика приписываем порт удалённой (серверной) стороны:
        // напр. "(tls/https):443", "(http):80". Если сторону не определить — без порта.
        if (!kind.empty()) {
            bool sLoc = isLocalIp(p.srcIp), dLoc = isLocalIp(p.dstIp);
            int rport = 0;
            if (sLoc != dLoc) rport = sLoc ? p.dstPort : p.srcPort;
            std::string key = kind;
            if (rport > 0) key += ":" + std::to_string(rport);
            tally[key]++;
        }
        if (p.proto == "TCP") tcp++;
        else if (p.proto == "UDP") udp++;
        else if (p.proto == "ICMP") icmp++;
        totalPayload += p.length;

        // строка 1 — как в tcpdump: IP6 для IPv6, у ICMP портов нет (-1),
        // у TCP с данными seq — диапазоном начало:конец
        auto ep = [](const std::string& a, int port) {
            return port >= 0 ? a + "." + std::to_string(port) : a;
        };
        bool v6 = p.srcIp.find(':') != std::string::npos;
        printf("%s %s %s > %s: ", p.ts.c_str(), v6 ? "IP6" : "IP",
            ep(p.srcIp, p.srcPort).c_str(), ep(p.dstIp, p.dstPort).c_str());
        if (p.proto == "TCP") printf("Flags %s", p.flags.empty() ? "[-]" : p.flags.c_str());
        else                  printf("%s", p.proto.c_str());
        if (p.proto == "TCP" && p.length > 0 && p.seqStart >= 0 && p.seq >= 0)
            printf(", seq %lld:%lld", p.seqStart, p.seq);
        else if (p.seq >= 0) printf(", seq %lld", p.seq);
        if (p.ack >= 0) printf(", ack %lld", p.ack);
        if (p.win >= 0) printf(", win %lld", p.win);
        printf(", length %lld", p.length);
        if (!p.appHint.empty()) printf(": %s", p.appHint.c_str());
        printf("\n");

        // строка 2 — человекочитаемая подпись + справка о сервисе порта + цвет
        std::string sL = sideLabel(p.srcIp, si);
        std::string dL = sideLabel(p.dstIp, di);
        std::string svc;
        bool remoteHosting = false;
        {
            bool sLoc = isLocalIp(p.srcIp), dLoc = isLocalIp(p.dstIp);
            if (sLoc != dLoc) {
                int rport = sLoc ? p.dstPort : p.srcPort;

                // {portService} показываем только если kind не раскрывает протокол.
                // Когда kind = "(tls/https)", "(http)", "(ssh session)" и т.п. —
                // portService лишь повторяет то же самое, не добавляя информации.
                bool kindDescribes =
                    kind.find("tls/https")    != std::string::npos ||
                    kind.find("http)")        != std::string::npos ||
                    kind.find("ssh")          != std::string::npos ||
                    kind.find("torrent")      != std::string::npos ||
                    kind.find("stun/webrtc")  != std::string::npos ||
                    kind.find("dns")          != std::string::npos ||
                    kind.find("udp/quic")     != std::string::npos ||
                    kind.find("VPN:")         != std::string::npos ||
                    kind.find("proxy:")       != std::string::npos ||
                    kind.find("vless")        != std::string::npos ||
                    kind.find("Hysteria")     != std::string::npos ||
                    kind.find("icmp")         != std::string::npos;

                if (!kindDescribes) {
                    if (const char* s = portService(rport); s && s[0] != '\0')
                        svc = std::string("  {") + s + "}";
                }

                // [appByPort] показываем только для конкретных приложений
                // (Steam, RDP, Minecraft, SIP и т.п.) — исключаем общие HTTP/HTTPS/DNS
                // чтобы не повторять то, что уже сказано в kind.
                const char* app = appByPort(rport, p.proto);
                // если kind уже распознал VPN/proxy — app-хинт (особенно «голос/
                // медиа» по высокому UDP-порту) лишний и противоречит. Подавляем.
                bool kindIsVpn = (kind.find("VPN") != std::string::npos ||
                                  kind.find("proxy:") != std::string::npos);
                // торрент/STUN опознан по содержимому, порт пира случайный —
                // подсказка по нему («[WireGuard]» на 51820) противоречит метке
                bool kindIsP2p = kind.find("torrent") != std::string::npos ||
                                 kind.find("stun/webrtc") != std::string::npos;
                if (app && !kindIsVpn && !kindIsP2p) {
                    std::string appStr = app;
                    // фильтруем дубли: если app содержит то же что kind — пропускаем
                    bool appDups =
                        (appStr.find("HTTPS") != std::string::npos && kindDescribes) ||
                        (appStr.find("HTTP")  != std::string::npos && kind.find("http") != std::string::npos) ||
                        (appStr.find("DNS")   != std::string::npos && kind.find("dns")  != std::string::npos) ||
                        (appStr.find("SSH")   != std::string::npos && kind.find("ssh")  != std::string::npos) ||
                        (appStr.find("QUIC")  != std::string::npos && kindDescribes) ||
                        // DoT: portService уже дал {DoT}, не дублируем [DNS-over-TLS]
                        (appStr.find("DNS-over-TLS") != std::string::npos &&
                         svc.find("DoT") != std::string::npos) ||
                        // то же если svc уже содержит этот текст
                        (svc.find(appStr) != std::string::npos);
                    if (!appDups)
                        svc += std::string("  [") + appStr + "]";
                }
                const IpInfo& rem = sLoc ? di : si;
                remoteHosting = (rem.hosting || looksHostingOrg(rem.org, rem.asn)) &&
                                !isOwnIspOrg(rem.org, rem.asn) && !rem.vpnWhite;
                // (hosting) показываем только на 443/8443 — там хостинг важен,
                // т.к. трафик не отличить от обычного HTTPS. На прочих портах не нужно.
                bool tlsPort = (rport == 443 || rport == 8443);
                if (remoteHosting && tlsPort && !looksCdnOrg(rem.org)) svc += "  (hosting)";
                else remoteHosting = false; // не влияет на цвет вне 443/8443
            }
        }
        // цвет по типу метки: VPN/proxy=красный, probably/подозрительное=жёлтый,
        // обычный трафик=зелёный.
        const char* col = C::GRN;
        if (kind.find("VPN:") != std::string::npos ||
            kind.find("proxy:") != std::string::npos) col = C::RED;
        else if (kind.find("probably") != std::string::npos ||
                 kind.find("possibly") != std::string::npos ||
                 remoteHosting) col = C::YEL;

        std::string sniStr;
        if (!p.sni.empty())
            sniStr = std::string(p.proto == "UDP" ? "  [QUIC SNI: " : "  [SNI: ") + p.sni + "]";
        if (!p.ja4.empty())
            sniStr += "  [JA4: " + p.ja4 + "]";

        printf("    %s%s > %s %s%s%s%s\n",
            col, ep(sL, p.srcPort).c_str(), ep(dL, p.dstPort).c_str(),
            kind.c_str(), svc.c_str(), sniStr.c_str(), C::RST);
        printf("\n"); // пустая строка-разделитель между пакетами
    }

    // 5) сводка
    printf("\n=================== СВОДКА ===================\n");
    printf("Всего пакетов: %lld   (TCP: %lld, UDP: %lld, ICMP: %lld)\n",
           (long long)packets.size(), tcp, udp, icmp);
    printf("Суммарный payload: %lld байт\n", totalPayload);
    printf("Уникальных публичных IP: %lld\n\n", (long long)publicIps.size());

    printf("Распределение по типу трафика:\n");
    for (auto& kv : tally)
        printf("  %-26s %lld\n", kv.first.c_str(), kv.second);

    analyzeJa4(packets, &ipCache);

    // ---- вердикт о наличии VPN (пассивно, по дампу) ----
    printf("\n=================== ВЕРДИКТ VPN ===================\n");
    const TcpConnTable tt = buildTcpConnTable(packets, g_localIp);
    const VpnVerdict vv = computeVpnVerdict(packets, tt, &ipCache);
    const auto& reasons = vv.reasons;
    const auto& byRemote = vv.byRemote;
    const long long sumRemoteBytes = vv.sumRemoteBytes;
    const int score = vv.score;
    const char* verdict = score >= kVpnLikelyScore   ? "ВЕРОЯТНО ВКЛЮЧЁН VPN"
                        : score >= kVpnPossibleScore ? "ВОЗМОЖНО есть VPN (нужна проверка)"
                                                     : "Признаков VPN не найдено";
    const char* vcol = score >= kVpnLikelyScore ? C::RED : score >= kVpnPossibleScore ? C::YEL : C::GRN;
    printf("Итог: %s%s%s%s  (score=%d)\n", C::BOLD, vcol, verdict, C::RST, score);
    if (score > 0)
        printf("  %sбаллы: порты/прокси %d, форма трафика %d, потоковые %d, MSS %d%s\n",
               C::GRY, vv.portScore, vv.shapeScore, vv.flowScore, vv.mssScore, C::RST);
    if (reasons.empty()) {
        printf("  %sТрафик распределён по многим хостам, явных VPN-портов нет.%s\n",
               C::GRN, C::RST);
    } else {
        for (auto& r : reasons) printf("  %s•%s %s\n", vcol, C::RST, r.c_str());
    }

    // топ удалённых адресатов по объёму — полезно саппорту
    printf("\nТоп удалённых адресатов по объёму:\n");
    std::vector<std::pair<std::string, VpnRemote>> flowsSorted(byRemote.begin(), byRemote.end());
    std::sort(flowsSorted.begin(), flowsSorted.end(),
              [](auto& a, auto& b){ return a.second.bytes > b.second.bytes; });
    int shownF = 0;
    for (auto& f : flowsSorted) {
        if (shownF++ >= 8) break;
        const IpInfo& i = infoFor(f.first);
        double share = sumRemoteBytes ? 100.0 * f.second.bytes / sumRemoteBytes : 0;
        bool host = ((i.hosting || looksHostingOrg(i.org, i.asn)) && !isOwnIspOrg(i.org, i.asn)) &&
                    !looksCdnOrg(i.org) && !i.vpnWhite;
        printf("  %-16s %8lld B  %5.1f%%  %s %s%s%s%s\n",
            f.first.c_str(), f.second.bytes, share, i.asn.c_str(), i.org.c_str(),
            host ? "  (hosting)" : "",
            i.vpnWhite ? "  [белый список]" : "",
            f.second.vpnPort ? "  [VPN-PORT]" : "");
    }

    // геораспределение трафика по странам
    {
        std::vector<std::pair<std::string, long long>> geo(vv.bytesByCountry.begin(), vv.bytesByCountry.end());
        std::sort(geo.begin(), geo.end(), [](auto& a, auto& b){ return a.second > b.second; });
        bool any = false;
        for (auto& g : geo) if (g.second > 0) { any = true; break; }
        if (any) {
            printf("\nГеораспределение трафика (по объёму, без CDN):\n");
            int shownG = 0;
            for (auto& g : geo) {
                if (g.second == 0) continue;
                if (shownG++ >= 8) break;
                double share = sumRemoteBytes ? 100.0 * g.second / sumRemoteBytes : 0;
                printf("  %-4s %10lld B  %5.1f%%%s\n",
                    g.first.c_str(), g.second, share,
                    isVpnCountry(g.first) ? "   (частое направление VPN)" : "");
            }
        }
    }

    // скорость крупнейших потоков во времени — видно замедление туннеля (полку)
    analyzeThroughput(packets, g_localIp);
    printRealitySuspects(vv.reality, &ipCache);
    analyzeFreeze16k(tt, &ipCache);
    printBlockReasons(collectBlockReasons(packets, tt, &ipCache, g_localIp));
    analyzeDpiBypass(tt);

    printf("\nIP -> ASN / организация:\n");
    printf("%-18s %-8s %-8s %-10s %s\n", "IP", "Type", "Country", "ASN", "Organization");
    std::set<std::string> allIps;
    for (auto& p : packets) { allIps.insert(p.srcIp); allIps.insert(p.dstIp); }
    for (auto& ip : allIps) {
        const IpInfo& i = infoFor(ip);
        const bool loc = isLocalIp(ip);
        printf("%-18s %-8s %-8s %-10s %s\n",
            ip.c_str(), i.type.c_str(),
            (i.type == "private" ? "-" : i.country.c_str()),
            i.asn.c_str(), loc ? localRoleLabel(ip) : i.org.c_str());
    }
}
