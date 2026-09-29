// parser.cpp — разбор дампов: текст tcpdump, pcap/pcapng, кадры Ethernet/IP/TCP/UDP,
// DNS, TLS ClientHello (SNI, JA4), QUIC Initial; загрузка и склейка набора файлов.
#include "common.h"

// "10.199.102.163.57275" -> ip="10.199.102.163", port=57275
// "2a00:1450:4010::65.443" -> ip="2a00:1450:4010::65", port=443
static void splitIpPort(const std::string& token, std::string& ip, int& port) {
    // последняя точка отделяет порт
    size_t dot = token.find_last_of('.');
    int dots = (int)std::count(token.begin(), token.end(), '.');
    // IPv4 содержит 3 точки — порт есть, только если их 4.
    // В IPv6 точек нет вовсе (порт — единственная точка), кроме записи
    // с вложенным IPv4 (::ffff:1.2.3.4) — там снова 3 точки у адреса.
    bool hasPort = (token.find(':') != std::string::npos)
                 ? (dots == 1 || dots == 4)
                 : (dots >= 4);
    if (hasPort) {
        ip = token.substr(0, dot);
        std::string p = token.substr(dot + 1);
        port = p.empty() ? -1 : atoi(p.c_str());
    } else {
        ip = token;
        port = -1;
    }
}

// извлечь "ключ: число" после метки (ack/win/length)
static long long grabNum(const std::string& s, const std::string& key) {
    size_t p = s.find(key);
    if (p == std::string::npos) return -1;
    p += key.size();
    while (p < s.size() && (s[p] == ' ' || s[p] == ':')) p++;
    long long v = 0; bool any = false;
    while (p < s.size() && isdigit((unsigned char)s[p])) { v = v * 10 + (s[p] - '0'); p++; any = true; }
    return any ? v : -1;
}

// seq бывает "A:B" (диапазон) или "A"; возвращаем конец диапазона (B или A)
static long long grabSeqEnd(const std::string& s) {
    size_t p = s.find("seq ");
    if (p == std::string::npos) return -1;
    p += 4;
    std::string num;
    while (p < s.size() && (isdigit((unsigned char)s[p]) || s[p] == ':')) { num += s[p]; p++; }
    size_t c = num.find(':');
    if (c != std::string::npos) num = num.substr(c + 1);
    return num.empty() ? -1 : atoll(num.c_str());
}

// НАЧАЛО диапазона seq (A из "A:B"). Нужно для детекта ретрансмиссий:
// повторная отправка сегмента = тот же НАЧАЛЬНЫЙ seq. Использовать конец
// нельзя — end одного сегмента совпадает со start следующего при нормальной
// последовательной передаче (seq 100:200, затем 200:300), что давало ложные
// «ретрансмиссии» и завышенный % потерь.
static long long grabSeqStart(const std::string& s) {
    size_t p = s.find("seq ");
    if (p == std::string::npos) return -1;
    p += 4;
    std::string num;
    while (p < s.size() && (isdigit((unsigned char)s[p]) || s[p] == ':')) { num += s[p]; p++; }
    size_t c = num.find(':');
    if (c != std::string::npos) num = num.substr(0, c);
    return num.empty() ? -1 : atoll(num.c_str());
}

// ------------------------------------------------------------------
// разбор одной (уже склеенной) строки пакета
// ------------------------------------------------------------------
static Packet parseLine(const std::string& raw) {
    Packet pk;
    std::string line = trim(raw);
    if (line.empty()) return pk;

    std::istringstream is(line);
    std::string tok;

    // 1) время
    if (!(is >> pk.ts)) return pk;

    // 2) "IP"
    std::string ipword;
    if (!(is >> ipword)) return pk;
    if (ipword != "IP" && ipword != "IP6") {
        // строка не про IP-пакет (ARP и т.п.) — пропускаем
        return pk;
    }

    // tcpdump -v: сразу за «IP» идёт заголовок IP в скобках —
    //   IP (tos 0x0, ttl 64, id 1, offset 0, flags [DF], proto TCP (6), length 52) a.1 > b.2: ...
    //   IP6 (flowlabel 0x1, hlim 64, next-header TCP (6) payload length: 32) a.1 > b.2: ...
    // Его вырезаем: иначе адрес источника читался бы из «(tos», а length —
    // длина всего IP-пакета (у чистого ACK 40 > 0 — «данные»; у ICMP — с IP-заголовком).
    // TTL/hop limit из него берём — он нужен детектам RST-инъекции.
    {
        std::string after;
        std::getline(is, after);
        size_t b = after.find_first_not_of(' ');
        if (b != std::string::npos && after[b] == '(') {
            int depth = 0;
            size_t e = b;
            for (; e < after.size(); e++) {
                if (after[e] == '(') depth++;
                else if (after[e] == ')' && --depth == 0) break;
            }
            if (e >= after.size()) return pk;   // скобка не закрыта — строка обрезана
            const std::string hdr = after.substr(b + 1, e - b - 1);
            long long ttl = grabNum(hdr, "ttl ");
            if (ttl < 0) ttl = grabNum(hdr, "hlim ");
            if (ttl >= 0 && ttl <= 255) pk.ttl = (int)ttl;
            after.erase(0, e + 1);
        }
        is.clear();
        is.str(after);
    }

    // 3) src
    std::string srcTok;
    if (!(is >> srcTok)) return pk;

    // 4) ">"
    std::string arrow;
    if (!(is >> arrow)) return pk;

    // 5) dst (с двоеточием на конце)
    std::string dstTok;
    if (!(is >> dstTok)) return pk;
    if (!dstTok.empty() && dstTok.back() == ':') dstTok.pop_back();

    splitIpPort(srcTok, pk.srcIp, pk.srcPort);
    splitIpPort(dstTok, pk.dstIp, pk.dstPort);

    // остаток строки — флаги/seq/ack/win/length/proto
    std::string rest;
    std::getline(is, rest);

    // протокол. TCP-строка tcpdump всегда содержит "Flags [", а слово "UDP"
    // печатается лишь для нераспознанного payload («UDP, length N»): DNS, NTP,
    // QUIC и т.п. идут своим декодером без него. Раньше такие строки считались
    // TCP — DNS из текстового дампа уходил в «DNS over TCP», QUIC — в TLS.
    if (rest.find("ICMP") != std::string::npos) pk.proto = "ICMP";
    else if (rest.find("Flags [") != std::string::npos) pk.proto = "TCP";
    else if (pk.srcPort >= 0 && pk.dstPort >= 0) pk.proto = "UDP";
    else return pk;   // GRE/ESP/фрагменты без L4-портов — как и в pcap, не разбираем

    if (rest.find("HTTP") != std::string::npos) pk.appHint = "HTTP";

    // IPsec: tcpdump сам декодирует 500/4500 — «UDP-encap: ESP(spi=…)»,
    // «isakmp: parent_sa ikev2_init[I]», «NONESP-encap: isakmp: child_sa ikev2_auth[I]»,
    // IKEv1 — «isakmp: phase 1 I ident», шифрованные сообщения с «[E]».
    if (pk.proto == "UDP") {
        if (rest.find("ESP(") != std::string::npos) pk.ipsec = 3;
        else if (rest.find("isakmp") != std::string::npos &&
                 rest.find("keep-alive") == std::string::npos) {
            const bool init = rest.find("ikev2_init") != std::string::npos ||
                              (rest.find("phase 1") != std::string::npos &&
                               rest.find("[E]") == std::string::npos);
            pk.ipsec = init ? 1 : 2;
            // версия и инициатор: «ikev2_init[I]» — запрос инициатора IKEv2,
            // «phase 1 I» — сообщение инициатора фазы 1 IKEv1
            if (rest.find("ikev2") != std::string::npos) {
                pk.ike = 2;
                if (rest.find("ikev2_init[I]") != std::string::npos) pk.ike |= 4;
            } else if (rest.find("phase ") != std::string::npos) {
                pk.ike = 1;
                if (rest.find("phase 1 I") != std::string::npos) pk.ike |= 4;
            }
        }
    }

    // DNS-разбор (текстовый tcpdump показывает содержимое DNS в строке):
    //   запрос:  "... 40905+ A? top-fwz1.mail.ru. (34)"
    //   ответ A: "... 40905 1/0/0 A 95.163.52.67 (50)"
    //   NXDomain:"... 40905 NXDomain 0/1/0 (90)"
    if (pk.srcPort == 53 || pk.dstPort == 53) {
        std::istringstream ds(rest);
        std::string w;
        std::vector<std::string> toks;
        while (ds >> w) toks.push_back(w);
        // transaction id — первый токен вида "40905" или "40905+" или "40905*"
        for (auto& tk : toks) {
            std::string digits;
            for (char c : tk) { if (isdigit((unsigned char)c)) digits+=c; else break; }
            if (!digits.empty()) { pk.dnsId = digits; break; }
        }
        bool isQuery = (rest.find("? ") != std::string::npos);  // "A? ", "AAAA? "
        if (isQuery) {
            pk.dnsIsResponse = false;
            // домен идёт сразу после "A? " / "AAAA? " / "CNAME? "
            size_t q = rest.find("? ");
            if (q != std::string::npos) {
                // тип — слово перед "?": "A", "AAAA", "HTTPS", неизвестные — "Type65"
                size_t tb = q;
                while (tb > 0 && isalnum((unsigned char)rest[tb - 1])) tb--;
                const std::string qt = rest.substr(tb, q - tb);
                static const std::pair<const char*, uint16_t> kQt[] = {
                    {"A", 1}, {"NS", 2}, {"CNAME", 5}, {"SOA", 6}, {"PTR", 12}, {"MX", 15},
                    {"TXT", 16}, {"AAAA", 28}, {"SRV", 33}, {"SVCB", 64}, {"HTTPS", 65}, {"ANY", 255} };
                for (const auto& e : kQt) if (qt == e.first) { pk.dnsQtype = e.second; break; }
                if (pk.dnsQtype == 0 && qt.size() > 4 && qt.compare(0, 4, "Type") == 0)
                    pk.dnsQtype = (uint16_t)atoi(qt.c_str() + 4);
                std::string dom;
                size_t p = q + 2;
                while (p < rest.size() && (isalnum((unsigned char)rest[p])||rest[p]=='.'||rest[p]=='-'||rest[p]=='_'))
                    dom += rest[p++];
                while (!dom.empty() && dom.back()=='.') dom.pop_back();
                pk.dnsQuery = dom;
            }
        } else {
            pk.dnsIsResponse = true;
            if (rest.find("NXDomain") != std::string::npos) pk.dnsNxdomain = true;
            // все "A <ip>" / "AAAA <ip>" ответа: "3/0/0 CNAME x., A 1.2.3.4, A 5.6.7.8"
            // dnsAnswerIp — первая A (если её нет — первая AAAA), dnsAnswers — все
            std::string firstA, firstA6;
            for (const char* rr : { " A ", " AAAA " }) {
                size_t ap = 0;
                while ((ap = rest.find(rr, ap)) != std::string::npos) {
                    size_t p = ap + strlen(rr);
                    ap = p;
                    std::string ip;
                    while (p < rest.size() && (isxdigit((unsigned char)rest[p])||rest[p]=='.'||rest[p]==':'))
                        ip += rest[p++];
                    if (ip.find('.') == std::string::npos && ip.find(':') == std::string::npos) continue;
                    pk.dnsAnswers.push_back(ip);
                    if (rr[2] == ' ') { if (firstA.empty()) firstA = ip; }
                    else if (firstA6.empty()) firstA6 = ip;
                }
            }
            pk.dnsAnswerIp = !firstA.empty() ? firstA : firstA6;
            // "CNAME fp-back.facct.ru., A 185.17.9.134" — цели CNAME по порядку
            size_t cp = 0;
            while ((cp = rest.find(" CNAME ", cp)) != std::string::npos) {
                size_t p = cp + 7;
                cp = p;
                std::string nm;
                while (p < rest.size() && (isalnum((unsigned char)rest[p])||rest[p]=='.'||rest[p]=='-'||rest[p]=='_'))
                    nm += rest[p++];
                while (!nm.empty() && nm.back()=='.') nm.pop_back();
                if (!nm.empty()) pk.dnsCnames.push_back(nm);
            }
        }
    }

    // флаги "Flags [..]" — только у TCP (у DNS в строке бывает "[1au]" и т.п.)
    if (pk.proto == "TCP") {
        size_t fb = rest.find("Flags [");
        if (fb != std::string::npos) fb += 6;
        size_t fe = (fb == std::string::npos) ? std::string::npos : rest.find(']', fb);
        if (fb != std::string::npos && fe != std::string::npos)
            pk.flags = rest.substr(fb, fe - fb + 1);

        // TCP-опции: "options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7]",
        // SACK: "options [nop,nop,sack 2 {100:200}{300:400}]". Без них MSS-вердикт
        // по тексту не работал, а все крупные соединения выглядели «без window scale».
        size_t ob = rest.find("options [");
        size_t oe = (ob == std::string::npos) ? std::string::npos : rest.find(']', ob);
        if (oe != std::string::npos) {
            std::stringstream os(rest.substr(ob + 9, oe - ob - 9));
            std::string o;
            while (std::getline(os, o, ',')) {
                if (o.rfind("mss ", 0) == 0)         pk.mss = atoi(o.c_str() + 4);
                else if (o.rfind("wscale ", 0) == 0) pk.wscale = std::min(atoi(o.c_str() + 7), 14);
                else if (o.rfind("sack ", 0) == 0)   pk.sackBlocks = atoi(o.c_str() + 5);
                else if (o.rfind("TS val ", 0) == 0) {           // "TS val 123 ecr 456"
                    pk.tsVal = atoll(o.c_str() + 7);
                    long long e = grabNum(o, "ecr ");
                    if (e >= 0) pk.tsEcr = e; else pk.tsVal = -1;
                }
            }
        }
    }

    pk.seq    = grabSeqEnd(rest);
    pk.seqStart = grabSeqStart(rest);
    pk.ack    = grabNum(rest, "ack");
    pk.win    = grabNum(rest, "win");
    pk.length = std::max(0LL, grabNum(rest, "length"));
    // DNS по UDP печатается без «length N»: длина сообщения — в скобках в конце
    // строки, «... A? mail.ru. (34)». Без неё все DNS-пакеты текстового дампа
    // имели длину 0 (в pcap это длина UDP-нагрузки — то же число).
    if (pk.proto == "UDP" && pk.length == 0) {
        const int dnsPorts[] = { 53, 5353, 5355 };   // DNS, mDNS, LLMNR
        bool dns = false;
        for (int dp : dnsPorts) dns = dns || pk.srcPort == dp || pk.dstPort == dp;
        size_t e = rest.find_last_not_of(" \t\r\n");
        if (dns && e != std::string::npos && rest[e] == ')') {
            size_t b = rest.rfind('(', e);
            if (b != std::string::npos && e > b + 1 &&
                rest.find_first_not_of("0123456789", b + 1) == e)
                pk.length = atoll(rest.c_str() + b + 1);
        }
    }

    pk.valid = !pk.srcIp.empty() && !pk.dstIp.empty();
    return pk;
}

// ------------------------------------------------------------------
// main
// ------------------------------------------------------------------
// ------------------------------------------------------------------
// Чтение бинарного .pcap / .pcapng. Возвращает пакеты.
// Поддержка: link-type 1 (Ethernet), 113/276 (Linux SLL/SLL2, с направлением
// кадра), 0/108 (NULL/LOOP — loopback Npcap/BSD), 101/228/229 (raw IP);
// у Ethernet и SLL — метки VLAN и сессия PPPoE. IPv4 и IPv6, TCP/UDP/ICMP/ICMPv6; из payload — SNI (с досборкой
// ClientHello по сегментам) и DNS.
// ------------------------------------------------------------------
static uint16_t rd16(const unsigned char* p, bool be) {
    return be ? (uint16_t)((p[0] << 8) | p[1]) : (uint16_t)((p[1] << 8) | p[0]);
}
static uint32_t rd32(const unsigned char* p, bool be) {
    return be ? ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]
              : ((uint32_t)p[3]<<24)|((uint32_t)p[2]<<16)|((uint32_t)p[1]<<8)|p[0];
}
static uint16_t be16(const unsigned char* p) { return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t be32(const unsigned char* p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}

static std::string ipToStr(const unsigned char* p) {
    char b[16];
    snprintf(b, sizeof(b), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return b;
}
static std::string tsToStr(uint32_t sec, uint32_t usec) {
    // переводим в локальное HH:MM:SS.usec (как в tcpdump).
    // localtime_s недешёвый, а пакеты идут подряд в пределах одной минуты —
    // кэшируем разбор начала текущей минуты (сдвиги часовых поясов кратны
    // минуте, поэтому секунды внутри неё совпадают с UTC).
    thread_local uint32_t cMin = 0xFFFFFFFFu;
    thread_local int cH = 0, cM = 0;
    uint32_t minStart = sec - sec % 60;
    if (minStart != cMin) {
        time_t t = (time_t)minStart;
        struct tm tmv;
        localtime_s(&tmv, &t);
        cMin = minStart; cH = tmv.tm_hour; cM = tmv.tm_min;
    }
    char b[32];
    snprintf(b, sizeof(b), "%02d:%02d:%02d.%06u", cH, cM, (int)(sec - minStart), usec);
    return b;
}

// IPv6 в канонической сжатой форме (RFC 5952) — как печатает tcpdump
static std::string ip6ToStr(const unsigned char* p) {
    char b[INET6_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET6, (const void*)p, b, sizeof(b))) return "";
    return b;
}

// ------------------------------------------------------------------
// DNS из бинарного дампа. Заполняем те же поля, что и текстовый разбор
// tcpdump (dnsId десятичной строкой, dnsQuery без завершающей точки,
// dnsAnswerIp — первая A-запись, а если её нет — первая AAAA; dnsAnswers —
// все A/AAAA ответа, dnsCnames — цели CNAME; в ответе dnsQuery = имя из секции вопроса), чтобы
// анализ DNS-аномалий работал одинаково для .txt и .pcap.
// ------------------------------------------------------------------

// Прочитать имя начиная с p (со сжатием-указателями). p сдвигается за имя
// в исходном месте сообщения. out (если задан) — имя без конечной точки.
static bool dnsReadName(const uint8_t* d, size_t n, size_t& p, std::string* out) {
    size_t q = p;
    bool jumped = false;
    int steps = 0;
    std::string name;
    for (;;) {
        if (q >= n || ++steps > 128) return false;
        uint8_t len = d[q];
        if (len == 0) { q++; break; }
        if ((len & 0xC0) == 0xC0) {                    // указатель на ранее встреченное имя
            if (q + 1 >= n) return false;
            size_t ptr = ((size_t)(len & 0x3F) << 8) | d[q + 1];
            if (ptr >= n) return false;
            if (!jumped) { p = q + 2; jumped = true; }
            q = ptr;
            continue;
        }
        if (len & 0xC0) return false;                  // 0x40/0x80 — зарезервированы
        if (q + 1 + len > n) return false;
        if (out) {
            if (!name.empty()) name += '.';
            for (size_t i = 0; i < len; i++) {
                char c = (char)d[q + 1 + i];
                name += (c > 0x20 && c < 0x7f) ? c : '?';
            }
        }
        q += 1 + len;
    }
    if (!jumped) p = q;
    if (out) *out = name;
    return true;
}

static void parseDnsPayload(const uint8_t* d, size_t n, Packet& pk) {
    if (n < 12) return;
    uint16_t id = be16(d), fl = be16(d + 2);
    uint16_t qd = be16(d + 4), an = be16(d + 6);
    if ((fl >> 11) & 0x0F) return;                     // opcode не QUERY — не наш случай
    pk.dnsId = std::to_string(id);
    pk.dnsIsResponse = (fl & 0x8000) != 0;
    if (pk.dnsIsResponse && (fl & 0x000F) == 3) pk.dnsNxdomain = true;

    size_t p = 12;
    std::string qname;
    for (int i = 0; i < qd; i++) {
        std::string nm;
        if (!dnsReadName(d, n, p, i == 0 ? &nm : nullptr)) return;
        if (p + 4 > n) return;
        if (i == 0) { qname = nm; pk.dnsQtype = be16(d + p); }
        p += 4;                                        // QTYPE + QCLASS
    }
    if (!pk.dnsIsResponse) { pk.dnsQuery = qname; return; }

    // имя вопроса храним и в ответе: по нему сверяем SNI с резолвом (Reality)
    pk.dnsQuery = qname;
    std::string a4, a6;
    for (int i = 0; i < an && i < 64; i++) {
        if (!dnsReadName(d, n, p, nullptr)) break;
        if (p + 10 > n) break;
        uint16_t type  = be16(d + p);
        uint16_t rdlen = be16(d + p + 8);
        p += 10;
        if (p + rdlen > n) break;
        if (type == 1 && rdlen == 4) {
            std::string ip = ipToStr(d + p);
            pk.dnsAnswers.push_back(ip);
            if (a4.empty()) a4 = ip;
        } else if (type == 28 && rdlen == 16) {
            std::string ip = ip6ToStr(d + p);
            pk.dnsAnswers.push_back(ip);
            if (a6.empty()) a6 = ip;
        } else if (type == 5) {
            size_t q = p;                              // имя в rdata, со сжатием
            std::string nm;
            if (dnsReadName(d, n, q, &nm) && !nm.empty()) pk.dnsCnames.push_back(nm);
        }
        p += rdlen;                                    // прочие записи пропускаем
    }
    pk.dnsAnswerIp = !a4.empty() ? a4 : a6;
}

// разобрать один Ethernet/SLL/raw-кадр в Packet (IPv4/IPv6, TCP/UDP/ICMP).
// tcpPay/tcpPayLen (необязательно) — полезная нагрузка TCP-сегмента, если
// она захвачена целиком: по ней собирается ClientHello из нескольких сегментов.
// Для UDP сюда же отдаётся захваченная часть датаграммы (для QUIC Initial).
static std::string parseTlsSni(const uint8_t* d, size_t n); // объявление (тело ниже)
static bool ja4FromTlsRecords(const uint8_t* d, size_t n, Packet& pk); // тоже ниже

// Нешифрованный HTTP в начале сегмента: запрос -> Host, ответ -> код,
// Location и признаки страницы-заглушки о блокировке (провайдерские
// заглушки РКН обычно приходят ответом 302 на warning.rt.ru/lawfilter или
// 200/451 со страницей «доступ ограничен»). Смотрим только первые 4 КБ.
static void parseHttpHead(const uint8_t* d, size_t n, Packet& pk) {
    if (n < 8) return;
    std::string s((const char*)d, std::min<size_t>(n, 4096));
    std::string low = s;
    for (char& c : low) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    auto header = [&](const char* nameLow) -> std::string {
        std::string key = std::string("\r\n") + nameLow;
        size_t p = low.find(key);
        if (p == std::string::npos) return "";
        p += key.size();
        size_t e = s.find("\r\n", p);
        if (e == std::string::npos) e = s.size();
        std::string v = s.substr(p, e - p);
        size_t b = v.find_first_not_of(" \t");
        return b == std::string::npos ? "" : v.substr(b, 200);
    };
    static const char* kMethods[] = { "GET ", "POST ", "HEAD ", "PUT ", "OPTIONS ", "CONNECT " };
    for (const char* m : kMethods) {
        if (s.compare(0, strlen(m), m) == 0) {
            pk.httpHost = header("host:");
            size_t colon = pk.httpHost.find(':');
            if (colon != std::string::npos) pk.httpHost.resize(colon);
            pk.httpUa = header("user-agent:");
            // путь — до пробела перед версией; без версии (HTTP/0.9, обрезанная
            // строка) — до конца строки, чтобы не захватить заголовки
            size_t ps = strlen(m), pe = std::min(s.find(' ', ps), s.find("\r\n", ps));
            if (pe == std::string::npos && s.size() > ps) pe = s.size();
            if (pe != std::string::npos && pe > ps) pk.httpPath = s.substr(ps, std::min<size_t>(pe - ps, 200));
            return;
        }
    }
    if (s.compare(0, 7, "HTTP/1.") != 0 || s.size() < 12) return;
    int code = 0;
    for (size_t i = 9; i < 12 && i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') { code = 0; break; }
        code = code * 10 + (s[i] - '0');
    }
    pk.httpStatus = code;
    pk.httpLocation = header("location:");
    // признаки заглушки: и в Location, и в теле (что попало в сегмент)
    static const char* kMarks[] = {
        "warning.rt.ru", "lawfilter", "eais.rkn.gov.ru", "rkn.gov.ru",
        "zapret-info.gov.ru", "blocklist",
        "заблокирован", "Заблокирован", "доступ ограничен", "Доступ ограничен",
        "единый реестр", "Единый реестр",
    };
    for (const char* m : kMarks) {
        if (low.find(m) != std::string::npos || s.find(m) != std::string::npos) {
            pk.httpBlockMark = m;
            break;
        }
    }
    if (pk.httpBlockMark.empty() && code == 451) pk.httpBlockMark = "код 451";
}

const char* l7Name(int code) {
    switch (code) {
        case L7_TLS:        return "TLS";
        case L7_HTTP:       return "HTTP";
        case L7_HTTP_PROXY: return "HTTP-прокси";
        case L7_SSH:        return "SSH";
        case L7_BITTORRENT: return "BitTorrent";
        case L7_BT_DHT:     return "BitTorrent DHT";
        case L7_SOCKS5:     return "SOCKS5-прокси";
        case L7_SOCKS4:     return "SOCKS4-прокси";
        case L7_RDP:        return "RDP";
        case L7_TELNET:     return "Telnet";
        case L7_SMB:        return "SMB";
        case L7_STUN:       return "STUN/TURN (звонки)";
        case L7_DNS:        return "DNS";
        case L7_OPENVPN:    return "OpenVPN";
        default:            return "";
    }
}

// Протокол по первым байтам payload — свои эвристики в духе Wireshark/nDPI.
// p/n — захваченные байты, full — длина payload по заголовкам (n < full при
// обрезке snaplen). Сигнатуры короткие, поэтому где можно сверяем и длины.
static uint8_t detectL7(const uint8_t* p, size_t n, size_t full, bool tcp) {
    auto starts = [&](const char* s) {
        size_t k = strlen(s);
        return n >= k && memcmp(p, s, k) == 0;
    };
    // OpenVPN: опкод в старших 5 битах, key_id = 0. 7/10 — сброс от клиента
    // (v2 / tls-crypt-v2), 8 — ответ сервера. Поток признаётся OpenVPN только
    // если это ПЕРВЫЕ пакеты обеих сторон (флоу-маркировка в loadDumpSet).
    auto ovpn = [](uint8_t b) -> uint8_t {
        if ((b & 7) != 0) return L7_NONE;
        uint8_t op = b >> 3;
        if (op == 7 || op == 10) return L7_OVPN_CLIENT;
        if (op == 8)             return L7_OVPN_SERVER;
        return L7_NONE;
    };
    if (tcp) {
        // запись TLS: тип 20..23, версия 3.x
        if (n >= 3 && p[0] >= 0x14 && p[0] <= 0x17 && p[1] == 0x03 && p[2] <= 0x04) return L7_TLS;
        if (starts("SSH-")) return L7_SSH;
        if (n >= 20 && p[0] == 19 && memcmp(p + 1, "BitTorrent protocol", 19) == 0) return L7_BITTORRENT;
        if (starts("CONNECT ")) return L7_HTTP_PROXY;
        static const char* kMethods[] = { "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH " };
        for (const char* m : kMethods) {
            if (!starts(m)) continue;
            // абсолютный URI («GET http://host/…») шлют только HTTP-прокси
            size_t k = strlen(m);
            if (n >= k + 7 && memcmp(p + k, "http://", 7) == 0) return L7_HTTP_PROXY;
            return L7_HTTP;
        }
        if (starts("HTTP/1.")) return L7_HTTP;
        // SMB поверх NetBIOS-сессии: 00 + длина(3) + FF/FE "SMB"
        if (n >= 8 && p[0] == 0 && (p[4] == 0xFF || p[4] == 0xFE) && memcmp(p + 5, "SMB", 3) == 0)
            return L7_SMB;
        // RDP: TPKT (03 00 длина) + X.224 Connection Request/Confirm
        if (n >= 6 && p[0] == 3 && p[1] == 0 && be16(p + 2) == full && full >= 11 &&
            (size_t)p[4] + 5 <= full && ((p[5] & 0xF0) == 0xE0 || (p[5] & 0xF0) == 0xD0))
            return L7_RDP;
        // Telnet: согласование опций IAC WILL/WONT/DO/DONT, обычно пачкой
        if (n >= 3 && p[0] == 0xFF && p[1] >= 0xFB && p[1] <= 0xFE &&
            (full == 3 || (n >= 4 && p[3] == 0xFF)))
            return L7_TELNET;
        // SOCKS5 приветствие: 05, N, N методов (0..9) — ровно 2+N байт
        if (n >= 3 && p[0] == 5 && p[1] >= 1 && p[1] <= 9 && full == (size_t)2 + p[1] && n >= full) {
            bool ok = true;
            for (size_t i = 2; i < full; i++) if (p[i] > 9) { ok = false; break; }
            if (ok) return L7_SOCKS5;
        }
        // SOCKS4/4a: 04, команда 1/2, порт, IPv4, user-id\0 [домен\0]
        if (n >= 9 && p[0] == 4 && (p[1] == 1 || p[1] == 2) && full >= 9 && full <= 300 &&
            n >= full && p[full - 1] == 0)
            return L7_SOCKS4;
        // OpenVPN по TCP: 2 байта длины пакета, затем опкод
        if (n >= 3 && full >= 16 && full <= 1500 && be16(p) == full - 2)
            return ovpn(p[2]);
        return L7_NONE;
    }
    // --- UDP ---
    // STUN: 2 старших бита 0, длина кратна 4 и совпадает, magic cookie 2112A442
    if (n >= 20 && (p[0] & 0xC0) == 0 && be32(p + 4) == 0x2112A442u &&
        (be16(p + 2) & 3) == 0 && (size_t)be16(p + 2) + 20 == full)
        return L7_STUN;
    // DHT BitTorrent: bencode-словарь запроса/ответа
    if (starts("d1:ad2:id20:") || starts("d1:rd2:id20:") || starts("d2:ip6:")) return L7_BT_DHT;
    if (n >= 1 && full >= 14 && full <= 1500) return ovpn(p[0]);
    return L7_NONE;
}

static bool parseFrame(const unsigned char* d, size_t len, int linkType,
                       const std::string& ts, Packet& pk,
                       const uint8_t** tcpPay = nullptr, size_t* tcpPayLen = nullptr) {
    size_t off = 0;
    uint16_t ethertype = 0;
    if (tcpPay) *tcpPay = nullptr;
    if (tcpPayLen) *tcpPayLen = 0;

    if (linkType == 1) {                 // Ethernet
        if (len < 14) return false;
        ethertype = be16(d + 12);
        off = 14;
    } else if (linkType == 113) {        // Linux cooked (SLL)
        if (len < 16) return false;
        ethertype = be16(d + 14);
        off = 16;
        // packet_type (be16 в начале): 0 = адресован нам, 4 = отправлен нами
        uint16_t pt = be16(d);
        if (pt == 0) pk.dir = 0; else if (pt == 4) pk.dir = 1;
    } else if (linkType == 276) {        // Linux cooked v2 (SLL2, tcpdump -i any)
        if (len < 20) return false;
        ethertype = be16(d);
        off = 20;
        uint8_t pt = d[10];              // packet_type — 1 байт по смещению 10
        if (pt == 0) pk.dir = 0; else if (pt == 4) pk.dir = 1;
    } else if (linkType == 0 || linkType == 108) {
        // NULL (0, loopback Npcap/BSD): 4 байта семейства адресов в порядке
        // байт хоста-писателя; LOOP (108) — то же, но в сетевом порядке.
        // AF_INET = 2; AF_INET6 = 24/28/30 (разные ОС) или 23 (Windows).
        if (len < 4) return false;
        uint32_t af = (linkType == 108) ? be32(d)
                                        : (uint32_t)(d[0] | (d[1] << 8) | (d[2] << 16) | ((uint32_t)d[3] << 24));
        if (linkType == 0 && af > 0xFFFF) af = be32(d);   // писатель был big-endian
        if (af == 2) ethertype = 0x0800;
        else if (af == 23 || af == 24 || af == 28 || af == 30) ethertype = 0x86DD;
        else return false;
        off = 4;
    } else if (linkType == 101 || linkType == 228 || linkType == 229) {
        // raw IP (101), LINKTYPE_IPV4 (228), LINKTYPE_IPV6 (229):
        // версию берём из первого полубайта заголовка
        if (len < 1) return false;
        ethertype = ((d[0] >> 4) == 6) ? 0x86DD : 0x0800;
        off = 0;
    } else {
        return false;
    }

    // Вложения после канального заголовка — одинаковые для Ethernet и Linux
    // cooked (SLL/SLL2): метки VLAN 802.1Q/802.1ad (в т.ч. QinQ) и сессия
    // PPPoE (6 байт заголовка + 2 байта протокола PPP). Раньше VLAN снимался
    // только у Ethernet, а PPPoE не разбирался вовсе — такие кадры терялись.
    if (linkType == 1 || linkType == 113 || linkType == 276) {
        for (;;) {
            if ((ethertype == 0x8100 || ethertype == 0x88a8) && off + 4 <= len) {
                ethertype = be16(d + off + 2);
                off += 4;
            } else if (ethertype == 0x8864 && off + 8 <= len) {
                if (d[off] != 0x11 || d[off + 1] != 0x00) return false;  // ver/type 1, code «сессия»
                const uint16_t ppp = be16(d + off + 6);
                if (ppp == 0x0021) ethertype = 0x0800;        // IPv4
                else if (ppp == 0x0057) ethertype = 0x86DD;   // IPv6
                else return false;                            // LCP/IPCP и т.п.
                off += 8;
                break;
            } else break;
        }
    }

    uint8_t proto = 0;
    size_t l4off = 0, l4len = 0;
    if (ethertype == 0x0800) {                    // IPv4
        if (off + 20 > len) return false;
        const unsigned char* ip = d + off;
        if ((ip[0] >> 4) != 4) return false;
        int ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20 || off + ihl > len) return false;
        // не первый фрагмент: L4-заголовка в нём нет, разбор дал бы мусорные
        // порты/флаги (у IPv6 то же отсекается по Fragment-заголовку)
        if ((be16(ip + 6) & 0x1FFF) != 0) return false;
        proto = ip[9];
        pk.ttl = ip[8];                   // IP TTL — ключ для детекта RST-инъекции DPI
        pk.srcIp = ipToStr(ip + 12);
        pk.dstIp = ipToStr(ip + 16);
        uint16_t totalLen = be16(ip + 2);
        l4off = off + ihl;
        // totalLen == 0 — исходящий сегмент, снятый до TSO/LSO-разгрузки:
        // сетевая карта проставит длину сама. Берём длину по захваченному
        // кадру, иначе крупные исходящие сегменты выглядят пустыми.
        if (totalLen == 0)        l4len = len - off - ihl;
        else if (totalLen > ihl)  l4len = (size_t)(totalLen - ihl);
        else                      l4len = 0;
    } else if (ethertype == 0x86DD) {             // IPv6
        if (off + 40 > len) return false;
        const unsigned char* ip = d + off;
        if ((ip[0] >> 4) != 6) return false;
        proto = ip[6];                    // next header
        pk.ttl = ip[7];                   // hop limit — тот же смысл, что TTL
        pk.srcIp = ip6ToStr(ip + 8);
        pk.dstIp = ip6ToStr(ip + 24);
        size_t rem = be16(ip + 4);        // payload length (без 40 байт заголовка)
        // 0 — сегмент до LSO-разгрузки (как totalLen == 0 у IPv4): длина по кадру
        if (rem == 0) rem = len - (off + 40);
        size_t p = off + 40;
        // цепочка заголовков расширения до L4
        for (int guard = 0; guard < 8; guard++) {
            if (proto == 0 || proto == 43 || proto == 60) {   // hop-by-hop / routing / dest opts
                if (p + 2 > len || rem < 8) return false;
                size_t hl = ((size_t)d[p + 1] + 1) * 8;
                if (hl > rem) return false;
                proto = d[p];
                p += hl; rem -= hl;
            } else if (proto == 44) {                         // fragment
                if (p + 8 > len || rem < 8) return false;
                uint16_t fragOff = be16(d + p + 2) >> 3;
                proto = d[p];
                p += 8; rem -= 8;
                if (fragOff != 0) return false;   // не первый фрагмент — L4-заголовка нет
            } else {
                break;
            }
        }
        if (p > len) return false;
        l4off = p;
        l4len = rem;
    } else {
        return false;
    }
    const unsigned char* l4 = d + l4off;

    pk.ts = ts;

    if (proto == 6) {                    // TCP
        if (l4 + 20 > d + len) return false;
        pk.proto = "TCP";
        pk.srcPort = be16(l4);
        pk.dstPort = be16(l4 + 2);
        pk.seqStart = be32(l4 + 4);      // начало сегмента (raw TCP seq)
        pk.seq = be32(l4 + 4);           // временно начало; ниже сделаем концом
        pk.ack = be32(l4 + 8);
        int doff = (l4[12] >> 4) * 4;
        // data offset < 5 слов — битый заголовок: иначе заголовок посчитался бы
        // «данными» (ложная длина, ложный ClientHello)
        if (doff < 20) return false;
        uint8_t fl = l4[13];
        std::string fs;
        if (fl & 0x02) fs += 'S';
        if (fl & 0x01) fs += 'F';
        if (fl & 0x04) fs += 'R';
        if (fl & 0x08) fs += 'P';
        if (fl & 0x10) fs += '.';
        if (fl & 0x20) fs += 'U';
        pk.flags = "[" + (fs.empty() ? std::string("-") : fs) + "]";
        pk.win = be16(l4 + 14);
        // TCP-опции: MSS(2), window scale(3), SACK(5), timestamps(8)
        if (doff > 20) {
            const uint8_t* o = l4 + 20;
            const uint8_t* oe = l4 + doff;
            if (oe > d + len) oe = d + len;          // опции обрезаны snaplen
            while (o < oe) {
                uint8_t kind = o[0];
                if (kind == 0) break;                // end of options
                if (kind == 1) { o++; continue; }    // NOP
                if (o + 2 > oe) break;
                uint8_t ol = o[1];
                if (ol < 2 || o + ol > oe) break;
                if (kind == 2 && ol == 4) pk.mss = be16(o + 2);
                else if (kind == 3 && ol == 3) pk.wscale = std::min<int>(o[2], 14);
                else if (kind == 5 && ol >= 10) pk.sackBlocks = (ol - 2) / 8;
                else if (kind == 8 && ol == 10) { pk.tsVal = be32(o + 2); pk.tsEcr = be32(o + 6); }
                o += ol;
            }
        }
        pk.length = (l4len > (size_t)doff) ? (long long)(l4len - doff) : 0;
        // seq в тексте tcpdump = КОНЕЦ диапазона; приводим pcap к тому же виду
        // (конец = начало + length), чтобы RTT seq->ack считался одинаково.
        // По модулю 2^32, как и сам ack: иначе на переходе seq через 0 конец
        // сегмента никогда не совпадёт с подтверждением.
        if (pk.length > 0) pk.seq = (uint32_t)(pk.seqStart + pk.length);
        // если есть полезная нагрузка и порт похож на TLS — пробуем вытащить SNI
        const uint8_t* payload = l4 + doff;
        size_t payLen = (l4len > (size_t)doff) ? (l4len - doff) : 0;
        if (payLen >= 5 && payload + payLen <= d + len && payload[0] == 0x16) {
            std::string sni = parseTlsSni(payload, payLen);
            if (!sni.empty()) pk.sni = sni;
            // ClientHello целиком в одном сегменте — сразу и JA4; иначе
            // дособерёт HelloReassembler
            if (payLen >= 6 && payload[5] == 0x01) ja4FromTlsRecords(payload, payLen, pk);
        } else if (payLen >= 8 && payload < d + len) {
            // HTTP: хватает и обрезанного snaplen начала сегмента
            size_t cap = std::min(payLen, (size_t)((d + len) - payload));
            uint8_t c0 = payload[0];
            if (c0 == 'H' || c0 == 'G' || c0 == 'P' || c0 == 'O' || c0 == 'C')
                parseHttpHead(payload, cap, pk);
        }
        if (payLen > 0 && payload < d + len)
            pk.l7 = detectL7(payload, std::min(payLen, (size_t)((d + len) - payload)), payLen, true);
        if (tcpPay && tcpPayLen && payLen > 0 && payload + payLen <= d + len) {
            *tcpPay = payload;
            *tcpPayLen = payLen;
        }
    } else if (proto == 17) {            // UDP
        if (l4 + 8 > d + len) return false;
        pk.proto = "UDP";
        pk.srcPort = be16(l4);
        pk.dstPort = be16(l4 + 2);
        uint16_t ul = be16(l4 + 4);
        pk.length = (ul > 8) ? (ul - 8) : 0;
        pk.flags = "[-]";
        // Детект WireGuard по сигнатуре payload (работает на ЛЮБОМ порту):
        //  - init (тип 1):     первый байт 0x01, reserved 0x00 00 00, длина 148
        //  - response (тип 2): первый байт 0x02, reserved 0x00 00 00, длина 92
        // AmneziaWG с junk-префиксом сюда не попадёт (это и хорошо — там обфускация).
        const uint8_t* up = l4 + 8;
        if (up + 4 <= d + len) {
            if (pk.length == 148 && up[0] == 0x01 && up[1] == 0 && up[2] == 0 && up[3] == 0)
                pk.wgType = 1;
            else if (pk.length == 92 && up[0] == 0x02 && up[1] == 0 && up[2] == 0 && up[3] == 0)
                pk.wgType = 2;
        }
        if (!pk.wgType && pk.length > 0 && up < d + len)
            pk.l7 = detectL7(up, std::min((size_t)pk.length, (size_t)((d + len) - up)),
                             (size_t)pk.length, false);
        // IPsec: на 4500 первые 4 байта 0 — маркер non-ESP (дальше IKE), иначе
        // это SPI ESP-пакета; 1 байт 0xFF — NAT-keepalive. Заголовок IKE:
        // SPIi(8) SPIr(8) next(1) версия(1) тип обмена(1) флаги(1) …
        const bool natt = pk.srcPort == 4500 || pk.dstPort == 4500;
        if ((natt || pk.srcPort == 500 || pk.dstPort == 500) && up <= d + len) {
            const uint8_t* ike = up;
            size_t avail = std::min((size_t)pk.length, (size_t)((d + len) - up));
            bool isIke = !natt;
            if (natt && avail >= 4) {
                if (!(ike[0] | ike[1] | ike[2] | ike[3])) { ike += 4; avail -= 4; isIke = true; }
                else if (pk.length >= 8) pk.ipsec = 3;
            }
            if (isIke && avail >= 20) {
                const int ver = ike[17] >> 4, ex = ike[18], fl = ike[19];
                bool spiRZero = true;                                  // SPI ответчика ещё не назначен
                for (int k = 8; k < 16; k++) if (ike[k]) { spiRZero = false; break; }
                if (ver == 2) {
                    pk.ipsec = (ex == 34) ? 1 : 2;                     // 34 = IKE_SA_INIT
                    pk.ike = 2;
                    // запрос IKE_SA_INIT от инициатора: флаг I (0x08) есть, R (0x20) нет
                    if (ex == 34 && (fl & 0x08) && !(fl & 0x20)) pk.ike |= 4;
                } else if (ver == 1) {
                    pk.ipsec = (fl & 1) ? 2 : 1;                       // бит 0 — шифровано
                    pk.ike = 1;
                    if (spiRZero && !(fl & 1)) pk.ike |= 4;            // первое сообщение фазы 1
                }
            }
        }
        // DNS (порт 53) — разбираем по захваченным байтам, не выходя за кадр
        if (pk.srcPort == 53 || pk.dstPort == 53) {
            size_t avail = (up <= d + len) ? (size_t)((d + len) - up) : 0;
            size_t dn = std::min((size_t)pk.length, avail);
            parseDnsPayload(up, dn, pk);
        }
        // payload датаграммы наружу — по нему расшифровывается QUIC Initial
        if (tcpPay && tcpPayLen && up <= d + len) {
            size_t un = std::min((size_t)pk.length, (size_t)((d + len) - up));
            if (un > 0) { *tcpPay = up; *tcpPayLen = un; }
        }
    } else if (proto == 1 || proto == 58) {   // ICMP / ICMPv6
        pk.proto = "ICMP";
        pk.length = (long long)l4len;
        pk.flags = "[-]";
    } else {
        return false;
    }
    pk.valid = !pk.srcIp.empty() && !pk.dstIp.empty();
    return pk.valid;
}

// ------------------------------------------------------------------
// Извлечь SNI (server_name) из TLS ClientHello.
// Вход: указатель на TCP-payload и его длина. Возвращает имя или "".
// Структура: TLS record(0x16) -> Handshake ClientHello(0x01) -> ... ->
// extensions -> server_name(0x0000) -> server_name_list -> host_name.
// Все длины — big-endian. Аккуратно проверяем границы, чтобы не выйти за буфер.
// ------------------------------------------------------------------
static std::string parseTlsSni(const uint8_t* d, size_t n) {
    if (!d || n < 43) return "";
    if (d[0] != 0x16) return "";              // не TLS Handshake record
    // d[1],d[2] = версия записи; d[3],d[4] = длина записи
    size_t p = 5;
    if (p >= n || d[p] != 0x01) return "";    // не ClientHello
    // handshake length (3 байта) — пропускаем
    p += 4;
    p += 2;                                   // client_version
    p += 32;                                  // random
    if (p >= n) return "";
    size_t sidLen = d[p]; p += 1 + sidLen;    // session_id
    if (p + 2 > n) return "";
    size_t csLen = (d[p] << 8) | d[p+1]; p += 2 + csLen;   // cipher_suites
    if (p + 1 > n || p < 5) return "";        // p<5 ловит гипотетическое переполнение
    size_t cmLen = d[p]; p += 1 + cmLen;      // compression_methods
    if (p + 2 > n) return "";
    size_t extTotal = (d[p] << 8) | d[p+1]; p += 2;        // extensions length
    size_t extEnd = p + extTotal;
    if (extEnd > n) extEnd = n;
    while (p + 4 <= extEnd) {
        size_t extType = (d[p] << 8) | d[p+1];
        size_t extLen  = (d[p+2] << 8) | d[p+3];
        p += 4;
        if (p + extLen > extEnd) break;
        if (extType == 0x0000) {              // server_name
            size_t q = p;
            if (q + 2 > p + extLen) return "";
            // server_name_list length (2 байта)
            q += 2;
            if (q + 3 > p + extLen) return "";
            int nameType = d[q]; q += 1;
            size_t hostLen = (d[q] << 8) | d[q+1]; q += 2;
            if (nameType != 0 || q + hostLen > p + extLen) return "";
            std::string host((const char*)d + q, hostLen);
            // простая валидация: печатные ASCII
            for (char c : host) if (c < 0x20 || (unsigned char)c > 0x7e) return "";
            return host;
        }
        p += extLen;
    }
    return "";
}

// ------------------------------------------------------------------
// Сборка TLS ClientHello, разрезанного на несколько TCP-сегментов.
// Современный ClientHello с постквантовым key_share (X25519MLKEM768) весит
// ~1.8 КБ и не влезает в один сегмент, а Chrome ещё и перемешивает порядок
// расширений — server_name примерно в половине случаев оказывается во
// втором сегменте, и SNI по одному пакету теряется. Кроме того, средства
// обхода DPI режут ClientHello на несколько TLS-записей — их тоже склеиваем.
// ------------------------------------------------------------------

// Выделить handshake-сообщение ClientHello из потока TLS-записей s.
// 1 — собран целиком, 0 — нужны ещё байты, -1 — это не ClientHello.
// В hs остаётся всё, что удалось собрать (даже при 0/-1).
static int tlsCollectHello(const std::vector<uint8_t>& s, std::vector<uint8_t>& hs) {
    hs.clear();
    size_t pos = 0;
    while (pos + 5 <= s.size()) {
        if (s[pos] != 0x16 || s[pos + 1] != 0x03) return -1;   // не handshake-запись
        size_t rlen = ((size_t)s[pos + 3] << 8) | s[pos + 4];
        if (rlen == 0 || rlen > 16384 + 2048) return -1;
        size_t avail = std::min(rlen, s.size() - pos - 5);
        hs.insert(hs.end(), s.begin() + pos + 5, s.begin() + pos + 5 + avail);
        if (!hs.empty() && hs[0] != 0x01) return -1;           // не ClientHello
        if (hs.size() >= 4) {
            size_t need = 4 + (((size_t)hs[1] << 16) | ((size_t)hs[2] << 8) | hs[3]);
            if (need > 65536) return -1;
            if (hs.size() >= need) { hs.resize(need); return 1; }
        }
        if (avail < rlen) return 0;
        pos += 5 + rlen;
    }
    return 0;
}

// SNI из собранного handshake: оборачиваем его в одну TLS-запись и отдаём
// обычному parseTlsSni (длину записи он не проверяет, границы — по n).
static std::string sniFromHello(const std::vector<uint8_t>& hs) {
    if (hs.empty() || hs[0] != 0x01) return "";
    size_t l = std::min<size_t>(hs.size(), 0xFFFF);
    std::vector<uint8_t> rec;
    rec.reserve(hs.size() + 5);
    rec.push_back(0x16); rec.push_back(0x03); rec.push_back(0x01);
    rec.push_back((uint8_t)(l >> 8)); rec.push_back((uint8_t)(l & 0xFF));
    rec.insert(rec.end(), hs.begin(), hs.end());
    return parseTlsSni(rec.data(), rec.size());
}

static bool tlsIsGrease(uint16_t v) {
    return (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff);
}

// Первые 12 hex-символов SHA-256 (Windows CNG, на macOS — CommonCrypto)
#ifndef _WIN32
static std::string sha256Hex12(const std::string& s) {
    uint8_t dg[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(s.data(), (CC_LONG)s.size(), dg);
    char out[16];
    for (int i = 0; i < 6; i++) snprintf(out + i * 2, 3, "%02x", dg[i]);
    return std::string(out, 12);
}
#else
static std::string sha256Hex12(const std::string& s) {
    static BCRYPT_ALG_HANDLE alg = [] {
        BCRYPT_ALG_HANDLE h = nullptr;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
            h = nullptr;
        return h;
    }();
    if (!alg) return "000000000000";
    uint8_t dg[32];
    BCRYPT_HASH_HANDLE h = nullptr;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0))) return "000000000000";
    bool ok = BCRYPT_SUCCESS(BCryptHashData(h, (PUCHAR)s.data(), (ULONG)s.size(), 0))
           && BCRYPT_SUCCESS(BCryptFinishHash(h, dg, 32, 0));
    BCryptDestroyHash(h);
    if (!ok) return "000000000000";
    char out[16];
    for (int i = 0; i < 6; i++) snprintf(out + i * 2, 3, "%02x", dg[i]);
    return std::string(out, 12);
}
#endif

// hs — handshake-сообщение ClientHello (начинается с 0x01, без TLS-записи).
// transport: 't' — TCP, 'q' — QUIC. false — ClientHello неполный или битый.
// ech (необязательно) — выставляется, если в ClientHello есть расширение
// encrypted_client_hello (0xfe0d). Chrome шлёт его и «вхолостую» (GREASE ECH),
// поэтому настоящий ECH отличаем уже в анализе — по внешнему SNI (isEchPublicName).
static bool ja4FromHello(const uint8_t* hs, size_t n, char transport,
                         std::string& ja4, std::string& client, int& kind,
                         bool* ech = nullptr) {
    if (!hs || n < 4 || hs[0] != 0x01) return false;
    size_t end = 4 + (((size_t)hs[1] << 16) | ((size_t)hs[2] << 8) | hs[3]);
    if (end > n) return false;
    size_t p = 4;
    if (p + 2 + 32 + 1 > end) return false;
    uint16_t legacyVer = be16(hs + p);
    p += 2 + 32;                                    // версия + random
    p += 1 + (size_t)hs[p];                         // session_id
    if (p + 2 > end) return false;
    size_t csLen = be16(hs + p); p += 2;
    if (p + csLen > end || (csLen & 1)) return false;
    std::vector<uint16_t> ciphers;
    bool grease = false;
    for (size_t i = 0; i < csLen; i += 2) {
        uint16_t c = be16(hs + p + i);
        if (tlsIsGrease(c)) grease = true; else ciphers.push_back(c);
    }
    p += csLen;
    if (p + 1 > end) return false;
    p += 1 + (size_t)hs[p];                         // compression_methods
    if (p > end) return false;

    std::vector<uint16_t> exts, sigAlgs, groups;
    bool hasSni = false;
    std::string alpn;
    uint16_t maxVer = 0;
    if (p + 2 <= end) {
        size_t extEnd = p + 2 + be16(hs + p);
        p += 2;
        if (extEnd > end) return false;
        while (p + 4 <= extEnd) {
            uint16_t t = be16(hs + p);
            size_t l = be16(hs + p + 2);
            p += 4;
            if (p + l > extEnd) return false;
            const uint8_t* e = hs + p;
            if (tlsIsGrease(t)) grease = true;
            else {
                exts.push_back(t);
                if (t == 0xfe0d && ech) *ech = true;
                if (t == 0x0000) hasSni = true;
                else if (t == 0x0010 && l >= 3) {          // ALPN: len2, {len1, имя}...
                    size_t nl = e[2];
                    if (3 + nl <= l) alpn.assign((const char*)e + 3, nl);
                } else if (t == 0x000d && l >= 2) {        // signature_algorithms
                    size_t sl = be16(e);
                    for (size_t i = 2; i + 1 < 2 + sl && i + 1 < l; i += 2) {
                        uint16_t s = be16(e + i);
                        if (tlsIsGrease(s)) grease = true; else sigAlgs.push_back(s);
                    }
                } else if (t == 0x000a && l >= 2) {        // supported_groups
                    size_t gl = be16(e);
                    for (size_t i = 2; i + 1 < 2 + gl && i + 1 < l; i += 2) {
                        uint16_t g = be16(e + i);
                        if (tlsIsGrease(g)) grease = true; else groups.push_back(g);
                    }
                } else if (t == 0x0033 && l >= 2) {        // key_share: len2, {группа2, len2, ключ}...
                    size_t kl = std::min<size_t>(2 + (size_t)be16(e), l);
                    for (size_t i = 2; i + 4 <= kl; i += 4 + (size_t)be16(e + i + 2))
                        if (tlsIsGrease(be16(e + i))) grease = true;
                } else if (t == 0x002b && l >= 1) {        // supported_versions
                    size_t vl = e[0];
                    for (size_t i = 1; i + 1 <= vl && i + 1 < l; i += 2) {
                        uint16_t v = be16(e + i);
                        if (tlsIsGrease(v)) grease = true;
                        else if (v > maxVer) maxVer = v;
                    }
                }
            }
            p += l;
        }
    }

    uint16_t ver = maxVer ? maxVer : legacyVer;
    const char* vs = "00";
    switch (ver) {
        case 0x0304: vs = "13"; break;  case 0x0303: vs = "12"; break;
        case 0x0302: vs = "11"; break;  case 0x0301: vs = "10"; break;
        case 0x0300: vs = "s3"; break;  case 0x0200: vs = "s2"; break;
        case 0x0100: vs = "s1"; break;
    }
    auto alnum = [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    };
    std::string al = "00";
    if (!alpn.empty()) {
        unsigned char f = (unsigned char)alpn.front(), b = (unsigned char)alpn.back();
        static const char* hx = "0123456789abcdef";
        if (alnum(f) && alnum(b)) { al[0] = (char)f; al[1] = (char)b; }
        else { al[0] = hx[f >> 4]; al[1] = hx[b & 15]; }
    }
    char a[32];
    snprintf(a, sizeof(a), "%c%s%c%02d%02d%s", transport, vs, hasSni ? 'd' : 'i',
             (int)std::min<size_t>(ciphers.size(), 99), (int)std::min<size_t>(exts.size(), 99),
             al.c_str());

    auto joinHex = [](const std::vector<uint16_t>& v) {
        std::string s; char b[8];
        for (size_t i = 0; i < v.size(); i++) {
            snprintf(b, sizeof(b), "%s%04x", i ? "," : "", v[i]);
            s += b;
        }
        return s;
    };
    std::vector<uint16_t> sc = ciphers;
    std::sort(sc.begin(), sc.end());
    std::string partB = sc.empty() ? "000000000000" : sha256Hex12(joinHex(sc));
    std::vector<uint16_t> se;
    for (uint16_t t : exts) if (t != 0x0000 && t != 0x0010) se.push_back(t);
    std::sort(se.begin(), se.end());
    std::string partC = "000000000000";
    if (!se.empty()) {
        std::string src = joinHex(se);
        if (!sigAlgs.empty()) src += "_" + joinHex(sigAlgs);
        partC = sha256Hex12(src);
    }
    ja4 = std::string(a) + "_" + partB + "_" + partC;

    // --- догадка о клиенте: по набору шифров, GREASE и ALPN ---
    // Наборы шифров браузеров стабильны годами (в отличие от расширений),
    // поэтому сравниваем множество шифров, а не хеш целиком.
    static const uint16_t kChrome[] = { 0x1301,0x1302,0x1303,0xc02b,0xc02f,0xc02c,0xc030,
                                        0xcca9,0xcca8,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035 };
    static const uint16_t kFirefox[] = { 0x1301,0x1303,0x1302,0xc02b,0xc02f,0xcca9,0xcca8,0xc02c,
                                         0xc030,0xc00a,0xc009,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035 };
    auto sameSet = [&](const uint16_t* ref, size_t rn) {
        std::vector<uint16_t> r(ref, ref + rn);
        std::sort(r.begin(), r.end());
        return r == sc;
    };
    auto has = [&](uint16_t c) { return std::binary_search(sc.begin(), sc.end(), c); };
    bool chromeSet  = sameSet(kChrome,  sizeof(kChrome)  / sizeof(kChrome[0]));
    bool firefoxSet = sameSet(kFirefox, sizeof(kFirefox) / sizeof(kFirefox[0]));
    bool has3des = has(0x000a) || has(0xc008) || has(0xc012);
    auto inList = [](const std::vector<uint16_t>& v, uint16_t x) {
        return std::find(v.begin(), v.end(), x) != v.end();
    };
    // NSS (Firefox): record_size_limit / delegated_credentials — Go, rustls,
    // OpenSSL-клиенты по умолчанию их не шлют
    bool nssMark = inList(exts, 0x001c) || inList(exts, 0x0022);
    // группы ffdhe*/x448 — OpenSSL или NSS; у Go (quic-go) и rustls их нет
    bool ffdheOrX448 = inList(groups, 0x001e);
    for (uint16_t g : groups) if (g >= 0x0100 && g <= 0x0104) ffdheOrX448 = true;
    // Ed25519 в signature_algorithms: Go crypto/tls и rustls шлют всегда,
    // браузеры (Chrome, Safari, Firefox) — нет
    bool ed25519 = inList(sigAlgs, 0x0807);

    if (transport == 'q') {
        // Без GREASE в QUIC ходят и Firefox, и curl, и quic-go (Hysteria2) — одного
        // GREASE мало. VPN-признаком считаем только стек Go/rustls: Ed25519 есть,
        // меток NSS и групп OpenSSL нет. Всё прочее — не VPN (баллов не даёт).
        if (grease) { client = "браузер Chromium/Safari (QUIC)"; kind = JA4K_BROWSER; }
        else if (nssMark) { client = "Firefox (QUIC, NSS)"; kind = JA4K_BROWSER; }
        else if (ed25519 && !ffdheOrX448) {
            client = "QUIC-клиент на Go/Rust без GREASE (quic-go: Hysteria2, TUIC, Juicity; quinn)";
            kind = JA4K_LIBRARY;
        } else {
            client = "QUIC без GREASE, не Go-стек (Firefox, curl/OpenSSL и т.п.)";
            kind = JA4K_UNKNOWN;
        }
    } else if (ver < 0x0304) {
        client = "без TLS 1.3 — старая библиотека/ОС или встроенное устройство";
        kind = JA4K_LIBRARY;
    } else if (chromeSet && grease) {
        client = "Chromium (Chrome/Edge/Яндекс/Opera) или uTLS под Chrome";
        kind = JA4K_BROWSER;
    } else if (chromeSet) {
        // Ровно такой набор шифров у OkHttp (MODERN_TLS) — это большинство
        // Android-приложений. uTLS под Chrome копирует и GREASE, так что без
        // GREASE это не подделка, а обычное приложение: баллов не даёт.
        client = "шифры как у Chrome, без GREASE — Android-приложение (OkHttp) или BoringSSL";
        kind = JA4K_UNKNOWN;
    } else if (firefoxSet && !grease) {
        client = "Firefox (или uTLS под Firefox)";
        kind = JA4K_BROWSER;
    } else if (nssMark && !grease && !alpn.empty()) {
        // Firefox с изменённым набором шифров (новая версия, настройки about:config)
        client = "Firefox/NSS (по расширениям record_size_limit/delegated_credentials)";
        kind = JA4K_BROWSER;
    } else if (grease && has3des) {
        client = "Safari/WebKit (iOS/macOS) или uTLS под Safari";
        kind = JA4K_BROWSER;
    } else if (grease) {
        client = "клиент с GREASE (редкая сборка Chromium/Safari или uTLS)";
        kind = JA4K_UNKNOWN;
    } else if (alpn.empty()) {
        client = "не браузер: нет ALPN (Go — Xray/V2Ray/sing-box без uTLS, скрипт, API-клиент)";
        kind = JA4K_LIBRARY;
    } else {
        client = "не браузер: без GREASE (curl/OpenSSL, Go, Python, Java, Schannel…)";
        kind = JA4K_LIBRARY;
    }
    return true;
}

// JA4 по потоку TLS-записей (payload TCP): true, если ClientHello в нём целиком
static bool ja4FromTlsRecords(const uint8_t* d, size_t n, Packet& pk) {
    if (!d || n < 6 || d[0] != 0x16) return false;
    std::vector<uint8_t> s(d, d + n), hs;
    if (tlsCollectHello(s, hs) != 1) return false;
    return ja4FromHello(hs.data(), hs.size(), 't', pk.ja4, pk.tlsClient, pk.ja4Kind, &pk.ech);
}

class HelloReassembler {
    struct Pending {
        size_t idx = 0;              // пакет с первым сегментом — ему и пишем SNI
        uint32_t nextSeq = 0;        // ожидаемый seq следующего сегмента
        std::vector<uint8_t> buf;    // склеенные байты потока
        int segs = 0;
    };
    std::map<std::string, Pending> pend_;   // ключ — направление потока
    static const size_t kMaxBuf = 24 * 1024;
    static const int kMaxSegs = 64;

    // записать SNI из того, что собрано (в т.ч. частично — parseTlsSni
    // терпит обрыв, и имя часто уже есть в собранной части)
    // JA4 — только если ClientHello собран целиком
    static void apply(std::vector<Packet>& out, const Pending& pd) {
        if (pd.idx >= out.size()) return;
        std::vector<uint8_t> hs;
        int st = tlsCollectHello(pd.buf, hs);
        Packet& pk = out[pd.idx];
        if (pk.sni.empty()) {
            std::string sni = sniFromHello(hs);
            if (!sni.empty()) pk.sni = sni;
        }
        if (st == 1 && pk.ja4.empty())
            ja4FromHello(hs.data(), hs.size(), 't', pk.ja4, pk.tlsClient, pk.ja4Kind, &pk.ech);
    }

public:
    // вызывать сразу после out.push_back(pk) с payload этого TCP-сегмента
    void feed(std::vector<Packet>& out, const uint8_t* pay, size_t n) {
        if (out.empty() || !pay || n == 0) return;
        const size_t idx = out.size() - 1;
        const Packet& pk = out[idx];
        if (pk.proto != "TCP" || pk.seqStart < 0) return;
        const uint32_t seq = (uint32_t)pk.seqStart;
        std::string key = pk.srcIp + " " + std::to_string(pk.srcPort) + ">" +
                          pk.dstIp + " " + std::to_string(pk.dstPort);

        auto it = pend_.find(key);
        if (it != pend_.end()) {
            Pending& pd = it->second;
            int32_t diff = (int32_t)(seq - pd.nextSeq);
            if (diff <= 0) {
                // продолжение; перекрытие (ретрансмит) отрезаем
                size_t skip = (size_t)(-(int64_t)diff);
                if (skip < n) {
                    pd.buf.insert(pd.buf.end(), pay + skip, pay + n);
                    pd.nextSeq += (uint32_t)(n - skip);
                }
                pd.segs++;
                std::vector<uint8_t> hs;
                int st = tlsCollectHello(pd.buf, hs);
                if (st != 0 || pd.buf.size() > kMaxBuf || pd.segs > kMaxSegs) {
                    apply(out, pd);
                    pend_.erase(it);
                }
                return;
            }
            // дырка (сегмент потерян при съёме) — берём, что успели собрать
            apply(out, pd);
            pend_.erase(it);
        }

        // начало нового ClientHello, которого не хватило одного сегмента?
        // (SNI бывает уже в первом сегменте, а для JA4 нужен ClientHello целиком)
        // Средства обхода DPI (zapret/GoodbyeDPI/ByeDPI) режут ClientHello
        // на сегменты по 1–2 байта — поэтому начало ловим и по крошечному сегменту.
        if (!pk.sni.empty() && !pk.ja4.empty()) return;
        if (pay[0] != 0x16 || (n > 1 && pay[1] != 0x03) || (n > 5 && pay[5] != 0x01)) return;
        Pending pd;
        pd.idx = idx;
        pd.nextSeq = seq + (uint32_t)n;
        pd.buf.assign(pay, pay + n);
        pd.segs = 1;
        std::vector<uint8_t> hs;
        int st = tlsCollectHello(pd.buf, hs);
        if (st < 0) return;
        if (st == 1) { apply(out, pd); return; }   // несколько записей в одном сегменте
        pend_[key] = std::move(pd);
    }

    // конец файла: дописать SNI по незавершённым сборкам
    void flush(std::vector<Packet>& out) {
        for (auto& kv : pend_) apply(out, kv.second);
        pend_.clear();
    }
};

// ------------------------------------------------------------------
// DNS поверх TCP/53 (RFC 7766): перед каждым сообщением 2 байта длины; в
// одном сегменте бывает несколько сообщений, а одно сообщение — в нескольких
// сегментах. Поток собирается по направлению, готовые сообщения разбирает тот
// же parseDnsPayload, что и UDP. Сообщение пишется в пакет, которым оно
// завершилось; второе и следующие сообщения того же сегмента — в пакеты-копии
// нулевой длины (у Packet одно DNS-сообщение, иначе их некуда записать).
// После дыры в потоке (сегмент не попал в дамп) граница сообщений потеряна —
// ждём сегмент, похожий на начало сообщения. Встречается и DNS по TCP без
// префикса длины (кривые клиенты): его узнаём по числу вопросов на месте.
// ------------------------------------------------------------------
class DnsTcpReassembler {
    struct Stream {
        uint32_t nextSeq = 0;
        std::vector<uint8_t> buf;      // байты с начала текущего сообщения
        bool noPrefix = false;         // поток без префикса длины
    };
    std::map<std::string, Stream> st_;
    static const size_t kMaxBuf = 65535 + 2;

    // заголовок DNS: один вопрос и opcode QUERY — так почти у всех запросов/ответов
    static bool looksMsg(const uint8_t* m, size_t n) {
        return n >= 12 && be16(m + 4) == 1 && ((m[2] >> 3) & 0x0F) == 0;
    }
    // 1 — начало сообщения с префиксом длины, 2 — без префикса, 0 — не начало
    static int startKind(const uint8_t* p, size_t n) {
        if (n >= 14 && be16(p) >= 12 && looksMsg(p + 2, n - 2)) return 1;
        if (looksMsg(p, n)) return 2;
        if (n >= 2 && n < 14 && be16(p) >= 12) return 1;   // сегмент — лишь начало (префикс)
        return 0;
    }
    static Packet ghost(const Packet& pk) {
        Packet g;
        g.ts = pk.ts; g.srcIp = pk.srcIp; g.dstIp = pk.dstIp;
        g.srcPort = pk.srcPort; g.dstPort = pk.dstPort; g.proto = pk.proto;
        g.ttl = pk.ttl; g.dir = pk.dir; g.flags = "[.]"; g.valid = true;
        return g;
    }

public:
    // вызывать после out.push_back(pk) (и после остальных сборщиков) с payload сегмента
    void feed(std::vector<Packet>& out, const uint8_t* pay, size_t n) {
        if (out.empty() || !pay || n == 0) return;
        const size_t idx = out.size() - 1;
        if (out[idx].proto != "TCP" || out[idx].seqStart < 0) return;
        if (out[idx].srcPort != 53 && out[idx].dstPort != 53) return;
        const Packet pk = out[idx];    // копия: ниже out может вырасти
        const uint32_t seq = (uint32_t)pk.seqStart;
        const uint32_t segEnd = seq + (uint32_t)n;
        const std::string key = pk.srcIp + " " + std::to_string(pk.srcPort) + ">" +
                                pk.dstIp + " " + std::to_string(pk.dstPort);

        auto it = st_.find(key);
        if (it != st_.end()) {
            int32_t diff = (int32_t)(seq - it->second.nextSeq);
            if (diff < 0) {            // повтор/перекрытие: берём только новые байты
                size_t skip = (size_t)(-(int64_t)diff);
                if (skip >= n) return;
                pay += skip; n -= skip;
            } else if (diff > 0) {     // дыра: граница сообщений потеряна
                st_.erase(it);
                it = st_.end();
            }
        }
        if (it == st_.end()) {
            int k = startKind(pay, n);
            if (k == 0) return;
            Stream s;
            s.noPrefix = (k == 2);
            it = st_.emplace(key, std::move(s)).first;
        }
        Stream& s = it->second;
        s.buf.insert(s.buf.end(), pay, pay + n);
        s.nextSeq = segEnd;

        size_t pos = 0;
        int emitted = 0;
        for (;;) {
            const size_t left = s.buf.size() - pos;
            const uint8_t* m;
            size_t mlen;
            if (s.noPrefix) {
                // без префикса граница сообщения — конец сегмента
                if (left < 12) break;
                m = s.buf.data() + pos; mlen = left;
            } else {
                if (left < 2) break;
                mlen = be16(s.buf.data() + pos);
                if (mlen < 12) { st_.erase(it); return; }   // не DNS или сбились
                if (left - 2 < mlen) break;                 // сообщение ещё не собрано
                m = s.buf.data() + pos + 2;
            }
            if (!looksMsg(m, mlen)) { st_.erase(it); return; }
            if (emitted++ == 0) parseDnsPayload(m, mlen, out[idx]);
            else { out.push_back(ghost(pk)); parseDnsPayload(m, mlen, out.back()); }
            pos += s.noPrefix ? mlen : mlen + 2;
        }
        // сообщение без префикса — разовое (обычно хвост после дыры, префикс
        // остался в потерянном сегменте): следующий сегмент определяем заново
        if (s.noPrefix) { st_.erase(it); return; }
        s.buf.erase(s.buf.begin(), s.buf.begin() + pos);
        if (s.buf.size() > kMaxBuf) st_.erase(it);
    }
};

// ------------------------------------------------------------------
// QUIC Initial -> SNI (как делает Wireshark).
// Initial-пакеты шифруются, но ключи публичные: они выводятся из
// Destination Connection ID первого пакета клиента и константной «соли»
// версии (RFC 9001 §5.2, RFC 9369 для QUIC v2). Любой наблюдатель, в том
// числе ТСПУ, может снять защиту и прочитать ClientHello — так и работает
// блокировка QUIC по SNI. Мы делаем то же самое, чтобы увидеть имя сервера.
//   initial_secret = HKDF-Extract(salt, DCID)
//   client_secret  = HKDF-Expand-Label(initial_secret, "client in", 32)
//   key/iv/hp      = HKDF-Expand-Label(client_secret, "quic key|iv|hp")
// Дальше: снять защиту заголовка (AES-ECB по 16 байтам «пробы»), получить
// номер пакета, расшифровать AES-128-GCM и собрать CRYPTO-фреймы — Chrome
// режет ClientHello на куски, перемешивает их и разносит по двум датаграммам.
// Криптография — штатный Windows CNG (bcrypt), без своих реализаций.
// На macOS — CommonCrypto; GCM там не публичный, поэтому GCM собран из
// AES-ECB (счётчик) и GHASH по NIST SP 800-38D.
// ------------------------------------------------------------------
#ifndef _WIN32
static bool hmacSha256(const uint8_t* key, size_t kl, const uint8_t* msg, size_t ml, uint8_t out[32]) {
    CCHmac(kCCHmacAlgSHA256, key, kl, msg, ml, out);
    return true;
}

// AES-128-ECB по n блокам подряд (n*16 байт)
static bool aesEcbBlocks(const uint8_t key[16], const uint8_t* in, uint8_t* out, size_t n) {
    size_t got = 0;
    return CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, key, 16, nullptr,
                   in, n * 16, out, n * 16, &got) == kCCSuccess && got == n * 16;
}

static bool aesEcbBlock(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    return aesEcbBlocks(key, in, out, 1);
}

// Умножение в GF(2^128) для GHASH (побитово — данных тут пара килобайт)
static void gcmMul(uint8_t x[16], const uint8_t h[16]) {
    uint8_t z[16] = {0}, v[16];
    memcpy(v, h, 16);
    for (int i = 0; i < 128; i++) {
        if (x[i / 8] & (0x80 >> (i % 8)))
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        const bool lsb = v[15] & 1;
        for (int j = 15; j > 0; j--) v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xe1;
    }
    memcpy(x, z, 16);
}

static void ghashUpdate(uint8_t y[16], const uint8_t h[16], const uint8_t* d, size_t n) {
    for (size_t off = 0; off < n; off += 16) {
        const size_t l = std::min<size_t>(16, n - off);
        for (size_t j = 0; j < l; j++) y[j] ^= d[off + j];
        gcmMul(y, h);
    }
}

// AES-128-GCM: ct включает 16 байт тега в конце. false — тег не сошёлся.
static bool aesGcmOpen(const uint8_t key[16], const uint8_t nonce[12],
                       const uint8_t* aad, size_t aadLen,
                       const uint8_t* ct, size_t ctLen, std::vector<uint8_t>& pt) {
    if (ctLen <= 16) return false;
    const size_t n = ctLen - 16;
    const size_t blocks = (n + 15) / 16;
    // счётчики: J0 = nonce||0^31||1, данные — с inc32(J0)
    std::vector<uint8_t> ctr((blocks + 1) * 16), ks((blocks + 1) * 16);
    for (size_t b = 0; b <= blocks; b++) {
        uint8_t* c = &ctr[b * 16];
        memcpy(c, nonce, 12);
        const uint32_t v = (uint32_t)(b + 1);
        c[12] = (uint8_t)(v >> 24); c[13] = (uint8_t)(v >> 16); c[14] = (uint8_t)(v >> 8); c[15] = (uint8_t)v;
    }
    const uint8_t zero[16] = {0};
    uint8_t h[16];
    if (!aesEcbBlock(key, zero, h) || !aesEcbBlocks(key, ctr.data(), ks.data(), blocks + 1))
        return false;

    uint8_t y[16] = {0};
    ghashUpdate(y, h, aad, aadLen);
    ghashUpdate(y, h, ct, n);
    uint8_t lens[16];
    const uint64_t abits = (uint64_t)aadLen * 8, cbits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) {
        lens[i] = (uint8_t)(abits >> (56 - 8 * i));
        lens[8 + i] = (uint8_t)(cbits >> (56 - 8 * i));
    }
    ghashUpdate(y, h, lens, 16);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (uint8_t)((y[i] ^ ks[i]) ^ ct[n + i]);   // ks[0..15] = E(K, J0)
    if (diff) return false;

    pt.resize(n);
    for (size_t i = 0; i < n; i++) pt[i] = ct[i] ^ ks[16 + i];
    return true;
}
#else
struct QuicCng {
    BCRYPT_ALG_HANDLE hmac = nullptr, ecb = nullptr, gcm = nullptr;
    bool ok = false;
    QuicCng() {
        ok = BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hmac, BCRYPT_SHA256_ALGORITHM, nullptr,
                                                        BCRYPT_ALG_HANDLE_HMAC_FLAG))
          && BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&ecb, BCRYPT_AES_ALGORITHM, nullptr, 0))
          && BCRYPT_SUCCESS(BCryptSetProperty(ecb, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                                              sizeof(BCRYPT_CHAIN_MODE_ECB), 0))
          && BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&gcm, BCRYPT_AES_ALGORITHM, nullptr, 0))
          && BCRYPT_SUCCESS(BCryptSetProperty(gcm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                              sizeof(BCRYPT_CHAIN_MODE_GCM), 0));
    }
    ~QuicCng() {
        if (hmac) BCryptCloseAlgorithmProvider(hmac, 0);
        if (ecb)  BCryptCloseAlgorithmProvider(ecb, 0);
        if (gcm)  BCryptCloseAlgorithmProvider(gcm, 0);
    }
};
static QuicCng& quicCng() { static QuicCng c; return c; }

static bool hmacSha256(const uint8_t* key, size_t kl, const uint8_t* msg, size_t ml, uint8_t out[32]) {
    QuicCng& c = quicCng();
    if (!c.ok) return false;
    BCRYPT_HASH_HANDLE h = nullptr;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(c.hmac, &h, nullptr, 0, (PUCHAR)key, (ULONG)kl, 0))) return false;
    bool ok = BCRYPT_SUCCESS(BCryptHashData(h, (PUCHAR)msg, (ULONG)ml, 0))
           && BCRYPT_SUCCESS(BCryptFinishHash(h, out, 32, 0));
    BCryptDestroyHash(h);
    return ok;
}
#endif

// HKDF-Expand-Label из TLS 1.3 с пустым контекстом; L <= 32 (хватает одного блока T(1))
static bool hkdfExpandLabel(const uint8_t secret[32], const char* label, uint8_t* out, size_t L) {
    std::string full = std::string("tls13 ") + label;
    std::vector<uint8_t> info;
    info.push_back((uint8_t)(L >> 8)); info.push_back((uint8_t)(L & 0xFF));
    info.push_back((uint8_t)full.size());
    info.insert(info.end(), full.begin(), full.end());
    info.push_back(0);                   // context = ""
    info.push_back(1);                   // счётчик блока T(1)
    uint8_t t[32];
    if (!hmacSha256(secret, 32, info.data(), info.size(), t)) return false;
    memcpy(out, t, L);
    return true;
}

#ifdef _WIN32
static bool aesEcbBlock(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    QuicCng& c = quicCng();
    if (!c.ok) return false;
    BCRYPT_KEY_HANDLE k = nullptr;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(c.ecb, &k, nullptr, 0, (PUCHAR)key, 16, 0))) return false;
    uint8_t buf[16];
    memcpy(buf, in, 16);
    ULONG got = 0;
    bool ok = BCRYPT_SUCCESS(BCryptEncrypt(k, buf, 16, nullptr, nullptr, 0, out, 16, &got, 0)) && got == 16;
    BCryptDestroyKey(k);
    return ok;
}

// AES-128-GCM: ct включает 16 байт тега в конце. false — тег не сошёлся.
static bool aesGcmOpen(const uint8_t key[16], const uint8_t nonce[12],
                       const uint8_t* aad, size_t aadLen,
                       const uint8_t* ct, size_t ctLen, std::vector<uint8_t>& pt) {
    QuicCng& c = quicCng();
    if (!c.ok || ctLen <= 16) return false;
    BCRYPT_KEY_HANDLE k = nullptr;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(c.gcm, &k, nullptr, 0, (PUCHAR)key, 16, 0))) return false;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR)nonce;            ai.cbNonce = 12;
    ai.pbAuthData = (PUCHAR)aad;           ai.cbAuthData = (ULONG)aadLen;
    ai.pbTag = (PUCHAR)(ct + ctLen - 16);  ai.cbTag = 16;
    pt.resize(ctLen - 16);
    ULONG got = 0;
    bool ok = BCRYPT_SUCCESS(BCryptDecrypt(k, (PUCHAR)ct, (ULONG)(ctLen - 16), &ai, nullptr, 0,
                                           pt.data(), (ULONG)pt.size(), &got, 0));
    BCryptDestroyKey(k);
    if (ok) pt.resize(got);
    return ok;
}
#endif

static bool quicVarint(const uint8_t* d, size_t n, size_t& p, uint64_t& v) {
    if (p >= n) return false;
    size_t l = (size_t)1 << (d[p] >> 6);
    if (p + l > n) return false;
    v = d[p] & 0x3f;
    for (size_t i = 1; i < l; i++) v = (v << 8) | d[p + i];
    p += l;
    return true;
}

static const uint32_t QUIC_V2 = 0x6b3343cf;
static bool quicKnownVersion(uint32_t v) {
    return v == 1 || v == QUIC_V2 || (v >= 0xff00001d && v <= 0xff000020);   // + draft-29..32
}

struct QuicKeys { uint8_t key[16], iv[12], hp[16]; };

static bool quicClientKeys(uint32_t ver, const uint8_t* dcid, size_t dl, QuicKeys& k) {
    static const uint8_t saltV1[20]  = { 0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,0x4d,0x17,
                                         0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a };
    static const uint8_t saltV2[20]  = { 0x0d,0xed,0xe3,0xde,0xf7,0x00,0xa6,0xdb,0x81,0x93,
                                         0x81,0xbe,0x6e,0x26,0x9d,0xcb,0xf9,0xbd,0x2e,0xd9 };
    static const uint8_t saltD29[20] = { 0xaf,0xbf,0xec,0x28,0x99,0x93,0xd2,0x4c,0x9e,0x97,
                                         0x86,0xf1,0x9c,0x61,0x11,0xe0,0x43,0x90,0xa8,0x99 };
    bool v2 = (ver == QUIC_V2);
    const uint8_t* salt = v2 ? saltV2 : (ver == 1 ? saltV1 : saltD29);
    uint8_t initial[32], client[32];
    if (!hmacSha256(salt, 20, dcid, dl, initial)) return false;       // HKDF-Extract
    if (!hkdfExpandLabel(initial, "client in", client, 32)) return false;
    return hkdfExpandLabel(client, v2 ? "quicv2 key" : "quic key", k.key, 16)
        && hkdfExpandLabel(client, v2 ? "quicv2 iv"  : "quic iv",  k.iv, 12)
        && hkdfExpandLabel(client, v2 ? "quicv2 hp"  : "quic hp",  k.hp, 16);
}

// Снять защиту заголовка и расшифровать один long-header пакет.
// q — начало пакета, pnOff — смещение номера пакета, end — конец пакета.
static bool quicOpenPacket(const uint8_t* q, size_t pnOff, size_t end,
                           const QuicKeys& k, std::vector<uint8_t>& plain) {
    if (pnOff + 4 + 16 > end) return false;           // нет 16 байт «пробы» для маски
    uint8_t mask[16];
    if (!aesEcbBlock(k.hp, q + pnOff + 4, mask)) return false;
    std::vector<uint8_t> hdr(q, q + pnOff + 4);
    hdr[0] ^= mask[0] & 0x0f;                          // long header: младшие 4 бита
    size_t pnLen = (size_t)(hdr[0] & 3) + 1;
    uint64_t pn = 0;
    for (size_t i = 0; i < pnLen; i++) {
        hdr[pnOff + i] ^= mask[1 + i];
        pn = (pn << 8) | hdr[pnOff + i];
    }
    hdr.resize(pnOff + pnLen);                         // AAD = заголовок без защиты
    uint8_t nonce[12];
    memcpy(nonce, k.iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (uint8_t)(pn >> (8 * i));
    size_t ctOff = pnOff + pnLen;
    return aesGcmOpen(k.key, nonce, hdr.data(), hdr.size(), q + ctOff, end - ctOff, plain);
}

class QuicHelloCollector {
    struct Flow {
        size_t idx = 0;                  // первый расшифрованный Initial — ему пишем SNI
        uint32_t ver = 0;
        QuicKeys keys{};
        std::vector<uint8_t> buf, have; // CRYPTO-поток и карта заполненных байт
        bool done = false;
    };
    std::map<std::string, Flow> fl_;    // ключ — направление потока (клиент -> сервер)
    static constexpr size_t kMaxCrypto = 64 * 1024;
    static constexpr size_t kMaxFlows = 20000;

    // ClientHello клиента: ключи потока, иначе — выведенные из DCID этого пакета.
    // Пакет сервера (другие ключи, "server in") просто не расшифруется — тег не сойдётся.
    void onInitial(std::vector<Packet>& out, size_t idx, uint32_t ver,
                   const uint8_t* dcid, size_t dl,
                   const uint8_t* q, size_t pnOff, size_t end) {
        const Packet& pk = out[idx];
        std::string key = pk.srcIp + " " + std::to_string(pk.srcPort) + ">" +
                          pk.dstIp + " " + std::to_string(pk.dstPort);
        auto it = fl_.find(key);
        if (it != fl_.end() && it->second.done) return;
        if (it == fl_.end() && fl_.size() >= kMaxFlows) return;
        std::vector<uint8_t> plain;
        QuicKeys k;
        bool ok = false;
        if (it != fl_.end() && it->second.ver == ver) {
            k = it->second.keys;
            ok = quicOpenPacket(q, pnOff, end, k, plain);
        }
        if (!ok) {
            if (!quicClientKeys(ver, dcid, dl, k)) return;
            ok = quicOpenPacket(q, pnOff, end, k, plain);
        }
        if (!ok) return;
        if (it == fl_.end()) {
            it = fl_.emplace(key, Flow()).first;
            it->second.idx = idx;
            it->second.ver = ver;
            it->second.keys = k;
        }
        Flow& f = it->second;

        // фреймы: PADDING, PING, ACK пропускаем, CRYPTO кладём по смещению
        const uint8_t* d = plain.data();
        size_t n = plain.size(), p = 0;
        while (p < n) {
            uint8_t t = d[p];
            if (t == 0x00 || t == 0x01) { p++; continue; }
            uint64_t v = 0;
            if (t == 0x02 || t == 0x03) {             // ACK (0x03 — с ECN-счётчиками)
                p++;
                uint64_t cnt = 0;
                bool good = quicVarint(d, n, p, v) && quicVarint(d, n, p, v) &&
                            quicVarint(d, n, p, cnt) && quicVarint(d, n, p, v);
                for (uint64_t i = 0; good && i < cnt; i++)
                    good = quicVarint(d, n, p, v) && quicVarint(d, n, p, v);
                for (int i = 0; good && t == 0x03 && i < 3; i++)
                    good = quicVarint(d, n, p, v);
                if (!good) break;
                continue;
            }
            if (t == 0x06) {                          // CRYPTO: offset, length, data
                p++;
                uint64_t off = 0, len = 0;
                if (!quicVarint(d, n, p, off) || !quicVarint(d, n, p, len) || len > n - p) break;
                if (off < kMaxCrypto && len > 0) {
                    size_t e = (size_t)std::min<uint64_t>(off + len, kMaxCrypto);
                    if (f.buf.size() < e) { f.buf.resize(e, 0); f.have.resize(e, 0); }
                    for (size_t i = (size_t)off; i < e; i++) { f.buf[i] = d[p + (i - (size_t)off)]; f.have[i] = 1; }
                }
                p += (size_t)len;
                continue;
            }
            break;                                    // CONNECTION_CLOSE и прочее — дальше не читаем
        }

        // непрерывное начало потока — это ClientHello (без TLS-записи)
        size_t pre = 0;
        while (pre < f.have.size() && f.have[pre]) pre++;
        if (pre == 0) return;
        if (f.buf[0] != 0x01) { f.done = true; return; }
        std::vector<uint8_t> hs(f.buf.begin(), f.buf.begin() + pre);
        Packet& first = out[f.idx];
        if (first.sni.empty()) {
            std::string sni = sniFromHello(hs);
            if (!sni.empty()) first.sni = sni;
        }
        // SNI часто уже в первой датаграмме, но для JA4 ждём ClientHello целиком
        if (pre >= 4) {
            size_t need = 4 + (((size_t)hs[1] << 16) | ((size_t)hs[2] << 8) | hs[3]);
            if (pre >= need) {                        // ClientHello целиком
                ja4FromHello(hs.data(), need, 'q', first.ja4, first.tlsClient, first.ja4Kind, &first.ech);
                f.done = true;
            }
        }
    }

public:
    // вызывать сразу после out.push_back(pk) с payload этой UDP-датаграммы
    void feed(std::vector<Packet>& out, const uint8_t* pay, size_t n) {
        if (out.empty() || !pay || n < 7) return;
        const size_t idx = out.size() - 1;
        if (out[idx].proto != "UDP") return;
        size_t pos = 0;
        // в одной датаграмме может быть несколько склеенных QUIC-пакетов
        for (int guard = 0; guard < 4 && pos + 7 <= n; guard++) {
            const uint8_t* q = pay + pos;
            size_t qn = n - pos;
            if ((q[0] & 0xC0) != 0xC0) break;         // short header или не QUIC
            uint32_t ver = be32(q + 1);
            if (!quicKnownVersion(ver)) break;        // в т.ч. Version Negotiation (0)
            int type = (q[0] >> 4) & 3;
            bool v2 = (ver == QUIC_V2);
            bool initial = v2 ? (type == 1) : (type == 0);
            bool retry   = v2 ? (type == 0) : (type == 3);
            if (retry) { if (out[idx].quic == 0) out[idx].quic = 2; break; }
            size_t p = 5;
            size_t dl = q[p++];
            if (dl > 20 || p + dl + 1 > qn) break;
            const uint8_t* dcid = q + p;
            p += dl;
            size_t sl = q[p++];
            if (sl > 20 || p + sl > qn) break;
            p += sl;
            uint64_t v = 0;
            if (initial) {                            // токен есть только у Initial
                if (!quicVarint(q, qn, p, v) || v > qn - p) break;
                p += (size_t)v;
            }
            if (!quicVarint(q, qn, p, v)) break;      // Length: номер пакета + payload
            size_t pnOff = p;
            bool whole = (v <= qn - p);
            out[idx].quic = initial ? 1 : (out[idx].quic ? out[idx].quic : 2);
            if (initial && whole) onInitial(out, idx, ver, dcid, dl, q, pnOff, pnOff + (size_t)v);
            if (!whole) break;                        // обрезано snaplen
            pos += pnOff + (size_t)v;
        }
    }
};

// Прочитать .pcap целиком. err — текст ошибки/предупреждения.
// ------------------------------------------------------------------
// pcapng — секционный формат, пришедший на смену классическому pcap.
// Структура: блоки переменной длины, каждый начинается с
//   block_type (4) + block_total_length (4) + тело + block_total_length (4).
// Ключевые типы:
//   SHB (0x0A0D0D0A) — Section Header: byte order magic 0x1A2B3C4D
//   IDB (0x00000001) — Interface Description: linktype + snaplen
//   EPB (0x00000006) — Enhanced Packet: interface_id + timestamp + данные
//   SPB (0x00000003) — Simple Packet: только данные, без метки времени
// Опции блоков нас не интересуют — пропускаем.
// ------------------------------------------------------------------
static std::vector<Packet> readPcapng(const std::vector<unsigned char>& buf,
                                      std::string& err) {
    std::vector<Packet> out;
    if (buf.size() < 28) { err = "файл слишком мал для pcapng"; return out; }

    size_t pos = 0;
    bool be = false;
    // tsresol по умолчанию — микросекунды (10^-6); интерфейс может переопределить
    struct IfDesc { int linkType; uint64_t tsUnits; int64_t tsOffset; };
    std::vector<IfDesc> ifaces;
    HelloReassembler hello;
    QuicHelloCollector quic;
    DnsTcpReassembler dnsTcp;
    // у SPB своего времени нет — берём время последнего EPB, чтобы пакет не
    // улетал в 00:00:00 и не ломал порядок и длительности потоков
    std::string lastTs = "00:00:00.000000";

    while (pos + 12 <= buf.size()) {
        uint32_t btype = rd32(buf.data() + pos, false);
        uint32_t blen  = rd32(buf.data() + pos + 4, false);

        // SHB — определяем порядок байт по magic (BOM лежит сразу после Block Total Length)
        if (btype == 0x0A0D0D0A) {
            if (pos + 12 > buf.size()) break;
            uint32_t bom = rd32(buf.data() + pos + 8, false);
            if (bom == 0x1A2B3C4D) be = false;
            else                   be = true;
            blen = rd32(buf.data() + pos + 4, be);
            ifaces.clear();
            if (blen < 12 || pos + blen > buf.size()) break;
            pos += blen;
            continue;
        }

        btype = rd32(buf.data() + pos, be);
        blen  = rd32(buf.data() + pos + 4, be);
        if (blen < 12 || pos + blen > buf.size()) break;

        if (btype == 1) {   // IDB
            if (pos + 16 > buf.size()) { pos += blen; continue; }
            uint16_t lt = rd16(buf.data() + pos + 8, be);
            uint64_t tsUnits = 1000000;   // единиц времени в секунде; по умолчанию 10^-6
            int64_t  tsOffset = 0;
            // ищем опции if_tsresol (код 9) и if_tsoffset (код 14) в блоке
            size_t opos = pos + 16;                    // начало опций
            size_t oend = pos + blen - 4;              // конец (перед завершающим length)
            while (opos + 4 <= oend) {
                uint16_t ocode = rd16(buf.data() + opos, be);
                uint16_t olen  = rd16(buf.data() + opos + 2, be);
                if (ocode == 0) break;                 // opt_endofopt
                if (opos + 4 + olen > oend) break;     // опция вылезает за блок
                if (ocode == 9 && olen >= 1) {         // if_tsresol
                    uint8_t rv = buf[opos + 4];
                    // старший бит: 2^-N, иначе 10^-N. Любое N, влезающее в
                    // 64 бита; остальное — битый блок, остаёмся на микросекундах.
                    int pw = rv & 0x7f;
                    if (rv & 0x80) {
                        if (pw <= 63) tsUnits = 1ULL << pw;
                    } else if (pw <= 19) {
                        tsUnits = 1;
                        for (int i = 0; i < pw; ++i) tsUnits *= 10;
                    }
                } else if (ocode == 14 && olen >= 8) { // if_tsoffset, секунды
                    tsOffset = (int64_t)(((uint64_t)rd32(buf.data() + opos + (be ? 4 : 8), be) << 32)
                                         | rd32(buf.data() + opos + (be ? 8 : 4), be));
                }
                opos += 4 + ((olen + 3) & ~3u);        // опции выровнены по 4
            }
            ifaces.push_back({(int)lt, tsUnits, tsOffset});

        } else if (btype == 6) {   // EPB
            if (pos + 32 > buf.size()) { pos += blen; continue; }
            uint32_t ifId   = rd32(buf.data() + pos + 8, be);
            uint32_t tsHi   = rd32(buf.data() + pos + 12, be);
            uint32_t tsLo   = rd32(buf.data() + pos + 16, be);
            uint32_t caplen = rd32(buf.data() + pos + 20, be);
            const unsigned char* pdata = buf.data() + pos + 28;
            // данные обязаны лежать внутри блока (иначе блок битый — чужие байты)
            if (28 + (size_t)caplen + 4 > blen) { pos += blen; continue; }

            int lt = 1;
            uint64_t tsUnits = 1000000;
            int64_t  tsOffset = 0;
            if (ifId < ifaces.size()) {
                lt = ifaces[ifId].linkType;
                tsUnits = ifaces[ifId].tsUnits; tsOffset = ifaces[ifId].tsOffset;
            }

            uint64_t ts64 = ((uint64_t)tsHi << 32) | tsLo;
            uint64_t frac = ts64 % tsUnits;
            uint32_t sec  = (uint32_t)((int64_t)(ts64 / tsUnits) + tsOffset);
            uint32_t usec;
            if (tsUnits == 1000000)     usec = (uint32_t)frac;
            else if (tsUnits > 1000000 && tsUnits % 1000000 == 0)
                                        usec = (uint32_t)(frac / (tsUnits / 1000000));
            else if (tsUnits < 1000000 && 1000000 % tsUnits == 0)
                                        usec = (uint32_t)(frac * (1000000 / tsUnits));
            else {                      // 2^-N: доля секунды через double
                usec = (uint32_t)((double)frac * 1e6 / (double)tsUnits);
                if (usec > 999999) usec = 999999;
            }

            std::string ts = tsToStr(sec, usec);
            lastTs = ts;
            Packet pk;
            const uint8_t* pay = nullptr; size_t payLen = 0;
            if (parseFrame(pdata, caplen, lt, ts, pk, &pay, &payLen)) {
                // epb_flags (опция 2): биты 0-1 — направление (1 вход, 2 выход).
                // Его пишут Npcap/dumpcap, если драйвер знает направление;
                // заголовок SLL/SLL2 (если он был) важнее — не перетираем.
                if (pk.dir < 0) {
                    size_t opos = pos + 28 + (((size_t)caplen + 3) & ~(size_t)3);
                    size_t oend = pos + blen - 4;
                    while (opos + 4 <= oend) {
                        uint16_t ocode = rd16(buf.data() + opos, be);
                        uint16_t olen  = rd16(buf.data() + opos + 2, be);
                        if (ocode == 0) break;
                        if (opos + 4 + olen > oend) break;
                        if (ocode == 2 && olen == 4) {
                            uint32_t fl = rd32(buf.data() + opos + 4, be) & 3u;
                            if (fl == 1) pk.dir = 0; else if (fl == 2) pk.dir = 1;
                        }
                        opos += 4 + ((olen + 3) & ~3u);
                    }
                }
                out.push_back(std::move(pk));
                hello.feed(out, pay, payLen);
                quic.feed(out, pay, payLen);
                dnsTcp.feed(out, pay, payLen);
            }

        } else if (btype == 3) {   // SPB — без времени и без interface_id
            if (blen < 16 || pos + 16 > buf.size()) { pos += blen; continue; }
            uint32_t origLen = rd32(buf.data() + pos + 8, be);
            uint32_t caplen = blen - 16;    // тело SPB = блок минус header/footer
            if (origLen < caplen) caplen = origLen;
            const unsigned char* pdata = buf.data() + pos + 12;
            if (pos + 12 + caplen > buf.size()) { pos += blen; continue; }
            int lt = ifaces.empty() ? 1 : ifaces[0].linkType;
            Packet pk;
            const uint8_t* pay = nullptr; size_t payLen = 0;
            if (parseFrame(pdata, caplen, lt, lastTs, pk, &pay, &payLen)) {
                out.push_back(std::move(pk));
                hello.feed(out, pay, payLen);
                quic.feed(out, pay, payLen);
                dnsTcp.feed(out, pay, payLen);
            }
        }

        pos += blen;
    }
    hello.flush(out);
    return out;
}

static std::vector<Packet> readPcap(const std::string& path, std::string& err) {
    std::vector<Packet> out;
    std::ifstream f(upath(path), std::ios::binary | std::ios::ate);
    if (!f) { err = "не удалось открыть файл"; return out; }
    // одним read вместо istreambuf_iterator (тот читает побайтно и
    // многократно перевыделяет вектор — на сотнях МБ это секунды)
    std::streamoff fsz = f.tellg();
    if (fsz < 0) { err = "не удалось прочитать файл"; return out; }
    std::vector<unsigned char> buf((size_t)fsz);
    f.seekg(0, std::ios::beg);
    if (!buf.empty() && !f.read((char*)buf.data(), (std::streamsize)buf.size())) {
        err = "не удалось прочитать файл"; return out;
    }
    if (buf.size() < 24) { err = "файл слишком мал для pcap"; return out; }

    uint32_t magic = be32(buf.data());
    if (magic == 0x0A0D0D0A) {
        return readPcapng(buf, err);
    }

    bool be;          // порядок байт
    bool nano = false; // наносекунды вместо микросекунд
    uint32_t m_le = rd32(buf.data(), false);
    uint32_t m_be = rd32(buf.data(), true);
    if (m_le == 0xA1B2C3D4) { be = false; nano = false; }
    else if (m_be == 0xA1B2C3D4) { be = true; nano = false; }
    else if (m_le == 0xA1B23C4D) { be = false; nano = true; }
    else if (m_be == 0xA1B23C4D) { be = true; nano = true; }
    else { err = "не похоже на pcap (неверная сигнатура)"; return out; }

    // в старших битах поля бывают флаги FCS — сам linktype в младших 16
    uint32_t linkType = rd32(buf.data() + 20, be) & 0xFFFF;

    size_t pos = 24; // после глобального заголовка
    HelloReassembler hello;
    QuicHelloCollector quic;
    DnsTcpReassembler dnsTcp;
    while (pos + 16 <= buf.size()) {
        uint32_t tsSec  = rd32(buf.data() + pos, be);
        uint32_t tsFrac = rd32(buf.data() + pos + 4, be);
        uint32_t caplen = rd32(buf.data() + pos + 8, be);
        // uint32_t origlen = rd32(buf.data() + pos + 12, be);
        pos += 16;
        if (pos + caplen > buf.size()) break;

        uint32_t usec = nano ? (tsFrac / 1000) : tsFrac;
        std::string ts = tsToStr(tsSec, usec);

        Packet pk;
        const uint8_t* pay = nullptr; size_t payLen = 0;
        if (parseFrame(buf.data() + pos, caplen, (int)linkType, ts, pk, &pay, &payLen)) {
            out.push_back(std::move(pk));
            hello.feed(out, pay, payLen);
            quic.feed(out, pay, payLen);
            dnsTcp.feed(out, pay, payLen);
        }
        pos += caplen;
    }
    hello.flush(out);
    return out;
}

// расширение файла в нижнем регистре
static std::string lowerExt(const std::string& path) {
    size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) return "";
    std::string e = path.substr(dot + 1);
    for (auto& c : e) c = (char)::tolower((unsigned char)c);
    return e;
}

// По пути «..._in.pcap» подбирает парный «..._out.pcap» (и наоборот).
// Пустая строка = суффикса нет или парного файла не существует.
std::string siblingDumpPath(const std::string& path) {
    size_t slash = path.find_last_of("\\/");
    size_t dot   = path.find_last_of('.');
    // точка должна быть в имени файла, а не в каком-то каталоге выше по пути
    bool hasExt = (dot != std::string::npos &&
                   (slash == std::string::npos || dot > slash));
    std::string stem = hasExt ? path.substr(0, dot) : path;
    std::string ext  = hasExt ? path.substr(dot)    : std::string();

    auto endsWith = [](const std::string& s, const char* suf) {
        size_t n = strlen(suf);
        return s.size() > n && _stricmp(s.c_str() + s.size() - n, suf) == 0;
    };
    std::string cand;
    if      (endsWith(stem, "_in"))  cand = stem.substr(0, stem.size() - 3) + "_out" + ext;
    else if (endsWith(stem, "_out")) cand = stem.substr(0, stem.size() - 4) + "_in"  + ext;
    else return "";

    std::ifstream f(upath(cand), std::ios::binary);
    return f ? cand : std::string();
}

// Загрузка ОДНОГО файла дампа: бинарный pcap либо текстовый вывод tcpdump.
// fmt — распознанный формат (для печати). false + err — файл прочитать не вышло.
static bool loadDumpFile(const std::string& path, std::vector<Packet>& out,
                         std::string& err, std::string& fmt) {
    out.clear();
    std::string ext = lowerExt(path);
    bool wantPcap = (ext == "pcap" || ext == "pcapng" || ext == "cap" || ext == "dmp");
    if (!wantPcap) {
        // заглянем в первые 4 байта — вдруг это pcap без «правильного» расширения
        std::ifstream pf(upath(path), std::ios::binary);
        if (pf) {
            unsigned char m[4] = {0};
            pf.read((char*)m, 4);
            uint32_t le  = ((uint32_t)m[3]<<24)|((uint32_t)m[2]<<16)|((uint32_t)m[1]<<8)|m[0];
            uint32_t beM = ((uint32_t)m[0]<<24)|((uint32_t)m[1]<<16)|((uint32_t)m[2]<<8)|m[3];
            if (le == 0xA1B2C3D4 || beM == 0xA1B2C3D4 ||
                le == 0xA1B23C4D || beM == 0xA1B23C4D || beM == 0x0A0D0D0A)
                wantPcap = true;
        }
    }

    if (wantPcap) {
        out = readPcap(path, err);
        if (!err.empty()) return false;
        // Определяем формат по magic: pcapng начинается с 0x0A0D0D0A (SHB)
        std::ifstream mf(upath(path), std::ios::binary);
        unsigned char hdr[4] = {0};
        if (mf) mf.read((char*)hdr, 4);
        fmt = (be32(hdr) == 0x0A0D0D0A) ? "pcapng (бинарный)" : "pcap (бинарный)";
        return true;
    }

    std::ifstream f(upath(path), std::ios::binary);
    if (!f) { err = "не удалось открыть файл"; return false; }
    fmt = "текстовый дамп tcpdump";

    // читаем и склеиваем разорванные строки.
    // Запись пакета начинается со штампа времени вида HH:MM:SS.xxxxxx.
    auto startsWithTime = [](const std::string& s) {
        std::string t = trim(s);
        if (t.size() < 8) return false;
        return isdigit((unsigned char)t[0]) && isdigit((unsigned char)t[1]) && t[2] == ':' &&
               isdigit((unsigned char)t[3]) && isdigit((unsigned char)t[4]) && t[5] == ':';
    };

    // строка-продолжение пакета НЕ должна быть служебной сводкой tcpdump
    // ("N packets captured", "... received by filter", "... dropped by kernel"),
    // иначе её цифры попадут в length последнего пакета и раздуют объём.
    auto isTcpdumpTrailer = [](const std::string& s) {
        return s.find("packets captured") != std::string::npos ||
               s.find("packets received") != std::string::npos ||
               s.find("packets dropped")  != std::string::npos ||
               s.find("received by filter")!= std::string::npos ||
               s.find("dropped by kernel") != std::string::npos ||
               s.find("dropped by interface") != std::string::npos;
    };

    std::vector<std::string> records;
    std::string raw, cur;
    while (std::getline(f, raw)) {
        if (!raw.empty() && raw.back() == '\r') raw.pop_back();
        raw = fixPad(raw);
        std::string t = trim(raw);
        if (t.empty()) continue;
        if (isTcpdumpTrailer(t)) {        // дошли до сводки tcpdump — пакеты кончились
            if (!cur.empty()) { records.push_back(cur); cur.clear(); }
            continue;
        }
        if (startsWithTime(t)) {
            if (!cur.empty()) records.push_back(cur);
            cur = t;
        } else if (!cur.empty()) {
            // настоящее продолжение пакета — приклеиваем через пробел
            cur += " " + t;
        }
    }
    if (!cur.empty()) records.push_back(cur);

    out.reserve(records.size());
    for (auto& r : records) {
        Packet p = parseLine(r);
        if (p.valid) out.push_back(std::move(p));
    }
    return true;
}

// ------------------------------------------------------------------
// РЕЖИМ 2: диагностика проблем соединения / блокировок по TCP-флагам.
// Пассивно подсвечивает аномалии. ВАЖНО: по дампу нельзя достоверно отличить
// блокировку провайдером от недоступности сервера или плохого канала —
// выводим признаки, а вывод о причине остаётся за человеком.
// ------------------------------------------------------------------
// Конвертирует строку времени "HH:MM:SS.usec" в число микросекунд с начала суток.
// Возвращает -1, если не удалось распарсить.
// Разбор вручную (без sscanf): анализаторы вызывают её для каждого пакета
// полтора десятка раз. Дробная часть приводится к 6 знакам, так что и
// наносекундный штамп (tcpdump --nano) даёт микросекунды, а не число в 1000 раз больше.
long long tsToMicros(const std::string& ts) {
    const char* p = ts.c_str();
    while (*p == ' ' || *p == '\t') p++;
    long long hms[3];
    for (int k = 0; k < 3; k++) {
        if (!isdigit((unsigned char)*p)) return -1;
        long long v = 0; int nd = 0;
        while (isdigit((unsigned char)*p)) {
            if (++nd > 9) return -1;
            v = v * 10 + (*p++ - '0');
        }
        hms[k] = v;
        if (k < 2) { if (*p != ':') return -1; p++; }
    }
    long long usec = 0;
    if (*p == '.') {
        p++;
        int nd = 0;
        for (; isdigit((unsigned char)*p); p++)
            if (nd < 6) { usec = usec * 10 + (*p - '0'); nd++; }
        for (; nd < 6; nd++) usec *= 10;
    }
    return (hms[0] * 3600 + hms[1] * 60 + hms[2]) * 1000000LL + usec;
}

// Кто на том конце IPsec (UDP 500/4500): VPN или звонки по Wi-Fi (VoWiFi —
// телефон строит IPsec до ePDG своего мобильного оператора). По одному пакету
// не понять, поэтому решаем по всему дампу и проставляем Packet::ipsecPeer:
//  - VoWiFi точно: DNS в этом же дампе отдал адрес на имя ePDG (стандартное
//    epdg.epc.mncXXX.mccXXX.pub.3gppnetwork.org, 3GPP TS 23.003);
//  - IPsec-VPN точно: IKEv1 (VoWiFi по 3GPP TS 24.302 — только IKEv2) или
//    IKE SA начал удалённый адрес — у абонента IPsec-сервер, а ePDG сам к
//    телефону не подключается;
//  - признаков нет или они противоречат друг другу — 0, «не ясно».
// Хостинг тут не учитываем (сведений об адресах ещё нет) — это ipsecClass.
// Нужен локальный адрес — вызывать после его определения.
static void markIpsecPeers(std::vector<Packet>& packets) {
    auto isIpsecPort = [](const Packet& p) {
        return p.proto == "UDP" && (p.srcPort == 500 || p.srcPort == 4500 ||
                                    p.dstPort == 500 || p.dstPort == 4500);
    };
    // имя ePDG: какая-нибудь метка начинается с «epdg»
    auto isEpdgName = [](std::string n) {
        for (auto& c : n) c = (char)tolower((unsigned char)c);
        for (size_t pos = 0; pos < n.size(); ) {
            if (n.compare(pos, 4, "epdg") == 0) return true;
            size_t dot = n.find('.', pos);
            if (dot == std::string::npos) break;
            pos = dot + 1;
        }
        return false;
    };
    // запрос и ответ DNS — по (IP клиента, порт клиента, id), как в analyzeDnsAnomalies
    std::set<std::string> epdgIps;
    std::map<std::string, std::string> dnsQByKey;
    for (const auto& p : packets) {
        if (p.dnsId.empty()) continue;
        if (!p.dnsIsResponse) {
            if (!p.dnsQuery.empty())
                dnsQByKey[p.srcIp + "|" + std::to_string(p.srcPort) + "|" + p.dnsId] = p.dnsQuery;
            continue;
        }
        std::string q = p.dnsQuery;
        if (q.empty()) {
            auto it = dnsQByKey.find(p.dstIp + "|" + std::to_string(p.dstPort) + "|" + p.dnsId);
            if (it != dnsQByKey.end()) q = it->second;
        }
        if (q.empty() || !isEpdgName(q)) continue;
        for (const auto& a : p.dnsAnswers) epdgIps.insert(a);
        if (p.dnsAnswers.empty() && !p.dnsAnswerIp.empty()) epdgIps.insert(p.dnsAnswerIp);
    }
    std::set<std::string> vpnIps;
    for (const auto& p : packets) {
        if (!p.ike || !isIpsecPort(p)) continue;
        bool sLoc = isLocalIp(p.srcIp), dLoc = isLocalIp(p.dstIp);
        if (sLoc == dLoc) continue;
        if ((p.ike & 1) || (!sLoc && (p.ike & 4))) vpnIps.insert(sLoc ? p.dstIp : p.srcIp);
    }
    if (epdgIps.empty() && vpnIps.empty()) return;
    for (auto& p : packets) {
        if (!isIpsecPort(p)) continue;
        bool sLoc = isLocalIp(p.srcIp), dLoc = isLocalIp(p.dstIp);
        if (sLoc == dLoc) continue;
        const std::string& remote = sLoc ? p.dstIp : p.srcIp;
        const bool vpn = vpnIps.count(remote) > 0, voWifi = epdgIps.count(remote) > 0;
        if (vpn != voWifi) p.ipsecPeer = vpn ? 1 : 2;
    }
}

// Загрузка набора файлов дампа (один файл или пара «_in»/«_out»): разбор,
// слияние по времени, удаление дублей, флоу-маркировка WireGuard и
// определение локального адреса абонента (g_localIp / g_localIp6).
// false — файл не прочитан или пакетов нет (сообщение уже напечатано).
bool loadDumpSet(const std::vector<std::string>& paths,
                 std::vector<Packet>& packets, std::vector<int>& origin) {
    packets.clear(); origin.clear();
    // --- загрузка всех выбранных файлов ---
    bool loadFailed = false;
    for (size_t fi = 0; fi < paths.size(); fi++) {
        std::vector<Packet> part;
        std::string err, fmt;
        if (!loadDumpFile(paths[fi], part, err, fmt)) {
            std::cout << C::RED << "Не удалось прочитать " << paths[fi] << ": " << err
                      << C::RST << "\n";
            loadFailed = true;
            break;
        }
        std::cout << "Файл: " << paths[fi] << "\n"
                  << "  формат: " << fmt << ", пакетов: " << part.size() << "\n";
        origin.insert(origin.end(), part.size(), (int)fi);
        packets.insert(packets.end(),
                       std::make_move_iterator(part.begin()),
                       std::make_move_iterator(part.end()));
    }
    if (loadFailed) return false;

    // --- слияние половин дампа по времени ---
    // Простая склейка недопустима: все пакеты из «_in» встали бы перед всеми
    // из «_out», и разбор развалился бы — SYN-ACK оказался бы «раньше» своего
    // SYN, интервалы ретрансмиссий и RTT ушли бы в минус, а определение
    // инициатора по первому пакету потока давало бы обратное направление.
    // Поэтому упорядочиваем объединённый набор по метке времени.
    // Время в дампе — часы:минуты:секунды без даты. Переход через полночь
    // разворачиваем так же, как absTimes: внутри файла скачок назад больше
    // чем на полсуток = новые сутки; между файлами — файл, начавшийся на
    // полсуток «раньше» другого, на самом деле начат после полуночи. Раньше
    // пакеты после 00:00 вставали в начало, перед пакетами из 23:59.
    if (paths.size() > 1 && !packets.empty()) {
        // Ключи считаем заранее: tsToMicros разбирает строку, внутри компаратора
        // это обошлось бы в тысячи лишних разборов. Пакеты с неразобранным
        // временем (-1) не выбрасываем — даём им время предыдущего, чтобы они
        // остались рядом со своими соседями по файлу.
        const long long DAY = 86400LL * 1000000;
        std::vector<std::pair<long long, size_t>> ord(packets.size());
        std::vector<long long> tMin(paths.size(), -1), tMax(paths.size(), -1);
        std::vector<long long> prevT(paths.size(), -1), dayOff(paths.size(), 0);
        for (size_t i = 0; i < packets.size(); i++) {
            const int fo = origin[i];
            long long t = tsToMicros(packets[i].ts);
            if (t < 0) {
                t = std::max(0LL, prevT[fo]);
            } else {
                t += dayOff[fo];
                if (prevT[fo] >= 0 && t < prevT[fo] - DAY / 2) { dayOff[fo] += DAY; t += DAY; }
                prevT[fo] = t;
                if (tMin[fo] < 0 || t < tMin[fo]) tMin[fo] = t;
                if (t > tMax[fo])                 tMax[fo] = t;
            }
            ord[i] = std::make_pair(t, i);
        }
        {
            long long latestStart = -1;
            for (long long m : tMin) latestStart = std::max(latestStart, m);
            std::vector<long long> shift(paths.size(), 0);
            for (size_t k = 0; k < paths.size(); k++)
                if (tMin[k] >= 0 && tMin[k] < latestStart - DAY / 2) {
                    shift[k] = DAY;
                    tMin[k] += DAY; tMax[k] += DAY;
                }
            for (auto& kv : ord) kv.first += shift[origin[kv.second]];
        }
        // stable_sort: при совпадении времени (частое дело — микросекундная
        // точность) сохраняем исходный порядок, а не тасуем пакеты случайно.
        std::stable_sort(ord.begin(), ord.end(),
            [](const std::pair<long long,size_t>& a, const std::pair<long long,size_t>& b) {
                return a.first < b.first;
            });

        std::vector<Packet> merged;  merged.reserve(packets.size());
        std::vector<int>    morig;   morig.reserve(origin.size());
        for (auto& kv : ord) {
            merged.push_back(std::move(packets[kv.second]));
            if (kv.second < origin.size()) morig.push_back(origin[kv.second]);
        }
        packets.swap(merged);
        origin.swap(morig);

        // Половины снимаются ОДНОВРЕМЕННО, значит их временные диапазоны обязаны
        // пересекаться. Не пересеклись — выбрана не та пара (дампы от разных
        // сеансов), и объединять их бессмысленно: получится один сеанс,
        // пришитый к другому, со сплошными «односторонними» соединениями.
        {
            auto hhmmss = [DAY](long long us) {
                us %= DAY;                            // после разворота через полночь
                char b[16];
                snprintf(b, sizeof(b), "%02lld:%02lld:%02lld",
                         us/3600000000LL, (us/60000000LL)%60, (us/1000000LL)%60);
                return std::string(b);
            };
            for (size_t k = 1; k < paths.size(); k++) {
                if (tMin[0] < 0 || tMin[k] < 0) continue;
                if (tMax[0] < tMin[k] || tMax[k] < tMin[0])
                    std::cout << C::YEL << "внимание: диапазоны времени не пересекаются ("
                              << hhmmss(tMin[0]) << "-" << hhmmss(tMax[0]) << " и "
                              << hhmmss(tMin[k]) << "-" << hhmmss(tMax[k])
                              << ") — похоже, это дампы разных сеансов" << C::RST << "\n";
            }
        }

        // Оба файла пишутся одновременно с одного интерфейса, поэтому стоит
        // фильтрам захвата хоть немного перекрыться — и один и тот же пакет
        // попадёт в оба файла. Для анализа это яд: каждая копия выглядит как
        // ретрансмиссия и раздувает счётчик потерь. Настоящая ретрансмиссия
        // ВСЕГДА приходит позже оригинала, поэтому безопасно убрать только
        // полные совпадения с ТЕМ ЖЕ штампом времени — и только пришедшие из
        // РАЗНЫХ файлов. Совпадения внутри одного файла не трогаем: там это
        // особенность захвата, а не наше дублирование.
        {
            auto wireKey = [](const Packet& p) {
                char n[192];
                snprintf(n, sizeof(n), "|%d|%d|%lld|%lld|%lld|%lld|",
                         p.srcPort, p.dstPort, p.seqStart, p.seq, p.ack, p.length);
                return p.srcIp + ">" + p.dstIp + n + p.proto + p.flags;
            };
            std::vector<char> drop(packets.size(), 0);
            long long dupCross = 0;
            size_t i = 0;
            while (i < packets.size()) {
                size_t j = i + 1;                       // группа пакетов с одним штампом
                while (j < packets.size() && packets[j].ts == packets[i].ts) j++;
                if (j - i > 1) {
                    // через map, а не попарно: при грубых штампах времени группа
                    // может оказаться большой, и O(n^2) встал бы колом
                    std::map<std::string,int> seen;
                    for (size_t a = i; a < j; a++) {
                        std::string k = wireKey(packets[a]);
                        auto it = seen.find(k);
                        if (it == seen.end())            seen[k] = origin[a];
                        else if (it->second != origin[a]) { drop[a] = 1; dupCross++; }
                    }
                }
                i = j;
            }
            if (dupCross > 0) {
                std::vector<Packet> uniq;  uniq.reserve(packets.size() - (size_t)dupCross);
                std::vector<int>    uorig; uorig.reserve(uniq.capacity());
                for (size_t a = 0; a < packets.size(); a++) {
                    if (drop[a]) continue;
                    uniq.push_back(std::move(packets[a]));
                    uorig.push_back(origin[a]);
                }
                packets.swap(uniq);
                origin.swap(uorig);
                std::cout << C::GRY << "Убрано " << dupCross
                          << " пакет(ов), попавших сразу в оба файла (фильтры захвата "
                             "перекрылись) — иначе они считались бы ретрансмиссиями"
                          << C::RST << "\n";
            }
        }

        std::cout << C::GRN << "Объединено по времени: " << packets.size()
                  << " пакетов из " << paths.size() << " файлов" << C::RST << "\n";
    }

    if (packets.empty()) {
        std::cout << C::RED << "В выбранных файлах не нашлось разбираемых пакетов."
                  << C::RST << "\n";
        return false;
    }

    // ФЛОУ-МАРКИРОВКА WireGuard: детект по payload ловит только handshake
    // (148/92 байт). Data-пакеты WG (тип 4, произвольная длина) сигнатуры не
    // имеют и поодиночке выглядят как «голос/медиа» по высокому UDP-порту.
    // Но если в ПОТОКЕ (паре IP:порт<->IP:порт) есть хоть один WG-пакет —
    // весь поток является WireGuard. Проставляем wgType всем пакетам потока.
    {
        auto flowKey = [](const Packet& p) {
            std::string a = p.srcIp + ":" + std::to_string(p.srcPort);
            std::string b = p.dstIp + ":" + std::to_string(p.dstPort);
            return (a < b) ? (a + "|" + b) : (b + "|" + a);   // нормализуем направление
        };
        std::set<std::string> wgFlows;
        for (const auto& p : packets)
            if (p.proto == "UDP" && p.wgType != 0) wgFlows.insert(flowKey(p));
        if (!wgFlows.empty()) {
            for (auto& p : packets)
                if (p.proto == "UDP" && p.wgType == 0 && wgFlows.count(flowKey(p)))
                    p.wgType = 4;   // тип 4 = data-пакет WireGuard (помечен по потоку)
        }

        // ФЛОУ-МАРКИРОВКА по содержимому: сигнатура есть в первых
        // сегментах, а протокол — у всего потока. Берём первую по времени.
        // Слабые сигнатуры (SOCKS, Telnet, опкод OpenVPN) — только из ПЕРВОГО
        // пакета с данными своей стороны: в середине потока такие байты
        // встречаются случайно (напр. короткий заголовок QUIC 0x40/0x50).
        std::unordered_map<std::string, int> ids;
        for (const auto& p : packets)
            if (p.l7 != L7_NONE) ids.emplace(p.proto + flowKey(p), (int)ids.size());
        if (!ids.empty()) {
            struct Acc {
                uint8_t code = L7_NONE;
                std::string srcA;                       // сторона первого пакета с данными
                bool seenA = false, seenB = false;
                uint8_t firstA = L7_NONE, firstB = L7_NONE;
            };
            auto weak = [](uint8_t c) {
                return c == L7_SOCKS5 || c == L7_SOCKS4 || c == L7_TELNET ||
                       c == L7_OVPN_CLIENT || c == L7_OVPN_SERVER;
            };
            std::vector<Acc> acc(ids.size());
            std::vector<int> fid(packets.size(), -1);
            for (size_t i = 0; i < packets.size(); i++) {
                const Packet& p = packets[i];
                auto it = ids.find(p.proto + flowKey(p));
                if (it == ids.end()) continue;
                fid[i] = it->second;
                if (p.length <= 0) continue;
                Acc& a = acc[(size_t)it->second];
                std::string src = p.srcIp + ":" + std::to_string(p.srcPort);
                if (a.srcA.empty()) a.srcA = src;
                const bool sideA = a.srcA == src;
                const bool first = sideA ? !a.seenA : !a.seenB;
                (sideA ? a.seenA : a.seenB) = true;
                const uint8_t c = p.l7;
                if (first) (sideA ? a.firstA : a.firstB) = c;
                if (c == L7_NONE || a.code != L7_NONE) continue;
                if (c == L7_OVPN_CLIENT || c == L7_OVPN_SERVER) continue;
                if (weak(c) && !first) continue;
                a.code = c;
            }
            for (Acc& a : acc) {
                const bool vpn = (a.firstA == L7_OVPN_CLIENT && a.firstB == L7_OVPN_SERVER) ||
                                 (a.firstA == L7_OVPN_SERVER && a.firstB == L7_OVPN_CLIENT);
                if (vpn) a.code = L7_OPENVPN;
            }
            for (size_t i = 0; i < packets.size(); i++)
                if (fid[i] >= 0) packets[i].l7 = acc[(size_t)fid[i]].code;
        }
    }

    // АВТО-ОПРЕДЕЛЕНИЕ ЛОКАЛЬНОГО АДРЕСА АБОНЕНТА.
    // «Локальной» стороной считаем адрес, присутствующий в БОЛЬШИНСТВЕ пакетов —
    // это общая точка съёма дампа (сам абонент). Адрес может быть как приватным,
    // так и ПУБЛИЧНЫМ. Случайный внутренний приватный IP (напр. одиночный
    // 192.168.x от какого-то устройства) НЕ должен перебивать настоящего абонента,
    // поэтому ориентируемся именно на частоту, а не на «первый приватный».
    // IPv4 и IPv6 считаем раздельно: при dual-stack у абонента по адресу на
    // каждое семейство, и общий подсчёт не дал бы ни одному набрать 50%.
    {
        auto top = [](const std::map<std::string, long long>& m, std::string& ip) {
            long long best = -1;
            for (auto& kv : m)
                if (kv.second > best) { best = kv.second; ip = kv.first; }
            return best;
        };
        // reversed — направление в кадрах записано с точки зрения узла съёма,
        // а не абонента (см. ниже); тогда dir у пакетов этого семейства переворачиваем.
        auto dominant = [&](bool v6, bool& reversed) {
            std::map<std::string, long long> freq, freqRev;
            long long n = 0;
            reversed = false;
            // Если захват Linux cooked (SLL/SLL2), в каждом кадре записано
            // направление — локальный адрес тогда известен точно: получатель
            // входящих и отправитель исходящих. Угадывание по частоте нужно
            // только когда направления нет или оно не сходится к одному адресу
            // (напр. -i any на маршрутизаторе, где пакеты транзитные).
            // Но направление — относительно узла, где снят дамп. Дамп с pppN
            // на BRAS снят ПО ТУ СТОРОНУ канала: «исходящие» там — пакеты К
            // абоненту. Поэтому считаем обе ориентации: абонент есть почти в
            // каждом пакете в одной из них, а удалённый сервер набирает больше
            // половины лишь в дампе, где один адресат забирает основной трафик
            // (туннель, загрузка). Без этого им и оказывался сам VPN-сервер.
            for (auto& p : packets) {
                if (p.dir < 0) continue;
                if ((p.srcIp.find(':') != std::string::npos) != v6) continue;
                n++;
                freq   [p.dir == 1 ? p.srcIp : p.dstIp]++;
                freqRev[p.dir == 1 ? p.dstIp : p.srcIp]++;
            }
            if (n > 0) {
                std::string ip, ipRev;
                long long best = top(freq, ip), bestRev = top(freqRev, ipRev);
                // Ничья — дамп в одну сторону к единственному адресату: обе
                // ориентации дают 100%. Абонентом тогда считаем приватный адрес
                // (у абонентов MARYNONET и за домашним роутером он приватный).
                bool useRev = bestRev > best ||
                              (bestRev == best && ip != ipRev &&
                               isPrivateIp(ipRev) && !isPrivateIp(ip));
                if (useRev) { best = bestRev; ip = ipRev; }
                if (best >= n * 0.5) { reversed = useRev; return ip; }
            }
            freq.clear(); n = 0;
            for (auto& p : packets) {
                if ((p.srcIp.find(':') != std::string::npos) != v6) continue;
                // src == dst (сам себе) — один пакет, считаем адрес один раз
                n++; freq[p.srcIp]++; if (p.dstIp != p.srcIp) freq[p.dstIp]++;
            }
            std::string ip;
            long long best = top(freq, ip);
            // принимаем, только если адрес реально доминирует (>= 50% пакетов)
            if (n == 0 || best < n * 0.5) ip.clear();
            return ip;
        };
        bool rev4 = false, rev6 = false;
        std::string v4 = dominant(false, rev4), v6 = dominant(true, rev6);
        // Дальше dir читается как «от абонента / к абоненту» (сверка половин
        // «_in»/«_out» ниже) — приводим его к этому смыслу.
        if (rev4 || rev6)
            for (auto& p : packets) {
                if (p.dir < 0) continue;
                bool isV6 = p.srcIp.find(':') != std::string::npos;
                if (isV6 ? rev6 : rev4) p.dir = 1 - p.dir;
            }
        // g_localIp — основной адрес (его печатаем и передаём в анализаторы);
        // в дампе без IPv4 им становится IPv6-адрес.
        g_localIp  = !v4.empty() ? v4 : v6;
        g_localIp6 = (v6 != g_localIp) ? v6 : std::string();
    }

    // IPsec: VPN или VoWiFi — по всему дампу, когда локальный адрес уже известен
    markIpsecPeers(packets);

    // --- сверка половин дампа с их именами ---
    // Направление известно только сейчас, когда определён локальный адрес.
    // Если файл «_in» на деле полон исходящих (или выбраны два несвязанных
    // дампа), об этом лучше сказать сразу: дальше расхождение проявится уже
    // в виде странных выводов про потери и односторонние соединения.
    if (paths.size() > 1 && origin.size() == packets.size() && !g_localIp.empty()) {
        std::vector<long long> nIn(paths.size(), 0), nOut(paths.size(), 0);
        for (size_t i = 0; i < packets.size(); i++) {
            // направление из заголовка SLL/SLL2 точнее догадки по адресам
            if (packets[i].dir >= 0) {
                if (packets[i].dir == 1) nOut[origin[i]]++; else nIn[origin[i]]++;
                continue;
            }
            bool sLoc = isLocalIp(packets[i].srcIp);
            bool dLoc = isLocalIp(packets[i].dstIp);
            if (sLoc == dLoc) continue;           // направление не определяется
            if (sLoc) nOut[origin[i]]++; else nIn[origin[i]]++;
        }
        std::cout << C::GRY << "Состав объединённого дампа:" << C::RST << "\n";
        for (size_t k = 0; k < paths.size(); k++) {
            size_t slash = paths[k].find_last_of("\\/");
            std::string name = (slash == std::string::npos) ? paths[k] : paths[k].substr(slash + 1);
            std::cout << "  " << name << ": входящих " << nIn[k]
                      << ", исходящих " << nOut[k] << "\n";
            std::string low = name;
            for (auto& ch : low) ch = (char)tolower((unsigned char)ch);
            bool claimsIn  = low.find("_in")  != std::string::npos;
            bool claimsOut = low.find("_out") != std::string::npos;
            if ((claimsIn && !claimsOut && nOut[k] > nIn[k]) ||
                (claimsOut && nIn[k] > nOut[k]))
                std::cout << C::YEL << "    внимание: содержимое не совпадает с именем файла"
                          << C::RST << "\n";
        }
    }
    return true;
}
