// analyzer.cpp — ядро анализа: классификация адресов и портов, организации
// (хостинг/CDN/свой провайдер), потоки (buildFlows), общая TCP-таблица
// соединений. Детекторы — detector_dpi.cpp / detector_vpn.cpp, отчёты — report.cpp.
#include "analyzer_internal.h"

// 10/8, 172.16/12, 192.168/16, 100.64/10, 127/8, 169.254/16, 0/8 («этот
// хост»/0.0.0.0 — адрес-заглушка DNS-блокировок и источник DHCP Discover),
// 224/4 multicast и 240/4 (включая broadcast 255.255.255.255).
// IPv6: ::1, ::, fe80::/10 (link-local), fc00::/7 (ULA), ff00::/8 (multicast —
// не публичный хост, резолвить его бессмысленно), ::ffff:a.b.c.d — по IPv4.
bool isPrivateIp(const std::string& ip) {
    if (ip.find(':') != std::string::npos) {
        unsigned char a[16];
        if (inet_pton(AF_INET6, ip.c_str(), a) != 1) return false;
        static const unsigned char zero10[10] = {0};
        if (memcmp(a, zero10, 10) == 0 && a[10] == 0xff && a[11] == 0xff) {
            char v4[16];
            snprintf(v4, sizeof(v4), "%u.%u.%u.%u", a[12], a[13], a[14], a[15]);
            return isPrivateIp(std::string(v4));
        }
        bool zero15 = true;
        for (int i = 0; i < 15; i++) if (a[i]) { zero15 = false; break; }
        if (zero15 && a[15] <= 1) return true;                 // ::1 и ::
        if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) return true; // fe80::/10
        if ((a[0] & 0xfe) == 0xfc) return true;                 // fc00::/7
        if (a[0] == 0xff) return true;                          // ff00::/8
        return false;
    }
    // Разбор вручную, без sscanf: функция зовётся через isLocalIp по нескольку
    // раз на каждый пакет в каждом анализаторе, и sscanf здесь был главным
    // потребителем CPU на больших дампах.
    int o[4];
    const char* s = ip.c_str();
    for (int k = 0; k < 4; k++) {
        if (!isdigit((unsigned char)*s)) return false;
        int v = 0, nd = 0;
        while (isdigit((unsigned char)*s)) {
            if (++nd > 3) return false;
            v = v * 10 + (*s++ - '0');
        }
        if (v > 255) return false;                 // «300.1.1.1» — не адрес
        o[k] = v;
        if (k < 3) { if (*s != '.') return false; s++; }
    }
    if (*s != '\0') return false;                  // хвост после 4-го октета
    int a = o[0], b = o[1];
    if (a == 0) return true;
    if (a == 10) return true;
    if (a == 127) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;
    if (a == 100 && b >= 64 && b <= 127) return true;
    if (a == 169 && b == 254) return true;
    // 224/4 multicast (mDNS, SSDP, LLMNR) и 240/4 с 255.255.255.255 — не
    // публичные хосты. Без этого SSDP/mDNS домашнего ПК считались «соединением
    // наружу» и гасили детект «DNS работает, а соединений нет».
    if (a >= 224) return true;
    return false;
}
bool isLocalIp(const std::string& ip) {
    return isPrivateIp(ip) || (!g_localIp.empty() && ip == g_localIp)
                           || (!g_localIp6.empty() && ip == g_localIp6);
}

// ------------------------------------------------------------------
// классификация трафика (эвристика)
// ------------------------------------------------------------------
// известные VPN/туннельные порты (для пассивного определения по дампу).
// Таблицы — в конфиге (vpn_udp_ports / vpn_tcp_ports), строки в них живут
// до конца программы, так что c_str() можно отдавать наружу.
const char* vpnPortName(int port, const std::string& proto) {
    const std::map<int, std::string>* m = nullptr;
    if (proto == "UDP") m = &cfg().vpnUdpPorts;
    else if (proto == "TCP") m = &cfg().vpnTcpPorts;
    if (!m) return nullptr;
    auto it = m->find(port);
    return it == m->end() ? nullptr : it->second.c_str();
}

// UDP 500/4500: IPsec-VPN (в т.ч. корпоративный — не обязательно на хостинге),
// звонки по Wi-Fi (VoWiFi: телефон строит IPsec до ePDG своего оператора)
// или не понять. Точные признаки по всему дампу — Packet::ipsecPeer
// (markIpsecPeers: IKEv1, IKE начат удалённой стороной, DNS-имя ePDG); без них
// VPN — только адрес на хостинге (ePDG стоят в сети оператора, не на VPS).
// Адрес не резолвили (remote == nullptr) — хостинг не подтверждён.
// Одно правило для guessKind, UDP-таблицы, TSPU?-пометки и причин блокировок —
// иначе VoWiFi в одном месте «звонки», в другом «VPN режут».
IpsecClass ipsecClass(const Packet& p, int remotePort, const IpInfo* remote) {
    if (p.proto != "UDP" || (remotePort != 500 && remotePort != 4500)) return IPSEC_NONE;
    if (p.ipsecPeer == 2) return IPSEC_VOWIFI;
    if (p.ipsecPeer == 1) return IPSEC_VPN;
    if (remote && !remote->vpnWhite &&
        (remote->hosting || looksHostingOrg(remote->org, remote->asn)) &&
        !isOwnIspOrg(remote->org, remote->asn))
        return IPSEC_VPN;
    return IPSEC_UNSURE;
}

// Абонент сам держит WG/AmneziaWG-листенер: характерный порт 51820/51821/55555
// на ЛОКАЛЬНОЙ стороне. Эти порты — в эфемерном диапазоне любой ОС (Windows/macOS
// 49152–65535, Linux 32768–60999), с них случайно уходят DNS, QUIC, звонки.
// Поэтому листенер — только если удалённый порт не служебный (≥1024: не DNS,
// NTP, QUIC/443, DoT) и поток не опознан как другой протокол (QUIC, STUN, DHT);
// к листенеру клиенты ходят со своих случайных портов. Сигнатура WireGuard
// (wgType) — отдельно, на любом порту. Одно правило для guessKind, UDP-таблицы,
// TSPU?-пометки и причин блокировок. nullptr — не листенер.
const char* udpLocalVpnListener(const Packet& p, int remotePort, int localPort) {
    if (p.proto != "UDP" || (localPort != 51820 && localPort != 51821 && localPort != 55555))
        return nullptr;
    if (remotePort < 1024 || p.quic || p.l7 == L7_STUN || p.l7 == L7_BT_DHT) return nullptr;
    const char* v = vpnPortName(localPort, "UDP");
    return v ? v : "WireGuard";
}

// Справочные подписи сервисов по портам (НЕ влияют на VPN-вердикт —
// только поясняют, что обычно слушает порт). Нейтральные сервисы тоже здесь.
struct PortHint { int port; const char* svc; const char* proto; };
static const PortHint PORT_HINTS[] = {
    {22,"SSH","tcp"},{53,"DNS","tcp/udp"},{80,"HTTP","tcp"},{88,"Kerberos","tcp"},
    {443,"HTTPS / XTLS / Reality","tcp"},{465,"SMTPS","tcp"},{587,"SMTP+TLS","tcp"},
    {853,"DoT","tcp"},{990,"FTPS","tcp"},{993,"IMAPS","tcp"},{995,"POP3S","tcp"},
    {1080,"SOCKS5","tcp"},{1194,"OpenVPN","tcp/udp"},{1701,"L2TP","udp"},
    {1723,"PPTP","tcp"},{3128,"Squid HTTP proxy","tcp"},{3389,"RDP","tcp"},
    {4433,"XTLS/Reality/Trojan","tcp"},{4443,"XTLS/Reality","tcp"},
    {4500,"IKEv2 NAT-T","udp"},{5060,"SIP","tcp/udp"},{5555,"ADB / alt-admin","tcp"},
    {8080,"HTTP proxy","tcp"},{8118,"Privoxy","tcp"},{8123,"Polipo","tcp"},
    {8388,"Shadowsocks","tcp/udp"},{8443,"HTTPS alt / Reality","tcp"},
    {8888,"HTTP alt","tcp"},{9050,"Tor SOCKS","tcp"},{9051,"Tor control","tcp"},
    {10808,"v2ray/xray SOCKS","tcp"},{10809,"v2ray/xray HTTP","tcp"},
    {10810,"v2ray/xray alt","tcp"},
    {51820,"WireGuard","udp"},{55555,"AmneziaWG","udp"},{41641,"Tailscale","udp"},
    {500,"IKE ISAKMP","udp"},
};
static const size_t PORT_HINTS_N = sizeof(PORT_HINTS) / sizeof(PORT_HINTS[0]);

const char* portService(int p) {
    for (size_t i = 0; i < PORT_HINTS_N; ++i)
        if (PORT_HINTS[i].port == p) return PORT_HINTS[i].svc;
    if (p == 6443) return "HTTPS alt / возможный VPN over TLS";
    if (p >= 10800 && p <= 10820) return "v2ray/xray-подобный диапазон";
    return "";
}

// Узнаваемое приложение/сервис по порту — чтобы хелперу было понятно "что не
// работает" (Steam, Discord, RDP, ...), а не просто номер порта.
// Возвращает короткое имя или nullptr.
const char* appByPort(int port, const std::string& proto) {
    switch (port) {
        case 443:   return proto == "UDP" ? "QUIC (HTTP/3, веб)" : "HTTPS/веб";
        case 80:    return "HTTP/веб";
        case 53:    return "DNS";
        case 853:   return "DNS-over-TLS";
        case 22:    return "SSH";
        case 3389:  return "RDP (удалённый рабочий стол)";
        case 25: case 465: case 587: return "почта (SMTP)";
        case 993: case 995: case 143: case 110: return "почта (IMAP/POP3)";
        case 5060: case 5061: return "SIP-телефония";
        case 1935:  return "RTMP-стрим";
        case 3478: case 3479: return "STUN/TURN (звонки/видео)";
        // игры/мессенджеры/сервисы
        case 27015: case 27016: case 27017: case 27018: case 27019:
                    return "Steam / Source-сервер";
        case 25565: return "Minecraft";
        case 3074:  return "Xbox Live";
        case 3658:  return "PlayStation Network";
        case 6112: case 6113: return "Blizzard/Battle.net";
        case 5222: case 5223: return "XMPP/Jabber/push";
        case 6667: case 6697: return "IRC";
        case 1119:  return "Battle.net";
        case 8000: case 8001: return "веб-сервис/стрим (alt)";
        case 1194: case 1195: return "OpenVPN";
        case 51820: case 51821: return "WireGuard";
        case 6881: case 6882: case 6883: case 6884: case 6885:
        case 6886: case 6887: case 6888: case 6889: return "торрент (BitTorrent)";
        // --- дополнительные известные приложения/сервисы ---
        // игры
        case 3724:  return "World of Warcraft";
        case 28015: return "Rust (игра)";
        case 7777:  return "Terraria / Unreal-сервер";
        case 27036: case 27037: return "Steam (remote play)";
        case 9000: case 9001: return "Dota/игровой сервер (alt)";
        case 5000: case 5001: return "игровой/веб-сервис (alt)";
        case 7000: case 7001: return "игровой сервер (alt)";
        case 19132: case 19133: return "Minecraft Bedrock";
        case 25575: return "Minecraft RCON";
        case 44405: return "Roblox";
        case 30000: return "FiveM / игровой сервер";
        case 30120: return "FiveM (GTA RP)";
        case 7878:  return "Genshin Impact";
        case 22102: case 22101: return "Genshin Impact";
        // мессенджеры/связь
        case 5228:  return "Google Play / push (GCM)";
        case 5938:  return "TeamViewer";
        case 8800:  return "Viber";
        case 4244:  return "WhatsApp";
        case 50318: return "Discord (голос)";
        // веб/сервисы
        case 8080: case 8081: return "HTTP-прокси / веб-альт";
        case 8443:  return "HTTPS-альт (или Hysteria2)";
        case 2052: case 2082: case 2086: case 2095: return "Cloudflare HTTP";
        case 2053: case 2083: case 2087: case 2096: return "Cloudflare HTTPS";
        case 123:   return "NTP (синхронизация времени)";
        case 161: case 162: return "SNMP (мониторинг)";
        case 389:   return "LDAP";
        case 636:   return "LDAPS";
        case 3306:  return "MySQL";
        case 5432:  return "PostgreSQL";
        case 6379:  return "Redis";
        case 21:    return "FTP";
        case 990:   return "FTPS";
        case 23:    return "Telnet";
        case 3128:  return "HTTP-прокси (Squid)";
        case 1080:  return "SOCKS-прокси";
        // стриминг/медиа
        case 1755:  return "MMS-стрим";
        case 554:   return "RTSP (видеопоток/камеры)";
        case 5004: case 5005: return "RTP (медиапоток)";
        default: break;
    }
    // Discord голос — UDP в диапазоне 50000-65535 (нестрого), Telegram — свои DC.
    if (proto == "UDP" && port >= 50000) return "голос/медиа (возможно Discord/звонок)";
    return nullptr;
}

// Прокси/Tor/Reality-порты, которые УСИЛИВАЮТ подозрение (но мягче, чем явные VPN).
// На серверной стороне такой порт повышает score, но не так сильно, как туннельный.
// Таблица — в конфиге (proxy_ports).
const char* proxyPortName(int port) {
    const auto& m = cfg().proxyPorts;
    auto it = m.find(port);
    return it == m.end() ? nullptr : it->second.c_str();
}

// «Домашние» ISP-сети оператора, которые НЕ нужно метить hosting, даже если
// внешний geo-API относит их к датацентрам (оператор может иметь и хостинг-
// услуги, но для диагностики абонентского трафика это его собственная сеть).
// Номер AS из списка (с «as» или без) в поле asn — целым числом: подстрокой
// «39709» совпадал и с AS397091. Возвращает номер без «as» или "" — не найден.
// Номер n (цифры, len байт) есть в asn целым числом. Без копий строк —
// isOwnIspOrg зовётся на каждый пакет.
static bool asnHasNumber(const std::string& asn, const char* n, size_t len) {
    if (len == 0) return false;
    for (size_t pos = asn.find(n, 0, len); pos != std::string::npos; pos = asn.find(n, pos + 1, len)) {
        const bool l = pos == 0 || !::isdigit((unsigned char)asn[pos - 1]);
        const bool r = pos + len >= asn.size() || !::isdigit((unsigned char)asn[pos + len]);
        if (l && r) return true;
    }
    return false;
}

static std::string asnInList(const std::string& asn, const std::vector<std::string>& list) {
    for (const auto& n : list) {
        const size_t skip = n.compare(0, 2, "as") == 0 ? 2 : 0;
        if (asnHasNumber(asn, n.c_str() + skip, n.size() - skip)) return n.substr(skip);
    }
    return {};
}

bool isOwnIspOrg(const std::string& org, const std::string& asn) {
    // own_isp_org / own_isp_asn из конфига; без own_isp_asn — AS, запомненный
    // кнопкой «Определить» в настройках (ownIspDetect)
    const auto& kws = cfg().ownIspOrgKeywords;
    if (!kws.empty()) {
        std::string o = org; for (auto& c : o) c = (char)::tolower((unsigned char)c);
        for (const auto& kw : kws)
            if (!kw.empty() && o.find(kw) != std::string::npos) return true;
    }
    if (!asnInList(asn, cfg().ownIspAsns).empty()) return true;
    if (cfg().ownIspAsnFromIni) return false;
    const unsigned autoAsn = ownIspAutoAsn();
    if (!autoAsn) return false;
    char buf[16];
    const int len = snprintf(buf, sizeof buf, "%u", autoAsn);
    return len > 0 && asnHasNumber(asn, buf, (size_t)len);
}

bool looksHostingOrg(const std::string& org, const std::string& /*asn*/) {
    std::string o = org;  for (auto& c : o) c = (char)::tolower((unsigned char)c);
    // Короткие общие слова — только целым словом: подстрока «colo» ловила
    // Colombia, «server»/«cloud» — названия обычных провайдеров и iCloud.
    static const char* wordKw[] = { "server", "servers", "cloud", "colo", "vps", "vds" };
    for (auto* kw : wordKw) {
        size_t n = strlen(kw);
        for (size_t pos = o.find(kw); pos != std::string::npos; pos = o.find(kw, pos + 1)) {
            bool l = (pos == 0) || !::isalnum((unsigned char)o[pos - 1]);
            bool r = (pos + n >= o.size()) || !::isalnum((unsigned char)o[pos + n]);
            if (l && r) return true;
        }
    }
    // Selectel убран: на нём живёт масса обычных российских сайтов и сервисов,
    // «VLESS» по нему давал ложные срабатывания на рядовом HTTPS.
    static const char* hostKw[] = {
        "hosting", "datacenter", "data center", "data-center", "dedicated",
        "colocation", "colocrossing",
        "digitalocean", "hetzner", "ovh", "vultr", "linode", "aeza",
        "scaleway", "contabo", "leaseweb", "choopa", "ramnode", "time4vps",
        "g-core", "gcore", "stark industries", "hostkey", "ihor", "vdsina",
        "mevspace", "pq hosting", "pq.hosting", "the constant company", "datacamp",
        "m247", "zenlayer", "kamatera", "netcup", "ip volume",
        "serverius", "worldstream", "frantech", "buyvm", "alibaba cloud",
        "tencent", "oracle cloud", "upcloud", "clouvider", "hostinger",
        "cgi global", "cgi-global",
        "aurologic", "combahton", "pfcloud", "melbicom", "fasthosts",
        "incrediserve", "xhost", "ucloud", "hostglobal", "43networks",
        "petersburg internet", "pinspb"
    };
    for (auto* kw : hostKw)
        if (o.find(kw) != std::string::npos) return true;
    return false;
}

// CDN/крупные контентные сети — точно НЕ VPN (даже на 443).
bool looksCdnOrg(const std::string& org) {
    std::string o = org;  for (auto& c : o) c = (char)::tolower((unsigned char)c);
    static const char* cdnKw[] = {
        "google", "akamai", "cloudflare", "fastly", "amazon", "aws", "microsoft",
        "azure", "meta", "facebook", "edgecast", "blizzard", "yandex", "vkontakte",
        "vk ", "mail.ru", "apple", "netflix", "cloudfront", "limelight", "stackpath",
        "incapsula", "sucuri", "bunny", "cdn",
        // мессенджеры/сервисы — это НЕ хостинг (свои AS, но легитимный сервис):
        "telegram", "whatsapp", "viber", "signal", "discord", "twitch",
        "cloudflarenet", "warp", "ddos-guard", "ddosguard", "stormwall", "qrator",
        "storm systems", "stormsystems", "github", "githubusercontent", "gitlab", "fastly"
    };
    for (auto* kw : cdnKw)
        if (o.find(kw) != std::string::npos) return true;
    return false;
}

std::string guessKind(const Packet& p, const IpInfo& srcI, const IpInfo& dstI) {
    auto any = [&](int port) { return p.srcPort == port || p.dstPort == port; };

    if (p.proto == "ICMP") return "(icmp)";

    // security-флаги от ipapi.is — самый сильный сигнал, ГЛОБАЛЬНО для любого порта.
    // Метку по трафику (vless, Hysteria2, VPN-порт) не теряем: computeVpnVerdict
    // ищет в ней «vless»/«Hysteria2», и ранний возврат одного флага гасил эти
    // признаки — адрес из базы VPN давал баллов меньше, чем такой же без флага.
    // Адрес из белого списка VPN: флаги баз и таблицы портов не смотрим, TLS/QUIC
    // к нему — как к CDN. Остаются только сигнатуры протокола (WireGuard,
    // OpenVPN, прокси по L7) — это сам туннель, а не догадка по адресу.
    const bool white = (isLocalIp(p.srcIp) ? dstI : srcI).vpnWhite;
    if (!white) {
        const bool remoteIsSrc = !isLocalIp(p.srcIp);
        const IpInfo& remote = remoteIsSrc ? srcI : dstI;
        // источник флага — ipapi.is (is_vpn/is_tor/is_proxy) или база IP2Proxy
        const bool viaPx = remote.flagSrc.find("IP2Proxy") != std::string::npos &&
                           remote.flagSrc.find("ipapi.is") == std::string::npos;
        const char* flag = remote.isVpn ? (viaPx ? "VPN: база IP2Proxy" : "VPN: подтверждён is_vpn")
                         : remote.isTor ? (viaPx ? "Tor: база IP2Proxy" : "Tor: is_tor")
                         : remote.isProxy ? (viaPx ? "proxy: база IP2Proxy" : "proxy: is_proxy") : nullptr;
        if (flag) {
            IpInfo plain = remote;
            plain.isVpn = plain.isTor = plain.isProxy = false;
            const std::string base = remoteIsSrc ? guessKind(p, plain, dstI) : guessKind(p, srcI, plain);
            const bool telling = base.find("VPN") != std::string::npos || base.find("proxy") != std::string::npos ||
                                 base.find("vless") != std::string::npos || base.find("Hysteria") != std::string::npos;
            if (telling) return base.substr(0, base.size() - 1) + "; " + flag + ")";
            return std::string("(") + flag + ")";
        }
    }

    // WireGuard по сигнатуре payload (148B init / 92B response) — на любом порту
    if (p.wgType != 0) return "(VPN: WireGuard)";
    // сигнатуры по содержимому (L7Proto) — тоже на любом порту
    if (p.l7 == L7_OPENVPN) return "(VPN: OpenVPN)";
    if (l7IsProxy(p.l7))    return std::string("(proxy: ") + l7Name(p.l7) + ")";
    if (p.l7 == L7_SSH)     return "(ssh session)";
    if (p.l7 == L7_BITTORRENT || p.l7 == L7_BT_DHT) return "(torrent)";
    // STUN в потоке — WebRTC-звонок к пиру с эфемерным портом (бывает и 51820),
    // не VPN-порт (computeVpnVerdict его тоже не считает)
    if (p.l7 == L7_STUN)    return "(stun/webrtc)";

    // явные VPN-порты — только если порт на удалённой (серверной) стороне.
    // локальный эфемерный порт может случайно совпасть (напр. 1194) — это не VPN.
    {
        bool srcLocal = isLocalIp(p.srcIp), dstLocal = isLocalIp(p.dstIp);
        if (srcLocal != dstLocal && !white) {
            int remotePort = srcLocal ? p.dstPort : p.srcPort;
            int localPort  = srcLocal ? p.srcPort : p.dstPort;
            // «(ipsec: …)» — не VPN-порт (см. computeVpnVerdict)
            switch (ipsecClass(p, remotePort, srcLocal ? &dstI : &srcI)) {
                case IPSEC_VOWIFI: return "(ipsec: VoWiFi — звонки по Wi-Fi)";
                case IPSEC_UNSURE: return "(ipsec: IPsec или VoWiFi?)";
                default: break;   // IPSEC_VPN — ниже, как VPN-порт
            }
            if (const char* v = vpnPortName(remotePort, p.proto))
                return std::string("(VPN: ") + v + ")";
            if (const char* px = proxyPortName(remotePort))
                return std::string("(proxy: ") + px + ")";
            // абонент сам держит VPN-листенер: характерный WG/AmneziaWG-порт на
            // ЛОКАЛЬНОЙ стороне — только не к служебному порту (udpLocalVpnListener)
            if (const char* v = udpLocalVpnListener(p, remotePort, localPort))
                return std::string("(VPN-сервер у абонента: ") + v + ")";
        }
    }

    if (any(22))  return "(ssh session)";
    if (any(21))  return "(ftp session)";
    if (any(53))  return "(dns)";
    if (any(123)) return "(ntp)";
    if (any(80) || p.appHint == "HTTP") return "(http)";

    // только TCP: UDP/443 — это QUIC/Hysteria2, его разбирает ветка ниже
    // (без проверки протокола та ветка была недостижима, а QUIC шёл в «vless»)
    if (p.proto == "TCP" && any(443)) {
        // TLS на 443. Решаем по принадлежности удалённого IP хостингу,
        // а НЕ по длине отдельного пакета (иначе один поток получает разные метки).
        const IpInfo& remote = isLocalIp(p.srcIp) ? dstI : srcI;

        bool isCdn  = looksCdnOrg(remote.org) || remote.vpnWhite;
        // хостинг: либо флаг от ip-api, либо по названию ASN/организации (резерв)
        bool isHost = (remote.hosting || looksHostingOrg(remote.org, remote.asn)) && !isOwnIspOrg(remote.org, remote.asn);

        // хостинг/датацентр + 443 и НЕ CDN => вероятный VLESS/Reality поверх TLS;
        // не-хостинг (обычные сайты/CDN) на 443 => обычный HTTPS, не VPN.
        if (isHost && !isCdn)
            return "(probably vless)";
        return "(tls/https)";
    }
    if (p.proto == "UDP" && (p.srcPort == 443 || p.dstPort == 443)) {
        const IpInfo& remote = isLocalIp(p.srcIp) ? dstI : srcI;
        bool isHost = (remote.hosting || looksHostingOrg(remote.org, remote.asn)) && !isOwnIspOrg(remote.org, remote.asn);
        // UDP/443 к хостингу — сигнатура Hysteria2/QUIC-VPN => считаем VPN (красный).
        if (isHost && !looksCdnOrg(remote.org) && !remote.vpnWhite) return "(VPN: Hysteria2/QUIC)";
        return "(udp/quic)";
    }
    // Обычный UDP на прочих портах — это НЕ повод считать VPN/QUIC.
    // VPN по UDP помечается только по конкретным портам (vpnPortName: WireGuard,
    // Hysteria/Hysteria2, WARP, IPsec, OpenVPN и т.п.) — это делается отдельно.
    if (p.proto == "UDP") return "(udp)";
    return "";
}

// Подпись локального адреса: сам абонент или другой адрес его сети (роутер,
// соседние устройства, multicast). Если адрес абонента не определён —
// любой приватный считаем абонентом.
const char* localRoleLabel(const std::string& ip) {
    if ((!g_localIp.empty() && ip == g_localIp) || (!g_localIp6.empty() && ip == g_localIp6))
        return "MainIP";
    if (g_localIp.empty() && g_localIp6.empty()) return "MainIP";
    return "LocalIP";
}

// метка стороны: локальный -> «MainIP»/«LocalIP», иначе организация (или IP)
std::string sideLabel(const std::string& ip, const IpInfo& info) {
    if (info.type == "private" || isLocalIp(ip)) return localRoleLabel(ip);
    if (info.org != "-" && !info.org.empty()) return info.org;
    return ip;
}

bool flagHas(const std::string& f, char c) {
    return f.find(c) != std::string::npos;
}

std::vector<FlowRec> buildFlows(const std::vector<Packet>& packets) {
    // Канонический ключ (меньший endpoint первым) нужен РОВНО для одного —
    // чтобы A->B и B->A слились в один поток. Определять по нему направление
    // нельзя: это сравнение строк, а не факт о соединении. Раньше инициатором
    // считался тот, чей "ip:port" лексикографически меньше, из-за чего примерно
    // у половины потоков вход и выход менялись местами.
    auto keyOf = [](const Packet& p) {
        std::string a = p.srcIp + ":" + std::to_string(p.srcPort);
        std::string b = p.dstIp + ":" + std::to_string(p.dstPort);
        return (a <= b ? a + "|" + b : b + "|" + a) + "|" + p.proto;
    };

    // --- проход 1: кто инициатор (по фактам, с уровнем уверенности) ---
    //   3 — чистый SYN: инициатор — его отправитель, это прямое доказательство;
    //   2 — SYN-ACK: инициатор — тот, КОМУ он адресован;
    //   1 — ровно одна сторона локальная: инициатор — она (исходящее соединение);
    //   0 — фактов нет (захват с середины, UDP, ICMP): отправитель первого
    //       пакета потока В ПОРЯДКЕ ЗАХВАТА — грубо, но всё же по времени,
    //       а не по алфавиту.
    // Отдельный проход нужен потому, что направление должно быть известно ДО
    // накопления bytesIn/bytesOut, а лучший признак (SYN) не обязан оказаться
    // первым пакетом, который мы встретим для этого ключа.
    struct Init { std::string ip; int port = 0; int conf = -1; };
    std::map<std::string, Init> init;
    for (const auto& p : packets) {
        if (!p.valid) continue;
        bool S = flagHas(p.flags, 'S'), A = flagHas(p.flags, '.');
        bool sLoc = isLocalIp(p.srcIp), dLoc = isLocalIp(p.dstIp);
        int conf; bool srcInit;
        if (S && !A)           { conf = 3; srcInit = true;  }
        else if (S && A)       { conf = 2; srcInit = false; }
        else if (sLoc != dLoc) { conf = 1; srcInit = sLoc;  }
        else                   { conf = 0; srcInit = true;  }
        Init& in = init[keyOf(p)];
        if (conf > in.conf) {          // строго больше — при равенстве побеждает первый по времени
            in.conf = conf;
            in.ip   = srcInit ? p.srcIp   : p.dstIp;
            in.port = srcInit ? p.srcPort : p.dstPort;
        }
    }

    // --- проход 2: накопление счётчиков относительно найденного инициатора ---
    std::map<std::string, FlowRec> flows;
    for (const auto& p : packets) {
        if (!p.valid) continue;
        std::string key = keyOf(p);

        FlowRec& f = flows[key];
        if (f.proto.empty()) {              // первый пакет — фиксируем инициатора
            auto ii = init.find(key);
            bool srcIsInit = (ii == init.end()) ||
                             (p.srcIp == ii->second.ip && p.srcPort == ii->second.port);
            if (srcIsInit) { f.srcIp=p.srcIp; f.srcPort=p.srcPort; f.dstIp=p.dstIp; f.dstPort=p.dstPort; }
            else           { f.srcIp=p.dstIp; f.srcPort=p.dstPort; f.dstIp=p.srcIp; f.dstPort=p.srcPort; }
            f.proto = p.proto;
        }
        bool outbound = (p.srcIp == f.srcIp && p.srcPort == f.srcPort);
        if (outbound) f.bytesOut += p.length;
        else          f.bytesIn  += p.length;
    }
    std::vector<FlowRec> out;
    out.reserve(flows.size());
    for (auto& kv : flows) out.push_back(kv.second);
    // сортируем по объёму (крупные потоки сверху)
    std::sort(out.begin(), out.end(),
              [](const FlowRec& x, const FlowRec& y){ return x.bytes() > y.bytes(); });
    return out;
}

// Display-фильтр Wireshark для адреса (и порта, если задан): строку можно
// вставить в поле фильтра и сразу попасть на проблемный поток/узел.
std::string wsFilter(const std::string& ip, int port /*= -1*/, const char* l4 /*= "tcp"*/) {
    std::string f = (ip.find(':') != std::string::npos ? "ipv6.addr==" : "ip.addr==") + ip;
    if (port > 0) f += std::string(" && ") + l4 + ".port==" + std::to_string(port);
    return f;
}

// время каждого пакета в мкс с поправкой на переход через полночь
// (tsToMicros считает от начала суток); -1 — время не разобрано.
// Скачок назад больше чем на полсуток — новые сутки; вперёд больше чем на
// полсуток после перехода — запоздавший пакет прежних суток (pcapng с двумя
// интерфейсами, «-i any»: штампы у полуночи идут не по порядку). Отсчёт ведём
// от самого позднего: запоздавший пакет уводил prev на сутки вперёд, следующий
// «переходил полночь» ещё раз, и весь хвост дампа уезжал на +24 ч.
std::vector<long long> absTimes(const std::vector<Packet>& packets) {
    const long long DAY = 86400LL * 1000000;
    std::vector<long long> absT(packets.size(), -1);
    long long dayOff = 0, prev = -1;
    for (size_t i = 0; i < packets.size(); i++) {
        long long t = tsToMicros(packets[i].ts);
        if (t < 0) continue;
        t += dayOff;
        if (prev >= 0) {
            if (t < prev - DAY / 2) { dayOff += DAY; t += DAY; }
            else if (dayOff > 0 && t > prev + DAY / 2) t -= DAY;
        }
        absT[i] = t; prev = std::max(prev, t);
    }
    return absT;
}

// Сравнение TCP-номеров последовательности по модулю 2^32 (RFC 1982). Прямое
// "a < b" неприменимо: seq 32-битный и заворачивается через ноль, поэтому на
// границе заворота обычное сравнение даёт обратный результат и выдаёт всплеск
// ложных «пакетов из прошлого». Парсер кладёт в seqStart сырой be32, без
// разворачивания (см. parseFrame, разбор TCP), так что модульное сравнение обязательно.
bool seqLess(long long a, long long b) {
    return (int32_t)((uint32_t)a - (uint32_t)b) < 0;
}

// Номер позади правого края больше чем на 2^30 — не повтор: окно TCP не больше
// 2^30 даже с wscale 14. Значит, сменилась база нумерации (в текстовом дампе не
// распознан абсолютный первый пакет беседы — см. fixFirstAbsoluteSeq в parser.cpp —
// или это новое соединение на тех же портах), и сегмент — новые данные.
static bool seqRebased(long long maxEnd, long long seq) {
    return maxEnd >= 0 && (int32_t)((uint32_t)seq - (uint32_t)maxEnd) < -(1 << 30);
}

// Внешний SNI настоящего ECH — «публичное имя» провайдера. Chrome кладёт
// расширение ECH в КАЖДЫЙ ClientHello (GREASE ECH), так что само наличие 0xfe0d
// ещё не ECH; реальный ECH виден по внешнему имени (у Cloudflare — cloudflare-ech.com).
bool isEchPublicName(const std::string& sni) {
    std::string s = sni; for (auto& c : s) c = (char)::tolower((unsigned char)c);
    return s == "cloudflare-ech.com" || s.rfind("ech.", 0) == 0 ||
           s.find("-ech.") != std::string::npos;
}

TcpConnTable buildTcpConnTable(const std::vector<Packet>& packets,
                               const std::string& localIp) {
    auto isLocal = [&](const std::string& ip) {
        return isLocalIp(ip) || (!localIp.empty() && ip == localIp);
    };
    TcpConnTable tt;
    std::vector<long long> absT = absTimes(packets);
    std::vector<int> outTtls;
    // Смещение сегмента абонента от начала потока (ISN+1) по модулю 2^32. В pcap и
    // tcpdump -S номера абсолютные; текстовый tcpdump без -S после рукопожатия
    // печатает их от ISN или ISN+1 (seqBase). Абсолютное прочтение дальше 1 МБ от
    // ISN — значит, номера относительные.
    auto streamOff = [](const TcpConnState& c, long long seq) -> long long {
        const int32_t a = (int32_t)((uint32_t)seq - (uint32_t)c.isn - 1u);
        if (a > -(1 << 20) && a < (1 << 20)) return a;
        return (int32_t)((uint32_t)seq - (c.seqBase == 0 ? 0u : 1u));
    };
    // ClientHello абонента — настоящий выбирается после прохода (нужен outTtlTypical).
    // pos: 1 — сегмент начинает поток (накрывает ISN+1), -1 — целиком до начала
    // потока (фейк с неверным seq), 0 — дальше в потоке или рукопожатия в дампе нет
    struct Hello { TcpConnState* c; size_t i; long long t; int pos; };
    std::vector<Hello> hellos;
    for (size_t i = 0; i < packets.size(); i++) {
        const Packet& p = packets[i];
        long long t = absT[i];
        if (t > tt.tEnd) tt.tEnd = t;
        if (p.proto != "TCP") continue;
        bool sLoc = isLocal(p.srcIp), dLoc = isLocal(p.dstIp);
        if (sLoc == dLoc) continue;
        std::string rip = sLoc ? p.dstIp : p.srcIp;
        const std::string& lip = sLoc ? p.srcIp : p.dstIp;
        int rport = sLoc ? p.dstPort : p.srcPort;
        int lport = sLoc ? p.srcPort : p.dstPort;
        // локальный адрес — в ключе: в дампе сегмента LAN (или «-i any» на роутере
        // с NAT, сохраняющим порт) два устройства с одним портом к одному серверу
        // сливались — RST одного и данные другого давали «поддельный RST»
        TcpConnState& c = tt.conns[rip + "|" + std::to_string(rport) + "|" + std::to_string(lport) +
                                   "|" + lip];
        if (c.ip.empty()) { c.ip = rip; c.rport = rport; c.lport = lport; c.lip = lip; }
        if (t >= 0) { if (c.firstTime < 0) c.firstTime = t; c.lastTime = t; }
        bool S = flagHas(p.flags, 'S'), A = flagHas(p.flags, '.');
        bool repeat = false;   // повтор уже отправленных/принятых данных (для «заморозки»)
        if (sLoc) {
            c.outBytes += p.length;
            if (!S && !flagHas(p.flags, 'R')) {
                if (p.length > 1) {
                    // данные: повтор, если этот seq уже уходил (сервер не подтвердил)
                    if (p.seq < 0) repeat = true;   // без seq повтор не отличить — как раньше
                    else if (c.outMaxEnd >= 0 && !seqLess(c.outMaxEnd, p.seq) &&
                             !seqRebased(c.outMaxEnd, p.seq)) repeat = true;
                    else c.outMaxEnd = p.seq;
                    if (c.firstOutDataTime < 0) c.firstOutDataTime = t;
                } else {
                    // 0–1 байт (ACK, keepalive-проба, FIN): повтор, только если на
                    // предыдущий такой пакет сервер не ответил ничем. Живой сервер
                    // отвечает на keepalive — простаивающее соединение не «заморозка».
                    if (c.lastProbeOut >= 0 && c.lastInTime < c.lastProbeOut) repeat = true;
                    c.lastProbeOut = t;
                }
            }
            if (S && !A) {
                c.syn++;
                if (c.synTime < 0) c.synTime = t;
                if (p.seqStart >= 0) c.isn = p.seqStart;
            }
            if (!p.httpHost.empty() && c.httpHost.empty()) c.httpHost = p.httpHost;
            if (p.ttl > 0 && outTtls.size() < 20000) outTtls.push_back(p.ttl);
            // первый ACK абонента: в тексте «ack 1» — SYN-ACK этот tcpdump видел,
            // номера от ISN; иначе этот ACK начал отсчёт сам — от ISN+1. «ack 1»,
            // поставленный fixFirstAbsoluteSeq, — второй случай: tcpdump напечатал
            // этот ACK абсолютным
            if (A && !S && c.syn > 0 && c.seqBase < 0) c.seqBase = p.ack == 1 && !p.seqRelFixed ? 1 : 0;
            // где сегмент в потоке — только если рукопожатие в дампе: у соединения,
            // начатого до записи, первым с данными бывает keep-alive Windows (1 байт,
            // seq = SND.NXT−1), а не «разрезанный ClientHello»
            const bool known = !S && p.length > 0 && c.syn > 0 && c.isn >= 0 && p.seqStart >= 0;
            const long long off = known ? streamOff(c, p.seqStart) : 0;
            const int pos = !known ? 0 : off + p.length <= 0 ? -1 : off <= 0 ? 1 : 0;
            // первый сегмент потока — накрывающий ISN+1 (seqovl начинается раньше —
            // считаем байты с ISN+1)
            if (pos > 0 && c.firstOutDataLen < 0) c.firstOutDataLen = (int)(off + p.length);
            // данные раньше ISN+1 (keep-alive — 1 байт с seq = ISN — не в счёт)
            if (known && off < 0 && p.length > 1) c.preIsnOut++;
            if (!p.sni.empty()) c.snis.insert(p.sni);
            if (!p.sni.empty() || !p.ja4.empty()) hellos.push_back({&c, i, t, pos});
            if (p.ech) c.ech = true;
            // mTLS: какой сертификат прислал абонент; первый запрос после рукопожатия
            if (p.tlsHs & TLSHS_CERT) c.clientCert = 1;
            else if (p.tlsHs & TLSHS_CERT_EMPTY) c.clientCert = 0;
            if (p.tlsHs & TLSHS_CCS) c.outCcs = true;
            else if (c.certReq && c.outCcs && c.reqTime < 0 && p.length > 1 && p.seq >= 0 &&
                     !S && !flagHas(p.flags, 'R')) {
                c.reqTime = t; c.reqSeqEnd = p.seq;
            }
            if (flagHas(p.flags, 'F') && c.finOutTime < 0) c.finOutTime = t;
        } else {
            tt.anyInboundTcp = true;
            if (t >= 0) c.lastInTime = t;
            if (S && A) {
                c.synack++;
                if (p.ttl >= 0 && c.synAckTtl < 0) c.synAckTtl = p.ttl;
                if (c.synAckTime < 0) c.synAckTime = t;
            }
            bool R = flagHas(p.flags, 'R');
            if (flagHas(p.flags, 'F')) c.inFin = true;
            if (R) {
                if (!c.inRst) {
                    c.inRst = true; c.rstTime = t;
                    if (p.ttl >= 0) c.rstTtl = p.ttl;
                    c.rstIpId = p.ipId;
                    // инъекция по пути счётчика IP ID сервера не знает
                    c.rstServerId = ipIdNext(c.lastInIpId, p.ipId) && p.ttl == c.lastInTtl;
                    if (t >= 0 && c.rstTime >= 0) c.rstBurst++;
                } else if (t >= 0 && c.rstTime >= 0 && t - c.rstTime <= 200000LL &&
                           !ipIdCaptureCopy(p.ipId, c.lastRstIpId, p.seqStart, c.lastRstSeq,
                                            t - c.lastRstTime)) {
                    // одинаковые RST от инжектора — пачка; копия захвата — нет
                    c.rstBurst++;
                }
                if (t >= 0) { c.lastRstTime = t; c.lastRstIpId = p.ipId; c.lastRstSeq = p.seqStart; }
            } else if (c.inRst && !S && t >= 0 && c.rstTime >= 0 && t - c.rstTime <= 2000000LL &&
                       !ipIdBefore(p.ipId, c.rstIpId)) {
                // сервер «не заметил» RST: ответ пришёл уже после него (в пределах 2 с,
                // чтобы не спутать с новым соединением на том же порту). Пакет с IP ID
                // РАНЬШЕ RST сервер отправил до него — это перестановка в пути, не ответ
                c.inAfterRst++;
            }
            if (!R && !c.inRst) { c.lastInIpId = p.ipId; c.lastInTtl = p.ttl; }
            if (p.httpStatus > 0 && c.httpStatus == 0) {
                c.httpStatus = p.httpStatus;
                c.httpLocation = p.httpLocation;
            }
            if (!p.httpBlockMark.empty() && c.httpBlockMark.empty()) c.httpBlockMark = p.httpBlockMark;
            // mTLS: запрос сертификата, Alert, когда сервер подтвердил запрос
            // абонента и когда ответил на него (ниже по ветке данных — continue)
            if (p.tlsHs & TLSHS_CERT_REQ) c.certReq = true;
            if ((p.tlsHs & TLSHS_ALERT) && c.tlsAlertIn < 0) c.tlsAlertIn = p.tlsAlert;
            if (flagHas(p.flags, 'F') && c.finInTime < 0) c.finInTime = t;
            if (c.reqTime >= 0 && c.reqAckTime < 0 && A && p.ack >= 0 && !seqLess(p.ack, c.reqSeqEnd))
                c.reqAckTime = t;
            if (c.inCcs && p.length > 0 && !R) {
                c.inAppBytes += p.length;
                if (c.reqTime >= 0 && c.respTime < 0) c.respTime = t;
            }
            if (p.tlsHs & TLSHS_CCS) c.inCcs = true;
            if (p.length > 0 && !flagHas(p.flags, 'R')) {
                if (c.firstData < 0) c.firstData = t;
                c.serverBytes += p.length;
                if (p.ttl >= 0 && c.dataTtl < 0) c.dataTtl = p.ttl;
                // новые ли это данные или ретрансмит уже принятого
                bool fresh = true; long long add = p.length;
                if (p.seq >= 0) {
                    const long long maxEnd = seqRebased(c.inMaxEnd, p.seq) ? -1 : c.inMaxEnd;
                    if (maxEnd >= 0 && !seqLess(maxEnd, p.seq)) fresh = false;
                    else if (maxEnd >= 0) {
                        long long gap = (long long)(uint32_t)((uint32_t)p.seq - (uint32_t)maxEnd);
                        if (gap < add) add = gap;
                    }
                    if (fresh) c.inMaxEnd = p.seq;
                }
                if (fresh) { c.inUniqBytes += add; c.lastNewData = t; c.laterPkts = 0; continue; }
                repeat = true;   // ретрансмит уже принятого
            }
        }
        // повтор (в любую сторону) спустя ≥1 с после последних новых данных. Голые
        // ACK, keepalive и запросы, которые сервер подтвердил, не считаем: так выглядит
        // обычное простаивающее keep-alive-соединение, а не «заморозка».
        if (repeat && c.lastNewData >= 0 && t >= 0 && t - c.lastNewData >= 1000000LL) c.laterPkts++;
    }
    // исходящие с данными и TTL заметно ниже обычного — фейки средств обхода DPI
    if (!outTtls.empty()) {
        std::nth_element(outTtls.begin(), outTtls.begin() + outTtls.size() / 2, outTtls.end());
        tt.outTtlTypical = outTtls[outTtls.size() / 2];
    }
    if (tt.outTtlTypical >= 32) {
        for (size_t i = 0; i < packets.size(); i++) {
            const Packet& p = packets[i];
            if (p.proto != "TCP" || p.length <= 0 || p.ttl <= 0 || p.ttl > 12) continue;
            bool sLoc = isLocal(p.srcIp), dLoc = isLocal(p.dstIp);
            if (!sLoc || dLoc) continue;
            auto it = tt.conns.find(p.dstIp + "|" + std::to_string(p.dstPort) + "|" +
                                    std::to_string(p.srcPort) + "|" + p.srcIp);
            if (it != tt.conns.end()) it->second.lowTtlOut++;
        }
    }
    // Настоящий ClientHello. Обходчики DPI (zapret, GoodbyeDPI, ByeDPI) шлют перед
    // ним фейки с чужим SNI: по первому блокировка доставалась домену-приманке или
    // гасилась рабочими соединениями с тем же фейком. Фейки с малым TTL (как
    // lowTtlOut) и целиком до начала потока не берём; из остальных — начинающий
    // поток (ISN+1), а из равных — последний: фейк уходит раньше настоящего (фейк с
    // верным seq и испорченной контрольной суммой иначе не отличить). JA4 — так же.
    // Время — первого ClientHello с выбранным SNI: повторы его не сдвигают.
    std::unordered_map<const TcpConnState*, int> sniRank, ja4Rank;
    for (const Hello& h : hellos) {
        const Packet& p = packets[h.i];
        if (h.pos < 0 || (tt.outTtlTypical >= 32 && p.ttl > 0 && p.ttl <= 12)) continue;
        const int r = h.pos > 0 ? 2 : 1;
        if (!p.sni.empty() && r >= sniRank[h.c]) { sniRank[h.c] = r; h.c->sni = p.sni; }
        if (!p.ja4.empty() && r >= ja4Rank[h.c]) {
            ja4Rank[h.c] = r;
            h.c->ja4 = p.ja4; h.c->ja4Kind = p.ja4Kind;
        }
    }
    for (const Hello& h : hellos)
        if (!h.c->ch && !h.c->sni.empty() && packets[h.i].sni == h.c->sni) {
            h.c->ch = true; h.c->chTime = h.t;
        }
    for (const auto& kv : tt.conns)
        if (kv.second.serverBytes >= 200) tt.workedIps.insert(kv.second.ip);
    return tt;
}

// Проверка «домен заканчивается на suffix» с учётом границы поддомена:
// исключает ложные срабатывания вроде "microsof[t.co]m" когда ищем "t.co".
bool domainEndsWith(const std::string& d, const std::string& suffix) {
    if (d.size() < suffix.size()) return false;
    if (d.compare(d.size() - suffix.size(), suffix.size(), suffix) != 0) return false;
    if (d.size() == suffix.size()) return true;
    return d[d.size() - suffix.size() - 1] == '.';
}

// Проверка «домен относится к ресурсу, ограниченному в РФ» (по точной границе).
bool isCommonlyBlockedDomain(const std::string& d) {
    static const char* suf[] = {
        "facebook.com", "fbcdn.net", "cdninstagram.com", "instagram.com",
        "twitter.com", "x.com", "tiktok.com",
        "linkedin.com", "discordapp.com", "discord.com",
        "youtube.com", "googlevideo.com",
        nullptr
    };
    for (int i = 0; suf[i]; ++i)
        if (domainEndsWith(d, suf[i])) return true;
    return false;
}

// Фоновые загрузки Windows/Microsoft. Порядок: User-Agent (точнее всего),
// путь HTTP (кэш DO/MCC у провайдера отдаёт по IP, без «своего» имени),
// затем имя узла.
const char* msBackgroundDownload(const std::string& host, const std::string& ua,
                                 const std::string& path) {
    auto low = [](std::string s) {
        for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        return s;
    };
    struct Rule { const char* pat; const char* what; };
    if (!ua.empty()) {
        static const Rule kUa[] = {
            { "microsoft-delivery-optimization", "Delivery Optimization" },
            { "windows-update-agent",            "Windows Update" },
            { "microsoft bits",                  "BITS (фоновая передача Windows)" },
            { "microsoft-cryptoapi",             "CryptoAPI (сертификаты/CRL)" },
            { "mpcommunication",                 "Microsoft Defender" },
            { "microsoft edge update",           "обновление Edge" },
            { "microsoftedgeupdate",             "обновление Edge" },
            { "msoffice",                        "Office" },
            { "microsoft office",                "Office" },
        };
        const std::string u = low(ua);
        for (const Rule& r : kUa) if (u.find(r.pat) != std::string::npos) return r.what;
    }
    if (!path.empty()) {
        static const Rule kPath[] = {
            { "/filestreamingservice/files/", "Delivery Optimization" },
            { "/msdownload/update/",          "Windows Update" },
            { "/c/upgr/",                     "Windows Update (обновление версии)" },
            { "/d/upgr/",                     "Windows Update (обновление версии)" },
            { "/office/data/",                "Office (Click-to-Run)" },
        };
        const std::string pt = low(path);
        for (const Rule& r : kPath) if (pt.find(r.pat) != std::string::npos) return r.what;
    }
    if (!host.empty()) {
        std::string h = low(host);
        while (!h.empty() && h.back() == '.') h.pop_back();
        static const Rule kHost[] = {
            { "do.dsp.mp.microsoft.com",       "Delivery Optimization" },
            { "delivery.mp.microsoft.com",     "Windows Update / Store" },
            { "mp.microsoft.com",              "Windows Update / Store" },
            { "windowsupdate.com",             "Windows Update" },
            { "update.microsoft.com",          "Windows Update" },
            { "windowsupdate.microsoft.com",   "Windows Update" },
            { "ntservicepack.microsoft.com",   "Windows Update" },
            { "wustat.windows.com",            "Windows Update" },
            { "cdp.microsoft.com",             "Windows Update" },
            { "emdl.ws.microsoft.com",         "Microsoft Store" },
            { "download.microsoft.com",        "загрузка Microsoft" },
            { "officecdn.microsoft.com",       "Office (Click-to-Run)" },
            { "officecdn.microsoft.com.edgesuite.net", "Office (Click-to-Run)" },
            { "cdn.office.net",                "Office (Click-to-Run)" },
            { "definitionupdates.microsoft.com", "Microsoft Defender" },
            { "msedge.net",                    "обновление Edge / CDN Microsoft" },
            { "oneclient.sfx.ms",              "обновление OneDrive" },
            { "assets1.xboxlive.com",          "Xbox / Microsoft Store (игры)" },
            { "assets2.xboxlive.com",          "Xbox / Microsoft Store (игры)" },
            { "dlassets.xboxlive.com",         "Xbox / Microsoft Store (игры)" },
            { "dlassets2.xboxlive.com",        "Xbox / Microsoft Store (игры)" },
            { "xvcf1.xboxlive.com",            "Xbox / Microsoft Store (игры)" },
            { "xvcf2.xboxlive.com",            "Xbox / Microsoft Store (игры)" },
            { "d1.xboxlive.com",               "Xbox / Microsoft Store (игры)" },
            { "d2.xboxlive.com",               "Xbox / Microsoft Store (игры)" },
        };
        for (const Rule& r : kHost) if (domainEndsWith(h, r.pat)) return r.what;
    }
    return nullptr;
}

// ------------------------------------------------------------------
// Сведения об удалённом узле для детекторов ниже
// ------------------------------------------------------------------
const IpInfo* ipInfoOf(const std::unordered_map<std::string, IpInfo>* ipCache,
                       const std::string& ip) {
    if (!ipCache) return nullptr;
    auto it = ipCache->find(ip);
    return it == ipCache->end() ? nullptr : &it->second;
}
// хостинг/датацентр, не CDN и не сеть оператора
bool isHostingNonCdn(const IpInfo* i) {
    if (!i) return false;
    return (i->hosting || looksHostingOrg(i->org, i->asn)) &&
           !isOwnIspOrg(i->org, i->asn) && !looksCdnOrg(i->org);
}
bool isForeignHosting(const IpInfo* i) {
    return isHostingNonCdn(i) && !i->country.empty() && i->country != "-" && i->country != "RU";
}

// адрес -> имена, для которых DNS в дампе вернул этот адрес (нижний регистр,
// без точки в конце). Запрос и ответ сводятся по клиент|порт|id.
std::map<std::string, std::set<std::string>> dnsNamesByIp(const std::vector<Packet>& packets) {
    std::map<std::string, std::string> qByKey;
    std::map<std::string, std::set<std::string>> out;
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
        for (auto& c : q) c = (char)::tolower((unsigned char)c);
        while (!q.empty() && q.back() == '.') q.pop_back();
        if (q.empty()) continue;
        for (const auto& ip : p.dnsAnswers) out[ip].insert(q);
        if (p.dnsAnswers.empty() && !p.dnsAnswerIp.empty()) out[p.dnsAnswerIp].insert(q);
    }
    return out;
}

bool inVpnWhitelistAsn(const std::string& asn) {
    return !asnInList(asn, cfg().vpnWhitelistAsns).empty();
}

std::string vpnWhitelistDomain(const std::string& name) {
    for (const auto& d : cfg().vpnWhitelistDomains)
        if (domainEndsWith(name, d)) return d;
    return {};
}

std::unordered_map<std::string, IpInfo> withVpnWhitelist(
        const std::vector<Packet>& packets,
        const std::unordered_map<std::string, IpInfo>* ipCache) {
    std::unordered_map<std::string, IpInfo> out;
    if (ipCache) out = *ipCache;
    for (auto& kv : out) {
        if (kv.second.vpnWhite) continue;
        const std::string n = asnInList(kv.second.asn, cfg().vpnWhitelistAsns);
        if (n.empty()) continue;
        kv.second.vpnWhite = true;
        kv.second.whiteWhy = "AS" + n;
    }
    if (cfg().vpnWhitelistDomains.empty()) return out;
    for (const auto& kv : dnsNamesByIp(packets)) {
        if (isLocalIp(kv.first)) continue;
        for (const auto& name : kv.second) {
            if (vpnWhitelistDomain(name).empty()) continue;
            IpInfo& i = out[kv.first];          // адрес не резолвился — заглушка с пометкой
            if (!i.vpnWhite) { i.vpnWhite = true; i.whiteWhy = name + " по DNS"; }
            break;
        }
    }
    return out;
}
std::string connWsFilter(const TcpConnState& c) {
    return wsFilter(c.ip, c.rport) + " && tcp.port==" + std::to_string(c.lport);
}

// Объём по удалённым адресам: все протоколы (TCP, UDP, ICMP), полезная нагрузка
// обоих направлений, только пакеты с ровно одной локальной стороной. Одно
// определение для топа режима 1, «Куда уходит трафик» в Обзоре и сравнения
// дампов — раньше Обзор терял ICMP и брал TCP из таблицы соединений.
std::map<std::string, long long> bytesByRemote(const std::vector<Packet>& packets) {
    std::map<std::string, long long> m;
    for (const auto& p : packets)
        if (const std::string* rip = remoteSideOf(p)) m[*rip] += p.length;
    return m;
}
