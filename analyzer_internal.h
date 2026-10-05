// analyzer_internal.h — общее для модулей анализа (НЕ для остальной программы:
// наружу торчат только функции из common.h).
//   analyzer.cpp     — ядро: адреса, порты, организации, потоки, TCP-таблица
//   detector_dpi.cpp — детекторы блокировок/DPI/ТСПУ, DNS, UDP/QUIC, «16 КБ»,
//                      причины блокировок, обходчики DPI
//   detector_vpn.cpp — JA4, VLESS/Reality, потоковые признаки VPN, режим 1
//   report.cpp       — режим 2 (анализ соединений, пропускная способность),
//                      печать причин блокировок, сводка и сравнение дампов
#pragma once
#include "common.h"

// ------------------------------------------------------------------
// FLOW BUILDER — единый слой агрегации пакетов в потоки (как NetFlow).
// Каждый поток = одна «беседа» по 5-tuple (src_ip,dst_ip,src_port,dst_port,proto).
// Пакеты обоих направлений сливаются в один flow; направление считается
// относительно ИНИЦИАТОРА — того, кто ОТКРЫЛ соединение (см. buildFlows).
// ------------------------------------------------------------------
struct FlowRec {
    std::string srcIp, dstIp;          // инициатор -> ответчик
    int srcPort = 0, dstPort = 0;
    std::string proto;                 // TCP / UDP / ICMP
    long long bytesOut = 0, bytesIn = 0;         // от инициатора / к инициатору
    long long bytes() const { return bytesOut + bytesIn; }
};

// ------------------------------------------------------------------
// Общая таблица TCP-соединений для детекторов блокировок.
// Ключ — полный 4-tuple со стороны абонента: удалённый IP | удалённый порт |
// локальный порт. Раньше детекторы сливали соединения по «IP:порт» или вовсе
// по IP, и RST/данные одного соединения приписывались другому (браузер
// открывает к одному серверу по 6 параллельных соединений).
// ------------------------------------------------------------------
struct TcpConnState {
    std::string ip; int rport = 0, lport = 0;
    std::string sni;                  // SNI первого ClientHello
    std::set<std::string> snis;       // все SNI в соединении (фейк-ClientHello обхода DPI)
    bool ch = false;                  // был ClientHello от абонента
    bool ech = false;                 // в ClientHello расширение ECH
    std::string ja4; int ja4Kind = -1; // отпечаток первого ClientHello (-1 — не разобран)
    long long chTime = -1;
    long long firstTime = -1, lastTime = -1;
    long long syn = 0, synack = 0;    // чистые SYN (с повторами) / SYN-ACK
    int synAckTtl = -1;               // TTL SYN-ACK — эталон, если данных сервера нет
    long long firstData = -1, serverBytes = 0;
    int dataTtl = -1;
    bool inRst = false; long long rstTime = -1; int rstTtl = -1;   // ПЕРВЫЙ входящий RST
    bool inFin = false;
    long long outBytes = 0;
    int firstOutDataLen = -1;         // длина первого исходящего сегмента с данными
    long long firstOutDataTime = -1;  // время первого исходящего сегмента с данными (>1 байта)
    int lowTtlOut = 0;                // исходящих сегментов с данными и аномально низким TTL
    // «заморозка» после ~16 КБ: уникальные входящие байты и что было после
    long long inMaxEnd = -1;          // правый край принятых данных (seq)
    long long inUniqBytes = 0;
    long long lastNewData = -1;       // время последнего сегмента с НОВЫМИ данными
    int laterPkts = 0;                // повторов данных (в любую сторону) через ≥1 с после него
    long long outMaxEnd = -1;         // правый край отправленных абонентом данных (seq)
    long long lastInTime = -1;        // время последнего входящего пакета (любого)
    long long lastProbeOut = -1;      // время последнего исходящего ACK/keepalive/FIN (0–1 байт)
    // признаки поддельного RST (см. connForgedRst)
    long long synTime = -1, synAckTime = -1;   // первый исходящий SYN / первый входящий SYN-ACK
    int rstBurst = 0;                 // входящих RST в пределах 200 мс от первого
    int inAfterRst = 0;               // входящих НЕ-RST пакетов после первого RST
    int lastInIpId = -1, lastInTtl = -1;   // IP ID и TTL последнего входящего до RST
    int rstIpId = -1;                 // IP ID первого входящего RST
    long long lastRstTime = -1;       // последний входящий RST: время, IP ID и seq
    int lastRstIpId = -1;             //   (копию захвата не считать пачкой)
    long long lastRstSeq = -1;
    // IP ID у RST продолжает счётчик сервера, TTL тот же — RST послал сам сервер
    bool rstServerId = false;
    // нешифрованный HTTP
    std::string httpHost;             // Host: первого запроса
    int httpStatus = 0;               // код первого ответа
    std::string httpLocation, httpBlockMark;
    // mTLS (открытое рукопожатие TLS 1.2, Packet::tlsHs): сервер запросил
    // сертификат клиента — что прислал абонент и как ответил сервер
    bool certReq = false;             // от сервера был CertificateRequest
    int clientCert = -1;              // Certificate абонента: 0 пустой, 1 с сертификатом, -1 не было
    bool outCcs = false, inCcs = false;   // ChangeCipherSpec абонента / сервера
    int tlsAlertIn = -1;              // открытый Alert сервера (код), -1 — не было
    long long reqTime = -1, reqSeqEnd = -1;   // первый запрос абонента после рукопожатия
    long long reqAckTime = -1;        // сервер подтвердил (ACK) этот запрос
    long long respTime = -1;          // первые данные сервера после запроса
    long long inAppBytes = 0;         // данные сервера после его ChangeCipherSpec
    long long finOutTime = -1, finInTime = -1;   // первый FIN абонента / сервера
};
struct TcpConnTable {
    std::map<std::string, TcpConnState> conns;   // ключ "rip|rport|lport"
    long long tEnd = -1;              // время последнего пакета захвата
    bool anyInboundTcp = false;       // нет входящих — дамп однонаправленный, о дропах молчим
    int outTtlTypical = -1;           // медианный TTL исходящих пакетов абонента
    std::set<std::string> workedIps;  // адреса, где хоть одно соединение получило ≥200 Б
};

// VLESS/Reality: подозрительный адрес (см. collectRealitySuspects)
struct RealitySuspect {
    std::string ip, sni;
    bool famous = false, dnsMismatch = false;
    std::set<std::string> dnsIps;     // куда домен резолвился в этом дампе
    int conns = 0;
    long long bytes = 0;              // вход + выход по этим соединениям
    const TcpConnState* example = nullptr;
};

// Потоковые признаки туннеля для вердикта режима 1. Независимы от «формы»
// трафика (доля, гео, число хостов) и потому не дублируют те баллы.
struct FlowEvidence {
    int score = 0; std::vector<std::string> reasons;
    bool onlyJa4Lib = false;   // весь балл — «TLS не из браузера»: независимым признаком не считается
};

// Трафик к одному удалённому адресу — вход вердикта VPN.
struct VpnRemote {
    long long bytes = 0;
    std::set<int> remotePorts;
    bool vpnPort = false; std::string vpnName; int vpnPortNum = 0; std::string vpnProto;
    bool proxyPort = false; std::string proxyName; int proxyPortNum = 0; std::string proxyProto;
    int synMss = -1;                  // MSS из SYN-ACK удалённой стороны (экв. IPv4)
    std::set<std::string> snis;       // SNI к этому адресу (нижний регистр, без точки в конце)
};
// Полный вердикт VPN. Считается ОДНОЙ функцией (computeVpnVerdict) для режима 1,
// Обзора GUI и сравнения дампов — раньше GUI показывал только потоковую часть,
// и один дамп получал «ВЕРОЯТНО VPN» в консоли и «0 баллов» в Обзоре.
struct VpnVerdict {
    int score = 0;
    int portScore = 0, shapeScore = 0, flowScore = 0, mssScore = 0;   // из чего сложен score
    std::vector<std::string> reasons;
    std::map<std::string, VpnRemote> byRemote;
    std::map<std::string, long long> bytesByCountry;   // без CDN
    long long sumRemoteBytes = 0;
    std::vector<RealitySuspect> reality;
};

// Удалённая сторона пакета: ровно одна сторона локальная, иначе nullptr.
// Объём по адресам (режим 1, Обзор GUI, сравнение) считается только через неё.
inline const std::string* remoteSideOf(const Packet& p) {
    const bool sLoc = isLocalIp(p.srcIp), dLoc = isLocalIp(p.dstIp);
    if (sLoc == dLoc) return nullptr;
    return sLoc ? &p.dstIp : &p.srcIp;
}

// ---- analyzer.cpp ----
const char* vpnPortName(int port, const std::string& proto);
const char* proxyPortName(int port);
bool isOwnIspOrg(const std::string& org, const std::string& asn);
// UDP 500/4500: IPsec-VPN точно, VoWiFi (звонки по Wi-Fi) точно или не ясно
enum IpsecClass { IPSEC_NONE, IPSEC_VPN, IPSEC_VOWIFI, IPSEC_UNSURE };
IpsecClass ipsecClass(const Packet& p, int remotePort, const IpInfo* remote);
std::string guessKind(const Packet& p, const IpInfo& srcI, const IpInfo& dstI);
std::string sideLabel(const std::string& ip, const IpInfo& info);
bool flagHas(const std::string& f, char c);
std::vector<FlowRec> buildFlows(const std::vector<Packet>& packets);
std::string wsFilter(const std::string& ip, int port = -1, const char* l4 = "tcp");
bool seqLess(long long a, long long b);
TcpConnTable buildTcpConnTable(const std::vector<Packet>& packets, const std::string& localIp);
bool domainEndsWith(const std::string& d, const std::string& suffix);
bool isCommonlyBlockedDomain(const std::string& d);
const IpInfo* ipInfoOf(const std::unordered_map<std::string, IpInfo>* ipCache,
                       const std::string& ip);
bool isForeignHosting(const IpInfo* i);
std::map<std::string, std::set<std::string>> dnsNamesByIp(const std::vector<Packet>& packets);
// Белый список VPN (vpn_whitelist_domains / vpn_whitelist_asn): суффикс из
// списка, которому соответствует имя ("" — не в списке).
std::string vpnWhitelistDomain(const std::string& name);
// Копия ipCache для анализа VPN: у адресов из белого списка стоит vpnWhite —
// по номеру AS или по имени из списка, которое DNS в этом дампе разрезолвил в
// этот адрес. Адрес без записи (не резолвился), попавший в список по DNS,
// получает заглушку. Проверкам соединения (режим 2) эту копию не отдавать:
// проблемы связи с такими адресами ищутся как обычно.
std::unordered_map<std::string, IpInfo> withVpnWhitelist(
        const std::vector<Packet>& packets,
        const std::unordered_map<std::string, IpInfo>* ipCache);
std::string connWsFilter(const TcpConnState& c);
std::map<std::string, long long> bytesByRemote(const std::vector<Packet>& packets);

// ---- detector_dpi.cpp ----
void analyzeDnsAnomalies(const std::vector<Packet>& packets);
bool connSilentDrop(const TcpConnTable& tt, const TcpConnState& c);
bool connSniRst(const TcpConnState& c);
int  connTtlInjection(const TcpConnState& c, int& ref, const char*& refWhat);
bool connIsForgedRst(const TcpConnState& c);
std::vector<std::string> detectDpiInjection(const TcpConnTable& tt);
std::vector<std::string> detectDpiInjection(const std::vector<Packet>& packets,
                                            const std::string& localIp);
std::set<std::string> collectTspuBlockedIps(const std::vector<Packet>& packets,
                                            const std::string& localIp,
                                            const TcpConnTable* ttIn = nullptr,
                                            const std::unordered_map<std::string, IpInfo>* ipCache = nullptr);
std::map<std::string,std::string> collectBlockedSnis(const std::vector<Packet>& packets,
                                                     const std::string& localIp,
                                                     const TcpConnTable* ttIn = nullptr);
void analyzeUdpConns(const std::vector<Packet>& packets, const std::string& localIp,
                     const std::string& targetIp = "",
                     const std::unordered_map<std::string, IpInfo>* ipCache = nullptr);
void analyzeQuic(const std::vector<Packet>& packets, const std::string& localIp,
                 const std::string& targetIp = "");
void analyzeConnectivityFailure(const std::vector<Packet>& packets, const std::string& localIp);
void analyzeFreeze16k(const TcpConnTable& tt,
                      const std::unordered_map<std::string, IpInfo>* ipCache);
std::vector<BlockReason> collectBlockReasons(const std::vector<Packet>& packets,
                                             const TcpConnTable& tt,
                                             const std::unordered_map<std::string, IpInfo>* ipCache,
                                             const std::string& localIp,
                                             const std::string& onlyIp = "");
void analyzeDpiBypass(const TcpConnTable& tt);

// ---- detector_vpn.cpp ----
void analyzeJa4(const std::vector<Packet>& packets,
                const std::unordered_map<std::string, IpInfo>* ipCache,
                const std::string& targetIp = "");
std::vector<RealitySuspect> collectRealitySuspects(const std::vector<Packet>& packets,
                                                   const TcpConnTable& tt,
                                                   const std::unordered_map<std::string, IpInfo>* ipCache);
void printRealitySuspects(const std::vector<RealitySuspect>& rs,
                          const std::unordered_map<std::string, IpInfo>* ipCache);
FlowEvidence flowVpnEvidence(const TcpConnTable& tt, const std::vector<RealitySuspect>& reality,
                             const std::unordered_map<std::string, IpInfo>* ipCache);
VpnVerdict computeVpnVerdict(const std::vector<Packet>& packets, const TcpConnTable& tt,
                             const std::unordered_map<std::string, IpInfo>* ipCache);

// ---- report.cpp ----
void analyzeThroughput(const std::vector<Packet>& packets, const std::string& localIp,
                       const std::string& targetIp = "");
void printBlockReasons(const std::vector<BlockReason>& rs);
