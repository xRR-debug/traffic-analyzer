// config.h — настройки программы: пороги анализа, таблицы портов.
//
// Значения по умолчанию заданы в config.cpp. Их переопределяет файл
// analyzer.ini (ищется рядом с exe, затем в текущем каталоге; формат
// «ключ = значение», образец — analyzer.ini.example). Ключей API больше нет:
// внешние сервисы (Globalping, ip-api/ipwho.is/ipapi.is) работают без них.
#pragma once

#include <map>
#include <string>
#include <vector>

// Пороги вердикта VPN: одни для режима 1, Обзора GUI и сравнения дампов.
// В ini не настраиваются; потолки ниже ограничены относительно них.
constexpr int kVpnLikelyScore   = 3;   // «ВЕРОЯТНО ВКЛЮЧЁН VPN»
constexpr int kVpnPossibleScore = 1;   // «ВОЗМОЖНО есть VPN»
// Предел shape_cap: одна «форма» трафика (доля, гео, число хостов) не должна
// давать «ВЕРОЯТНО» без единого прямого признака.
constexpr int kShapeCapMax      = kVpnLikelyScore - 1;
// Предел flow_score_cap: больше потоковые признаки набрать не могут
// (Reality 2 + JA4 2 + долгий поток 1).
constexpr int kFlowScoreCapMax  = 5;

struct AppConfig {
    // --- внешние сервисы ---
    bool autoResolve          = true;        // GUI: страна/ASN сразу после загрузки дампа
                                             // (адреса уходят во внешние geo-сервисы)
    std::string ip2proxyDb;                  // путь к базе IP2Proxy .BIN (UTF-8, полный); "" — не задана

    // --- пороги анализа ---
    long long tailUs          = 3000000;     // «хвост» дампа: запрос/ClientHello в последние N мкс
                                             // без ответа не считаем — ответ мог не попасть в дамп
    long long freezeMinBytes  = 10 * 1024;   // «заморозка ~16 КБ»: принято не меньше…
    long long freezeMaxBytes  = 32 * 1024;   // …и не больше
    long long freezeSilenceUs = 5000000;     // тишина после последних новых данных
    int       freezeLaterPkts = 3;           // пакетов впустую после остановки
    int       tspuMinSyn      = 6;           // SYN без ответа к адресу — «блокировка рукопожатия»
    int       splitMinConns   = 2;           // соединений с первым сегментом 1–5 байт — сигнал split
    int       shapeCap        = 2;           // потолок баллов за «форму» трафика, 0..kShapeCapMax
    int       flowScoreCap    = 4;           // потолок потоковых признаков VPN, 0..kFlowScoreCapMax
    long long longFlowUs      = 120000000;   // долгий двусторонний поток к хостингу: длительность,
    long long longFlowMinIn   = 1000000;     //   принято байт не меньше,
    long long longFlowMinOut  = 100 * 1024;  //   отправлено байт не меньше

    // --- порты ---
    std::map<int, std::string> vpnUdpPorts;  // явные VPN/туннельные порты (UDP)
    std::map<int, std::string> vpnTcpPorts;  // то же для TCP
    std::map<int, std::string> proxyPorts;   // прокси/Tor/Reality — мягкий признак
    std::vector<int> scanTopPorts, scanServicePorts, scanVpnPorts;   // наборы режима 7

    // --- своя сеть оператора: не помечать «хостингом» ---
    // По умолчанию списки пусты: AS своей сети определяется кнопкой
    // «Определить» в настройках и запоминается. own_isp_asn в ini важнее.
    std::vector<std::string> ownIspOrgKeywords;   // подстроки названия организации (нижний регистр)
    std::vector<std::string> ownIspAsns;          // номера AS (подстрока поля asn)
    bool ownIspAsnFromIni = false;                // own_isp_asn задан в ini — запомненный AS не нужен

    // --- белый список VPN: крупные сервисы, баллов VPN не дают ---
    // Адрес в списке, если его AS есть в vpnWhitelistAsns или DNS в этом же
    // дампе разрезолвил в него имя из vpnWhitelistDomains. Одного SNI мало:
    // Reality ставит в SNI как раз vk.com / gosuslugi.ru, а ведёт на VPS.
    std::vector<std::string> vpnWhitelistDomains; // суффиксы доменов (нижний регистр)
    std::vector<std::string> vpnWhitelistAsns;    // номера AS

    // --- служебное ---
    std::string loadedFrom;                  // какой ini прочитан ("" — не найден, всё по умолчанию)
    std::vector<std::string> warnings;       // что в ini не разобралось
};

// Текущие настройки (после loadConfig — с учётом ini).
const AppConfig& cfg();

// Читает analyzer.ini и запомненную свою сеть. Вызывается при старте и по
// кнопке «Перечитать analyzer.ini» (startReloadConfig). Повторный вызов
// заменяет весь AppConfig: ссылки из cfg() становятся недействительными,
// поэтому звать только когда анализ не идёт (в GUI — без фоновой задачи).
// Базу IP2Proxy закрывает (ip2proxyReset): следующий запрос откроет её заново,
// и по тому же пути — файл мог появиться или обновиться.
void loadConfig();

// Закрыть базу IP2Proxy (ip2proxy.cpp); следующий запрос откроет её заново.
void ip2proxyReset();

// Каталог исполняемого файла в UTF-8, с разделителем на конце ("" — не удалось).
std::string exeDirUtf8();

// --- своя сеть, определённая по кнопке ---
// AS провайдера, через которого программа выходит в интернет: кнопка
// «Определить» в настройках (ownIspDetect, network.cpp) спрашивает ip-api.com
// и запоминает ответ — Windows: реестр HKCU\Software\MARYNONET\TrafficAnalyzer,
// macOS: ~/Library/Application Support/TrafficAnalyzer/state.ini.
// loadConfig читает запомненное, в сеть не ходит.
struct OwnIspAuto {
    unsigned    asn = 0;      // номер AS; 0 — не определён
    std::string name;         // «AS39709 Extreme Ltd» — для показа
    std::string status;       // откуда взят номер
};
OwnIspAuto ownIspAuto();                  // снимок (потокобезопасно)
unsigned   ownIspAutoAsn();               // только номер, без блокировки (для анализа)
void       ownIspAutoSet(const OwnIspAuto& v);
// Запомненное значение между запусками ("" — нет).
std::string rememberedGet(const char* name);
bool        rememberedSet(const char* name, const std::string& v);   // "" — удалить; false — не записалось
