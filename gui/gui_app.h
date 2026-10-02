// gui_app.h — внутренний заголовок GUI: журнал вывода, загруженный набор
// дампов, фоновые задачи. Не для остального кода программы.
#pragma once

#include "../common.h"
#include "imgui/imgui.h"
#include <memory>
#include <functional>

using IpCache = std::unordered_map<std::string, IpInfo>;

// ------------------------------------------------------------------
// Журнал (gui_log.cpp): весь вывод анализа (rprintf и std::cout) с цветами
// ANSI. Дописывается из фонового потока, рисуется в потоке окна.
// ------------------------------------------------------------------
class LogBuffer {
public:
    void append(const char* s, size_t n);      // потокобезопасно
    void clear();
    // Рисует журнал в текущем дочернем окне. filter — подстрока (без учёта
    // регистра латиницы), пустая = все строки.
    void draw(const char* filter, bool autoScroll);
    std::string text();                        // весь текст без ANSI
    std::string selectedText();                // выделенное мышью ("" — ничего)
    bool hasSelection();
    void selectAll();
    size_t lineCount();

private:
    struct Run { size_t off; unsigned char col; };
    struct TextPos { size_t line = 0, off = 0; };   // строка и байт от её начала
    void newLineLocked();
    void rebuildFilterLocked(const std::string& f);
    void resetSelectionLocked();
    void selectAllLocked();
    std::string selectedTextLocked();

    std::mutex mx_;
    std::string text_;                  // текст без escape-кодов, строки через '\n'
    std::vector<size_t> lineStart_{0};  // начало каждой строки в text_
    std::vector<Run> runs_;             // смены цвета: с позиции off — цвет col
    unsigned char curCol_ = 0;          // текущий цвет (0 = по умолчанию)
    std::string esc_;                   // недописанная escape-последовательность
    bool inEsc_ = false;
    // фильтр
    std::string filter_;
    std::vector<size_t> filtered_;      // номера строк, прошедших фильтр
    size_t filteredUpTo_ = 0;           // сколько строк уже проверено
    size_t lastDrawnLines_ = 0;
    // выделение мышью: якорь (где нажали) и курсор (куда тянут)
    TextPos selAnchor_, selCursor_;
    bool selDragging_ = false;
};

LogBuffer& appLog();
// Строка в журнал от самого GUI (не через printf — у GUI свой заголовок).
void logLine(const char* ansiColor, const std::string& text);

// ------------------------------------------------------------------
// Соединение (поток) для таблицы: агрегат по proto + локальный + удалённый
// конец. Считается один раз при загрузке, дальше не меняется.
// ------------------------------------------------------------------
enum FlowState {
    FS_OK = 0,        // рукопожатие есть, данные в обе стороны
    FS_NO_ANSWER,     // SYN без SYN-ACK
    FS_RST,           // удалённая сторона (или кто-то за неё) прислала RST
    FS_ONE_WAY,       // данные только в одну сторону
    FS_MIDSTREAM,     // начало соединения не попало в дамп
    FS_UDP,           // UDP/ICMP — без состояния
    FS_IN_REFUSED,    // входящий SYN, абонент не принял (RST или молчание) — чаще сканер
};

// Событие временного профиля (waterfall) TCP-соединения. Чистые ACK не
// записываются; пакеты данных одного направления подряд сливаются в серию.
enum FlowEvKind : uint8_t {
    FE_SYN, FE_SYNACK,
    FE_HELLO,          // TLS ClientHello (есть SNI)
    FE_HTTPREQ,        // запрос HTTP без TLS
    FE_DATA,           // серия пакетов с новыми данными
    FE_RETX,           // серия повторов (данные, которые уже были)
    FE_HTTPRESP,       // ответ HTTP (code — код)
    FE_RST, FE_FIN,
};

struct FlowEvent {
    long long us = 0, endUs = 0;   // от начала дампа; у серии — первый и последний пакет
    long long bytes = 0;           // полезная нагрузка (у серии — сумма)
    int count = 1;                 // пакетов в серии
    int ttl = -1;                  // TTL первого пакета
    // RST от сервера: эталонный TTL сервера, как в connTtlInjection (-1 — нет);
    // code = 1 — эталон по данным сервера, 2 — по SYN-ACK
    int ttlRef = -1;
    int code = 0;                  // FE_HTTPRESP: код ответа
    uint8_t kind = FE_DATA;
    bool out = false;              // от абонента
    bool serverId = false;         // RST от сервера: IP ID продолжает его счётчик, TTL тот же
    // RST от сервера, как rstBurst / inAfterRst в buildTcpConnTable: RST в пачке
    // (без копий захвата — тот же IP ID за единицы мкс) и входящих не-RST за 2 с после
    // него (без отправленных сервером раньше RST — IP ID меньше)
    int burst = 0, afterRst = 0;
};

struct FlowRow {
    std::string proto;
    std::string localIp, remoteIp;
    int localPort = -1, remotePort = -1;
    long long pktsOut = 0, pktsIn = 0, bytesOut = 0, bytesIn = 0;
    long long firstUs = -1, lastUs = -1;       // от начала дампа
    std::string sni, ja4, tlsClient, dnsName, app;
    std::string dnsCname;                      // "fl.yoomoney.ru → fp-back.facct.ru" или пусто
    int ja4Kind = 0;
    int synOut = 0, synAckIn = 0, rstIn = 0, rstOut = 0, finIn = 0, finOut = 0;
    int synIn = 0, synAckOut = 0;              // входящее соединение (к абоненту)
    int ttlMin = -1, ttlMax = -1;              // TTL входящих пакетов
    bool quic = false, wg = false, ech = false;
    bool dns = false;                          // в потоке разобраны DNS-сообщения
    uint8_t l7 = L7_NONE;                      // протокол по содержимому (L7Proto)
    bool appByContent = false;                 // app — по содержимому, а не догадка по порту
    // HTTP без TLS: первый запрос и первый ответ потока
    std::string httpHost, httpLocation, httpBlockMark;
    int httpStatus = 0;
    long long httpReqUs = -1, httpRespUs = -1; // время запроса/ответа (от начала дампа)
    std::string msBg;                          // фоновая загрузка Windows/Microsoft (msBackgroundDownload) или пусто
    std::vector<FlowEvent> wf;                 // временной профиль (только TCP), по времени
    int wfDropped = 0;                         // событий сверх лимита — не записаны
    int state = FS_OK;
    bool problem = false;                      // стоит показать в «только проблемные»
    std::string search;                        // строка для фильтра (нижний регистр)
};

// ------------------------------------------------------------------
// Загруженный набор (один файл или пара _in/_out).
// packets трогают ТОЛЬКО фоновые задачи (по одной за раз); flows и прочие
// поля неизменны после загрузки; summary/ipCache заменяются целиком под
// мьютексом (см. snapshot()).
// ------------------------------------------------------------------
struct Dataset {
    std::vector<std::string> paths;
    std::string name;
    std::vector<Packet> packets;
    std::string localIp, localIp6;
    std::vector<FlowRow> flows;
    double durSec = 0;
    long long totalBytes = 0;
    std::map<std::string, std::string> ipName;  // удалённый IP -> имя (SNI/DNS)
    std::map<std::string, std::string> ipCname; // удалённый IP -> цепочка DNS с CNAME

    std::shared_ptr<const DumpSummary> summary;
    std::shared_ptr<const IpCache> ipCache;     // nullptr — адреса ещё не резолвились
};

// Снимок для отрисовки одного кадра.
struct View {
    std::shared_ptr<Dataset> ds;
    std::shared_ptr<const DumpSummary> summary;
    std::shared_ptr<const IpCache> ipCache;
    unsigned generation = 0;    // меняется при каждой замене набора/сводки
};

View snapshot();

// ------------------------------------------------------------------
// Фоновые задачи (gui_data.cpp): одна за раз, вывод идёт в журнал.
// ------------------------------------------------------------------
bool jobBusy();
bool jobFailed();           // последняя задача закончилась ошибкой (для уведомления)
std::string jobTitle();
void startLoad(std::vector<std::string> paths);
void startResolve();
void startVpnAnalysis();
void startConnAnalysis(const std::string& target);
void startIpOwner(const std::string& target);   // режим 13 (кому принадлежит IP) в журнал
// сравнение: A — текущий набор (если pathsA пуст) или указанные файлы
void startCompare(std::vector<std::string> pathsA, std::vector<std::string> pathsB);
void startReloadConfig();
void startOwnIspDetect();   // своя сеть: AS по своему адресу, запомнить, пересчитать обзор
// true, если перед выходом нужно убить процесс (задача ещё работает)
bool jobMustAbortOnExit();

// Интерактивные режимы (3..9, 10 = сравнение в консоли, 11 = DNS, 12 = «16 КБ», 13 = владелец IP) — отдельным процессом
// в своём консольном окне.
bool launchConsoleTool(int mode);
struct ToolProc { int mode; std::string title; };
const char* toolTitle(int mode);
std::vector<ToolProc> runningTools();           // заодно убирает завершившиеся

// ------------------------------------------------------------------
// Вкладка «Проверка РКН» (gui_rkn.cpp): ручная проверка домена / IP /
// подсети / AS через cheburcheck.ru. Только по действию пользователя —
// данные дампа сами никуда не отправляются. Свой поток, не задача.
// ------------------------------------------------------------------
struct GuiColors { ImVec4 accent, good, warn, bad, dim, panelBg; };
// Рисует содержимое вкладки. true — идёт запрос, нужны кадры без пауз.
bool rknDrawTab(const GuiColors& c);
// Подставить цель в поле ввода и сразу проверить (из меню соединения).
void rknCheck(const std::string& target);

// ------------------------------------------------------------------
// Окно (gui.cpp / gui_main.cpp)
// ------------------------------------------------------------------
// Модификатор сочетаний в подписях: ImGuiMod_Ctrl на macOS — это Cmd.
#ifdef __APPLE__
#define GUI_MOD "Cmd"
#else
#define GUI_MOD "Ctrl"
#endif

HWND mainHwnd();                 // на macOS — nullptr
void guiRequestClose();          // закрыть окно (как крестик)
// Окно без системного заголовка (Windows): «свернуть / развернуть / закрыть»
// рисует панель меню, а её пустая часть — заголовок (перетаскивание, двойной
// щелчок, Snap). На macOS заголовок системный — guiCustomTitleBar() == false.
bool guiCustomTitleBar();
void guiMinimize();
void guiToggleMaximize();
bool guiIsMaximized();
// пустая часть панели меню, за которую тянут окно (x от left до right, y до
// height; координаты ImGui = клиентские пиксели окна). Каждый кадр.
void guiSetCaptionArea(float left, float right, float height);
void guiInit();                 // стиль, состояние
void guiFrame();                 // один кадр интерфейса
void guiRequestLogTab();         // переключиться на вкладку «Журнал»
bool guiLightTheme();            // выбрана светлая тема (палитра журнала, заголовок окна)
ImVec4 guiClearColor();          // фон под окном ImGui — по теме
bool guiWantsFrames();           // идёт анимация — главный цикл не должен засыпать
std::string fmtBytes(long long b);
extern ImFont* g_fontMono;       // моноширинный для журнала (может быть nullptr)

// Картинка на фоне окна (gui_main.cpp — там устройство D3D11).
struct WallpaperTex {
    ImTextureID tex = 0;         // 0 — не загружена
    int w = 0, h = 0;
    bool builtin = false;        // встроенная (из ресурса exe)
};
// path пустой — встроенная. При ошибке прежняя картинка остаётся, err — причина.
// Звать в начале кадра, до отрисовки фона (старая текстура освобождается сразу).
bool wallpaperLoad(const std::wstring& path, std::string& err);
const WallpaperTex& wallpaperTex();
