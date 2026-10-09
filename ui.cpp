// ui.cpp — консоль и меню: вывод с копией в отчёт, цвета, выбор файлов,
// ввод цели, режим сравнения, main и главный цикл.
#include "common.h"
#include "gui/gui.h"

#ifdef _WIN32
static BOOL WINAPI ctrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
        g_traceAbort = true;   // прервать текущую трассировку (если идёт)
        return TRUE;           // обработали — система НЕ завершает процесс
    }
    if (type == CTRL_CLOSE_EVENT) return FALSE; // закрытие окна — пусть закрывается
    return TRUE;
}
#else
static void sigintHandler(int) { g_traceAbort = true; }   // то же: Ctrl+C не закрывает
#endif
static void stripAnsiTo(FILE* f, const char* s, size_t n) {
    const char* e = s + n;
    for (const char* p = s; p < e; ++p) {
        if (*p == '\x1b') { while (p < e && *p != 'm') ++p; if (p >= e) break; continue; }
        fputc(*p, f);
    }
}
// БЕЗОПАСНАЯ версия rprintf.
//  * Стековый буфер 16 КБ покрывает 99% строк без аллокаций.
//  * Если формат оказался длиннее — переключаемся на кучу, не режем строку
//    и не портим стек (у старой версии buf[4096] длинные форматы обрезались).
//  * Один fwrite вместо fputs → один WriteFile-сисколл вместо посимвольного.
//  * fwrite к stdout собирает вывод в CRT-буфер (setvbuf в main его расширяет
//    до 256 КБ), что даёт кратное ускорение отрисовки в консоли Win10.
static std::mutex g_printMx;   // rprintf вызывается и из пула потоков — сериализуем
int rprintf(const char* fmt, ...) {
    char stack[16384];
    va_list ap; va_start(ap, fmt);
    va_list ap2; va_copy(ap2, ap);
    int need = vsnprintf(stack, sizeof(stack), fmt, ap);
    va_end(ap);
    // ошибка форматирования: содержимое stack не определено (может быть
    // без завершающего нуля) — ничего не выводим
    if (need < 0) { va_end(ap2); return need; }
    char* buf = stack;
    std::vector<char> heap;
    if (need >= (int)sizeof(stack)) {
        heap.resize((size_t)need + 1);
        vsnprintf(heap.data(), heap.size(), fmt, ap2);
        buf = heap.data();
    }
    va_end(ap2);
    size_t len = strlen(buf);
    {
        std::lock_guard<std::mutex> lk(g_printMx);
        if (g_consoleEcho) fwrite(buf, 1, len, stdout);
        if (g_report) stripAnsiTo(g_report, buf, len);
        if (auto sink = g_outputSink.load()) sink(buf, len);
    }
    return need;
}

// Вывод std::cout в GUI-режиме (см. CoutRedirect в gui_main.cpp): в консоль,
// если она есть, и в журнал окна. В файл-отчёт, как и раньше, не пишется.
void rawOutput(const char* s, size_t n) {
    if (n == 0) return;
    std::lock_guard<std::mutex> lk(g_printMx);
    if (g_consoleEcho) fwrite(s, 1, n, stdout);
    if (auto sink = g_outputSink.load()) sink(s, n);
}

// ------------------------------------------------------------------
// файл-отчёт рядом с дампом: <basePath>.<kind>.<время>.txt (UTF-8 с BOM)
// ------------------------------------------------------------------
void closeReport() {
    std::lock_guard<std::mutex> lk(g_printMx);
    if (g_report) { fclose(g_report); g_report = nullptr; }
}

std::string openReport(const std::string& basePath, const char* kind) {
    closeReport();
    if (!g_logEnabled || basePath.empty()) return "";
    time_t now = time(nullptr);
    struct tm lt; localtime_s(&lt, &now);
    char stamp[32];
    strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &lt);
    std::string reportPath = basePath + "." + kind + "." + stamp + ".txt";
    FILE* f = ufopen(reportPath, "wb");
    if (!f) {
        std::cout << C::YEL << "Не удалось создать отчёт: " << reportPath << C::RST << "\n";
        return "";
    }
    // UTF-8 BOM, чтобы Блокнот корректно показал кириллицу
    fputc(0xEF, f); fputc(0xBB, f); fputc(0xBF, f);
    {
        std::lock_guard<std::mutex> lk(g_printMx);
        g_report = f;
    }
    std::cout << "Отчёт будет сохранён: " << reportPath << "\n";
    return reportPath;
}

// Собственный «cls» без system("cls"). system() создаёт новый процесс cmd.exe
// (~150 мс на слабом ПК) и часто ломает scrollback. Здесь: VT-escape для новых
// Win10, потом fallback через FillConsoleOutputCharacter — надёжно везде.
#ifndef _WIN32
static void clearScreen() {
    fflush(stdout);
    std::cout << "\x1b[2J\x1b[3J\x1b[H" << std::flush;   // экран, scrollback, курсор домой
}
#else
static void clearScreen() {
    fflush(stdout);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) { std::cout << "\x1b[2J\x1b[H" << std::flush; return; }
    // 1) VT-escape (Windows 10 1809+)
    DWORD written = 0;
    const char* seq = "\x1b[2J\x1b[3J\x1b[H";  // очистить экран, scrollback, курсор домой
    WriteFile(h, seq, (DWORD)strlen(seq), &written, NULL);
    // 2) fallback через старый Console API — на случай, если VT не включен
    CONSOLE_SCREEN_BUFFER_INFO ci;
    if (GetConsoleScreenBufferInfo(h, &ci)) {
        DWORD size = (DWORD)ci.dwSize.X * (DWORD)ci.dwSize.Y;
        COORD home = {0, 0};
        DWORD w = 0;
        FillConsoleOutputCharacterA(h, ' ', size, home, &w);
        FillConsoleOutputAttribute(h, ci.wAttributes, size, home, &w);
        SetConsoleCursorPosition(h, home);
    }
}

// Разово расширяем scrollback-буфер консоли. По умолчанию на Windows 300 строк —
// при большом отчёте пользователь не может отпролистать вывод наверх и в
// некоторых сборках Win10 conhost начинает подтормаживать/крашиться.
static void enlargeScrollback() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return;
    CONSOLE_SCREEN_BUFFER_INFO ci;
    if (!GetConsoleScreenBufferInfo(h, &ci)) return;
    // Ширину оставляем как есть, высоту буфера увеличиваем до 9999.
    COORD s = { ci.dwSize.X, (SHORT)std::max<int>(9999, ci.dwSize.Y) };
    SetConsoleScreenBufferSize(h, s);
}

static void enableAnsiColors() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (!GetConsoleMode(h, &mode)) return;
    SetConsoleMode(h, mode | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/);
}
#endif

// ------------------------------------------------------------------
// утилиты
// ------------------------------------------------------------------
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// Названия стран по ISO-коду: одна таблица для колонки REGION (англ., капс)
// и режима гео-RTT (рус.). Раньше это были две функции с разными списками.
// Незнакомый код возвращается как есть — копией, а не указателем на аргумент.
struct CountryNames { const char* cc; const char* en; const char* ru; };
static const CountryNames kCountries[] = {
    {"RU", "RUSSIA", "Россия"},             {"NL", "NETHERLANDS", "Нидерланды"},
    {"DE", "GERMANY", "Германия"},          {"FI", "FINLAND", "Финляндия"},
    {"US", "UNITED STATES", "США"},         {"GB", "UNITED KINGDOM", "Великобритания"},
    {"FR", "FRANCE", "Франция"},            {"SE", "SWEDEN", "Швеция"},
    {"LV", "LATVIA", "Латвия"},             {"LT", "LITHUANIA", "Литва"},
    {"TR", "TURKEY", "Турция"},             {"SG", "SINGAPORE", "Сингапур"},
    {"JP", "JAPAN", "Япония"},              {"CN", "CHINA", "Китай"},
    {"AE", "UAE", "ОАЭ"},                   {"UA", "UKRAINE", "Украина"},
    {"KZ", "KAZAKHSTAN", "Казахстан"},      {"PL", "POLAND", "Польша"},
    {"EE", "ESTONIA", "Эстония"},           {"CZ", "CZECHIA", "Чехия"},
    {"CA", "CANADA", "Канада"},             {"IN", "INDIA", "Индия"},
    {"HK", "HONG KONG", "Гонконг"},         {"KR", "SOUTH KOREA", "Южная Корея"},
    {"BY", "BELARUS", "Беларусь"},          {"MD", "MOLDOVA", "Молдова"},
    {"CH", "SWITZERLAND", "Швейцария"},     {"IT", "ITALY", "Италия"},
    {"ES", "SPAIN", "Испания"},             {"RO", "ROMANIA", "Румыния"},
    {"BG", "BULGARIA", "Болгария"},         {"AT", "AUSTRIA", "Австрия"},
};
static const CountryNames* findCountry(const std::string& cc) {
    for (const auto& c : kCountries)
        if (cc == c.cc) return &c;
    return nullptr;
}

std::string regionName(const std::string& cc) {
    if (cc.empty() || cc == "-") return "-";
    const CountryNames* c = findCountry(cc);
    return c ? c->en : cc;
}

std::string countryNameRu(const std::string& cc) {
    const CountryNames* c = findCountry(cc);
    return c ? c->ru : cc;
}

// tcpdump-вывод в txt разбит «дырами» из множества пробелов, которые рвут
// числа (seq 135810<...пробелы...>9:1359521 == 1358109:1359521).
// Убираем ТОЛЬКО длинные прогоны пробелов (>=2). Одиночные пробелы —
// настоящие разделители — сохраняем.
std::string fixPad(const std::string& s) {
    std::string o; o.reserve(s.size());
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] == ' ' || s[i] == '\t') {
            size_t j = i;
            while (j < s.size() && (s[j] == ' ' || s[j] == '\t')) j++;
            if (j - i < 2) o += ' ';
            i = j;
        } else o += s[i++];
    }
    return o;
}

// Диалог выбора файлов дампа (если программу запустили без аргумента).
// Множественный выбор разрешён: трафик часто пишут двумя файлами —
// «..._in» (только входящие) и «..._out» (только исходящие), и анализировать
// их нужно вместе, иначе картина заведомо неверная.
// Возвращает список путей; пустой список = пользователь отменил.
// owner — окно-владелец диалога (GUI) или nullptr (консоль).
#ifndef _WIN32
extern char** environ;

std::string asQuote(const std::string& s) {
    std::string r = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') r += '\\';
        r += c;
    }
    return r + "\"";
}

std::string shQuote(const std::string& s) {
    std::string r = "'";
    for (char c : s) {
        if (c == '\'') r += "'\\''";
        else r += c;
    }
    return r + "'";
}

std::string macOsascript(const std::string& script, int* exitCode) {
    if (exitCode) *exitCode = -1;
    int fd[2];
    if (pipe(fd) != 0) return "";
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, fd[1], 1);
    posix_spawn_file_actions_addclose(&fa, fd[0]);
    posix_spawn_file_actions_addclose(&fa, fd[1]);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    const char* argv[] = { "/usr/bin/osascript", "-e", script.c_str(), nullptr };
    pid_t pid = 0;
    const int rc = posix_spawn(&pid, argv[0], &fa, nullptr, (char* const*)argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(fd[1]);
    std::string out;
    if (rc == 0) {
        char buf[4096];
        ssize_t n;
        while ((n = read(fd[0], buf, sizeof(buf))) > 0 || (n < 0 && errno == EINTR))
            if (n > 0) out.append(buf, (size_t)n);
        int st = 0;
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
        if (exitCode) *exitCode = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    }
    close(fd[0]);
    return out;
}

// macOS: системный диалог Finder (AppleScript «choose file»).
// Отмена — osascript завершается с ошибкой и ничего не печатает.
std::vector<std::string> pickDumpFiles(HWND) {
    const std::string script =
        "activate\n"                       // диалог поверх окон, а не позади
        "set fs to choose file with prompt "
        + asQuote("Выберите дамп (можно два сразу: _in и _out)") +
        " with multiple selections allowed\n"
        "set out to \"\"\n"
        "repeat with f in fs\n"
        "set out to out & POSIX path of f & linefeed\n"
        "end repeat\n"
        "return out";
    std::vector<std::string> out;
    const std::string all = macOsascript(script);
    std::istringstream ss(all);
    std::string line;
    while (std::getline(ss, line)) {
        line = trim(line);
        if (!line.empty()) out.push_back(line);
    }
    return out;
}
#else
std::vector<std::string> pickDumpFiles(HWND owner) {
    // При OFN_ALLOWMULTISELECT буфер заполняется как "каталог\0имя1\0имя2\0\0",
    // поэтому MAX_PATH недостаточно — берём с запасом.
    std::vector<wchar_t> buf(32768, 0);
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFile = buf.data();
    ofn.nMaxFile = (DWORD)buf.size();
    ofn.lpstrFilter =
        L"Дампы трафика (*.txt;*.pcap;*.pcapng;*.cap)\0*.txt;*.pcap;*.pcapng;*.cap\0"
        L"Текстовый дамп (*.txt)\0*.txt\0"
        L"PCAP / pcapng (*.pcap;*.pcapng;*.cap)\0*.pcap;*.pcapng;*.cap\0"
        L"Все файлы (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrTitle = L"Выберите дамп (можно два сразу: _in и _out)";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER |
                OFN_ALLOWMULTISELECT | OFN_NOCHANGEDIR;

    // Диалог переводит текущий каталог процесса в папку выбранного файла, а
    // OFN_NOCHANGEDIR для GetOpenFileName, по документации, не действует —
    // возвращаем каталог сами. Иначе analyzer.ini («Перечитать» и инструменты
    // --tool, которые наследуют каталог) искался бы в папке с дампом абонента,
    // а ini из каталога запуска больше не находился.
    wchar_t cwd[MAX_PATH * 4];
    const DWORD cwdLen = GetCurrentDirectoryW((DWORD)(sizeof(cwd) / sizeof(cwd[0])), cwd);
    const BOOL picked = GetOpenFileNameW(&ofn);
    if (cwdLen > 0 && cwdLen < sizeof(cwd) / sizeof(cwd[0])) SetCurrentDirectoryW(cwd);

    std::vector<std::string> out;
    if (!picked) return out;

    auto toUtf8 = [](const wchar_t* w) {
        int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
        std::string s(len > 0 ? len - 1 : 0, '\0');
        if (len > 0) WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], len, NULL, NULL);
        return s;
    };

    // Один выбранный файл — в буфере лежит сразу полный путь. Несколько —
    // сначала каталог, затем имена, признак конца списка — пустая строка.
    const wchar_t* p = buf.data();
    std::string first = toUtf8(p);
    p += wcslen(p) + 1;
    if (*p == L'\0') { out.push_back(first); return out; }
    std::string dir = first;
    if (!dir.empty() && dir.back() != '\\' && dir.back() != '/') dir += "\\";
    while (*p) { out.push_back(dir + toUtf8(p)); p += wcslen(p) + 1; }
    return out;
}
#endif

// Выбран один файл с суффиксом _in/_out — подтягиваем парный, если он лежит
// рядом: анализировать половину дампа почти всегда ошибка.
bool addSiblingDump(std::vector<std::string>& paths) {
    if (paths.size() != 1) return false;
    std::string sib = siblingDumpPath(paths[0]);
    if (sib.empty()) return false;
    paths.push_back(sib);
    std::cout << C::BYEL << "Рядом найдена вторая половина дампа — беру оба файла."
              << C::RST << "\n";
    return true;
}

// Имя набора для заголовков: «a.pcap + b.pcap» без каталогов.
std::string dumpSetName(const std::vector<std::string>& paths) {
    std::string r;
    for (const auto& p : paths) {
        size_t sl = p.find_last_of("\\/");
        if (!r.empty()) r += " + ";
        r += (sl == std::string::npos) ? p : p.substr(sl + 1);
    }
    return r;
}

// Ответ «да» на вопрос y/n: y/Y или русская д/Д. Кириллица в UTF-8 — два
// байта, поэтому сравнивать ans[0] с 'д' нельзя (многобайтовый литерал
// никогда не равен одному char) — проверяем префикс строкой.
bool isYesAnswer(const std::string& s) {
    if (s.empty()) return false;
    if (s[0] == 'y' || s[0] == 'Y') return true;
    return s.rfind("д", 0) == 0 || s.rfind("Д", 0) == 0;   // /utf-8: литералы в UTF-8
}

// Строка, введённая в консоли, — для всех запросов вместо std::getline(std::cin, …).
// На Windows Ctrl+C обрывает ожидающий ReadConsole, CRT отдаёт конец ввода, и у
// std::cin взводятся eofbit|failbit: без clear() все следующие getline сразу
// возвращали пустую строку (окно --tool закрывалось, меню стирало отчёт).
// Состояние сбрасываем, прерванный ввод — пустая строка, как отмена.
// false — строки нет (Ctrl+C или конец ввода).
bool readLine(std::string& s) {
    s.clear();
    if (std::getline(std::cin, s)) return true;
    std::cin.clear();
    clearerr(stdin);
    return false;
}

// Спрашивает у пользователя цель диагностики: IP или домен (askTargetIp).
// Возвращает IP-строку, домен или пустую строку при отмене.
// Строгая проверка IPv4: ровно 4 октета 0..255 и ничего лишнего. Вручную, без
// sscanf: "%d" пропускал «+1.2.3.4», « 1.2.3.4» и «01.2.3.4» (ведущий ноль
// ping и часть утилит читают как восьмеричное — адрес был бы другим).
bool isValidIpv4Str(const std::string& str) {
    const char* s = str.c_str();
    for (int k = 0; k < 4; k++) {
        if (!isdigit((unsigned char)*s)) return false;
        if (*s == '0' && isdigit((unsigned char)s[1])) return false;
        int v = 0, nd = 0;
        while (isdigit((unsigned char)*s)) {
            if (++nd > 3) return false;
            v = v * 10 + (*s++ - '0');
        }
        if (v > 255) return false;
        if (k < 3) { if (*s != '.') return false; s++; }
    }
    return *s == '\0';
}
// Похоже ли на доменное имя: есть точка, только допустимые символы, TLD >=2 букв.
bool looksLikeDomainStr(const std::string& str) {
    if (str.size() < 4) return false;
    if (str.find('.') == std::string::npos) return false;
    bool hasAlpha = false;
    for (char ch : str) {
        if (!(isalnum((unsigned char)ch) || ch=='.' || ch=='-' || ch=='_')) return false;
        if (isalpha((unsigned char)ch)) hasAlpha = true;
    }
    size_t dot = str.rfind('.');
    std::string tld = str.substr(dot+1);
    if (tld.size() < 2) return false;
    for (char ch : tld) if (!isalpha((unsigned char)ch)) return false;
    return hasAlpha;
}

std::string askTargetIp() {
    std::cout << "\nУкажите цель для диагностики (IP или домен).\n"
              << "Пример: 31.56.27.51   или   youtube.com\n"
              << "Цель: " << std::flush;
    std::string s;
    readLine(s);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\r' || s.back() == '\n')) s.pop_back();
    while (!s.empty() && (s.front() == ' '))  s.erase(s.begin());
    if (s.empty()) return "";

    if (isValidIpv4Str(s)) return s;            // корректный IPv4

    // IPv6 (можно в квадратных скобках). Приводим к канонической сжатой
    // форме — в ней же адреса лежат в пакетах (и у tcpdump, и из pcap),
    // иначе «2A00:0:0::1» не совпал бы с «2a00::1».
    if (s.find(':') != std::string::npos) {
        std::string t = s;
        if (t.size() > 2 && t.front() == '[' && t.back() == ']') t = t.substr(1, t.size() - 2);
        unsigned char a6[16];
        char norm[INET6_ADDRSTRLEN] = {0};
        if (inet_pton(AF_INET6, t.c_str(), a6) == 1 &&
            inet_ntop(AF_INET6, a6, norm, sizeof(norm)))
            return norm;
    }

    if (!looksLikeDomainStr(s)) {               // ни IP, ни домен
        std::cout << "Это не похоже на IP-адрес или доменное имя — пропускаю фильтр.\n";
        return "";
    }
    // домен — как есть: все его адреса режим 2 ищет в самом дампе (targetAddrs
    // в report.cpp), а не берёт один IPv4 от резолвера этого ПК
    return s;
}

// ------------------------------------------------------------------
// РЕЖИМ 10: сравнение двух уже загруженных наборов («было / стало»).
// Общий для консоли и GUI. У каждого набора свой локальный адрес, а детекторы
// опираются на g_localIp — поэтому переключаем его перед каждой сводкой.
// ------------------------------------------------------------------
void compareDumpSets(const DumpRef& a, const DumpRef& b) {
    if (!a.paths || !a.packets || !b.paths || !b.packets) return;
    openReport(b.paths->empty() ? std::string() : b.paths->front(), "compare");

    // публичные адреса обоих дампов резолвим одним заходом (ASN/хостинг нужны
    // детекторам Reality и потоковых признаков VPN)
    std::unordered_map<std::string, IpInfo> ipCache;
    {
        // свои адреса абонента из ОБОИХ дампов не шлём: белый IP из дампа A
        // иначе уходил в геосервисы, встретившись в дампе B как «чужой»
        std::set<std::string> own;
        for (const std::string* ip : { &a.localIp, &a.localIp6, &b.localIp, &b.localIp6 })
            if (!ip->empty()) own.insert(*ip);
        std::set<std::string> pub;
        for (const auto* pk : { a.packets, b.packets })
            for (const auto& p : *pk) for (const std::string* ip : { &p.srcIp, &p.dstIp })
                if (!ip->empty() && !isPrivateIp(*ip) && !own.count(*ip)) pub.insert(*ip);
        std::vector<std::string> ipList(pub.begin(), pub.end());
        if (!ipList.empty()) {
            std::cout << "Резолвлю " << ipList.size() << " адрес(ов) (ASN/флаги)...\n";
            resolveIps(ipList, ipCache);
            resolveHostingSecondary(ipCache, ipList);
        }
    }

    g_localIp = a.localIp; g_localIp6 = a.localIp6;
    DumpSummary sa = summarizeDump(*a.packets, dumpSetName(*a.paths), &ipCache);
    g_localIp = b.localIp; g_localIp6 = b.localIp6;
    DumpSummary sb = summarizeDump(*b.packets, dumpSetName(*b.paths), &ipCache);
    printDumpCompare(sa, sb, ipCache);
    fflush(stdout);
    closeReport();
}

// Выбор и загрузка одного набора (файл или пара _in/_out) для сравнения.
static bool pickAndLoadForCompare(const char* label, std::vector<std::string>& paths,
                                  std::vector<Packet>& packets) {
    std::cout << "Выберите дамп " << C::BWHT << label << C::RST << " в диалоге...\n";
    paths = pickDumpFiles(nullptr);
    if (paths.empty()) { std::cout << "Файл не выбран.\n"; return false; }
    addSiblingDump(paths);
    std::vector<int> origin;
    return loadDumpSet(paths, packets, origin);
}

static void runCompareMode() {
    std::vector<std::string> pathsA, pathsB;
    std::vector<Packet> pa, pb;
    std::cout << C::GRY << "A — «как было» (эталон), B — «как стало» (проверяемый)."
              << C::RST << "\n\n";
    if (!pickAndLoadForCompare("A", pathsA, pa)) return;
    DumpRef ra{ &pathsA, &pa, g_localIp, g_localIp6 };
    std::cout << "\n";
    if (!pickAndLoadForCompare("B", pathsB, pb)) return;
    DumpRef rb{ &pathsB, &pb, g_localIp, g_localIp6 };
    compareDumpSets(ra, rb);
}

// ------------------------------------------------------------------
// консоль
// ------------------------------------------------------------------
// Программа собрана как оконная (SubSystem Windows, чтобы GUI запускался без
// мигающей консоли), поэтому своей консоли у процесса нет. Для --console и
// инструментов создаём её и подключаем к ней stdin/stdout/stderr.
#ifndef _WIN32
static void attachConsole() {}   // macOS: запускаемся из Терминала, консоль уже есть

static void initConsoleIo() {
    static char g_stdoutBuf[256 * 1024];
    setvbuf(stdout, g_stdoutBuf, _IOFBF, sizeof(g_stdoutBuf));
    std::ios::sync_with_stdio(true);
    std::cout.tie(nullptr);
    // Ctrl+C только прерывает трассировку/захват; SA_RESTART — чтобы getline
    // и прочие блокирующие вызовы не обрывались с EINTR
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigintHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, nullptr);
}
#else
static void attachConsole() {
    if (!GetConsoleWindow()) AllocConsole();
    SetConsoleTitleW(L"TrafficAnalyzer");
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$", "r", stdin);
    std::cout.clear(); std::cerr.clear(); std::cin.clear();
}

static void initConsoleIo() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    enableAnsiColors();
    enlargeScrollback();

    // Большой буфер stdout ускоряет вывод в разы: без него КАЖДЫЙ printf делает
    // отдельный WriteFile в консоль (при CP_UTF8 + ANSI цветах это очень
    // медленно на Win10). 256 КБ хватает на весь отчёт средней длины —
    // будет один-два флаша вместо тысяч.
    static char g_stdoutBuf[256 * 1024];
    setvbuf(stdout, g_stdoutBuf, _IOFBF, sizeof(g_stdoutBuf));
    // std::cout и stdout — разные буферы. Синхронизируем и отвязываем cout от
    // cerr, чтобы cout не флашился на каждой строчке. Без синхронизации у нас
    // могут «мешаться» порядки вывода printf() и std::cout << ....
    std::ios::sync_with_stdio(true);
    std::cout.tie(nullptr);

    // глобально перехватываем Ctrl+C на весь срок работы — он никогда не закрывает
    // программу, только прерывает текущую трассировку (см. ctrlHandler).
    SetConsoleCtrlHandler(ctrlHandler, TRUE);
}
#endif

// Клавиша в меню без ожидания Enter: символ, KEY_TOGGLE_LOG или KEY_NONE
// (за ~30 мс ничего не нажато). Delete переключает запись отчёта.
enum { KEY_NONE = 0, KEY_TOGGLE_LOG = -2 };
#ifdef _WIN32
// conio и так читает без буферизации строки; конструктор — чтобы MSVC не
// ругался (C4101) на «неиспользуемую» переменную RawTerm в меню
struct RawTerm { RawTerm() {} };
static int menuKey() {
    if (!_kbhit()) { Sleep(30); return KEY_NONE; }
    int ch = _getch();
    if (ch == 0 || ch == 0xE0)                 // префикс расширенной клавиши
        return _getch() == 0x53 ? KEY_TOGGLE_LOG : KEY_NONE;   // 0x53 = Delete
    return ch;
}
#define LOG_KEY_HINT "Delete"
#else
// Терминал без построчной буферизации и эха — на время ожидания выбора в меню
struct RawTerm {
    termios old{};
    bool ok = false;
    RawTerm() {
        if (tcgetattr(0, &old) != 0) return;
        termios t = old;
        t.c_lflag &= ~(ICANON | ECHO);
        t.c_cc[VMIN] = 1; t.c_cc[VTIME] = 0;
        ok = tcsetattr(0, TCSANOW, &t) == 0;
    }
    ~RawTerm() { if (ok) tcsetattr(0, TCSANOW, &old); }
};
static bool stdinReady(int ms) {
    pollfd p{0, POLLIN, 0};
    return poll(&p, 1, ms) > 0;
}
static int menuKey() {
    if (!stdinReady(30)) return KEY_NONE;
    unsigned char c;
    if (read(0, &c, 1) != 1) { Sleep(30); return KEY_NONE; }
    if (c == 0x1b) {                        // ESC [ 3 ~ — Forward Delete (fn+Delete)
        unsigned char seq[3]; int n = 0;
        while (n < 3 && stdinReady(20) && read(0, &seq[n], 1) == 1) n++;
        return (n == 3 && seq[0] == '[' && seq[1] == '3' && seq[2] == '~')
            ? KEY_TOGGLE_LOG : KEY_NONE;
    }
    if (c == 'l' || c == 'L') return KEY_TOGGLE_LOG;   // на Mac отдельной Delete нет
    if (c == 0x7f) return 8;                // клавиша delete на Mac = Backspace
    return c;
}
#define LOG_KEY_HINT "L"
#endif

static void waitEnter(const char* msg) {
    std::cout << "\n" << C::GRY << msg << C::RST;
    std::cout.flush(); fflush(stdout);
    std::string dummy;
    // Ctrl+C обрывает ожидание (см. readLine) — ждём Enter дальше. Флаг ставит
    // обработчик в своём потоке, иногда чуть позже, чем вернулся ввод
    while (!readLine(dummy)) {
        Sleep(50);
        if (!g_traceAbort) break;      // настоящий конец ввода — не ждём вечно
        g_traceAbort = false;
    }
}

// Режимы 3..13 — интерактивные инструменты: цель и параметры спрашивают сами.
// Зовутся из меню консоли и как отдельный процесс из GUI (--tool N).
static void runToolMode(int mode) {
    switch (mode) {
    case 3:
        std::cout << "\n" << C::BMAG << ">>> Режим: трассировка маршрута" << C::RST << "\n\n";
        runTraceMode();
        closeReport();
        break;
    case 4:
        std::cout << "\n" << C::BCYN << ">>> Режим: проверка гео по RTT" << C::RST << "\n\n";
        runGeoRttMode();
        closeReport();
        break;
    case 5:
        std::cout << "\n" << C::BGRN << ">>> Режим: захват трафика в .pcap" << C::RST << "\n\n";
        runCaptureMode();
        break;
    case 6:
        std::cout << "\n" << C::BYEL << ">>> Режим: проверка порта извне" << C::RST << "\n\n";
        runPortCheckMode();
        break;
    case 7:
        std::cout << "\n" << C::BMAG << ">>> Режим: скан TCP-портов" << C::RST << "\n\n";
        runPortScanMode();
        break;
    case 8:
        std::cout << "\n" << C::BMAG << ">>> Режим: UDP handshake-пробы" << C::RST << "\n\n";
        runUdpProbeMode();
        break;
    case 9:
        std::cout << "\n" << C::BMAG << ">>> Режим: TSPU DPI Locator" << C::RST << "\n\n";
        runDpiLocatorMode();
        break;
    case 10:
        std::cout << "\n" << C::BCYN << ">>> Режим: сравнение двух дампов" << C::RST << "\n\n";
        runCompareMode();
        break;
    case 11:
        std::cout << "\n" << C::BCYN << ">>> Режим: честность DNS" << C::RST << "\n\n";
        runDnsHonestyMode();
        break;
    case 12:
        std::cout << "\n" << C::BYEL << ">>> Режим: тест «16 КБ» по хостингам" << C::RST << "\n\n";
        runTcp16Mode();
        break;
    case 13:
        std::cout << "\n" << C::BCYN << ">>> Режим: кому принадлежит IP / домен" << C::RST << "\n\n";
        runIpOwnerMode();
        break;
    default: break;
    }
}

// Консольный режим: меню -> анализ -> обратно в меню. files — дампы из
// командной строки (для первого запуска режима 1/2), tool — сразу выполнить
// один инструмент и выйти (так GUI запускает интерактивные режимы).
static int consoleMain(std::vector<std::string> files, int tool) {
    attachConsole();
    initConsoleIo();

    // настройки: analyzer.ini + переменные окружения (см. config.h)
    loadConfig();
    if (!cfg().warnings.empty()) {
        printf("%sОшибки в %s:%s\n", C::YEL,
               cfg().loadedFrom.empty() ? "analyzer.ini" : cfg().loadedFrom.c_str(), C::RST);
        for (const auto& w : cfg().warnings) printf("  %s\n", w.c_str());
        printf("Для этих строк оставлены значения по умолчанию.\n");
        if (!tool) {
            // меню сразу очищает экран — без паузы предупреждения никто не увидит
            printf("Enter — продолжить...");
            fflush(stdout);
            std::string dummy; readLine(dummy);
        }
    }

    if (tool) {
        g_traceAbort = false;
        runToolMode(tool);
        closeReport();
        waitEnter("Готово. Нажмите Enter, чтобы закрыть окно...");
        return 0;
    }

    // ---- главный цикл: меню -> анализ -> обратно в меню ----
    while (true) {
    fflush(stdout);
    clearScreen(); // очищаем экран при каждом возврате в меню (без system())
    int mode = 0;
    g_traceAbort = false; // сбрасываем флаг прерывания при возврате в меню

    // ---- цветной баннер ----
    const int BOXW = 54; // внутренняя ширина бокса (видимых символов)
    // считает «видимую» ширину UTF-8 строки (кодовые точки, не байты),
    // пропуская ANSI-escape последовательности
    auto visWidth = [](const std::string& s) -> int {
        int w = 0;
        for (size_t i = 0; i < s.size(); ) {
            unsigned char c = (unsigned char)s[i];
            if (c == 0x1b) { while (i < s.size() && s[i] != 'm') i++; if (i<s.size()) i++; continue; }
            if (c < 0x80) i += 1;
            else if ((c >> 5) == 0x6) i += 2;
            else if ((c >> 4) == 0xE) i += 3;
            else if ((c >> 3) == 0x1E) i += 4;
            else i += 1;
            w++;
        }
        return w;
    };
    // печатает строку внутри рамки: "  ║" + content + добивка пробелами + "║"
    // content может содержать ANSI-цвета — они не учитываются в ширине
    auto boxLine = [&](const std::string& content) {
        int vis = visWidth(content);
        int pad = BOXW - vis; if (pad < 0) pad = 0;
        std::cout << C::BCYN << "  ║" << C::RST << content
                  << std::string(pad, ' ')
                  << C::BCYN << "║" << C::RST << "\n";
    };

    std::cout << "\n";
    std::cout << C::BCYN << "  T R A F F I C   A N A L Y Z E R   U T I L" << C::RST << "\n";
    std::cout << "\n";
    std::cout << C::BCYN << "  ╔"; for(int i=0;i<BOXW;i++) std::cout << "═"; std::cout << "╗" << C::RST << "\n";
    boxLine(std::string(C::BWHT) + "             В Ы Б Е Р И Т Е   Р Е Ж И М");
    std::cout << C::BCYN << "  ╠"; for(int i=0;i<BOXW;i++) std::cout << "═"; std::cout << "╣" << C::RST << "\n";
    boxLine("");
    boxLine(std::string("  ") + C::BMAG + "[1]" + C::BWHT + " Анализ на VPN / прокси");
    boxLine(std::string("  ") + C::BMAG + "[2]" + C::BWHT + " Анализ на блокировки и проблемы соединения");
    boxLine(std::string("      ") + C::GRY + "(1 и 2: можно выбрать пару файлов «..._in» и «..._out»)");
    boxLine(std::string("  ") + C::BMAG + "[3]" + C::BWHT + " Трассировка маршрута (trace) до IP / домена");
    boxLine(std::string("  ") + C::BMAG + "[4]" + C::BWHT + " Проверка гео по RTT (детект подмены локации)");
    boxLine(std::string("  ") + C::BMAG + "[5]" + C::BWHT + " Захват трафика с интерфейса в .pcap (Npcap)");
    boxLine(std::string("  ") + C::BMAG + "[6]" + C::BWHT + " Проверка порта извне (TCP с зондов Globalping)");
    boxLine(std::string("  ") + C::BMAG + "[7]" + C::BWHT + " Скан TCP-портов (с нашей машины)");
    boxLine(std::string("  ") + C::BMAG + "[8]" + C::BWHT + " UDP handshake-пробы (VPN-протоколы)");
    boxLine(std::string("  ") + C::BMAG + "[9]" + C::BWHT + " TSPU DPI Locator (поиск хопа блокировки по SNI)");
    boxLine(std::string("  ") + C::BMAG + "[0]" + C::BWHT + " Сравнение двух дампов (было / стало)");
    boxLine(std::string(" ") + C::BMAG + "[11]" + C::BWHT + " Честность DNS (заглушки, подмена, перехват)");
    boxLine(std::string(" ") + C::BMAG + "[12]" + C::BWHT + " Тест «16 КБ» по зарубежным хостингам");
    boxLine(std::string(" ") + C::BMAG + "[13]" + C::BWHT + " Кому принадлежит IP / домен, ответы DNS");
    boxLine("");
    // строка статуса лога (галочка). Фиолетовая галочка = запись включена.
    {
        std::string mark = g_logEnabled
            ? std::string(C::BMAG) + "[✓]" + C::GRY  // [✓]
            : std::string(C::GRY)  + "[ ]";
        boxLine(std::string("  ") + mark + C::GRY + " LOG  (" LOG_KEY_HINT " — вкл/выкл запись отчёта)" );
    }
    std::cout << C::BCYN << "  ╚"; for(int i=0;i<BOXW;i++) std::cout << "═"; std::cout << "╝" << C::RST << "\n";
    std::cout << "\n  " << C::GRY << "> " << C::RST << std::flush;
    // Ввод: номер (1-2 цифры) набирается и подтверждается ENTER. Delete переключает лог
    // мгновенно (через _getch ловим расширенную клавишу, не дожидаясь Enter).
    std::string typed;
    {
    RawTerm raw;
    while (mode == 0) {
        int ch = menuKey();
        if (ch != KEY_NONE) {
            if (ch == KEY_TOGGLE_LOG) {         // Delete — переключаем лог и перерисовываем меню
                g_logEnabled = !g_logEnabled;
                break;
            }
            if (ch == '\r' || ch == '\n') {     // Enter — подтверждаем выбор
                if (!typed.empty()) {
                    int v = atoi(typed.c_str());
                    if (v == 0) v = 10;             // «0» — режим 10 (сравнение дампов)
                    if (v >= 1 && v <= 13) { mode = v; }
                    else { typed.clear(); printf("\n  %sВведите 0-13 и Enter:%s ", C::YEL, C::RST); }
                }
            } else if (ch >= '0' && ch <= '9') {
                if (typed.size() < 2) {             // номер до двух цифр (11..13)
                    typed += (char)ch;
                    printf("%c", ch); fflush(stdout);   // эхо ввода
                }
            } else if (ch == 8 && !typed.empty()) { // Backspace
                typed.pop_back(); printf("\b \b"); fflush(stdout);
            }
        }
    }
    }   // RawTerm: терминал возвращается в обычный режим
    if (mode == 0) continue; // была нажата Delete — перерисовываем меню
    if (mode >= 3) {
        runToolMode(mode);
        waitEnter("Нажмите Enter для возврата в меню...");
        continue;
    }
    std::cout << "\n" << (mode == 1 ? C::BGRN : C::BYEL) << ">>> Режим: "
              << (mode == 1 ? "анализ на VPN/прокси"
                            : "анализ на блокировки/проблемы соединения")
              << C::RST << "\n\n";

    // Дамп может состоять из ДВУХ файлов: «..._in» (только входящие соединения)
    // и «..._out» (только исходящие). Каждый по отдельности даёт заведомо ложную
    // картину — во «_out» все SYN окажутся без ответов, во «_in» все SYN-ACK
    // без запросов. Поэтому такие половины загружаем вместе и сливаем в один
    // поток пакетов, а анализ работает уже по объединённому дампу.
    std::vector<std::string> paths;
    if (!files.empty()) {
        paths.swap(files);   // первый раз берём из командной строки, дальше — диалог
    } else {
        std::cout << "Откройте файл дампа в диалоге выбора...\n";
        std::cout << C::GRY << "  (можно выделить сразу два файла — «..._in» и «..._out»)"
                  << C::RST << "\n";
        paths = pickDumpFiles(nullptr);
        if (paths.empty()) {
            std::cout << "Файл не выбран — возврат в меню.\n";
            continue;
        }
    }
    addSiblingDump(paths);

    // --- загрузка, слияние половин, определение локального адреса ---
    std::vector<Packet> packets;
    std::vector<int> origin;          // из какого файла пришёл каждый пакет
    if (!loadDumpSet(paths, packets, origin)) {
        waitEnter("Нажмите Enter для возврата в меню...");
        continue;
    }

    // --- файл-отчёт рядом с дампом (если запись лога включена) ---
    // Открываем после загрузки: иначе при нечитаемом дампе рядом оставался
    // пустой отчёт (loadDumpSet пишет только в консоль, в отчёт ничего не теряется).
    if (g_logEnabled) openReport(paths[0], "report");
    else std::cout << "(запись отчёта выключена — Delete в меню включает)\n";

    if (mode == 2) runConnAnalysis(packets, paths);   // блокировки / проблемы соединения
    else           runVpnAnalysis(packets, paths);    // VPN / прокси
    if (g_report) { closeReport(); std::cout << "Отчёт сохранён.\n"; }
    waitEnter("Нажмите Enter для возврата в меню...");
    } // end while(true)
    return 0;
}

// Пакетный режим (--batch 1|2): анализ без меню и вопросов — для прогона
// тестовых дампов скриптом. Весь вывод (printf и std::cout) — в stdout или в
// файл --out; консольное окно не открывается.
static int batchMain(int mode, std::vector<std::string> paths, const std::string& outPath) {
    if (!outPath.empty()) {
        FILE* f = nullptr;
#ifdef _WIN32
        if (_wfreopen_s(&f, u8w(outPath).c_str(), L"wb", stdout) != 0) f = nullptr;
#else
        f = freopen(outPath.c_str(), "wb", stdout);
#endif
        if (!f) return 3;
    }
    std::ios::sync_with_stdio(true);
    std::cout.clear();
    loadConfig();
    for (const auto& w : cfg().warnings) printf("analyzer.ini: %s\n", w.c_str());
    if (paths.empty()) { printf("--batch: не указан дамп\n"); return 2; }
    addSiblingDump(paths);
    std::vector<Packet> packets;
    std::vector<int> origin;
    int rc = 1;
    if (loadDumpSet(paths, packets, origin)) {
        if (mode == 2) runConnAnalysis(packets, paths);
        else           runVpnAnalysis(packets, paths);
        rc = 0;
    }
    std::cout.flush(); fflush(stdout);
    return rc;
}

// Аргументы командной строки в UTF-8 (argv у main — в ANSI-кодировке, и
// путь с кириллицей в нём ломается).
// На macOS argv уже в UTF-8.
static std::vector<std::string> commandLineUtf8(int argc, char** argv) {
    std::vector<std::string> out;
#ifdef _WIN32
    (void)argc; (void)argv;
    int n = 0;
    LPWSTR* w = CommandLineToArgvW(GetCommandLineW(), &n);
    if (!w) return out;
    for (int i = 0; i < n; i++) out.push_back(w2u8(w[i]));
    LocalFree(w);
#else
    for (int i = 0; i < argc; i++) out.push_back(argv[i]);
#endif
    return out;
}

// Фатальная ошибка GUI-режима: на Windows окно-сообщение, на macOS — stderr
static void fatalGuiMessage(const std::string& text) {
#ifdef _WIN32
    MessageBoxW(nullptr, u8w(text).c_str(), L"TrafficAnalyzer", MB_ICONERROR);
#else
    fprintf(stderr, "TrafficAnalyzer: %s\n", text.c_str());
#endif
}

// Запуск:
//   TrafficAnalyzer.exe [дамп ...]          — окно (GUI), дампы сразу загружаются
//   TrafficAnalyzer.exe --console [дамп]    — прежнее консольное меню
//   TrafficAnalyzer.exe --tool N [--log]    — один интерактивный режим N (3..13, 0)
//                                             в своей консоли; так его запускает GUI
//   TrafficAnalyzer.exe --batch 1|2 [--out файл] дамп ...
//                                           — анализ 1/2 без меню, вывод в stdout/файл
// Обёртки try/catch не дают окну «просто закрыться» без объяснения, если где-то
// всплыло std::bad_alloc / std::out_of_range.
int main(int argc, char** argv) {
#ifndef _WIN32
    // запись в закрытый сокет не должна убивать процесс (на Windows SIGPIPE нет)
    signal(SIGPIPE, SIG_IGN);
#endif
    std::vector<std::string> args = commandLineUtf8(argc, argv);
    bool consoleMode = false;
    int tool = 0, batch = 0;
    std::string batchOut;
    std::vector<std::string> files;
    for (size_t i = 1; i < args.size(); i++) {
        const std::string& a = args[i];
        if (a == "--console") consoleMode = true;
        else if (a == "--batch" && i + 1 < args.size()) batch = atoi(args[++i].c_str()) == 2 ? 2 : 1;
        else if (a == "--out" && i + 1 < args.size()) batchOut = args[++i];
        else if (a == "--gui") {}
        else if (a == "--log") g_logEnabled = true;
        else if (a.rfind("-psn_", 0) == 0) {}            // macOS Finder: номер процесса
        else if (a == "--tool" && i + 1 < args.size()) {
            const std::string& t = args[++i];
            const bool digits = !t.empty() && t.size() <= 2 &&
                                t.find_first_not_of("0123456789") == std::string::npos;
            tool = digits ? atoi(t.c_str()) : -1;        // не число — в меню
            if (tool == 0) tool = 10;                    // «0» — сравнение, как в меню
            if (tool < 3 || tool > 13) tool = 0;
            consoleMode = true;
        } else files.push_back(a);
    }

    if (batch) {
        try { return batchMain(batch, files, batchOut); }
        catch (const std::exception& e) { printf("[FATAL] %s\n", e.what()); fflush(stdout); return 1; }
        catch (...) { printf("[FATAL] неизвестная ошибка\n"); fflush(stdout); return 2; }
    }

    if (!consoleMode) {
        try {
            loadConfig();
            return RunGuiMain(files);
        } catch (const std::exception& e) {
            fatalGuiMessage(std::string("Необработанное исключение:\n") + e.what());
            return 1;
        } catch (...) {
            fatalGuiMessage("Неизвестная фатальная ошибка.");
            return 2;
        }
    }

    try { return consoleMain(files, tool); }
    catch (const std::exception& e) {
        fflush(stdout);
        fprintf(stderr, "\n[FATAL] Необработанное исключение: %s\n", e.what());
        fprintf(stderr, "Нажмите Enter для выхода...\n");
        std::cout.flush(); fflush(stdout); std::cin.get();
        return 1;
    } catch (...) {
        fflush(stdout);
        fprintf(stderr, "\n[FATAL] Неизвестная фатальная ошибка.\n");
        fprintf(stderr, "Нажмите Enter для выхода...\n");
        std::cout.flush(); fflush(stdout); std::cin.get();
        return 2;
    }
}
