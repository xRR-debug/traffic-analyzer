// capture.cpp — режим 5: захват трафика через Npcap в .pcap.
#include "common.h"

// ------------------------------------------------------------------
// РЕЖИМ 5: захват трафика с сетевого интерфейса в .pcap-файл (Npcap).
// Требует Npcap SDK при сборке (макрос HAVE_NPCAP) и установленный драйвер
// Npcap на машине запуска, плюс права администратора.
// Захваченный файл потом анализируется режимами 1/2.
// Останавливается по Ctrl+C (используем g_traceAbort).
// ------------------------------------------------------------------
#ifdef HAVE_NPCAP
#include <pcap.h>
#ifndef _WIN32
// macOS: libpcap системный, захват через /dev/bpf* — нужен root (sudo) или
// доступ к BPF-устройствам (ChmodBPF, ставится вместе с Wireshark).
static const char* kCapturePermHint =
    "Запустите через sudo или установите Wireshark (пакет ChmodBPF даёт доступ к /dev/bpf*).";
#else
static const char* kCapturePermHint =
    "Проверьте, что Npcap установлен и программа запущена от администратора.";
#endif
void runCaptureMode() {
#ifdef _WIN32
    // при delay-load wpcap.dll грузится только сейчас. Если Npcap не установлен,
    // DLL не найдётся — проверяем заранее, чтобы не уронить программу.
    // Npcap кладёт wpcap.dll в System32\Npcap (в System32 — только в режиме
    // совместимости с WinPcap). Грузим по полному пути и НЕ выгружаем: delay-load
    // возьмёт уже загруженный модуль по имени и не пойдёт искать DLL в каталоге
    // exe / текущем каталоге (подмена DLL в процессе с правами администратора).
    HMODULE hWpcap = nullptr;
    {
        wchar_t sysDir[MAX_PATH] = {0};
        UINT n = GetSystemDirectoryW(sysDir, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            std::wstring npcapDir = std::wstring(sysDir) + L"\\Npcap";
            SetDllDirectoryW(npcapDir.c_str());   // Packet.dll wpcap подгружает оттуда же
            hWpcap = LoadLibraryW((npcapDir + L"\\wpcap.dll").c_str());
            if (!hWpcap) hWpcap = LoadLibraryW((std::wstring(sysDir) + L"\\wpcap.dll").c_str());
        }
    }
    if (!hWpcap) {
        printf("%sNpcap не установлен (wpcap.dll не найдена).%s\n\n", C::RED, C::RST);
        printf("Захват трафика требует драйвер Npcap.\n");
        // Установщик (ресурс NPCAP_INSTALLER) вшит, только если при сборке лежал в
        // redist\ (npcap.rc). В релизах из CI его нет: лицензия Npcap не разрешает
        // распространять установщик — тогда отправляем на npcap.com.
        // RT_RCDATA в Unicode-сборке — wchar_t*, поэтому для ...A берём MAKEINTRESOURCEA(10).
        HRSRC hRes = FindResourceA(nullptr, "NPCAP_INSTALLER", MAKEINTRESOURCEA(10));
        if (!hRes) {
            printf("Скачайте установщик с https://npcap.com/#download («Npcap ... installer»),\n"
                   "установите его, затем снова выберите режим 5.\n\n");
            printf("Открыть страницу загрузки? (y/n): ");
            std::string ans; readLine(ans);
            if (isYesAnswer(ans))
                ShellExecuteA(nullptr, "open", "https://npcap.com/#download", nullptr, nullptr, SW_SHOWNORMAL);
            return;
        }
        printf("Установщик Npcap встроен в эту программу.\n\n");
        printf("Установить сейчас? (y/n): ");
        std::string ans; readLine(ans);
        if (!isYesAnswer(ans)) {
            printf("Отменено. Можно установить Npcap вручную с https://npcap.com\n");
            return;
        }
        // извлекаем встроенный установщик во временный файл
        HGLOBAL hData = LoadResource(nullptr, hRes);
        DWORD sz = SizeofResource(nullptr, hRes);
        void* p = LockResource(hData);
        if (!p || sz == 0) { printf("%sНе удалось прочитать установщик.%s\n", C::RED, C::RST); return; }

        char tmpDir[MAX_PATH] = {0}; GetTempPathA(MAX_PATH, tmpDir);
        std::string instPath = std::string(tmpDir) + "npcap-installer.exe";
        FILE* of = fopen(instPath.c_str(), "wb");
        if (!of) { printf("%sНе удалось создать временный файл.%s\n", C::RED, C::RST); return; }
        bool written = fwrite(p, 1, sz, of) == sz;
        if (fclose(of) != 0) written = false;
        if (!written) {
            // недописанный установщик запускать нельзя (мало места на диске и т.п.)
            printf("%sНе удалось записать установщик во временный файл.%s\n", C::RED, C::RST);
            remove(instPath.c_str());
            return;
        }

        printf("\nЗапускаю установщик Npcap (потребуется подтверждение UAC)...\n");
        printf("Пройдите установку, затем вернитесь и снова выберите режим 5.\n");
        // запуск с запросом прав администратора (UAC)
        HINSTANCE r = ShellExecuteA(nullptr, "runas", instPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        if ((INT_PTR)r <= 32)
            printf("%sНе удалось запустить установщик (код %lld). Установите вручную: "
                   "https://npcap.com%s\n", C::YEL, (long long)(INT_PTR)r, C::RST);
        return;
    }
    // hWpcap не освобождаем: delay-load pcap-функций привяжется к этому модулю
#endif

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
        printf("%sНе удалось получить список интерфейсов: %s%s\n", C::RED, errbuf, C::RST);
        printf("%s\n", kCapturePermHint);
        return;
    }

    // показываем список интерфейсов
    printf("Доступные интерфейсы:\n");
    std::vector<pcap_if_t*> devs;
    int idx = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        devs.push_back(d);
        printf("  %s[%d]%s %s\n", C::BCYN, ++idx, C::RST,
               d->description ? d->description : d->name);
        printf("       %s%s%s\n", C::GRY, d->name, C::RST);
    }
    if (devs.empty()) { printf("Интерфейсы не найдены.\n"); pcap_freealldevs(alldevs); return; }

    printf("\nВыберите интерфейс (1-%d): ", (int)devs.size());
    std::string line; readLine(line);
    int sel = atoi(line.c_str());
    if (sel < 1 || sel > (int)devs.size()) { printf("Неверный выбор.\n"); pcap_freealldevs(alldevs); return; }
    pcap_if_t* dev = devs[sel-1];

    // опциональный BPF-фильтр
    printf("Фильтр BPF (Enter — без фильтра).\n");
    printf("Можно просто номер порта (443) или IP (8.8.8.8), либо полный\n");
    printf("синтаксис: host 8.8.8.8 | udp port 51820 | tcp port 443\n");
    printf("Фильтр: ");
    std::string filter; readLine(filter);
    while (!filter.empty() && (filter.back()=='\r'||filter.back()=='\n'||filter.back()==' ')) filter.pop_back();
    while (!filter.empty() && filter.front()==' ') filter.erase(filter.begin());

    // Удобство: распознаём сокращения. Голое число -> "port N"; голый IP -> "host X".
    // BPF не понимает просто "443" или "8.8.8.8" — нужны ключевые слова.
    if (!filter.empty()) {
        bool allDigit = filter.find_first_not_of("0123456789") == std::string::npos;
        bool looksIp  = filter.find_first_not_of("0123456789.") == std::string::npos &&
                        std::count(filter.begin(), filter.end(), '.') == 3;
        if (allDigit) {
            int p = atoi(filter.c_str());
            if (p >= 1 && p <= 65535) { filter = "port " + filter;
                printf("  (фильтр развёрнут в: %s)\n", filter.c_str()); }
        } else if (looksIp) {
            filter = "host " + filter;
            printf("  (фильтр развёрнут в: %s)\n", filter.c_str());
        }
    }

    // открываем интерфейс: snaplen 65535 (полный пакет — нужно для SNI/TTL),
    // promiscuous, таймаут чтения 100мс (чтобы цикл реагировал на Ctrl+C)
    pcap_t* h = pcap_open_live(dev->name, 65535, 1, 100, errbuf);
    if (!h) {
        printf("%sНе удалось открыть интерфейс: %s%s\n", C::RED, errbuf, C::RST);
        printf("%s\n", kCapturePermHint);
        pcap_freealldevs(alldevs); return;
    }
    // проверим, что это Ethernet (наш парсер рассчитан на DLT_EN10MB и др.)
    int dlt = pcap_datalink(h);

    // применяем фильтр, если задан
    if (!filter.empty()) {
        bpf_program fp;
        bpf_u_int32 net = 0;
        if (pcap_compile(h, &fp, filter.c_str(), 1, net) == -1) {
            printf("%sОшибка в фильтре: %s%s\n", C::YEL, pcap_geterr(h), C::RST);
            printf("Продолжаю без фильтра.\n");
        } else {
            if (pcap_setfilter(h, &fp) == -1)
                printf("%sНе удалось применить фильтр: %s%s\n", C::YEL, pcap_geterr(h), C::RST);
            pcap_freecode(&fp);
        }
    }

    // имя выходного файла с датой
    time_t tt = time(nullptr); struct tm lt; localtime_s(&lt, &tt);
    char stamp[32]; strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &lt);
    std::string outPath = std::string("capture_") + stamp + ".pcap";
    std::string shownPath = outPath;        // для вывода — в UTF-8
    bool fullPath = false;                  // outPath — с папкой (shownPath), не в текущем каталоге
    // Кладём рядом с exe, а не в текущий каталог: при запуске с правами
    // администратора им часто оказывается System32. Если в папку exe писать
    // нельзя (на Windows — Program Files без прав администратора), на Windows
    // берём «Документы», затем временную папку; иначе — текущий каталог.
    // pcap_dump_open на Windows берёт путь в ANSI-кодировке — папку, которую в
    // ней не записать (символы вне кодовой страницы), пропускаем.
#ifndef _WIN32
    {   // macOS: пути в UTF-8, перекодировать нечего
        std::string dir = exeDirUtf8();
        if (!dir.empty() && access(dir.c_str(), W_OK) == 0) {
            outPath = dir + outPath;
            shownPath = outPath;
            fullPath = true;
        }
    }
#else
    {
        std::vector<std::wstring> dirs;     // кандидаты со слешем на конце
        wchar_t buf[MAX_PATH * 4];
        const DWORD cap = (DWORD)(sizeof(buf) / sizeof(buf[0]));
        DWORD n = GetModuleFileNameW(nullptr, buf, cap);
        std::wstring exe = (n > 0 && n < cap) ? std::wstring(buf, n) : L"";
        size_t slash = exe.find_last_of(L"\\/");
        if (slash != std::wstring::npos) dirs.push_back(exe.substr(0, slash + 1));
        n = GetEnvironmentVariableW(L"USERPROFILE", buf, cap);
        if (n > 0 && n < cap) dirs.push_back(std::wstring(buf, n) + L"\\Documents\\");
        n = GetTempPathW(cap, buf);
        if (n > 0 && n < cap) dirs.push_back(std::wstring(buf, n));
        for (const std::wstring& dir : dirs) {
            BOOL lossy = FALSE;
            int len = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, dir.c_str(), (int)dir.size(),
                                          nullptr, 0, nullptr, &lossy);
            if (len <= 0 || lossy) continue;
            std::string a(len, '\0');
            WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, dir.c_str(), (int)dir.size(),
                                &a[0], len, nullptr, &lossy);
            if (lossy) continue;
            // права на запись проверяем пробным файлом (удаляется при закрытии)
            HANDLE probe = CreateFileW((dir + u8w(outPath) + L".probe").c_str(), GENERIC_WRITE, 0,
                                       nullptr, CREATE_ALWAYS,
                                       FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
            if (probe == INVALID_HANDLE_VALUE) continue;
            CloseHandle(probe);
            shownPath = w2u8(dir.c_str()) + outPath;
            outPath = a + outPath;
            fullPath = true;
            break;
        }
    }
#endif

    pcap_dumper_t* dumper = pcap_dump_open(h, outPath.c_str());
    if (!dumper) {
        printf("%sНе удалось создать файл %s: %s%s\n", C::RED, shownPath.c_str(), pcap_geterr(h), C::RST);
        pcap_close(h); pcap_freealldevs(alldevs); return;
    }

    printf("\n%sЗахват идёт.%s Файл: %s%s%s\n", C::BGRN, C::RST, C::BWHT, shownPath.c_str(), C::RST);
    printf("DLT=%d (%s). %sCtrl+C — остановить и сохранить.%s\n\n",
           dlt, (dlt==1?"Ethernet":"иной"), C::GRY, C::RST);

    g_traceAbort = false;
    long long pktCount = 0, byteCount = 0;
    struct pcap_pkthdr* hdr = nullptr;
    const u_char* data = nullptr;
    while (!g_traceAbort) {
        int r = pcap_next_ex(h, &hdr, &data);
        if (r == 1) {            // пакет получен
            pcap_dump((u_char*)dumper, hdr, data);
            pktCount++; byteCount += hdr->len;
            if ((pktCount % 50) == 0) {
                printf("\r  захвачено пакетов: %s%lld%s, байт: %lld   ",
                       C::BWHT, pktCount, C::RST, byteCount);
                fflush(stdout);
            }
        } else if (r == 0) {
            continue;            // таймаут чтения — проверяем Ctrl+C и дальше
        } else {                 // ошибка или EOF
            printf("\n%sЗахват прерван: %s%s\n", C::YEL, pcap_geterr(h), C::RST);
            break;
        }
    }

    printf("\n\n%sЗахват остановлен.%s Сохранено: %s%lld пакетов, %lld байт.%s\n",
           C::BGRN, C::RST, C::BWHT, pktCount, byteCount, C::RST);

    pcap_dump_flush(dumper);
    pcap_dump_close(dumper);
    pcap_close(h);
    pcap_freealldevs(alldevs);

    // абсолютный путь для удобства
    char full[1024] = {0};
    if (fullPath)
        printf("Файл: %s%s%s\n", C::BWHT, shownPath.c_str(), C::RST);
#ifdef _WIN32
    else if (_fullpath(full, outPath.c_str(), sizeof(full)))
#else
    else if (sizeof(full) >= PATH_MAX && realpath(outPath.c_str(), full))
#endif
        printf("Файл: %s%s%s\n", C::BWHT, full, C::RST);
    printf("Теперь можно открыть этот .pcap в режиме 1 или 2 для анализа.\n");
}
#else
// сборка без Npcap SDK — режим показывает инструкцию
void runCaptureMode() {
    printf("%sРежим захвата требует сборки с Npcap SDK.%s\n\n", C::YEL, C::RST);
    printf("Чтобы включить захват:\n");
    printf("  1. Скачайте Npcap SDK: https://npcap.com/#download (раздел SDK).\n");
    printf("  2. Распакуйте в папку проекта, например: TrafficAnalyzer\\npcap-sdk\\\n");
    printf("  3. В свойствах проекта (Release|x64):\n");
    printf("     - C/C++ -> Доп. каталоги include: npcap-sdk\\Include\n");
    printf("     - Компоновщик -> Доп. каталоги библиотек: npcap-sdk\\Lib\\x64\n");
    printf("     - Компоновщик -> Доп. зависимости: wpcap.lib;Packet.lib\n");
    printf("     - C/C++ -> Препроцессор -> определения: добавьте HAVE_NPCAP\n");
    printf("  4. Установите драйвер Npcap на машине запуска: https://npcap.com\n");
    printf("     (если стоит Wireshark — Npcap уже установлен).\n");
    printf("  5. Запускайте программу ОТ АДМИНИСТРАТОРА (захват требует прав).\n");
    printf("\nПосле этого режим 5 будет писать трафик в capture_<дата>.pcap,\n");
    printf("который можно анализировать режимами 1 и 2.\n");
}
#endif
