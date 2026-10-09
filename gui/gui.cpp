// gui.cpp — интерфейс в окне (Dear ImGui): меню, панель действий, вкладки
// «Обзор», «Соединения», «Профиль соединения» (waterfall), «Проверка РКН»
// (содержимое — gui_rkn.cpp), «Журнал», «Инструменты», «Настройки», строка статуса.
// Тяжёлая работа — в фоновых задачах (gui_data.cpp), здесь только отрисовка.
// Здесь же темы оформления и анимации.
#include "gui_app.h"

#ifdef _WIN32
#pragma comment(lib, "advapi32.lib")   // реестр: выбранная тема
#else
#include <CoreFoundation/CoreFoundation.h>   // тема системы (AppleInterfaceStyle)
#endif

namespace {

enum Tab { TAB_NONE = -1, TAB_OVERVIEW = 0, TAB_FLOWS, TAB_LOG, TAB_TOOLS, TAB_SETTINGS, TAB_WATERFALL, TAB_RKN };
std::atomic<int> s_selectTab{TAB_NONE};

// цвета смыслов (заголовок / норма / внимание / плохо / второстепенное);
// меняются вместе с темой, см. setTheme()
ImVec4 kAccent(0.40f, 0.78f, 0.95f, 1);
ImVec4 kGood(0.42f, 0.85f, 0.45f, 1);
ImVec4 kWarn(0.95f, 0.80f, 0.35f, 1);
ImVec4 kBad(0.95f, 0.40f, 0.40f, 1);
ImVec4 kDim(0.58f, 0.60f, 0.64f, 1);

// ------------------------------------------------------------------
// анимация: общие помощники
// ------------------------------------------------------------------
bool s_anim = true;              // анимации включены (Вид → Анимации)
bool s_wantFrames = false;       // в этом кадре что-то анимируется — не засыпать

float clamp01(float t) { return t < 0 ? 0 : t > 1 ? 1 : t; }
float easeOut(float t) { t = clamp01(t); return 1 - (1 - t) * (1 - t) * (1 - t); }
float easeInOut(float t) { t = clamp01(t); return t * t * (3 - 2 * t); }

// Прогресс 0..1 анимации длиной dur, начатой в t0. Пока не закончилась —
// просим главный цикл рисовать кадры без пауз. Анимации выключены — сразу 1.
float animProgress(double t0, float dur) {
    if (!s_anim) return 1;
    const float t = (float)((ImGui::GetTime() - t0) / dur);
    if (t < 1) s_wantFrames = true;
    return clamp01(t);
}

ImVec4 mix(const ImVec4& a, const ImVec4& b, float t) {
    return ImVec4(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, a.z + (b.z - a.z) * t, a.w + (b.w - a.w) * t);
}
ImVec4 withA(ImVec4 c, float a) { c.w = a; return c; }
ImVec4 shade(const ImVec4& c, float d) {
    return ImVec4(clamp01(c.x + d), clamp01(c.y + d), clamp01(c.z + d), c.w);
}

// ------------------------------------------------------------------
// темы
// ------------------------------------------------------------------
struct ThemeSpec {
    const char* name;
    bool light;
    ImVec4 bg, child, popup, frame, button, text, textDim;   // поверхности
    ImVec4 accent, good, warn, bad, dim;                     // смыслы (kAccent…)
    bool wallpaper = false;      // картинка на фоне (режим «в теме Аниме»)
};

const ThemeSpec kThemes[] = {
    { "Тёмная", false,
      {0.09f, 0.10f, 0.12f, 1}, {0.11f, 0.12f, 0.14f, 1}, {0.12f, 0.13f, 0.16f, 1}, {0.16f, 0.18f, 0.21f, 1},
      {0.18f, 0.33f, 0.45f, 1}, {1.00f, 1.00f, 1.00f, 1}, {0.50f, 0.50f, 0.50f, 1},
      {0.40f, 0.78f, 0.95f, 1}, {0.42f, 0.85f, 0.45f, 1}, {0.95f, 0.80f, 0.35f, 1},
      {0.95f, 0.40f, 0.40f, 1}, {0.58f, 0.60f, 0.64f, 1} },
    { "Полночь", false,
      {0.06f, 0.07f, 0.13f, 1}, {0.08f, 0.09f, 0.17f, 1}, {0.09f, 0.10f, 0.19f, 1}, {0.13f, 0.15f, 0.27f, 1},
      {0.30f, 0.24f, 0.55f, 1}, {0.90f, 0.92f, 1.00f, 1}, {0.45f, 0.48f, 0.62f, 1},
      {0.66f, 0.58f, 1.00f, 1}, {0.40f, 0.88f, 0.70f, 1}, {1.00f, 0.78f, 0.40f, 1},
      {1.00f, 0.42f, 0.55f, 1}, {0.55f, 0.58f, 0.72f, 1} },
    { "Графит", false,
      {0.12f, 0.12f, 0.12f, 1}, {0.15f, 0.15f, 0.15f, 1}, {0.16f, 0.16f, 0.16f, 1}, {0.21f, 0.21f, 0.21f, 1},
      {0.46f, 0.28f, 0.12f, 1}, {0.93f, 0.93f, 0.93f, 1}, {0.50f, 0.50f, 0.50f, 1},
      {1.00f, 0.62f, 0.25f, 1}, {0.55f, 0.85f, 0.40f, 1}, {1.00f, 0.82f, 0.30f, 1},
      {1.00f, 0.40f, 0.35f, 1}, {0.62f, 0.62f, 0.62f, 1} },
    { "Светлая", true,
      {0.94f, 0.95f, 0.97f, 1}, {1.00f, 1.00f, 1.00f, 1}, {1.00f, 1.00f, 1.00f, 1}, {0.87f, 0.89f, 0.92f, 1},
      {0.62f, 0.79f, 0.94f, 1}, {0.10f, 0.11f, 0.13f, 1}, {0.55f, 0.56f, 0.60f, 1},
      {0.05f, 0.42f, 0.72f, 1}, {0.10f, 0.55f, 0.18f, 1}, {0.72f, 0.48f, 0.00f, 1},
      {0.80f, 0.15f, 0.15f, 1}, {0.42f, 0.44f, 0.48f, 1} },
    // ночная синева и светящийся голубой — под встроенную картинку;
    // новые темы только в конец: в реестре хранится номер
    { "Аниме", false,
      {0.035f, 0.045f, 0.12f, 1}, {0.05f, 0.065f, 0.16f, 1}, {0.06f, 0.075f, 0.18f, 1}, {0.09f, 0.12f, 0.26f, 1},
      {0.17f, 0.22f, 0.52f, 1}, {0.88f, 0.93f, 1.00f, 1}, {0.45f, 0.52f, 0.70f, 1},
      {0.45f, 0.90f, 1.00f, 1}, {0.45f, 0.95f, 0.75f, 1}, {1.00f, 0.80f, 0.45f, 1},
      {1.00f, 0.45f, 0.62f, 1}, {0.58f, 0.64f, 0.82f, 1}, true },
};
constexpr int kThemeCount = (int)(sizeof(kThemes) / sizeof(kThemes[0]));

// Полный набор цветов темы — то, что плавно перетекает при смене.
struct ThemeColors {
    ImVec4 col[ImGuiCol_COUNT];
    ImVec4 sem[5];      // kAccent, kGood, kWarn, kBad, kDim
    ImVec4 clear;       // фон под окном ImGui (виден при изменении размера)
};

int s_theme = 0;
ImVec4 s_clear(0.07f, 0.08f, 0.10f, 1);
ThemeColors s_cur;               // цвета темы как есть; в стиль ImGui — через finalizeStyle()
ThemeColors s_themeFrom, s_themeTo;
double s_themeT0 = -1;           // < 0 — переход не идёт
const float kThemeFade = 0.35f;

void buildTheme(const ThemeSpec& t, ThemeColors& out) {
    ImGuiStyle base;                            // только ради цветов по умолчанию
    if (t.light) ImGui::StyleColorsLight(&base); else ImGui::StyleColorsDark(&base);
    ImVec4* c = out.col;
    for (int i = 0; i < ImGuiCol_COUNT; i++) c[i] = base.Colors[i];

    const float s = t.light ? -1.0f : 1.0f;     // «ярче при наведении»: в светлой — темнее
    const ImVec4 bh = shade(t.button, 0.06f * s);
    const ImVec4 ba = mix(t.button, t.accent, 0.45f);
    const ImVec4 border = t.light ? ImVec4(0, 0, 0, 0.14f) : withA(mix(t.frame, t.text, 0.25f), 0.45f);

    c[ImGuiCol_Text]                  = t.text;
    c[ImGuiCol_TextDisabled]          = t.textDim;
    c[ImGuiCol_WindowBg]              = t.bg;
    c[ImGuiCol_ChildBg]               = t.child;
    c[ImGuiCol_PopupBg]               = withA(t.popup, 0.98f);
    c[ImGuiCol_MenuBarBg]             = t.popup;
    c[ImGuiCol_Border]                = border;
    c[ImGuiCol_FrameBg]               = t.frame;
    c[ImGuiCol_FrameBgHovered]        = shade(t.frame, 0.05f * s);
    c[ImGuiCol_FrameBgActive]         = shade(t.frame, 0.08f * s);
    c[ImGuiCol_ScrollbarBg]           = withA(t.bg, 0.6f);
    c[ImGuiCol_ScrollbarGrab]         = shade(t.frame, 0.10f * s);
    c[ImGuiCol_ScrollbarGrabHovered]  = shade(t.frame, 0.16f * s);
    c[ImGuiCol_ScrollbarGrabActive]   = shade(t.frame, 0.22f * s);
    c[ImGuiCol_CheckMark]             = t.accent;
    c[ImGuiCol_SliderGrab]            = t.accent;
    c[ImGuiCol_SliderGrabActive]      = shade(t.accent, 0.10f * s);
    c[ImGuiCol_Button]                = t.button;
    c[ImGuiCol_ButtonHovered]         = bh;
    c[ImGuiCol_ButtonActive]          = ba;
    c[ImGuiCol_Header]                = withA(t.button, 0.55f);
    c[ImGuiCol_HeaderHovered]         = withA(bh, 0.70f);
    c[ImGuiCol_HeaderActive]          = withA(ba, 0.90f);
    c[ImGuiCol_Separator]             = border;
    c[ImGuiCol_SeparatorHovered]      = withA(t.accent, 0.60f);
    c[ImGuiCol_SeparatorActive]       = t.accent;
    c[ImGuiCol_ResizeGrip]            = withA(t.button, 0.30f);
    c[ImGuiCol_ResizeGripHovered]     = withA(bh, 0.60f);
    c[ImGuiCol_ResizeGripActive]      = ba;
    c[ImGuiCol_Tab]                   = mix(t.bg, t.frame, 0.6f);
    c[ImGuiCol_TabHovered]            = bh;
    c[ImGuiCol_TabSelected]           = t.button;
    c[ImGuiCol_TabSelectedOverline]   = t.accent;
    c[ImGuiCol_TabDimmed]             = c[ImGuiCol_Tab];     // главное окно теряет фокус при
    c[ImGuiCol_TabDimmedSelected]     = t.button;            // каждом меню — не мигать вкладками
    c[ImGuiCol_TabDimmedSelectedOverline] = withA(t.accent, 0.5f);
    c[ImGuiCol_PlotHistogram]         = mix(t.button, t.accent, 0.35f);
    c[ImGuiCol_PlotHistogramHovered]  = t.accent;
    c[ImGuiCol_TableHeaderBg]         = mix(t.child, t.frame, 0.6f);
    c[ImGuiCol_TableBorderStrong]     = mix(t.frame, t.text, 0.15f);
    c[ImGuiCol_TableBorderLight]      = mix(t.child, t.frame, 0.9f);
    c[ImGuiCol_TableRowBgAlt]         = t.light ? ImVec4(0, 0, 0, 0.035f) : ImVec4(1, 1, 1, 0.025f);
    c[ImGuiCol_TextSelectedBg]        = withA(t.accent, 0.35f);
    c[ImGuiCol_TextLink]              = t.accent;
    c[ImGuiCol_NavCursor]             = t.accent;

    out.sem[0] = t.accent; out.sem[1] = t.good; out.sem[2] = t.warn;
    out.sem[3] = t.bad;    out.sem[4] = t.dim;
    out.clear = t.light ? shade(t.bg, -0.03f) : shade(t.bg, -0.02f);
}

void captureTheme(ThemeColors& out) { out = s_cur; }

void applyTheme(const ThemeColors& a, const ThemeColors& b, float t) {
    for (int i = 0; i < ImGuiCol_COUNT; i++) s_cur.col[i] = mix(a.col[i], b.col[i], t);
    for (int i = 0; i < 5; i++) s_cur.sem[i] = mix(a.sem[i], b.sem[i], t);
    s_cur.clear = mix(a.clear, b.clear, t);
    kAccent = s_cur.sem[0];
    kGood   = s_cur.sem[1];
    kWarn   = s_cur.sem[2];
    kBad    = s_cur.sem[3];
    kDim    = s_cur.sem[4];
    s_clear = s_cur.clear;
}

// Выбор темы и «Анимации» хранятся в реестре пользователя (analyzer.ini —
// общий файл настроек анализа, программа его только читает).
// На macOS — в ~/Library/Application Support/TrafficAnalyzer/gui.ini с тем же API.
#ifdef _WIN32
const wchar_t kRegKey[] = L"Software\\MARYNONET\\TrafficAnalyzer";

DWORD regGetDword(const wchar_t* key, const wchar_t* name, DWORD def) {
    DWORD v = 0, sz = sizeof(v);
    if (RegGetValueW(HKEY_CURRENT_USER, key, name, RRF_RT_REG_DWORD, nullptr, &v, &sz) == ERROR_SUCCESS)
        return v;
    return def;
}

void regSetDword(const wchar_t* name, DWORD v) {
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k,
                        nullptr) != ERROR_SUCCESS)
        return;
    RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE*)&v, sizeof(v));
    RegCloseKey(k);
}

std::wstring regGetString(const wchar_t* name) {
    DWORD sz = 0;
    if (RegGetValueW(HKEY_CURRENT_USER, kRegKey, name, RRF_RT_REG_SZ, nullptr, nullptr, &sz) != ERROR_SUCCESS ||
        sz < sizeof(wchar_t) || sz > 64 * 1024)
        return L"";
    std::wstring s(sz / sizeof(wchar_t), L'\0');
    if (RegGetValueW(HKEY_CURRENT_USER, kRegKey, name, RRF_RT_REG_SZ, nullptr, &s[0], &sz) != ERROR_SUCCESS)
        return L"";
    s.resize(wcsnlen(s.c_str(), s.size()));
    return s;
}

// Пустая строка — удалить значение.
void regSetString(const wchar_t* name, const std::wstring& v) {
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k,
                        nullptr) != ERROR_SUCCESS)
        return;
    if (v.empty()) RegDeleteValueW(k, name);
    else RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)v.c_str(), (DWORD)((v.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(k);
}

// Светлая ли тема у приложений Windows («Персонализация → Цвета»).
bool systemLightTheme() {
    return regGetDword(L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
                       L"AppsUseLightTheme", 0) != 0;
}
#else
const wchar_t kRegKey[] = L"TrafficAnalyzer";     // на macOS не используется

std::string settingsPath() {
    const char* home = getenv("HOME");
    if (!home || !*home) return "";
    return std::string(home) + "/Library/Application Support/TrafficAnalyzer/gui.ini";
}

// «имя=значение» по строке; читается один раз, пишется целиком при каждом изменении
std::map<std::string, std::string>& settings() {
    static std::map<std::string, std::string> m;
    static bool loaded = false;
    if (!loaded) {
        loaded = true;
        std::ifstream in(settingsPath());
        std::string line;
        while (std::getline(in, line)) {
            const size_t eq = line.find('=');
            if (eq != std::string::npos && eq > 0) m[line.substr(0, eq)] = line.substr(eq + 1);
        }
    }
    return m;
}

void saveSettings() {
    const std::string path = settingsPath();
    if (path.empty()) return;
    mkdir(path.substr(0, path.rfind('/')).c_str(), 0755);
    std::ofstream out(path, std::ios::trunc);
    for (const auto& kv : settings()) out << kv.first << '=' << kv.second << '\n';
}

DWORD regGetDword(const wchar_t*, const wchar_t* name, DWORD def) {
    const auto& m = settings();
    const auto it = m.find(w2u8(name));
    if (it == m.end() || it->second.empty()) return def;
    char* end = nullptr;
    const unsigned long v = strtoul(it->second.c_str(), &end, 10);
    return *end == 0 ? (DWORD)v : def;
}

void regSetDword(const wchar_t* name, DWORD v) {
    settings()[w2u8(name)] = std::to_string(v);
    saveSettings();
}

std::wstring regGetString(const wchar_t* name) {
    const auto& m = settings();
    const auto it = m.find(w2u8(name));
    return it == m.end() ? std::wstring() : u8w(it->second);
}

// Пустая строка — удалить значение.
void regSetString(const wchar_t* name, const std::wstring& v) {
    if (v.empty()) settings().erase(w2u8(name));
    else settings()[w2u8(name)] = w2u8(v.c_str());
    saveSettings();
}

// «Оформление» macOS: при тёмном AppleInterfaceStyle = "Dark", при светлом ключа нет.
bool systemLightTheme() {
    CFPropertyListRef v = CFPreferencesCopyAppValue(CFSTR("AppleInterfaceStyle"),
                                                    kCFPreferencesAnyApplication);
    if (!v) return true;
    bool dark = false;
    if (CFGetTypeID(v) == CFStringGetTypeID())
        dark = CFStringCompare((CFStringRef)v, CFSTR("Dark"), kCFCompareCaseInsensitive) ==
               kCFCompareEqualTo;
    CFRelease(v);
    return !dark;
}

// Выбор файла через AppleScript; "" — отмена. script должен вернуть POSIX-путь.
std::string macPickPath(const std::string& script) {
    int rc = -1;
    std::string out = macOsascript("activate\n" + script, &rc);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
    return rc == 0 ? out : std::string();
}
#endif

void setTheme(int idx, bool animate) {
    if (idx < 0 || idx >= kThemeCount) idx = 0;
    const bool save = idx != s_theme;
    s_theme = idx;
    buildTheme(kThemes[idx], s_themeTo);
    if (animate && s_anim) {
        captureTheme(s_themeFrom);              // с текущих цветов — даже посреди перехода
        s_themeT0 = ImGui::GetTime();
    } else {
        applyTheme(s_themeTo, s_themeTo, 1);
        s_themeT0 = -1;
    }
    if (save) regSetDword(L"Theme", (DWORD)idx);
}

void updateTheme() {
    if (s_themeT0 < 0) return;
    const float t = animProgress(s_themeT0, kThemeFade);
    applyTheme(s_themeFrom, s_themeTo, easeInOut(t));
    if (t >= 1) s_themeT0 = -1;
}

void setAnimations(bool on) {
    s_anim = on;
    regSetDword(L"Animations", on ? 1 : 0);
}

// ------------------------------------------------------------------
// картинка на фоне
// ------------------------------------------------------------------
enum { WP_THEME = 0, WP_ALWAYS, WP_OFF };
int s_wpMode = WP_THEME;         // когда показывать
int s_wpDim = 55;                // затемнение картинки цветом фона темы, %
std::wstring s_wpPath;           // своя картинка; пусто — встроенная
std::wstring s_wpPending;        // загрузить в начале следующего кадра
bool s_wpPendingSet = false;
bool s_wpTried = false;          // сохранённую уже пробовали загрузить (не повторять каждый кадр)
// что сейчас грузится: картинка читается в своём потоке, итог — wallpaperPoll
enum { WPL_NONE = 0, WPL_PICKED, WPL_SAVED, WPL_BUILTIN };
int s_wpLoad = WPL_NONE;
float s_wpVis = 0;               // насколько видна сейчас, 0..1 (плавно)
ImVec2 s_wpPar(0, 0);            // сглаженный параллакс от мыши
ImVec4 s_panelBg;                // «стекло» карточек, журнала, таблицы
const float kPanelGlass = 0.72f; // непрозрачность «стекла» поверх картинки

bool wallpaperWanted() {
    return s_wpMode == WP_ALWAYS || (s_wpMode == WP_THEME && kThemes[s_theme].wallpaper);
}

std::string wideName(const std::wstring& path) {
    const size_t p = path.find_last_of(L"\\/");
    return w2u8((p == std::wstring::npos ? path : path.substr(p + 1)).c_str());
}

void actPickWallpaper() {
#ifndef _WIN32
    const std::string path = macPickPath(
        "POSIX path of (choose file with prompt \"Картинка для фона\" of type {\"public.image\"})");
    if (path.empty()) return;
    s_wpPending = u8w(path);
    s_wpPendingSet = true;
#else
    wchar_t file[MAX_PATH] = L"";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = mainHwnd();
    ofn.lpstrFilter = L"Изображения\0*.jpg;*.jpeg;*.png;*.bmp;*.gif;*.tif;*.tiff;*.webp;*.jxr\0"
                      L"Все файлы\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn)) return;
    s_wpPending = file;              // загрузим в начале кадра (см. wallpaperLoad)
    s_wpPendingSet = true;
#endif
}

// Начало кадра: загрузка (отложенная из настроек или первая), плавность.
// Картинка читается в своём потоке — сохранённый путь в недоступной сетевой
// папке не подвешивает окно; пока картинки нет, интерфейс просто без фона.
void updateWallpaper() {
    if (s_wpPendingSet) {
        s_wpPendingSet = false;
        s_wpTried = true;
        wallpaperLoad(s_wpPending);
        s_wpLoad = WPL_PICKED;
    }

    bool want = wallpaperWanted();
    if (want && !wallpaperTex().tex && !s_wpTried) {
        s_wpTried = true;
        wallpaperLoad(s_wpPath);
        s_wpLoad = WPL_SAVED;
    }

    std::string err;
    const int got = wallpaperPoll(err);
    if (got != 0) {
        const int what = s_wpLoad;
        s_wpLoad = WPL_NONE;
        if (what == WPL_PICKED) {
            const std::string name = s_wpPending.empty() ? std::string("встроенная") : wideName(s_wpPending);
            if (got > 0) {
                s_wpPath = s_wpPending;
                regSetString(L"WallpaperPath", s_wpPath);
                // выбрали свою картинку, а в этой теме она не показывается — показать
                if (!s_wpPath.empty() && !wallpaperWanted()) {
                    s_wpMode = WP_ALWAYS;
                    regSetDword(L"WallpaperMode", (DWORD)s_wpMode);
                }
                logLine(C::GRN, "Картинка на фоне: " + name);
            } else {
                logLine(C::YEL, "Картинка «" + name + "» не загружена: " + err);
            }
        } else if (got < 0 && what == WPL_SAVED && !s_wpPath.empty()) {
            // файл переехал/удалён — путь в реестре не трогаем (может быть
            // временно недоступная сетевая папка), показываем встроенную
            logLine(C::YEL, "Картинка «" + wideName(s_wpPath) + "»: " + err + " — показываю встроенную");
            wallpaperLoad(L"");
            s_wpLoad = WPL_BUILTIN;
        } else if (got < 0) {
            logLine(C::YEL, (what == WPL_BUILTIN ? "Встроенная картинка: " : "Картинка на фоне: ") + err);
        }
    }
    if (!wallpaperTex().tex) want = false;

    const float target = want ? 1.0f : 0.0f;
    if (!s_anim) s_wpVis = target;
    else if (s_wpVis != target) {
        const float step = ImGui::GetIO().DeltaTime / 0.5f;
        s_wpVis = target > s_wpVis ? std::min(target, s_wpVis + step) : std::max(target, s_wpVis - step);
        s_wantFrames = true;
    }
}

// Цвета темы -> стиль ImGui. Пока видна картинка, фон главного окна и
// служебных дочерних окон прозрачный, меню/поля/вкладки — полупрозрачные,
// карточки и журнал — «стекло» (s_panelBg, см. pushPanelBg).
void finalizeStyle() {
    ImGuiStyle& st = ImGui::GetStyle();
    for (int i = 0; i < ImGuiCol_COUNT; i++) st.Colors[i] = s_cur.col[i];
    s_panelBg = s_cur.col[ImGuiCol_ChildBg];
    const float v = easeInOut(s_wpVis);
    if (v <= 0) return;
    auto fade = [&](ImGuiCol c, float keep) { st.Colors[c].w *= 1 - (1 - keep) * v; };
    fade(ImGuiCol_WindowBg, 0);
    fade(ImGuiCol_ChildBg, 0);
    fade(ImGuiCol_MenuBarBg, 0.55f);
    fade(ImGuiCol_FrameBg, 0.75f);
    fade(ImGuiCol_FrameBgHovered, 0.85f);
    fade(ImGuiCol_FrameBgActive, 0.90f);
    fade(ImGuiCol_Tab, 0.60f);
    fade(ImGuiCol_TabDimmed, 0.60f);
    fade(ImGuiCol_TableHeaderBg, 0.75f);
    fade(ImGuiCol_ScrollbarBg, 0.30f);
    fade(ImGuiCol_Button, 0.85f);
    s_panelBg.w *= 1 - (1 - kPanelGlass) * v;
}

// Фон дочернего окна-панели; фон рисуется в BeginChild/BeginTable, поэтому
// снимать можно сразу после них.
void pushPanelBg() { ImGui::PushStyleColor(ImGuiCol_ChildBg, s_panelBg); }

ImU32 u32(const ImVec4& c) { return ImGui::ColorConvertFloat4ToU32(c); }   // без style.Alpha

// Детерминированное «случайное» 0..1 по номеру (частицы).
float hash01(unsigned i, unsigned salt) {
    unsigned x = i * 747796405u + salt * 2891336453u + 1u;
    x ^= x >> 16; x *= 0x7feb352du;
    x ^= x >> 15; x *= 0x846ca68bu;
    x ^= x >> 16;
    return (float)(x & 0xFFFFFFu) / 16777215.0f;
}

// Картинка под всем интерфейсом: заполняет окно (обрезая лишнее), затемнена
// цветом темы, виньетка у меню и строки статуса. С анимациями — медленный
// дрейф, параллакс за мышью, огоньки, у встроенной — мерцание глаз.
void drawWallpaper() {
    const WallpaperTex& wp = wallpaperTex();
    if (s_wpVis <= 0 || !wp.tex || wp.w <= 0 || wp.h <= 0) return;
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    const ImVec2 p0 = vp->Pos, sz = vp->Size;
    if (sz.x <= 0 || sz.y <= 0) return;
    const float v = easeInOut(s_wpVis);
    const float t = (float)ImGui::GetTime();
    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    // запас 6% по краям — есть куда сдвигаться
    const float margin = s_anim ? 0.06f : 0.0f;
    const float sc = std::max(sz.x / wp.w, sz.y / wp.h) * (1 + margin);
    const ImVec2 isz(wp.w * sc, wp.h * sc);
    float fx = 0, fy = 0;                        // сдвиг в долях запаса, -1..1
    if (s_anim) {
        ImVec2 tgt(0, 0);
        const ImVec2 m = ImGui::GetIO().MousePos;
        if (ImGui::IsMousePosValid(&m)) {
            tgt.x = std::max(-1.0f, std::min(1.0f, ((m.x - p0.x) / sz.x - 0.5f) * 2));
            tgt.y = std::max(-1.0f, std::min(1.0f, ((m.y - p0.y) / sz.y - 0.5f) * 2));
        }
        const float k = std::min(1.0f, ImGui::GetIO().DeltaTime * 2.5f);
        s_wpPar.x += (tgt.x - s_wpPar.x) * k;
        s_wpPar.y += (tgt.y - s_wpPar.y) * k;
        fx = 0.45f * sinf(t * 0.050f) - 0.40f * s_wpPar.x;
        fy = 0.45f * cosf(t * 0.037f) - 0.40f * s_wpPar.y;
    }
    const ImVec2 i0(p0.x + (sz.x - isz.x) * 0.5f * (1 + fx), p0.y + (sz.y - isz.y) * 0.5f * (1 + fy));
    const ImVec2 i1(i0.x + isz.x, i0.y + isz.y);
    dl->AddImage(wp.tex, i0, i1, ImVec2(0, 0), ImVec2(1, 1), u32(ImVec4(1, 1, 1, v)));

    // затемнение и виньетка — цветом фона темы (в светлой — «высветление»)
    const ImVec4 bg = s_cur.col[ImGuiCol_WindowBg];
    const ImVec2 p1(p0.x + sz.x, p0.y + sz.y);
    dl->AddRectFilled(p0, p1, u32(withA(bg, v * s_wpDim / 100.0f)));
    const float vh = sz.y * 0.16f;
    const ImU32 cv = u32(withA(bg, v * 0.55f)), c0 = u32(withA(bg, 0));
    dl->AddRectFilledMultiColor(p0, ImVec2(p1.x, p0.y + vh), cv, cv, c0, c0);
    dl->AddRectFilledMultiColor(ImVec2(p0.x, p1.y - vh * 0.7f), p1, c0, c0, cv, cv);

    if (!s_anim) return;
    const ImVec4 glow(0.55f, 0.90f, 1.00f, 1);

    // огоньки: медленно поднимаются, мерцают, гаснут у краёв
    const float em = ImGui::GetFontSize();
    for (unsigned i = 0; i < 36; i++) {
        const float sp = 0.012f + 0.022f * hash01(i, 1);               // доля высоты в секунду
        const float y = 1.0f - fmodf(hash01(i, 2) + t * sp, 1.0f);
        const float x = fmodf(hash01(i, 3) + 0.015f * sinf(t * (0.3f + hash01(i, 4)) + i) + 1.0f, 1.0f);
        const float r = em * (0.07f + 0.12f * hash01(i, 5));
        const float tw = 0.5f + 0.5f * sinf(t * (1.0f + 2.0f * hash01(i, 6)) + i * 1.7f);
        const float a = v * (0.08f + 0.30f * tw) * sinf(3.14159f * y);
        const ImVec2 c(p0.x + x * sz.x, p0.y + y * sz.y);
        dl->AddCircleFilled(c, r * 2.6f, u32(withA(glow, a * 0.16f)), 12);
        dl->AddCircleFilled(c, r, u32(withA(glow, a)), 8);
    }

    // встроенная картинка: глаза «светятся» (координаты глаз — доли картинки)
    if (wp.builtin) {
        const ImVec2 eyes[2] = { ImVec2(0.338f, 0.562f), ImVec2(0.665f, 0.363f) };
        const float R = 0.048f * isz.x;
        for (int e = 0; e < 2; e++) {
            const ImVec2 c(i0.x + eyes[e].x * isz.x, i0.y + eyes[e].y * isz.y);
            const float p = 0.5f + 0.5f * sinf(t * 1.6f + e * 0.7f);
            for (int k = 0; k < 4; k++) {
                const float r = R * (0.30f + 0.25f * k) * (0.95f + 0.10f * p);
                dl->AddCircleFilled(c, r, u32(withA(glow, (0.025f + 0.030f * p) * v)), 32);
            }
        }
    }
}

// Три квадратика — фон, кнопка, акцент темы (в списке выбора).
void themeSwatch(const ThemeSpec& t) {
    const float sz = ImGui::GetFontSize() * 0.8f, gap = sz * 0.25f;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float y = p.y + (ImGui::GetTextLineHeight() - sz) * 0.5f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec4 cols[3] = { t.bg, t.button, t.accent };
    for (int i = 0; i < 3; i++) {
        const float x = p.x + i * (sz + gap);
        dl->AddRectFilled(ImVec2(x, y), ImVec2(x + sz, y + sz), ImGui::GetColorU32(cols[i]), sz * 0.2f);
        dl->AddRect(ImVec2(x, y), ImVec2(x + sz, y + sz), ImGui::GetColorU32(ImGuiCol_Border), sz * 0.2f);
    }
    ImGui::Dummy(ImVec2(3 * sz + 2 * gap, ImGui::GetTextLineHeight()));
}

// ------------------------------------------------------------------
// анимированные элементы
// ------------------------------------------------------------------
// Крутящаяся дуга высотой в строку кнопок (вместо «|/-\»).
void spinner(const ImVec4& col) {
    const float h = ImGui::GetFrameHeight();
    const ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(h, h));
    const ImVec2 c(p.x + h * 0.5f, p.y + h * 0.5f);
    const float r = h * 0.30f;
    const float t = (float)ImGui::GetTime();
    const float a0 = t * 6.0f;
    const float len = 2.0f + 1.4f * sinf(t * 2.2f);   // дуга «дышит»: ~0.6..3.4 рад
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddCircle(c, r, ImGui::GetColorU32(withA(col, col.w * 0.20f)), 24, r * 0.28f);
    dl->PathArcTo(c, r, a0, a0 + len, 24);
    dl->PathStroke(ImGui::GetColorU32(col), 0, r * 0.28f);
}

// Плавное проявление содержимого вкладки при переключении и новом дампе.
int s_curTab = TAB_NONE;
double s_tabT0 = 0;

void beginTabBody(int tab) {
    if (tab != s_curTab) { s_curTab = tab; s_tabT0 = ImGui::GetTime(); }
    const float a = easeOut(animProgress(s_tabT0, 0.22f));
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * (0.15f + 0.85f * a));
}
void endTabBody() { ImGui::PopStyleVar(); }

// Всплывающее «Завершено: …» / «Ошибка: …» в правом нижнем углу после фоновой задачи.
bool s_wasBusy = false;
std::string s_busyTitle;
std::string s_toast;
bool s_toastFailed = false;
double s_toastT0 = -100;
const float kToastLife = 4.0f;

void trackJobForToast() {
    const bool busy = jobBusy();
    if (busy) s_busyTitle = jobTitle();
    else if (s_wasBusy) {
        s_toastFailed = jobFailed();
        if (s_toastFailed)
            s_toast = s_busyTitle.empty() ? std::string("Задача завершилась ошибкой") : "Ошибка: " + s_busyTitle;
        else
            s_toast = s_busyTitle.empty() ? std::string("Задача завершена") : "Завершено: " + s_busyTitle;
        s_toastT0 = ImGui::GetTime();
    }
    s_wasBusy = busy;
}

// панель действий
char s_target[256] = "";

// таблица соединений
char s_flowFilter[256] = "";
int s_proto = 0;                 // 0 все, 1 TCP, 2 UDP, 3 прочие
bool s_onlyProblems = false;
std::vector<int> s_order;        // индексы ds->flows после фильтра и сортировки
std::vector<std::string> s_geo;  // страна/ASN по индексу ds->flows (для сортировки)
unsigned s_orderGen = ~0u;
std::string s_orderFilter;
int s_orderProto = -1;
bool s_orderProblems = false;
bool s_needRefilter = true;     // пересобрать s_order (фильтр) — до строки «показано N из M»
bool s_needResort = true;       // пересортировать s_order — внутри таблицы, где есть sort specs
int s_wfIdx = -1;                // выбранное соединение (индекс ds->flows) для «Профиля соединения»

// журнал
char s_logFilter[256] = "";
bool s_autoScroll = true;

std::shared_ptr<Dataset> s_lastDs;
std::shared_ptr<const DumpSummary> s_lastSummary;
double s_sumT0 = -100;           // когда появилась текущая сводка (рост полос, пульс)

std::string lowerAscii(std::string s) {
    for (char& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

std::string fmtDur(double sec) {
    char b[64];
    if (sec < 1) snprintf(b, sizeof(b), "%.0f мс", sec * 1000);
    else if (sec < 120) snprintf(b, sizeof(b), "%.1f с", sec);
    else if (sec < 7200) snprintf(b, sizeof(b), "%d мин %02d с", (int)sec / 60, (int)sec % 60);
    else snprintf(b, sizeof(b), "%d ч %02d мин", (int)sec / 3600, ((int)sec % 3600) / 60);
    return b;
}

std::string endpoint(const std::string& ip, int port) {
    if (port < 0) return ip;
    if (ip.find(':') != std::string::npos) return "[" + ip + "]:" + std::to_string(port);
    return ip + ":" + std::to_string(port);
}

std::string geoOf(const IpCache* cache, const std::string& ip) {
    if (!cache) return "";
    auto it = cache->find(ip);
    if (it == cache->end()) return "";
    const IpInfo& i = it->second;
    std::string s;
    if (i.country != "-") s += i.country;
    // номер AS и название организации: «AS57043 Hostkey B.V.»
    std::string as;
    if (i.asn != "-") as = i.asn;
    if (i.org != "-" && !i.org.empty()) { if (!as.empty()) as += ' '; as += i.org; }
    if (!as.empty()) { if (!s.empty()) s += " · "; s += as; }
    // белый список VPN (Google, VK, Яндекс…) — флаги баз не показываем
    if (i.vpnWhite || inVpnWhitelistAsn(i.asn)) s += " [белый список]";
    else if (i.isVpn) s += " [VPN]";
    else if (i.isProxy) s += " [proxy]";
    else if (i.isTor) s += " [Tor]";
    else if (i.pxType == "RES") s += " [резидентный прокси]";
    else if (i.pxType == "CPN") s += " [Private Relay и т.п.]";
    else if (i.pxType == "EPN") s += " [корп. сеть]";
    // сырой флаг ip-api стоит и у Google/Microsoft/Yandex — фильтр как в отчётах
    else if (isHostingNonCdn(&i)) s += " [хостинг]";
    if (s.empty()) s = "?";          // спрашивали, но сервис ничего не вернул
    return s;
}

const char* stateText(int st) {
    switch (st) {
    case FS_OK:        return "норма";
    case FS_NO_ANSWER: return "нет ответа";
    case FS_RST:       return "сброс (RST)";
    case FS_ONE_WAY:   return "в одну сторону";
    case FS_MIDSTREAM: return "начало не в дампе";
    case FS_UDP:       return "—";
    case FS_IN_REFUSED: return "входящее не принято";
    default:           return "?";
    }
}

ImVec4 stateColor(const FlowRow& r) {
    switch (r.state) {
    case FS_OK:        return kGood;
    case FS_NO_ANSWER: return r.problem ? kBad : kDim;
    case FS_RST:       return r.problem ? kBad : kWarn;
    case FS_ONE_WAY:   return r.problem ? kWarn : kDim;
    default:           return r.problem ? kWarn : kDim;
    }
}

// blockedIps — блокировка всего адреса (общие адреса CDN, где работают другие
// сайты, туда не попадают); blockedSnis — по имени: помечаем только строки
// с этим доменом, а не все строки его IP.
bool isBlocked(const DumpSummary* s, const FlowRow& r) {
    if (!s) return false;
    if (s->blockedIps.count(r.remoteIp)) return true;
    return !r.sni.empty() && s->blockedSnis.count(r.sni) > 0;
}

std::string wiresharkFilter(const FlowRow& r) {
    std::string f = (r.remoteIp.find(':') != std::string::npos ? "ipv6.addr==" : "ip.addr==") + r.remoteIp;
    if (r.remotePort >= 0 && (r.proto == "TCP" || r.proto == "UDP"))
        f += " && " + lowerAscii(r.proto) + ".port==" + std::to_string(r.remotePort);
    return f;
}

bool hasDs(const View& v) { return v.ds != nullptr; }

// ------------------------------------------------------------------
// действия
// ------------------------------------------------------------------
void actOpen() {
    if (jobBusy()) return;
    std::vector<std::string> p = pickDumpFiles(mainHwnd());
    if (!p.empty()) startLoad(p);
}

// Окно-подсказка с одной кнопкой OK.
void infoBox(const char* title, const char* text) {
#ifdef _WIN32
    MessageBoxW(mainHwnd(), u8w(text).c_str(), u8w(title).c_str(), MB_ICONINFORMATION);
#else
    macOsascript("activate\ndisplay dialog " + asQuote(text) + " with title " + asQuote(title) +
                 " buttons {\"OK\"} default button 1 with icon note");
#endif
}

void actCompareWithCurrent() {
    if (jobBusy()) return;
    infoBox("Сравнение дампов", "Текущий набор — A («как было»).\nВыберите дамп B («как стало»).");
    std::vector<std::string> b = pickDumpFiles(mainHwnd());
    if (!b.empty()) startCompare({}, b);
}

void actCompareTwo() {
    if (jobBusy()) return;
    infoBox("Сравнение дампов", "Выберите дамп A («как было», эталон).");
    std::vector<std::string> a = pickDumpFiles(mainHwnd());
    if (a.empty()) return;
    infoBox("Сравнение дампов", "Теперь выберите дамп B («как стало»).");
    std::vector<std::string> b = pickDumpFiles(mainHwnd());
    if (!b.empty()) startCompare(a, b);
}

void actSaveLog() {
#ifndef _WIN32
    // choose file name сам спрашивает про замену существующего файла
    const std::string path = macPickPath(
        "POSIX path of (choose file name with prompt \"Сохранить журнал\" "
        "default name \"TrafficAnalyzer-журнал.txt\")");
    if (path.empty()) return;
    FILE* f = ufopen(path, "wb");
    if (!f) { logLine(C::RED, "Не удалось сохранить журнал: " + path); return; }
    const std::string t = appLog().text();
    fwrite(t.data(), 1, t.size(), f);
    fclose(f);
    logLine(C::GRN, "Журнал сохранён: " + path);
#else
    wchar_t file[MAX_PATH] = L"TrafficAnalyzer-журнал.txt";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = mainHwnd();
    ofn.lpstrFilter = L"Текст (*.txt)\0*.txt\0Все файлы\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn)) return;
    FILE* f = _wfopen(file, L"wb");
    if (!f) { logLine(C::RED, "Не удалось сохранить журнал: " + w2u8(file)); return; }
    fputc(0xEF, f); fputc(0xBB, f); fputc(0xBF, f);
    std::string t = appLog().text();
    std::string crlf;                       // для Блокнота — CRLF
    crlf.reserve(t.size() + t.size() / 40);
    for (char c : t) { if (c == '\n') crlf += '\r'; crlf += c; }
    fwrite(crlf.data(), 1, crlf.size(), f);
    fclose(f);
    logLine(C::GRN, "Журнал сохранён: " + w2u8(file));
#endif
}

// ------------------------------------------------------------------
// меню и панель действий
// ------------------------------------------------------------------
// Системного заголовка у окна нет (gui_main.cpp): справа на панели меню —
// «свернуть / развернуть / закрыть», пустая часть между меню и ними — заголовок
// (за неё тянут окно, двойной щелчок разворачивает). Зовётся внутри панели меню.
void drawWindowButtons(float menusEnd) {
    const ImVec2 wp = ImGui::GetWindowPos();
    const float h = ImGui::GetFrameHeight();              // высота панели меню
    const float bw = h * 1.8f;
    const float x0 = wp.x + ImGui::GetWindowWidth() - bw * 3;
    guiSetCaptionArea(menusEnd - wp.x, x0 - wp.x, h);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const char* title = "TrafficAnalyzer — MARYNONET";
    const ImVec2 ts = ImGui::CalcTextSize(title);
    if (x0 - menusEnd > ts.x + h * 2) {                    // по центру окна, если влезает
        const float tx = std::clamp(wp.x + (ImGui::GetWindowWidth() - ts.x) * 0.5f,
                                    menusEnd + h, x0 - h - ts.x);
        dl->AddText(ImVec2(tx, wp.y + (h - ts.y) * 0.5f), ImGui::GetColorU32(kDim), title);
    }

    const float th = std::max(1.0f, std::round(h / 24.0f));   // толщина линий значков
    const float s = std::round(h * 0.2f);                      // полуразмер значка
    for (int i = 0; i < 3; i++) {
        ImGui::SetCursorScreenPos(ImVec2(x0 + bw * i, wp.y));
        ImGui::PushID(i);
        const bool pressed = ImGui::InvisibleButton("##winbtn", ImVec2(bw, h));
        const bool hov = ImGui::IsItemHovered(), held = ImGui::IsItemActive();
        ImGui::PopID();
        const ImVec2 a = ImGui::GetItemRectMin(), b = ImGui::GetItemRectMax();
        if (hov || held) {
            const ImU32 bg = i == 2 ? IM_COL32(196, 43, 28, held ? 190 : 255)
                                    : ImGui::GetColorU32(held ? ImGuiCol_ButtonActive : ImGuiCol_ButtonHovered);
            dl->AddRectFilled(a, b, bg);
        }
        const ImU32 col = (i == 2 && hov) ? IM_COL32_WHITE : ImGui::GetColorU32(ImGuiCol_Text);
        const ImVec2 c(std::floor((a.x + b.x) * 0.5f) + 0.5f, std::floor((a.y + b.y) * 0.5f) + 0.5f);
        if (i == 0) {
            dl->AddLine(ImVec2(c.x - s, c.y), ImVec2(c.x + s, c.y), col, th);
        } else if (i == 1) {
            if (guiIsMaximized()) {        // «восстановить»: два квадрата
                const float o = std::round(s * 0.4f);
                dl->AddRect(ImVec2(c.x - s, c.y - s + o), ImVec2(c.x + s - o, c.y + s), col, 0, 0, th);
                dl->AddLine(ImVec2(c.x - s + o, c.y - s + o), ImVec2(c.x - s + o, c.y - s), col, th);
                dl->AddLine(ImVec2(c.x - s + o, c.y - s), ImVec2(c.x + s, c.y - s), col, th);
                dl->AddLine(ImVec2(c.x + s, c.y - s), ImVec2(c.x + s, c.y + s - o), col, th);
                dl->AddLine(ImVec2(c.x + s, c.y + s - o), ImVec2(c.x + s - o, c.y + s - o), col, th);
            } else {
                dl->AddRect(ImVec2(c.x - s, c.y - s), ImVec2(c.x + s, c.y + s), col, 0, 0, th);
            }
        } else {
            dl->AddLine(ImVec2(c.x - s, c.y - s), ImVec2(c.x + s, c.y + s), col, th);
            dl->AddLine(ImVec2(c.x - s, c.y + s), ImVec2(c.x + s, c.y - s), col, th);
        }
        if (hov) ImGui::SetTooltip("%s", i == 0 ? "Свернуть"
                                        : i == 1 ? (guiIsMaximized() ? "Восстановить" : "Развернуть")
                                                 : "Закрыть");
        if (pressed) {
            if (i == 0) guiMinimize();
            else if (i == 1) guiToggleMaximize();
            else guiRequestClose();
        }
    }
}

void drawMenuBar(const View& v) {
    const bool busy = jobBusy();
    if (!ImGui::BeginMenuBar()) return;
    if (ImGui::BeginMenu("Файл")) {
        if (ImGui::MenuItem("Открыть дамп…", GUI_MOD "+O", false, !busy)) actOpen();
        if (ImGui::MenuItem("Сравнить текущий с другим…", nullptr, false, !busy && hasDs(v)))
            actCompareWithCurrent();
        if (ImGui::MenuItem("Сравнить два дампа…", nullptr, false, !busy)) actCompareTwo();
        ImGui::Separator();
        if (ImGui::MenuItem("Сохранить журнал…")) actSaveLog();
        ImGui::Separator();
#ifdef _WIN32
        if (ImGui::MenuItem("Выход", "Alt+F4")) guiRequestClose();
#else
        if (ImGui::MenuItem("Выход", "Cmd+Q")) guiRequestClose();
#endif
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Анализ")) {
        const bool can = !busy && hasDs(v);
        if (ImGui::MenuItem("VPN / прокси", nullptr, false, can)) startVpnAnalysis();
        if (ImGui::MenuItem("Блокировки и проблемы соединения", nullptr, false, can))
            startConnAnalysis(s_target);
        if (ImGui::MenuItem("Резолв адресов (страна / ASN)", nullptr, false, can)) startResolve();
        ImGui::Separator();
        bool log = g_logEnabled;
        if (ImGui::MenuItem("Сохранять отчёт рядом с дампом", nullptr, &log)) g_logEnabled = log;
        ImGui::EndMenu();
    }
    if (ImGui::BeginMenu("Инструменты")) {
        for (int m = 3; m <= 13; m++)
            if (ImGui::MenuItem(toolTitle(m))) launchConsoleTool(m);
        ImGui::EndMenu();
    }
    const bool viewOpen = ImGui::BeginMenu("Вид");
    const float menusEnd = ImGui::GetItemRectMax().x;   // дальше — «заголовок» окна
    if (viewOpen) {
        if (ImGui::MenuItem("Обзор")) s_selectTab = TAB_OVERVIEW;
        if (ImGui::MenuItem("Соединения")) s_selectTab = TAB_FLOWS;
        if (ImGui::MenuItem("Профиль соединения")) s_selectTab = TAB_WATERFALL;
        if (ImGui::MenuItem("Проверка РКН (cheburcheck)")) s_selectTab = TAB_RKN;
        if (ImGui::MenuItem("Журнал")) s_selectTab = TAB_LOG;
        if (ImGui::MenuItem("Инструменты")) s_selectTab = TAB_TOOLS;
        if (ImGui::MenuItem("Настройки")) s_selectTab = TAB_SETTINGS;
        ImGui::Separator();
        if (ImGui::BeginMenu("Тема")) {
            for (int i = 0; i < kThemeCount; i++)
                if (ImGui::MenuItem(kThemes[i].name, nullptr, i == s_theme)) setTheme(i, true);
            ImGui::Separator();
            if (ImGui::MenuItem("Следующая", GUI_MOD "+T")) setTheme((s_theme + 1) % kThemeCount, true);
            ImGui::EndMenu();
        }
        bool anim = s_anim;
        if (ImGui::MenuItem("Анимации", nullptr, &anim)) setAnimations(anim);
        ImGui::EndMenu();
    }
    if (guiCustomTitleBar()) drawWindowButtons(menusEnd);
    ImGui::EndMenuBar();
}

void drawToolbar(const View& v) {
    const bool busy = jobBusy();
    const bool can = !busy && hasDs(v);

    ImGui::BeginDisabled(busy);
    if (ImGui::Button("Открыть…")) actOpen();
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Дамп tcpdump (.txt) или .pcap/.pcapng. Можно выбрать пару «_in» + «_out».");

    ImGui::SameLine();
    ImGui::BeginDisabled(!can);
    if (ImGui::Button("VPN / прокси")) startVpnAnalysis();
    ImGui::SetItemTooltip("Полный анализ на VPN и прокси (режим 1) — результат в журнале.");
    ImGui::SameLine();
    if (ImGui::Button("Блокировки")) startConnAnalysis(s_target);
    ImGui::SetItemTooltip("Блокировки и проблемы соединения (режим 2) по цели справа.");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 14);
    ImGui::InputTextWithHint("##target", "цель: IP или домен (пусто — все)", s_target, sizeof(s_target));
    ImGui::SameLine();
    if (ImGui::Button("Резолв ASN")) startResolve();
    ImGui::SetItemTooltip("Страна, ASN, хостинг и VPN-флаги удалённых адресов (ip-api / ipapi.is).");
    ImGui::SameLine();
    if (ImGui::Button("Сравнить…")) actCompareWithCurrent();
    ImGui::SetItemTooltip("Сравнить текущий дамп (A, «было») с другим (B, «стало»).");
    ImGui::EndDisabled();

    if (busy) {
        ImGui::SameLine();
        spinner(kWarn);
        ImGui::SameLine();
        ImGui::TextColored(kWarn, "%s", jobTitle().c_str());
    }

    // тонкая «бегущая» полоса под панелью, пока идёт задача (место под неё
    // занято всегда — чтобы вкладки не прыгали)
    const float barH = std::max(2.0f, ImGui::GetFontSize() * 0.18f);
    if (busy) {
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, barH * 0.5f);
        ImGui::ProgressBar(-1.0f - (float)ImGui::GetTime(), ImVec2(-1, barH), nullptr);
        ImGui::PopStyleVar();
    } else {
        ImGui::Dummy(ImVec2(1, barH));
    }
}

// ------------------------------------------------------------------
// «Обзор»
// ------------------------------------------------------------------
void beginCard(const char* id, const char* title, float w) {
    pushPanelBg();
    ImGui::BeginChild(id, ImVec2(w, 0), ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY);
    ImGui::PopStyleColor();
    ImGui::TextColored(kAccent, "%s", title);
    ImGui::Separator();
}

void kv(const char* k, const std::string& v, const ImVec4* col = nullptr) {
    ImGui::TextColored(kDim, "%s", k);
    ImGui::SameLine(ImGui::GetFontSize() * 11);
    if (col) ImGui::TextColored(*col, "%s", v.c_str());
    else ImGui::TextUnformatted(v.c_str());
}

std::string pct(long long a, long long b) {
    if (b <= 0) return "—";
    char buf[32]; snprintf(buf, sizeof(buf), "%.1f%%", 100.0 * a / b);
    return buf;
}

void drawOverview(const View& v) {
    if (!v.ds) {
        ImGui::Dummy(ImVec2(0, ImGui::GetFontSize() * 4));
        ImGui::TextColored(kDim, "Дамп не загружен.");
        ImGui::TextWrapped("Перетащите файл на окно или нажмите «Открыть…» (" GUI_MOD "+O). Поддерживаются "
                           "текстовый вывод tcpdump и .pcap/.pcapng; два файла «..._in» и «..._out» "
                           "загружаются как один набор.");
        return;
    }
    const Dataset& ds = *v.ds;
    const DumpSummary* s = v.summary.get();

    ImGui::TextColored(kAccent, "%s", ds.name.c_str());
    for (const auto& p : ds.paths) ImGui::TextColored(kDim, "%s", p.c_str());
    ImGui::Text("MainIP: %s%s%s", ds.localIp.empty() ? "не определён" : ds.localIp.c_str(),
                ds.localIp6.empty() ? "" : "  /  ", ds.localIp6.c_str());
    if (!ds.localIp.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(kDim, isPrivateIp(ds.localIp) ? "(приватный — за NAT)" : "(публичный)");
    }
    ImGui::Spacing();

    const float sp = ImGui::GetStyle().ItemSpacing.x;
    const float w = (ImGui::GetContentRegionAvail().x - sp * 2) / 3;

    // --- дамп ---
    beginCard("##c_dump", "Дамп", w);
    kv("Пакетов", std::to_string(ds.packets.size()));
    kv("Длительность", fmtDur(ds.durSec));
    kv("Объём", fmtBytes(ds.totalBytes));
    if (s) {
        // та же база, что у «Куда уходит трафик» и вердикта VPN (bytesByRemote):
        // без локальных/multicast и трафика «внутри сети» — отсюда разница с «Объёмом»
        long long ext = 0;
        for (const auto& kvp : s->bytesByIp) ext += kvp.second;
        kv("  с внешними адресами", fmtBytes(ext));
    }
    kv("Соединений", std::to_string(ds.flows.size()));
    {
        size_t pr = 0;
        for (const auto& r : ds.flows) if (r.problem || isBlocked(s, r)) pr++;
        const ImVec4& c = pr ? kWarn : kGood;
        kv("С проблемами", std::to_string(pr), &c);
        if (pr) {
            ImGui::SameLine();
            if (ImGui::SmallButton("показать")) { s_onlyProblems = true; s_selectTab = TAB_FLOWS; }
        }
    }
    ImGui::EndChild();

    // --- VPN ---
    ImGui::SameLine();
    beginCard("##c_vpn", "Признаки VPN / прокси", w);
    if (s) {
        // тот же расчёт и пороги, что в режиме 1 (computeVpnVerdict)
        const bool likely = s->vpnScore >= kVpnLikelyScore, possible = s->vpnScore >= kVpnPossibleScore;
        const ImVec4& c = likely ? kBad : possible ? kWarn : kGood;
        kv("Вердикт", likely ? "вероятно VPN" : possible ? "возможно VPN" : "признаков нет", &c);
        kv("Баллы", std::to_string(s->vpnScore) + "  (вероятно — от " +
           std::to_string(kVpnLikelyScore) + ")", &c);
        if (s->vpnScore > 0)
            ImGui::TextColored(kDim, "порты/прокси %d · форма %d · потоки %d · MSS %d",
                               s->vpnPortScore, s->vpnShapeScore, s->vpnFlowScore, s->vpnMssScore);
        kv("WireGuard-пиры", std::to_string(s->wgPeers.size()),
           s->wgPeers.empty() ? nullptr : &kBad);
        kv("Похоже на Reality", std::to_string(s->realityIps.size()),
           s->realityIps.empty() ? nullptr : &kWarn);
        // «подделку под браузер» (JA4K_FAKE) не определяем — счётчик всегда 0, не показываем
        kv("ClientHello библиотек (JA4)", std::to_string(s->ja4Lib));
        // причины теперь полные (как в режиме 1) и длинные — с переносом строк
        for (const auto& r : s->vpnReasons) { ImGui::Bullet(); ImGui::TextWrapped("%s", r.c_str()); }
        if (!v.ipCache) {
            ImGui::PushStyleColor(ImGuiCol_Text, kDim);
            ImGui::TextWrapped("Без «Резолв ASN» хостинг, гео, CDN и Reality не видны — "
                               "баллы могут отличаться от режима 1 в обе стороны.");
            ImGui::PopStyleColor();
        }
    }
    ImGui::EndChild();

    // --- TCP / DNS ---
    ImGui::SameLine();
    beginCard("##c_tcp", "TCP и DNS", w);
    if (s) {
        kv("TCP с SYN", std::to_string(s->tcpConns));
        long long bad = s->tcpNoAnswer;
        if (s->noInboundTcp)   // односторонний дамп: ответов не видно, «0» было бы враньём
            kv("Без ответа", "н/д (нет входящих)", &kDim);
        else
            kv("Без ответа", std::to_string(bad) + "  (" + pct(bad, s->tcpConns) + ")",
               bad ? &kBad : nullptr);
        if (!s->hsRtt.empty()) {
            std::vector<long long> r = s->hsRtt;
            std::nth_element(r.begin(), r.begin() + r.size() / 2, r.end());
            char b[32]; snprintf(b, sizeof(b), "%.1f мс", r[r.size() / 2] / 1000.0);
            kv("RTT (медиана)", b);
        }
        kv("Ретрансмиссии", pct(s->outRetrans, s->outDataSegs),
           (s->outDataSegs > 0 && s->outRetrans * 20 > s->outDataSegs) ? &kWarn : nullptr);
        kv("DNS-запросов", std::to_string(s->dnsQueries));
        kv("DNS без ответа", std::to_string(s->dnsNoAnswer), s->dnsNoAnswer ? &kWarn : nullptr);
        kv("NXDOMAIN", std::to_string(s->dnsNx));
    }
    ImGui::EndChild();

    // --- блокировки ---
    if (s) {
        ImGui::Spacing();
        // причины-не-блокировки (UDP_SESSION, TLS_CLIENT_CERT) — отдельным блоком ниже
        bool anyReasonBlock = false, anyReasonOther = false;
        for (const auto& r : s->blockReasons)
            (blockReasonIsBlock(r.code) ? anyReasonBlock : anyReasonOther) = true;
        // таблица причин: block — признаки блокировок, иначе прочие проблемы связи
        auto drawReasons = [&](const char* id, bool block) {
            if (!ImGui::BeginTable(id, 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                          ImGuiTableFlags_SizingStretchProp))
                return;
            ImGui::TableSetupColumn("Причина", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableSetupColumn("Ресурс", ImGuiTableColumnFlags_WidthStretch, 1.1f);
            ImGui::TableSetupColumn("Соед.", ImGuiTableColumnFlags_WidthFixed);
            ImGui::TableSetupColumn("Что видно в дампе", ImGuiTableColumnFlags_WidthStretch, 2.4f);
            ImGui::TableHeadersRow();
            for (const auto& r : s->blockReasons) {
                if (blockReasonIsBlock(r.code) != block) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                const bool soft = !block || r.code == "TLS_RST" || r.code == "UDP_DROP";
                ImGui::TextColored(soft ? kWarn : kBad, "%s", r.code.c_str());
                if (ImGui::BeginItemTooltip()) {
                    ImGui::TextUnformatted(blockReasonTitle(r.code));
                    ImGui::Separator();
                    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32.0f);
                    ImGui::TextUnformatted(blockReasonAdvice(r.code));
                    ImGui::PopTextWrapPos();
                    ImGui::EndTooltip();
                }
                ImGui::TableNextColumn();
                if (r.target != r.ip) ImGui::Text("%s  (%s)", r.target.c_str(), r.ip.c_str());
                else ImGui::TextUnformatted(r.target.c_str());
                ImGui::TableNextColumn(); ImGui::Text("%d", r.conns);
                ImGui::TableNextColumn(); ImGui::TextWrapped("%s", r.detail.c_str());
            }
            ImGui::EndTable();
            ImGui::TextColored(kDim, "Наведите на код причины — подсказка, что сказать абоненту.");
        };
        const bool anyBlock = !s->blockedIps.empty() || !s->blockedSnis.empty() ||
                              anyReasonBlock || s->silentDrops || s->sniRsts ||
                              s->ttlInj || s->forgedRsts || s->httpStubs;
        {
            // заголовок красный; первые секунды после загрузки — плавно пульсирует
            ImVec4 hc = anyBlock ? kBad : kGood;
            const float since = (float)(ImGui::GetTime() - s_sumT0);
            if (anyBlock && animProgress(s_sumT0, 4.0f) < 1) {
                const float p = 0.5f + 0.5f * cosf(since * 6.2831853f);   // 1 Гц, к концу — 1
                hc.w *= 0.40f + 0.60f * p;
            }
            ImGui::PushStyleColor(ImGuiCol_Text, hc);
            ImGui::PushStyleColor(ImGuiCol_Separator, withA(hc, hc.w * 0.45f));
            ImGui::SeparatorText(anyBlock ? "Признаки блокировок" : "Признаков блокировок нет");
            ImGui::PopStyleColor(2);
        }
        if (anyBlock) {
            ImGui::Text("Тихий обрыв после ClientHello: %lld   RST на SNI: %lld   "
                        "Поддельных RST: %lld (по TTL: %lld)   HTTP-заглушек: %lld",
                        s->silentDrops, s->sniRsts, s->forgedRsts, s->ttlInj, s->httpStubs);
            if (anyReasonBlock) drawReasons("##reasons", true);
            if (!s->blockedSnis.empty() &&
                ImGui::BeginTable("##bsni", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                               ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Домен (SNI)");
                ImGui::TableSetupColumn("Как блокируется");
                ImGui::TableHeadersRow();
                for (const auto& kvp : s->blockedSnis) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextColored(kBad, "%s", kvp.first.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(kvp.second.c_str());
                }
                ImGui::EndTable();
                ImGui::TextColored(kDim, "Если на том же адресе (CDN) работают другие сайты, адрес "
                                         "целиком не помечается — в таблице соединений красные только "
                                         "строки с этим доменом.");
            }
            if (!s->blockedIps.empty() &&
                ImGui::BeginTable("##bip", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
                                              ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Адрес (обрыв по SNI, поддельный RST, SYN или UDP без ответа)");
                ImGui::TableSetupColumn("Имя");
                ImGui::TableSetupColumn("Страна / ASN");
                ImGui::TableHeadersRow();
                for (const auto& ip : s->blockedIps) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextColored(kBad, "%s", ip.c_str());
                    ImGui::TableNextColumn();
                    auto nm = ds.ipName.find(ip);
                    ImGui::TextUnformatted(nm == ds.ipName.end() ? "" : nm->second.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(geoOf(v.ipCache.get(), ip).c_str());
                }
                ImGui::EndTable();
            }
            ImGui::TextColored(kDim, "Подробности и методика — «Блокировки» (режим 2), вывод в журнале.");
        }
        // оборвавшиеся UDP-сессии (игры, голос): проблема связи, но не блокировка
        if (anyReasonOther) {
            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_Text, kWarn);
            ImGui::PushStyleColor(ImGuiCol_Separator, withA(kWarn, kWarn.w * 0.45f));
            ImGui::SeparatorText("Другие проблемы связи (не блокировка)");
            ImGui::PopStyleColor(2);
            drawReasons("##reasonsOther", false);
        }

        // --- топ адресов по объёму ---
        ImGui::Spacing();
        ImGui::SeparatorText("Куда уходит трафик (топ по объёму)");
        std::vector<std::pair<long long, std::string>> top;
        for (const auto& kvp : s->bytesByIp) top.push_back({ kvp.second, kvp.first });
        std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
        if (top.size() > 15) top.resize(15);
        const long long mx = top.empty() ? 1 : std::max(1LL, top.front().first);
        if (ImGui::BeginTable("##top", 3, ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("a", ImGuiTableColumnFlags_WidthStretch, 1.2f);
            ImGui::TableSetupColumn("b", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableSetupColumn("c", ImGuiTableColumnFlags_WidthStretch, 1.6f);
            int row = 0;
            for (const auto& t : top) {
                // полосы «вырастают» по очереди сверху вниз
                const float grow = easeOut(animProgress(s_sumT0 + 0.04 * row++, 0.6f));
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                auto nm = ds.ipName.find(t.second);
                if (nm != ds.ipName.end()) ImGui::Text("%s  (%s)", nm->second.c_str(), t.second.c_str());
                else ImGui::TextUnformatted(t.second.c_str());
                ImGui::TableNextColumn();
                ImGui::TextColored(kDim, "%s", geoOf(v.ipCache.get(), t.second).c_str());
                ImGui::TableNextColumn();
                ImGui::ProgressBar((float)((double)t.first / mx) * grow, ImVec2(-1, 0),
                                   fmtBytes(t.first).c_str());
            }
            ImGui::EndTable();
        }
    }
}

// ------------------------------------------------------------------
// «Соединения»
// ------------------------------------------------------------------
enum Col { C_PROTO, C_LOCAL, C_REMOTE, C_NAME, C_GEO, C_APP, C_PKTS, C_OUT, C_IN, C_START, C_DUR,
           C_STATE, C_TTL, C_TLS, C_COUNT };

// имя потока: SNI, иначе Host нешифрованного HTTP (оба — из самого потока), иначе DNS
const std::string& rowName(const FlowRow& r) {
    if (!r.sni.empty()) return r.sni;
    return r.httpHost.empty() ? r.dnsName : r.httpHost;
}

// Фильтр: какие потоки попадают в таблицу. Зовётся до отрисовки счётчика
// «показано N из M», иначе он показывал бы число прошлого кадра.
void filterOrder(const View& v) {
    const Dataset& ds = *v.ds;
    const DumpSummary* s = v.summary.get();
    s_geo.assign(ds.flows.size(), std::string());
    for (size_t i = 0; i < ds.flows.size(); i++) s_geo[i] = geoOf(v.ipCache.get(), ds.flows[i].remoteIp);

    const std::string f = lowerAscii(s_flowFilter);
    s_order.clear();
    for (size_t i = 0; i < ds.flows.size(); i++) {
        const FlowRow& r = ds.flows[i];
        if (s_proto == 1 && r.proto != "TCP") continue;
        if (s_proto == 2 && r.proto != "UDP") continue;
        if (s_proto == 3 && (r.proto == "TCP" || r.proto == "UDP")) continue;
        if (s_onlyProblems && !r.problem && !isBlocked(s, r)) continue;
        if (!f.empty() && r.search.find(f) == std::string::npos &&
            lowerAscii(s_geo[i]).find(f) == std::string::npos) continue;
        s_order.push_back((int)i);
    }
}

// Сортировка уже отфильтрованного s_order по колонке таблицы.
void sortOrder(const View& v, const ImGuiTableSortSpecs* specs) {
    const Dataset& ds = *v.ds;
    const DumpSummary* s = v.summary.get();
    if (!specs || specs->SpecsCount == 0) return;
    const ImGuiTableColumnSortSpecs& sp = specs->Specs[0];
    const bool asc = sp.SortDirection == ImGuiSortDirection_Ascending;
    const int col = (int)sp.ColumnUserID;
    // «блокировка» в колонке состояния берётся из сводки (isBlocked), а не из
    // r.state — сортируем по тому, что видно: блокировка > проблема > прочее.
    std::vector<char> blocked;
    if (col == C_STATE) {
        blocked.assign(ds.flows.size(), 0);
        for (int i : s_order) blocked[(size_t)i] = isBlocked(s, ds.flows[(size_t)i]) ? 1 : 0;
    }
    auto key = [&](const FlowRow& r) -> long long {
        switch (col) {
        case C_PKTS:  return r.pktsIn + r.pktsOut;
        case C_OUT:   return r.bytesOut;
        case C_IN:    return r.bytesIn;
        case C_START: return r.firstUs;
        case C_DUR:   return (r.firstUs >= 0) ? r.lastUs - r.firstUs : -1;
        case C_STATE: return (blocked[(size_t)(&r - ds.flows.data())] ? 200 : 0) +
                             (r.problem ? 100 : 0) + r.state;
        case C_TTL:   return r.ttlMin;
        default:      return 0;
        }
    };
    auto str = [&](int i) -> const std::string& {
        const FlowRow& r = ds.flows[(size_t)i];
        switch (col) {
        case C_PROTO:  return r.proto;
        case C_LOCAL:  return r.localIp;
        case C_REMOTE: return r.remoteIp;
        case C_NAME:   return rowName(r);
        case C_GEO:    return s_geo[(size_t)i];
        case C_APP:    return r.app;
        default:       return r.tlsClient.empty() ? r.ja4 : r.tlsClient;
        }
    };
    const bool numeric = col == C_PKTS || col == C_OUT || col == C_IN || col == C_START ||
                         col == C_DUR || col == C_STATE || col == C_TTL;
    std::stable_sort(s_order.begin(), s_order.end(), [&](int a, int b) {
        const FlowRow& ra = ds.flows[(size_t)a];
        const FlowRow& rb = ds.flows[(size_t)b];
        int c;
        if (numeric) { long long ka = key(ra), kb = key(rb); c = ka < kb ? -1 : ka > kb ? 1 : 0; }
        else {
            c = str(a).compare(str(b));
            if (c == 0 && (col == C_LOCAL || col == C_REMOTE)) {
                int pa = col == C_LOCAL ? ra.localPort : ra.remotePort;
                int pb = col == C_LOCAL ? rb.localPort : rb.remotePort;
                c = pa < pb ? -1 : pa > pb ? 1 : 0;
            }
        }
        return asc ? c < 0 : c > 0;
    });
}

void flowTooltip(const FlowRow& r, bool blocked) {
    if (!ImGui::BeginItemTooltip()) return;
    ImGui::Text("%s  %s  ->  %s", r.proto.c_str(), endpoint(r.localIp, r.localPort).c_str(),
                endpoint(r.remoteIp, r.remotePort).c_str());
    if (r.proto == "TCP") {
        ImGui::Text("SYN %d / SYN-ACK %d   (входящих: SYN %d / SYN-ACK %d)",
                    r.synOut, r.synAckIn, r.synIn, r.synAckOut);
        ImGui::Text("RST от сервера %d, от абонента %d;  FIN %d / %d", r.rstIn, r.rstOut, r.finIn, r.finOut);
        if (r.state == FS_ONE_WAY)
            ImGui::TextColored(r.problem ? kWarn : kDim, "%s", r.problem
                ? "Абонент отправлял данные, а сервер не прислал ни байта (ни RST, ни FIN): запрос до сервера "
                  "не дошёл или ответ отброшен по пути."
                : "Абонент отправил данные в самом конце записи — ответ сервера мог в неё не попасть.");
    }
    if (!r.dnsCname.empty()) ImGui::Text("DNS: %s", r.dnsCname.c_str());
    if (!r.app.empty())
        ImGui::Text("Приложение: %s — %s", r.app.c_str(),
                    r.appByContent ? "по содержимому пакетов" : "догадка по номеру порта");
    if (!r.httpHost.empty()) ImGui::Text("HTTP (без шифрования), Host: %s", r.httpHost.c_str());
    if (!r.msBg.empty())
        ImGui::TextColored(kDim, "Фоновая загрузка Windows/Microsoft (%s): скорость ограничивает "
                                 "сама Windows — на тариф и канал по ней не судить.", r.msBg.c_str());
    if (r.httpStatus > 0) {
        std::string line = "Ответ сервера: " + std::to_string(r.httpStatus);
        if (r.httpReqUs >= 0 && r.httpRespUs >= r.httpReqUs)
            line += " через " + std::to_string((r.httpRespUs - r.httpReqUs) / 1000) + " мс после запроса";
        if (r.httpStatus >= 400) ImGui::TextColored(kWarn, "%s", line.c_str());
        else ImGui::TextUnformatted(line.c_str());
        if (!r.httpLocation.empty()) ImGui::Text("Перенаправление на: %s", r.httpLocation.c_str());
    }
    if (!r.httpBlockMark.empty())
        ImGui::TextColored(kBad, "Похоже на страницу-заглушку о блокировке (найдено «%s»).",
                           r.httpBlockMark.c_str());
    if (r.ttlMin >= 0) ImGui::Text("TTL входящих: %d–%d", r.ttlMin, r.ttlMax);
    if (!r.ja4.empty()) ImGui::Text("JA4: %s", r.ja4.c_str());
    if (r.ech) ImGui::TextUnformatted("ClientHello с ECH: настоящий домен зашифрован, в SNI — "
                                      "публичное имя провайдера");
    if (r.certReq) {
        std::string line = "TLS: сервер запросил сертификат клиента (mTLS) — ";
        line += r.clientCert == 0 ? "устройство прислало пустой"
              : r.clientCert == 1 ? "устройство предъявило сертификат"
              : "ответа устройства не видно";
        if (r.tlsAlertIn >= 0) line += "; ошибка TLS от сервера, код " + std::to_string(r.tlsAlertIn);
        if (r.mtlsReqUs >= 0) {
            char b[96];
            if (r.mtlsRespUs >= r.mtlsReqUs)
                snprintf(b, sizeof(b), "; ответ на запрос через %.1f с", (r.mtlsRespUs - r.mtlsReqUs) / 1e6);
            else
                snprintf(b, sizeof(b), "; на запрос сервер не ответил");
            line += b;
        }
        if (r.certProblem) {
            ImGui::TextColored(kWarn, "%s", line.c_str());
            ImGui::TextColored(kDim, "Не блокировка и не сеть: сервис требует сертификат клиента "
                                     "(брокер, банк, корп. доступ) — его нужно установить на устройство.");
        } else {
            ImGui::TextUnformatted(line.c_str());
        }
    }
    // blockedIps/blockedSnis — вывод самой программы по дампу, не внешний реестр
    if (blocked) ImGui::TextColored(kBad, "Программа считает адрес/имя недоступным (см. «Обзор»): "
                                          "по одному дампу не определить, где теряются пакеты.");
    ImGui::TextColored(kDim, r.proto == "TCP"
        ? "Двойной щелчок — временной профиль соединения; ПКМ — копировать / анализ по этому адресу"
        : "ПКМ — копировать / анализ по этому адресу");
    ImGui::EndTooltip();
}

void drawFlows(const View& v) {
    if (!v.ds) { ImGui::TextColored(kDim, "Дамп не загружен."); return; }
    const Dataset& ds = *v.ds;
    const DumpSummary* s = v.summary.get();

    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 18);
    ImGui::InputTextWithHint("##ff", "фильтр: IP, порт, домен, приложение, страна…",
                             s_flowFilter, sizeof(s_flowFilter), ImGuiInputTextFlags_EscapeClearsAll);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 7);
    const char* protos[] = { "Все", "TCP", "UDP", "Прочие" };
    ImGui::Combo("##proto", &s_proto, protos, 4);
    ImGui::SameLine();
    ImGui::Checkbox("Только проблемные", &s_onlyProblems);
    ImGui::SetItemTooltip("Нет ответа на SYN, сброс без закрытия, трафик в одну сторону, "
                          "адреса/SNI из списка блокировок, HTTP-заглушки о блокировке.");

    const std::string f = s_flowFilter;
    if (v.generation != s_orderGen || f != s_orderFilter || s_proto != s_orderProto ||
        s_onlyProblems != s_orderProblems) {
        s_needRefilter = true;
        s_orderGen = v.generation; s_orderFilter = f;
        s_orderProto = s_proto; s_orderProblems = s_onlyProblems;
    }
    if (s_needRefilter) { filterOrder(v); s_needRefilter = false; s_needResort = true; }
    ImGui::SameLine();
    ImGui::TextColored(kDim, "показано %zu из %zu", s_order.size(), ds.flows.size());
    ImGui::SetItemTooltip("Прокрутка вбок: Shift + колесо мыши или полоса внизу таблицы.");

    const ImGuiTableFlags tf = ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable |
        ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersV | ImGuiTableFlags_BordersOuterH | ImGuiTableFlags_ScrollY |
        ImGuiTableFlags_ScrollX | ImGuiTableFlags_SizingFixedFit;
    const float em = ImGui::GetFontSize();
    pushPanelBg();                              // таблица с прокруткой — своё дочернее окно
    // полосы прокрутки толще обычных: таблица широкая, за тонкую полосу
    // трудно ухватиться (размер берётся при создании дочернего окна в BeginTable)
    ImGui::PushStyleVar(ImGuiStyleVar_ScrollbarSize, std::max(18.0f, em * 1.15f));
    const bool tableOpen = ImGui::BeginTable("##flows", C_COUNT, tf, ImVec2(0, 0));
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
    if (!tableOpen) return;
    // Шаг прокрутки вбок: ImGui сдвигает на 2 высоты шрифта за щелчок колеса,
    // для 14 колонок это слишком мелко — добавляем ещё 12 (примерно колонка за
    // щелчок). Текущее окно здесь — дочернее окно таблицы, и шаг ImGui к этому
    // моменту уже применён в его Begin, так что GetScrollX() его учитывает.
    if (ImGui::IsWindowHovered()) {
        const ImGuiIO& io = ImGui::GetIO();
        float wx = io.MouseWheelH;
        if (wx == 0.0f && io.KeyShift) wx = io.MouseWheel;
        if (wx != 0.0f) ImGui::SetScrollX(ImGui::GetScrollX() - wx * em * 12.0f);
    }
    ImGui::TableSetupScrollFreeze(0, 1);
    // не скрывается: на ней Selectable строки (ПКМ-меню и подсказка)
    ImGui::TableSetupColumn("Прот.",      ImGuiTableColumnFlags_NoHide, em * 3.5f, C_PROTO);
    ImGui::TableSetupColumn("Абонент",    ImGuiTableColumnFlags_DefaultHide, em * 10, C_LOCAL);
    ImGui::TableSetupColumn("Удалённый",  0, em * 10, C_REMOTE);
    ImGui::TableSetupColumn("Имя (SNI / Host / DNS)", 0, em * 13, C_NAME);
    ImGui::TableSetupColumn("Страна / ASN", 0, em * 15, C_GEO);
    ImGui::TableSetupColumn("Приложение", 0, em * 9, C_APP);
    ImGui::TableSetupColumn("Пакеты",     0, em * 4, C_PKTS);
    ImGui::TableSetupColumn("Отправлено", 0, em * 5, C_OUT);
    ImGui::TableSetupColumn("Принято",    ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending,
                            em * 5, C_IN);
    ImGui::TableSetupColumn("Начало",     ImGuiTableColumnFlags_DefaultHide, em * 5, C_START);
    ImGui::TableSetupColumn("Длит.",      0, em * 5, C_DUR);
    ImGui::TableSetupColumn("Состояние",  0, em * 8, C_STATE);
    ImGui::TableSetupColumn("TTL",        ImGuiTableColumnFlags_DefaultHide, em * 4, C_TTL);
    ImGui::TableSetupColumn("TLS-клиент (JA4)", 0, em * 10, C_TLS);
    ImGui::TableHeadersRow();

    if (ImGuiTableSortSpecs* sp = ImGui::TableGetSortSpecs()) {
        if (sp->SpecsDirty) { s_needResort = true; sp->SpecsDirty = false; }
        if (s_needResort) { sortOrder(v, sp); s_needResort = false; }
    } else s_needResort = false;

    ImGuiListClipper clip;
    clip.Begin((int)s_order.size());
    while (clip.Step()) {
        for (int row = clip.DisplayStart; row < clip.DisplayEnd; row++) {
            const size_t idx = (size_t)s_order[(size_t)row];
            if (idx >= ds.flows.size()) continue;
            const FlowRow& r = ds.flows[idx];
            const bool blocked = isBlocked(s, r);
            ImGui::PushID((int)idx);
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(C_PROTO);
            // щелчок выбирает строку для «Профиля соединения», двойной — открывает его
            if (ImGui::Selectable(r.proto.c_str(), (int)idx == s_wfIdx,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap |
                                  ImGuiSelectableFlags_AllowDoubleClick)) {
                s_wfIdx = (int)idx;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) s_selectTab = TAB_WATERFALL;
            }
            const bool ctxOpen = ImGui::BeginPopupContextItem("##row");
            if (!ctxOpen) flowTooltip(r, blocked);
            if (ctxOpen) {
                if (ImGui::MenuItem("Временной профиль (waterfall)", nullptr, false, r.proto == "TCP")) {
                    s_wfIdx = (int)idx;
                    s_selectTab = TAB_WATERFALL;
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Копировать удалённый IP")) ImGui::SetClipboardText(r.remoteIp.c_str());
                if (!rowName(r).empty() && ImGui::MenuItem("Копировать имя"))
                    ImGui::SetClipboardText(rowName(r).c_str());
                if (ImGui::MenuItem("Копировать фильтр Wireshark"))
                    ImGui::SetClipboardText(wiresharkFilter(r).c_str());
                ImGui::Separator();
                if (ImGui::MenuItem("Показать только этот адрес"))
                    snprintf(s_flowFilter, sizeof(s_flowFilter), "%s", r.remoteIp.c_str());
                if (ImGui::MenuItem("Анализ блокировок по этому адресу", nullptr, false, !jobBusy())) {
                    snprintf(s_target, sizeof(s_target), "%s", r.remoteIp.c_str());
                    startConnAnalysis(r.remoteIp);
                }
                if (ImGui::MenuItem("Кому принадлежит адрес", nullptr, false, !jobBusy()))
                    startIpOwner(r.remoteIp);
                // cheburcheck.ru — только по этому щелчку и только выбранная цель
                ImGui::Separator();
                const std::string nm = rowName(r);
                if (!nm.empty() && ImGui::MenuItem(("Проверить " + nm + " в cheburcheck.ru").c_str())) {
                    rknCheck(nm);
                    s_selectTab = TAB_RKN;
                }
                if (ImGui::MenuItem("Проверить IP в cheburcheck.ru", nullptr, false, !isPrivateIp(r.remoteIp))) {
                    rknCheck(r.remoteIp);
                    s_selectTab = TAB_RKN;
                }
                ImGui::EndPopup();
            }

            if (ImGui::TableSetColumnIndex(C_LOCAL))
                ImGui::TextUnformatted(endpoint(r.localIp, r.localPort).c_str());
            if (ImGui::TableSetColumnIndex(C_REMOTE)) {
                if (blocked) ImGui::TextColored(kBad, "%s", endpoint(r.remoteIp, r.remotePort).c_str());
                else ImGui::TextUnformatted(endpoint(r.remoteIp, r.remotePort).c_str());
            }
            if (ImGui::TableSetColumnIndex(C_NAME)) {
                const std::string& n = rowName(r);
                if (!r.sni.empty() || !r.httpHost.empty()) ImGui::TextUnformatted(n.c_str());
                else ImGui::TextColored(kDim, "%s", n.c_str());   // имя из DNS — менее точное
            }
            if (ImGui::TableSetColumnIndex(C_GEO)) ImGui::TextUnformatted(s_geo.size() > idx ? s_geo[idx].c_str() : "");
            if (ImGui::TableSetColumnIndex(C_APP)) {
                if (r.appByContent) ImGui::TextUnformatted(r.app.c_str());
                else ImGui::TextColored(kDim, "%s", r.app.c_str());   // догадка по порту
                if (r.ech) { ImGui::SameLine(); ImGui::TextColored(kWarn, "ECH"); }
            }
            if (ImGui::TableSetColumnIndex(C_PKTS)) ImGui::Text("%lld/%lld", r.pktsOut, r.pktsIn);
            if (ImGui::TableSetColumnIndex(C_OUT)) ImGui::TextUnformatted(fmtBytes(r.bytesOut).c_str());
            if (ImGui::TableSetColumnIndex(C_IN)) ImGui::TextUnformatted(fmtBytes(r.bytesIn).c_str());
            if (ImGui::TableSetColumnIndex(C_START))
                ImGui::TextUnformatted(r.firstUs >= 0 ? fmtDur(r.firstUs / 1e6).c_str() : "");
            if (ImGui::TableSetColumnIndex(C_DUR))
                ImGui::TextUnformatted(r.firstUs >= 0 ? fmtDur((r.lastUs - r.firstUs) / 1e6).c_str() : "");
            if (ImGui::TableSetColumnIndex(C_STATE)) {
                if (blocked) ImGui::TextColored(kBad, "блокировка");
                else ImGui::TextColored(stateColor(r), "%s", stateText(r.state));
            }
            if (ImGui::TableSetColumnIndex(C_TTL)) {
                if (r.ttlMin < 0) ImGui::TextUnformatted("");
                else if (r.ttlMin == r.ttlMax) ImGui::Text("%d", r.ttlMin);
                else ImGui::TextColored(kWarn, "%d–%d", r.ttlMin, r.ttlMax);
            }
            if (ImGui::TableSetColumnIndex(C_TLS)) {
                const std::string& t = r.tlsClient.empty() ? r.ja4 : r.tlsClient;
                if (r.ja4Kind == JA4K_FAKE) ImGui::TextColored(kBad, "%s", t.c_str());
                else if (r.ja4Kind == JA4K_LIBRARY) ImGui::TextColored(kWarn, "%s", t.c_str());
                else ImGui::TextUnformatted(t.c_str());
            }
            ImGui::PopID();
        }
    }
    clip.End();
    ImGui::EndTable();
}

// ------------------------------------------------------------------
// «Профиль соединения» (waterfall): события TCP-соединения на шкале
// времени — кто что прислал и где была тишина. Шкала сжатая (по логарифму
// паузы), чтобы 1 мс и 5 с были видны на одном графике. События собраны
// при загрузке (FlowRow::wf), здесь только отрисовка.
// ------------------------------------------------------------------
int s_wfHover = -1;              // событие под мышью на графике (подсветка в таблице)

std::string fmtUs(long long us) {
    char b[64];
    if (us < 0) us = 0;
    if (us < 10000) snprintf(b, sizeof(b), "%.1f мс", us / 1000.0);
    else if (us < 1000000) snprintf(b, sizeof(b), "%lld мс", us / 1000);
    else if (us < 120000000) snprintf(b, sizeof(b), "%.2f с", us / 1e6);
    else return fmtDur(us / 1e6);
    return b;
}

// Сводка по событиям соединения — для заголовка, подписей и подсказок.
struct WfInfo {
    long long t0 = 0;              // первое событие (от начала записи)
    long long rtt = -1;            // SYN → SYN-ACK (только без повторов SYN)
    int synCount = 0;
    long long helloUs = -1;        // первый ClientHello / HTTP-запрос
    const char* helloWhat = "";
    long long answerUs = -1;       // первое, что пришло от сервера после него
    long long recEnd = 0;          // конец записи (от начала дампа)
    std::vector<std::pair<long long, long long>> gaps;   // тишина: ни одного события
};

WfInfo wfInfo(const FlowRow& r, const Dataset& ds) {
    WfInfo w;
    w.t0 = r.wf.empty() ? 0 : r.wf.front().us;
    w.recEnd = (long long)(ds.durSec * 1e6);
    long long synUs = -1;
    std::vector<std::pair<long long, long long>> iv;
    for (const FlowEvent& e : r.wf) {
        iv.push_back({ e.us, e.endUs });
        if (e.kind == FE_SYN && e.out && synUs < 0) { synUs = e.us; w.synCount = e.count; }
        if (e.kind == FE_SYNACK && !e.out && synUs >= 0 && w.rtt < 0 && w.synCount == 1)
            w.rtt = e.us - synUs;
        if ((e.kind == FE_HELLO || e.kind == FE_HTTPREQ) && e.out && w.helloUs < 0) {
            w.helloUs = e.us;
            w.helloWhat = e.kind == FE_HELLO ? "ClientHello" : "HTTP-запроса";
        } else if (!e.out && w.helloUs >= 0 && w.answerUs < 0 && e.kind != FE_SYNACK)
            w.answerUs = e.us;
    }
    std::sort(iv.begin(), iv.end());
    long long end = -1;
    for (const auto& p : iv) {
        if (end >= 0 && p.first > end) w.gaps.push_back({ end, p.first });
        end = std::max(end, p.second);
    }
    return w;
}

std::string wfTitle(const FlowEvent& e) {
    std::string s;
    switch (e.kind) {
    case FE_SYN:      s = "SYN"; break;
    case FE_SYNACK:   s = "SYN-ACK"; break;
    case FE_HELLO:    s = "ClientHello"; break;
    case FE_HTTPREQ:  s = "HTTP-запрос"; break;
    case FE_DATA:     s = fmtBytes(e.bytes); break;
    case FE_RETX:     s = "повтор"; break;
    case FE_HTTPRESP: s = "HTTP " + std::to_string(e.code); break;
    case FE_RST:      s = "RST"; break;
    case FE_FIN:      s = "FIN"; break;
    }
    if (e.count > 1 && e.kind != FE_DATA) s += " ×" + std::to_string(e.count);
    return s;
}

// Признаки того, что RST прислал не сервер, — те же, что в connForgedRst
// (режим 2), только для показа: на вердикты программы не влияет. Возвращает
// сумму баллов (≥2 — похоже на подделку).
int wfRstForged(const FlowRow& r, size_t i, const WfInfo& w, std::vector<std::string>* why) {
    const FlowEvent& e = r.wf[i];
    if (e.kind != FE_RST || e.out) return 0;
    int score = 0;
    auto add = [&](int s, const std::string& t) { score += s; if (why) why->push_back(t); };
    if (e.ttl >= 0 && e.ttlRef >= 0 && e.ttl - e.ttlRef >= 5)
        add(e.code == 1 ? 1 : 2,
            "TTL " + std::to_string(e.ttl) + ", а у " + (e.code == 1 ? "данных" : "SYN-ACK") +
            " сервера " + std::to_string(e.ttlRef) + " — на " + std::to_string(e.ttl - e.ttlRef) +
            " хопов ближе к абоненту");
    if (w.rtt >= 3000 && w.helloUs >= 0 && e.us >= w.helloUs && (e.us - w.helloUs) * 2 < w.rtt)
        add(1, "через " + fmtUs(e.us - w.helloUs) + " после " + w.helloWhat + " при RTT " +
               fmtUs(w.rtt) + " — быстрее, чем мог ответить сервер");
    // счётчики — из wfAdd, по тем же правилам, что inAfterRst / rstBurst
    if (e.afterRst >= 2)
        add(2, "после RST сервер прислал ещё " + std::to_string(e.afterRst) +
               " пакет(ов) — сам он соединение не сбрасывал");
    if (e.burst >= 2) add(1, std::to_string(e.burst) + " RST подряд за 200 мс");
    // как в connForgedRst: сервер слал и после RST — IP ID подобран, не вычитаем
    if (e.serverId && score > 0 && e.afterRst < 2)
        add(-2, "но IP ID продолжает счётчик сервера и TTL тот же — похоже на RST самого сервера");
    return std::max(score, 0);
}

// Подробности события — строки для таблицы и подсказки.
std::vector<std::string> wfDetail(const FlowRow& r, size_t i, const WfInfo& w) {
    const FlowEvent& e = r.wf[i];
    std::vector<std::string> d;
    const long long span = e.endUs - e.us;
    switch (e.kind) {
    case FE_SYN:
        if (e.count > 1) d.push_back("повторы SYN за " + fmtUs(span) + " — сервер долго не отвечал");
        break;
    case FE_SYNACK:
        if (w.rtt >= 0 && i > 0) d.push_back("RTT " + fmtUs(w.rtt));
        break;
    case FE_HELLO:
        if (!r.sni.empty()) d.push_back("SNI " + r.sni + (r.ech ? " (ECH: настоящий домен скрыт)" : ""));
        break;
    case FE_HTTPREQ:
        if (!r.httpHost.empty()) d.push_back("Host: " + r.httpHost);
        break;
    case FE_DATA: case FE_RETX:
        d.push_back(std::to_string(e.count) + " пак., " + fmtBytes(e.bytes) +
                    (span > 0 ? " за " + fmtUs(span) : std::string()));
        if (e.kind == FE_RETX)
            d.push_back(e.out ? "абонент повторяет уже отправленное — до сервера не доходит или нет подтверждения"
                              : "сервер повторяет уже присланное — не видит подтверждения абонента");
        break;
    case FE_HTTPRESP:
        if (!r.httpLocation.empty()) d.push_back("перенаправление на " + r.httpLocation);
        if (!r.httpBlockMark.empty()) d.push_back("похоже на заглушку о блокировке («" + r.httpBlockMark + "»)");
        break;
    case FE_RST:
        if (e.out) d.push_back("сброс со стороны абонента");
        else wfRstForged(r, i, w, &d);
        break;
    default: break;
    }
    if (!e.out && e.ttl >= 0 && e.kind != FE_RST) d.push_back("TTL " + std::to_string(e.ttl));
    return d;
}

ImVec4 wfColor(const FlowRow& r, const FlowEvent& e) {
    switch (e.kind) {
    case FE_SYN: case FE_SYNACK:   return kAccent;
    case FE_HELLO: case FE_HTTPREQ: return mix(kAccent, kBad, 0.45f);
    case FE_DATA:                  return withA(e.out ? kAccent : kGood, 0.75f);
    case FE_RETX:                  return kWarn;
    case FE_HTTPRESP:              return (e.code >= 400 || !r.httpBlockMark.empty()) ? kWarn : kGood;
    case FE_RST:                   return kBad;
    default:                       return kDim;
    }
}

// Текст профиля — для «Копировать» (в заявку, в чат).
std::string wfText(const FlowRow& r, const WfInfo& w, const char* remoteName) {
    std::string s = r.proto + "  " + endpoint(r.localIp, r.localPort) + "  ->  " +
                    endpoint(r.remoteIp, r.remotePort);
    if (!rowName(r).empty()) s += "  (" + rowName(r) + ")";
    s += "\n";
    long long prevEnd = -1;
    for (size_t i = 0; i < r.wf.size(); i++) {
        const FlowEvent& e = r.wf[i];
        char b[64];
        snprintf(b, sizeof(b), "%12s  ", ("+" + fmtUs(e.us - w.t0)).c_str());
        s += b;
        if (prevEnd >= 0 && e.us > prevEnd) s += "[пауза " + fmtUs(e.us - prevEnd) + "]  ";
        s += e.out ? "абонент -> " : std::string(remoteName) + " -> ";
        s += wfTitle(e);
        for (const auto& x : wfDetail(r, i, w)) s += "; " + x;
        s += "\n";
        prevEnd = std::max(prevEnd, e.endUs);
    }
    if (w.recEnd > prevEnd && prevEnd >= 0) s += "до конца записи тишина " + fmtUs(w.recEnd - prevEnd) + "\n";
    return s;
}

// Выбор соединения прямо в «Профиле»: сначала удалённый адрес, затем одно из
// его TCP-соединений. Список адресов собирается раз на набор/сводку.
struct WfIp {
    std::string ip, name, search;  // search — ip и имя в нижнем регистре (фильтр)
    std::vector<int> flows;        // индексы ds.flows (только TCP), по времени начала
    int problems = 0, blocked = 0;
    long long bytes = 0;
};
std::vector<WfIp> s_wfIps;
std::string s_wfIpLongest;       // самый длинный адрес — ширина колонки в списке
unsigned s_wfIpsGen = ~0u;
char s_wfIpFilter[128] = "";

void wfBuildIps(const View& v) {
    if (s_wfIpsGen == v.generation) return;
    s_wfIpsGen = v.generation;
    s_wfIps.clear();
    s_wfIpLongest.clear();
    if (!v.ds) return;
    const Dataset& ds = *v.ds;
    std::unordered_map<std::string, size_t> at;
    for (size_t i = 0; i < ds.flows.size(); i++) {
        const FlowRow& r = ds.flows[i];
        if (r.proto != "TCP") continue;
        auto it = at.find(r.remoteIp);
        if (it == at.end()) {
            it = at.emplace(r.remoteIp, s_wfIps.size()).first;
            s_wfIps.emplace_back();
            s_wfIps.back().ip = r.remoteIp;
        }
        WfIp& e = s_wfIps[it->second];
        e.flows.push_back((int)i);
        if (r.problem) e.problems++;
        if (isBlocked(v.summary.get(), r)) e.blocked++;
        e.bytes += r.bytesIn + r.bytesOut;
        if (e.name.empty()) e.name = rowName(r);
    }
    for (WfIp& e : s_wfIps) {
        auto n = ds.ipName.find(e.ip);
        if (n != ds.ipName.end() && !n->second.empty()) e.name = n->second;
        std::stable_sort(e.flows.begin(), e.flows.end(), [&](int a, int b) {
            return ds.flows[(size_t)a].firstUs < ds.flows[(size_t)b].firstUs;
        });
        e.search = lowerAscii(e.ip + " " + e.name);
        if (e.ip.size() > s_wfIpLongest.size()) s_wfIpLongest = e.ip;
    }
    // сначала заблокированные, потом с проблемами, дальше — по объёму
    std::stable_sort(s_wfIps.begin(), s_wfIps.end(), [](const WfIp& a, const WfIp& b) {
        if ((a.blocked > 0) != (b.blocked > 0)) return a.blocked > 0;
        if ((a.problems > 0) != (b.problems > 0)) return a.problems > 0;
        return a.bytes > b.bytes;
    });
}

// Какое соединение открыть при выборе адреса: заблокированное, проблемное, первое.
int wfPickFlow(const View& v, const WfIp& e) {
    const Dataset& ds = *v.ds;
    for (int i : e.flows) if (isBlocked(v.summary.get(), ds.flows[(size_t)i])) return i;
    for (int i : e.flows) if (ds.flows[(size_t)i].problem) return i;
    return e.flows.empty() ? -1 : e.flows[0];
}

std::string wfFlowLabel(const FlowRow& r, size_t k, size_t n) {
    std::string s = std::to_string(k + 1) + "/" + std::to_string(n) + "  +" + fmtUs(r.firstUs) + "  :" +
                    std::to_string(r.localPort) + " → :" + std::to_string(r.remotePort);
    const std::string nm = rowName(r);
    if (!nm.empty()) s += "  " + nm;
    s += "  " + fmtBytes(r.bytesIn + r.bytesOut);
    return s;
}

void drawWfPicker(const View& v) {
    const Dataset& ds = *v.ds;
    wfBuildIps(v);
    const float em = ImGui::GetFontSize();
    if (s_wfIps.empty()) {
        ImGui::TextColored(kDim, "В дампе нет TCP-соединений — временной профиль строится только для TCP.");
        return;
    }
    const FlowRow* cur = (s_wfIdx >= 0 && (size_t)s_wfIdx < ds.flows.size()) ? &ds.flows[(size_t)s_wfIdx] : nullptr;
    int curIp = -1;
    // в s_wfIps только TCP: выбранный во «Соединениях» UDP-поток к тому же адресу
    // не должен подставлять в список чужое TCP-соединение
    if (cur && cur->proto == "TCP")
        for (size_t i = 0; i < s_wfIps.size(); i++)
            if (s_wfIps[i].ip == cur->remoteIp) { curIp = (int)i; break; }

    // --- адрес ---
    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Адрес");
    ImGui::SameLine();
    std::string preview = "выберите адрес…";
    if (curIp >= 0) {
        const WfIp& e = s_wfIps[(size_t)curIp];
        preview = e.ip + (e.name.empty() ? std::string() : "  " + e.name);
    }
    ImGui::SetNextItemWidth(em * 22);
    ImGui::SetNextWindowSizeConstraints(ImVec2(em * 46, 0), ImVec2(FLT_MAX, FLT_MAX));
    if (ImGui::BeginCombo("##wfip", preview.c_str(), ImGuiComboFlags_HeightLarge)) {
        const bool appearing = ImGui::IsWindowAppearing();
        if (appearing) ImGui::SetKeyboardFocusHere();
        ImGui::SetNextItemWidth(-FLT_MIN);
        const bool enter = ImGui::InputTextWithHint("##wfipf", "фильтр: IP или имя", s_wfIpFilter,
                                                    sizeof(s_wfIpFilter), ImGuiInputTextFlags_EnterReturnsTrue);
        const std::string f = lowerAscii(trim(s_wfIpFilter));
        std::vector<int> shown;
        int selPos = -1;
        for (size_t i = 0; i < s_wfIps.size(); i++)
            if (f.empty() || s_wfIps[i].search.find(f) != std::string::npos) {
                if ((int)i == curIp) selPos = (int)shown.size();
                shown.push_back((int)i);
            }
        ImGui::TextColored(kDim, "%zu из %zu адресов; сверху — с блокировкой и проблемами", shown.size(), s_wfIps.size());
        if (enter && !shown.empty()) {
            s_wfIdx = wfPickFlow(v, s_wfIps[(size_t)shown[0]]);
            ImGui::CloseCurrentPopup();
        }
        const float nameX = ImGui::CalcTextSize(s_wfIpLongest.c_str()).x + em * 1.5f;
        ImGuiListClipper clip;
        clip.Begin((int)shown.size());
        if (appearing && selPos >= 0) clip.IncludeItemByIndex(selPos);
        while (clip.Step())
            for (int k = clip.DisplayStart; k < clip.DisplayEnd; k++) {
                const WfIp& e = s_wfIps[(size_t)shown[(size_t)k]];
                ImGui::PushID(shown[(size_t)k]);
                const bool colored = e.blocked > 0 || e.problems > 0;
                if (colored) ImGui::PushStyleColor(ImGuiCol_Text, e.blocked ? kBad : kWarn);
                if (ImGui::Selectable(e.ip.c_str(), k == selPos, ImGuiSelectableFlags_AllowOverlap))
                    s_wfIdx = wfPickFlow(v, e);
                if (colored) ImGui::PopStyleColor();
                if (appearing && k == selPos) ImGui::SetScrollHereY();
                ImGui::SameLine(nameX);
                if (!e.name.empty()) {
                    ImGui::TextColored(kAccent, "%s", e.name.c_str());
                    ImGui::SameLine();
                }
                std::string info = std::to_string(e.flows.size()) + " TCP · " + fmtBytes(e.bytes);
                const std::string geo = geoOf(v.ipCache.get(), e.ip);
                if (!geo.empty()) info += " · " + geo;
                ImGui::TextColored(kDim, "%s", info.c_str());
                if (e.blocked) { ImGui::SameLine(); ImGui::TextColored(kBad, "блокировка"); }
                else if (e.problems) { ImGui::SameLine(); ImGui::TextColored(kWarn, "проблемных %d", e.problems); }
                ImGui::PopID();
            }
        ImGui::EndCombo();
    }

    // --- соединение с этим адресом ---
    if (curIp < 0) return;
    const WfIp& e = s_wfIps[(size_t)curIp];
    size_t curK = 0;
    for (size_t k = 0; k < e.flows.size(); k++) if (e.flows[k] == s_wfIdx) curK = k;
    ImGui::SameLine();
    ImGui::TextUnformatted("Соединение");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(em * 26);
    ImGui::SetNextWindowSizeConstraints(ImVec2(em * 40, 0), ImVec2(FLT_MAX, FLT_MAX));
    const std::string cprev = wfFlowLabel(ds.flows[(size_t)e.flows[curK]], curK, e.flows.size());
    if (ImGui::BeginCombo("##wfconn", cprev.c_str(), ImGuiComboFlags_HeightLarge)) {
        const bool appearing = ImGui::IsWindowAppearing();
        ImGuiListClipper clip;
        clip.Begin((int)e.flows.size());
        if (appearing) clip.IncludeItemByIndex((int)curK);
        while (clip.Step())
            for (int k = clip.DisplayStart; k < clip.DisplayEnd; k++) {
                const int idx = e.flows[(size_t)k];
                const FlowRow& r = ds.flows[(size_t)idx];
                ImGui::PushID(idx);
                if (ImGui::Selectable(wfFlowLabel(r, (size_t)k, e.flows.size()).c_str(), idx == s_wfIdx,
                                      ImGuiSelectableFlags_AllowOverlap))
                    s_wfIdx = idx;
                if (appearing && (size_t)k == curK) ImGui::SetScrollHereY();
                ImGui::SameLine();
                if (isBlocked(v.summary.get(), r)) ImGui::TextColored(kBad, "блокировка");
                else ImGui::TextColored(stateColor(r), "%s", stateText(r.state));
                ImGui::PopID();
            }
        ImGui::EndCombo();
    }
}

void drawWaterfall(const View& v) {
    if (!v.ds) { ImGui::TextColored(kDim, "Дамп не загружен."); return; }
    const Dataset& ds = *v.ds;
    const float em = ImGui::GetFontSize();

    drawWfPicker(v);

    // листать по списку «Соединения» — с его фильтром и сортировкой
    int pos = -1;
    for (size_t k = 0; k < s_order.size(); k++)
        if (s_order[k] == s_wfIdx) { pos = (int)k; break; }
    auto step = [&](int dir) {
        for (int k = pos + dir; k >= 0 && k < (int)s_order.size(); k += dir) {
            const int i = s_order[(size_t)k];
            if ((size_t)i < ds.flows.size() && ds.flows[(size_t)i].proto == "TCP") { s_wfIdx = i; return; }
        }
    };
    ImGui::BeginDisabled(s_order.empty());
    if (ImGui::Button("← Пред.")) step(-1);
    ImGui::SameLine();
    if (ImGui::Button("След. →")) step(+1);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextColored(kDim, "TCP-соединения по списку «Соединения» (его фильтр и сортировка)");

    if (s_wfIdx < 0 || (size_t)s_wfIdx >= ds.flows.size()) {
        ImGui::Spacing();
        ImGui::TextColored(kDim, "Выберите адрес в списке выше или TCP-соединение во вкладке «Соединения»: "
                                 "двойной щелчок по строке или ПКМ → «Временной профиль».");
        return;
    }
    const FlowRow& r = ds.flows[(size_t)s_wfIdx];
    const bool incoming = r.synIn > 0 && r.synOut == 0;
    const char* remoteName = incoming ? "удалённый" : "сервер";

    ImGui::Text("%s  %s  →  %s", r.proto.c_str(), endpoint(r.localIp, r.localPort).c_str(),
                endpoint(r.remoteIp, r.remotePort).c_str());
    if (!rowName(r).empty()) { ImGui::SameLine(); ImGui::TextColored(kAccent, "%s", rowName(r).c_str()); }
    const std::string geo = geoOf(v.ipCache.get(), r.remoteIp);
    if (!geo.empty()) { ImGui::SameLine(); ImGui::TextColored(kDim, "%s", geo.c_str()); }
    ImGui::SameLine();
    if (isBlocked(v.summary.get(), r)) ImGui::TextColored(kBad, "блокировка");
    else ImGui::TextColored(stateColor(r), "%s", stateText(r.state));

    if (r.proto != "TCP") {
        ImGui::TextColored(kDim, "Временной профиль строится только для TCP: у UDP нет рукопожатия и сбросов.");
        return;
    }
    if (r.wf.empty()) {
        ImGui::TextColored(kDim, "Событий нет: в потоке только подтверждения (ACK) или у пакетов нет времени.");
        return;
    }
    const WfInfo w = wfInfo(r, ds);

    // --- ключевые числа ---
    {
        std::string s;
        if (w.rtt >= 0) s += "рукопожатие (RTT) " + fmtUs(w.rtt);
        else if (w.synCount > 1) s += "SYN ×" + std::to_string(w.synCount);
        else if (r.synOut == 0 && r.synIn == 0) s += "начало соединения не попало в запись";
        if (w.helloUs >= 0) {
            if (!s.empty()) s += "  ·  ";
            s += w.answerUs >= 0 ? std::string("ответ после ") + w.helloWhat + " через " + fmtUs(w.answerUs - w.helloUs)
                                 : std::string("на ") + (w.helloWhat[0] == 'C' ? "ClientHello" : "HTTP-запрос") +
                                   " ответа нет";
        }
        if (!s.empty()) ImGui::TextUnformatted(s.c_str());
    }
    // «заморозка ~16 КБ» — по правилам connFreeze16k режима 2 (счётчики — в
    // buildFlows): ClientHello или порт 443, от сервера ни RST, ни FIN, принято
    // freeze_min..max КБ, после — тишина до конца записи, а повторы без ответа ещё
    // идут. Здесь только подсказка, без вердикта (хостинг не проверяется)
    {
        const AppConfig& k = cfg();
        if ((!r.sni.empty() || r.remotePort == 443) && r.rstIn == 0 && r.finIn == 0 &&
            r.frzBytes >= k.freezeMinBytes && r.frzBytes <= k.freezeMaxBytes &&
            r.frzSilenceUs >= k.freezeSilenceUs && r.frzLater >= k.freezeLaterPkts)
            ImGui::TextColored(kWarn, "Принято %s, затем до конца записи тишина %s, а повторы без ответа "
                                      "идут — так выглядит «заморозка ~16 КБ» (ТСПУ к зарубежному хостингу).",
                               fmtBytes(r.frzBytes).c_str(), fmtUs(r.frzSilenceUs).c_str());
    }
    for (size_t i = 0; i < r.wf.size(); i++)
        if (wfRstForged(r, i, w, nullptr) >= 2) {
            ImGui::TextColored(kBad, "RST на +%s похож на поддельный: прислал не сервер, а оборудование по пути "
                                     "(ТСПУ/DPI). Причины — в подсказке к RST.",
                               fmtUs(r.wf[i].us - w.t0).c_str());
            break;
        }

    if (ImGui::SmallButton("Копировать как текст")) ImGui::SetClipboardText(wfText(r, w, remoteName).c_str());
    if (r.wfDropped > 0) {
        ImGui::SameLine();
        ImGui::TextColored(kDim, "показаны первые %zu событий, ещё %d не поместились", r.wf.size(), r.wfDropped);
    }

    // --- график ---
    const float lh = ImGui::GetTextLineHeight();
    const float mk = em * 0.42f;                 // полувысота маркера
    const ImVec2 pad = ImGui::GetStyle().WindowPadding;
    const float yOut = 2 * lh + mk + 4;          // над дорожкой абонента — 2 ряда подписей
    const float yIn = yOut + 2 * mk + em * 2.6f; // между дорожками — подписи пауз
    const float contentH = yIn + mk + 4 + 2 * lh;
    const float H = contentH + pad.y * 2 + ImGui::GetStyle().ScrollbarSize;

    std::vector<long long> pts;
    long long lastEnd = 0;
    for (const FlowEvent& e : r.wf) { pts.push_back(e.us); pts.push_back(e.endUs); lastEnd = std::max(lastEnd, e.endUs); }
    const bool tail = w.recEnd > lastEnd;
    if (tail) pts.push_back(w.recEnd);
    std::sort(pts.begin(), pts.end());
    pts.erase(std::unique(pts.begin(), pts.end()), pts.end());
    const float unit = em * 2.0f;
    std::vector<float> xs(pts.size());
    xs[0] = em * 0.8f;
    for (size_t k = 1; k < pts.size(); k++)
        xs[k] = xs[k - 1] + unit * (0.45f + log10f(1.0f + (pts[k] - pts[k - 1]) / 1000.0f));
    const float W = xs.back() + em * 10;

    ImGui::BeginChild("##wfl", ImVec2(em * 5.5f, H), ImGuiChildFlags_AlwaysUseWindowPadding,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    {
        const ImVec2 o = ImGui::GetCursorScreenPos();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddText(ImVec2(o.x, o.y + yOut - lh / 2), ImGui::GetColorU32(kAccent), "абонент");
        dl->AddText(ImVec2(o.x, o.y + yIn - lh / 2), ImGui::GetColorU32(kGood), remoteName);
    }
    ImGui::EndChild();
    ImGui::SameLine(0, 0);

    pushPanelBg();
    ImGui::BeginChild("##wfg", ImVec2(0, H), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PopStyleColor();
    const ImVec2 o = ImGui::GetCursorScreenPos();
    {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        auto X = [&](long long t) {
            size_t k = (size_t)(std::lower_bound(pts.begin(), pts.end(), t) - pts.begin());
            if (k >= pts.size()) k = pts.size() - 1;
            return o.x + xs[k];
        };
        const float yo = o.y + yOut, yi = o.y + yIn, ymid = (yo + yi) / 2 - lh / 2;
        const ImU32 lineCol = ImGui::GetColorU32(withA(kDim, 0.35f));
        dl->AddLine(ImVec2(o.x, yo), ImVec2(o.x + W, yo), lineCol);
        dl->AddLine(ImVec2(o.x, yi), ImVec2(o.x + W, yi), lineCol);

        // паузы: тишина ≥1 с — полосой, короче — только подпись, если влезает
        auto gapLabel = [&](long long a, long long b, bool isTail) {
            const float x0 = X(a), x1 = X(b);
            const long long d = b - a;
            std::string t = fmtUs(d);
            ImVec4 c = kDim;
            if (isTail) {
                dl->AddRectFilled(ImVec2(x0, yo - mk), ImVec2(x1, yi + mk), ImGui::GetColorU32(withA(kDim, 0.08f)));
                t = "до конца записи " + t;
            } else if (d >= 1000000) {
                dl->AddRectFilled(ImVec2(x0, yo - mk), ImVec2(x1, yi + mk), ImGui::GetColorU32(withA(kWarn, 0.13f)));
                t = "тишина " + t;
                c = kWarn;
            }
            const float tw = ImGui::CalcTextSize(t.c_str()).x;
            if (tw + 4 <= x1 - x0) dl->AddText(ImVec2((x0 + x1 - tw) / 2, ymid), ImGui::GetColorU32(c), t.c_str());
            else if (isTail || d >= 1000000) {           // широкую подпись — хотя бы короткой
                const std::string s2 = fmtUs(d);
                const float w2 = ImGui::CalcTextSize(s2.c_str()).x;
                if (w2 + 4 <= x1 - x0) dl->AddText(ImVec2((x0 + x1 - w2) / 2, ymid), ImGui::GetColorU32(c), s2.c_str());
            }
        };
        for (const auto& g : w.gaps) gapLabel(g.first, g.second, false);
        if (tail) gapLabel(lastEnd, w.recEnd, true);

        // события; подписи — в два ряда над/под дорожкой, чтобы соседние не слипались
        float rowRight[2][2] = { { -1e9f, -1e9f }, { -1e9f, -1e9f } };   // [out][ряд]
        int hover = -1;
        const bool winHovered = ImGui::IsWindowHovered();
        for (size_t i = 0; i < r.wf.size(); i++) {
            const FlowEvent& e = r.wf[i];
            const float y = e.out ? yo : yi;
            const ImVec4 col = wfColor(r, e);
            const ImU32 c = ImGui::GetColorU32(col);
            float x0 = X(e.us), x1 = X(e.endUs);
            const bool isSpan = e.kind == FE_DATA || e.kind == FE_RETX;
            const int forged = wfRstForged(r, i, w, nullptr);
            if (isSpan) {
                x1 = std::max(x1, x0 + 5);
                dl->AddRectFilled(ImVec2(x0, y - mk * 0.75f), ImVec2(x1, y + mk * 0.75f), c, 2.0f);
            } else {
                if (x1 > x0)       // повторы SYN / пачка RST — тонкая полоса до последнего
                    dl->AddRectFilled(ImVec2(x0, y - 1.5f), ImVec2(x1, y + 1.5f), c);
                dl->AddCircleFilled(ImVec2(x0, y), mk, c);
                if (forged >= 2) dl->AddCircle(ImVec2(x0, y), mk * 1.7f, c, 0, 2.0f);
                x1 = x0;
            }
            // подпись
            std::string t = wfTitle(e);
            if (e.kind == FE_RST && !e.out && e.ttl >= 0) t += " TTL " + std::to_string(e.ttl);
            if (forged >= 2) t += " — подделка?";
            const float tw = ImGui::CalcTextSize(t.c_str()).x;
            const float lx = std::max(o.x + 2, (x0 + x1 - tw) / 2);
            const int lane = e.out ? 1 : 0;
            for (int row = 0; row < 2; row++) {
                if (lx <= rowRight[lane][row] + 6) continue;
                const float ly = e.out ? yo - mk - 2 - lh * (row + 1) : yi + mk + 2 + lh * row;
                dl->AddText(ImVec2(lx, ly), ImGui::GetColorU32(e.kind == FE_DATA ? kDim : col), t.c_str());
                rowRight[lane][row] = lx + tw;
                break;
            }
            if (winHovered && ImGui::IsMouseHoveringRect(ImVec2(x0 - mk - 2, y - mk - 3), ImVec2(x1 + mk + 2, y + mk + 3)))
                hover = (int)i;
        }
        s_wfHover = hover;
        if (hover >= 0) {
            const FlowEvent& e = r.wf[(size_t)hover];
            ImGui::BeginTooltip();
            ImGui::TextColored(wfColor(r, e), "%s", wfTitle(e).c_str());
            ImGui::SameLine();
            ImGui::TextColored(kDim, "%s", e.out ? "от абонента" : (std::string("от: ") + remoteName).c_str());
            ImGui::Text("+%s от начала соединения (%s от начала записи)", fmtUs(e.us - w.t0).c_str(),
                        fmtDur(e.us / 1e6).c_str());
            for (const auto& d : wfDetail(r, (size_t)hover, w)) ImGui::TextUnformatted(d.c_str());
            ImGui::EndTooltip();
        }
    }
    // площадь графика (задаёт ширину прокрутки) и колесо мыши: без Shift —
    // тоже вбок; забираем колесо себе, иначе прокрутится и вкладка
    ImGui::SetCursorScreenPos(o);
    ImGui::InvisibleButton("##wfarea", ImVec2(W, contentH));
    if (ImGui::SetItemKeyOwner(ImGuiKey_MouseWheelY)) {
        const float wy = ImGui::GetIO().MouseWheel;
        if (wy != 0.0f) ImGui::SetScrollX(ImGui::GetScrollX() - wy * em * 6.0f);
    }
    ImGui::EndChild();
    ImGui::TextColored(kDim, "Шкала сжатая: ширина промежутка — по логарифму паузы. Чистые ACK не показаны; "
                             "пакеты с данными подряд слиты в серию. Колесо мыши — прокрутка вбок.");

    // --- таблица событий ---
    const ImGuiTableFlags tf = ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV |
        ImGuiTableFlags_BordersOuterH | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit;
    pushPanelBg();
    const bool open = ImGui::BeginTable("##wft", 5, tf, ImVec2(0, 0));
    ImGui::PopStyleColor();
    if (!open) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Время", 0, em * 6);
    ImGui::TableSetupColumn("Пауза", 0, em * 6);
    ImGui::TableSetupColumn("Откуда", 0, em * 6);
    ImGui::TableSetupColumn("Событие", 0, em * 9);
    ImGui::TableSetupColumn("Подробности", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    long long prevEnd = -1;
    for (size_t i = 0; i < r.wf.size(); i++) {
        const FlowEvent& e = r.wf[i];
        ImGui::TableNextRow();
        if ((int)i == s_wfHover)
            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, ImGui::GetColorU32(withA(kAccent, 0.18f)));
        ImGui::TableNextColumn(); ImGui::Text("+%s", fmtUs(e.us - w.t0).c_str());
        ImGui::TableNextColumn();
        if (prevEnd >= 0 && e.us > prevEnd) {
            const long long d = e.us - prevEnd;
            if (d >= 1000000) ImGui::TextColored(kWarn, "%s", fmtUs(d).c_str());
            else ImGui::TextColored(kDim, "%s", fmtUs(d).c_str());
        }
        prevEnd = std::max(prevEnd, e.endUs);
        ImGui::TableNextColumn();
        ImGui::TextColored(e.out ? kAccent : kGood, "%s", e.out ? "абонент" : remoteName);
        ImGui::TableNextColumn(); ImGui::TextColored(wfColor(r, e), "%s", wfTitle(e).c_str());
        ImGui::TableNextColumn();
        std::string d;
        for (const auto& x : wfDetail(r, i, w)) { if (!d.empty()) d += "; "; d += x; }
        ImGui::TextUnformatted(d.c_str());
    }
    if (tail && prevEnd >= 0) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextColored(kDim, "+%s", fmtUs(w.recEnd - w.t0).c_str());
        ImGui::TableNextColumn(); ImGui::TextColored(w.recEnd - prevEnd >= 1000000 ? kWarn : kDim, "%s",
                                                     fmtUs(w.recEnd - prevEnd).c_str());
        ImGui::TableNextColumn();
        ImGui::TableNextColumn(); ImGui::TextColored(kDim, "конец записи");
        ImGui::TableNextColumn();
    }
    ImGui::EndTable();
}

// ------------------------------------------------------------------
// «Журнал»
// ------------------------------------------------------------------
void drawLog() {
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 18);
    ImGui::InputTextWithHint("##lf", "фильтр строк…", s_logFilter, sizeof(s_logFilter),
                             ImGuiInputTextFlags_EscapeClearsAll);
    ImGui::SameLine();
    ImGui::Checkbox("Прокрутка за выводом", &s_autoScroll);
    ImGui::SameLine();
    if (ImGui::Button("Копировать всё")) ImGui::SetClipboardText(appLog().text().c_str());
    ImGui::SameLine();
    if (ImGui::Button("Сохранить…")) actSaveLog();
    ImGui::SameLine();
    ImGui::BeginDisabled(jobBusy());
    if (ImGui::Button("Очистить")) appLog().clear();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextColored(kDim, "строк: %zu", appLog().lineCount());

    pushPanelBg();
    ImGui::BeginChild("##log", ImVec2(0, 0), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    ImGui::PopStyleColor();
    if (g_fontMono) ImGui::PushFont(g_fontMono, g_fontMono->LegacySize);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 1));
    appLog().draw(s_logFilter, s_autoScroll);
    ImGui::PopStyleVar();
    if (g_fontMono) ImGui::PopFont();
    ImGui::EndChild();
}

// ------------------------------------------------------------------
// «Инструменты»
// ------------------------------------------------------------------
struct ToolDef { int mode; const char* desc; };
const ToolDef kTools[] = {
    { 3,  "Трассировка до IP или домена: на каком хопе теряются пакеты или растёт задержка." },
    { 4,  "Задержка до адреса против заявленной страны — выявляет подмену геолокации (VPN/прокси)." },
    { 5,  "Запись трафика с сетевого интерфейса в .pcap через Npcap; файл потом открыть здесь." },
    { 6,  "Доступен ли TCP-порт абонента извне: TCP-ping с 6 зондов Globalping на разных континентах." },
    { 7,  "Скан TCP-портов адреса с этой машины: какие сервисы открыты." },
    { 8,  "Пробы рукопожатий VPN-протоколов по UDP: отвечает ли сервер." },
    { 9,  "Поиск хопа, на котором DPI (ТСПУ) режет соединение по SNI." },
    { 10, "Сравнение двух дампов в консоли (в окне — «Файл → Сравнить…»)." },
    { 11, "Один домен у системного DNS, у DNS провайдера, у 8.8.8.8/1.1.1.1/9.9.9.9 и через DoH: "
          "заглушки, NXDOMAIN-подмена, вброшенные DPI ответы, перехват UDP:53." },
    { 12, "Качает по 256 КБ с зарубежных хостингов (Hetzner, OVH, DO, Vultr, Linode, Cloudflare) "
          "и российских контрольных: видно, встаёт ли поток на ~16 КБ (ТСПУ)." },
    { 13, "Владелец IP или домена: провайдер, ASN, город и страна (ip-api.com), диапазон и имя "
          "сети из реестра RIPE/ARIN (RDAP), признаки хостинга, CDN, прокси, мобильной сети. "
          "Для домена — какие адреса отдают система, DNS провайдера, Google, Cloudflare, Quad9, "
          "Яндекс, OpenDNS, AdGuard и DoH (заглушки, подмена)." },
};

void drawTools() {
    ImGui::TextWrapped("Интерактивные инструменты спрашивают цель и параметры сами, поэтому "
                       "открываются в отдельном консольном окне. Окно анализатора при этом "
                       "остаётся свободным.");
    if (g_logEnabled)
        ImGui::TextColored(kDim, "Запись отчёта включена — трассировка и гео сохранят отчёт в файл.");
    ImGui::Spacing();

    // режим 13 без консоли: цель тут, результат — в журнале
    ImGui::SeparatorText("Кому принадлежит IP / домен — прямо в окне");
    static char s_owner[512] = "";
    ImGui::BeginDisabled(jobBusy());
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 24);
    const bool enter = ImGui::InputTextWithHint("##owner", "IP или домен, можно несколько через пробел",
                                                s_owner, sizeof(s_owner), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if ((ImGui::Button("Проверить") || enter) && s_owner[0]) startIpOwner(s_owner);
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("Провайдер, ASN, диапазон сети из реестра и ответы разных резолверов — в журнал.");
    ImGui::Spacing();
    if (ImGui::BeginTable("##tools", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp |
                                        ImGuiTableFlags_BordersInnerH)) {
        ImGui::TableSetupColumn("btn", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFontSize() * 16);
        ImGui::TableSetupColumn("desc", ImGuiTableColumnFlags_WidthStretch);
        for (const ToolDef& t : kTools) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(t.mode);
            if (ImGui::Button(toolTitle(t.mode), ImVec2(-1, 0))) launchConsoleTool(t.mode);
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::AlignTextToFramePadding();
            ImGui::TextWrapped("%s", t.desc);
        }
        ImGui::EndTable();
    }
    std::vector<ToolProc> run = runningTools();
    ImGui::Spacing();
    ImGui::SeparatorText("Запущены");
    if (run.empty()) ImGui::TextColored(kDim, "нет");
    for (const auto& t : run) ImGui::BulletText("%s", t.title.c_str());
}

// ------------------------------------------------------------------
// «Настройки»
// ------------------------------------------------------------------
std::string portList(const std::map<int, std::string>& m) {
    std::string s;
    for (const auto& kvp : m) {
        if (!s.empty()) s += ", ";
        s += std::to_string(kvp.first);
        if (!kvp.second.empty()) s += " (" + kvp.second + ")";
    }
    return s.empty() ? "—" : s;
}

std::string joinList(const std::vector<std::string>& v) {
    std::string s;
    for (const auto& x : v) { if (!s.empty()) s += ", "; s += x; }
    return s.empty() ? "—" : s;
}

void drawSettings() {
    const AppConfig& c = cfg();
    bool log = g_logEnabled;
    if (ImGui::Checkbox("Сохранять отчёт (.txt) рядом с дампом", &log)) g_logEnabled = log;
    ImGui::SetItemTooltip("Анализ VPN/блокировок и сравнение пишутся в <дамп>.report.<время>.txt");

    ImGui::SeparatorText("Оформление");
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 12);
    if (ImGui::BeginCombo("Тема", kThemes[s_theme].name)) {
        for (int i = 0; i < kThemeCount; i++) {
            ImGui::PushID(i);
            if (ImGui::Selectable(kThemes[i].name, i == s_theme, 0, ImVec2(ImGui::GetFontSize() * 7, 0)))
                setTheme(i, true);
            if (i == s_theme) ImGui::SetItemDefaultFocus();
            ImGui::SameLine();
            themeSwatch(kThemes[i]);
            ImGui::PopID();
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::TextColored(kDim, GUI_MOD "+T — следующая");
    bool anim = s_anim;
    if (ImGui::Checkbox("Анимации", &anim)) setAnimations(anim);
    ImGui::SetItemTooltip("Плавная смена темы, проявление вкладок, рост полос, уведомления. "
                          "Выключите при работе через медленный удалённый рабочий стол.");

    const float em = ImGui::GetFontSize();
    static const char* const kWpModes[] = { "в теме «Аниме»", "во всех темах", "не показывать" };
    ImGui::SetNextItemWidth(em * 12);
    if (ImGui::Combo("Картинка на фоне", &s_wpMode, kWpModes, 3))
        regSetDword(L"WallpaperMode", (DWORD)s_wpMode);
    ImGui::SetNextItemWidth(em * 12);
    ImGui::SliderInt("Затемнение", &s_wpDim, 0, 90, "%d%%", ImGuiSliderFlags_AlwaysClamp);
    if (ImGui::IsItemDeactivatedAfterEdit()) regSetDword(L"WallpaperDim", (DWORD)s_wpDim);
    ImGui::SetItemTooltip("Картинка притемняется цветом фона темы — чтобы текст поверх читался.");
    if (ImGui::Button("Своя картинка…")) actPickWallpaper();
    ImGui::SetItemTooltip("JPG, PNG, BMP, GIF, TIFF; WebP — если в Windows есть его кодек.");
    ImGui::SameLine();
    const WallpaperTex& wp = wallpaperTex();
    ImGui::BeginDisabled(s_wpPath.empty() && (wp.builtin || !wp.tex));
    if (ImGui::Button("Встроенная")) { s_wpPending.clear(); s_wpPendingSet = true; }
    ImGui::EndDisabled();
    ImGui::SameLine();
    const std::string cur = s_wpLoad != WPL_NONE ? std::string("загружается…")
                          : !wp.tex ? std::string("ещё не загружалась")
                          : wp.builtin ? std::string("встроенная") : wideName(s_wpPath);
    ImGui::TextColored(kDim, "сейчас: %s", cur.c_str());
    if (!s_anim && wallpaperWanted())
        ImGui::TextColored(kDim, "Без анимаций картинка неподвижна, огоньков и свечения нет.");

    ImGui::TextColored(kDim, "Оформление запоминается для пользователя Windows (реестр, HKCU).");

    ImGui::SeparatorText("Файл настроек");
    kv("analyzer.ini", c.loadedFrom.empty() ? "не найден — значения по умолчанию" : c.loadedFrom);
    ImGui::BeginDisabled(jobBusy());
    if (ImGui::Button("Перечитать analyzer.ini")) startReloadConfig();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextColored(kDim, "образец — analyzer.ini.example рядом с программой");
    for (const auto& w : c.warnings) ImGui::TextColored(kWarn, "%s", w.c_str());

    ImGui::SeparatorText("Пороги анализа");
    char b[128];
    snprintf(b, sizeof(b), "%.1f с", c.tailUs / 1e6);                 kv("Хвост дампа", b);
    snprintf(b, sizeof(b), "%lld–%lld КБ", c.freezeMinBytes / 1024, c.freezeMaxBytes / 1024);
    kv("Заморозка ~16 КБ", b);
    snprintf(b, sizeof(b), "%.1f с, %d пакетов", c.freezeSilenceUs / 1e6, c.freezeLaterPkts);
    kv("  тишина после", b);
    kv("SYN без ответа (ТСПУ)", std::to_string(c.tspuMinSyn));
    kv("Split-соединений", std::to_string(c.splitMinConns));
    kv("Потолок баллов", "форма " + std::to_string(c.shapeCap) + ", потоки " + std::to_string(c.flowScoreCap));
    snprintf(b, sizeof(b), "%.0f с, принято ≥ %s, отправлено ≥ %s", c.longFlowUs / 1e6,
             fmtBytes(c.longFlowMinIn).c_str(), fmtBytes(c.longFlowMinOut).c_str());
    kv("Долгий поток", b);

    ImGui::SeparatorText("Порты и своя сеть");
    ImGui::PushTextWrapPos(0);
    ImGui::TextColored(kDim, "VPN UDP:");   ImGui::SameLine(); ImGui::TextUnformatted(portList(c.vpnUdpPorts).c_str());
    ImGui::TextColored(kDim, "VPN TCP:");   ImGui::SameLine(); ImGui::TextUnformatted(portList(c.vpnTcpPorts).c_str());
    ImGui::TextColored(kDim, "Прокси:");    ImGui::SameLine(); ImGui::TextUnformatted(portList(c.proxyPorts).c_str());
    ImGui::TextColored(kDim, "Своя сеть (организация):"); ImGui::SameLine();
    ImGui::TextUnformatted(joinList(c.ownIspOrgKeywords).c_str());
    ImGui::TextColored(kDim, "Своя сеть (AS):"); ImGui::SameLine();
    if (c.ownIspAsnFromIni) {
        ImGui::TextUnformatted((joinList(c.ownIspAsns) + "  (analyzer.ini)").c_str());
    } else {
        const OwnIspAuto oi = ownIspAuto();
        const std::string shown = oi.asn ? (oi.name.empty() ? "AS" + std::to_string(oi.asn) : oi.name)
                                         : std::string("не определена");
        ImGui::TextUnformatted(shown.c_str());
        ImGui::SameLine();
        ImGui::BeginDisabled(jobBusy());
        if (ImGui::Button("Определить")) startOwnIspDetect();
        ImGui::EndDisabled();
        ImGui::SetItemTooltip("Узнать AS провайдера, через которого программа сейчас выходит в "
                              "интернет (запрос к ip-api.com по своему адресу), и запомнить. "
                              "Адреса этой сети не считаются хостингом. Нажимайте из сети "
                              "оператора и без VPN. Задать вручную — own_isp_asn в analyzer.ini.");
        if (oi.asn) ImGui::TextColored(kDim, "  %s", oi.status.c_str());
        else ImGui::TextColored(kWarn, "  нажмите «Определить», находясь в сети оператора без VPN");
    }
    ImGui::TextColored(kDim, "Белый список VPN (AS):"); ImGui::SameLine();
    ImGui::TextUnformatted(joinList(c.vpnWhitelistAsns).c_str());
    ImGui::TextColored(kDim, "Белый список VPN (домены по DNS):"); ImGui::SameLine();
    ImGui::TextUnformatted(joinList(c.vpnWhitelistDomains).c_str());
    ImGui::PopTextWrapPos();
}

// ------------------------------------------------------------------
// строка статуса
// ------------------------------------------------------------------
void drawStatus(const View& v) {
    ImGui::Separator();
    if (v.ds)
        ImGui::TextColored(kDim, "%s  ·  %zu пакетов  ·  %zu соединений  ·  MainIP %s",
                           v.ds->name.c_str(), v.ds->packets.size(), v.ds->flows.size(),
                           v.ds->localIp.empty() ? "?" : v.ds->localIp.c_str());
    else
        ImGui::TextColored(kDim, "Дамп не загружен");
    ImGui::SameLine();
    std::string right = std::string("отчёт: ") + (g_logEnabled ? "вкл" : "выкл");
    size_t tools = runningTools().size();
    if (tools) right = "инструментов открыто: " + std::to_string(tools) + "  ·  " + right;
    if (jobBusy()) right = jobTitle() + "  ·  " + right;
    float w = ImGui::CalcTextSize(right.c_str()).x;
    float avail = ImGui::GetContentRegionAvail().x;
    if (avail > w) ImGui::SameLine(0, avail - w);
    else ImGui::SameLine();
    ImGui::TextColored(jobBusy() ? kWarn : kDim, "%s", right.c_str());
}

bool tabItem(const char* label, int tab, int want) {
    return ImGui::BeginTabItem(label, nullptr, want == tab ? ImGuiTabItemFlags_SetSelected : 0);
}

// Уведомление: выезжает снизу, держится, гаснет. Клик — открыть журнал.
void drawToast(float bottomPad) {
    const float t = (float)(ImGui::GetTime() - s_toastT0);
    if (s_toast.empty() || t < 0 || t >= kToastLife) return;
    s_wantFrames = true;                        // и без анимаций — чтобы вовремя исчезло
    float a = 1;
    if (s_anim) {
        if (t < 0.25f) a = easeOut(t / 0.25f);
        else if (t > kToastLife - 0.6f) a = clamp01((kToastLife - t) / 0.6f);
    }
    const float em = ImGui::GetFontSize();
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    const ImVec2 pos(vp->WorkPos.x + vp->WorkSize.x - em,
                     vp->WorkPos.y + vp->WorkSize.y - bottomPad - em + (1 - a) * em * 1.5f);
    ImGui::SetNextWindowPos(pos, ImGuiCond_Always, ImVec2(1, 1));
    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, a);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, em * 0.4f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(em * 0.8f, em * 0.5f));
    ImGui::PushStyleColor(ImGuiCol_WindowBg, ImGui::GetStyleColorVec4(ImGuiCol_PopupBg));
    const ImVec4 mark = s_toastFailed ? kBad : kGood;
    ImGui::PushStyleColor(ImGuiCol_Border, withA(mark, 0.6f));
    const ImGuiWindowFlags wf = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav |
        ImGuiWindowFlags_NoMove;
    if (ImGui::Begin("##toast", nullptr, wf)) {
        ImGui::TextColored(mark, s_toastFailed ? "✗" : "✓");
        ImGui::SameLine();
        ImGui::TextUnformatted(s_toast.c_str());
        ImGui::SameLine();
        ImGui::TextColored(kDim, "— журнал");
        if (ImGui::IsWindowHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            s_selectTab = TAB_LOG;
            s_toastT0 = -100;
        }
    }
    ImGui::End();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(3);
}

} // namespace

bool guiLightTheme() { return kThemes[s_theme].light; }
ImVec4 guiClearColor() { return s_clear; }
bool guiWantsFrames() { return s_wantFrames; }

std::string fmtBytes(long long b) {
    char buf[32];
    if (b < 1024) snprintf(buf, sizeof(buf), "%lld Б", b);
    else if (b < 1024LL * 1024) snprintf(buf, sizeof(buf), "%.1f КБ", b / 1024.0);
    else if (b < 1024LL * 1024 * 1024) snprintf(buf, sizeof(buf), "%.1f МБ", b / (1024.0 * 1024));
    else snprintf(buf, sizeof(buf), "%.2f ГБ", b / (1024.0 * 1024 * 1024));
    return buf;
}

void guiRequestLogTab() { s_selectTab = TAB_LOG; }

void guiInit() {
    ImGuiStyle& st = ImGui::GetStyle();
    st.WindowRounding = 0;
    st.ChildRounding = 4;
    st.FrameRounding = 4;
    st.PopupRounding = 4;
    st.GrabRounding = 4;
    st.TabRounding = 4;
    st.ScrollbarRounding = 6;
    st.FramePadding = ImVec2(8, 4);
    st.ItemSpacing = ImVec2(8, 6);
    st.CellPadding = ImVec2(6, 3);
    st.WindowPadding = ImVec2(10, 8);

    st.TabBarOverlineSize = 2;

    // Тема: сохранённая; при первом запуске — как в системе (светлая/тёмная).
    const bool sysLight = systemLightTheme();
    int lightIdx = 0;
    for (int i = 0; i < kThemeCount; i++) if (kThemes[i].light) lightIdx = i;
    const DWORD saved = regGetDword(kRegKey, L"Theme", sysLight ? (DWORD)lightIdx : 0);
    s_anim = regGetDword(kRegKey, L"Animations", 1) != 0;
    s_theme = saved < (DWORD)kThemeCount ? (int)saved : 0;
    s_wpMode = (int)std::min<DWORD>(regGetDword(kRegKey, L"WallpaperMode", WP_THEME), WP_OFF);
    s_wpDim = (int)std::min<DWORD>(regGetDword(kRegKey, L"WallpaperDim", 55), 90);
    s_wpPath = regGetString(L"WallpaperPath");
    setTheme(s_theme, false);
    finalizeStyle();                // картинка (если нужна) проявится в первых кадрах
}

void guiFrame() {
    s_wantFrames = false;
    updateTheme();
    updateWallpaper();              // до отрисовки: может заменить текстуру
    finalizeStyle();
    drawWallpaper();
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_T, ImGuiInputFlags_RouteGlobal))
        setTheme((s_theme + 1) % kThemeCount, true);
    trackJobForToast();

    View v = snapshot();
    if (v.summary != s_lastSummary) {
        s_lastSummary = v.summary;
        s_sumT0 = ImGui::GetTime();
    }
    // загружен новый набор — показываем его обзор (сюда же сбрасываем фильтры)
    if (v.ds != s_lastDs) {
        s_tabT0 = ImGui::GetTime();             // проявить заново
        if (v.ds) s_selectTab = TAB_OVERVIEW;
        s_lastDs = v.ds;
        s_flowFilter[0] = 0;
        s_onlyProblems = false;
        s_order.clear();
        s_geo.clear();
        s_wfIdx = -1;
        s_needRefilter = true;
        s_needResort = true;
    }

    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_O, ImGuiInputFlags_RouteGlobal)) actOpen();

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    const ImGuiWindowFlags wf = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_MenuBar |
        ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::Begin("##main", nullptr, wf);

    drawMenuBar(v);
    drawToolbar(v);
    ImGui::Spacing();

    const float statusH = ImGui::GetFrameHeightWithSpacing() + ImGui::GetStyle().ItemSpacing.y;
    ImGui::BeginChild("##body", ImVec2(0, -statusH));
    const int want = s_selectTab.exchange(TAB_NONE);
    if (ImGui::BeginTabBar("##tabs", ImGuiTabBarFlags_DrawSelectedOverline)) {
        if (tabItem("Обзор", TAB_OVERVIEW, want)) {
            beginTabBody(TAB_OVERVIEW);
            ImGui::BeginChild("##ov");
            drawOverview(v);
            ImGui::EndChild();
            endTabBody();
            ImGui::EndTabItem();
        }
        if (tabItem("Соединения", TAB_FLOWS, want)) {
            beginTabBody(TAB_FLOWS); drawFlows(v); endTabBody();
            ImGui::EndTabItem();
        }
        if (tabItem("Профиль соединения", TAB_WATERFALL, want)) {
            beginTabBody(TAB_WATERFALL); drawWaterfall(v); endTabBody();
            ImGui::EndTabItem();
        }
        if (tabItem("Проверка РКН", TAB_RKN, want)) {
            beginTabBody(TAB_RKN);
            if (rknDrawTab(GuiColors{kAccent, kGood, kWarn, kBad, kDim, s_panelBg})) s_wantFrames = true;
            endTabBody();
            ImGui::EndTabItem();
        }
        if (tabItem("Журнал", TAB_LOG, want)) {
            beginTabBody(TAB_LOG); drawLog(); endTabBody();
            ImGui::EndTabItem();
        }
        if (tabItem("Инструменты", TAB_TOOLS, want)) {
            beginTabBody(TAB_TOOLS); drawTools(); endTabBody();
            ImGui::EndTabItem();
        }
        if (tabItem("Настройки", TAB_SETTINGS, want)) {
            beginTabBody(TAB_SETTINGS);
            ImGui::BeginChild("##set");
            drawSettings();
            ImGui::EndChild();
            endTabBody();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::EndChild();

    drawStatus(v);
    ImGui::End();

    drawToast(statusH);
}
