// gui_main.cpp — окно GUI: Win32 + Direct3D 11 + Dear ImGui, шрифты с учётом
// DPI, перетаскивание файлов, перехват std::cout в журнал окна.
// Основа цикла — пример example_win32_directx11 из Dear ImGui (MIT).
#include "gui.h"
#include "gui_app.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include <d3d11.h>
#include <dwmapi.h>
#include <wincodec.h>
#include <windowsx.h>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "windowscodecs.lib")   // WIC: картинка на фоне
#pragma comment(lib, "ole32.lib")

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

ImFont* g_fontMono = nullptr;

namespace {

HWND g_hwnd = nullptr;
ID3D11Device* g_dev = nullptr;
ID3D11DeviceContext* g_ctx = nullptr;
IDXGISwapChain* g_swap = nullptr;
ID3D11RenderTargetView* g_rtv = nullptr;
bool g_occluded = false;
UINT g_resizeW = 0, g_resizeH = 0;
std::vector<std::string> g_dropped;     // файлы, брошенные на окно (поток окна)
// пустая часть панели меню — «заголовок» окна (guiSetCaptionArea), клиентские px
float g_capL = 0, g_capR = 0, g_capH = 0;

// Системного заголовка нет: стиль остаётся WS_OVERLAPPEDWINDOW (Snap, анимации,
// тень, кнопка на панели задач), но вся рамка отдана клиентской области
// (WM_NCCALCSIZE), а края и заголовок назначает WM_NCHITTEST.
LRESULT hitTest(HWND hWnd, LPARAM lParam) {
    POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
    ScreenToClient(hWnd, &pt);
    RECT rc;
    GetClientRect(hWnd, &rc);
    if (!IsZoomed(hWnd)) {
        const int b = GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
        // сверху полоса тоньше — под ней меню и кнопки окна
        const int bt = GetSystemMetrics(SM_CYSIZEFRAME);
        const bool l = pt.x < b, r = pt.x >= rc.right - b;
        const bool t = pt.y < bt, d = pt.y >= rc.bottom - b;
        if (t && l) return HTTOPLEFT;
        if (t && r) return HTTOPRIGHT;
        if (d && l) return HTBOTTOMLEFT;
        if (d && r) return HTBOTTOMRIGHT;
        if (l) return HTLEFT;
        if (r) return HTRIGHT;
        if (t) return HTTOP;
        if (d) return HTBOTTOM;
    }
    if (pt.y >= 0 && pt.y < g_capH && pt.x >= g_capL && pt.x < g_capR) return HTCAPTION;
    return HTCLIENT;
}

// std::cout -> журнал окна. Без буфера: каждый << сразу уходит в rawOutput,
// порядок с printf (rprintf) сохраняется.
class CoutToLog : public std::streambuf {
protected:
    int_type overflow(int_type ch) override {
        if (!traits_type::eq_int_type(ch, traits_type::eof())) {
            char c = traits_type::to_char_type(ch);
            rawOutput(&c, 1);
            return ch;
        }
        return traits_type::not_eof(ch);
    }
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        if (n > 0) rawOutput(s, (size_t)n);
        return n;
    }
};

void sinkToLog(const char* s, size_t n) { appLog().append(s, n); }

void createRenderTarget() {
    ID3D11Texture2D* back = nullptr;
    if (SUCCEEDED(g_swap->GetBuffer(0, IID_PPV_ARGS(&back))) && back) {
        g_dev->CreateRenderTargetView(back, nullptr, &g_rtv);
        back->Release();
    }
}

void cleanupRenderTarget() {
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
}

bool createDevice(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    D3D_FEATURE_LEVEL got;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                                               levels, 2, D3D11_SDK_VERSION, &sd, &g_swap,
                                               &g_dev, &got, &g_ctx);
    if (hr == DXGI_ERROR_UNSUPPORTED)   // нет аппаратного ускорения (RDP, старый драйвер)
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0,
                                           levels, 2, D3D11_SDK_VERSION, &sd, &g_swap,
                                           &g_dev, &got, &g_ctx);
    if (hr != S_OK) return false;
    createRenderTarget();
    return true;
}

void cleanupDevice() {
    cleanupRenderTarget();
    if (g_swap) { g_swap->Release(); g_swap = nullptr; }
    if (g_ctx) { g_ctx->Release(); g_ctx = nullptr; }
    if (g_dev) { g_dev->Release(); g_dev = nullptr; }
}

LRESULT WINAPI wndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;
    switch (msg) {
    case WM_NCCALCSIZE:
        if (wParam == TRUE) {
            // развёрнутое окно Windows выносит за край монитора на толщину рамки —
            // без неё клиентская часть должна совпасть с рабочей областью
            if (IsZoomed(hWnd)) {
                MONITORINFO mi{ sizeof(mi) };
                if (GetMonitorInfoW(MonitorFromWindow(hWnd, MONITOR_DEFAULTTONEAREST), &mi))
                    ((NCCALCSIZE_PARAMS*)lParam)->rgrc[0] = mi.rcWork;
            }
            return 0;
        }
        break;
    case WM_NCHITTEST:
        return hitTest(hWnd, lParam);
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) return 0;
        g_resizeW = (UINT)LOWORD(lParam);
        g_resizeH = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) return 0;   // Alt не открывает системное меню
        break;
    case WM_GETMINMAXINFO: {
        auto* mm = (MINMAXINFO*)lParam;
        mm->ptMinTrackSize.x = 800;
        mm->ptMinTrackSize.y = 500;
        return 0;
    }
    case WM_DPICHANGED: {
        const RECT* r = (const RECT*)lParam;
        SetWindowPos(hWnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        return 0;
    }
    case WM_DROPFILES: {
        HDROP drop = (HDROP)wParam;
        UINT n = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
        for (UINT i = 0; i < n; i++) {
            UINT len = DragQueryFileW(drop, i, nullptr, 0);
            std::wstring w(len + 1, L'\0');
            DragQueryFileW(drop, i, &w[0], len + 1);
            w.resize(len);
            g_dropped.push_back(w2u8(w.c_str()));
        }
        DragFinish(drop);
        return 0;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ------------------------------------------------------------------
// Картинка на фоне: WIC декодирует (jpg/png/bmp/gif/tiff, webp — если в
// системе есть кодек), текстура D3D11 для ImGui.
// ------------------------------------------------------------------
ID3D11ShaderResourceView* g_wpSrv = nullptr;
WallpaperTex g_wp;

template <class T> void release(T*& p) { if (p) { p->Release(); p = nullptr; } }

// Декодирует в RGBA 8 бит. Картинку крупнее монитора (monW×monH) уменьшает заранее
// (сэмплер ImGui без мип-уровней — при сильном уменьшении на лету была бы рябь).
// Зовётся из потока загрузки (см. WpJob): COM в нём уже инициализирован.
bool decodeImage(const std::wstring& path, double monW, double monH,
                 std::vector<unsigned char>& px, UINT& w, UINT& h, std::string& err) {
    IWICImagingFactory* fac = nullptr;
    IWICStream* stream = nullptr;
    IWICBitmapDecoder* dec = nullptr;
    IWICBitmapFrameDecode* frame = nullptr;
    IWICBitmapScaler* scaler = nullptr;
    IWICFormatConverter* conv = nullptr;
    bool ok = false;
    do {
        if (FAILED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_PPV_ARGS(&fac)))) {
            err = "компонент Windows Imaging (WIC) недоступен";
            break;
        }
        HRESULT hr;
        if (path.empty()) {
            // встроенная — ресурс ANIME_BG (RCDATA) в exe, см. npcap.rc
            HRSRC r = FindResourceW(nullptr, L"ANIME_BG", MAKEINTRESOURCEW(10));
            HGLOBAL g = r ? LoadResource(nullptr, r) : nullptr;
            void* data = g ? LockResource(g) : nullptr;
            const DWORD size = r ? SizeofResource(nullptr, r) : 0;
            if (!data || !size) { err = "встроенной картинки нет в exe"; break; }
            if (FAILED(fac->CreateStream(&stream)) ||
                FAILED(stream->InitializeFromMemory((BYTE*)data, size))) {
                err = "не удалось открыть встроенную картинку";
                break;
            }
            hr = fac->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnDemand, &dec);
        } else {
            hr = fac->CreateDecoderFromFilename(path.c_str(), nullptr, GENERIC_READ,
                                                WICDecodeMetadataCacheOnDemand, &dec);
        }
        if (FAILED(hr)) { err = "файл не читается или формат не поддерживается"; break; }
        if (FAILED(dec->GetFrame(0, &frame))) { err = "не удалось прочитать изображение"; break; }
        UINT sw = 0, sh = 0;
        frame->GetSize(&sw, &sh);
        if (!sw || !sh) { err = "пустое изображение"; break; }

        // «cover» на весь монитор с запасом 10% на движение
        const double k = std::max(monW / sw, monH / sh) * 1.1;
        IWICBitmapSource* src = frame;
        w = sw; h = sh;
        if (k < 0.95) {
            w = std::max(1u, (UINT)(sw * k));
            h = std::max(1u, (UINT)(sh * k));
            if (FAILED(fac->CreateBitmapScaler(&scaler)) ||
                FAILED(scaler->Initialize(frame, w, h, WICBitmapInterpolationModeFant))) {
                err = "не удалось уменьшить изображение";
                break;
            }
            src = scaler;
        }
        if (w > 8192 || h > 8192) { err = "слишком вытянутое изображение"; break; }
        if (FAILED(fac->CreateFormatConverter(&conv)) ||
            FAILED(conv->Initialize(src, GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone,
                                    nullptr, 0, WICBitmapPaletteTypeCustom))) {
            err = "не удалось преобразовать изображение";
            break;
        }
        px.resize((size_t)w * h * 4);
        if (FAILED(conv->CopyPixels(nullptr, w * 4, (UINT)px.size(), px.data()))) {
            err = "не удалось декодировать изображение";
            break;
        }
        ok = true;
    } while (false);
    release(conv); release(scaler); release(frame); release(dec); release(stream); release(fac);
    return ok;
}

// Загрузка картинки — в своём потоке: файл из недоступной сетевой папки WIC ждёт
// до таймаута SMB (десятки секунд), и окно всё это время «не отвечало» бы — при
// каждом запуске, раз путь сохранён. Поток отвязан: зависшее чтение не держит ни
// окно, ни выход из программы. Текстуру из готовых пикселей создаёт поток окна
// (wallpaperPoll).
struct WpJob {
    std::wstring path;
    double monW = 0, monH = 0;           // монитор — узнаём в потоке окна
    std::atomic<bool> done{false};       // поля ниже готовы
    bool ok = false;
    std::vector<unsigned char> px;
    UINT w = 0, h = 0;
    std::string err;
};
std::shared_ptr<WpJob> g_wpJob;          // последний запрос; прежние, если ещё идут, забыты
std::wstring g_wpShown;                  // картинка текущей текстуры (пусто — встроенная)

// ------------------------------------------------------------------
// Потеря устройства D3D11: обновился или упал драйвер видеокарты (TDR), сменился
// GPU. Present/ResizeBuffers возвращают DXGI_ERROR_DEVICE_REMOVED/RESET, и старое
// устройство больше ничего не рисует — окно застыло бы до перезапуска. Создаём
// новое вместе с бэкендом ImGui, картинку фона загружаем заново.
// ------------------------------------------------------------------
bool g_devLost = false;
bool g_wpReload = false;                 // текстура фона пропала вместе с устройством

bool deviceLost(HRESULT hr) { return hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET; }

void dropDevice() {
    ImGui_ImplDX11_Shutdown();
    g_wpReload = g_wp.tex != 0;
    release(g_wpSrv);
    g_wp = WallpaperTex{};
    cleanupDevice();
    g_devLost = true;
    logLine(C::YEL, "Видеодрайвер сбросил Direct3D (обновление драйвера или сбой) — окно пересоздаёт устройство.");
}

// false — устройство пока не создаётся (драйвер ещё ставится): повторить позже
bool restoreDevice() {
    if (!createDevice(g_hwnd)) { cleanupDevice(); return false; }
    ImGui_ImplDX11_Init(g_dev, g_ctx);
    g_devLost = false;
    // картинку фона — заново, если её как раз не грузят (тогда текстура и так будет)
    if (g_wpReload && !g_wpJob) wallpaperLoad(g_wpShown);
    g_wpReload = false;
    return true;
}

std::wstring fontsDir() {
    wchar_t win[MAX_PATH];
    UINT n = GetWindowsDirectoryW(win, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"C:\\Windows\\Fonts\\";
    return std::wstring(win) + L"\\Fonts\\";
}

// Шрифт из папки Windows, если он есть (AddFontFromFileTTF в отладочной
// сборке падает на assert, если файла нет).
ImFont* addSystemFont(const wchar_t* file, float size, const ImFontConfig* fc = nullptr) {
    std::wstring path = fontsDir() + file;
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return nullptr;
    return ImGui::GetIO().Fonts->AddFontFromFileTTF(w2u8(path.c_str()).c_str(), size, fc);
}

// Символы (✓ ✗ ● ▲ …), которых нет в основном шрифте, — из Segoe UI Symbol.
void mergeSymbols(float size) {
    ImFontConfig fc;
    fc.MergeMode = true;
    addSystemFont(L"seguisym.ttf", size, &fc);
}

void setupFonts() {
    ImGuiIO& io = ImGui::GetIO();
    const float size = 17.0f;   // до масштаба DPI (его добавляет style.FontScaleDpi)
    ImFont* ui = addSystemFont(L"segoeui.ttf", size);
    if (ui) mergeSymbols(size);
    else io.Fonts->AddFontDefault();

    g_fontMono = addSystemFont(L"consola.ttf", 15.0f);
    if (g_fontMono) mergeSymbols(15.0f);
    io.FontDefault = ui;   // nullptr = первый добавленный
}

} // namespace

HWND mainHwnd() { return g_hwnd; }
void guiRequestClose() { if (g_hwnd) PostMessageW(g_hwnd, WM_CLOSE, 0, 0); }
bool guiCustomTitleBar() { return true; }
void guiMinimize() { if (g_hwnd) ShowWindow(g_hwnd, SW_MINIMIZE); }
void guiToggleMaximize() {
    if (g_hwnd) ShowWindow(g_hwnd, IsZoomed(g_hwnd) ? SW_RESTORE : SW_MAXIMIZE);
}
bool guiIsMaximized() { return g_hwnd && IsZoomed(g_hwnd); }
void guiSetCaptionArea(float left, float right, float height) {
    g_capL = left; g_capR = right; g_capH = height;
}

void wallpaperLoad(const std::wstring& path) {
    auto job = std::make_shared<WpJob>();
    job->path = path;
    MONITORINFO mi{ sizeof(mi) };
    GetMonitorInfoW(MonitorFromWindow(g_hwnd, MONITOR_DEFAULTTOPRIMARY), &mi);
    job->monW = std::max(640L, mi.rcMonitor.right - mi.rcMonitor.left);
    job->monH = std::max(480L, mi.rcMonitor.bottom - mi.rcMonitor.top);
    g_wpJob = job;
    try {
        std::thread([job] {
            // WIC — это COM: у потока своя инициализация
            const HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            job->ok = decodeImage(job->path, job->monW, job->monH, job->px, job->w, job->h, job->err);
            if (SUCCEEDED(co)) CoUninitialize();
            job->done = true;
        }).detach();
    } catch (const std::exception&) {
        job->err = "не удалось запустить загрузку";
        job->done = true;
    }
}

int wallpaperPoll(std::string& err) {
    if (!g_wpJob || !g_wpJob->done) return 0;
    const std::shared_ptr<WpJob> job = std::move(g_wpJob);
    if (!job->ok) { err = job->err; return -1; }
    if (!g_dev) { err = "Direct3D не готов"; return -1; }
    const std::vector<unsigned char>& px = job->px;
    const UINT w = job->w, h = job->h;

    D3D11_TEXTURE2D_DESC td{};
    td.Width = w;
    td.Height = h;
    td.MipLevels = 1;
    td.ArraySize = 1;
    td.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    td.SampleDesc.Count = 1;
    td.Usage = D3D11_USAGE_IMMUTABLE;
    td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    D3D11_SUBRESOURCE_DATA sd{ px.data(), w * 4, 0 };
    ID3D11Texture2D* tex = nullptr;
    if (FAILED(g_dev->CreateTexture2D(&td, &sd, &tex)) || !tex) {
        err = "видеокарта не приняла текстуру " + std::to_string(w) + "×" + std::to_string(h);
        return -1;
    }
    ID3D11ShaderResourceView* srv = nullptr;
    const HRESULT hr = g_dev->CreateShaderResourceView(tex, nullptr, &srv);
    tex->Release();
    if (FAILED(hr) || !srv) { err = "не удалось создать текстуру"; return -1; }

    // Прежнюю освобождаем сразу: gui.cpp зовёт wallpaperPoll в начале кадра, до
    // того как старая текстура попала в списки отрисовки этого кадра.
    release(g_wpSrv);
    g_wpSrv = srv;
    g_wp.tex = (ImTextureID)(intptr_t)srv;
    g_wp.w = (int)w;
    g_wp.h = (int)h;
    g_wp.builtin = job->path.empty();
    g_wpShown = job->path;
    return 1;
}

const WallpaperTex& wallpaperTex() { return g_wp; }

int RunGuiMain(const std::vector<std::string>& files) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    // COM — для WIC (картинка на фоне); диалоги выбора файла тоже его любят
    const HRESULT comHr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

    ImGui_ImplWin32_EnableDpiAwareness();
    const float scale = ImGui_ImplWin32_GetDpiScaleForMonitor(
        MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = wndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"TrafficAnalyzerGui";
    RegisterClassExW(&wc);
    g_hwnd = CreateWindowW(wc.lpszClassName, L"TrafficAnalyzer — MARYNONET",
                           WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                           (int)(1360 * scale), (int)(860 * scale),
                           nullptr, nullptr, wc.hInstance, nullptr);
    if (!g_hwnd || !createDevice(g_hwnd)) {
        cleanupDevice();
        if (g_hwnd) DestroyWindow(g_hwnd);
        UnregisterClassW(wc.lpszClassName, wc.hInstance);
        MessageBoxW(nullptr, L"Не удалось инициализировать Direct3D 11.\n"
                             L"Консольный режим: TrafficAnalyzer.exe --console",
                    L"TrafficAnalyzer", MB_ICONERROR);
        if (SUCCEEDED(comHr)) CoUninitialize();
        return 1;
    }
    // без системного заголовка (см. hitTest): пересчитать рамку, а тень и
    // скругление (Windows 11) оставить — DWM рисует их, пока рамка «есть»
    {
        const MARGINS m{ 0, 0, 1, 0 };
        DwmExtendFrameIntoClientArea(g_hwnd, &m);
        SetWindowPos(g_hwnd, nullptr, 0, 0, 0, 0,
                     SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    ShowWindow(g_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);
    DragAcceptFiles(g_hwnd, TRUE);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;       // раскладка фиксированная, imgui.ini не нужен

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    guiInit();                      // свои цвета/отступы — до масштабирования
    style.ScaleAllSizes(scale);
    style.FontScaleDpi = scale;

    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_dev, g_ctx);
    setupFonts();

    // весь вывод анализа — в журнал окна
    g_consoleEcho = false;
    g_outputSink = &sinkToLog;
    CoutToLog coutBuf;
    std::streambuf* oldOut = std::cout.rdbuf(&coutBuf);
    std::streambuf* oldErr = std::cerr.rdbuf(&coutBuf);

    logLine(C::BCYN, "TrafficAnalyzer — анализ дампов трафика абонента (MARYNONET)");
    logLine(C::GRY, "Откройте дамп (Ctrl+O) или перетащите .pcap/.pcapng/.txt на окно. "
                    "Два файла «..._in» и «..._out» загружаются как один набор.");
    if (!cfg().warnings.empty()) {
        logLine(C::YEL, "Ошибки в " + (cfg().loadedFrom.empty() ? std::string("analyzer.ini")
                                                                : cfg().loadedFrom) + ":");
        for (const auto& w : cfg().warnings) logLine(C::YEL, "  " + w);
    }
    if (!files.empty()) startLoad(files);

    int titleLight = -1;            // заголовок окна: тёмный/светлый — по теме
    bool done = false;
    while (!done) {
        // В фоне, без задачи и без анимации — не крутим кадры впустую
        // (ждём ввода или 250 мс).
        if (GetForegroundWindow() != g_hwnd && !jobBusy() && !guiWantsFrames())
            MsgWaitForMultipleObjects(0, nullptr, FALSE, 250, QS_ALLINPUT);

        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        // устройство потеряно — пересоздаём; не вышло (драйвер ещё ставится) — ждём
        if (g_devLost && !restoreDevice()) {
            Sleep(500);
            continue;
        }

        if (g_occluded && g_swap->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
            Sleep(10);
            continue;
        }
        g_occluded = false;

        if (g_resizeW != 0 && g_resizeH != 0) {
            cleanupRenderTarget();
            const HRESULT hr = g_swap->ResizeBuffers(0, g_resizeW, g_resizeH, DXGI_FORMAT_UNKNOWN, 0);
            g_resizeW = g_resizeH = 0;
            // новая цепочка обмена всё равно возьмёт текущий размер окна
            if (deviceLost(hr)) { dropDevice(); continue; }
            createRenderTarget();
        }

        if (!g_dropped.empty()) {
            if (jobBusy()) logLine(C::YEL, "Идёт задача — дождитесь окончания и перетащите файл снова.");
            else startLoad(g_dropped);
            g_dropped.clear();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        guiFrame();
        ImGui::Render();

        const int light = guiLightTheme() ? 1 : 0;
        if (light != titleLight) {
            // DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 10 20H1+; раньше — просто ошибка)
            const BOOL dark = light ? FALSE : TRUE;
            DwmSetWindowAttribute(g_hwnd, 20, &dark, sizeof(dark));
            titleLight = light;
        }

        const ImVec4 clear = guiClearColor();
        const float cc[4] = { clear.x, clear.y, clear.z, clear.w };
        // цели рисования нет (не создалась после смены размера) — не очищаем:
        // ClearRenderTargetView(nullptr) недопустим
        if (g_rtv) {
            g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
            g_ctx->ClearRenderTargetView(g_rtv, cc);
        }
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        HRESULT hr = g_swap->Present(1, 0);
        g_occluded = (hr == DXGI_STATUS_OCCLUDED);
        if (deviceLost(hr)) dropDevice();
    }

    // Задача ещё идёт (резолв/анализ может занять минуты) — ждать её при
    // закрытии окна незачем: закрываем отчёт и завершаем процесс.
    if (jobMustAbortOnExit()) {
        closeReport();
        ExitProcess(0);
    }

    g_outputSink = nullptr;
    std::cout.rdbuf(oldOut);
    std::cerr.rdbuf(oldErr);

    if (!g_devLost) ImGui_ImplDX11_Shutdown();   // при потере устройства — уже в dropDevice
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    release(g_wpSrv);
    g_wp = WallpaperTex{};
    cleanupDevice();
    DestroyWindow(g_hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    if (SUCCEEDED(comHr)) CoUninitialize();
    WSACleanup();
    return 0;
}
