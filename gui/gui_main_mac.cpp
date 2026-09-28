// gui_main_mac.cpp — окно GUI на macOS: GLFW + OpenGL 3 + Dear ImGui, шрифты
// из системы, перетаскивание файлов, перехват std::cout в журнал окна.
// Аналог gui_main.cpp (Win32 + D3D11); интерфейс общий — gui.cpp.
// Основа цикла — пример example_glfw_opengl3 из Dear ImGui (MIT).
#include "gui.h"
#include "gui_app.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <OpenGL/gl3.h>
#include <ImageIO/ImageIO.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreFoundation/CoreFoundation.h>

ImFont* g_fontMono = nullptr;

namespace {

GLFWwindow* g_win = nullptr;
std::vector<std::string> g_dropped;     // файлы, брошенные на окно (поток окна)

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

void onGlfwError(int code, const char* text) {
    fprintf(stderr, "GLFW %d: %s\n", code, text ? text : "");
}

void onDrop(GLFWwindow*, int n, const char** paths) {
    for (int i = 0; i < n; i++)
        if (paths[i] && *paths[i]) g_dropped.push_back(paths[i]);
}

// ------------------------------------------------------------------
// Картинка на фоне: ImageIO декодирует (jpg/png/heic/webp/tiff/gif/bmp),
// CoreGraphics рисует в RGBA-буфер, дальше — текстура OpenGL для ImGui.
// ------------------------------------------------------------------
GLuint g_wpGl = 0;
WallpaperTex g_wp;

// Размер основного монитора в пикселях (для уменьшения большой картинки).
void monitorPixels(double& w, double& h) {
    w = 1920; h = 1080;
    GLFWmonitor* mon = glfwGetPrimaryMonitor();
    const GLFWvidmode* mode = mon ? glfwGetVideoMode(mon) : nullptr;
    if (!mode) return;
    float sx = 1, sy = 1;
    glfwGetMonitorContentScale(mon, &sx, &sy);
    w = std::max(640.0, mode->width * (double)sx);
    h = std::max(480.0, mode->height * (double)sy);
}

// Декодирует в RGBA 8 бит. Картинку крупнее монитора уменьшает заранее
// (сэмплер ImGui без мип-уровней — при сильном уменьшении на лету была бы рябь).
bool decodeImage(const std::string& path, std::vector<unsigned char>& px, int& w, int& h,
                 std::string& err) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        nullptr, (const UInt8*)path.data(), (CFIndex)path.size(), false);
    CGImageSourceRef src = url ? CGImageSourceCreateWithURL(url, nullptr) : nullptr;
    if (url) CFRelease(url);
    if (!src) { err = "файл не читается"; return false; }
    CGImageRef img = CGImageSourceGetCount(src) > 0
                         ? CGImageSourceCreateImageAtIndex(src, 0, nullptr) : nullptr;
    CFRelease(src);
    if (!img) { err = "формат не поддерживается"; return false; }

    const double sw = (double)CGImageGetWidth(img), sh = (double)CGImageGetHeight(img);
    if (sw < 1 || sh < 1) { CGImageRelease(img); err = "пустое изображение"; return false; }
    double monW, monH;
    monitorPixels(monW, monH);
    // «cover» на весь монитор с запасом 10% на движение
    const double k = std::max(monW / sw, monH / sh) * 1.1;
    w = (int)sw; h = (int)sh;
    if (k < 0.95) {
        w = std::max(1, (int)(sw * k));
        h = std::max(1, (int)(sh * k));
    }
    if (w > 8192 || h > 8192) { CGImageRelease(img); err = "слишком вытянутое изображение"; return false; }

    px.assign((size_t)w * h * 4, 0);
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(px.data(), (size_t)w, (size_t)h, 8, (size_t)w * 4, cs,
                                             kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(cs);
    if (!ctx) { CGImageRelease(img); err = "не удалось декодировать изображение"; return false; }
    CGContextSetInterpolationQuality(ctx, kCGInterpolationHigh);
    CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), img);
    CGContextRelease(ctx);
    CGImageRelease(img);
    return true;
}

// Шрифт из системы, если файл есть (AddFontFromFileTTF в отладочной сборке
// падает на assert, если файла нет). Берёт первый найденный из списка.
ImFont* addSystemFont(std::initializer_list<const char*> files, float size,
                      const ImFontConfig* fc = nullptr) {
    for (const char* f : files)
        if (access(f, R_OK) == 0)
            return ImGui::GetIO().Fonts->AddFontFromFileTTF(f, size, fc);
    return nullptr;
}

// Символы (✓ ✗ ● ▲ …), которых нет в основном шрифте.
void mergeSymbols(float size) {
    ImFontConfig fc;
    fc.MergeMode = true;
    addSystemFont({ "/System/Library/Fonts/Apple Symbols.ttf" }, size, &fc);
    addSystemFont({ "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
                    "/Library/Fonts/Arial Unicode.ttf" }, size, &fc);
}

void setupFonts() {
    ImGuiIO& io = ImGui::GetIO();
    // размеры — в пунктах macOS; Retina ImGui учитывает сам (DisplayFramebufferScale)
    const float size = 15.0f;
    ImFont* ui = addSystemFont({ "/System/Library/Fonts/SFNS.ttf",
                                 "/System/Library/Fonts/HelveticaNeue.ttc",
                                 "/System/Library/Fonts/Helvetica.ttc" }, size);
    if (ui) mergeSymbols(size);
    else io.Fonts->AddFontDefault();

    g_fontMono = addSystemFont({ "/System/Library/Fonts/Menlo.ttc",
                                 "/System/Library/Fonts/SFNSMono.ttf",
                                 "/System/Library/Fonts/Monaco.ttf" }, 13.0f);
    if (g_fontMono) mergeSymbols(13.0f);
    io.FontDefault = ui;   // nullptr = первый добавленный
}

} // namespace

HWND mainHwnd() { return nullptr; }
void guiRequestClose() { if (g_win) glfwSetWindowShouldClose(g_win, GLFW_TRUE); }

bool wallpaperLoad(const std::wstring& path, std::string& err) {
    if (!g_win) { err = "OpenGL не готов"; return false; }
    // встроенная — anime_bg.jpg рядом с программой (CMake кладёт его туда)
    const std::string file = path.empty() ? exeDirUtf8() + "anime_bg.jpg" : w2u8(path.c_str());
    if (path.empty() && access(file.c_str(), R_OK) != 0) {
        err = "нет файла anime_bg.jpg рядом с программой";
        return false;
    }
    std::vector<unsigned char> px;
    int w = 0, h = 0;
    if (!decodeImage(file, px, w, h, err)) return false;

    GLint maxTex = 0;
    glGetIntegerv(GL_MAX_TEXTURE_SIZE, &maxTex);
    if (maxTex > 0 && (w > maxTex || h > maxTex)) {
        err = "видеокарта не приняла текстуру " + std::to_string(w) + "×" + std::to_string(h);
        return false;
    }
    GLuint tex = 0;
    glGenTextures(1, &tex);
    if (!tex) { err = "не удалось создать текстуру"; return false; }
    glBindTexture(GL_TEXTURE_2D, tex);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, px.data());
    glBindTexture(GL_TEXTURE_2D, 0);
    if (glGetError() != GL_NO_ERROR) {
        glDeleteTextures(1, &tex);
        err = "видеокарта не приняла текстуру " + std::to_string(w) + "×" + std::to_string(h);
        return false;
    }

    // Прежнюю освобождаем сразу: gui.cpp зовёт загрузку в начале кадра, до
    // того как старая текстура попала в списки отрисовки этого кадра.
    if (g_wpGl) glDeleteTextures(1, &g_wpGl);
    g_wpGl = tex;
    g_wp.tex = (ImTextureID)(intptr_t)tex;
    g_wp.w = w;
    g_wp.h = h;
    g_wp.builtin = path.empty();
    return true;
}

const WallpaperTex& wallpaperTex() { return g_wp; }

int RunGuiMain(const std::vector<std::string>& files) {
    glfwSetErrorCallback(onGlfwError);
    if (!glfwInit()) {
        fprintf(stderr, "TrafficAnalyzer: не удалось запустить окно (GLFW).\n"
                        "Консольный режим: TrafficAnalyzer --console\n");
        return 1;
    }
    // OpenGL 3.2 core — максимум, что даёт macOS (и ровно то, что нужно бэкенду ImGui)
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

    // окно 1360×860 пт, но не больше рабочей области экрана (MacBook Air — 1440×900)
    int winW = 1360, winH = 860;
    if (GLFWmonitor* mon = glfwGetPrimaryMonitor()) {
        int ax = 0, ay = 0, aw = 0, ah = 0;
        glfwGetMonitorWorkarea(mon, &ax, &ay, &aw, &ah);
        if (aw > 0 && ah > 0) {
            winW = std::min(winW, aw * 92 / 100);
            winH = std::min(winH, ah * 92 / 100);
        }
    }
    g_win = glfwCreateWindow(winW, winH, "TrafficAnalyzer — MARYNONET", nullptr, nullptr);
    if (!g_win) {
        glfwTerminate();
        fprintf(stderr, "TrafficAnalyzer: не удалось создать окно OpenGL 3.2.\n"
                        "Консольный режим: TrafficAnalyzer --console\n");
        return 1;
    }
    glfwSetWindowSizeLimits(g_win, 800, 500, GLFW_DONT_CARE, GLFW_DONT_CARE);
    glfwMakeContextCurrent(g_win);
    glfwSwapInterval(1);            // vsync
    glfwSetDropCallback(g_win, onDrop);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;       // раскладка фиксированная, imgui.ini не нужен

    // Координаты на macOS — в пунктах, Retina (×2) ImGui учитывает сам:
    // ScaleAllSizes не нужен.
    ImGui::StyleColorsDark();
    guiInit();

    ImGui_ImplGlfw_InitForOpenGL(g_win, true);
    ImGui_ImplOpenGL3_Init("#version 150");
    setupFonts();

    // весь вывод анализа — в журнал окна
    g_consoleEcho = false;
    g_outputSink = &sinkToLog;
    CoutToLog coutBuf;
    std::streambuf* oldOut = std::cout.rdbuf(&coutBuf);
    std::streambuf* oldErr = std::cerr.rdbuf(&coutBuf);

    logLine(C::BCYN, "TrafficAnalyzer — анализ дампов трафика абонента (MARYNONET, AS39709)");
    logLine(C::GRY, "Откройте дамп (Cmd+O) или перетащите .pcap/.pcapng/.txt на окно. "
                    "Два файла «..._in» и «..._out» загружаются как один набор.");
    if (!cfg().warnings.empty()) {
        logLine(C::YEL, "Ошибки в " + (cfg().loadedFrom.empty() ? std::string("analyzer.ini")
                                                                : cfg().loadedFrom) + ":");
        for (const auto& w : cfg().warnings) logLine(C::YEL, "  " + w);
    }
    if (!files.empty()) startLoad(files);

    while (!glfwWindowShouldClose(g_win)) {
        // В фоне, без задачи и без анимации — не крутим кадры впустую
        // (ждём ввода или 250 мс).
        if (!glfwGetWindowAttrib(g_win, GLFW_FOCUSED) && !jobBusy() && !guiWantsFrames())
            glfwWaitEventsTimeout(0.25);
        else
            glfwPollEvents();
        if (glfwGetWindowAttrib(g_win, GLFW_ICONIFIED)) {
            glfwWaitEventsTimeout(0.1);
            continue;
        }

        if (!g_dropped.empty()) {
            if (jobBusy()) logLine(C::YEL, "Идёт задача — дождитесь окончания и перетащите файл снова.");
            else startLoad(g_dropped);
            g_dropped.clear();
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        guiFrame();
        ImGui::Render();

        int fbW = 0, fbH = 0;
        glfwGetFramebufferSize(g_win, &fbW, &fbH);
        const ImVec4 clear = guiClearColor();
        glViewport(0, 0, fbW, fbH);
        glClearColor(clear.x, clear.y, clear.z, clear.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(g_win);
    }

    // Задача ещё идёт (резолв/анализ может занять минуты) — ждать её при
    // закрытии окна незачем: закрываем отчёт и завершаем процесс.
    if (jobMustAbortOnExit()) {
        closeReport();
        fflush(nullptr);
        _exit(0);
    }

    g_outputSink = nullptr;
    std::cout.rdbuf(oldOut);
    std::cerr.rdbuf(oldErr);

    if (g_wpGl) { glDeleteTextures(1, &g_wpGl); g_wpGl = 0; }
    g_wp = WallpaperTex{};
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(g_win);
    g_win = nullptr;
    glfwTerminate();
    return 0;
}
