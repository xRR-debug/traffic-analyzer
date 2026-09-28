// gui_log.cpp — журнал вывода в окне: приём текста с ANSI-цветами из любого
// потока, хранение одной строкой + индекс строк, отрисовка через клиппер
// (видимые строки только), фильтр по подстроке.
#include "gui_app.h"

namespace {

// Палитры ANSI-цветов. Индекс: 0 — по умолчанию, 1..8 — коды 30..37,
// 9..16 — яркие 90..97.
const ImVec4 kPalDark[17] = {
    ImVec4(0, 0, 0, 0),
    ImVec4(0.45f, 0.45f, 0.45f, 1), ImVec4(0.95f, 0.38f, 0.38f, 1),   // 30, 31
    ImVec4(0.42f, 0.85f, 0.45f, 1), ImVec4(0.95f, 0.80f, 0.35f, 1),   // 32, 33
    ImVec4(0.45f, 0.60f, 0.98f, 1), ImVec4(0.85f, 0.50f, 0.90f, 1),   // 34, 35
    ImVec4(0.40f, 0.82f, 0.88f, 1), ImVec4(0.86f, 0.86f, 0.86f, 1),   // 36, 37
    ImVec4(0.55f, 0.55f, 0.58f, 1), ImVec4(1.00f, 0.45f, 0.45f, 1),   // 90, 91
    ImVec4(0.50f, 0.95f, 0.55f, 1), ImVec4(1.00f, 0.90f, 0.45f, 1),   // 92, 93
    ImVec4(0.55f, 0.70f, 1.00f, 1), ImVec4(0.95f, 0.60f, 1.00f, 1),   // 94, 95
    ImVec4(0.50f, 0.92f, 0.98f, 1), ImVec4(1.00f, 1.00f, 1.00f, 1),   // 96, 97
};

// Для светлой темы: те же оттенки темнее; «белый» (37/97, им выделяют
// важное) становится почти чёрным, иначе на белом фоне его не видно.
const ImVec4 kPalLight[17] = {
    ImVec4(0, 0, 0, 0),
    ImVec4(0.35f, 0.35f, 0.35f, 1), ImVec4(0.78f, 0.15f, 0.15f, 1),   // 30, 31
    ImVec4(0.10f, 0.52f, 0.15f, 1), ImVec4(0.66f, 0.45f, 0.00f, 1),   // 32, 33
    ImVec4(0.15f, 0.30f, 0.80f, 1), ImVec4(0.60f, 0.20f, 0.65f, 1),   // 34, 35
    ImVec4(0.00f, 0.48f, 0.58f, 1), ImVec4(0.25f, 0.25f, 0.27f, 1),   // 36, 37
    ImVec4(0.48f, 0.48f, 0.50f, 1), ImVec4(0.86f, 0.18f, 0.18f, 1),   // 90, 91
    ImVec4(0.12f, 0.60f, 0.20f, 1), ImVec4(0.74f, 0.52f, 0.00f, 1),   // 92, 93
    ImVec4(0.20f, 0.38f, 0.92f, 1), ImVec4(0.70f, 0.24f, 0.76f, 1),   // 94, 95
    ImVec4(0.00f, 0.55f, 0.68f, 1), ImVec4(0.04f, 0.04f, 0.05f, 1),   // 96, 97
};

std::string lowerAscii(const std::string& s) {
    std::string r = s;
    for (char& c : r) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return r;
}

// Поиск без учёта регистра латиницы. Кириллица сравнивается как есть.
bool containsCi(const char* b, const char* e, const std::string& needleLower) {
    size_t n = needleLower.size();
    if (n == 0) return true;
    if ((size_t)(e - b) < n) return false;
    for (const char* p = b; p + n <= e; ++p) {
        size_t i = 0;
        for (; i < n; ++i) {
            char c = p[i];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            if (c != needleLower[i]) break;
        }
        if (i == n) return true;
    }
    return false;
}

// Больше этого не храним: журнал очищается с пометкой (защита от
// бесконечного вывода, который съел бы всю память).
const size_t kMaxLogBytes = 256u * 1024u * 1024u;

// Длина UTF-8 символа по первому байту (битый байт — 1, чтобы не зациклиться).
size_t utf8Len(unsigned char c) {
    if (c < 0x80) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

} // namespace

LogBuffer& appLog() {
    static LogBuffer log;
    return log;
}

void logLine(const char* ansiColor, const std::string& text) {
    std::string s;
    if (ansiColor) s += ansiColor;
    s += text;
    if (ansiColor) s += C::RST;
    s += "\n";
    appLog().append(s.data(), s.size());
}

void LogBuffer::newLineLocked() {
    text_ += '\n';
    lineStart_.push_back(text_.size());
}

void LogBuffer::append(const char* s, size_t n) {
    std::lock_guard<std::mutex> lk(mx_);
    if (text_.size() > kMaxLogBytes) {
        text_.clear(); lineStart_.assign(1, 0); runs_.clear();
        filtered_.clear(); filteredUpTo_ = 0; curCol_ = 0;
        resetSelectionLocked();
        // inEsc_/esc_ не сбрасываем: незаконченная escape-последовательность
        // продолжится в этом же s и должна быть съедена, а не выведена текстом
        const char* note = "[журнал превысил 256 МБ и был очищен]";
        text_ += note;
        newLineLocked();
    }
    auto setColor = [&](unsigned char col) {
        if (col == curCol_) return;
        curCol_ = col;
        if (!runs_.empty() && runs_.back().off == text_.size()) runs_.back().col = col;
        else runs_.push_back({ text_.size(), col });
    };
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        if (inEsc_) {
            esc_ += c;
            bool isFinal = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
            if (isFinal) {
                if (c == 'm') {
                    // SGR: "[31m", "[0m", "[1;33m" ...
                    int num = 0; bool have = false;
                    for (size_t k = 1; k < esc_.size(); ++k) {
                        char d = esc_[k];
                        if (d >= '0' && d <= '9') { num = num * 10 + (d - '0'); have = true; continue; }
                        // ';' или 'm' — число закончилось
                        int v = have ? num : 0;
                        if (v == 0) setColor(0);
                        else if (v >= 30 && v <= 37) setColor((unsigned char)(v - 30 + 1));
                        else if (v >= 90 && v <= 97) setColor((unsigned char)(v - 90 + 9));
                        else if (v == 39) setColor(0);
                        num = 0; have = false;
                    }
                }
                inEsc_ = false; esc_.clear();
            } else if (esc_.size() > 32) {
                inEsc_ = false; esc_.clear();   // мусор — не escape
            }
            continue;
        }
        switch (c) {
        case '\x1b': inEsc_ = true; esc_.clear(); break;
        case '\r': case '\b': case '\a': break;
        case '\n': newLineLocked(); break;
        case '\t': text_ += "    "; break;
        default: text_ += c; break;
        }
    }
}

void LogBuffer::clear() {
    std::lock_guard<std::mutex> lk(mx_);
    text_.clear(); lineStart_.assign(1, 0); runs_.clear();
    curCol_ = 0; inEsc_ = false; esc_.clear();
    filtered_.clear(); filteredUpTo_ = 0; lastDrawnLines_ = 0;
    resetSelectionLocked();
}

std::string LogBuffer::text() {
    std::lock_guard<std::mutex> lk(mx_);
    return text_;
}

void LogBuffer::resetSelectionLocked() {
    selAnchor_ = selCursor_ = TextPos();
    selDragging_ = false;
}

// Выделенный текст. При включённом фильтре — только видимые (прошедшие
// фильтр) строки, как их видит пользователь.
std::string LogBuffer::selectedTextLocked() {
    TextPos s = selAnchor_, e = selCursor_;
    if (e.line < s.line || (e.line == s.line && e.off < s.off)) std::swap(s, e);
    const size_t nLines = lineStart_.size();
    std::string out;
    if (s.line == e.line && s.off == e.off) return out;
    bool first = true;
    for (size_t li = s.line; li <= e.line && li < nLines; ++li) {
        const size_t b = lineStart_[li];
        const size_t end = (li + 1 < nLines) ? lineStart_[li + 1] - 1 : text_.size();
        if (!filter_.empty() && !containsCi(text_.data() + b, text_.data() + end, filter_)) continue;
        const size_t len = end - b;
        const size_t from = (li == s.line) ? std::min(s.off, len) : 0;
        const size_t to   = (li == e.line) ? std::min(e.off, len) : len;
        if (!first) out += '\n';
        first = false;
        if (to > from) out.append(text_, b + from, to - from);
    }
    return out;
}

std::string LogBuffer::selectedText() {
    std::lock_guard<std::mutex> lk(mx_);
    return selectedTextLocked();
}

bool LogBuffer::hasSelection() {
    std::lock_guard<std::mutex> lk(mx_);
    return selAnchor_.line != selCursor_.line || selAnchor_.off != selCursor_.off;
}

void LogBuffer::selectAllLocked() {
    const size_t nLines = lineStart_.size();
    selAnchor_ = { 0, 0 };
    selCursor_ = { nLines - 1, text_.size() - lineStart_[nLines - 1] };
    selDragging_ = false;
}

void LogBuffer::selectAll() {
    std::lock_guard<std::mutex> lk(mx_);
    selectAllLocked();
}

size_t LogBuffer::lineCount() {
    std::lock_guard<std::mutex> lk(mx_);
    return lineStart_.size();
}

void LogBuffer::rebuildFilterLocked(const std::string& f) {
    filter_ = f;
    filtered_.clear();
    filteredUpTo_ = 0;
}

void LogBuffer::draw(const char* filter, bool autoScroll) {
    // строка под курсором и строка, для которой открыто контекстное меню
    static std::string s_ctxLineText;
    std::string hoveredText;
    bool hoveredValid = false;

    {
        std::lock_guard<std::mutex> lk(mx_);
        std::string f = lowerAscii(filter ? filter : "");
        if (f != filter_) rebuildFilterLocked(f);

        const size_t nLines = lineStart_.size();
        auto lineEnd = [&](size_t li) {
            return (li + 1 < nLines) ? lineStart_[li + 1] - 1 : text_.size();
        };
        // полные строки проверяем один раз, последнюю (недописанную) — каждый кадр
        bool lastMatches = true;
        if (!filter_.empty()) {
            for (; filteredUpTo_ + 1 < nLines; ++filteredUpTo_) {
                size_t li = filteredUpTo_;
                if (containsCi(text_.data() + lineStart_[li], text_.data() + lineEnd(li), filter_))
                    filtered_.push_back(li);
            }
            size_t li = nLines - 1;
            lastMatches = lineStart_[li] < text_.size() &&
                containsCi(text_.data() + lineStart_[li], text_.data() + lineEnd(li), filter_);
        }
        size_t count = filter_.empty() ? nLines : filtered_.size() + (lastMatches ? 1 : 0);

        // прилипание к низу: если пользователь уже внизу — едем за новыми строками
        bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 2.0f;
        const float mouseY = ImGui::GetIO().MousePos.y;
        const bool winHovered = ImGui::IsWindowHovered();
        const ImVec4* pal = guiLightTheme() ? kPalLight : kPalDark;

        auto drawLine = [&](size_t li) {
            const size_t b = lineStart_[li], e = lineEnd(li);
            // цвет на начало строки — последняя смена цвета не позже b
            auto it = std::upper_bound(runs_.begin(), runs_.end(), b,
                                       [](size_t v, const Run& r) { return v < r.off; });
            unsigned char col = (it == runs_.begin()) ? 0 : std::prev(it)->col;
            size_t pos = b;
            bool first = true;
            while (pos < e) {
                size_t segEnd = (it != runs_.end() && it->off < e) ? it->off : e;
                if (segEnd > pos) {
                    if (!first) ImGui::SameLine(0, 0);
                    if (col) ImGui::PushStyleColor(ImGuiCol_Text, pal[col]);
                    ImGui::TextUnformatted(text_.data() + pos, text_.data() + segEnd);
                    if (col) ImGui::PopStyleColor();
                    first = false;
                }
                pos = segEnd;
                if (it != runs_.end() && it->off <= pos && pos < e) { col = it->col; ++it; }
            }
            if (first) ImGui::TextUnformatted("");
        };

        // ---- выделение мышью ----
        // Строки идут с постоянным шагом, поэтому строку под мышью считаем по
        // геометрии, а не по тому, что клиппер успел нарисовать: так работает и
        // протяжка за пределы окна (там строки не рисуются).
        auto rowToLine = [&](size_t r) {
            if (filter_.empty()) return r;
            return r < filtered_.size() ? filtered_[r] : nLines - 1;
        };
        const ImVec2 origin = ImGui::GetCursorScreenPos();
        const float itemH = ImGui::GetTextLineHeightWithSpacing();
        // байт в строке li, ближайший к экранной координате x (по границам символов)
        auto hitOff = [&](size_t li, float x) -> size_t {
            const char* b = text_.data() + lineStart_[li];
            const char* e = text_.data() + lineEnd(li);
            const char* p = b;
            float cx = origin.x;
            while (p < e) {
                const char* q = p + utf8Len((unsigned char)*p);
                if (q > e) q = e;
                const float w = ImGui::CalcTextSize(p, q).x;
                if (x < cx + w * 0.5f) break;
                cx += w; p = q;
            }
            return (size_t)(p - b);
        };
        auto posAt = [&](const ImVec2& m) -> TextPos {
            const float fr = (m.y - origin.y) / itemH;
            if (fr < 0) return { rowToLine(0), 0 };
            const size_t r = (size_t)fr;
            if (r >= count) {
                const size_t li = rowToLine(count - 1);
                return { li, lineEnd(li) - lineStart_[li] };
            }
            const size_t li = rowToLine(r);
            return { li, hitOff(li, m.x) };
        };
        const ImGuiIO& io = ImGui::GetIO();
        const ImGuiStyle& st = ImGui::GetStyle();
        const ImVec2 wp = ImGui::GetWindowPos(), ws = ImGui::GetWindowSize();
        // область текста — без полос прокрутки (клик по ним не выделение)
        const float visMaxX = wp.x + ws.x - (ImGui::GetScrollMaxY() > 0 ? st.ScrollbarSize : 0.0f);
        const float visMaxY = wp.y + ws.y - (ImGui::GetScrollMaxX() > 0 ? st.ScrollbarSize : 0.0f);
        const bool inText = winHovered && io.MousePos.x < visMaxX && io.MousePos.y < visMaxY;
        if (selAnchor_.line >= nLines || selCursor_.line >= nLines) resetSelectionLocked();
        if (count > 0) {
            if (inText && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                const TextPos p = posAt(io.MousePos);
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    // двойной клик — вся строка
                    selAnchor_ = { p.line, 0 };
                    selCursor_ = { p.line, lineEnd(p.line) - lineStart_[p.line] };
                    selDragging_ = false;
                } else {
                    if (!io.KeyShift) selAnchor_ = p;   // Shift+клик — продлить выделение
                    selCursor_ = p;
                    selDragging_ = true;
                }
            } else if (selDragging_) {
                if (ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
                    selCursor_ = posAt(io.MousePos);
                    // протяжка за край окна — прокручиваем, тем быстрее, чем дальше мышь
                    if (io.MousePos.y < wp.y)
                        ImGui::SetScrollY(ImGui::GetScrollY() - std::max(itemH, wp.y - io.MousePos.y));
                    else if (io.MousePos.y > visMaxY)
                        ImGui::SetScrollY(ImGui::GetScrollY() + std::max(itemH, io.MousePos.y - visMaxY));
                } else {
                    selDragging_ = false;
                }
            }
        }
        if (ImGui::IsWindowFocused() && io.KeyCtrl) {
            if (ImGui::IsKeyPressed(ImGuiKey_A, false)) selectAllLocked();
            if (ImGui::IsKeyPressed(ImGuiKey_C, false)) {
                const std::string sel = selectedTextLocked();
                if (!sel.empty()) ImGui::SetClipboardText(sel.c_str());
            }
        }
        TextPos selS = selAnchor_, selE = selCursor_;
        if (selE.line < selS.line || (selE.line == selS.line && selE.off < selS.off)) std::swap(selS, selE);
        const bool haveSel = selS.line != selE.line || selS.off != selE.off;
        ImDrawList* dl = ImGui::GetWindowDrawList();
        const ImU32 selCol = ImGui::GetColorU32(ImGuiCol_TextSelectedBg);
        const float lineH = ImGui::GetTextLineHeight();
        const float nlW = ImGui::CalcTextSize(" ").x * 0.5f;   // «перевод строки» в выделении

        ImGuiListClipper clipper;
        clipper.Begin((int)count);
        while (clipper.Step()) {
            for (int r = clipper.DisplayStart; r < clipper.DisplayEnd; ++r) {
                const size_t li = rowToLine((size_t)r);
                const ImVec2 p0 = ImGui::GetCursorScreenPos();
                // подсветка выделения — до текста, чтобы текст был поверх
                if (haveSel && li >= selS.line && li <= selE.line) {
                    const char* base = text_.data() + lineStart_[li];
                    const size_t len = lineEnd(li) - lineStart_[li];
                    const size_t a = (li == selS.line) ? std::min(selS.off, len) : 0;
                    const size_t z = (li == selE.line) ? std::min(selE.off, len) : len;
                    const float x0 = p0.x + ImGui::CalcTextSize(base, base + a).x;
                    float x1 = p0.x + ImGui::CalcTextSize(base, base + z).x;
                    if (li != selE.line) x1 += nlW;
                    if (x1 > x0) dl->AddRectFilled(ImVec2(x0, p0.y), ImVec2(x1, p0.y + lineH), selCol);
                }
                drawLine(li);
                const float y1 = ImGui::GetCursorScreenPos().y;
                if (winHovered && mouseY >= p0.y && mouseY < y1) {
                    hoveredText.assign(text_.data() + lineStart_[li], text_.data() + lineEnd(li));
                    hoveredValid = true;
                }
            }
        }
        clipper.End();

        // пока тянут выделение, к низу не прилипаем — иначе текст уедет из-под мыши
        if (autoScroll && atBottom && !selDragging_ && count != lastDrawnLines_) ImGui::SetScrollHereY(1.0f);
        lastDrawnLines_ = count;
    }

    // контекстное меню — уже без блокировки журнала
    if (ImGui::IsWindowHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Right)) {
        s_ctxLineText = hoveredValid ? hoveredText : std::string();
        ImGui::OpenPopup("##logctx");
    }
    if (ImGui::BeginPopup("##logctx")) {
        // текст собираем только по клику: при «выделить всё» это весь журнал
        if (ImGui::MenuItem("Копировать выделенное", "Ctrl+C", false, hasSelection()))
            ImGui::SetClipboardText(selectedText().c_str());
        if (ImGui::MenuItem("Выделить всё", "Ctrl+A")) selectAll();
        if (ImGui::MenuItem("Копировать строку", nullptr, false, !s_ctxLineText.empty()))
            ImGui::SetClipboardText(s_ctxLineText.c_str());
        if (ImGui::MenuItem("Копировать весь журнал"))
            ImGui::SetClipboardText(text().c_str());
        ImGui::EndPopup();
    }
}
