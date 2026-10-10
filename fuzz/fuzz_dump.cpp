// Фаззер разбора дампа: pcap, pcapng и текст tcpdump из произвольных байт.
// Собирается отдельно от программы (fuzz/build_fuzz.cmd, шаг Fuzz в CI):
//   cl /DTA_FUZZ /fsanitize=fuzzer /fsanitize=address fuzz\fuzz_dump.cpp parser.cpp
// Ищем падения, выходы за границы и зависания; результат разбора не проверяем.
#include "../common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // разбор зависит от локального адреса (направление пакетов) — сбрасываем,
    // чтобы прогоны не влияли друг на друга
    g_localIp.clear();
    g_localIp6.clear();
    std::vector<Packet> out;
    std::string err, warn;
    parseDumpBuffer(data, size, out, err, warn);
    return 0;
}
