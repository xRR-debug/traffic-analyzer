// Фаззер разбора TLS ClientHello: JA4 (TCP и QUIC), SNI, ECH, поток TLS-записей.
// Вход — сырые байты, как они лежали бы в полезной нагрузке TCP.
// Собирается отдельно от программы (fuzz/build_fuzz.cmd, шаг Fuzz в CI):
//   cl /DTA_FUZZ /fsanitize=fuzzer /fsanitize=address fuzz\fuzz_hello.cpp parser.cpp
#include "../common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    fuzzParseClientHello(data, size);
    return 0;
}
