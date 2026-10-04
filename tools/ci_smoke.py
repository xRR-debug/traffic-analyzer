#!/usr/bin/env python3
# ci_smoke.py — дымовой прогон для CI: дампы из gen_test_dumps.py через
# TrafficAnalyzer --batch. Проверяется только, что анализ доходит до конца:
# код возврата 0, отчёт не пустой, без [FATAL]. Содержимое отчётов не
# сверяется — они (без ANSI-цветов) остаются в <каталог>/reports/.
#
# Режим 2 (соединения) — для всех файлов, режим 1 (VPN) — только для .pcap:
# разбор формата у режимов общий, а ip-api.com пускает 15 пакетных запросов
# в минуту. Сеть для проверки не обязательна: без ответа ip-api отчёт просто
# выходит без ASN.
#
# --quick — только .pcap в режиме 2: проверить, что сборка вообще запускается и
# анализирует (например, x86_64-половина универсального бинарника macOS).
#
# Запуск: python ci_smoke.py [--quick] каталог_дампов путь_к_программе

import glob
import os
import re
import subprocess
import sys
import time

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TIMEOUT = 180   # с на один прогон: зависание — тоже ошибка


def run(exe, dumps, path, mode, out):
    try:
        rc = subprocess.run([exe, "--batch", str(mode), "--out", out, path],
                            cwd=dumps, timeout=TIMEOUT).returncode
    except subprocess.TimeoutExpired:
        rc = "таймаут %d с" % TIMEOUT
    text = ""
    if os.path.exists(out):
        with open(out, "rb") as h:
            text = ANSI.sub("", h.read().decode("utf-8", "replace"))
        with open(out, "w", encoding="utf-8") as h:
            h.write(text)
    why = []
    if rc != 0:
        why.append("rc=%s" % rc)
    if not text.strip():
        why.append("пустой отчёт")
    if "[FATAL]" in text:
        why.append("[FATAL]")
    return why


def main():
    sys.stdout.reconfigure(encoding="utf-8")   # консоль CI на Windows — не UTF-8
    argv = sys.argv[1:]
    quick = "--quick" in argv
    argv = [a for a in argv if a != "--quick"]
    if len(argv) != 2:
        print("Запуск: python ci_smoke.py [--quick] каталог_дампов путь_к_программе")
        return 2
    dumps, exe = os.path.abspath(argv[0]), os.path.abspath(argv[1])
    rep = os.path.join(dumps, "reports")
    os.makedirs(rep, exist_ok=True)
    exts = (".pcap",) if quick else (".txt", ".pcap", ".pcapng")
    files = sorted(f for f in glob.glob(os.path.join(dumps, "*"))
                   if f.endswith(exts) and not f.endswith("README.txt"))
    if not files:
        print("Нет дампов в " + dumps)
        return 2
    runs, failed = 0, []
    for f in files:
        for mode in ((1, 2) if f.endswith(".pcap") and not quick else (2,)):
            name = "%s.m%d" % (os.path.basename(f), mode)
            t0 = time.time()
            why = run(exe, dumps, f, mode, os.path.join(rep, name + ".txt"))
            runs += 1
            print("%-36s %5.1f с  %s" % (name, time.time() - t0, ", ".join(why) or "ok"), flush=True)
            if why:
                failed.append(name)
    print("\nПрогонов: %d, с ошибкой: %d" % (runs, len(failed)))
    for name in failed:
        print("  " + name)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
