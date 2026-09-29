#!/usr/bin/env python3
# run_test_dumps.py — прогон дампов из gen_test_dumps.py через TrafficAnalyzer --batch.
#
# Для каждого файла (.txt/.pcap/.pcapng) и режима (1 — VPN, 2 — соединения)
# пишет отчёт без ANSI-цветов в <каталог>/reports/<файл>.m<режим>.txt.
# Между запусками пауза: ip-api.com пускает 15 пакетных запросов в минуту.
#
# Запуск: python run_test_dumps.py [каталог_дампов] [путь_к_exe]

import glob
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DUMPS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "testdumps")
EXE = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "..", "x64", "Release", "TrafficAnalyzer.exe")
PAUSE = 4.5
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def main():
    rep = os.path.join(DUMPS, "reports")
    os.makedirs(rep, exist_ok=True)
    files = sorted(f for f in glob.glob(os.path.join(DUMPS, "*"))
                   if f.endswith((".txt", ".pcap", ".pcapng")) and not f.endswith("README.txt"))
    for f in files:
        for mode in (1, 2):
            out = os.path.join(rep, "%s.m%d.txt" % (os.path.basename(f), mode))
            t0 = time.time()
            rc = subprocess.run([EXE, "--batch", str(mode), "--out", out, f],
                                cwd=DUMPS, timeout=300).returncode
            with open(out, "rb") as h:
                text = ANSI.sub("", h.read().decode("utf-8", "replace"))
            with open(out, "w", encoding="utf-8") as h:
                h.write(text)
            print("%-34s m%d rc=%d %.1fs" % (os.path.basename(f), mode, rc, time.time() - t0), flush=True)
            time.sleep(PAUSE)


if __name__ == "__main__":
    main()
