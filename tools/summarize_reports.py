#!/usr/bin/env python3
# summarize_reports.py — сводная таблица по отчётам run_test_dumps.py.
#
# Для каждого сценария и формата (.txt / .v.txt / .pcap / .pcapng) выписывает:
#   VPN   — итог режима 1 (score);
#   ВЫВОД — первая строка вывода режима 2 (или «явных проблем нет»);
#   ПРИЧ  — коды из «ПРИЧИНЫ БЛОКИРОВОК»;
#   UDP   — пометки из «ИТОГ ПО VPN/UDP-ТУННЕЛЯМ» и таблицы UDP.
# Строки, где форматы одного сценария расходятся, помечены «≠».
#
# Запуск: python summarize_reports.py [каталог_дампов]

import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DUMPS = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "testdumps")
FORMATS = (".txt", ".v.txt", ".pcap", ".pcapng")


def read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def vpn_verdict(m1):
    m = re.search(r"^Итог: (.*?)\s+\(score=(\d+)\)", m1, re.M)
    return "%s [%s]" % (m.group(1), m.group(2)) if m else "-"


def conclusion(m2):
    m = re.search(r"=+ ВЫВОД =+\n(.+)", m2)
    if m:
        return m.group(1).strip()
    if "Явных проблем соединения не обнаружено" in m2:
        return "явных проблем нет (TCP)"
    return "-"


def reasons(text):
    return ",".join(sorted(set(re.findall(r"^\s+\[([A-Z0-9_]+)\]", text, re.M)))) or "-"


def udp_notes(m2):
    out = []
    sec = re.search(r"=== ИТОГ ПО VPN/UDP-ТУННЕЛЯМ ===\n(.*?)(?:\n===|\Z)", m2, re.S)
    if sec:
        for line in sec.group(1).splitlines():
            line = line.strip()
            if line.startswith("•"):
                out.append(line[1:].strip()[:110])
    return " | ".join(out) or "-"


def main():
    rep = os.path.join(DUMPS, "reports")
    names = sorted({os.path.basename(f).split(".")[0]
                    for f in glob.glob(os.path.join(rep, "*.m1.txt"))})
    for n in names:
        print("=" * 100)
        print(n)
        rows = {}
        for ext in FORMATS:
            m1 = read(os.path.join(rep, n + ext + ".m1.txt"))
            m2 = read(os.path.join(rep, n + ext + ".m2.txt"))
            if not m1 and not m2:
                continue
            rows[ext] = {
                "VPN": vpn_verdict(m1),
                "ВЫВОД": conclusion(m2),
                "ПРИЧ": reasons(m2),
                "UDP": udp_notes(m2),
            }
        for key in ("VPN", "ВЫВОД", "ПРИЧ", "UDP"):
            vals = {ext: r[key] for ext, r in rows.items()}
            diff = len(set(vals.values())) > 1
            for ext, v in vals.items():
                print("  %s %-6s %-8s %s" % ("≠" if diff else " ", key, ext, v))


if __name__ == "__main__":
    main()
