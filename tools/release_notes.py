#!/usr/bin/env python3
# release_notes.py — номер и описание релиза для CI (.github/workflows/build.yml).
#
#   python release_notes.py version             — тег нового релиза: vГГГГ.ММ.ДД.N
#                                                  (дата по Москве, N — номер за день).
#                                                  Если на HEAD уже есть такой тег
#                                                  (перезапуск сборки) — он же.
#   python release_notes.py notes --tag TAG --out FILE
#                                               — описание релиза на русском: темы
#                                                  коммитов с прошлого релиза, файлы,
#                                                  установка.
#
# Описание собирается из тем коммитов (без merge-коммитов) — поэтому темы коммитов
# в репозитории пишутся по-русски.

import argparse
import datetime
import re
import subprocess
import sys

TAG_GLOB = "v[0-9]*"
TAG_RE = re.compile(r"^v\d{4}\.\d{2}\.\d{2}\.\d+$")
MSK = datetime.timezone(datetime.timedelta(hours=3))   # Москва, без перехода на летнее
MAX_ITEMS = 60


def git(*args, check=True):
    r = subprocess.run(["git"] + list(args), capture_output=True, text=True, encoding="utf-8")
    if check and r.returncode != 0:
        sys.exit("git %s: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout.strip() if r.returncode == 0 else ""


def head_tag():
    tags = [t for t in git("tag", "--points-at", "HEAD", "--list", TAG_GLOB).splitlines() if TAG_RE.match(t)]
    return sorted(tags)[-1] if tags else ""


def cmd_version():
    t = head_tag()
    if t:
        return t
    day = datetime.datetime.now(MSK).strftime("%Y.%m.%d")
    nums = [int(t.rsplit(".", 1)[1]) for t in git("tag", "--list", "v%s.*" % day).splitlines() if TAG_RE.match(t)]
    return "v%s.%d" % (day, max(nums, default=0) + 1)


def prev_tag():
    # с первого родителя: на HEAD тега ещё нет, а при перезапуске он уже есть —
    # тогда describe с HEAD вернул бы его самого и список изменений вышел бы пустым
    if not git("rev-parse", "-q", "--verify", "HEAD^", check=False):
        return ""
    return git("describe", "--tags", "--abbrev=0", "--match", TAG_GLOB, "HEAD^", check=False)


def cmd_notes(tag, out):
    prev = prev_tag()
    rng = "%s..HEAD" % prev if prev else "HEAD"
    log = git("log", "--no-merges", "--format=%h\t%s", rng).splitlines()
    sha = git("rev-parse", "--short", "HEAD")

    lines = ["Сборка из `main`, коммит `%s`." % sha, "", "## Что изменилось", ""]
    if not log:
        lines.append("- Изменений в коде нет — пересборка.")
    for item in log[:MAX_ITEMS]:
        h, _, subj = item.partition("\t")
        lines.append("- %s (`%s`)" % (subj, h))
    if len(log) > MAX_ITEMS:
        lines.append("- … и ещё %d — полный список в истории коммитов." % (len(log) - MAX_ITEMS))
    lines.append("")
    lines.append("С прошлого релиза `%s`." % prev if prev else "Первый релиз — все изменения с начала проекта.")
    lines += [
        "",
        "## Файлы",
        "",
        "| Файл | Для чего |",
        "|---|---|",
        "| `TrafficAnalyzer-%s-windows-x64.zip` | Windows 10/11, x64 |" % tag,
        "| `TrafficAnalyzer-%s-macos-universal.zip` | macOS 11 и новее, Apple Silicon и Intel |" % tag,
        "| `SHA256SUMS.txt` | контрольные суммы архивов |",
        "",
        "## Установка",
        "",
        "**Windows.** Распакуйте архив и запустите `TrafficAnalyzer.exe`. Установщик Npcap "
        "в релиз не входит — его лицензия не разрешает распространение. Для захвата трафика "
        "(режим 5) установите Npcap с [npcap.com](https://npcap.com/#download) — программа "
        "сама предложит открыть страницу загрузки. Остальные режимы работают без Npcap.",
        "",
        "**macOS.** Распакуйте архив. Программа не подписана сертификатом Apple, поэтому "
        "перед первым запуском снимите с неё карантин:",
        "",
        "```",
        "cd TrafficAnalyzer",
        "xattr -dr com.apple.quarantine .",
        "./TrafficAnalyzer",
        "```",
        "",
        "Захват трафика (режим 5) на macOS — через `sudo` или ChmodBPF (ставится вместе с Wireshark).",
        "",
    ]
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    n = sub.add_parser("notes")
    n.add_argument("--tag", required=True)
    n.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.cmd == "version":
        print(cmd_version())
    else:
        cmd_notes(a.tag, a.out)


if __name__ == "__main__":
    main()
