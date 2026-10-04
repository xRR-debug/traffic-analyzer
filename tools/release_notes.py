#!/usr/bin/env python3
# release_notes.py — номер и описание релиза для CI (.github/workflows/build.yml).
#
#   python release_notes.py version             — тег нового релиза: vГГГГ.ММ.ДД.N
#                                                  (дата по Москве, N — номер за день).
#                                                  Если на HEAD уже есть такой тег
#                                                  (перезапуск сборки) — он же.
#   python release_notes.py released            — самый ранний релиз, в который HEAD
#                                                  уже вошёл (пусто — ещё не вошёл).
#                                                  Перезапуск старой сборки main не
#                                                  должен выпускать старый код заново.
#   python release_notes.py notes --tag TAG --out FILE
#                                               — описание релиза на русском: темы
#                                                  коммитов, ещё не вошедших в релизы,
#                                                  файлы, установка.
#
# Описание собирается из тем коммитов (без merge-коммитов) — поэтому темы коммитов
# в репозитории пишутся по-русски.

import argparse
import datetime
import re
import subprocess
import sys

TAG_GLOB = "v[0-9][0-9][0-9][0-9].[0-9][0-9].[0-9][0-9].*"
TAG_RE = re.compile(r"^v\d{4}\.\d{2}\.\d{2}\.\d+$")
MSK = datetime.timezone(datetime.timedelta(hours=3))   # Москва, без перехода на летнее
MAX_ITEMS = 60


def git(*args, check=True):
    r = subprocess.run(["git"] + list(args), capture_output=True, text=True, encoding="utf-8")
    if check and r.returncode != 0:
        sys.exit("git %s: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout.strip() if r.returncode == 0 else ""


def tag_key(t):
    return tuple(int(x) for x in t[1:].split("."))


def release_tags(*args):
    return sorted((t for t in git("tag", "--list", TAG_GLOB, *args).splitlines() if TAG_RE.match(t)),
                  key=tag_key)


def head_tag():
    tags = release_tags("--points-at", "HEAD")
    return tags[-1] if tags else ""


def cmd_released():
    # без тега самого HEAD: перезапуск выпущенного коммита решает version (тот же тег)
    t = head_tag()
    tags = [x for x in release_tags("--contains", "HEAD") if x != t]
    return tags[0] if tags else ""


def cmd_version():
    t = head_tag()
    if t:
        return t
    day = datetime.datetime.now(MSK).strftime("%Y.%m.%d")
    nums = [tag_key(t)[3] for t in release_tags() if t.startswith("v%s." % day)]
    return "v%s.%d" % (day, max(nums, default=0) + 1)


def cmd_notes(tag, out):
    # Тег самого HEAD (перезапуск) не считаем: описание то же, что в первый раз.
    # Изменения — коммиты, не вошедшие ни в один другой релиз: так они не
    # повторяются при любой топологии merge (не только «первый родитель — main»).
    own = head_tag()
    others = [t for t in release_tags() if t != own]
    exclude = ["--exclude", own] if own else []
    prev = git("describe", "--tags", "--abbrev=0", "--match", TAG_GLOB, *exclude, "HEAD", check=False)
    log = git("log", "--no-merges", "--format=%h\t%s", "HEAD", *(["--not"] + others if others else [])).splitlines()
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
        "**Windows.** Распакуйте архив и запустите `TrafficAnalyzer.exe` — ничего "
        "дополнительно ставить не нужно. Программа не подписана, поэтому при первом запуске "
        "Windows может показать «Система Windows защитила ваш компьютер»: нажмите "
        "«Подробнее» → «Выполнить в любом случае».",
        "",
        "Установщик Npcap в релиз не входит — его лицензия не разрешает распространение. "
        "Для захвата трафика (режим 5) установите Npcap с [npcap.com](https://npcap.com/#download), "
        "программа сама предложит открыть страницу загрузки. Бесплатная лицензия Npcap "
        "ограничивает число установок — условия на npcap.com. Остальные режимы работают без Npcap.",
        "",
        "**macOS.** Распакуйте архив. Программа не подписана сертификатом Apple, поэтому "
        "перед первым запуском снимите карантин с самой программы. В Терминале перейдите "
        "в её папку: наберите `cd ` (с пробелом), перетащите папку TrafficAnalyzer из Finder "
        "в окно Терминала и нажмите Enter. Затем:",
        "",
        "```",
        "xattr -d com.apple.quarantine TrafficAnalyzer",
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
    sub.add_parser("released")
    n = sub.add_parser("notes")
    n.add_argument("--tag", required=True)
    n.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.cmd == "version":
        print(cmd_version())
    elif a.cmd == "released":
        print(cmd_released())
    else:
        cmd_notes(a.tag, a.out)


if __name__ == "__main__":
    main()
