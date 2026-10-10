#!/usr/bin/env python3
# gen_fuzz_seeds.py — затравка (seed corpus) для фаззеров fuzz/fuzz_dump.cpp и
# fuzz/fuzz_hello.cpp.
#
# Берёт сценарии tools/gen_test_dumps.py, но оставляет от каждого лишь начало
# потоков (до 6 пакетов на поток, до 48 на дамп): фаззеру нужны все форматы и
# протоколы, а не мегабайты данных — большие входы только замедляют прогон.
#   dump/  — .pcap (Ethernet и прочие linktype: raw IP, SLL, SLL2, NULL,
#            VLAN+PPPoE; big-endian и наносекундный pcap), .pcapng, текст
#            tcpdump -n и -nv, один IPv6;
#   hello/ — ClientHello: голое handshake-сообщение и в записи TLS (Chrome,
#            Go/quic-go, вариант для QUIC), запись, разрезанная на две.
#
# Запуск: python gen_fuzz_seeds.py <каталог>   (создаст <каталог>/dump и /hello)
# Нужен модуль cryptography — как и gen_test_dumps.py.

import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_test_dumps as g  # noqa: E402

PER_FLOW, PER_DUMP = 6, 48


def trimmed(d):
    """Копия дампа: первые PER_FLOW пакетов каждого потока, всего ≤ PER_DUMP."""
    out, seen = g.Dump(d.name, d.title), {}
    for p in d.sorted():
        key = (p.proto,) + tuple(sorted([(p.src, p.sport), (p.dst, p.dport)]))
        if seen.get(key, 0) >= PER_FLOW:
            continue
        seen[key] = seen.get(key, 0) + 1
        out.add(p)
        if len(out.pkts) >= PER_DUMP:
            break
    return out


def write_pcap_lt(path, frames, linktype, be=False, nano=False):
    e = ">" if be else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    with open(path, "wb") as f:
        f.write(struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 262144, linktype))
        for sec, us, fr in frames:
            frac = us * 1000 if nano else us
            f.write(struct.pack(e + "IIII", sec, frac, len(fr), len(fr)) + fr)


def ip_frames(d):
    """(sec, мкс, IP-пакет, исходящий?) — без канального заголовка."""
    for p in d.sorted():
        ts = g.BASE_TS + p.t
        sec = int(ts)
        us = min(int(round((ts - sec) * 1e6)), 999999)
        yield sec, us, p.ip_bytes(), p.src == g.LOCAL


def linktype_variants(d, base):
    fr = list(ip_frames(d))
    # raw IP (101)
    write_pcap_lt(base + ".raw.pcap", [(s, u, ip) for s, u, ip, _ in fr], 101)
    # Linux cooked SLL (113): packet_type 4 — отправлен нами, 0 — нам
    sll = []
    for s, u, ip, out in fr:
        hdr = struct.pack("!HHH", 4 if out else 0, 1, 6) + g.MAC_LOCAL + b"\0\0" + struct.pack("!H", 0x0800)
        sll.append((s, u, hdr + ip))
    write_pcap_lt(base + ".sll.pcap", sll, 113)
    # SLL2 (276): протокол, резерв, ifindex, ARPHRD, packet_type, длина адреса, адрес
    sll2 = []
    for s, u, ip, out in fr:
        hdr = struct.pack("!HHIHBB", 0x0800, 0, 2, 1, 4 if out else 0, 6) + g.MAC_LOCAL + b"\0\0"
        sll2.append((s, u, hdr + ip))
    write_pcap_lt(base + ".sll2.pcap", sll2, 276)
    # NULL (0): семейство адресов в порядке байт писателя
    write_pcap_lt(base + ".null.pcap", [(s, u, struct.pack("<I", 2) + ip) for s, u, ip, _ in fr], 0)
    # Ethernet + VLAN 802.1Q + PPPoE-сессия; big-endian наносекундный pcap
    eth = []
    for s, u, ip, out in fr:
        macs = g.MAC_GW + g.MAC_LOCAL if out else g.MAC_LOCAL + g.MAC_GW
        pppoe = struct.pack("!BBHHH", 0x11, 0, 0x1234, len(ip) + 2, 0x0021)
        eth.append((s, u, macs + struct.pack("!HHH", 0x8100, 100, 0x8864) + pppoe + ip))
    write_pcap_lt(base + ".vlan-pppoe.be-nano.pcap", eth, 1, be=True, nano=True)


def ipv6_seed(path):
    """IPv6: TCP SYN и ClientHello к 2a00:1450::/32, DNS по UDP."""
    src = bytes.fromhex("2a0b4c8000000000000000000000abcd")
    dst = bytes.fromhex("2a001450400100000000000000000065")
    ch = g.tls_ch_record("www.google.com")

    def ip6(nh, l4):
        return struct.pack("!IHBB", 6 << 28, len(l4), nh, 64) + src + dst + l4

    syn = struct.pack("!HHIIBBHHH", 50000, 443, 1000, 0, 5 << 4, 0x02, 65535, 0, 0)
    data = struct.pack("!HHIIBBHHH", 50000, 443, 1001, 1, 5 << 4, 0x18, 512, 0, 0) + ch
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + g.dns_name("ya.ru") + b"\0\x1c\0\x01"
    dns = struct.pack("!HHHH", 53000, 53, 8 + len(q), 0) + q
    t0 = int(g.BASE_TS)
    frames = [(t0, 0, ip6(6, syn)), (t0, 50000, ip6(6, data)), (t0, 90000, ip6(17, dns))]
    write_pcap_lt(path, frames, 101)


def hello_seeds(out):
    variants = {
        "chrome": g.client_hello("www.youtube.com"),
        "go": g.client_hello("example.org", alpn=(b"h3",), go=True),
        "quic": g.client_hello("www.google.com", alpn=(b"h3",), quic=True),
    }
    for name, hs in variants.items():
        with open(os.path.join(out, name + ".hs"), "wb") as f:
            f.write(hs)
        with open(os.path.join(out, name + ".rec"), "wb") as f:
            f.write(b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs)
    # одно handshake-сообщение в двух записях TLS (разрез посередине)
    hs = variants["chrome"]
    a, b = hs[:len(hs) // 2], hs[len(hs) // 2:]
    with open(os.path.join(out, "chrome.split.rec"), "wb") as f:
        f.write(g.tls_record(0x16, a) + g.tls_record(0x16, b))


def main():
    if len(sys.argv) < 2:
        sys.exit("использование: gen_fuzz_seeds.py <каталог>")
    dump_dir = os.path.join(sys.argv[1], "dump")
    hello_dir = os.path.join(sys.argv[1], "hello")
    os.makedirs(dump_dir, exist_ok=True)
    os.makedirs(hello_dir, exist_ok=True)
    for i, sc in enumerate(g.SCENARIOS):
        d = trimmed(sc())
        base = os.path.join(dump_dir, d.name)
        d.write_pcap(base + ".pcap")
        d.write_pcapng(base + ".pcapng")
        d.write_txt(base + ".txt")
        d.write_txt(base + ".v.txt", verbose=True)
        if i == 0 or d.name.startswith("vless"):
            linktype_variants(d, base)
    ipv6_seed(os.path.join(dump_dir, "ipv6.raw.pcap"))
    hello_seeds(hello_dir)
    for sub in (dump_dir, hello_dir):
        files = os.listdir(sub)
        size = sum(os.path.getsize(os.path.join(sub, f)) for f in files)
        print("%s: %d файлов, %d КБ" % (sub, len(files), size // 1024))


if __name__ == "__main__":
    main()
