#!/usr/bin/env python3
# gen_test_dumps.py — синтетические дампы для проверки TrafficAnalyzer.
#
# Каждый сценарий (рабочий / заблокированный VPN, YouTube, обычный сайт) пишется
# в трёх форматах: текст tcpdump (.txt, как «tcpdump -n» на BRAS), .pcap и
# .pcapng (Ethernet). Пакеты связные: TCP с рукопожатием, seq/ack, опциями и
# TLS ClientHello с SNI; QUIC Initial зашифрован по RFC 9001 (SNI читается,
# как у настоящего клиента); IKEv2/IKEv1/ESP, WireGuard, DNS — по форматам
# протоколов. Адреса — публичные адреса известных сетей (Hetzner, DigitalOcean,
# Google, Яндекс), абонент — адрес из сети MARYNONET.
#
# Запуск: python gen_test_dumps.py [каталог]   (по умолчанию ../../testdumps)
# Нужен только модуль cryptography (AES-GCM/ECB для QUIC Initial).

import hashlib
import hmac
import os
import random
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOCAL = "81.88.218.123"          # абонент
ISP_DNS = "81.88.208.202"        # DNS провайдера
BASE_TS = time.mktime((2026, 9, 29, 14, 0, 0, 0, 0, -1))

rnd = random.Random(39709)


def rbytes(n):
    return bytes(rnd.getrandbits(8) for _ in range(n)) if n < 4096 else os.urandom(n)


def ip2b(ip):
    return bytes(int(x) for x in ip.split("."))


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# ---------------------------------------------------------------------------
# пакет и дамп
# ---------------------------------------------------------------------------
class Pkt:
    __slots__ = ("t", "src", "sport", "dst", "dport", "proto", "ttl", "tcp", "payload", "text")

    def __init__(self, t, src, sport, dst, dport, proto, ttl, tcp, payload, text):
        self.t, self.src, self.sport, self.dst, self.dport = t, src, sport, dst, dport
        self.proto, self.ttl, self.tcp, self.payload, self.text = proto, ttl, tcp, payload, text

    def ip_bytes(self):
        if self.proto == "TCP":
            seq, ack, flags, win, opts = self.tcp
            doff = (20 + len(opts)) // 4
            l4 = struct.pack("!HHIIBBHHH", self.sport, self.dport, seq & 0xFFFFFFFF,
                             ack & 0xFFFFFFFF, doff << 4, flags, win, 0, 0) + opts + self.payload
            pnum = 6
        else:
            l4 = struct.pack("!HHHH", self.sport, self.dport, 8 + len(self.payload), 0) + self.payload
            pnum = 17
        pseudo = ip2b(self.src) + ip2b(self.dst) + struct.pack("!BBH", 0, pnum, len(l4))
        c = csum(pseudo + l4)
        off = 16 if pnum == 6 else 6
        l4 = l4[:off] + struct.pack("!H", c or 0xFFFF) + l4[off + 2:]
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), rnd.getrandbits(16),
                          0x4000 if pnum == 6 else 0, self.ttl, pnum, 0,
                          ip2b(self.src), ip2b(self.dst))
        hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
        return hdr + l4


MAC_LOCAL = bytes.fromhex("0011223344ee")
MAC_GW = bytes.fromhex("a0b1c2d3e4f5")


class Dump:
    def __init__(self, name, title):
        self.name, self.title, self.pkts = name, title, []

    def add(self, p):
        self.pkts.append(p)
        return p

    def udp(self, t, src, sport, dst, dport, payload, text, ttl=None):
        if ttl is None:
            ttl = 64 if src == LOCAL else 53
        return self.add(Pkt(t, src, sport, dst, dport, "UDP", ttl, None, payload, text))

    def sorted(self):
        return sorted(self.pkts, key=lambda p: p.t)

    # --- форматы ---
    def write_txt(self, path, verbose=False):
        # verbose — как «tcpdump -nv»: заголовок IP с TTL, пакет — строкой-продолжением
        with open(path, "w", encoding="ascii", newline="\n") as f:
            for n, p in enumerate(self.sorted()):
                ts = BASE_TS + p.t
                lt = time.localtime(ts)
                us = int(round((ts - int(ts)) * 1e6)) % 1000000
                stamp = "%02d:%02d:%02d.%06d" % (lt.tm_hour, lt.tm_min, lt.tm_sec, us)
                body = "%s.%d > %s.%d: %s" % (p.src, p.sport, p.dst, p.dport, p.text)
                if not verbose:
                    f.write("%s IP %s\n" % (stamp, body))
                    continue
                if p.proto == "TCP":
                    iplen, pr, df = 40 + len(p.tcp[4]) + len(p.payload), "TCP (6)", "[DF]"
                else:
                    iplen, pr, df = 28 + len(p.payload), "UDP (17)", "[none]"
                f.write("%s IP (tos 0x0, ttl %d, id %d, offset 0, flags %s, proto %s, length %d)\n    %s\n"
                        % (stamp, p.ttl, (n * 7919) & 0xFFFF, df, pr, iplen, body))

    def frames(self):
        for p in self.sorted():
            ip = p.ip_bytes()
            out = p.src == LOCAL
            eth = (MAC_GW + MAC_LOCAL if out else MAC_LOCAL + MAC_GW) + b"\x08\x00"
            ts = BASE_TS + p.t
            sec = int(ts)
            us = int(round((ts - sec) * 1e6))
            if us >= 1000000:
                sec, us = sec + 1, us - 1000000
            yield sec, us, eth + ip

    def write_pcap(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
            for sec, us, fr in self.frames():
                f.write(struct.pack("<IIII", sec, us, len(fr), len(fr)) + fr)

    def write_pcapng(self, path):
        def block(btype, body):
            body += b"\0" * ((4 - len(body) % 4) % 4)
            ln = 12 + len(body)
            return struct.pack("<II", btype, ln) + body + struct.pack("<I", ln)

        def opt(code, val):
            return struct.pack("<HH", code, len(val)) + val + b"\0" * ((4 - len(val) % 4) % 4)

        with open(path, "wb") as f:
            shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + opt(4, b"gen_test_dumps.py") + opt(0, b"")
            f.write(block(0x0A0D0D0A, shb))
            idb = struct.pack("<HHI", 1, 0, 262144) + opt(2, b"eth0") + opt(9, b"\x06") + opt(0, b"")
            f.write(block(1, idb))
            for sec, us, fr in self.frames():
                t = sec * 1000000 + us
                epb = struct.pack("<IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(fr), len(fr)) + fr
                f.write(block(6, epb))


# ---------------------------------------------------------------------------
# TCP-сессия: рукопожатие, данные сегментами, ACK, FIN/RST; текст как у tcpdump
# (SYN/SYN-ACK — абсолютные seq, дальше относительные)
# ---------------------------------------------------------------------------
F_FIN, F_SYN, F_RST, F_PSH, F_ACK = 1, 2, 4, 8, 16


def flag_str(fl):
    s = ""
    if fl & F_SYN: s += "S"
    if fl & F_FIN: s += "F"
    if fl & F_RST: s += "R"
    if fl & F_PSH: s += "P"
    if fl & F_ACK: s += "."
    return "[" + (s or "none") + "]"


class Tcp:
    def __init__(self, d, cport, sip, sport, rtt=0.045, sttl=53, mss=1460):
        self.d, self.cip, self.cport, self.sip, self.sport = d, LOCAL, cport, sip, sport
        self.rtt, self.sttl, self.mss = rtt, sttl, mss
        self.isn = {True: rnd.getrandbits(32), False: rnd.getrandbits(32)}   # True = клиент
        self.nxt = {True: 1, False: 1}       # следующий относительный seq
        self.ts0 = {True: rnd.getrandbits(30), False: rnd.getrandbits(30)}
        self.lastts = {True: 0, False: 0}
        self.win = {True: 502, False: 509}
        self.t = 0.0

    def _tsval(self, fromc, t):
        return self.ts0[fromc] + int(t * 1000)

    def emit(self, t, fromc, flags, seq_rel=None, payload=b"", ttl=None, win=None, notext_opts=False):
        src, sport, dst, dport = ((self.cip, self.cport, self.sip, self.sport) if fromc
                                  else (self.sip, self.sport, self.cip, self.cport))
        if ttl is None:
            ttl = 64 if fromc else self.sttl
        if seq_rel is None:
            seq_rel = self.nxt[fromc]
        ack_rel = self.nxt[not fromc]
        tsv, tse = self._tsval(fromc, t), self.lastts[not fromc]
        self.lastts[fromc] = tsv
        w = self.win[fromc] if win is None else win
        if flags & F_RST:
            opts = b""
            w = 0 if win is None else win
        else:
            opts = b"\x01\x01\x08\x0a" + struct.pack("!II", tsv, tse)
        seq_abs = self.isn[fromc] + seq_rel
        ack_abs = self.isn[not fromc] + ack_rel if flags & F_ACK else 0
        n = len(payload)
        parts = ["Flags " + flag_str(flags)]
        if n:
            parts.append("seq %d:%d" % (seq_rel, seq_rel + n))
        elif flags & (F_FIN | F_RST):
            parts.append("seq %d" % seq_rel)
        if flags & F_ACK:
            parts.append("ack %d" % ack_rel)
        parts.append("win %d" % w)
        if opts:
            parts.append("options [nop,nop,TS val %d ecr %d]" % (tsv, tse))
        parts.append("length %d" % n)
        text = ", ".join(parts)
        if n and (self.sport == 80) and fromc and payload[:4] in (b"GET ", b"POST", b"HEAD"):
            text += ": HTTP: " + payload.split(b"\r\n")[0].decode()
        elif n and self.sport == 80 and not fromc and payload[:5] == b"HTTP/":
            text += ": HTTP: " + payload.split(b"\r\n")[0].decode()
        return self.d.add(Pkt(t, src, sport, dst, dport, "TCP", ttl,
                              (seq_abs, ack_abs, flags, w, opts), payload, text))

    def _syn(self, t, fromc, synack=False):
        tsv = self._tsval(fromc, t)
        tse = self.lastts[not fromc] if synack else 0
        self.lastts[fromc] = tsv
        opts = (struct.pack("!BBH", 2, 4, self.mss) + b"\x04\x02\x08\x0a" +
                struct.pack("!II", tsv, tse) + b"\x01\x03\x03\x07")
        src, sport, dst, dport = ((self.cip, self.cport, self.sip, self.sport) if fromc
                                  else (self.sip, self.sport, self.cip, self.cport))
        w = 64240 if fromc else 65160
        flags = F_SYN | (F_ACK if synack else 0)
        seq = self.isn[fromc]
        ack = self.isn[not fromc] + 1 if synack else 0
        text = "Flags %s, seq %d, %swin %d, options [mss %d,sackOK,TS val %d ecr %d,nop,wscale 7], length 0" % (
            flag_str(flags), seq, ("ack %d, " % ack) if synack else "", w, self.mss, tsv, tse)
        return self.d.add(Pkt(t, src, sport, dst, dport, "TCP", 64 if fromc else self.sttl,
                              (seq, ack, flags, w, opts), b"", text))

    def syn(self, t):
        return self._syn(t, True)

    def handshake(self, t):
        self._syn(t, True)
        self._syn(t + self.rtt, False, synack=True)
        self.emit(t + self.rtt + 0.0002, True, F_ACK)
        return t + self.rtt + 0.0002

    def ack(self, t, fromc):
        return self.emit(t, fromc, F_ACK)

    def send(self, t, fromc, data, rate=None, seg=1448, auto_ack=True):
        """Данные сегментами. rate — байт/с (пауза между сегментами), по умолчанию
        ~25 Мбит/с. Получатель подтверждает каждый второй сегмент: сторона абонента
        сразу (дамп снят рядом с ним), сервер — через rtt."""
        gap = seg / (rate or 3_000_000)
        i, k = 0, 0
        while i < len(data):
            chunk = data[i:i + seg]
            last = i + seg >= len(data)
            self.emit(t, fromc, F_ACK | (F_PSH if last else 0), payload=chunk)
            self.nxt[fromc] += len(chunk)
            i += seg
            k += 1
            if auto_ack and (k % 2 == 0 or last):
                self.emit(t + (0.0003 if not fromc else self.rtt), not fromc, F_ACK)
            t += gap
        return t

    def request_response(self, t, req, resp, rate=None, think=0.0):
        """Запрос клиента и ответ сервера через rtt. Возвращает время конца."""
        self.send(t, True, req, auto_ack=False)
        return self.send(t + self.rtt + think, False, resp, rate=rate)

    def close(self, t, fromc=True):
        self.emit(t, fromc, F_FIN | F_ACK)
        self.nxt[fromc] += 1
        other = not fromc
        t2 = t + (self.rtt if fromc else 0.0005)
        self.emit(t2, other, F_FIN | F_ACK)
        self.nxt[other] += 1
        self.emit(t2 + (0.0003 if fromc else self.rtt), fromc, F_ACK)
        return t2

    def rst(self, t, fromc, ttl=None, with_ack=True, seq_rel=None):
        return self.emit(t, fromc, F_RST | (F_ACK if with_ack else 0), seq_rel=seq_rel, ttl=ttl)


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------
def ext(t, body):
    return struct.pack("!HH", t, len(body)) + body


def client_hello(sni, alpn=(b"h2", b"http/1.1"), quic=False, go=False):
    """Handshake-сообщение ClientHello (без заголовка записи). По умолчанию —
    Chrome (с GREASE); go=True — Go crypto/tls, как у quic-go (Hysteria2):
    без GREASE, с Ed25519 в signature_algorithms."""
    grease = not go
    if quic:
        ciphers = [0x1301, 0x1302, 0x1303]
    else:
        ciphers = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
                   0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
    if grease:
        ciphers = [0x3A3A] + ciphers
    sn = sni.encode()
    e = ext(0x5A5A, b"") if grease else b""
    e += ext(0x0000, struct.pack("!HBH", len(sn) + 3, 0, len(sn)) + sn)
    if not quic:
        e += ext(0x0017, b"") + ext(0xFF01, b"\x00")
    groups = [0x001D, 0x0017, 0x0018, 0x0019] if go else [0x8A8A, 0x001D, 0x0017, 0x0018]
    e += ext(0x000A, struct.pack("!H", len(groups) * 2) + b"".join(struct.pack("!H", g) for g in groups))
    if not quic:
        e += ext(0x000B, b"\x01\x00") + ext(0x0023, b"")
    al = b"".join(bytes([len(a)]) + a for a in alpn)
    e += ext(0x0010, struct.pack("!H", len(al)) + al)
    if not quic:
        e += ext(0x0005, b"\x01\x00\x00\x00\x00")
    sig = ([0x0804, 0x0403, 0x0807, 0x0805, 0x0503, 0x0806, 0x0603, 0x0401, 0x0501, 0x0601] if go
           else [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601])
    e += ext(0x000D, struct.pack("!H", len(sig) * 2) + b"".join(struct.pack("!H", s) for s in sig))
    if not quic:
        e += ext(0x0012, b"")
    e += ext(0x0033, struct.pack("!HHH", 36, 0x001D, 32) + rbytes(32))
    e += ext(0x002D, b"\x01\x01")
    e += ext(0x002B, b"\x02\x03\x04" if quic else b"\x04\x03\x04\x03\x03")
    if quic:
        tp = bytes.fromhex("0104800075300304800100000404809896800504800f42400604800f4240"
                           "0704800f42400802406409024064") + b"\x0f\x08" + rbytes(8)
        e += ext(0x0039, tp)
    else:
        e += ext(0x001B, b"\x02\x00\x02")
    if grease:
        e += ext(0x1A1A, b"\x00")
    body =(b"\x03\x03" + rbytes(32) + (b"\x00" if quic else b"\x20" + rbytes(32)) +
            struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers) +
            b"\x01\x00")
    if not quic:
        pad = 512 - (len(body) + 2 + len(e) + 4) - 4
        if pad > 0:
            e += ext(0x0015, b"\0" * pad)
    body += struct.pack("!H", len(e)) + e
    return b"\x01" + struct.pack("!I", len(body))[1:] + body


def tls_record(ctype, body):
    return bytes([ctype]) + b"\x03\x03" + struct.pack("!H", len(body)) + body


def tls_ch_record(sni, **kw):
    hs = client_hello(sni, **kw)
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tls_app(n):
    """n байт данных приложения записями TLS 1.3 (0x17)."""
    out = bytearray()
    while len(out) < n:
        k = min(16384 + 17, n - len(out) - 5)
        if k <= 0:
            out += b"\0" * (n - len(out))
            break
        out += tls_record(0x17, os.urandom(k))
    return bytes(out[:n])


def tls_server_flight(extra=3800):
    sh = b"\x02" + struct.pack("!I", 118)[1:] + b"\x03\x03" + rbytes(32) + b"\x20" + rbytes(32) + \
        b"\x13\x01\x00" + struct.pack("!H", 46) + ext(0x002B, b"\x03\x04") + \
        ext(0x0033, struct.pack("!HH", 0x001D, 32) + rbytes(32))
    return tls_record(0x16, sh) + tls_record(0x14, b"\x01") + tls_app(extra)


# ---------------------------------------------------------------------------
# QUIC Initial (RFC 9001 §5) — как у клиента, SNI расшифровывается
# ---------------------------------------------------------------------------
QUIC_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def hkdf_label(secret, label, n):
    full = b"tls13 " + label
    return hkdf_expand(secret, struct.pack("!H", n) + bytes([len(full)]) + full + b"\x00", n)


def varint(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return struct.pack("!H", 0x4000 | v)
    return struct.pack("!I", 0x80000000 | v)


def quic_client_initial(dcid, scid, pn, crypto, pad_to=1250):
    init = hmac.new(QUIC_SALT_V1, dcid, hashlib.sha256).digest()
    cs = hkdf_label(init, b"client in", 32)
    key, iv, hp = hkdf_label(cs, b"quic key", 16), hkdf_label(cs, b"quic iv", 12), hkdf_label(cs, b"quic hp", 16)
    frame = b"\x06" + varint(0) + varint(len(crypto)) + crypto
    pre = b"\xc1" + b"\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00"
    total = len(pre) + 2 + 2 + len(frame) + 16
    if total < pad_to:
        frame += b"\x00" * (pad_to - total)
    hdr = pre + struct.pack("!H", 0x4000 | (2 + len(frame) + 16)) + struct.pack("!H", pn)
    nonce = bytes(a ^ b for a, b in zip(iv, b"\0" * 4 + struct.pack("!Q", pn)))
    ct = AESGCM(key).encrypt(nonce, frame, hdr)
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(ct[2:18]) + enc.finalize()
    pn_off = len(hdr) - 2
    first = bytes([hdr[0] ^ (mask[0] & 0x0F)])
    pnb = bytes(hdr[pn_off + i] ^ mask[1 + i] for i in range(2))
    return first + hdr[1:pn_off] + pnb + ct


def quic_server_long(dcid, scid, n, ptype=0):
    hdr = bytes([0xC1 | (ptype << 4)]) + b"\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid + \
        bytes([len(scid)]) + scid + (b"\x00" if ptype == 0 else b"")
    body = rbytes(n - len(hdr) - 2)
    return hdr + struct.pack("!H", 0x4000 | len(body)) + body


def quic_short(dcid, n):
    return bytes([0x40 | rnd.getrandbits(5)]) + dcid + os.urandom(max(1, n - 1 - len(dcid)))


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
def dns_name(n):
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\0"


def dns_exchange(d, t, name, answers, rcode=0, qtype=1, sport=None, rtt=0.004):
    """answers: [("CNAME", имя) | ("A", ip)]."""
    qid = rnd.getrandbits(16)
    sport = sport or rnd.randint(30000, 60000)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)
    d.udp(t, LOCAL, sport, ISP_DNS, 53, q, "%d+ %s? %s. (%d)" % (qid, "A" if qtype == 1 else "AAAA", name, len(q)))
    rr = b""
    owner = name
    for typ, val in answers:
        if typ == "CNAME":
            rd = dns_name(val)
            rr += dns_name(owner) + struct.pack("!HHIH", 5, 1, 300, len(rd)) + rd
            owner = val
        else:
            rr += dns_name(owner) + struct.pack("!HHIH", 1, 1, 300, 4) + ip2b(val)
    r = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0) + \
        dns_name(name) + struct.pack("!HH", qtype, 1) + rr
    if rcode == 3:
        txt = "%d NXDomain 0/0/0 (%d)" % (qid, len(r))
    else:
        txt = "%d %d/0/0 %s (%d)" % (qid, len(answers), ", ".join(
            "%s %s%s" % (a, v, "." if a == "CNAME" else "") for a, v in answers), len(r))
    d.udp(t + rtt, ISP_DNS, 53, LOCAL, sport, r, txt, ttl=63)
    return t + rtt


# ---------------------------------------------------------------------------
# IPsec: IKEv2 / IKEv1 / ESP (UDP 500 и 4500 с NAT-T)
# ---------------------------------------------------------------------------
def ike_msg(spi_i, spi_r, np, ver, exch, flags, msgid, body_len):
    body = bytes([0, 0]) + struct.pack("!H", 4 + body_len) + rbytes(body_len)
    return spi_i + spi_r + bytes([np, ver, exch, flags]) + struct.pack("!II", msgid, 28 + len(body)) + body


class Ipsec:
    def __init__(self, d, peer, lport=500, rttl=53, rtt=0.05):
        self.d, self.peer, self.rttl, self.rtt = d, peer, rttl, rtt
        self.spi_i, self.spi_r = rbytes(8), b"\0" * 8
        self.spi_out, self.spi_in = rnd.getrandbits(32), rnd.getrandbits(32)
        self.seq_out = self.seq_in = 0
        self.lport = lport

    def _send(self, t, out, port, payload, text):
        if out:
            self.d.udp(t, LOCAL, port if port == 500 else 4500, self.peer, port, payload, text)
        else:
            self.d.udp(t, self.peer, port, LOCAL, port if port == 500 else 4500, payload, text, ttl=self.rttl)

    def ikev2_init(self, t, answer=True):
        m = ike_msg(self.spi_i, b"\0" * 8, 33, 0x20, 34, 0x08, 0, 420)
        self._send(t, True, 500, m, "isakmp: parent_sa ikev2_init[I]")
        if answer:
            self.spi_r = rbytes(8)
            r = ike_msg(self.spi_i, self.spi_r, 33, 0x20, 34, 0x20, 0, 400)
            self._send(t + self.rtt, False, 500, r, "isakmp: parent_sa ikev2_init[R]")
        return t + self.rtt

    def ikev2_auth(self, t, msgid=1, size_i=520, size_r=1100):
        m = b"\0\0\0\0" + ike_msg(self.spi_i, self.spi_r, 46, 0x20, 35, 0x08, msgid, size_i)
        self._send(t, True, 4500, m, "NONESP-encap: isakmp: child_sa  ikev2_auth[I]")
        r = b"\0\0\0\0" + ike_msg(self.spi_i, self.spi_r, 46, 0x20, 35, 0x20, msgid, size_r)
        self._send(t + self.rtt, False, 4500, r, "NONESP-encap: isakmp: child_sa  ikev2_auth[R]")
        return t + self.rtt

    def ikev1_main(self, t):
        """Main Mode: 1–4 открыто на 500, 5–6 шифрованы уже на 4500 (NAT-T), затем Quick Mode."""
        rt = self.rtt
        m1 = ike_msg(self.spi_i, b"\0" * 8, 1, 0x10, 2, 0x00, 0, 300)
        self._send(t, True, 500, m1, "isakmp: phase 1 I ident")
        self.spi_r = rbytes(8)
        self._send(t + rt, False, 500, ike_msg(self.spi_i, self.spi_r, 1, 0x10, 2, 0x00, 0, 140),
                   "isakmp: phase 1 R ident")
        t += rt + 0.01
        self._send(t, True, 500, ike_msg(self.spi_i, self.spi_r, 4, 0x10, 2, 0x00, 0, 300),
                   "isakmp: phase 1 I ident")
        self._send(t + rt, False, 500, ike_msg(self.spi_i, self.spi_r, 4, 0x10, 2, 0x00, 0, 300),
                   "isakmp: phase 1 R ident")
        t += rt + 0.01
        self._send(t, True, 4500, b"\0\0\0\0" + ike_msg(self.spi_i, self.spi_r, 5, 0x10, 2, 0x01, 0, 92),
                   "NONESP-encap: isakmp: phase 1 I ident[E]")
        self._send(t + rt, False, 4500, b"\0\0\0\0" + ike_msg(self.spi_i, self.spi_r, 5, 0x10, 2, 0x01, 0, 92),
                   "NONESP-encap: isakmp: phase 1 R ident[E]")
        t += rt + 0.01
        mid = rnd.getrandbits(32)
        for i, (out, sz) in enumerate(((True, 420), (False, 400), (True, 60))):
            self._send(t, out, 4500,
                       b"\0\0\0\0" + ike_msg(self.spi_i, self.spi_r, 8, 0x10, 32, 0x01, mid, sz),
                       "NONESP-encap: isakmp: phase 2/others %s oakley-quick[E]" % ("I" if out else "R"))
            t += rt if i == 0 else 0.01
        return t

    def esp(self, t, out, size):
        if out:
            self.seq_out += 1
            spi, seq = self.spi_out, self.seq_out
        else:
            self.seq_in += 1
            spi, seq = self.spi_in, self.seq_in
        p = struct.pack("!II", spi, seq) + os.urandom(size - 8)
        self._send(t, out, 4500, p, "UDP-encap: ESP(spi=0x%08x,seq=0x%x), length %d" % (spi, seq, size))

    def keepalive(self, t):
        self._send(t, True, 4500, b"\xff", "isakmp-nat-keep-alive")

    def traffic(self, t0, dur, pps_out=15, pps_in=30, big_in=True):
        t = t0
        evs = []
        n_out, n_in = int(dur * pps_out), int(dur * pps_in)
        for _ in range(n_out):
            evs.append((t0 + rnd.random() * dur, True, rnd.choice((100, 132, 164, 180, 212))))
        for _ in range(n_in):
            evs.append((t0 + rnd.random() * dur, False,
                        rnd.choice((1400, 1400, 1384, 564, 132)) if big_in else rnd.choice((100, 132, 164))))
        for tt, out, sz in sorted(evs):
            self.esp(tt, out, sz)
        k = t0 + 20
        while k < t0 + dur:
            self.keepalive(k)
            k += 20
        return t0 + dur


# ---------------------------------------------------------------------------
# фоновый трафик: DNS и обычный HTTPS к Яндексу — есть в каждом дампе
# ---------------------------------------------------------------------------
YA = "77.88.55.242"


def bg_https(d, t, name="ya.ru", ip=YA, size=6200, sttl=58, rtt=0.008):
    dns_exchange(d, t, name, [("A", ip)])
    c = Tcp(d, rnd.randint(40000, 65000), ip, 443, rtt=rtt, sttl=sttl)
    t = c.handshake(t + 0.01)
    t = c.request_response(t + 0.001, tls_ch_record(name), tls_server_flight(size), rate=6_000_000)
    t = c.request_response(t + 0.05, tls_app(620), tls_app(size * 3), rate=6_000_000)
    return c.close(t + 0.3)


def background(d, t_end):
    bg_https(d, 0.4)
    t = 8.0
    while t < t_end - 2:
        bg_https(d, t, size=rnd.randint(3000, 9000))
        t += rnd.uniform(9, 14)
    bg_https(d, t_end - 0.8, size=2500)


# ---------------------------------------------------------------------------
# сценарии
# ---------------------------------------------------------------------------
IP_IPSEC = "46.101.55.10"        # DigitalOcean (Франкфурт) — IPsec-VPN сервер
IP_CORP = "217.107.219.10"       # офис, не хостинг — корпоративный IPsec (IKEv1)
IP_EPDG = "213.87.130.10"        # ePDG оператора (VoWiFi)
IP_HY = "5.75.200.40"            # Hetzner — Hysteria2
IP_VLESS = "95.216.47.12"        # Hetzner — VLESS+Reality
IP_WG = "164.92.180.33"          # DigitalOcean — WireGuard
IP_YT = "142.250.74.46"          # www.youtube.com
IP_GV = "173.194.182.8"          # rr3---sn-4g5lznek.googlevideo.com
IP_YTIMG = "142.250.74.54"       # i.ytimg.com
IP_WIKI = "185.15.59.224"        # ru.wikipedia.org
IP_MIRROR = "213.180.204.183"    # mirror.yandex.ru (HTTP)
IP_DOWN = "91.215.42.100"        # сайт, сервер которого лежит (не блокировка)
GV_NAME = "rr3---sn-4g5lznek.googlevideo.com"


def sc_ipsec_ok():
    d = Dump("01_ipsec_ok", "IPsec IKEv2 (strongSwan) к VPS — работает")
    background(d, 45)
    dns_exchange(d, 1.5, "vpn.fastline-vpn.net", [("A", IP_IPSEC)])
    s = Ipsec(d, IP_IPSEC, rtt=0.052)
    t = s.ikev2_init(1.6)
    t = s.ikev2_auth(t + 0.01)
    s.traffic(t + 0.05, 40)
    return d


def sc_ipsec_blocked():
    d = Dump("02_ipsec_blocked", "IPsec IKEv2 к VPS — ТСПУ режет, ответа на IKE_SA_INIT нет")
    background(d, 45)
    dns_exchange(d, 1.5, "vpn.fastline-vpn.net", [("A", IP_IPSEC)])
    s = Ipsec(d, IP_IPSEC)
    t = 1.6
    for k in range(3):           # три попытки подключения, у каждой повторы 4/7.2/13 с
        s = Ipsec(d, IP_IPSEC)
        for dt in (0, 4.0, 11.2, 24.2):
            if t + dt < 44:
                s.ikev2_init(t + dt, answer=False)
        t += 14
    return d


def sc_ipsec_blocked_esp():
    d = Dump("03_ipsec_esp_blocked", "IPsec IKEv2 к VPS — IKE проходит, ESP в ответ не приходит")
    background(d, 45)
    dns_exchange(d, 1.5, "vpn.fastline-vpn.net", [("A", IP_IPSEC)])
    s = Ipsec(d, IP_IPSEC, rtt=0.052)
    t = s.ikev2_init(1.6)
    t = s.ikev2_auth(t + 0.01)
    t0 = t + 0.05
    for i in range(int(40 * 6)):
        s.esp(t0 + i / 6 + rnd.random() * 0.1, True, rnd.choice((100, 132, 164)))
    return d


def sc_ipsec_corp():
    d = Dump("04_ipsec_corp_ikev1", "Корпоративный IPsec (IKEv1 Main Mode + NAT-T) к офису — работает")
    background(d, 45)
    s = Ipsec(d, IP_CORP, rtt=0.018, rttl=56)
    t = s.ikev1_main(1.2)
    s.traffic(t + 0.05, 40, pps_out=10, pps_in=14)
    return d


def sc_vowifi():
    d = Dump("05_vowifi", "VoWiFi (звонки по Wi-Fi): ePDG оператора, IKEv2 + ESP")
    background(d, 45)
    dns_exchange(d, 1.0, "epdg.epc.mnc001.mcc250.pub.3gppnetwork.org", [("A", IP_EPDG)])
    s = Ipsec(d, IP_EPDG, rtt=0.012, rttl=58)
    t = s.ikev2_init(1.1)
    for m in range(1, 5):        # EAP-AKA: четыре обмена IKE_AUTH
        t = s.ikev2_auth(t + 0.02, msgid=m, size_i=300 + 40 * m, size_r=260 + 80 * m)
    s.traffic(t + 0.05, 40, pps_out=2, pps_in=2, big_in=False)
    return d


def hy_client(d, t, sni, answer, dur=30.0, rtt=0.047):
    cport = rnd.randint(40000, 60000)
    dcid, scid = rbytes(8), rbytes(4)
    ch = client_hello(sni, alpn=(b"h3",), quic=True, go=True)
    if not answer:
        # quic-go: повторы Initial с растущим PTO, затем новая попытка (новый DCID)
        for attempt in range(3):
            dcid = rbytes(8)
            for i, dt in enumerate((0, 0.3, 0.9, 2.1, 4.5)):
                d.udp(t + dt, LOCAL, cport, IP_HY, 443, quic_client_initial(dcid, scid, i, ch), "UDP, length %d" % 1250)
            t += 10
        return t
    d.udp(t, LOCAL, cport, IP_HY, 443, quic_client_initial(dcid, scid, 0, ch), "UDP, length 1250")
    sdcid = rbytes(8)
    for i, n in enumerate((1200, 1200, 890)):
        p = quic_server_long(scid, sdcid, n, ptype=0 if i == 0 else 2)
        d.udp(t + rtt + i * 0.0004, IP_HY, 443, LOCAL, cport, p, "UDP, length %d" % len(p), ttl=52)
    t += rtt + 0.002
    p = quic_server_long(sdcid, scid, 90, ptype=2)
    d.udp(t, LOCAL, cport, IP_HY, 443, p, "UDP, length %d" % len(p))
    t += 0.01
    end = t + dur
    while t < end:           # туннель: вниз крупные пакеты, вверх мелкие
        burst = rnd.randint(5, 40)
        for _ in range(burst):
            n = rnd.choice((1252, 1252, 1252, 800))
            d.udp(t, IP_HY, 443, LOCAL, cport, quic_short(scid, n), "UDP, length %d" % n, ttl=52)
            t += 0.0006
        for _ in range(max(1, burst // 4)):
            n = rnd.choice((60, 72, 180, 420))
            d.udp(t, LOCAL, cport, IP_HY, 443, quic_short(sdcid, n), "UDP, length %d" % n)
            t += 0.0004
        t += rnd.uniform(0.05, 0.4)
    return t


def sc_hysteria_ok():
    d = Dump("06_hysteria_ok", "Hysteria2 (QUIC, UDP/443) к VPS Hetzner — работает")
    background(d, 45)
    hy_client(d, 2.0, "www.bing.com", True, dur=38)
    return d


def sc_hysteria_blocked():
    d = Dump("07_hysteria_blocked", "Hysteria2 (QUIC) к VPS Hetzner — ответа на Initial нет")
    background(d, 45)
    hy_client(d, 2.0, "www.bing.com", False)
    return d


def reality_ok(d, t, dur=35.0):
    c = Tcp(d, rnd.randint(40000, 65000), IP_VLESS, 443, rtt=0.043, sttl=52)
    t = c.handshake(t)
    t = c.request_response(t + 0.001, tls_ch_record("www.microsoft.com"), tls_server_flight(4200))
    c.send(t + 0.002, True, tls_app(64) + tls_app(900), auto_ack=False)
    t += c.rtt
    end = t + dur
    while t < end:
        t = c.request_response(t, tls_app(rnd.randint(200, 1400)), tls_app(rnd.randint(20000, 400000)),
                               rate=rnd.choice((1_500_000, 3_000_000)))
        t += rnd.uniform(0.1, 1.5)
    return c.close(t)


def sc_vless_ok():
    d = Dump("08_vless_reality_ok", "VLESS+Reality (TCP/443, SNI www.microsoft.com) к Hetzner — работает")
    background(d, 45)
    reality_ok(d, 2.0)
    return d


def freeze_conn(d, t, sip, sni, frozen_at=16800, sttl=52, rtt=0.043):
    """TLS-соединение, в котором после ~16 КБ ответа сервера входящие пакеты
    пропадают: клиент повторяет запрос, потом FIN — ответа нет."""
    c = Tcp(d, rnd.randint(40000, 65000), sip, 443, rtt=rtt, sttl=sttl)
    t = c.handshake(t)
    c.send(t + 0.001, True, tls_ch_record(sni), auto_ack=False)
    t += 0.001 + rtt
    flight = tls_server_flight(4200) + tls_app(frozen_at)
    flight = flight[:frozen_at]
    t = c.send(t, False, flight, rate=2_000_000)
    req = tls_app(820)
    t += 0.01
    c.send(t, True, req, auto_ack=False)
    seq_req = c.nxt[True] - len(req)
    rto = 0.25
    for _ in range(6):           # повторы запроса — сервер их не подтверждает (ACK тоже режутся)
        t += rto
        c.emit(t, True, F_ACK | F_PSH, seq_rel=seq_req, payload=req)
        rto *= 2
    return t


def sc_vless_blocked():
    d = Dump("09_vless_reality_16kb", "VLESS+Reality к Hetzner — «заморозка» после ~16 КБ (ТСПУ)")
    background(d, 50)
    t = 2.0
    for i in range(4):
        freeze_conn(d, t, IP_VLESS, "www.microsoft.com", frozen_at=rnd.randint(15500, 18500))
        t += 6.5
    return d


def sc_vless_rst():
    d = Dump("10_vless_reality_sni_rst", "VLESS+Reality к Hetzner — RST от ТСПУ сразу после ClientHello")
    background(d, 45)
    t = 2.0
    for i in range(5):
        c = Tcp(d, rnd.randint(40000, 65000), IP_VLESS, 443, rtt=0.043, sttl=52)
        t1 = c.handshake(t)
        c.send(t1 + 0.001, True, tls_ch_record("www.microsoft.com"), auto_ack=False)
        # инъекция: RST на 2 мс после ClientHello, TTL ближе к абоненту, пачкой
        c.rst(t1 + 0.003, False, ttl=61)
        c.rst(t1 + 0.0032, False, ttl=61, seq_rel=c.nxt[False] + 1448)
        t += 5
    return d


def wg(d, t, answer, dur=38.0):
    cport = rnd.randint(40000, 60000)
    sidx = rbytes(4)
    if not answer:
        end = t + dur
        while t < end:          # wireguard-go: повтор рукопожатия каждые 5 с (+джиттер)
            d.udp(t, LOCAL, cport, IP_WG, 51820, b"\x01\0\0\0" + sidx + rbytes(140), "UDP, length 148")
            t += 5 + rnd.random() * 0.33
        return t
    d.udp(t, LOCAL, cport, IP_WG, 51820, b"\x01\0\0\0" + sidx + rbytes(140), "UDP, length 148")
    ridx = rbytes(4)
    d.udp(t + 0.05, IP_WG, 51820, LOCAL, cport, b"\x02\0\0\0" + ridx + sidx + rbytes(80), "UDP, length 92", ttl=51)
    t += 0.051
    ctr = {True: 0, False: 0}
    end = t + dur

    def data(tt, out, n):
        ctr[out] += 1
        p = b"\x04\0\0\0" + (ridx if out else sidx) + struct.pack("<Q", ctr[out]) + os.urandom(n - 16)
        if out:
            d.udp(tt, LOCAL, cport, IP_WG, 51820, p, "UDP, length %d" % n)
        else:
            d.udp(tt, IP_WG, 51820, LOCAL, cport, p, "UDP, length %d" % n, ttl=51)
    while t < end:
        for _ in range(rnd.randint(4, 30)):
            data(t, False, rnd.choice((1452, 1452, 1452, 620)))
            t += 0.0007
        data(t, True, rnd.choice((96, 112, 144, 400)))
        t += rnd.uniform(0.05, 0.5)
    return t


def sc_wg_ok():
    d = Dump("11_wireguard_ok", "WireGuard к VPS DigitalOcean — работает")
    background(d, 45)
    wg(d, 2.0, True)
    return d


def sc_wg_blocked():
    d = Dump("12_wireguard_blocked", "WireGuard к VPS DigitalOcean — рукопожатие без ответа (ТСПУ)")
    # 70 с: повтор раз в 5 с — 14 попыток; детектору нужно ≥10 за ≥10 с
    background(d, 75)
    wg(d, 2.0, False, dur=70.0)
    return d


def yt_dns(d, t):
    dns_exchange(d, t, "www.youtube.com", [("CNAME", "youtube-ui.l.google.com"), ("A", IP_YT)])
    dns_exchange(d, t + 0.3, "i.ytimg.com", [("A", IP_YTIMG)])
    dns_exchange(d, t + 0.9, GV_NAME, [("CNAME", "rr3.sn-4g5lznek.googlevideo.com"), ("A", IP_GV)])


def sc_youtube_ok():
    d = Dump("13_youtube_ok", "YouTube: страница, картинки и видео (TCP и QUIC) — работает")
    background(d, 45)
    yt_dns(d, 1.0)
    c = Tcp(d, rnd.randint(40000, 65000), IP_YT, 443, rtt=0.021, sttl=56)
    t = c.handshake(1.1)
    t = c.request_response(t + 0.001, tls_ch_record("www.youtube.com"), tls_server_flight(5200))
    t = c.request_response(t + 0.01, tls_app(1400), tls_app(380_000), rate=4_000_000)
    c.close(t + 5)
    c2 = Tcp(d, rnd.randint(40000, 65000), IP_YTIMG, 443, rtt=0.021, sttl=56)
    t = c2.handshake(1.5)
    t = c2.request_response(t + 0.001, tls_ch_record("i.ytimg.com"), tls_server_flight(4600))
    t = c2.request_response(t + 0.01, tls_app(700), tls_app(160_000), rate=4_000_000)
    c2.close(t + 3)
    # видео по TCP
    c3 = Tcp(d, rnd.randint(40000, 65000), IP_GV, 443, rtt=0.019, sttl=57)
    t = c3.handshake(2.1)
    t = c3.request_response(t + 0.001, tls_ch_record(GV_NAME), tls_server_flight(5000))
    for _ in range(6):
        t = c3.request_response(t + 0.2, tls_app(900), tls_app(rnd.randint(300_000, 600_000)), rate=5_000_000)
        t += 2.5
    c3.close(t + 1)
    # видео по QUIC
    cport, dcid, scid = rnd.randint(40000, 60000), rbytes(8), b""
    t = 3.0
    d.udp(t, LOCAL, cport, IP_GV, 443,
          quic_client_initial(dcid, scid, 0, client_hello(GV_NAME, alpn=(b"h3",), quic=True)), "UDP, length 1250")
    sdcid = rbytes(8)
    for i in range(3):
        p = quic_server_long(scid, sdcid, 1200, ptype=0 if i == 0 else 2)
        d.udp(t + 0.019 + i * 0.0003, IP_GV, 443, LOCAL, cport, p, "UDP, length 1200", ttl=57)
    t += 0.03
    while t < 40:
        for _ in range(rnd.randint(20, 80)):
            d.udp(t, IP_GV, 443, LOCAL, cport, quic_short(scid, 1250), "UDP, length 1250", ttl=57)
            t += 0.0004
        d.udp(t, LOCAL, cport, IP_GV, 443, quic_short(sdcid, 45), "UDP, length 45")
        t += rnd.uniform(0.2, 1.2)
    return d


def sc_youtube_blocked():
    d = Dump("14_youtube_blocked", "YouTube: RST на www.youtube.com, видео — дроп после ClientHello и QUIC без ответа")
    background(d, 45)
    yt_dns(d, 1.0)
    # www.youtube.com: ТСПУ сбрасывает после ClientHello (TTL не как у сервера)
    for k in range(3):
        c = Tcp(d, rnd.randint(40000, 65000), IP_YT, 443, rtt=0.021, sttl=56)
        t = c.handshake(1.1 + k * 1.3)
        c.send(t + 0.001, True, tls_ch_record("www.youtube.com"), auto_ack=False)
        c.rst(t + 0.0025, False, ttl=62)
    # i.ytimg.com работает
    c2 = Tcp(d, rnd.randint(40000, 65000), IP_YTIMG, 443, rtt=0.021, sttl=56)
    t = c2.handshake(1.5)
    t = c2.request_response(t + 0.001, tls_ch_record("i.ytimg.com"), tls_server_flight(4600))
    c2.close(t + 3)
    # googlevideo по TCP: SYN-ACK есть, после ClientHello — тишина, повторы ClientHello
    for k in range(3):
        c3 = Tcp(d, rnd.randint(40000, 65000), IP_GV, 443, rtt=0.019, sttl=57)
        t = c3.handshake(2.1 + k * 7)
        ch = tls_ch_record(GV_NAME)
        c3.send(t + 0.001, True, ch, auto_ack=False)
        s = c3.nxt[True] - len(ch)
        rto = 0.22
        for _ in range(5):
            t += rto
            c3.emit(t, True, F_ACK | F_PSH, seq_rel=s, payload=ch)
            rto *= 2
    # googlevideo по QUIC: Initial без ответа
    for k in range(3):
        cport, dcid = rnd.randint(40000, 60000), rbytes(8)
        ch = client_hello(GV_NAME, alpn=(b"h3",), quic=True)
        for i, dt in enumerate((0, 0.3, 0.9, 2.1)):
            d.udp(3.0 + k * 9 + dt, LOCAL, cport, IP_GV, 443, quic_client_initial(dcid, b"", i, ch), "UDP, length 1250")
    return d


def sc_normal_ok():
    d = Dump("15_normal_sites_ok", "Обычные сайты: Википедия (HTTPS), зеркало Яндекса (HTTP) — всё работает")
    background(d, 45)
    dns_exchange(d, 1.0, "ru.wikipedia.org", [("CNAME", "dyna.wikimedia.org"), ("A", IP_WIKI)])
    c = Tcp(d, rnd.randint(40000, 65000), IP_WIKI, 443, rtt=0.038, sttl=55)
    t = c.handshake(1.1)
    t = c.request_response(t + 0.001, tls_ch_record("ru.wikipedia.org"), tls_server_flight(4800))
    for _ in range(4):
        t = c.request_response(t + 0.4, tls_app(700), tls_app(rnd.randint(30_000, 250_000)))
    c.close(t + 2)
    dns_exchange(d, 5.0, "mirror.yandex.ru", [("A", IP_MIRROR)])
    h = Tcp(d, rnd.randint(40000, 65000), IP_MIRROR, 80, rtt=0.009, sttl=58)
    t = h.handshake(5.1)
    req = b"GET /ubuntu/ls-lR.gz HTTP/1.1\r\nHost: mirror.yandex.ru\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
    body = b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/octet-stream\r\nContent-Length: 2400000\r\n\r\n"
    t = h.request_response(t + 0.001, req, body + os.urandom(2_400_000), rate=5_000_000)
    h.close(t + 0.1)
    return d


def sc_host_down():
    d = Dump("16_host_down", "Сайт не работает сам (сервер лежит): SYN без ответа — не блокировка")
    background(d, 45)
    dns_exchange(d, 1.0, "shop.example-down.ru", [("A", IP_DOWN)])
    for k in range(3):
        c = Tcp(d, rnd.randint(40000, 65000), IP_DOWN, 443)
        t = 1.1 + k * 12
        for dt in (0, 1, 3, 7):
            c.syn(t + dt)
    return d


SCENARIOS = [sc_ipsec_ok, sc_ipsec_blocked, sc_ipsec_blocked_esp, sc_ipsec_corp, sc_vowifi,
             sc_hysteria_ok, sc_hysteria_blocked, sc_vless_ok, sc_vless_blocked, sc_vless_rst,
             sc_wg_ok, sc_wg_blocked, sc_youtube_ok, sc_youtube_blocked, sc_normal_ok, sc_host_down]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "..", "testdumps")
    os.makedirs(out, exist_ok=True)
    idx = []
    for sc in SCENARIOS:
        d = sc()
        base = os.path.join(out, d.name)
        d.write_txt(base + ".txt")
        d.write_txt(base + ".v.txt", verbose=True)
        d.write_pcap(base + ".pcap")
        d.write_pcapng(base + ".pcapng")
        idx.append("%-28s %6d пакетов  %s" % (d.name, len(d.pkts), d.title))
        print(idx[-1])
    with open(os.path.join(out, "README.txt"), "w", encoding="utf-8") as f:
        f.write("Синтетические дампы для проверки TrafficAnalyzer (tools/gen_test_dumps.py).\n")
        f.write("Абонент %s, DNS провайдера %s. Каждый сценарий — .txt (tcpdump -n), .v.txt (tcpdump -nv, с TTL), .pcap, .pcapng.\n\n"
                % (LOCAL, ISP_DNS))
        f.write("\n".join(idx) + "\n")


if __name__ == "__main__":
    main()
