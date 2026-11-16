#!/usr/bin/env python3
"""Threat sightings evaluation, Linux/macOS side (see scripts/sightings-eval.ts).

Looks up the planted domains mixed at random into the normal ones (Tranco top 1,000), one
every 50 ms, then opens 4 connections to the planted IP, each held 20 s (the agent polls the
connection table every 30 s, so a connection shorter than that can be missed: a stated blind
spot). Writes what it did, with times, to lookups-<host>.csv. Needs no root.

  python3 lookups.py planted-domains.txt normal-domains.txt 188.184.67.127
"""

import csv
import random
import socket
import sys
import time


def read(path):
    with open(path, encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip()]


def main():
    planted, normal, ip = read(sys.argv[1]), read(sys.argv[2]), sys.argv[3]
    names = [(n, True) for n in planted] + [(n, False) for n in normal]
    random.Random(7).shuffle(names)
    out = f"lookups-{socket.gethostname()}.csv"
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["utc", "what", "value", "planted", "result"])
        for name, is_planted in names:
            t = time.time()
            try:
                result = ",".join(sorted({a[4][0] for a in socket.getaddrinfo(name, None, socket.AF_INET)}))
            except socket.gaierror as exc:
                result = f"error {exc.errno}"
            w.writerow([f"{t:.3f}", "lookup", name, is_planted, result])
            time.sleep(0.05)
        for i in range(4):
            t = time.time()
            try:
                s = socket.create_connection((ip, 80), timeout=10)
                s.sendall(b"GET / HTTP/1.1\r\nHost: info.cern.ch\r\n")      # unfinished: the server waits
                w.writerow([f"{t:.3f}", "connect", ip, True, "open"])
                fh.flush()
                time.sleep(20)
                s.close()
            except OSError as exc:
                w.writerow([f"{t:.3f}", "connect", ip, True, f"error {exc}"])
    print(f"{len(names)} lookups ({len(planted)} planted) and 4 connections to {ip}; log in {out}")


if __name__ == "__main__":
    main()
