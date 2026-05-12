#!/usr/bin/env python3
"""dga_inspector.py — Detect DGA activity in a PCAP file.

Usage:
    python dga_inspector.py capture.pcap
    python dga_inspector.py capture.pcap --threshold 0.7 --model-dir results/
"""

import argparse
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import joblib
import tldextract
from scapy.all import DNS, DNSQR, IP, IPv6, PcapReader

BURST_WINDOW_SEC  = 300
BURST_MIN_DOMAINS = 10


def load_model(model_dir: str):
    d = Path(model_dir)
    return joblib.load(d / "rf_default.joblib"), joblib.load(d / "tfidf_vectorizer.joblib")


def extract_dns_queries(pcap_path: str) -> list[tuple]:
    queries = []
    with PcapReader(str(pcap_path)) as pcap:
        for pkt in pcap:
            if DNS not in pkt or DNSQR not in pkt:
                continue
            if pkt[DNS].qr != 0 or pkt[DNSQR].qtype not in (1, 28):
                continue
            src_ip = pkt[IP].src if IP in pkt else pkt[IPv6].src
            fqdn = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            if fqdn:
                queries.append((float(pkt.time), src_ip, fqdn))
    return queries


def score_queries(queries: list, rf, vectorizer, threshold: float = 0.5) -> list[tuple]:
    if not queries:
        return []
    labeled = [(i, tldextract.extract(fqdn).domain) for i, (_, _, fqdn) in enumerate(queries)]
    labeled = [(i, lbl) for i, lbl in labeled if lbl]
    if not labeled:
        return []
    scores = rf.predict_proba(vectorizer.transform([lbl for _, lbl in labeled]))[:, 1]
    return [(*queries[i], lbl, float(s), s >= threshold) for (i, lbl), s in zip(labeled, scores)]


def detect_bursts(scored: list, window: int = BURST_WINDOW_SEC, min_count: int = BURST_MIN_DOMAINS) -> dict:
    dga_by_ip: dict = defaultdict(list)
    for ts, src_ip, fqdn, _, score, is_dga in scored:
        if is_dga:
            dga_by_ip[src_ip].append((ts, fqdn, score))

    alerts = {}
    for src_ip, events in dga_by_ip.items():
        events.sort()
        best = None
        for i, (t0, _, _) in enumerate(events):
            distinct = list({f: (t, f, s) for t, f, s in events[i:] if t - t0 <= window}.values())
            if len(distinct) >= min_count and (best is None or len(distinct) > best["count"]):
                best = {
                    "start": datetime.fromtimestamp(t0, tz=timezone.utc).isoformat(),
                    "end":   datetime.fromtimestamp(distinct[-1][0], tz=timezone.utc).isoformat(),
                    "count": len(distinct),
                    "domains": sorted(distinct, key=lambda x: -x[2]),
                }
        if best:
            alerts[src_ip] = best
    return alerts


def print_report(scored: list, bursts: dict, threshold: float, verbose: bool = False) -> None:
    SEP = "=" * 60
    dga_hits    = [(ts, src_ip, fqdn, score) for ts, src_ip, fqdn, _, score, is_dga in scored if is_dga]
    distinct_dga = {fqdn for _, _, fqdn, _ in dga_hits}

    print(f"\n{SEP}")
    print(f"  DGA DOMAINS DETECTED  (threshold={threshold:.2f})  [{len(distinct_dga)} unique / {len(dga_hits)} hits]")
    print(SEP)
    if not distinct_dga:
        print("  None.")
    elif verbose:
        seen: set = set()
        for _, src_ip, fqdn, score in sorted(dga_hits, key=lambda x: -x[3]):
            if fqdn not in seen:
                seen.add(fqdn)
                print(f"  {score:.3f}  {fqdn:<45}  src={src_ip}")
    else:
        print(f"  {len(distinct_dga)} domain(s) flagged. Use --verbose to list them.")

    print(f"\n{SEP}")
    print(f"  C2 BURST DETECTION  (window={BURST_WINDOW_SEC}s, min={BURST_MIN_DOMAINS} domains)")
    print(SEP)
    if not bursts:
        print("  No C2 burst pattern detected.")
    else:
        for src_ip, b in sorted(bursts.items()):
            t0 = b["start"].replace("+00:00", "Z")
            t1 = b["end"].replace("+00:00", "Z")
            print(f"\n  [!] {src_ip}  —  {b['count']} distinct DGA domains in 5 min")
            print(f"      {t0}  →  {t1}")
            if verbose:
                for _, fqdn, score in b["domains"][:10]:
                    print(f"        {score:.3f}  {fqdn}")
                if b["count"] > 10:
                    print(f"        … and {b['count'] - 10} more")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect a PCAP for DGA activity.")
    parser.add_argument("pcap",          help="Path to the .pcap / .pcapng file")
    parser.add_argument("--threshold",   type=float, default=0.5,    help="DGA probability threshold (default: 0.5)")
    parser.add_argument("--model-dir",   default="results",          help="Directory containing model files (default: results/)")
    parser.add_argument("-v", "--verbose", action="store_true",      help="Print the full list of detected DGA domains and C2 domains")
    args = parser.parse_args()

    print(f"[*] Loading model from '{args.model_dir}'…", file=sys.stderr)
    rf, vectorizer = load_model(args.model_dir)

    print(f"[*] Parsing '{args.pcap}'…", file=sys.stderr)
    queries = extract_dns_queries(args.pcap)
    print(f"[*] {len(queries)} DNS A/AAAA queries extracted.", file=sys.stderr)

    if not queries:
        print("No DNS queries found in PCAP.")
        return

    scored = score_queries(queries, rf, vectorizer, threshold=args.threshold)
    bursts = detect_bursts(scored)
    print_report(scored, bursts, args.threshold, verbose=args.verbose)


if __name__ == "__main__":
    main()
