"""
risk-calibration.py: calibrate the CVSS/EPSS part of the composite risk score
(workers/src/lib/riskScore.ts) against real exploitation, on public data, without hindsight.

Question: with the score's other parts fixed (criticality 15%, threat-intel match +10), how
should the remaining 75% be split between CVSS and EPSS, and on what scale should EPSS enter,
so that CVEs that are about to be exploited rank first?

Design (temporal, so nothing the score could not have known is used):
  * At a cut-off date T, take every CVE that FIRST.org scored with EPSS on T, as EPSS was on T.
  * Drop CVEs already in CISA KEV on T: the deployed score lifts those by its threat-intel bonus.
  * Positive = added to KEV within the following 365 days ("exploited in the wild, later").
  * Fit the split on T = 2024-11-16 (train), report it on T = 2025-11-16 (test).
CVSS comes from NVD (v3.x base score, else v2) as published today; scores rarely change, but
this is the one input not frozen at T.

Data (downloaded once into --data, about 140 MB):
  EPSS   https://epss.empiricalsecurity.com/epss_scores-<date>.csv.gz
  KEV    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  NVD    https://github.com/fkie-cad/nvd-json-data-feeds (per-year CVE-<year>.json.xz)

Run (Python 3.10+, standard library only):
  python scripts/risk-calibration.py --data C:/FYP/AP2/eval/data --out C:/FYP/AP2/eval
"""
import argparse
import csv
import gzip
import io
import json
import lzma
import math
import os
import random
import sys
import time
import urllib.request
from datetime import date, timedelta

EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz'
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
NVD_URL = 'https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-{y}.json.xz'
TRAIN, TEST = date(2024, 11, 16), date(2025, 11, 16)
HORIZON = timedelta(days=365)
CVSS_EPSS_SHARE = 0.75        # what is left after criticality (0.15) and the +10 CTI bonus
CURRENT = ('raw', 0.40)       # deployed: CVSS 0.40, raw EPSS 0.35


def fetch(url, path):
    if os.path.exists(path):
        return path
    print(f'  downloading {url}', flush=True)
    req = urllib.request.Request(url, headers={'User-Agent': 'UMEagleEye-evaluation'})
    with urllib.request.urlopen(req, timeout=300) as r, open(path + '.part', 'wb') as f:
        while chunk := r.read(1 << 20):
            f.write(chunk)
    os.replace(path + '.part', path)
    return path


def load_epss(data, d):
    path = fetch(EPSS_URL.format(d=d.isoformat()), os.path.join(data, f'epss_scores-{d}.csv.gz'))
    out = {}
    with gzip.open(path, 'rt', encoding='utf-8') as f:
        lines = (ln for ln in f if not ln.startswith('#'))
        for row in csv.DictReader(lines):
            out[row['cve']] = (float(row['epss']), float(row['percentile']))
    return out


def load_kev(data):
    path = fetch(KEV_URL, os.path.join(data, 'kev.json'))
    with open(path, encoding='utf-8') as f:
        kev = json.load(f)
    return kev.get('catalogVersion'), {v['cveID']: date.fromisoformat(v['dateAdded']) for v in kev['vulnerabilities']}


def load_cvss(data, last_year):
    """CVE id -> CVSS base score (v3.1/v3.0 primary, else any v3, else v2), cached as CSV."""
    cache = os.path.join(data, 'cvss.csv')
    if os.path.exists(cache):
        with open(cache, encoding='utf-8') as f:
            return {r[0]: float(r[1]) for r in csv.reader(f)}
    out = {}
    for y in range(1999, last_year + 1):
        path = fetch(NVD_URL.format(y=y), os.path.join(data, f'CVE-{y}.json.xz'))
        with lzma.open(path, 'rt', encoding='utf-8') as f:
            doc = json.load(f)
        for item in doc.get('cve_items') or doc.get('vulnerabilities') or []:
            cve = item.get('cve', item)
            metrics = cve.get('metrics', {})
            score = None
            for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                ms = metrics.get(key) or []
                if not ms:
                    continue
                primary = next((m for m in ms if m.get('type') == 'Primary'), ms[0])
                score = primary['cvssData']['baseScore']
                break
            if score is not None:
                out[cve['id']] = float(score)
        print(f'  NVD {y}: {len(out)} CVEs with CVSS so far', flush=True)
        del doc
    with open(cache, 'w', encoding='utf-8', newline='') as f:
        csv.writer(f).writerows(out.items())
    return out


# ── EPSS scales ────────────────────────────────────────────────────────────────
# raw: the probability itself (heavily skewed: most CVEs are under 0.01)
# log: log10 of the probability mapped 1e-5..1 onto 0..1 (computable from the stored EPSS)
# pct: FIRST.org's percentile (uniform 0..1; needs the percentile stored at ingest)
def scale(kind, epss, pct):
    if kind == 'raw':
        return epss
    if kind == 'log':
        return max(0.0, min(1.0, (math.log10(max(epss, 1e-5)) + 5) / 5))
    return pct


def score(kind, w_cvss, cvss, epss, pct):
    """The CVSS+EPSS part of the composite (criticality and CTI are constant here)."""
    w_epss = CVSS_EPSS_SHARE - w_cvss
    return round(cvss * 10 * w_cvss + scale(kind, epss, pct) * 100 * w_epss, 4)


# ── Ranking metrics, ties broken uniformly at random (expected values) ─────────
def groups(scores, labels):
    g = {}
    for s, y in zip(scores, labels):
        n, p = g.get(s, (0, 0))
        g[s] = (n + 1, p + y)
    return sorted(g.items(), key=lambda kv: -kv[0])


def metrics(scores, labels):
    gs = groups(scores, labels)
    P = sum(p for _, (n, p) in gs)
    N = sum(n for _, (n, p) in gs) - P
    total = P + N
    # AUC (Mann-Whitney, mid-ranks)
    neg_below, s = N, 0.0
    for _, (n, p) in gs:
        neg = n - p
        neg_below -= neg
        s += p * (neg_below + neg / 2)
    auc = s / (P * N)
    # Average precision with positives at their expected ranks in a tie group
    seen = hits = 0
    ap = 0.0
    for _, (n, p) in gs:
        for i in range(1, p + 1):
            ap += (hits + i) / (seen + i * (n + 1) / (p + 1))
        seen += n
        hits += p
    ap /= P

    def effort(cov):
        need, seen, hits = cov * P, 0, 0
        for _, (n, p) in gs:
            if hits + p >= need - 1e-9:
                return (seen + (n * (need - hits) / p if p else 0)) / total
            seen += n
            hits += p
        return 1.0

    def hits_at(k):
        seen = hits = 0
        for _, (n, p) in gs:
            if seen + n <= k:
                seen += n
                hits += p
                continue
            return hits + p * (k - seen) / n
        return hits
    return {'auc': auc, 'ap': ap, 'effort_50': effort(0.5), 'effort_80': effort(0.8),
            'hits_at_1pct': hits_at(total // 100), 'hits_at_1000': hits_at(1000)}


def population(epss, cvss, kev, t):
    rows = []
    for cve, (e, pct) in epss.items():
        c = cvss.get(cve)
        if c is None:
            continue
        added = kev.get(cve)
        if added and added <= t:
            continue                       # already known exploited on T
        rows.append((c, e, pct, 1 if added and added <= t + HORIZON else 0))
    return rows


def evaluate(rows, kind, w):
    sc = [score(kind, w, c, e, p) for c, e, p, _ in rows]
    return metrics(sc, [y for *_, y in rows])


def baseline(rows, key):
    sc = [c if key == 'cvss' else e for c, e, p, _ in rows]
    return metrics(sc, [y for *_, y in rows])


def bootstrap_gain(rows, score_a, score_b, key, n=200, seed=20261116):
    """metric(a) - metric(b) over resampled CVEs (positives and negatives resampled separately)."""
    rnd = random.Random(seed)
    pos = [r for r in rows if r[3]]
    neg = [r for r in rows if not r[3]]
    out = []
    for _ in range(n):
        s = [rnd.choice(pos) for _ in pos] + [rnd.choice(neg) for _ in neg]
        ys = [r[3] for r in s]
        out.append(metrics([score_a(r) for r in s], ys)[key] - metrics([score_b(r) for r in s], ys)[key])
    out.sort()
    return {'mean': sum(out) / n, 'ci95': [out[int(0.025 * n)], out[int(0.975 * n) - 1]], 'resamples': n}


METRICS = (('auc', 1), ('ap', 1), ('effort_50', -1), ('effort_80', -1))   # 1: higher is better


def no_worse(m, ref):
    return all((m[k] - ref[k]) * sign >= -1e-12 for k, sign in METRICS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', required=True)
    ap.add_argument('--out')
    ap.add_argument('--bootstrap', type=int, default=200)
    args = ap.parse_args()
    os.makedirs(args.data, exist_ok=True)

    t0 = time.time()
    kev_version, kev = load_kev(args.data)
    cvss = load_cvss(args.data, TEST.year)
    print(f'KEV {kev_version}: {len(kev)} CVEs; NVD: {len(cvss)} CVEs with CVSS')

    report = {'kev_catalogue': kev_version, 'train_cutoff': TRAIN.isoformat(), 'test_cutoff': TEST.isoformat(),
              'horizon_days': HORIZON.days, 'cvss_epss_share': CVSS_EPSS_SHARE, 'splits': {}}
    grid = [round(0.05 * i, 2) for i in range(int(CVSS_EPSS_SHARE / 0.05) + 1)]
    kinds = ['raw', 'log', 'pct']
    rows_by = {}
    for name, t in (('train', TRAIN), ('test', TEST)):
        rows = population(load_epss(args.data, t), cvss, kev, t)
        rows_by[name] = rows
        P = sum(r[3] for r in rows)
        print(f'\n{name} (T={t}): {len(rows)} CVEs, {P} added to KEV within {HORIZON.days} days ({100 * P / len(rows):.3f}%)')
        split = {'cves': len(rows), 'positives': P,
                 'cvss_only': baseline(rows, 'cvss'), 'epss_only': baseline(rows, 'epss'),
                 'current': evaluate(rows, *CURRENT), 'grid': {}}
        for kind in kinds:
            split['grid'][kind] = {str(w): evaluate(rows, kind, w) for w in grid}
        report['splits'][name] = split
        print(f"  CVSS only  AUC {split['cvss_only']['auc']:.3f}  AP {split['cvss_only']['ap']:.4f}")
        print(f"  EPSS only  AUC {split['epss_only']['auc']:.3f}  AP {split['epss_only']['ap']:.4f}")
        print(f"  current    AUC {split['current']['auc']:.3f}  AP {split['current']['ap']:.4f}")

    # A queue needs both a good top (AP, effort to 50%) and a good tail (AUC, effort to 80%),
    # so no single metric picks the weights. A candidate must be no worse than the current
    # formula on ALL four metrics at the TRAIN cut-off; only those are then checked on TEST.
    train, test = report['splits']['train'], report['splits']['test']
    candidates = [(k, float(w)) for k in kinds for w in train['grid'][k]
                  if (k, float(w)) != CURRENT and no_worse(train['grid'][k][w], train['current'])]
    report['candidates_no_worse_on_train'] = [
        {'scale': k, 'w_cvss': w, 'test': test['grid'][k][str(w)],
         'no_worse_on_test': no_worse(test['grid'][k][str(w)], test['current'])} for k, w in candidates]
    print(f"\nSplits no worse than the current formula on all four train metrics: {len(candidates)}"
          + ''.join(f"\n  {k} EPSS, CVSS {w:.2f}: also no worse on test: {no_worse(test['grid'][k][str(w)], test['current'])}" for k, w in candidates))
    # Best split per scale by each metric at the train cut-off, to show how flat the optimum is
    report['train_best_split_by_metric'] = {k: {m: max((float(w) for w in train['grid'][k]),
        key=lambda w: sign * train['grid'][k][str(w)][m]) for m, sign in METRICS} for k in kinds}
    print('Best CVSS weight at the train cut-off, by metric:', json.dumps(report['train_best_split_by_metric']))

    print(f"\n{'Ranking (test, T=' + TEST.isoformat() + ')':42} {'AUC':>6} {'AP':>7} {'Eff50%':>7} {'Eff80%':>7} {'Top1%':>7}")
    rowsfmt = [('CVSS only', test['cvss_only']), ('EPSS only', test['epss_only']),
               ('Current composite (CVSS .40, raw EPSS .35)', test['current'])]
    for k in kinds:
        rowsfmt.append((f'{k} EPSS, CVSS 0.40 / EPSS 0.35', test['grid'][k]['0.4']))
    P = test['positives']
    for label, m in rowsfmt:
        print(f"{label:42} {m['auc']:6.3f} {m['ap']:7.4f} {100 * m['effort_50']:6.1f}% {100 * m['effort_80']:6.1f}% {m['hits_at_1pct']:6.1f}/{P}")

    if args.bootstrap:
        print(f'\nBootstrap ({args.bootstrap} resamples) at the test cut-off...', flush=True)
        cur = lambda r: score(*CURRENT, r[0], r[1], r[2])
        report['test_gain_of_current'] = {
            'auc_vs_cvss': bootstrap_gain(rows_by['test'], cur, lambda r: r[0], 'auc', n=args.bootstrap),
            'auc_vs_epss': bootstrap_gain(rows_by['test'], cur, lambda r: r[1], 'auc', n=args.bootstrap),
            'effort_80_vs_cvss': bootstrap_gain(rows_by['test'], cur, lambda r: r[0], 'effort_80', n=args.bootstrap),
        }
        for name, g in report['test_gain_of_current'].items():
            print(f"  current formula, {name}: {g['mean']:+.4f} (95% CI {g['ci95'][0]:+.4f} to {g['ci95'][1]:+.4f})")

    print(f'\nDone in {time.time() - t0:.0f} s')
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, 'risk-calibration.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f'Wrote {path}')


if __name__ == '__main__':
    sys.exit(main())
