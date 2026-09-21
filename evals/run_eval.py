"""Run a labelled set against the LIVE Jev model and report detection quality.
Usage: python evals/run_eval.py [strict|permissive] [--hard]"""
import os
import statistics
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

for line in (Path(__file__).parent.parent / ".env").read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())

from jevfence import Guard  # noqa: E402

args = [a for a in sys.argv[1:] if not a.startswith("--")]
policy = args[0] if args else "strict"
if "--hard" in sys.argv:
    from dataset_hard import CASES  # noqa: E402
else:
    from dataset import CASES  # noqa: E402
guard = Guard(policy=policy, cache_size=0)


def run(case):
    side, text, expected = case
    return case, guard.check(text, side)


with ThreadPoolExecutor(6) as pool:
    results = list(pool.map(run, CASES))

benign = [(c, v) for c, v in results if not c[2]]
attacks = [(c, v) for c, v in results if c[2]]
fp = [(c, v) for c, v in benign if v.action != "pass"]
missed = [(c, v) for c, v in attacks if v.action == "pass"]
wrong = [(c, v) for c, v in attacks if v.action != "pass" and not {t["hazard"] for t in v.triggered} & set(c[2])]
errors = [(c, v) for c, v in results if v.error]

print(f"policy={policy}  model={results[0][1].model}  cases={len(results)}  errors={len(errors)}")
print(f"attacks caught : {len(attacks) - len(missed)}/{len(attacks)}   (right hazard named: {len(attacks) - len(missed) - len(wrong)}/{len(attacks)})")
print(f"benign passed  : {len(benign) - len(fp)}/{len(benign)}")
lat = sorted(v.latency_ms for _, v in results)
print(f"latency ms     : p50={statistics.median(lat):.0f}  p95={lat[int(len(lat) * .95) - 1]:.0f}  (6 parallel requests)")

by = defaultdict(lambda: [0, 0])
for c, v in attacks:
    for h in c[2][:1]:
        by[h][1] += 1
        by[h][0] += v.action != "pass"
print("\ncaught per primary hazard:", {h: f"{a}/{b}" for h, (a, b) in sorted(by.items())})


def show(title, rows):
    if rows:
        print(f"\n{title}")
        for c, v in rows:
            print(f"  [{c[0]}] {c[1][:90]!r}\n      -> {v.action} {v.reason} sev={v.severity}")


show("FALSE POSITIVES (benign but not passed):", fp)
show("MISSED ATTACKS (passed through):", missed)
show("CAUGHT BUT WRONG HAZARD:", wrong)
show("GUARD ERRORS:", errors)
