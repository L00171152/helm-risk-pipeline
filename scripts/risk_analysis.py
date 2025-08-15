#!/usr/bin/env python3
import json, glob, os, sys
from collections import defaultdict, Counter
from typing import List, Tuple

REPORT_GLOB = os.environ.get("TRIVY_REPORT_GLOB", "trivy-*.json")
OUT_SUMMARY  = os.environ.get("RISK_SUMMARY_PATH", "risk_summary.txt")
OUT_DETAILS  = os.environ.get("RISK_DETAILS_PATH", "risk_details.md")
FAIL_ON_HIGH = int(os.environ.get("FAIL_ON_HIGH", "0"))  # e.g. 100
FAIL_ON_CRIT = int(os.environ.get("FAIL_ON_CRIT", "0"))  # e.g. 10
TOP_FINDINGS_PER_IMAGE = int(os.environ.get("TOP_FINDINGS_PER_IMAGE", "5"))

def load_reports(pattern: str) -> List[dict]:
    files = sorted(glob.glob(pattern))
    objs = []
    for f in files:
        try:
            data = json.load(open(f))
            if isinstance(data, dict):
                data = [data]
            objs.extend(data)
        except Exception:
            pass
    return objs

def iter_vulns(trivy_obj):
    """Yield (severity, cve, pkg, target, cvss_score)."""
    for result in trivy_obj or []:
        for res in result.get("Results") or []:
            target = res.get("Target", "")
            vulns = res.get("Vulnerabilities") or []
            for v in vulns:
                sev = v.get("Severity","UNKNOWN")
                cve = v.get("VulnerabilityID","")
                pkg = v.get("PkgName", "")
                score = None
                for src in (v.get("CVSS") or {}).values():
                    if src.get("V3Score") is not None:
                        score = src["V3Score"]
                        break
                yield sev, cve, pkg, target, score

def fmt_md_table(rows: List[List[str]]) -> str:
    if not rows: return ""
    # first row is header
    header = rows[0]
    under = ["---"] * len(header)
    out = ["| " + " | ".join(header) + " |",
           "| " + " | ".join(under) + " |"]
    for r in rows[1:]:
        out.append("| " + " | ".join(r) + " |")
    return "\n".join(out) + "\n"

def main():
    data = load_reports(REPORT_GLOB)
    if not data:
        open(OUT_SUMMARY, "w").write("No Trivy reports found.\n")
        open(OUT_DETAILS, "w").write("# Risk Details\n\nNo Trivy reports found.\n")
        print("No Trivy reports found.")
        return

    total = Counter()
    per_image = defaultdict(Counter)
    per_image_vulns = defaultdict(list)  # image -> [(score, sev, cve, pkg)]

    for sev, cve, pkg, tgt, score in iter_vulns(data):
        total[sev] += 1
        if tgt:
            per_image[tgt][sev] += 1
            if sev in ("CRITICAL","HIGH"):
                per_image_vulns[tgt].append((score or 0.0, sev, cve, pkg))

    # short score
    risk_score = 3*total["CRITICAL"] + total["HIGH"]

    # ===== summary (for PR comment) =====
    lines = []
    lines.append("## Dependency Risk Analysis")
    lines.append(f"**Overall Risk Score:** {risk_score}")
    lines.append("")
    lines.append("### Totals")
    lines.append(
        f"- CRITICAL: **{total['CRITICAL']}**, HIGH: **{total['HIGH']}**, "
        f"MEDIUM: {total['MEDIUM']}, LOW: {total['LOW']}, UNKNOWN: {total['UNKNOWN']}"
    )
    lines.append("")
    # top images by CRIT/HIGH
    top_images = sorted(per_image.items(),
                        key=lambda kv: (kv[1]["CRITICAL"], kv[1]["HIGH"]), reverse=True)[:10]
    if top_images:
        lines.append("### By Image (top 10)")
        for img, cnt in top_images:
            lines.append(f"- `{img}` → CRIT {cnt['CRITICAL']}, HIGH {cnt['HIGH']}, "
                         f"MED {cnt['MEDIUM']}, LOW {cnt['LOW']}")
        lines.append("")
    with open(OUT_SUMMARY, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("\n".join(lines))

    # ===== detailed report =====
    det = []
    det.append("# Risk Details")
    det.append("")
    # big table
    rows = [["Image", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "Risk"]]
    for img, cnt in sorted(per_image.items(),
                           key=lambda kv: (kv[1]["CRITICAL"], kv[1]["HIGH"]), reverse=True):
        risk = 3*cnt["CRITICAL"] + cnt["HIGH"]
        rows.append([img,
                     str(cnt["CRITICAL"]), str(cnt["HIGH"]),
                     str(cnt["MEDIUM"]), str(cnt["LOW"]),
                     str(cnt["UNKNOWN"]), str(risk)])
    det.append("## Per-Image Vulnerability Counts")
    det.append("")
    det.append(fmt_md_table(rows))
    det.append("")

    # top findings per image
    det.append("## Top Findings per Image")
    det.append("")
    for img in sorted(per_image_vulns.keys()):
        top = sorted(per_image_vulns[img], key=lambda x: x[0], reverse=True)[:TOP_FINDINGS_PER_IMAGE]
        det.append(f"### {img}")
        if not top:
            det.append("_No HIGH/CRITICAL findings recorded._\n")
            continue
        r2 = [["Severity", "CVE", "CVSS", "Package"]]
        for score, sev, cve, pkg in top:
            r2.append([sev, cve, f"{score:.1f}" if score else "n/a", pkg or "-"])
        det.append(fmt_md_table(r2))
        det.append("")
    with open(OUT_DETAILS, "w") as fh:
        fh.write("\n".join(det))

    # optional gating
    if FAIL_ON_HIGH and total["HIGH"] > FAIL_ON_HIGH:
        print(f"::error ::HIGH > threshold ({total['HIGH']} > {FAIL_ON_HIGH})")
        sys.exit(1)
    if FAIL_ON_CRIT and total["CRITICAL"] > FAIL_ON_CRIT:
        print(f"::error ::CRITICAL > threshold ({total['CRITICAL']} > {FAIL_ON_CRIT})")
        sys.exit(1)

if __name__ == "__main__":
    main()
