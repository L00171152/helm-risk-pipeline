import json
import sys
from epss_api import EPSS
from cvss import CVSS3

def composite(trivy_json_file):
    with open(trivy_json_file) as f:
        report = json.load(f)

    epss = EPSS()
    vulns = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vulns.append(vuln)

    if not vulns:
        return 0.0

    cvss_scores = []
    epss_scores = []
    for v in vulns:
        cvss_vec = v.get("CVSS", {}).get("nvd", {}).get("V3Vector")
        base = CVSS3(cvss_vec).scores() if cvss_vec else 0
        cvss_scores.append(base)
        eid = v.get("VulnerabilityID")
        epss_val = float(epss.score(eid).get("epss", 0.01))
        epss_scores.append(epss_val)

    max_cvss = max(cvss_scores)
    mean_cvss = sum(cvss_scores)/len(cvss_scores)
    max_epss = max(epss_scores)

    risk_score = round(0.6*max_cvss/10 + 0.3*mean_cvss/10 + 0.1*max_epss, 3)
    return risk_score

if __name__ == "__main__":
    score = composite(sys.argv[1])
    print(f"Composite risk-score: {score}")
