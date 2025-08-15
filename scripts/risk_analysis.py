import json
import sys

def calculate_risk(report):
    score = 0
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            sev = vuln.get("Severity")
            if sev == "CRITICAL": score += 5
            elif sev == "HIGH": score += 3
            elif sev == "MEDIUM": score += 1
    return "High" if score >= 15 else "Medium" if score >= 5 else "Low"

if __name__ == "__main__":
    with open("trivy_report.json") as f:
        report = json.load(f)
    risk = calculate_risk(report)
    print(f"Overall Risk Level: {risk}")
    with open("risk_summary.txt", "w") as f:
        f.write(f"### Dependency Risk Analysis\n\nOverall Risk Level: **{risk}**\n\n")
    if risk == "High":
        sys.exit(1)  # Fail the workflow
    sys.exit(0)
