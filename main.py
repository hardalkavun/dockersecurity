import subprocess
import json

# ---------------------------
# Get containers
# ---------------------------
def get_containers():
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.ID}}"],
        capture_output=True,
        text=True
    )

    containers = result.stdout.strip().split("\n")
    return [c for c in containers if c]


# ---------------------------
# Inspect container
# ---------------------------
def inspect_container(cid):
    result = subprocess.run(
        ["docker", "inspect", cid],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)[0]


# ---------------------------
# Auto fix suggestions
# ---------------------------
def get_fix(finding):
    fixes = {
        "Running as root": "Set USER non-root in Dockerfile (USER appuser)",
        "Using latest tag": "Use pinned version like nginx:1.25 instead of latest",
        "Privileged mode enabled": "Remove --privileged flag",
        "Exposed ports": "Limit exposed ports using firewall / security groups",
        "Docker socket mounted": "Do NOT mount /var/run/docker.sock"
    }
    return fixes.get(finding, "No suggestion available")


# ---------------------------
# Security analysis engine
# ---------------------------
def analyze(container):
    issues = []

    image = container["Config"]["Image"]
    user = container["Config"]["User"]

    # Root user
    if user == "" or user == "root":
        issues.append({
            "finding": "Running as root",
            "risk": "HIGH",
            "impact": "Container compromise may lead to privilege escalation",
            "fix": get_fix("Running as root")
        })

    # Latest tag
    if ":latest" in image:
        issues.append({
            "finding": "Using latest tag",
            "risk": "MEDIUM",
            "impact": "Uncontrolled updates may introduce vulnerabilities",
            "fix": get_fix("Using latest tag")
        })

    # Privileged mode
    if container["HostConfig"].get("Privileged", False):
        issues.append({
            "finding": "Privileged mode enabled",
            "risk": "CRITICAL",
            "impact": "Full host system access possible",
            "fix": get_fix("Privileged mode enabled")
        })

    # Exposed ports
    if container["NetworkSettings"].get("Ports"):
        issues.append({
            "finding": "Exposed ports",
            "risk": "MEDIUM",
            "impact": "Increases attack surface",
            "fix": get_fix("Exposed ports")
        })

    # Docker socket
    binds = container["HostConfig"].get("Binds") or []
    if any("docker.sock" in b for b in binds):
        issues.append({
            "finding": "Docker socket mounted",
            "risk": "CRITICAL",
            "impact": "Host takeover risk via Docker API access",
            "fix": get_fix("Docker socket mounted")
        })

    return issues


# ---------------------------
# Risk level
# ---------------------------
def get_risk_level(issues):
    if not issues:
        return "LOW"

    if any(i["risk"] == "CRITICAL" for i in issues):
        return "CRITICAL"
    elif any(i["risk"] == "HIGH" for i in issues):
        return "HIGH"
    elif any(i["risk"] == "MEDIUM" for i in issues):
        return "MEDIUM"
    else:
        return "LOW"


# ---------------------------
# Risk score (0-100)
# ---------------------------
def calculate_score(issues):
    score = 0

    for i in issues:
        if i["risk"] == "CRITICAL":
            score += 100
        elif i["risk"] == "HIGH":
            score += 70
        elif i["risk"] == "MEDIUM":
            score += 40

    return min(score, 100)


# ---------------------------
# Main
# ---------------------------
def main():
    containers = get_containers()

    if not containers:
        print("No running containers found.")
        return

    report = {
        "containers": [],
        "summary": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    }

    for cid in containers:
        data = inspect_container(cid)
        issues = analyze(data)
        risk = get_risk_level(issues)
        score = calculate_score(issues)

        report["summary"][risk] += 1

        report["containers"].append({
            "id": cid,
            "image": data["Config"]["Image"],
            "risk": risk,
            "score": score,
            "issues": issues
        })

        print("\n====================")
        print("Container:", cid)
        print("Image:", data["Config"]["Image"])
        print("Risk:", risk)
        print("Score:", score)

        if issues:
            print("Issues:")
            for i in issues:
                print("-", i["finding"])
                print("  Impact:", i["impact"])
                print("  Fix:", i["fix"])
        else:
            print("No issues found")

    # Save report
    with open("report.json", "w") as f:
        json.dump(report, f, indent=4)

    print("\n====================")
    print("Report saved to report.json")


if __name__ == "__main__":
    main()
