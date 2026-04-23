import subprocess
import json

def get_containers():
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.ID}}"],
        capture_output=True,
        text=True
    )

    containers = result.stdout.strip().split("\n")

    if containers == [''] or not containers:
        return []

    return containers

def inspect_container(container_id):
    result = subprocess.run(
        ["docker", "inspect", container_id],
        capture_output=True,
        text=True
    )

    return json.loads(result.stdout)[0]

def analyze(container):
    issues = []

    if container["Config"]["User"] == "":
        issues.append("Running as root")

    if container["HostConfig"].get("Privileged", False):
        issues.append("Privileged mode enabled")

    ports = container["NetworkSettings"].get("Ports")
    if ports:
        issues.append("Exposed ports")

    return issues

def get_risk_level(issues):
    if len(issues) == 0:
        return "LOW"
    elif len(issues) == 1:
        return "MEDIUM"
    else:
        return "HIGH"

def main():
    containers = get_containers()

    if not containers:
        print("No running containers found.")
        return

    for c in containers:
        data = inspect_container(c)
        issues = analyze(data)
        risk = get_risk_level(issues)

        print("\n======================")
        print("Container ID:", c)
        print("Image:", data["Config"]["Image"])
        print("User:", data["Config"]["User"] or "root (default)")
        print("Risk Level:", risk)

        if issues:
            print("Issues found:")
            for i in issues:
                print("-", i)
        else:
            print("No issues found")

if __name__ == "__main__":
    main()
