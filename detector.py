import psutil
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Suspicious indicators
SUSPICIOUS_KEYWORDS = ["logger", "keyboard", "spy", "hook"]
SUSPICIOUS_LOCATIONS = ["appdata", "temp", "downloads"]

def score_process(proc):
    """Assigns a risk score to a process based on multiple checks."""
    score = 0
    reasons = []

    try:
        pname = proc.info['name'].lower() if proc.info['name'] else ""
        pexe = proc.info['exe'].lower() if proc.info['exe'] else ""
        cpu = proc.cpu_percent(interval=0.1)
        mem = proc.memory_percent()

        # Rule 1: Suspicious keywords in name
        if any(keyword in pname for keyword in SUSPICIOUS_KEYWORDS):
            score += 30
            reasons.append("Suspicious process name")

        # Rule 2: Running from suspicious folder
        if any(loc in pexe for loc in SUSPICIOUS_LOCATIONS):
            score += 20
            reasons.append("Running from suspicious location")

        # Rule 3: High resource usage for background process
        if cpu > 5 or mem > 5:  # threshold can be adjusted
            score += 20
            reasons.append("Unusual CPU/Memory usage")

        # Rule 4: Persistence check (simulated for demo)
        if "startup" in pexe:
            score += 20
            reasons.append("Found in startup location")

        # Rule 5: Network activity
        if proc.net_connections(kind="inet"):
            score += 30
            reasons.append("Has active network connections")

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return 0, []

    return score, reasons


def detect_keyloggers():
    alerts = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        score, reasons = score_process(proc)
        if score >= 40:  # threshold for suspicious process
            alerts.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "score": score,
                "reasons": reasons
            })
    return alerts


if __name__ == "__main__":
    print("=== Keylogger Detection Report ===")
    results = detect_keyloggers()

    if results:
        for r in results:
            risk = "HIGH" if r["score"] >= 70 else "MEDIUM"
            print(f"⚠️ {r['name']} (PID {r['pid']}) | Risk: {risk} | Score: {r['score']}")
            print("   Reasons: " + ", ".join(r['reasons']))
    else:
        print("✅ No suspicious processes found.")
