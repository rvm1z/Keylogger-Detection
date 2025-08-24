import psutil
import os
import sys
sys.stdout.reconfigure(encoding='utf-8')

# Suspicious indicators
SUSPICIOUS_KEYWORDS = ["logger", "keyboard", "spy", "hook"]
SUSPICIOUS_LOCATIONS = ["appdata", "temp", "downloads"]

# Whitelisted common safe processes (lowercase!)
WHITELIST = [
    "code.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "explorer.exe", "spotify.exe", "discord.exe", "teams.exe"
]

def score_process(proc):
    """Assigns a risk score to a process based on multiple checks."""
    score = 0
    reasons = []

    try:
        pname = proc.info['name'].lower() if proc.info['name'] else ""
        pexe = proc.info['exe'].lower() if proc.info['exe'] else ""
        cpu = proc.cpu_percent(interval=0.1)
        mem = proc.memory_percent()

        # Skip whitelisted safe apps unless very suspicious
        if pname in WHITELIST:
            return 0, []

        # Rule 1: Suspicious keywords in process name
        if any(keyword in pname for keyword in SUSPICIOUS_KEYWORDS):
            score += 30
            reasons.append("Suspicious process name")

        # Rule 2: Running from suspicious folder
        if any(loc in pexe for loc in SUSPICIOUS_LOCATIONS):
            score += 20
            reasons.append("Running from suspicious location")

        # Rule 3: High resource usage
        if cpu > 5 or mem > 5:
            score += 15  # lowered slightly
            reasons.append("Unusual CPU/Memory usage")

        # Rule 4: Persistence check (simulated)
        if "startup" in pexe:
            score += 25
            reasons.append("Found in startup location")

        # Rule 5: Network activity
        if proc.net_connections(kind="inet"):
            score += 10  # lowered weight
            reasons.append("Has active network connections")

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return 0, []

    return score, reasons


def detect_keyloggers():
    alerts = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        score, reasons = score_process(proc)
        if score >= 40:  # threshold for flagging
            alerts.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "score": score,
                "reasons": reasons
            })
    return alerts


def classify_risk(score):
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


if __name__ == "__main__":
    print("=== Keylogger Detection Report ===")
    results = detect_keyloggers()

    if results:
        for r in results:
            risk = classify_risk(r["score"])
            print(f"⚠️ {r['name']} (PID {r['pid']}) | Risk: {risk} | Score: {r['score']}")
            print("   Reasons: " + ", ".join(r['reasons']))
            print("-" * 60)
    else:
        print("✅ No suspicious processes found.")
