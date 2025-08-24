🛡️ Keylogger Detection Tool (Python) 

This repository contains a simple Keylogger Detection Tool built in Python.
It scans running processes, checks for suspicious behaviors, and generates a risk score to help identify potential keyloggers.

🔧 Features

Scans all currently running processes

Flags suspicious ones based on keywords, memory usage, or unusual behavior

Assigns a risk score (Low / Medium / High)

Reports results in a clean and readable format

Lightweight and runs on any machine with Python installed

📂 Versions
1. Basic Detection Script (First Version)

Straightforward implementation

Prints suspicious processes with names, PIDs, and scores

Used simple ASCII output (no emojis)

Suitable for environments where Unicode characters may not render correctly

Example Output:

=== Keylogger Detection Report ===
SuspiciousProcess.exe (PID 1452) | Risk: HIGH | Score: 85

2. Enhanced Detection Script (Modified Version)

Improved readability with Unicode warnings and icons (⚠️)

Color-coded and more user-friendly output

Added better error handling for Windows terminals (with encoding fixes)

Cleaner, more polished output

Example Output:

=== Keylogger Detection Report ===
⚠️ Code.exe (PID 1448) | Risk: MEDIUM | Score: 50

🚀 How to Run

Clone this repo:

git clone https://github.com/yourusername/keylogger-detector.git
cd keylogger-detector


Run the script:

python detector.py


⚠️ Note:

No external packages are required — works with standard Python libraries.

On some Windows terminals, emojis may not render properly. In that case, use the first version.

📌 Use Cases

Demonstrating simple malware/keylogger detection logic for educational purposes

Practicing Python process monitoring and security basics

A base for further development into a more advanced security tool

⚠️ Disclaimer

This tool is for educational purposes only.
It is not a replacement for professional antivirus or endpoint security solutions.
Always use trusted software to protect your system.
