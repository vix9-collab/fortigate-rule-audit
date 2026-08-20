# Building Standalone Binaries (Windows & macOS)

PyInstaller cannot cross-compile — it must run **on** the OS you're
building for. A Windows .exe has to be built on Windows; a macOS app
has to be built on a Mac. This is a one-time, ~2 minute setup per OS.

## What you need on the build machine
- Python 3.8+ installed (one-time, only on the machine doing the build —
  not needed by whoever runs the final tool)
- The three script files: `fw_parser.py`, `fw_audit.py`, `firewall_rule_audit.py`

## Windows

1. Install Python from python.org (check "Add to PATH" during install).
2. Open Command Prompt in the folder with the three .py files.
3. Run:
   ```
   pip install pyinstaller
   pyinstaller --onefile --name firewall_rule_audit firewall_rule_audit.py
   ```
4. Output: `dist\firewall_rule_audit.exe`

**Expect a SmartScreen warning** ("Windows protected your PC") the first
time it's run on another machine — unsigned .exe. Fix: click "More info"
-> "Run anyway". One-time per machine. An EV code-signing certificate
removes this warning entirely, worth it once this goes to more than a
handful of engineers.

## macOS

1. Python 3 ships with macOS, or install via `brew install python3`.
2. Open Terminal in the folder with the three .py files.
3. Run:
   ```
   pip3 install pyinstaller
   pyinstaller --onefile --name firewall_rule_audit firewall_rule_audit.py
   ```
4. Output: `dist/firewall_rule_audit`

**Expect a Gatekeeper warning** ("cannot be opened because the developer
cannot be verified") on other Macs. Fix: right-click the binary -> Open
-> Open (one-time per machine). An Apple Developer ID certificate
($99/year) lets you notarize the binary so this warning doesn't appear.

## Running it (both platforms, once built)

```
firewall_rule_audit --current current_running.conf --baseline baseline_approved.conf --out report.txt --csv worklist.csv
```

Same flags on both platforms — this is a CLI tool, no GUI. On Windows,
run it from Command Prompt or PowerShell; on macOS, from Terminal.

## Testing before you ship

Test the compiled binary against the sample configs included
(`samples/current_running.conf` and `samples/baseline_approved.conf`)
before pointing it at a real production config — confirms the build
worked correctly on that machine.
