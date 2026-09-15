# Password Guardian Pro
### AI Password Security Analyzer

Programming Fundamentals Course Project
Department: BS Cyber Security
Developer: Faizan Ahmed
University: Superior University

Password Guardian Pro is the upgraded, professional version of the original
Password Guardian tool. Every original feature has been preserved (password
strength analysis, the hand-written SHA-1 implementation, the Have I Been
Pwned breach check, the password generator, the ANSI-colored console, the
report generator and the loading animations) and extended into a full
password security suite.

## Features

- **Password Strength Analyzer** — length, character classes, unique
  character count and diversity, dictionary words, common passwords,
  keyboard patterns, repeated characters/words, sequential letters/numbers,
  ascending/descending patterns, years, names, emails, phone-number-like
  digit runs, date-of-birth-like digit runs, spaces, unicode characters,
  consecutive repeated symbols, predictable leet-speak substitutions, and
  weak prefixes/suffixes.
- **Entropy Engine** — entropy in bits, complexity label, search space, and
  a plain-English explanation of what entropy means.
- **Crack Time Estimation** — online, offline, GPU, dictionary, hybrid and
  brute-force attack estimates, formatted from seconds up to millions of
  years.
- **Weighted Security Score (0–100)** with letter grades A+ through F.
- **Threat Level** — SAFE / LOW / MEDIUM / HIGH / CRITICAL, color-coded.
- **AI Explanation Engine** — explains *why* a password scored the way it
  did instead of just labeling it.
- **AI Recommendations** — specific, actionable improvement tips.
- **Password Security Dashboard** — a single professional report combining
  every module above, with animated ASCII progress bars.
- **Upgraded Password Generator** — Easy / Medium / Strong / Military /
  Custom levels, selectable lengths (8/12/16/20/24/32), toggleable
  character types, an "avoid ambiguous characters" option, and multi-
  password generation.
- **Password Comparison** — score, entropy and crack-time comparison
  between two passwords, with a declared winner.
- **Password Policy Checker** — define a minimum length and required
  character types; get a PASS/FAIL result.
- **Attack Simulator (educational only)** — a visual, non-functional
  simulation of dictionary, hybrid, rainbow-table and brute-force attacks,
  paired with real crack-time estimates. It never performs an actual
  attack.
- **Security Facts** — 50+ built-in cybersecurity facts, one shown after
  each analysis.
- **Improved HIBP Breach Check** — same k-Anonymity approach as before
  (only the first 5 hash characters are ever sent), now with a privacy
  explanation, connection status, occurrence count and risk explanation.
- **Report Generator** — exports a full text report to `reports/`.
- **History** — stores the last 20 analyses in memory (passwords are
  masked, never stored in full) with view/delete options.

## Project Structure

```
PasswordGuardianPro/
├── main.cpp                   Menu, banner, startup screen, program entry
├── Utils.h / Utils.cpp        Colors, display helpers, security facts
├── PasswordAnalyzer.h/.cpp    Pattern analysis, scoring, AI explanations
├── Entropy.h / Entropy.cpp    Entropy math and crack-time estimation
├── HIBP.h / HIBP.cpp          SHA-1 implementation + breach checking
├── PasswordGenerator.h/.cpp   Upgraded password generator
├── AttackSimulator.h/.cpp     Educational (non-real) attack simulation
├── History.h / History.cpp    In-memory session history
├── Report.h / Report.cpp      Text report export
├── reports/                   Generated report files are saved here
├── PasswordGuardianPro.sln
└── PasswordGuardianPro.vcxproj / .vcxproj.filters
```

## Requirements

- Windows 10+ recommended (for native ANSI color support)
- Visual Studio 2022 with the "Desktop development with C++" workload
- MSVC compiler, C++17 language standard
- `curl` available on the PATH (used only for the Have I Been Pwned check;
  every other feature works fully offline)

## Building in Visual Studio 2022

1. Open `PasswordGuardianPro.sln`.
2. Confirm **C++ Language Standard** is set to `/std:c++17` (already
   configured in the provided `.vcxproj`).
3. Build with **Build → Build Solution** (`Ctrl+Shift+B`).
4. Run with **F5** (Debug) or **Ctrl+F5** (Run without debugging), from the
   project root so the relative `reports/` folder resolves correctly.

## Building from the command line

**g++ (MinGW or any POSIX system):**
```bash
g++ -std=c++17 -Wall -Wextra main.cpp PasswordAnalyzer.cpp Entropy.cpp \
    HIBP.cpp PasswordGenerator.cpp AttackSimulator.cpp History.cpp \
    Report.cpp Utils.cpp -o PasswordGuardianPro
```

**MSVC (Developer Command Prompt):**
```bat
cl /std:c++17 /EHsc main.cpp PasswordAnalyzer.cpp Entropy.cpp HIBP.cpp ^
   PasswordGenerator.cpp AttackSimulator.cpp History.cpp Report.cpp Utils.cpp ^
   /Fe:PasswordGuardianPro.exe
```

## Notes

- The Have I Been Pwned check requires an internet connection and `curl`.
  Every other menu option works completely offline.
- History is kept in memory only for the current session and stores masked
  passwords, never the full plaintext, to keep the tool privacy-conscious.
- The Attack Simulator never performs a real attack against any system —
  it only visualizes the concept and shows realistic time estimates
  calculated from entropy.
