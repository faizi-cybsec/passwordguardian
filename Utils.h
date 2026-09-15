/*
    ============================================================
    UTILS.H
    ============================================================
    Shared helper functions used across the whole program:
      - Console colors (ANSI escape codes)
      - Simple display helpers (titles, rows, checklists, bars)
      - Loading animation
      - A library of random cybersecurity facts

    These were originally written directly inside main.cpp in the
    first version of Password Guardian. They have been moved into
    their own file so the project is easier to navigate, but the
    functions themselves work exactly the same way as before.
    ============================================================
*/

#pragma once

#include <string>
#include <vector>

// ---- Console colors (ANSI escape codes) ----
// These are declared here with "extern" and defined once inside
// Utils.cpp. That way every file that includes Utils.h can use
// COLOR_RED, COLOR_GREEN, etc. without redefining them.
extern const std::string COLOR_RESET;
extern const std::string COLOR_GREEN;
extern const std::string COLOR_YELLOW;
extern const std::string COLOR_RED;
extern const std::string COLOR_BLUE;
extern const std::string COLOR_CYAN;
extern const std::string COLOR_WHITE;
extern const std::string COLOR_MAGENTA;

// A full-width separator line, reused everywhere for a consistent look
extern const std::string LINE;

// ---- Basic display helpers (same behaviour as the original project) ----
void printLine();
void printTitle(const std::string &title);
void printRow(const std::string &label, const std::string &value);
void printSection(const std::string &label);
void printCheckRow(bool passed, const std::string &label);
void pauseScreen();
void showLoadingStep(const std::string &message);

// Turns a true/false result into "YES" / "NO" text
std::string yesNo(bool value);

// Builds a labeled ASCII progress bar, e.g.
//   Entropy         [##########------] 62%
// "value" and "maxValue" describe how full the bar should be.
std::string buildProgressBar(const std::string &label, int value, int maxValue);

// Picks a color based on a 0-100 style score
// (used for security score, entropy score, complexity score, etc.)
std::string getScoreColor(int score);

// Returns one random cybersecurity fact from an internal list of
// at least 50 facts. Used to show a "did you know?" tip after
// every password analysis.
std::string getRandomSecurityFact();

// Returns the current date as a text string, e.g. "2026-07-24"
std::string getCurrentDateString();

// Returns the current time as a text string, e.g. "14:35:02"
std::string getCurrentTimeString();
