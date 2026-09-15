/*
    ============================================================
    PASSWORDANALYZER.H
    ============================================================
    This is the upgraded brain of Password Guardian Pro.

    The original project only checked 4 things (uppercase,
    lowercase, digits, special characters) and gave a simple
    score out of 100. This version keeps those same basic checks
    (they are still used below) but adds many more pattern
    checks, a smarter weighted score, a letter grade, a threat
    level, and an "AI explanation engine" that tells the user
    WHY their password is weak or strong instead of just saying
    "Strong" or "Weak".

    Everything here is still plain, beginner-friendly C++:
    simple loops, simple string comparisons, no regex, no
    advanced templates.
    ============================================================
*/

#pragma once

#include <string>
#include <vector>

// ----------------------------------------------------------------
// PasswordAnalysis
// ----------------------------------------------------------------
// Holds every single check the analyzer performs on one password.
// This struct is filled in by analyzePassword() and then used by
// the scoring, explanation, and recommendation functions below.
struct PasswordAnalysis
{
    std::string password;

    // ---- Basic counts (same idea as the original project) ----
    int length = 0;
    int upperCount = 0;
    int lowerCount = 0;
    int digitCount = 0;
    int specialCount = 0;
    int uniqueCount = 0;
    double diversityPercent = 0.0; // unique characters / length * 100

    // ---- Weakness / pattern flags (new in Pro version) ----
    bool isDictionaryWord = false;
    bool isCommonPassword = false;
    bool hasKeyboardPattern = false;
    bool hasRepeatedChars = false;       // e.g. "aaa"
    bool hasRepeatedWords = false;       // e.g. "abcabc"
    bool hasSequentialLetters = false;   // e.g. "abc"
    bool hasSequentialNumbers = false;   // e.g. "123"
    bool hasAscendingPattern = false;    // any 3+ chars rising by 1 in ASCII
    bool hasDescendingPattern = false;   // any 3+ chars falling by 1 in ASCII
    bool containsYear = false;           // e.g. "1998", "2024"
    bool containsName = false;           // common first names
    bool containsEmail = false;          // looks like an email address
    bool containsPhonePattern = false;   // long run of digits, phone-like
    bool containsDobPattern = false;     // date-of-birth style digit pattern
    bool containsSpaces = false;
    bool containsUnicode = false;        // any byte outside normal ASCII
    bool hasConsecutiveRepeatedSymbols = false; // e.g. "!!!" or "###"
    bool hasPredictableSubstitution = false;    // e.g. "P@ssw0rd"
    bool hasWeakSuffix = false;          // e.g. ends with "123", "!", "01"
    bool hasWeakPrefix = false;          // e.g. starts with "admin", "test"
};

// ---- Simple character-class checks (kept from the original project) ----
bool hasUppercase(const std::string &password);
bool hasLowercase(const std::string &password);
bool hasDigit(const std::string &password);
bool hasSpecialChar(const std::string &password);

// Runs every check above and returns a fully filled PasswordAnalysis
PasswordAnalysis analyzePassword(const std::string &password);

// ---- Scoring, grading and threat level ----
// Builds a weighted score out of 100 using length, entropy,
// character diversity, predictability, dictionary/common password
// detection and pattern detection.
int calculateSecurityScore(const PasswordAnalysis &analysis, double entropyBits);

// Converts a 0-100 score into a letter grade: A+, A, B, C, D, F
std::string getSecurityGrade(int score);

// Converts a 0-100 score into a threat level:
// SAFE, LOW, MEDIUM, HIGH, CRITICAL
std::string getThreatLevel(int score);

// Returns the correct color for a given threat level
std::string getThreatLevelColor(const std::string &threatLevel);

// ---- AI Explanation Engine ----
// Explains WHY the password scored the way it did, instead of
// just giving a single word like "Strong" or "Weak".
std::vector<std::string> generateExplanations(const PasswordAnalysis &analysis);

// ---- AI Recommendations ----
// Generates a list of specific, actionable improvement tips.
std::vector<std::string> generateRecommendations(const PasswordAnalysis &analysis);

// Prints the full "Password Security Dashboard" for one analysis.
// This ties together PasswordAnalyzer, Entropy and the explanation
// engine into the professional report the user asked for.
void printPasswordDashboard(const PasswordAnalysis &analysis);
