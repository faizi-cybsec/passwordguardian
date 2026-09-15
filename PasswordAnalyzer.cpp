/*
    ============================================================
    PASSWORDANALYZER.CPP
    ============================================================
    See PasswordAnalyzer.h for an overview. This file is split
    into clearly labeled sections so it stays easy to follow even
    though it checks for many different weaknesses.
    ============================================================
*/

#include "PasswordAnalyzer.h"
#include "Entropy.h"
#include "Utils.h"
#include <iostream>
#include <cctype>

using namespace std;

// ==============================================================
// SECTION 1: BASIC CHARACTER-CLASS CHECKS (kept from original)
// ==============================================================

// Checks if the password contains at least one uppercase letter
bool hasUppercase(const string &password)
{
    for (size_t i = 0; i < password.size(); i++)
    {
        if (password[i] >= 'A' && password[i] <= 'Z')
        {
            return true;
        }
    }
    return false;
}

// Checks if the password contains at least one lowercase letter
bool hasLowercase(const string &password)
{
    for (size_t i = 0; i < password.size(); i++)
    {
        if (password[i] >= 'a' && password[i] <= 'z')
        {
            return true;
        }
    }
    return false;
}

// Checks if the password contains at least one digit
bool hasDigit(const string &password)
{
    for (size_t i = 0; i < password.size(); i++)
    {
        if (password[i] >= '0' && password[i] <= '9')
        {
            return true;
        }
    }
    return false;
}

// Checks if the password contains at least one special character
bool hasSpecialChar(const string &password)
{
    string specialChars = "!@#$%^&*()-_=+[]{};:,.<>?/|~";

    for (size_t i = 0; i < password.size(); i++)
    {
        for (size_t j = 0; j < specialChars.size(); j++)
        {
            if (password[i] == specialChars[j])
            {
                return true;
            }
        }
    }
    return false;
}

// ==============================================================
// SECTION 2: WORD LISTS USED BY THE PATTERN CHECKS
// ==============================================================
// These are small, fixed arrays (no external files or libraries)
// used to detect dictionary words, common passwords, keyboard
// patterns, common names, weak prefixes and weak suffixes.

static const string COMMON_PASSWORDS[] = {
    "password", "123456", "123456789", "qwerty", "abc123", "password1",
    "iloveyou", "admin", "welcome", "letmein", "monkey", "football",
    "dragon", "master", "login", "princess", "solo", "starwars",
    "trustno1", "sunshine", "shadow", "michael", "superman", "batman",
    "password123", "1q2w3e4r", "passw0rd", "hello", "freedom", "whatever"
};
static const int COMMON_PASSWORD_COUNT = sizeof(COMMON_PASSWORDS) / sizeof(COMMON_PASSWORDS[0]);

static const string DICTIONARY_WORDS[] = {
    "password", "welcome", "dragon", "monkey", "football", "baseball",
    "master", "shadow", "sunshine", "princess", "login", "admin",
    "letmein", "freedom", "trustno", "whatever", "starwars", "superman",
    "batman", "hello", "computer", "internet", "security", "system",
    "summer", "winter", "spring", "autumn", "iloveyou", "flower"
};
static const int DICTIONARY_WORD_COUNT = sizeof(DICTIONARY_WORDS) / sizeof(DICTIONARY_WORDS[0]);

static const string KEYBOARD_PATTERNS[] = {
    "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1qaz2wsx", "poiuyt",
    "lkjhgf", "mnbvcx", "1234567890", "0987654321"
};
static const int KEYBOARD_PATTERN_COUNT = sizeof(KEYBOARD_PATTERNS) / sizeof(KEYBOARD_PATTERNS[0]);

static const string COMMON_NAMES[] = {
    "james", "john", "robert", "michael", "david", "william",
    "mary", "patricia", "jennifer", "linda", "elizabeth", "susan",
    "ahmed", "ali", "hassan", "hussain", "usman", "bilal", "faizan",
    "sara", "ayesha", "fatima", "zainab", "hamza", "omar", "khan"
};
static const int COMMON_NAME_COUNT = sizeof(COMMON_NAMES) / sizeof(COMMON_NAMES[0]);

static const string WEAK_SUFFIXES[] = {
    "123", "1234", "12345", "01", "001", "007", "69", "99", "!",
    "!!", "!!!", "2020", "2021", "2022", "2023", "2024", "2025"
};
static const int WEAK_SUFFIX_COUNT = sizeof(WEAK_SUFFIXES) / sizeof(WEAK_SUFFIXES[0]);

static const string WEAK_PREFIXES[] = {
    "admin", "test", "user", "login", "pass", "root", "guest", "welcome"
};
static const int WEAK_PREFIX_COUNT = sizeof(WEAK_PREFIXES) / sizeof(WEAK_PREFIXES[0]);

// Converts a string to lowercase using a simple loop (no <algorithm>)
static string toLowerText(const string &text)
{
    string result = text;
    for (size_t i = 0; i < result.size(); i++)
    {
        if (result[i] >= 'A' && result[i] <= 'Z')
        {
            result[i] = (char)(result[i] - 'A' + 'a');
        }
    }
    return result;
}

// Returns true if "text" contains "word" anywhere inside it
static bool containsSubstring(const string &text, const string &word)
{
    return text.find(word) != string::npos;
}

// ==============================================================
// SECTION 3: INDIVIDUAL PATTERN CHECKS
// ==============================================================

// Counts how many different (unique) characters appear in the password
static int countUniqueCharacters(const string &password)
{
    bool seen[256] = { false };
    int uniqueCount = 0;

    for (size_t i = 0; i < password.size(); i++)
    {
        unsigned char ch = (unsigned char)password[i];
        if (!seen[ch])
        {
            seen[ch] = true;
            uniqueCount++;
        }
    }
    return uniqueCount;
}

// Checks if the password (in lowercase) exactly matches a known
// common password from our list
static bool checkCommonPassword(const string &lowerPassword)
{
    for (int i = 0; i < COMMON_PASSWORD_COUNT; i++)
    {
        if (lowerPassword == COMMON_PASSWORDS[i])
        {
            return true;
        }
    }
    return false;
}

// Checks if the password contains a known dictionary word anywhere inside it
static bool checkDictionaryWord(const string &lowerPassword)
{
    for (int i = 0; i < DICTIONARY_WORD_COUNT; i++)
    {
        if (containsSubstring(lowerPassword, DICTIONARY_WORDS[i]))
        {
            return true;
        }
    }
    return false;
}

// Checks if the password contains a common keyboard-walk pattern
static bool checkKeyboardPattern(const string &lowerPassword)
{
    for (int i = 0; i < KEYBOARD_PATTERN_COUNT; i++)
    {
        if (containsSubstring(lowerPassword, KEYBOARD_PATTERNS[i]))
        {
            return true;
        }
    }
    return false;
}

// Checks if the password contains a common first name
static bool checkContainsName(const string &lowerPassword)
{
    for (int i = 0; i < COMMON_NAME_COUNT; i++)
    {
        if (containsSubstring(lowerPassword, COMMON_NAMES[i]))
        {
            return true;
        }
    }
    return false;
}

// Checks if the password ends with a known weak suffix
static bool checkWeakSuffix(const string &lowerPassword)
{
    for (int i = 0; i < WEAK_SUFFIX_COUNT; i++)
    {
        const string &suffix = WEAK_SUFFIXES[i];
        if (lowerPassword.size() >= suffix.size())
        {
            string ending = lowerPassword.substr(lowerPassword.size() - suffix.size());
            if (ending == suffix)
            {
                return true;
            }
        }
    }
    return false;
}

// Checks if the password starts with a known weak prefix
static bool checkWeakPrefix(const string &lowerPassword)
{
    for (int i = 0; i < WEAK_PREFIX_COUNT; i++)
    {
        const string &prefix = WEAK_PREFIXES[i];
        if (lowerPassword.size() >= prefix.size())
        {
            string beginning = lowerPassword.substr(0, prefix.size());
            if (beginning == prefix)
            {
                return true;
            }
        }
    }
    return false;
}

// Checks for 3 or more of the SAME character in a row, e.g. "aaa" or "111"
static bool checkRepeatedChars(const string &password)
{
    int runLength = 1;
    for (size_t i = 1; i < password.size(); i++)
    {
        if (password[i] == password[i - 1])
        {
            runLength++;
            if (runLength >= 3)
            {
                return true;
            }
        }
        else
        {
            runLength = 1;
        }
    }
    return false;
}

// Checks for 3 or more of the SAME special/symbol character in a row,
// e.g. "!!!" or "###". This is a stricter version of checkRepeatedChars
// that only looks at special characters, so it can be reported separately.
static bool checkConsecutiveRepeatedSymbols(const string &password)
{
    string specialChars = "!@#$%^&*()-_=+[]{};:,.<>?/|~";
    int runLength = 1;

    for (size_t i = 1; i < password.size(); i++)
    {
        bool isSpecial = specialChars.find(password[i]) != string::npos;

        if (isSpecial && password[i] == password[i - 1])
        {
            runLength++;
            if (runLength >= 3)
            {
                return true;
            }
        }
        else
        {
            runLength = 1;
        }
    }
    return false;
}

// Checks if a repeated "word" (any substring of length 3+) appears
// twice inside the password, e.g. "abcabc" or "sunsun123"
static bool checkRepeatedWords(const string &lowerPassword)
{
    int length = (int)lowerPassword.size();

    // Try every possible chunk length from 3 up to half the password
    for (int chunkLength = 3; chunkLength <= length / 2; chunkLength++)
    {
        // Try every starting position for the first chunk
        for (int start = 0; start + (chunkLength * 2) <= length; start++)
        {
            string firstChunk = lowerPassword.substr(start, chunkLength);
            string restOfPassword = lowerPassword.substr(start + chunkLength);

            if (containsSubstring(restOfPassword, firstChunk))
            {
                return true;
            }
        }
    }
    return false;
}

// Checks for 3+ letters in a row that go up the alphabet, e.g. "abc"
static bool checkSequentialLetters(const string &password)
{
    string lower = toLowerText(password);

    for (size_t i = 0; i + 2 < lower.size(); i++)
    {
        char a = lower[i];
        char b = lower[i + 1];
        char c = lower[i + 2];

        bool allLetters = (a >= 'a' && a <= 'z') && (b >= 'a' && b <= 'z') && (c >= 'a' && c <= 'z');

        if (allLetters && (b == a + 1) && (c == b + 1))
        {
            return true;
        }
    }
    return false;
}

// Checks for 3+ digits in a row that go up in value, e.g. "123"
static bool checkSequentialNumbers(const string &password)
{
    for (size_t i = 0; i + 2 < password.size(); i++)
    {
        char a = password[i];
        char b = password[i + 1];
        char c = password[i + 2];

        bool allDigits = (a >= '0' && a <= '9') && (b >= '0' && b <= '9') && (c >= '0' && c <= '9');

        if (allDigits && (b == a + 1) && (c == b + 1))
        {
            return true;
        }
    }
    return false;
}

// General ascending pattern check: any 3+ characters (of any kind)
// whose character codes increase by exactly 1 each step, e.g. "efg" or ")*+"
static bool checkAscendingPattern(const string &password)
{
    for (size_t i = 0; i + 2 < password.size(); i++)
    {
        unsigned char a = (unsigned char)password[i];
        unsigned char b = (unsigned char)password[i + 1];
        unsigned char c = (unsigned char)password[i + 2];

        if (b == a + 1 && c == b + 1)
        {
            return true;
        }
    }
    return false;
}

// General descending pattern check: any 3+ characters (of any kind)
// whose character codes decrease by exactly 1 each step, e.g. "cba"
static bool checkDescendingPattern(const string &password)
{
    for (size_t i = 0; i + 2 < password.size(); i++)
    {
        unsigned char a = (unsigned char)password[i];
        unsigned char b = (unsigned char)password[i + 1];
        unsigned char c = (unsigned char)password[i + 2];

        if (b == a - 1 && c == b - 1)
        {
            return true;
        }
    }
    return false;
}

// Looks for any 4-digit run that forms a plausible year (1990-2035)
static bool checkContainsYear(const string &password)
{
    for (size_t i = 0; i + 3 < password.size(); i++)
    {
        bool allDigits = true;
        for (int j = 0; j < 4; j++)
        {
            if (password[i + j] < '0' || password[i + j] > '9')
            {
                allDigits = false;
                break;
            }
        }

        if (allDigits)
        {
            int year = (password[i] - '0') * 1000 +
                       (password[i + 1] - '0') * 100 +
                       (password[i + 2] - '0') * 10 +
                       (password[i + 3] - '0');

            if (year >= 1990 && year <= 2035)
            {
                return true;
            }
        }
    }
    return false;
}

// Looks for a simple email pattern: something, then '@', then
// something, then '.', then at least 2 more characters
static bool checkContainsEmail(const string &password)
{
    size_t atPosition = password.find('@');
    if (atPosition == string::npos || atPosition == 0)
    {
        return false;
    }

    size_t dotPosition = password.find('.', atPosition);
    if (dotPosition == string::npos)
    {
        return false;
    }

    // Need at least 1 character between '@' and '.', and at least
    // 2 characters after the '.'
    bool hasDomainName = (dotPosition - atPosition) >= 2;
    bool hasDomainSuffix = (password.size() - dotPosition) >= 3;

    return hasDomainName && hasDomainSuffix;
}

// Finds the longest run of consecutive digits in the password
// (ignoring common separators like '-' and ' ') and returns its length
static int longestDigitRun(const string &password)
{
    int longest = 0;
    int current = 0;

    for (size_t i = 0; i < password.size(); i++)
    {
        char ch = password[i];

        if (ch >= '0' && ch <= '9')
        {
            current++;
            if (current > longest)
            {
                longest = current;
            }
        }
        else if (ch == '-' || ch == ' ' || ch == '.')
        {
            // Separators do not break the run, but do not count either
        }
        else
        {
            current = 0;
        }
    }
    return longest;
}

// A phone-number-like pattern is a long run of digits (7 or more),
// which is a common thing people (unwisely) put in passwords
static bool checkContainsPhonePattern(const string &password)
{
    return longestDigitRun(password) >= 7;
}

// A date-of-birth style pattern is a run of exactly 6 or 8 digits,
// which matches common date formats like DDMMYY or DDMMYYYY
static bool checkContainsDobPattern(const string &password)
{
    int longest = longestDigitRun(password);
    return (longest == 6 || longest == 8);
}

// Checks for any whitespace character in the password
static bool checkContainsSpaces(const string &password)
{
    for (size_t i = 0; i < password.size(); i++)
    {
        if (password[i] == ' ')
        {
            return true;
        }
    }
    return false;
}

// Checks for any byte with the high bit set, which normally means
// the password contains a multi-byte UTF-8 (unicode) character
static bool checkContainsUnicode(const string &password)
{
    for (size_t i = 0; i < password.size(); i++)
    {
        unsigned char ch = (unsigned char)password[i];
        if (ch > 127)
        {
            return true;
        }
    }
    return false;
}

// Replaces common "leet speak" substitutions with their original
// letter, e.g. '@' -> 'a', '0' -> 'o', '3' -> 'e'. This lets us
// detect passwords like "P@ssw0rd" as predictable dictionary words
// in disguise.
static string undoLeetSubstitutions(const string &password)
{
    string result = password;

    for (size_t i = 0; i < result.size(); i++)
    {
        switch (result[i])
        {
            case '@': result[i] = 'a'; break;
            case '4': result[i] = 'a'; break;
            case '0': result[i] = 'o'; break;
            case '1': result[i] = 'i'; break;
            case '3': result[i] = 'e'; break;
            case '5': result[i] = 's'; break;
            case '$': result[i] = 's'; break;
            case '7': result[i] = 't'; break;
            default: break; // leave the character unchanged
        }
    }
    return result;
}

// Detects predictable substitutions: if the password is NOT already
// a plain dictionary word, but becomes one after undoing common
// leet-speak substitutions, it is still considered predictable.
static bool checkPredictableSubstitution(const string &lowerPassword, bool alreadyDictionaryWord)
{
    if (alreadyDictionaryWord)
    {
        // It was already caught as a plain dictionary word;
        // no need to flag it twice for the same underlying reason.
        return false;
    }

    string unsubstituted = toLowerText(undoLeetSubstitutions(lowerPassword));
    return checkDictionaryWord(unsubstituted) || checkCommonPassword(unsubstituted);
}

// ==============================================================
// SECTION 4: MAIN ANALYSIS FUNCTION
// ==============================================================

PasswordAnalysis analyzePassword(const string &password)
{
    PasswordAnalysis analysis;
    analysis.password = password;

    string lowerPassword = toLowerText(password);

    // ---- Basic counts ----
    analysis.length = (int)password.size();

    for (size_t i = 0; i < password.size(); i++)
    {
        char ch = password[i];
        if (ch >= 'A' && ch <= 'Z') analysis.upperCount++;
        else if (ch >= 'a' && ch <= 'z') analysis.lowerCount++;
        else if (ch >= '0' && ch <= '9') analysis.digitCount++;
        else if (ch != ' ') analysis.specialCount++;
    }

    analysis.uniqueCount = countUniqueCharacters(password);
    if (analysis.length > 0)
    {
        analysis.diversityPercent = ((double)analysis.uniqueCount / (double)analysis.length) * 100.0;
    }

    // ---- Pattern checks ----
    analysis.isCommonPassword = checkCommonPassword(lowerPassword);
    analysis.isDictionaryWord = checkDictionaryWord(lowerPassword);
    analysis.hasKeyboardPattern = checkKeyboardPattern(lowerPassword);
    analysis.hasRepeatedChars = checkRepeatedChars(password);
    analysis.hasRepeatedWords = checkRepeatedWords(lowerPassword);
    analysis.hasSequentialLetters = checkSequentialLetters(password);
    analysis.hasSequentialNumbers = checkSequentialNumbers(password);
    analysis.hasAscendingPattern = checkAscendingPattern(password);
    analysis.hasDescendingPattern = checkDescendingPattern(password);
    analysis.containsYear = checkContainsYear(password);
    analysis.containsName = checkContainsName(lowerPassword);
    analysis.containsEmail = checkContainsEmail(password);
    analysis.containsPhonePattern = checkContainsPhonePattern(password);
    analysis.containsDobPattern = checkContainsDobPattern(password);
    analysis.containsSpaces = checkContainsSpaces(password);
    analysis.containsUnicode = checkContainsUnicode(password);
    analysis.hasConsecutiveRepeatedSymbols = checkConsecutiveRepeatedSymbols(password);
    analysis.hasPredictableSubstitution = checkPredictableSubstitution(lowerPassword, analysis.isDictionaryWord);
    analysis.hasWeakSuffix = checkWeakSuffix(lowerPassword);
    analysis.hasWeakPrefix = checkWeakPrefix(lowerPassword);

    return analysis;
}

// ==============================================================
// SECTION 5: SCORING, GRADING AND THREAT LEVEL
// ==============================================================

int calculateSecurityScore(const PasswordAnalysis &analysis, double entropyBits)
{
    double score = 0.0;

    // ---- Length: up to 20 points ----
    if (analysis.length >= 8)  score += 8.0;
    if (analysis.length >= 12) score += 6.0;
    if (analysis.length >= 16) score += 6.0;

    // ---- Character diversity: up to 15 points ----
    score += (analysis.diversityPercent / 100.0) * 15.0;

    // ---- Character class variety: up to 20 points (5 each) ----
    if (analysis.upperCount > 0)   score += 5.0;
    if (analysis.lowerCount > 0)   score += 5.0;
    if (analysis.digitCount > 0)   score += 5.0;
    if (analysis.specialCount > 0) score += 5.0;

    // ---- Entropy: up to 25 points ----
    double entropyPoints = entropyBits / 3.2; // roughly caps near 80 bits
    if (entropyPoints > 25.0) entropyPoints = 25.0;
    score += entropyPoints;

    // ---- Reuse / predictability penalties ----
    if (analysis.isCommonPassword) score -= 40.0;
    if (analysis.isDictionaryWord) score -= 20.0;
    if (analysis.hasPredictableSubstitution) score -= 10.0;
    if (analysis.hasKeyboardPattern) score -= 15.0;
    if (analysis.hasRepeatedChars) score -= 8.0;
    if (analysis.hasRepeatedWords) score -= 8.0;
    if (analysis.hasSequentialLetters) score -= 8.0;
    if (analysis.hasSequentialNumbers) score -= 8.0;
    if (analysis.hasConsecutiveRepeatedSymbols) score -= 5.0;
    if (analysis.containsYear) score -= 5.0;
    if (analysis.containsName) score -= 8.0;
    if (analysis.containsEmail) score -= 10.0;
    if (analysis.containsPhonePattern) score -= 8.0;
    if (analysis.containsDobPattern) score -= 8.0;
    if (analysis.hasWeakSuffix) score -= 5.0;
    if (analysis.hasWeakPrefix) score -= 5.0;
    if (analysis.length < 8) score -= 15.0;

    // ---- Clamp the final score between 0 and 100 ----
    if (score < 0.0) score = 0.0;
    if (score > 100.0) score = 100.0;

    return (int)(score + 0.5); // round to nearest whole number
}

string getSecurityGrade(int score)
{
    if (score >= 95) return "A+";
    if (score >= 85) return "A";
    if (score >= 70) return "B";
    if (score >= 55) return "C";
    if (score >= 40) return "D";
    return "F";
}

string getThreatLevel(int score)
{
    if (score >= 85) return "SAFE";
    if (score >= 70) return "LOW";
    if (score >= 50) return "MEDIUM";
    if (score >= 30) return "HIGH";
    return "CRITICAL";
}

string getThreatLevelColor(const string &threatLevel)
{
    if (threatLevel == "SAFE")     return COLOR_GREEN;
    if (threatLevel == "LOW")      return COLOR_CYAN;
    if (threatLevel == "MEDIUM")   return COLOR_YELLOW;
    if (threatLevel == "HIGH")     return COLOR_RED;
    return COLOR_RED; // CRITICAL
}

// ==============================================================
// SECTION 6: AI EXPLANATION ENGINE
// ==============================================================

vector<string> generateExplanations(const PasswordAnalysis &analysis)
{
    vector<string> explanations;

    if (analysis.isCommonPassword)
    {
        explanations.push_back("This exact password appears on well-known lists of the most common passwords.");
    }
    if (analysis.isDictionaryWord)
    {
        explanations.push_back("It contains a plain dictionary word, which dictionary attacks try first.");
    }
    if (analysis.hasPredictableSubstitution)
    {
        explanations.push_back("It uses predictable substitutions (like '@' for 'a' or '0' for 'o') on a dictionary word - crackers check these automatically.");
    }
    if (analysis.hasKeyboardPattern)
    {
        explanations.push_back("It contains a keyboard-walk pattern (like \"qwerty\"), which is one of the first things attackers try.");
    }
    if (analysis.hasRepeatedChars)
    {
        explanations.push_back("It repeats the same character 3 or more times in a row, which lowers unpredictability.");
    }
    if (analysis.hasRepeatedWords)
    {
        explanations.push_back("It repeats the same chunk of text twice (e.g. \"abcabc\"), a very guessable pattern.");
    }
    if (analysis.hasSequentialLetters)
    {
        explanations.push_back("It contains sequential letters (like \"abc\"), which are easy to guess.");
    }
    if (analysis.hasSequentialNumbers)
    {
        explanations.push_back("It contains sequential numbers (like \"123\"), which are easy to guess.");
    }
    if (analysis.containsYear)
    {
        explanations.push_back("It contains what looks like a year, which attackers routinely test (birth years, current years, etc.).");
    }
    if (analysis.containsName)
    {
        explanations.push_back("It appears to contain a common first name, which is frequently guessed or found through social engineering.");
    }
    if (analysis.containsEmail)
    {
        explanations.push_back("It looks like it contains an email address, which should never be part of a password.");
    }
    if (analysis.containsPhonePattern)
    {
        explanations.push_back("It contains a long run of digits resembling a phone number, which is easy to research about a specific person.");
    }
    if (analysis.containsDobPattern)
    {
        explanations.push_back("It contains a digit pattern resembling a date of birth, a very common (and weak) password habit.");
    }
    if (analysis.hasWeakPrefix)
    {
        explanations.push_back("It starts with a commonly used prefix (like \"admin\" or \"test\"), which narrows an attacker's guesses.");
    }
    if (analysis.hasWeakSuffix)
    {
        explanations.push_back("It ends with a commonly used suffix (like \"123\" or \"!\"), a pattern attackers check automatically.");
    }
    if (analysis.containsSpaces)
    {
        explanations.push_back("It contains spaces, which some systems may not accept or may handle inconsistently.");
    }
    if (analysis.length < 8)
    {
        explanations.push_back("It is shorter than 8 characters, which dramatically reduces the total search space.");
    }
    if (analysis.diversityPercent < 60.0 && analysis.length >= 6)
    {
        explanations.push_back("Many characters repeat, so the character diversity is lower than it could be.");
    }

    if (explanations.empty())
    {
        explanations.push_back("No major weaknesses were detected. This password avoids the most common predictable patterns.");
    }

    // Always end with a short summary of why these patterns matter
    if (analysis.isCommonPassword || analysis.isDictionaryWord || analysis.hasKeyboardPattern ||
        analysis.hasSequentialLetters || analysis.hasSequentialNumbers || analysis.hasRepeatedChars)
    {
        explanations.push_back("These patterns make the password vulnerable to dictionary and hybrid attacks, which try known words and common variations before anything else.");
    }

    return explanations;
}

// ==============================================================
// SECTION 7: AI RECOMMENDATIONS
// ==============================================================

vector<string> generateRecommendations(const PasswordAnalysis &analysis)
{
    vector<string> recommendations;

    if (analysis.length < 12)
    {
        recommendations.push_back("Increase the length to at least 12 characters (16+ is even better).");
    }
    if (analysis.upperCount == 0)
    {
        recommendations.push_back("Add uppercase letters.");
    }
    if (analysis.lowerCount == 0)
    {
        recommendations.push_back("Add lowercase letters.");
    }
    if (analysis.digitCount == 0)
    {
        recommendations.push_back("Add numbers.");
    }
    if (analysis.specialCount == 0)
    {
        recommendations.push_back("Add special characters (e.g. ! @ # $ %).");
    }
    if (analysis.isDictionaryWord || analysis.isCommonPassword)
    {
        recommendations.push_back("Avoid dictionary words and known common passwords entirely.");
    }
    if (analysis.hasKeyboardPattern)
    {
        recommendations.push_back("Avoid keyboard sequences like \"qwerty\" or \"asdf\".");
    }
    if (analysis.hasSequentialLetters || analysis.hasSequentialNumbers)
    {
        recommendations.push_back("Avoid sequential patterns such as \"abc\" or \"123\".");
    }
    if (analysis.containsYear || analysis.containsDobPattern)
    {
        recommendations.push_back("Avoid using birth years or dates of birth in your password.");
    }
    if (analysis.containsName)
    {
        recommendations.push_back("Avoid using your own name or a family member's name.");
    }
    if (analysis.containsPhonePattern)
    {
        recommendations.push_back("Avoid including phone numbers or other personal digit sequences.");
    }
    if (analysis.hasPredictableSubstitution)
    {
        recommendations.push_back("Predictable substitutions (like '@' for 'a') do not add real security - use truly random characters instead.");
    }
    if (analysis.diversityPercent < 60.0)
    {
        recommendations.push_back("Try to use a wider variety of different characters instead of repeating the same ones.");
    }

    // General best-practice tips shown for every password
    recommendations.push_back("Store this password inside a reputable password manager.");
    recommendations.push_back("Never reuse this password on more than one website or service.");
    recommendations.push_back("Enable Multi-Factor Authentication (MFA) wherever it is available.");

    return recommendations;
}

// ==============================================================
// SECTION 8: PASSWORD SECURITY DASHBOARD
// ==============================================================

void printPasswordDashboard(const PasswordAnalysis &analysis)
{
    EntropyResult entropy = calculateEntropyDetails(analysis.password);
    int score = calculateSecurityScore(analysis, entropy.entropyBits);
    string grade = getSecurityGrade(score);
    string threatLevel = getThreatLevel(score);
    string threatColor = getThreatLevelColor(threatLevel);

    cout << "\n";
    printTitle("PASSWORD SECURITY DASHBOARD");

    printRow("Length", to_string(analysis.length) + " characters");
    printRow("Uppercase Letters", to_string(analysis.upperCount));
    printRow("Lowercase Letters", to_string(analysis.lowerCount));
    printRow("Numbers", to_string(analysis.digitCount));
    printRow("Special Characters", to_string(analysis.specialCount));
    printRow("Unique Characters", to_string(analysis.uniqueCount));

    cout << "------------------------------------------------------------\n";
    cout << buildProgressBar("Entropy", (int)entropy.entropyBits, 100) << "\n";
    cout << buildProgressBar("Complexity", (int)((analysis.diversityPercent))/1, 100) << "\n";
    cout << buildProgressBar("Security Score", score, 100) << "\n";
    cout << "------------------------------------------------------------\n";

    printRow("Entropy", to_string((int)entropy.entropyBits) + " bits (" + entropy.complexityLabel + ")");
    printRow("Search Space", entropy.searchSpaceText + " combinations");
    printRow("Dictionary Check", yesNo(analysis.isDictionaryWord));
    printRow("Common Password", yesNo(analysis.isCommonPassword));
    printRow("Pattern Check", (analysis.hasKeyboardPattern || analysis.hasSequentialLetters ||
                                analysis.hasSequentialNumbers || analysis.hasRepeatedChars)
                                   ? "Weak Patterns Found" : "No Obvious Patterns");

    cout << "------------------------------------------------------------\n";
    cout << "Overall Score : " << getScoreColor(score) << score << " / 100" << COLOR_RESET << "\n";
    cout << "Grade         : " << getScoreColor(score) << grade << COLOR_RESET << "\n";
    cout << "Threat Level  : " << threatColor << threatLevel << COLOR_RESET << "\n";

    // ---- Crack time estimation ----
    CrackTimeEstimates crackTimes = estimateCrackTimes(entropy.entropyBits, analysis.isDictionaryWord, analysis.isCommonPassword);

    printSection("CRACK TIME ESTIMATION");
    printRow("Online Attack", crackTimes.onlineAttack);
    printRow("Offline Attack", crackTimes.offlineAttack);
    printRow("GPU Attack", crackTimes.gpuAttack);
    printRow("Dictionary Attack", crackTimes.dictionaryAttack);
    printRow("Hybrid Attack", crackTimes.hybridAttack);
    printRow("Brute Force Attack", crackTimes.bruteForceAttack);

    // ---- Entropy explanation ----
    printSection("WHAT DOES ENTROPY MEAN?");
    cout << "  " << explainEntropy(entropy.entropyBits) << "\n";

    // ---- Checklist (kept from the original project, extended) ----
    printSection("CHECKLIST");
    printCheckRow(analysis.upperCount > 0, "Uppercase letter  (A-Z)");
    printCheckRow(analysis.lowerCount > 0, "Lowercase letter  (a-z)");
    printCheckRow(analysis.digitCount > 0, "Number            (0-9)");
    printCheckRow(analysis.specialCount > 0, "Special character (!@#$...)");
    printCheckRow(analysis.length >= 12, "12 or more characters");
    printCheckRow(!analysis.isDictionaryWord, "Not a dictionary word");
    printCheckRow(!analysis.isCommonPassword, "Not a common password");
    printCheckRow(!analysis.hasKeyboardPattern, "No keyboard pattern");
    printCheckRow(!analysis.hasSequentialLetters && !analysis.hasSequentialNumbers, "No sequential pattern");
    printCheckRow(!analysis.containsYear && !analysis.containsDobPattern, "No year / date-of-birth pattern");
    printCheckRow(!analysis.containsName, "No common name detected");

    // ---- AI Explanation Engine ----
    printSection("WHY THIS SCORE? (AI EXPLANATION)");
    vector<string> explanations = generateExplanations(analysis);
    for (size_t i = 0; i < explanations.size(); i++)
    {
        cout << "  - " << explanations[i] << "\n";
    }

    // ---- AI Recommendations ----
    printSection("AI RECOMMENDATIONS");
    vector<string> recommendations = generateRecommendations(analysis);
    for (size_t i = 0; i < recommendations.size(); i++)
    {
        cout << "  - " << recommendations[i] << "\n";
    }

    // ---- Random security fact ----
    printSection("DID YOU KNOW?");
    cout << "  " << getRandomSecurityFact() << "\n";

    printLine();
}
