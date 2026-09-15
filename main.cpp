/*
    ============================================================
    PASSWORD GUARDIAN PRO
    AI Password Security Analyzer
    ============================================================

    Programming Fundamentals Course Project
    Department : BS Cyber Security
    Developer  : Faizan Ahmed
    University : Superior University

    This is the upgraded "Pro" version of the original Password
    Guardian project. Every original feature has been kept:
      - Password Strength Analyzer
      - Password Generator
      - SHA-1 Hashing
      - Have I Been Pwned API Check
      - Security Recommendations
      - ANSI Colored Console
      - Structured Report
      - Loading Animations

    New in the Pro version:
      - Deep pattern analysis (dictionary words, keyboard
        patterns, sequential/repeated characters, years, names,
        emails, phone numbers, dates of birth, and more)
      - Real entropy calculation and crack-time estimation
      - A weighted 0-100 security score with A+ to F grading
      - A SAFE/LOW/MEDIUM/HIGH/CRITICAL threat level
      - An "AI explanation engine" that explains WHY a password
        scored the way it did
      - A professional Password Security Dashboard
      - An upgraded password generator with difficulty levels
      - Password comparison
      - A password policy checker
      - An educational (non-real) attack simulator
      - Session history and exportable text reports

    Technologies used:
      - C++17 (basic console I/O, strings, arrays, loops, vectors)
      - A hand-written SHA-1 hashing function (unchanged from v1)
      - The system "curl" command to talk to the internet
      - The Have I Been Pwned Password API (k-Anonymity model)

    ============================================================
*/

#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>

#include "Utils.h"
#include "PasswordAnalyzer.h"
#include "Entropy.h"
#include "PasswordGenerator.h"
#include "HIBP.h"
#include "AttackSimulator.h"
#include "History.h"
#include "Report.h"

using namespace std;

const string APP_VERSION = "2.0 Pro";

// ==============================================================
// SECTION 1: BANNER AND STARTUP SCREEN
// ==============================================================

// Prints the startup banner. The ASCII art title is stored as a
// raw string literal (R"( ... )") so the backslashes used to draw
// the letters do not need to be escaped one by one. This is the
// SAME banner as the original Password Guardian project.
void showBanner()
{
    // ---- ASCII art title: "PASSWORD" / "GUARDIAN" (cyan) ----
    cout << COLOR_CYAN << R"(
              ____   _    ____ ______        _____  ____  ____
             |  _ \ / \  / ___/ ___\ \      / / _ \|  _ \|  _ \
             | |_) / _ \ \___ \___ \\ \ /\ / / | | | |_) | | | |
             |  __/ ___ \ ___) |__) |\ V  V /| |_| |  _ <| |_| |
             |_| /_/   \_\____/____/  \_/\_/  \___/|_| \_\____/

               ____ _   _   _    ____  ____ ___    _    _   _
              / ___| | | | / \  |  _ \|  _ \_ _|  / \  | \ | |
             | |  _| | | |/ _ \ | |_) | | | | |  / _ \ |  \| |
             | |_| | |_| / ___ \|  _ <| |_| | | / ___ \| |\  |
              \____|\___/_/   \_\_| \_\____/___/_/   \_\_| \_|
)" << COLOR_RESET;

    // ---- Subtitle (yellow) ----
    cout << COLOR_YELLOW << R"(
                        AI Password Security Analyzer  -  PRO
)" << COLOR_RESET;
    printLine();
}

// Shows a professional-looking startup information panel: version,
// developer, university, project name, modules loaded, API status
// and the current time. Program startup now looks like real
// cybersecurity software instead of jumping straight to the menu.
void showStartupInfo()
{
    printRow("Project", "Password Guardian Pro");
    printRow("Version", APP_VERSION);
    printRow("Developer", "Faizan Ahmed");
    printRow("University", "Superior University");
    printRow("Department", "BS Cyber Security");
    printRow("Current Time", getCurrentDateString() + "  " + getCurrentTimeString());

    cout << "\n";
    printSection("MODULES LOADED");
    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET << "  Password Analyzer\n";
    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET << "  Entropy Engine\n";
    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET << "  Password Generator\n";
    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET << "  Attack Simulator\n";
    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET << "  History Manager\n";
    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET << "  Report Generator\n";
    cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET << "  HIBP Breach Checker (requires internet)\n";

    cout << "\n";
    printRow("API Status", COLOR_CYAN + string("Ready (connects when Breach Database is used)") + COLOR_RESET);

    cout << "\n";
    showLoadingStep("Initializing Password Guardian Pro");
    printLine();
}

// ==============================================================
// SECTION 2: MAIN MENU
// ==============================================================

void showMenu()
{
    cout << "\n";
    cout << COLOR_BLUE;
    printLine();
    cout << "                         MAIN MENU\n";
    printLine();
    cout << COLOR_RESET;

    cout << "  " << COLOR_CYAN << "[1]" << COLOR_RESET << "  Analyze Password\n";
    cout << "  " << COLOR_CYAN << "[2]" << COLOR_RESET << "  Generate Password\n";
    cout << "  " << COLOR_CYAN << "[3]" << COLOR_RESET << "  Compare Passwords\n";
    cout << "  " << COLOR_CYAN << "[4]" << COLOR_RESET << "  Password Policy Check\n";
    cout << "  " << COLOR_CYAN << "[5]" << COLOR_RESET << "  Breach Database\n";
    cout << "  " << COLOR_CYAN << "[6]" << COLOR_RESET << "  History\n";
    cout << "  " << COLOR_CYAN << "[7]" << COLOR_RESET << "  Reports\n";
    cout << "  " << COLOR_CYAN << "[8]" << COLOR_RESET << "  Security Tips\n";
    cout << "  " << COLOR_CYAN << "[9]" << COLOR_RESET << "  About\n";
    cout << "  " << COLOR_CYAN << "[10]" << COLOR_RESET << " Attack Simulator (Educational)\n";
    cout << "  " << COLOR_CYAN << "[0]" << COLOR_RESET << "  Exit\n";

    cout << COLOR_BLUE;
    printLine();
    cout << COLOR_RESET;
    cout << "Enter Choice : ";
}

// ==============================================================
// SECTION 3: MENU HANDLERS
// ==============================================================

// [1] Analyze Password - runs the full dashboard and saves to history
void handleAnalyzePassword()
{
    string password;
    cout << "\nEnter password to analyze: ";
    cin >> password;

    PasswordAnalysis analysis = analyzePassword(password);
    printPasswordDashboard(analysis);

    double entropyBits = calculateEntropyBits(password);
    int score = calculateSecurityScore(analysis, entropyBits);
    string grade = getSecurityGrade(score);
    string threatLevel = getThreatLevel(score);

    addHistoryEntry(password, score, grade, threatLevel);
}

// [3] Compare Passwords - analyzes two passwords side by side
void handleComparePasswords()
{
    string passwordA, passwordB;

    cout << "\n";
    printTitle("COMPARE TWO PASSWORDS");

    cout << "Enter first password : ";
    cin >> passwordA;
    cout << "Enter second password: ";
    cin >> passwordB;

    PasswordAnalysis analysisA = analyzePassword(passwordA);
    PasswordAnalysis analysisB = analyzePassword(passwordB);

    double entropyA = calculateEntropyBits(passwordA);
    double entropyB = calculateEntropyBits(passwordB);

    int scoreA = calculateSecurityScore(analysisA, entropyA);
    int scoreB = calculateSecurityScore(analysisB, entropyB);

    CrackTimeEstimates crackA = estimateCrackTimes(entropyA, analysisA.isDictionaryWord, analysisA.isCommonPassword);
    CrackTimeEstimates crackB = estimateCrackTimes(entropyB, analysisB.isDictionaryWord, analysisB.isCommonPassword);

    cout << "\n";
    printSection("SCORE COMPARISON");
    printRow("Password A Score", to_string(scoreA) + " / 100 (" + getSecurityGrade(scoreA) + ")");
    printRow("Password B Score", to_string(scoreB) + " / 100 (" + getSecurityGrade(scoreB) + ")");

    printSection("ENTROPY COMPARISON");
    printRow("Password A Entropy", to_string((int)entropyA) + " bits");
    printRow("Password B Entropy", to_string((int)entropyB) + " bits");

    printSection("CRACK TIME COMPARISON (OFFLINE ATTACK)");
    printRow("Password A", crackA.offlineAttack);
    printRow("Password B", crackB.offlineAttack);

    printSection("WINNER");
    if (scoreA > scoreB)
    {
        cout << "  " << COLOR_GREEN << "Password A is stronger." << COLOR_RESET << "\n";
    }
    else if (scoreB > scoreA)
    {
        cout << "  " << COLOR_GREEN << "Password B is stronger." << COLOR_RESET << "\n";
    }
    else
    {
        cout << "  " << COLOR_YELLOW << "Both passwords scored equally." << COLOR_RESET << "\n";
    }

    printLine();
}

// [4] Password Policy Check - checks a password against a chosen policy
void handlePasswordPolicyCheck()
{
    string password;
    int minLength;
    int requireUpperAnswer, requireDigitAnswer, requireSpecialAnswer;

    cout << "\n";
    printTitle("PASSWORD POLICY CHECK");

    cout << "Enter the password to check: ";
    cin >> password;

    cout << "\nDefine the policy:\n";
    cout << "Minimum length required: ";
    cin >> minLength;

    cout << "Require at least one uppercase letter? (1 = Yes, 0 = No): ";
    cin >> requireUpperAnswer;

    cout << "Require at least one number? (1 = Yes, 0 = No): ";
    cin >> requireDigitAnswer;

    cout << "Require at least one special character? (1 = Yes, 0 = No): ";
    cin >> requireSpecialAnswer;

    bool requireUpper = (requireUpperAnswer == 1);
    bool requireDigitFlag = (requireDigitAnswer == 1);
    bool requireSpecial = (requireSpecialAnswer == 1);

    bool passLength = (int)password.length() >= minLength;
    bool passUpper = !requireUpper || hasUppercase(password);
    bool passDigit = !requireDigitFlag || hasDigit(password);
    bool passSpecial = !requireSpecial || hasSpecialChar(password);

    bool overallPass = passLength && passUpper && passDigit && passSpecial;

    cout << "\n";
    printSection("POLICY RESULTS");
    printCheckRow(passLength, "Minimum length (" + to_string(minLength) + " characters)");

    if (requireUpper)
    {
        printCheckRow(passUpper, "Uppercase letter required");
    }
    if (requireDigitFlag)
    {
        printCheckRow(passDigit, "Number required");
    }
    if (requireSpecial)
    {
        printCheckRow(passSpecial, "Special character required");
    }

    cout << "\nOverall Result: ";
    if (overallPass)
    {
        cout << COLOR_GREEN << "PASS" << COLOR_RESET << "\n";
    }
    else
    {
        cout << COLOR_RED << "FAIL" << COLOR_RESET << "\n";
    }

    printLine();
}

// [6] History - view or delete stored analyses
void handleHistoryMenu()
{
    cout << "\n";
    cout << "  [1] View History\n";
    cout << "  [2] Delete History\n";
    cout << "Enter choice: ";

    int choice;
    cin >> choice;

    cout << "\n";
    if (choice == 1)
    {
        printHistory();
    }
    else if (choice == 2)
    {
        clearHistory();
    }
    else
    {
        cout << COLOR_YELLOW << "Invalid choice." << COLOR_RESET << "\n";
    }
}

// [8] Security Tips - kept from the original project's recommendations page
void showSecurityRecommendations()
{
    cout << "\n";
    printTitle("SECURITY TIPS");

    cout << "  - Increase password length.\n";
    cout << "  - Add symbols.\n";
    cout << "  - Avoid dictionary words.\n";
    cout << "  - Never reuse passwords.\n";
    cout << "  - Enable Multi-Factor Authentication.\n";

    printSection("DID YOU KNOW?");
    cout << "  " << getRandomSecurityFact() << "\n";

    printLine();
}

// [9] About - project information page
void showAbout()
{
    cout << "\n";
    printTitle("ABOUT PASSWORD GUARDIAN PRO");

    printRow("Project", "Password Guardian Pro - AI Password Security Analyzer");
    printRow("Version", APP_VERSION);
    printRow("Developer", "Faizan Ahmed");
    printRow("University", "Superior University");
    printRow("Department", "BS Cyber Security");

    cout << "\nPassword Guardian Pro analyzes password strength using a\n";
    cout << "rule-based scoring system, calculates entropy and estimated\n";
    cout << "crack times, checks real-world breach data through the Have\n";
    cout << "I Been Pwned API, and generates strong random passwords -\n";
    cout << "all from a single console application built in C++17.\n";

    printLine();
}

// ==============================================================
// SECTION 4: PROGRAM ENTRY POINT
// ==============================================================

int main()
{
    // Seed the random number generator once at the start
    srand((unsigned int)time(0));

    showBanner();
    showStartupInfo();

    int choice;

    do
    {
        showMenu();
        cin >> choice;

        switch (choice)
        {
        case 1:
            handleAnalyzePassword();
            pauseScreen();
            break;
        case 2:
            passwordGeneratorMenu();
            pauseScreen();
            break;
        case 3:
            handleComparePasswords();
            pauseScreen();
            break;
        case 4:
            handlePasswordPolicyCheck();
            pauseScreen();
            break;
        case 5:
            checkBreachDatabase();
            pauseScreen();
            break;
        case 6:
            handleHistoryMenu();
            pauseScreen();
            break;
        case 7:
            reportsMenu();
            pauseScreen();
            break;
        case 8:
            showSecurityRecommendations();
            pauseScreen();
            break;
        case 9:
            showAbout();
            pauseScreen();
            break;
        case 10:
            attackSimulatorMenu();
            pauseScreen();
            break;
        case 0:
            cout << "\n" << COLOR_GREEN
                 << "Thank you for using Password Guardian Pro. Stay safe online!"
                 << COLOR_RESET << "\n";
            break;
        default:
            cout << "\n" << COLOR_YELLOW
                 << "Invalid choice. Please try again."
                 << COLOR_RESET << "\n";
            break;
        }

    } while (choice != 0);

    return 0;
}
