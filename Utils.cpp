/*
    ============================================================
    UTILS.CPP
    ============================================================
    See Utils.h for an explanation of what each function does.
    ============================================================
*/

#include "Utils.h"
#include <iostream>
#include <ctime>
#include <cstdlib>

using namespace std;

// ---- Console color definitions ----
// (Same ANSI escape codes as the original single-file version,
//  plus one extra color - magenta - used for the new features.)
const string COLOR_RESET   = "\033[0m";
const string COLOR_GREEN   = "\033[32m";
const string COLOR_YELLOW  = "\033[33m";
const string COLOR_RED     = "\033[31m";
const string COLOR_BLUE    = "\033[34m";
const string COLOR_CYAN    = "\033[36m";
const string COLOR_WHITE   = "\033[37m";
const string COLOR_MAGENTA = "\033[35m";

const string LINE = "============================================================";

// Prints a full-width separator line
void printLine()
{
    cout << LINE << "\n";
}

// Prints a page title in cyan, framed by separator lines
void printTitle(const string &title)
{
    printLine();
    cout << COLOR_CYAN << title << COLOR_RESET << "\n";
    printLine();
}

// Prints one row of a report as "label : value", lined up neatly
void printRow(const string &label, const string &value)
{
    cout << label;

    // Pad the label with spaces so all values line up in a column
    int padding = 22 - (int)label.size();
    for (int i = 0; i < padding; i++)
    {
        cout << " ";
    }

    cout << ": " << value << "\n";
}

// Prints a smaller sub-section heading inside a report, e.g. "/// CHECKLIST ///"
void printSection(const string &label)
{
    cout << "\n" << COLOR_WHITE << "/// " << label << " ///" << COLOR_RESET << "\n";
}

// Prints one checklist line with a colored [OK] / [NO] tag in front
void printCheckRow(bool passed, const string &label)
{
    if (passed)
    {
        cout << "  " << COLOR_GREEN << "[OK]" << COLOR_RESET << "  " << label << "\n";
    }
    else
    {
        cout << "  " << COLOR_RED << "[NO]" << COLOR_RESET << "  " << label << "\n";
    }
}

// Waits for the user to press Enter before going back to the menu
void pauseScreen()
{
    cout << "\nPress Enter to return to Main Menu...";
    cin.ignore();
    cin.get();
}

// Small helper that "types out" a loading message with dots.
// Just a simple delay loop, no real animation library used.
void showLoadingStep(const string &message)
{
    cout << message;
    for (int i = 0; i < 3; i++)
    {
        cout << "." << flush;
        // Small busy-wait delay so the dots appear one at a time
        for (long j = 0; j < 80000000; j++)
        {
            // empty loop used only as a short delay
        }
    }
    cout << "\n";
}

// Turns a true/false result into "YES" / "NO" text
string yesNo(bool value)
{
    if (value)
    {
        return "YES";
    }
    return "NO";
}

// Picks a color based on a 0-100 style score.
// Used for the security score, entropy score bar, complexity bar, etc.
string getScoreColor(int score)
{
    if (score < 40)
    {
        return COLOR_RED;
    }
    else if (score < 70)
    {
        return COLOR_YELLOW;
    }
    else
    {
        return COLOR_GREEN;
    }
}

// Builds a labeled ASCII progress bar out of block characters.
// Example:  Entropy          [##############------] 68%
string buildProgressBar(const string &label, int value, int maxValue)
{
    if (value < 0) value = 0;
    if (value > maxValue) value = maxValue;

    int totalBlocks = 20;
    int filledBlocks = 0;

    if (maxValue > 0)
    {
        filledBlocks = (value * totalBlocks) / maxValue;
    }

    string bar = label;

    // Pad the label so all bars line up in a column
    int padding = 18 - (int)label.size();
    for (int i = 0; i < padding; i++)
    {
        bar += " ";
    }

    bar += "[";
    for (int i = 0; i < totalBlocks; i++)
    {
        if (i < filledBlocks)
        {
            bar += "#";
        }
        else
        {
            bar += "-";
        }
    }
    bar += "] ";

    // Show the value as a percentage of maxValue
    int percent = 0;
    if (maxValue > 0)
    {
        percent = (value * 100) / maxValue;
    }
    bar += to_string(percent);
    bar += "%";

    return bar;
}

// Returns the current date as text, e.g. "2026-07-24"
string getCurrentDateString()
{
    time_t now = time(0);
    tm localTime;

#ifdef _WIN32
    localtime_s(&localTime, &now);
#else
    localtime_r(&now, &localTime);
#endif

    char buffer[32];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d", &localTime);
    return string(buffer);
}

// Returns the current time as text, e.g. "14:35:02"
string getCurrentTimeString()
{
    time_t now = time(0);
    tm localTime;

#ifdef _WIN32
    localtime_s(&localTime, &now);
#else
    localtime_r(&now, &localTime);
#endif

    char buffer[32];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", &localTime);
    return string(buffer);
}

// ---- Security fact library ----
// A simple array of at least 50 short cybersecurity facts. One is
// picked at random and shown after every password analysis.
string getRandomSecurityFact()
{
    static const string facts[] = {
        "The most commonly used password in the world is still \"123456\".",
        "A 12-character random password can take centuries to brute-force.",
        "Over 80% of hacking-related breaches involve weak or stolen passwords.",
        "Password managers can generate and remember unique passwords for every site.",
        "Multi-Factor Authentication blocks over 99% of automated account attacks.",
        "Reusing the same password on multiple sites multiplies your breach risk.",
        "\"Password123!\" still fails most security audits despite looking complex.",
        "Attackers often try leaked email/password pairs on other websites - this is called credential stuffing.",
        "Dictionary attacks try real words first because people often use them.",
        "Adding just 4 extra random characters can increase crack time by years.",
        "Keyboard patterns like \"qwerty\" or \"asdf\" are among the first guesses attackers try.",
        "Birthdays and anniversaries are common - and predictable - password choices.",
        "The \"k-Anonymity\" model lets you check breaches without exposing your full password.",
        "GPUs can test billions of password guesses per second on stolen hash databases.",
        "Passphrases (multiple random words) can be both strong and easy to remember.",
        "Security questions like \"mother's maiden name\" are often easy to research.",
        "Password entropy measures how unpredictable a password is, in bits.",
        "Two-factor authentication apps are generally safer than SMS codes.",
        "Old breached passwords are still used in attacks years after the breach.",
        "Changing a password after a suspected breach reduces further damage.",
        "Predictable substitutions like \"@\" for \"a\" barely slow down modern crackers.",
        "Password length matters more than complexity for resisting brute force.",
        "Storing passwords in a browser is more convenient but less secure than a dedicated manager.",
        "Hackers use \"rainbow tables\" - precomputed hash lookups - to crack unsalted hashes quickly.",
        "Salting a password hash prevents rainbow table attacks.",
        "Never share your password over email or phone, even with \"IT support\".",
        "Unique passwords per account limit damage if one service is breached.",
        "Public Wi-Fi networks make it easier for attackers to intercept unencrypted logins.",
        "A password with only lowercase letters has far less entropy than a mixed-case one.",
        "Common pet names and sports teams appear frequently in leaked password lists.",
        "Attackers often try a company name plus the current year as a default password guess.",
        "Password spraying tries one common password across many accounts to avoid lockouts.",
        "Biometrics (fingerprint, face ID) can complement, but should not fully replace, passwords.",
        "The average person reuses a password across multiple accounts more than 3 times.",
        "Long random passphrases resist both dictionary and brute-force attacks well.",
        "Security audits often flag passwords under 8 characters as high risk.",
        "Writing passwords on paper stored securely can sometimes be safer than reusing weak ones.",
        "Phishing remains one of the top ways attackers steal passwords, not just cracking them.",
        "Password strength meters can be misleading if they ignore common patterns.",
        "Some breaches go undetected for months before being publicly reported.",
        "A password manager master password should be the strongest password you own.",
        "Attackers automate password guessing with scripts that try thousands of combinations per minute.",
        "Even \"random-looking\" passwords can be weak if humans generated them without true randomness.",
        "Companies are increasingly moving toward passkeys to eliminate passwords entirely.",
        "Repeating a character 3+ times in a row is one of the first patterns crackers check for.",
        "Sequential numbers like \"12345\" appear in millions of leaked password dumps.",
        "Your email password is often the master key to resetting all your other accounts.",
        "Old, unused accounts with weak passwords can still be exploited years later.",
        "Regularly reviewing account activity can help catch unauthorized access early.",
        "The strongest defense against most attacks is a long, unique, randomly generated password.",
        "Security experts recommend changing default router and device passwords immediately.",
    };

    int factCount = sizeof(facts) / sizeof(facts[0]);
    int index = rand() % factCount;
    return facts[index];
}
