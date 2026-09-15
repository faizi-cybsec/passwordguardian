/*
    ============================================================
    PASSWORDGENERATOR.CPP
    ============================================================
    See PasswordGenerator.h for an overview.
    ============================================================
*/

#include "PasswordGenerator.h"
#include "PasswordAnalyzer.h"
#include "Entropy.h"
#include "Utils.h"
#include "History.h"
#include <iostream>
#include <cstdlib>

using namespace std;

// Builds the pool of characters allowed for generation, based on
// which options are turned on. This is the same idea as combining
// upper + lower + digits + special in the original project, just
// with each part now optional and ambiguous characters removable.
static string buildCharacterPool(const GeneratorOptions &options, string &guaranteedUpper,
                                  string &guaranteedLower, string &guaranteedDigits,
                                  string &guaranteedSymbols)
{
    string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    string lower = "abcdefghijklmnopqrstuvwxyz";
    string digits = "0123456789";
    string symbols = "!@#$%^&*()-_=+";

    if (options.avoidAmbiguous)
    {
        // Remove characters that are easy to confuse with each other
        upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";   // removed I, O
        lower = "abcdefghjkmnpqrstuvwxyz";    // removed i, l, o
        digits = "23456789";                  // removed 0, 1
    }

    string pool = "";

    if (options.useUpper)   { pool += upper;   guaranteedUpper = upper; }
    if (options.useLower)   { pool += lower;   guaranteedLower = lower; }
    if (options.useDigits)  { pool += digits;  guaranteedDigits = digits; }
    if (options.useSymbols) { pool += symbols; guaranteedSymbols = symbols; }

    // Safety net: if the user somehow turned every option off,
    // fall back to lowercase letters so generation can still work.
    if (pool.empty())
    {
        pool = lower;
        guaranteedLower = lower;
    }

    return pool;
}

// Generates one random password using the given options.
string generatePasswordWithOptions(const GeneratorOptions &options)
{
    string guaranteedUpper, guaranteedLower, guaranteedDigits, guaranteedSymbols;
    string allChars = buildCharacterPool(options, guaranteedUpper, guaranteedLower,
                                          guaranteedDigits, guaranteedSymbols);

    string password = "";

    // Guarantee at least one character from each enabled category,
    // exactly like the original generator guaranteed one of each type.
    if (!guaranteedUpper.empty())   password += guaranteedUpper[rand() % guaranteedUpper.size()];
    if (!guaranteedLower.empty())   password += guaranteedLower[rand() % guaranteedLower.size()];
    if (!guaranteedDigits.empty())  password += guaranteedDigits[rand() % guaranteedDigits.size()];
    if (!guaranteedSymbols.empty()) password += guaranteedSymbols[rand() % guaranteedSymbols.size()];

    int targetLength = options.length;
    if (targetLength < (int)password.size())
    {
        targetLength = (int)password.size();
    }

    for (int i = (int)password.length(); i < targetLength; i++)
    {
        password += allChars[rand() % allChars.size()];
    }

    // Shuffle the characters so the guaranteed ones aren't always
    // at the start (same Fisher-Yates style shuffle as before)
    for (int i = (int)password.length() - 1; i > 0; i--)
    {
        int j = rand() % (i + 1);
        char temp = password[i];
        password[i] = password[j];
        password[j] = temp;
    }

    return password;
}

// Generates several random passwords using the same options
vector<string> generateMultiplePasswords(const GeneratorOptions &options, int howMany)
{
    vector<string> passwords;
    for (int i = 0; i < howMany; i++)
    {
        passwords.push_back(generatePasswordWithOptions(options));
    }
    return passwords;
}

// Prints a compact strength summary line for one generated password
static void printGeneratedPasswordSummary(const string &password)
{
    PasswordAnalysis analysis = analyzePassword(password);
    double entropyBits = calculateEntropyBits(password);
    int score = calculateSecurityScore(analysis, entropyBits);
    string grade = getSecurityGrade(score);
    string color = getScoreColor(score);

    cout << "  " << color << password << COLOR_RESET
         << "   (Score: " << score << "/100, Grade: " << grade
         << ", Entropy: " << (int)entropyBits << " bits)\n";
}

// Builds a GeneratorOptions struct for one of the named difficulty levels
static GeneratorOptions optionsForLevel(int levelChoice)
{
    GeneratorOptions options;

    switch (levelChoice)
    {
    case 1: // Easy
        options.length = 8;
        options.useUpper = true;
        options.useLower = true;
        options.useDigits = true;
        options.useSymbols = false;
        options.avoidAmbiguous = true;
        break;
    case 2: // Medium
        options.length = 12;
        options.useUpper = true;
        options.useLower = true;
        options.useDigits = true;
        options.useSymbols = true;
        options.avoidAmbiguous = false;
        break;
    case 3: // Strong
        options.length = 16;
        options.useUpper = true;
        options.useLower = true;
        options.useDigits = true;
        options.useSymbols = true;
        options.avoidAmbiguous = false;
        break;
    case 4: // Military
        options.length = 24;
        options.useUpper = true;
        options.useLower = true;
        options.useDigits = true;
        options.useSymbols = true;
        options.avoidAmbiguous = false;
        break;
    default:
        options.length = 12;
        break;
    }

    return options;
}

// Lets the user pick a custom length from the fixed list the
// project proposal asked for: 8, 12, 16, 20, 24, 32
static int askForLength()
{
    cout << "\nChoose a length:\n";
    cout << "  [1] 8 characters\n";
    cout << "  [2] 12 characters\n";
    cout << "  [3] 16 characters\n";
    cout << "  [4] 20 characters\n";
    cout << "  [5] 24 characters\n";
    cout << "  [6] 32 characters\n";
    cout << "Enter choice: ";

    int choice;
    cin >> choice;

    switch (choice)
    {
        case 1: return 8;
        case 2: return 12;
        case 3: return 16;
        case 4: return 20;
        case 5: return 24;
        case 6: return 32;
        default:
            cout << "Invalid choice. Using default length of 12.\n";
            return 12;
    }
}

// Asks the user to turn each character type on/off for Custom mode
static GeneratorOptions askForCustomOptions()
{
    GeneratorOptions options;
    options.length = askForLength();

    int answer;

    cout << "\nInclude uppercase letters? (1 = Yes, 0 = No): ";
    cin >> answer;
    options.useUpper = (answer == 1);

    cout << "Include lowercase letters? (1 = Yes, 0 = No): ";
    cin >> answer;
    options.useLower = (answer == 1);

    cout << "Include numbers? (1 = Yes, 0 = No): ";
    cin >> answer;
    options.useDigits = (answer == 1);

    cout << "Include symbols? (1 = Yes, 0 = No): ";
    cin >> answer;
    options.useSymbols = (answer == 1);

    cout << "Avoid ambiguous characters like 0/O and 1/l/I? (1 = Yes, 0 = No): ";
    cin >> answer;
    options.avoidAmbiguous = (answer == 1);

    return options;
}

// Runs the interactive "Password Generator" menu
void passwordGeneratorMenu()
{
    cout << "\n";
    printTitle("PASSWORD GENERATOR");

    cout << "  [1] Easy      (8 characters, letters + numbers)\n";
    cout << "  [2] Medium    (12 characters, all character types)\n";
    cout << "  [3] Strong    (16 characters, all character types)\n";
    cout << "  [4] Military  (24 characters, all character types)\n";
    cout << "  [5] Custom    (choose your own settings)\n";
    cout << "------------------------------------------------------------\n";
    cout << "Enter choice: ";

    int levelChoice;
    cin >> levelChoice;

    GeneratorOptions options;

    if (levelChoice == 5)
    {
        options = askForCustomOptions();
    }
    else if (levelChoice >= 1 && levelChoice <= 4)
    {
        options = optionsForLevel(levelChoice);
    }
    else
    {
        cout << "Invalid choice. Using Medium settings.\n";
        options = optionsForLevel(2);
    }

    cout << "\nHow many passwords would you like to generate? (1-10): ";
    int howMany;
    cin >> howMany;

    if (howMany < 1) howMany = 1;
    if (howMany > 10) howMany = 10;

    vector<string> passwords = generateMultiplePasswords(options, howMany);

    cout << "\n";
    printTitle("GENERATED PASSWORDS");

    for (size_t i = 0; i < passwords.size(); i++)
    {
        printGeneratedPasswordSummary(passwords[i]);
    }

    printLine();
    cout << "Tip: copy the password you like best directly from above.\n";

    // Save the first generated password into history as a convenience,
    // so the user can review its full analysis later if they want to.
    if (!passwords.empty())
    {
        PasswordAnalysis analysis = analyzePassword(passwords[0]);
        double entropyBits = calculateEntropyBits(passwords[0]);
        int score = calculateSecurityScore(analysis, entropyBits);
        string grade = getSecurityGrade(score);
        string threatLevel = getThreatLevel(score);
        addHistoryEntry(passwords[0], score, grade, threatLevel);
    }

    printLine();
}
