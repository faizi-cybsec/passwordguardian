/*
    ============================================================
    ATTACKSIMULATOR.CPP
    ============================================================
    See AttackSimulator.h - this file never performs a real
    attack. It only prints a simple, fake progress animation for
    teaching purposes, then shows the REAL estimated crack time
    for that attack type (calculated in Entropy.cpp).
    ============================================================
*/

#include "AttackSimulator.h"
#include "Entropy.h"
#include "Utils.h"
#include <iostream>

using namespace std;

// Prints a simple fake progress bar that fills up over a few steps.
// This is purely a visual effect for education - no guessing of
// the real password ever happens.
static void printFakeProgress(const string &label)
{
    for (int percent = 0; percent <= 100; percent += 20)
    {
        cout << "\r" << buildProgressBar(label, percent, 100) << flush;

        // Small delay so the animation is visible
        for (long i = 0; i < 60000000; i++)
        {
            // empty loop used only as a short delay
        }
    }
    cout << "\n";
}

// Simulates a dictionary attack: trying real words and known
// leaked passwords first.
static void simulateDictionaryAttack(const PasswordAnalysis &analysis, const string &crackTime)
{
    cout << "\nSimulating dictionary attack (trying known words/passwords first)...\n";
    printFakeProgress("Trying wordlist");

    if (analysis.isCommonPassword || analysis.isDictionaryWord)
    {
        cout << COLOR_RED << "Result: This password would likely be found almost immediately." << COLOR_RESET << "\n";
    }
    else
    {
        cout << COLOR_GREEN << "Result: This password was not found in the simulated wordlist." << COLOR_RESET << "\n";
    }

    cout << "Estimated real-world crack time for this attack type: " << crackTime << "\n";
}

// Simulates a hybrid attack: dictionary words plus common mutations
// (adding numbers, capitalizing, substituting letters, etc.)
static void simulateHybridAttack(const PasswordAnalysis &analysis, const string &crackTime)
{
    cout << "\nSimulating hybrid attack (dictionary words + common mutations)...\n";
    printFakeProgress("Trying mutations");

    if (analysis.isDictionaryWord || analysis.hasPredictableSubstitution || analysis.hasWeakSuffix)
    {
        cout << COLOR_RED << "Result: This password's pattern would likely be discovered quickly." << COLOR_RESET << "\n";
    }
    else
    {
        cout << COLOR_GREEN << "Result: No obvious mutation pattern was found." << COLOR_RESET << "\n";
    }

    cout << "Estimated real-world crack time for this attack type: " << crackTime << "\n";
}

// Simulates a rainbow table attack: precomputed hash lookups
static void simulateRainbowTable(const PasswordAnalysis & /*analysis*/)
{
    cout << "\nSimulating rainbow table attack (precomputed hash lookups)...\n";
    printFakeProgress("Searching tables");

    cout << COLOR_YELLOW
         << "Note: Rainbow tables only work against UNSALTED password hashes."
         << COLOR_RESET << "\n";
    cout << "Modern systems that properly salt their password hashes are\n";
    cout << "immune to this attack, regardless of password strength.\n";
}

// Simulates a brute force attack: trying every possible combination
static void simulateBruteForce(const string &crackTime)
{
    cout << "\nSimulating brute force attack (trying every possible combination)...\n";
    printFakeProgress("Trying combinations");

    cout << "Estimated real-world crack time for this attack type: " << crackTime << "\n";
}

// Runs the interactive "Attack Simulator" menu
void attackSimulatorMenu()
{
    string password;

    cout << "\n";
    printTitle("ATTACK SIMULATOR (EDUCATIONAL ONLY)");
    cout << COLOR_YELLOW
         << "This simulator never performs a real attack. It only shows a\n"
         << "visual demonstration alongside realistic time estimates.\n"
         << COLOR_RESET;

    cout << "\nEnter a password to simulate attacks against: ";
    cin >> password;

    PasswordAnalysis analysis = analyzePassword(password);
    double entropyBits = calculateEntropyBits(password);
    CrackTimeEstimates crackTimes = estimateCrackTimes(entropyBits, analysis.isDictionaryWord, analysis.isCommonPassword);

    cout << "\n";
    cout << "  [1] Dictionary Attack\n";
    cout << "  [2] Hybrid Attack\n";
    cout << "  [3] Rainbow Table Attack\n";
    cout << "  [4] Brute Force Attack\n";
    cout << "  [5] Run All Simulations\n";
    cout << "------------------------------------------------------------\n";
    cout << "Enter choice: ";

    int choice;
    cin >> choice;

    printLine();

    switch (choice)
    {
        case 1:
            simulateDictionaryAttack(analysis, crackTimes.dictionaryAttack);
            break;
        case 2:
            simulateHybridAttack(analysis, crackTimes.hybridAttack);
            break;
        case 3:
            simulateRainbowTable(analysis);
            break;
        case 4:
            simulateBruteForce(crackTimes.bruteForceAttack);
            break;
        case 5:
            simulateDictionaryAttack(analysis, crackTimes.dictionaryAttack);
            simulateHybridAttack(analysis, crackTimes.hybridAttack);
            simulateRainbowTable(analysis);
            simulateBruteForce(crackTimes.bruteForceAttack);
            break;
        default:
            cout << COLOR_YELLOW << "Invalid choice." << COLOR_RESET << "\n";
            break;
    }

    printLine();
}
