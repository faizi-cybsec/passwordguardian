/*
    ============================================================
    HISTORY.CPP
    ============================================================
    See History.h for an overview.
    ============================================================
*/

#include "History.h"
#include "Utils.h"
#include <iostream>

using namespace std;

// The history list itself. Kept as a simple global vector inside
// this file only (not visible to other files) - this is the same
// beginner-friendly approach as the rest of the project, just
// wrapped in functions so main.cpp does not need to know how it
// is stored internally.
static vector<HistoryEntry> historyList;

const int MAX_HISTORY_ENTRIES = 20;

// Masks a password for safe display: keeps the first and last
// character and replaces everything else with '*'
string maskPassword(const string &password)
{
    if (password.size() <= 2)
    {
        return string(password.size(), '*');
    }

    string masked = "";
    masked += password[0];

    for (size_t i = 1; i + 1 < password.size(); i++)
    {
        masked += '*';
    }

    masked += password[password.size() - 1];
    return masked;
}

// Adds a new entry, removing the oldest one if history is full
void addHistoryEntry(const string &password, int score, const string &grade, const string &threatLevel)
{
    HistoryEntry entry;
    entry.date = getCurrentDateString();
    entry.time = getCurrentTimeString();
    entry.maskedPassword = maskPassword(password);
    entry.score = score;
    entry.grade = grade;
    entry.threatLevel = threatLevel;

    historyList.push_back(entry);

    if ((int)historyList.size() > MAX_HISTORY_ENTRIES)
    {
        // Remove the oldest entry (the first one in the list)
        historyList.erase(historyList.begin());
    }
}

// Prints every stored entry as a simple table
void printHistory()
{
    printTitle("PASSWORD ANALYSIS HISTORY");

    if (historyList.empty())
    {
        cout << "No history yet. Analyze a password first.\n";
        printLine();
        return;
    }

    cout << "Showing the last " << historyList.size() << " analyses "
         << "(passwords are masked for privacy):\n\n";

    for (size_t i = 0; i < historyList.size(); i++)
    {
        const HistoryEntry &entry = historyList[i];

        cout << "  " << (i + 1) << ". " << entry.date << " " << entry.time
             << "  |  " << entry.maskedPassword
             << "  |  Score: " << entry.score
             << "  |  Grade: " << entry.grade
             << "  |  Threat: " << entry.threatLevel << "\n";
    }

    printLine();
}

// Clears every entry from history
void clearHistory()
{
    historyList.clear();
    cout << COLOR_GREEN << "History cleared." << COLOR_RESET << "\n";
}

// Returns how many entries are currently stored
int historyCount()
{
    return (int)historyList.size();
}
