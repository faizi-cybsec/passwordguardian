/*
    ============================================================
    HISTORY.H
    ============================================================
    Keeps a record of the last 20 password analyses performed
    during this session, so the user can review them later
    without re-typing anything.

    Privacy note: passwords are never stored in full. Only a
    masked version (e.g. "P********d") is kept, along with the
    score, grade and threat level, so nothing sensitive sits in
    memory longer than necessary.

    History is kept in memory only (a normal std::vector) for
    this session - it intentionally does not write your
    passwords to disk.
    ============================================================
*/

#pragma once

#include <string>
#include <vector>

// One row of password history
struct HistoryEntry
{
    std::string date;
    std::string time;
    std::string maskedPassword;
    int score = 0;
    std::string grade;
    std::string threatLevel;
};

// Masks a password for safe display/storage, e.g. "Summer2024!"
// becomes "S*********!" - only the first and last character are kept.
std::string maskPassword(const std::string &password);

// Adds one new entry to the history. If there are already 20
// entries, the oldest one is removed to make room.
void addHistoryEntry(const std::string &password, int score, const std::string &grade, const std::string &threatLevel);

// Prints every entry currently stored in history as a table
void printHistory();

// Removes every entry from history
void clearHistory();

// Returns how many entries are currently stored
int historyCount();
