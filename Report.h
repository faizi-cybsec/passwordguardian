/*
    ============================================================
    REPORT.H
    ============================================================
    Exports a password analysis to a plain text (.txt) file
    inside the "reports" folder, so the user has a saved copy
    they can submit or keep for their records.
    ============================================================
*/

#pragma once

#include "PasswordAnalyzer.h"

// Generates a full report file for one PasswordAnalysis and saves
// it inside the "reports" folder. Returns the filename that was
// created, or an empty string if the file could not be created.
std::string generatePasswordReport(const PasswordAnalysis &analysis);

// Runs the interactive "Reports" menu option: asks the user for a
// password, analyzes it, and saves a report file.
void reportsMenu();
