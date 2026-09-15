/*
    ============================================================
    REPORT.CPP
    ============================================================
    See Report.h for an overview.
    ============================================================
*/

#include "Report.h"
#include "Entropy.h"
#include "Utils.h"
#include "History.h"
#include <iostream>
#include <fstream>

using namespace std;

// Generates a report file for one password analysis and saves it
// inside the "reports" folder using a timestamp-based filename.
string generatePasswordReport(const PasswordAnalysis &analysis)
{
    EntropyResult entropy = calculateEntropyDetails(analysis.password);
    int score = calculateSecurityScore(analysis, entropy.entropyBits);
    string grade = getSecurityGrade(score);
    string threatLevel = getThreatLevel(score);
    vector<string> recommendations = generateRecommendations(analysis);

    string date = getCurrentDateString();
    string time = getCurrentTimeString();

    // Build a simple, safe filename using the date and time
    string safeTime = time;
    for (size_t i = 0; i < safeTime.size(); i++)
    {
        if (safeTime[i] == ':')
        {
            safeTime[i] = '-';
        }
    }

    string filename = "reports/password_report_" + date + "_" + safeTime + ".txt";

    ofstream reportFile(filename.c_str());
    if (!reportFile.is_open())
    {
        return "";
    }

    reportFile << "============================================================\n";
    reportFile << " PASSWORD GUARDIAN PRO - SECURITY REPORT\n";
    reportFile << "============================================================\n";
    reportFile << "Date  : " << date << "\n";
    reportFile << "Time  : " << time << "\n\n";

    reportFile << "---- Password Overview ----\n";
    reportFile << "Masked Password    : " << maskPassword(analysis.password) << "\n";
    reportFile << "Length             : " << analysis.length << " characters\n";
    reportFile << "Uppercase Letters  : " << analysis.upperCount << "\n";
    reportFile << "Lowercase Letters  : " << analysis.lowerCount << "\n";
    reportFile << "Numbers            : " << analysis.digitCount << "\n";
    reportFile << "Special Characters : " << analysis.specialCount << "\n";
    reportFile << "Unique Characters  : " << analysis.uniqueCount << "\n\n";

    reportFile << "---- Score ----\n";
    reportFile << "Security Score : " << score << " / 100\n";
    reportFile << "Grade          : " << grade << "\n";
    reportFile << "Threat Level   : " << threatLevel << "\n\n";

    reportFile << "---- Entropy ----\n";
    reportFile << "Entropy Bits   : " << (int)entropy.entropyBits << " bits\n";
    reportFile << "Complexity     : " << entropy.complexityLabel << "\n";
    reportFile << "Search Space   : " << entropy.searchSpaceText << " combinations\n\n";

    reportFile << "---- Recommendations ----\n";
    for (size_t i = 0; i < recommendations.size(); i++)
    {
        reportFile << "- " << recommendations[i] << "\n";
    }

    reportFile.close();
    return filename;
}

// Runs the interactive "Reports" menu option
void reportsMenu()
{
    string password;

    cout << "\n";
    printTitle("GENERATE SECURITY REPORT");
    cout << "Enter the password to include in the report: ";
    cin >> password;

    PasswordAnalysis analysis = analyzePassword(password);
    string filename = generatePasswordReport(analysis);

    cout << "\n";
    if (filename.empty())
    {
        cout << COLOR_RED << "Failed to create the report file." << COLOR_RESET << "\n";
    }
    else
    {
        cout << COLOR_GREEN << "Report saved successfully: " << filename << COLOR_RESET << "\n";
    }

    printLine();
}
