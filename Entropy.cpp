/*
    ============================================================
    ENTROPY.CPP
    ============================================================
    See Entropy.h for an explanation of what each function does.
    ============================================================
*/

#include "Entropy.h"
#include "PasswordAnalyzer.h" // for hasUppercase/hasLowercase/hasDigit/hasSpecialChar
#include <cmath>
#include <sstream>
#include <iomanip>

using namespace std;

// Calculates entropy in bits using the classic formula:
//   entropy = length * log2(poolSize)
// where poolSize is how many different characters could have
// been used at each position (26 lowercase, 26 uppercase,
// 10 digits, ~32 special characters).
double calculateEntropyBits(const string &password)
{
    if (password.empty())
    {
        return 0.0;
    }

    int poolSize = 0;

    if (hasLowercase(password))
    {
        poolSize += 26;
    }
    if (hasUppercase(password))
    {
        poolSize += 26;
    }
    if (hasDigit(password))
    {
        poolSize += 10;
    }
    if (hasSpecialChar(password))
    {
        poolSize += 32;
    }

    // If somehow no character type was detected, avoid log2(0)
    if (poolSize == 0)
    {
        poolSize = 1;
    }

    double bitsPerCharacter = log2((double)poolSize);
    return bitsPerCharacter * (double)password.length();
}

// Turns an entropy value into a short "Very Low" .. "Very High" label
string classifyComplexity(double entropyBits)
{
    if (entropyBits < 28)
    {
        return "Very Low";
    }
    else if (entropyBits < 36)
    {
        return "Low";
    }
    else if (entropyBits < 60)
    {
        return "Medium";
    }
    else if (entropyBits < 80)
    {
        return "High";
    }
    else
    {
        return "Very High";
    }
}

// Builds a readable "search space" string, e.g. "9.5 x 10^15 combinations"
// The search space is simply 2^entropyBits, written in scientific
// notation because it becomes an enormous number very quickly.
string buildSearchSpaceText(double entropyBits)
{
    double exponent = entropyBits * log10(2.0); // convert bits to power-of-10

    int wholeExponent = (int)exponent;
    double remainder = exponent - wholeExponent;
    double mantissa = pow(10.0, remainder);

    ostringstream oss;
    oss << fixed << setprecision(2) << mantissa << " x 10^" << wholeExponent;
    return oss.str();
}

// Builds the full EntropyResult for a password
EntropyResult calculateEntropyDetails(const string &password)
{
    EntropyResult result;

    result.entropyBits = calculateEntropyBits(password);
    result.complexityLabel = classifyComplexity(result.entropyBits);
    result.searchSpaceText = buildSearchSpaceText(result.entropyBits);

    result.poolSize = 0;
    if (hasLowercase(password)) result.poolSize += 26;
    if (hasUppercase(password)) result.poolSize += 26;
    if (hasDigit(password))     result.poolSize += 10;
    if (hasSpecialChar(password)) result.poolSize += 32;

    return result;
}

// Explains what the entropy number actually means, in plain English
string explainEntropy(double entropyBits)
{
    string label = classifyComplexity(entropyBits);

    if (label == "Very Low")
    {
        return "Entropy measures unpredictability. This password has very "
               "little randomness, so an attacker's software could guess "
               "it in a very short amount of time.";
    }
    else if (label == "Low")
    {
        return "Entropy measures unpredictability. This password has low "
               "randomness. It would likely fall to an automated cracking "
               "tool without much effort.";
    }
    else if (label == "Medium")
    {
        return "Entropy measures unpredictability. This password has a "
               "moderate amount of randomness - reasonable for everyday "
               "use, but not ideal for protecting sensitive accounts.";
    }
    else if (label == "High")
    {
        return "Entropy measures unpredictability. This password has a "
               "high amount of randomness, making it resistant to most "
               "automated guessing attacks.";
    }
    else
    {
        return "Entropy measures unpredictability. This password has a "
               "very high amount of randomness, making it extremely "
               "resistant to brute-force and dictionary attacks.";
    }
}

// Converts a number of seconds into a readable duration string
string formatDuration(double seconds)
{
    if (seconds < 1.0)
    {
        return "Instantly";
    }

    const double MINUTE = 60.0;
    const double HOUR = 3600.0;
    const double DAY = 86400.0;
    const double YEAR = DAY * 365.25;
    const double MILLION_YEARS = YEAR * 1000000.0;

    ostringstream oss;
    oss << fixed << setprecision(1);

    if (seconds < MINUTE)
    {
        oss << seconds << " seconds";
    }
    else if (seconds < HOUR)
    {
        oss << (seconds / MINUTE) << " minutes";
    }
    else if (seconds < DAY)
    {
        oss << (seconds / HOUR) << " hours";
    }
    else if (seconds < YEAR)
    {
        oss << (seconds / DAY) << " days";
    }
    else if (seconds < MILLION_YEARS)
    {
        oss << (seconds / YEAR) << " years";
    }
    else
    {
        oss << (seconds / MILLION_YEARS) << " million years";
    }

    return oss.str();
}

// Estimates crack time under each simulated attack type.
//
// Guess speeds used (guesses per second) - these are simplified,
// commonly cited educational figures:
//   Online attack      : 10           (rate-limited login form)
//   Offline attack      : 1,000,000,000 (1 billion, fast offline hashing)
//   GPU attack           : 10,000,000,000 (10 billion, dedicated GPU rig)
//   Dictionary attack    : instant if the password is a known/common
//                           word, otherwise treated like a slow guess
//   Hybrid attack        : faster than brute force if based on a
//                           dictionary word with small mutations
//   Brute force attack   : same speed as the offline attack, but
//                           always searches the FULL character space
CrackTimeEstimates estimateCrackTimes(double entropyBits, bool isDictionaryWord, bool isCommonPassword)
{
    CrackTimeEstimates estimates;

    double totalCombinations = pow(2.0, entropyBits);

    // On average, an attacker finds the password after searching
    // about half of the total search space.
    double averageCombinations = totalCombinations / 2.0;

    // ---- Online attack (throttled login form, ~10 guesses/sec) ----
    double onlineSeconds = averageCombinations / 10.0;
    estimates.onlineAttack = formatDuration(onlineSeconds);

    // ---- Offline attack (fast hash cracking, ~1 billion/sec) ----
    double offlineSeconds = averageCombinations / 1000000000.0;
    estimates.offlineAttack = formatDuration(offlineSeconds);

    // ---- GPU attack (dedicated rig, ~10 billion/sec) ----
    double gpuSeconds = averageCombinations / 10000000000.0;
    estimates.gpuAttack = formatDuration(gpuSeconds);

    // ---- Dictionary attack ----
    if (isCommonPassword)
    {
        // A password taken straight from a common password list would
        // be one of the very first guesses tried.
        estimates.dictionaryAttack = "Instantly (found in common password list)";
    }
    else if (isDictionaryWord)
    {
        estimates.dictionaryAttack = "Seconds (based on a known dictionary word)";
    }
    else
    {
        // Not a dictionary word, so a pure dictionary attack would
        // eventually have to fall back to guessing randomly.
        double dictionarySeconds = averageCombinations / 100000.0;
        estimates.dictionaryAttack = formatDuration(dictionarySeconds);
    }

    // ---- Hybrid attack (dictionary word + common mutations) ----
    if (isDictionaryWord || isCommonPassword)
    {
        estimates.hybridAttack = "Minutes (dictionary word with simple mutations)";
    }
    else
    {
        double hybridSeconds = averageCombinations / 10000000.0;
        estimates.hybridAttack = formatDuration(hybridSeconds);
    }

    // ---- Brute force attack (always tries the full search space) ----
    double bruteForceSeconds = averageCombinations / 1000000000.0;
    estimates.bruteForceAttack = formatDuration(bruteForceSeconds);

    return estimates;
}
