/*
    ============================================================
    HIBP.CPP
    ============================================================
    See HIBP.h for an overview. Section 1 (SHA-1) is copied over
    from the original Password Guardian project without any
    changes to the actual algorithm - it still works exactly the
    same way. Section 2 (the breach check) keeps the same
    k-Anonymity logic, with a more detailed report printed at
    the end.
    ============================================================
*/

#include "HIBP.h"
#include "Utils.h"
#include <iostream>
#include <cstdio>
#include <sstream>

#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif

using namespace std;

/*
    ============================================================
    SECTION 1: SHA-1 IMPLEMENTATION (PURE C++, UNCHANGED LOGIC)
    ============================================================
    The Have I Been Pwned API needs a SHA-1 hash of the
    password before it can check it against breach data.
    This is a simple, from-scratch SHA-1 implementation.
    No external libraries are used.
    ============================================================
*/

// Left-rotate a 32-bit number by "bits" positions.
// SHA-1 uses this operation many times during hashing.
unsigned int leftRotate(unsigned int value, unsigned int bits)
{
    return (value << bits) | (value >> (32 - bits));
}

// Takes a normal text password and returns its SHA-1 hash
// as an uppercase hex string (this is what the HIBP API wants).
string sha1Hash(const string& input)
{
    // Initial hash values (fixed constants defined by the SHA-1 standard)
    unsigned int h0 = 0x67452301;
    unsigned int h1 = 0xEFCDAB89;
    unsigned int h2 = 0x98BADCFE;
    unsigned int h3 = 0x10325476;
    unsigned int h4 = 0xC3D2E1F0;

    // ---- Step 1: Pre-processing (padding the message) ----
    string message = input;
    unsigned long long originalBitLength = (unsigned long long)message.size() * 8;

    // Append a single '1' bit (as byte 0x80)
    message += (char)0x80;

    // Pad with '0' bits until length in bytes is congruent to 56 mod 64
    while (message.size() % 64 != 56)
    {
        message += (char)0x00;
    }

    // Append original length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; i--)
    {
        char byte = (char)((originalBitLength >> (i * 8)) & 0xFF);
        message += byte;
    }

    // ---- Step 2: Process the message in 512-bit (64-byte) chunks ----
    for (size_t chunkStart = 0; chunkStart < message.size(); chunkStart += 64)
    {
        unsigned int w[80];

        // Break chunk into sixteen 32-bit big-endian words
        for (int i = 0; i < 16; i++)
        {
            int base = (int)chunkStart + i * 4;
            w[i] = ((unsigned char)message[base] << 24) |
                ((unsigned char)message[base + 1] << 16) |
                ((unsigned char)message[base + 2] << 8) |
                ((unsigned char)message[base + 3]);
        }

        // Extend the sixteen words into eighty words
        for (int i = 16; i < 80; i++)
        {
            w[i] = leftRotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        // Initialize working variables for this chunk
        unsigned int a = h0;
        unsigned int b = h1;
        unsigned int c = h2;
        unsigned int d = h3;
        unsigned int e = h4;

        // Main SHA-1 compression loop (80 rounds)
        for (int i = 0; i < 80; i++)
        {
            unsigned int f, k;

            if (i < 20)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (i < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            unsigned int temp = leftRotate(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = leftRotate(b, 30);
            b = a;
            a = temp;
        }

        // Add this chunk's result into the running hash values
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // ---- Step 3: Combine the five hash values into one hex string ----
    char result[41];
    sprintf_s(result, sizeof(result), "%08X%08X%08X%08X%08X",
        h0, h1, h2, h3, h4);

    return string(result);
}

/*
    ============================================================
    SECTION 2: HAVE I BEEN PWNED BREACH CHECK (k-ANONYMITY)
    ============================================================
    Steps:
      1. Hash the password using SHA-1
      2. Take the first 5 characters of the hash (the "prefix")
      3. Send only the prefix to the API using curl
      4. The API returns a list of hash suffixes that share
         that prefix, along with how many times each has
         appeared in known data breaches
      5. Search locally for our password's suffix in that list
      This way, the full password hash is NEVER sent over
      the internet - only the first 5 characters are shared.
    ============================================================
*/

// Runs a system command and returns its console output as a string.
// This is how we call "curl" and capture what it prints.
string runSystemCommand(const string &command)
{
    string result = "";
    char buffer[256];

    // popen runs the command and lets us read its output like a file
    FILE *pipe = popen(command.c_str(), "r");

    if (!pipe)
    {
        return "ERROR";
    }

    while (fgets(buffer, sizeof(buffer), pipe) != NULL)
    {
        result += buffer;
    }

    pclose(pipe);
    return result;
}

// Sends only the hash prefix to the API and checks the response
// locally for our password's hash suffix.
BreachCheckResult checkPasswordAgainstHIBP(const string &password)
{
    BreachCheckResult breachResult;

    // Convert password to SHA-1 hash
    string fullHash = sha1Hash(password);

    // Split hash into prefix (sent to the API) and suffix (kept local)
    breachResult.hashPrefix = fullHash.substr(0, 5);
    breachResult.hashSuffix = fullHash.substr(5);

    // Build API URL and command
    string url = "https://api.pwnedpasswords.com/range/" + breachResult.hashPrefix;
    string command = "curl -s \"" + url + "\"";

    // Get API response
    string response = runSystemCommand(command);

    if (response.empty() || response == "ERROR")
    {
        breachResult.connectedSuccessfully = false;
        return breachResult;
    }

    breachResult.connectedSuccessfully = true;

    // Read response line by line, looking for our suffix
    stringstream ss(response);
    string line;

    while (getline(ss, line))
    {
        // Remove '\r' if present
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }

        size_t colon = line.find(':');

        if (colon != string::npos)
        {
            string apiSuffix = line.substr(0, colon);
            string count = line.substr(colon + 1);

            if (apiSuffix == breachResult.hashSuffix)
            {
                breachResult.foundInBreach = true;
                breachResult.occurrences = stoi(count);
                break;
            }
        }
    }

    return breachResult;
}

// Prints the full, upgraded breach report shown from the main menu.
void checkBreachDatabase()
{
    string password;

    cout << "\nEnter password to check: ";
    cin >> password;

    cout << "\n";
    printTitle("ONLINE BREACH REPORT");

    cout << "Checking password against the Have I Been Pwned database...\n\n";

    // ---- Privacy explanation (new) ----
    printSection("PRIVACY EXPLANATION");
    cout << "  Your full password is NEVER sent over the internet.\n";
    cout << "  Only the FIRST 5 CHARACTERS of its SHA-1 hash are sent.\n";
    cout << "  This is called the k-Anonymity model - the API returns\n";
    cout << "  every hash suffix that shares those 5 characters, and\n";
    cout << "  your password is only compared to that list locally.\n";

    // Loading animation (kept from the original project)
    cout << "\n";
    showLoadingStep("Connecting to server");
    showLoadingStep("Checking password");
    showLoadingStep("Please wait");

    BreachCheckResult result = checkPasswordAgainstHIBP(password);

    cout << "\n";
    printSection("CONNECTION DETAILS");
    printRow("SHA-1 Prefix Sent", COLOR_CYAN + result.hashPrefix + COLOR_RESET);
    printRow("Connection Status", result.connectedSuccessfully
                                       ? (COLOR_GREEN + string("Connected") + COLOR_RESET)
                                       : (COLOR_RED + string("Failed") + COLOR_RESET));

    if (!result.connectedSuccessfully)
    {
        cout << "\n" << COLOR_RED
             << "Could not connect to the Have I Been Pwned API."
             << COLOR_RESET << "\n";
        cout << "Please check your internet connection and try again.\n";
        printLine();
        return;
    }

    printSection("BREACH RESULT");

    if (result.foundInBreach)
    {
        printRow("Status", COLOR_RED + string("FOUND IN BREACH DATA") + COLOR_RESET);
        printRow("Occurrences", to_string(result.occurrences) + " times");

        printSection("RISK EXPLANATION");
        cout << "  This password has appeared in " << result.occurrences
             << " previously known data breaches.\n";
        cout << "  Attackers commonly use these breach lists directly, so\n";
        cout << "  this password should be treated as already compromised.\n";

        printSection("RECOMMENDATION");
        cout << "  " << COLOR_RED
             << "Change this password immediately on every account that uses it."
             << COLOR_RESET << "\n";
    }
    else
    {
        printRow("Status", COLOR_GREEN + string("NOT FOUND") + COLOR_RESET);

        printSection("RISK EXPLANATION");
        cout << "  This password was not found in the current breach database.\n";
        cout << "  This does NOT guarantee it is unbreakable - it simply has\n";
        cout << "  not appeared in a breach that has been reported so far.\n";

        printSection("RECOMMENDATION");
        cout << "  Continue following good password practices: keep it unique,\n";
        cout << "  store it in a password manager, and enable MFA where possible.\n";
    }

    printLine();
}
