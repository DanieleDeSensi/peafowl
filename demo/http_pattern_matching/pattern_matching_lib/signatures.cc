/* -*- C++ -*- */

/*
 * Open a signature file (ZIP archive) and read all the
 * signatures.
 */

#define _POSIX_C_SOURCE 1
#include <cctype>
#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <iomanip>
//#include <cstdlib>
#include "signatures.h"

namespace antivirus {
    
    char const *virus_signatures_archive_name = "VirusSignatures.credo";
    char const *virus_signatures_file_name = "virussignatures.strings";
    
    bool
    signature_reader::read_name() {
        return static_cast<bool>(getline(_input, _current_name, '='));
    }

    template <typename T> static inline bool
    is_even(T n) {
        return (n % 2) == 0;
    }
    
    bool
    signature_reader::read_pattern() {
        string hex_encoded;
        getline(_input, hex_encoded, '\n');
        if (_input.fail()) {
            return false;
        }
        if (!is_even(hex_encoded.size())) {
            return false;
        }
        _current_pattern.clear();
        _current_pattern.reserve(hex_encoded.size() / 2);
        for (string::size_type i = 0; i < hex_encoded.size() / 2; i++) {
            char s[3];
            s[0] = hex_encoded.at(2 * i);
            s[1] = hex_encoded.at(2 * i + 1);
            s[2] = '\0';
            long value = strtol(s, NULL, 16);
            _current_pattern += (char) value;
        }
        return true;
    }

    bool
    signature_reader::next()
    {
        return read_name() && read_pattern();
    }
}

#ifdef TEST
using namespace antivirus;

int
main(int argc, char **argv) {
    using namespace std;
    
    ifstream input;

    if (argc == 2) {
        virus_signatures_file_name = argv[1];
    }
    input.open(virus_signatures_file_name);
    if (!input) {
        cerr << argv[0] << ": failed to open '" << virus_signatures_file_name
             << "'\n";
        exit(EXIT_FAILURE);
    }

    cout.fill('0');
    cout.setf(ios_base::hex, ios_base::basefield);
    
    signature_reader reader(input);
    while (reader.next())
    {
        cout << reader.current_name() << '=';
        string const &pattern = reader.current_pattern();
        for (string::const_iterator it = pattern.begin();
             it < pattern.end();
             it++)
        {
            cout << *it;
//             cout << setw(2) << (unsigned) *it;
        }
        cout << endl;
    }

    exit(EXIT_SUCCESS);
}
#endif
