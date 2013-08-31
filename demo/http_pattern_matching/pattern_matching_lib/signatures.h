/* -*- C++ -*- */

#ifndef SIGNATURES_H
#define SIGNATURES_H

#include <istream>
#include <string>

namespace antivirus {

    using std::istream;
    using std::string;
    
    /* Functions to read in a signature file.  */
    
    /**
     * The signature_reader is used to read in a virus signature file.
     * The virus signature file contains a single virus definition on
     * each line.  The line contains the name of the virus, followed
     * by an equals ('=') sign, followed by a hex-encoded byte stream.
     *
     * The user of signature_reader is responsible for initializing
     * and finalizing the associated <code>istream</code>.
     */
    class signature_reader {
    public:
        /**
         * Construct a new signature_reader from <code>input</code>.
         */
        explicit signature_reader(istream &input) : _input(input) {}
        
        /**
         * Destruct a signature_reader.  The user is responsible for
         * destructing the associated <code>istream</code>.
         */
        ~signature_reader() {}

        /**
         * Read the next virus signature.  If successful
         * <code>true</code> is returned and the name and signature of
         * the virus are availabe through the
         * <code>signature_reader::current_name</code> and
         * <code>signature_reader::current_pattern</code> member
         * functions.  Otherwise <code>false</code> is returned and no
         * more virus definitions are available.
         */
        bool next();

        /**
         * The name of the last virus read using the
         * <code>signature_reader::next</code> member function.
         */
        string const &current_name() const { return _current_name; }
        
        /**
         * The signature of the last virus read using the
         * <code>signature_reader::next</code> member function.  The
         * returned string should be treated as a binary byte array.
         */
        string const &current_pattern() const { return _current_pattern; }
    private:
        istream &_input;
        string _current_name;
        string _current_pattern;
        
        bool read_name();
        bool read_pattern();
    };
}

#endif /* SIGNATURES_H */
