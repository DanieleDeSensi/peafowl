/* -*- C++ -*- */

#ifndef BUFFER_H
#define BUFFER_H

#include <cassert>
#include <cstdlib>
#include <istream>
#include <stdexcept>

namespace antivirus {

    using std::istream;

    /**
     * Buffer the input from an <code>istream</code> to allow quick
     * character reading.  Arbitrary look-ahead is also supported.
     */
    class buffered_input {
    public:
        /**
         * Construct a new <code>buffered_input</code> from
         * <code>in</code>.  Reading from this
         * <code>buffered_input</code> will consume input from
         * <code>in</code>.
         */
        explicit buffered_input(istream &in);

        /**
         * Destruct this <code>buffered_input</code>.  The associated
         * <code>istream</code> is not destructed or closed.  This
         * must be done by the user of this class.
         */
        ~buffered_input();

        /**
         * Read a character from this <code>buffered_input</code>.  If
         * no more characters are available <code>false</code> is
         * returned.  Otherwise <code>true</code> is returned and the
         * read character is stored in <code>ch</code>.
         */
        bool get(char &ch) {
            if (_current_position >= _current_size) {
                read_buffer();
                if (_current_position >= _current_size) {
                    return false;
                }
            }
            ch = _buffer[_current_position];
            ++_current_position;
            ++_position;
            return true;
        }

        /**
         * Ensure at least <code>count</code> characters are avaible
         * for reading ahead.  If not enough characters are available
         * in the associated <code>istream</code> <code>false</code>
         * is returned.  Otherwise <code>true</code> is returned and
         * <code>count</code> characters are available for use with
         * <code>buffered_input::look_ahead</code>.
         */
        bool read_ahead(size_t count);

        /**
         * Look ahead <code>pos</code> characters.  Before calling
         * this method the <code>buffered_input::read_ahead</code>
         * method <em>must</em> be called with a <code>count</code>
         * that is greater than or equal to <code>pos</code>.
         * Multiple calls to this method are allowed for a single call
         * to <code>buffered_input::read_ahead</code> until more read
         * ahead is required or <code>buffered_input::get</code> is
         * called.
         *
         * @throws std::out_of_range fewer than <code>pos</code>
         * characters are available for look ahead
         */
        char look_ahead(size_t pos) {
            if (_current_position + pos < _current_size) {
                return _buffer[_current_position + pos];
            } else {
                throw std::out_of_range("buffered_input");
            }
        }

        /**
         * The current position in the <code>istream</code>.  This is
         * equal to the number of characters read so far.
         */
        size_t position() const {
            return _position;
        }
        
    private:
        void read_buffer();
        
        static size_t const initial_buffer_size;

        istream &_in;
        size_t _position;
        size_t _current_size;
        size_t _maximum_size;
        size_t _current_position;
        char  *_buffer;
    };
}

#endif /* BUFFER_H */
