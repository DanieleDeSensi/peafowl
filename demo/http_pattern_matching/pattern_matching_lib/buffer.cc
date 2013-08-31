/* -*- C++ -*- */

#define _POSIX_C_SOURCE 1
#include <cstring>
#include "buffer.h"

namespace antivirus {

    using std::memmove;
    
    size_t const buffered_input::initial_buffer_size = 65536;
    
    buffered_input::buffered_input(istream &in)
        : _in(in),
          _position(_in.tellg()),
          _current_size(0),
          _maximum_size(initial_buffer_size),
          _current_position(0),
          _buffer((char *) malloc(_maximum_size))
    {
    }

    buffered_input::~buffered_input() {
        free(_buffer);
    }

    void
    buffered_input::read_buffer() {
        if (!_in) {
            return;
        }
        
        _in.read(_buffer, _maximum_size);
        _current_size = _in.gcount();
        _current_position = 0;
    }

    bool
    buffered_input::read_ahead(size_t count) {
        using namespace std;
        
        if (_current_position + count < _current_size) {
            return true;
        }

        if (_current_position > 0) {
            memmove(_buffer, _buffer + _current_position,
                    _current_size - _current_position);
            _current_size -= _current_position;
            _current_position = 0;
        }

        if (_current_position + count > _maximum_size) {
            _maximum_size = _current_position + count + 1;
            char *temp = (char *) realloc(_buffer, _maximum_size);
            assert(temp);
            _buffer = temp;
        }

        if (!_in) {
            return false;
        }
        
        _in.read(_buffer + _current_size, _maximum_size - _current_size);
        _current_size += _in.gcount();
        return _current_position + count < _current_size;
    }
}
