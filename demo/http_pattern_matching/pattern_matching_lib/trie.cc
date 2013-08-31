/* -*- C++ -*- */

#define _POSIX_C_SOURCE 1
#include <algorithm>
#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>
#include "signatures.h"
#include "timer.h"
#include "trie.h"

namespace antivirus {

    using std::invalid_argument;
    
    class node {
    public:
        typedef vector<trie::value_type> match_vector;

        explicit node(node *parent);
        ~node() {}
        
        unsigned id() const { return _id; }
        node *parent() const { return _parent; }
        
        node *next(char c) const {
            return _next.at((unsigned char) c);
        }
        void next(char c, node *next) {
            _next.at((unsigned char) c) = next;
        }
        
        node *fail() const { return _fail; }
        void fail(node *fail) { _fail = fail; }
        
        bool is_final() const { return !_matches.empty(); }
        
        match_vector const &matches() const {
            return _matches;
        }
        void add_match(trie::value_type const &val) {
            _matches.push_back(val);
        }
        void add_matches(match_vector const &matches) {
            _matches.insert(_matches.end(), matches.begin(), matches.end());
        }
        unsigned depth() {
            return _parent ? _parent->depth() + 1 : 0;
        }
    private:
        static unsigned _count;
        
        unsigned const _id;
        match_vector _matches;
        node *_parent;
        node *_fail;
        node_vector _next;
    };
        
    unsigned node::_count = 0;
    
    node::node(node *parent)
        : _id(_count++),
          _matches(),
          _parent(parent),
          _fail(0),
          _next(NODE_CHILD_COUNT)
    {
        for (node_vector::size_type i = 0; i < _next.size(); i++) {
            _next.at(i) = 0;
        }
    }
        
    trie::trie(string::size_type maximum_depth)
        : _maximum_depth(maximum_depth),
          _prepared(false)
    {
    	_root=allocate_node(0);
        _allocated_nodes.push_back(_root);
    }
    
    trie::~trie() {
        for (node_vector::iterator it = _allocated_nodes.begin();
             it < _allocated_nodes.end();
             it++)
        {
            delete *it;
        }
    }
    
    void
    trie::insert(value_type const &val) {
        string const &pattern = val.first;
        string::size_type prefix_size
            = std::min(pattern.size(), _maximum_depth);
        node *current = _root;
        for (string::size_type i = 0; i < prefix_size; i++)
        {
            node *next = current->next(pattern.at(i));
            if (next == 0) {
                next = allocate_node(current);
                current->next(pattern.at(i), next);
            }
            current = next;
        }
        current->add_match(val);
    }

    void
    trie::create_failure_transitions() {
        using std::vector;
        
        node_vector *bfs = new node_vector();  // Nodes in BFS order.
        
        for (unsigned c = 0; c < NODE_CHILD_COUNT; c++) {
            node *next = _root->next(c);
            if (next) {
                next->fail(_root);
                bfs->push_back(next);
            }
        }

        while (!bfs->empty()) {
            node_vector *bfs_next = new vector<node *>();
            for (node_vector::const_iterator it = bfs->begin();
                 it < bfs->end(); it++)
            {
                node *parent = *it;
                for (unsigned c = 0; c < NODE_CHILD_COUNT; c++) {
                    node *next = parent->next(c);
                    if (next) {
                        bfs_next->push_back(next);
                        node *fail = parent->fail();
                        while (fail && !fail->next(c)) {
                            fail = fail->fail();
                        }

                        if (fail) {
                            next->fail(fail->next(c));
                            if (next->fail()->is_final()) {
                                next->add_matches(next->fail()->matches());
                            }
                        } else {
                            next->fail(_root->next(c));
                        }
                    }
                }
            }

            delete bfs;
            bfs = bfs_next;
        }

        delete bfs;
    }

// Returns 'ptr' if not null, otherwise 'def' is returned.
    template <typename T> inline T*
    coalesce(T *ptr, T *def) {
        return ptr ? ptr : def;
    }
    
/*
 * Create transitions taking into account the failure nodes of
 * each node. This saves a bit of work in the matching phase.
 */
    void
    trie::create_fast_transitions(node *n) {
        for (unsigned c = 0; c < NODE_CHILD_COUNT; c++) {
            node *next = n->next(c);
            if (next) {
                create_fast_transitions(next);
            } else {
                node *q = n;
                do {
                    q = q->fail();
                } while (q && !q->next(c));
                n->next(c, (q ? q->next(c) : coalesce(_root->next(c), _root)));
            }
        }
    }
    
    void
    trie::prepare() {
        create_failure_transitions();
        create_fast_transitions(_root);
        _prepared = true;
    }

    void
    trie::dump(ostream &out, node *start, unsigned c) {
        using namespace std;
        
        if (start) {
            out << start->id() << "(" << hex << c << dec << "): ";
            for (node *parent = start->parent();
                 parent;
                 parent = parent->parent())
            {
                out << parent->id() << " ";
            }
            out << ", fail = ";
            if (start->fail()) {
                out << start->fail()->id();
            } else {
                out << "FAIL";
            }
            if (start->is_final()) {
                out << ", matches = ";
                node::match_vector matches = start->matches();
                for (node::match_vector::const_iterator it
                         = matches.begin();
                     it < matches.end();
                     it++)
                {
                    cout << it->second << " ";
                }
            }
            out << endl;
            for (unsigned c = 0; c < NODE_CHILD_COUNT; c++) {
                if (start->depth() < start->next(c)->depth()) {
                    dump(out, start->next(c), c);
                }
            }
        }
    }
    
    void
    trie::dump(ostream &out) {
        dump(out, _root, ' ');
    }

    node *
    trie::allocate_node(node *parent) {
        node *result = new node(parent);
        _allocated_nodes.push_back(result);
        return result;
    }

    void ignore_match(string::size_type, trie::value_type const &) {
        // Ignore match.
    }
    
    stream_scanner::stream_scanner(trie const &trie, istream &in,
                                   match_callback_type callback)
        : _trie(trie),
          _in(in),
          _byte_count(0),
          _match_count(0),
          _match_count_tries(0),
          _callback(callback)
    {
        if (!_trie.is_prepared()) {
            throw invalid_argument("stream_scanner: trie is not prepared");
        }
        if (!callback) {
            throw invalid_argument("stream_scanner: callback is null");
        }
    }
    
    void
    stream_scanner::match() {
        buffered_input in(_in);
        
        _byte_count = 0;
        _match_count = 0;
        _match_count_tries = 0;
        node *current = _trie._root;
        char c;
        while (in.get(c)) {
            ++_byte_count;
            current = current->next(c);
            if (current->is_final()) {
                node::match_vector const &matches
                    = current->matches();
                for (node::match_vector::const_iterator it
                         = matches.begin();
                     it < matches.end();
                     it++)
                {
                    try_match(in, *it, in.position() - current->depth());
                }
            }
        }
    }

    void
    stream_scanner::try_match(buffered_input &in,
                              trie::value_type const &val,
                              size_t position)
    {
        _match_count_tries++;
        
        string const &pattern = val.first;
        if (pattern.size() <= _trie._maximum_depth) {
            _match_count++;
            _callback(position, val);
            return;
        }


        if (!in.read_ahead(pattern.size() - _trie._maximum_depth)) {
            return;
        }
        
        bool match = true;
        for (size_t pos = _trie._maximum_depth; pos < pattern.size(); pos++)
        {
            if (pattern.at(pos) != in.look_ahead(pos - _trie._maximum_depth)) {
                match = false;
                break;
            }
        }
        if (match) {
            _match_count++;
            _callback(position, val);
        }
    }

    byte_scanner::byte_scanner(trie const &trie, match_callback_type callback)
        : _trie(trie), _current(_trie._root),
          _match_count(0), _match_count_tries(0),
          _byte_count(0), _potential_match_iterations(0),
          _potential_matches(), _callback(callback)
    {
        if (!_trie.is_prepared()) {
            throw invalid_argument("byte_scanner: trie is not prepared");
        }
        if (!callback) {
            throw invalid_argument("byte_scanner: callback is null");
        }
    }
    
    inline bool
    byte_scanner::potential_match::match(char ch) {
        string const &pattern = _match.first;
        if (ch != pattern.at(_current_position)) {
            return true;
        }
        ++_current_position;
        if (_current_position >= pattern.size()) {
            _scanner->_match_count++;
            _scanner->_callback(_start_position, _match);
            return true;
        }
        return false;
    }

    void
    byte_scanner::match(char ch) {
        ++_byte_count;
        
        if (!_potential_matches.empty()) {
            list<potential_match *>::iterator it = _potential_matches.begin();
            while (it != _potential_matches.end()) {
                ++_potential_match_iterations;
                if ((*it)->match(ch)) {
                    delete *it;
                    it = _potential_matches.erase(it);
                } else {
                    it++;
                }
            }
        }
        
        _current = _current->next(ch);
        
        if (_current->is_final()) {
            node::match_vector const &matches
                = _current->matches();
            for (node::match_vector::const_iterator it
                     = matches.begin();
                 it != matches.end();
                 it++)
            {
                _match_count_tries++;
                
                trie::value_type const &match = *it;
                string const &pattern = match.first;
                
                if (pattern.size() <= _trie._maximum_depth) {
                    _match_count++;
//XXX                     callback->found(_byte_count - pattern.size());
                } else {
                    _potential_matches.push_back(
                        new potential_match(
                            this,
                            match,
                            _byte_count - _trie._maximum_depth));
                }
            }
        }
    }
}
