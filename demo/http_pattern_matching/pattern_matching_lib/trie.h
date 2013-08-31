/* -*- C++ -*- */

/**
 * @file trie.h
 *
 * Implementation of a pattern matcher using a trie and the associated
 * scanners.
 */

#ifndef TRIE_H
#define TRIE_H

#include <limits>
#include <list>
#include <istream>
#include <ostream>
#include <string>
#include <utility>
#include <vector>
#include "buffer.h"


/**
 * The antivirus namespace.
 */
namespace antivirus {

    using std::list;
    using std::ostream;
    using std::pair;
    using std::streamoff;
    using std::string;
    using std::vector;

    class node;
    class stream_scanner;
    class byte_scanner;

    /**
     * Used to store the transition function.  The vector is indexed
     * by bytes data being scanned.
     */
    typedef vector<node *> node_vector;

    /**
     * The number of child nodes for each node in the trie.
     */
    node_vector::size_type const NODE_CHILD_COUNT
        = std::numeric_limits<char>::max() - std::numeric_limits<char>::min() + 1;

    /**
     * The default maximum depth of the trie.
     */
    string::size_type const DEFAULT_TRIE_MAXIMUM_DEPTH = 5;

    /**
     * The trie class implements a modified version of the
     * Aho/Corasick pattern matching algorithm.  The trie is somewhat
     * similar to a <code>map</code>.  However, lookup of data in the
     * trie is done by scanning a stream of input bytes.  Whenever the
     * stream matches one of the patterns (keys) a callback is made to
     * a user supplied function.  See <code>stream_scanner</code> and
     * <code>byte_scanner</code> for two different ways to
     * scan data.
     *
     * The trie only stores the first <code>maximum_depth</code> bytes
     * of every pattern in the tree to reduce the memory usage.  The
     * rest of the pattern is matches using normal memory comparison
     * functions.
     */
    class trie {
        friend class antivirus::stream_scanner;
        friend class antivirus::byte_scanner;
    public:
        /**
         * The type of patterns.
         */
        typedef string key_type;

        /**
         * The type of the data associated with each pattern.
         */
        typedef string mapped_type;

        /**
         * The type for defining a mapping from key_type to
         * mapped_type.
         */
        typedef pair<key_type, mapped_type> value_type;

        /**
         * Construct a new trie.
         */
        explicit trie(string::size_type maximum_depth
                      = DEFAULT_TRIE_MAXIMUM_DEPTH);

        /**
         * Destruct a trie.
         */
        ~trie();

        /**
         * Insert a new pattern into the trie.  The key and the mapped
         * data are copied and stored in the trie.
         */
        void insert(value_type const &val);

        /**
         * Prepare the trie for matching patterns.  Before a trie is
         * prepared no scanning can take place using the trie.  After
         * a trie is prepared no new patterns can be inserted into the
         * trie.
         */
        void prepare();

        /**
         * Is the trie prepared?
         */
        bool is_prepared() const { return _prepared; }

        /**
         * The maximum depth of the trie as specified on construction.
         */
        string::size_type maximum_depth() const { return _maximum_depth; }

        /**
         * The number of nodes allocated in the trie so far.
         */
        node_vector::size_type node_count() const {
            return _allocated_nodes.size();
        }

        /**
         * Dump a text representation of the internal trie structure
         * to <code>out</code>.
         */
        void dump(ostream &out);

    private:
        string::size_type _maximum_depth;
        node *_root;
        bool _prepared;
        node_vector _allocated_nodes;

        void create_failure_transitions();
        void create_fast_transitions(node *start);
        void dump(ostream &out, node *start, unsigned c);
        node *allocate_node(node *parent);

        // Disallow copying.
        trie(trie const &rhs);
        trie &operator=(trie const &rhs);
    };

    /**
     * Type of callback functions.
     */
    typedef void (*match_callback_type)(string::size_type position,
                                        trie::value_type const &val);

    /**
     * Callback function that ignores any match.
     */
    void ignore_match(string::size_type position, trie::value_type const &val);

    
    /**
     * Use a trie to scan an <code>istream</code> for patterns.  The
     * <code>istream</code> is fully consumed during the scan.
     */
    class stream_scanner {
    public:
        /**
         * Construct a byte scanner that scans using <code>trie</code>
         * and <code>in</code>, calling <code>callback</code> whenever
         * a pattern matches.
         */
        stream_scanner(trie const &trie, istream &in,
                       match_callback_type callback = ignore_match);

        /**
         * Destruct the stream_scanner.  The user is responsible for
         * destructing the associated <code>trie</code> and
         * <code>istream</code>.
         */
        ~stream_scanner() {}

        /**
         * Read the input stream and call the callback for every
         * pattern matched.  The input stream is fully consumed by
         * this member function.
         */
        void match();
        
        /**
         * The number of bytes scanned.
         */
        streamoff byte_count() const { return _byte_count; }

        /**
         * The number of patterns matched.
         */
        unsigned match_count() const { return _match_count; }
        
        /**
         * The number of patterns matched using only the trie.  For
         * patterns that contain more bytes than the maximum depth of
         * the trie additional memory matching is done before a full
         * match is found.  This member function is for debugging
         * purposes only.
         */
        unsigned match_count_tries() const { return _match_count_tries; }
        
    private:
        trie const &_trie;
        istream &_in;
        streamoff _byte_count;
        unsigned _match_count;
        unsigned _match_count_tries;
        match_callback_type _callback;
        
        void try_match(buffered_input &in,
                       trie::value_type const &val,
                       size_t position);
        
        // Disallow copying.
        stream_scanner(stream_scanner const &rhs);
        stream_scanner &operator=(stream_scanner const &rhs);
    };

    /**
     * Use a trie to scan for patterns a byte at a time.
     */
    class byte_scanner {
    public:
        /**
         * Construct a byte scanner that scans using <code>trie</code>
         * and calls <code>callback</code> whenever a pattern matches.
         */
        explicit byte_scanner(trie const &trie, match_callback_type callback = ignore_match);

        /**
         * Destruct a byte_scanner.  The associated trie must be
         * separately destructed by the user.
         */
        ~byte_scanner() {}

        /**
         * The number of bytes scanned so far.
         */
        streamoff byte_count() const { return _byte_count; }

        /**
         * The number of patterns matched so far.
         */
        unsigned match_count() const { return _match_count; }

        /**
         * The number of patterns matched using only the trie.  For
         * patterns that contain more bytes than the maximum depth of
         * the trie additional memory matching is done before a full
         * match is found.  This member function is for debugging
         * purposes only.
         */
        unsigned match_count_tries() const { return _match_count_tries; }

        /**
         * Used for debugging.
         */
        unsigned potential_match_iterations() const { return _potential_match_iterations; }

        /**
         * Match the next byte.  If a pattern matches the callback
         * specified on construction is invoked.
         */
        void match(char ch);
    private:
        class potential_match {
        public:
            explicit potential_match(byte_scanner *scanner,
                                     trie::value_type const &match,
                                     string::size_type position)
                : _scanner(scanner),
                  _match(match),
                  _start_position(position),
                  _current_position(scanner->_trie.maximum_depth())
                {}
            ~potential_match() {}
            
            bool match(char ch);
        private:
            byte_scanner *_scanner;
            trie::value_type const &_match;
            string::size_type _start_position;
            string::size_type _current_position;
            
            // Disallow copying.
            potential_match(potential_match const &rhs);
            potential_match &operator=(potential_match const &rhs);
        };
        
        trie const &_trie;
        node const *_current;
        unsigned _match_count;
        unsigned _match_count_tries;
        std::streamoff _byte_count;
        unsigned _potential_match_iterations;
        list<potential_match *> _potential_matches;
        match_callback_type _callback;
        
        // Disallow copying.
        byte_scanner(byte_scanner const &rhs);
        byte_scanner &operator=(byte_scanner const &rhs);
    };
}

#endif /* TRIE_H */
