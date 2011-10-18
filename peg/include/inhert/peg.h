/**** *****************************************************************************
 *
 * INHERT.PEG Generator Library
 *
 * 	 PEG: Parsing Expression Grammer
 ***************************************************************************** ****/
#if !defined INHERT_PEG_INCLUDED
#define      INHERT_PEG_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

#if defined _WIN32
#  define __func__ __FUNCTION__
#endif

#if __STDC_VERSION__==199901L || 1200<_MSC_VER
#  define WARN(...)    WARN_I(__VA_ARGS__)
#  define WARN_I(...)  err_printf(__FILE__, __LINE__, __func__, __VA_ARGS__)
#else /* not support variadic macro */
#  define WARN         err_printf_row("%10s:%5d [%-20s] > ", __FILE__, __LINE__, __func__), \
		               err_printf_row
#endif

#define NOTIMPL   WARN("not implement yet... \n")

#define ASSERT(expr, str) ASSERT_I(expr, str)
#define ASSERT_I(expr, str)                  \
	do {                                     \
		bool const pp_cond_tmp_ = (expr);    \
		if (!pp_cond_tmp_) {                 \
			WARN("%s", str);                 \
			assert(false);                   \
		}                                    \
	} while (0)

typedef enum { false=0, true } bool;

#define NUM_OF_PEG_TYPE 11

//// type

typedef
	enum peg_type {		// kind of match
		PEG_NEGATIVE=0,	// x <- !A
		PEG_AND,        // x <- &A
		PEG_SEQ,        // x <- A B
		PEG_EXISTS,     // x <- A?
		PEG_PLUS,       // x <- A+
		PEG_REPEAT,     // x <- A*
		PEG_ANY,        // x <- .
		PEG_CLASS,      // x <- [a-z]
		PEG_CHOICE,		// x <- A / B / C
		PEG_IDENT,      // e.g. Expr, Term, Factor(nonterminal symbol)
		PEG_PATTERN     // e.g. "foobar", "template", "extends"(terminal symbol)
	}
PEG_KIND;

struct peg_rule;
struct peg_rule_bin;
typedef struct peg_rule PegRule;

struct peg_rule {
	PEG_KIND kind; // type tag specify type of body(:union)
	union {
		char * str;                 // specified with string
		struct peg_rule     * ref;  // have an alternative
		struct peg_rule_bin * refs; // have more than one alternatives
	} body;
};
struct peg_rule_bin {
	struct peg_rule     * ref;
	struct peg_rule_bin * next;
};
typedef struct peg_rule_bin peg_rule_bin;

typedef
	struct named_peg_rule_ {
		char * name;    // assert(name)
		PegRule * rule;
	}
NamedPegRule;

struct parsed_string_;
typedef struct parsed_string_ ParsedString;
struct parsed_string_bin_;
typedef struct parsed_string_bin_ ParsedStringBin;

/***
 * ::parsed_string_
 * ::parsed_string_bin_
 *
 * <parsed_string_>
 * +------+
 * | Rule +--------------- ('m'atched 'str')
 * +-+----+       +----------+-----------------------+
 *   |            |                                  |
 *   |            +====+    +====+    +====+    +====+  
 *   +- (nest) -> | R  | -> | R  | -> | R  | -> | R  |  
 *                +====+    +====+    +====+    +====+
 *              [sub-rule]                 <parsed_string_bin_>
 * ***/

struct parsed_string_ {
	char    * ident; // Maybe name(of rule)
	PegRule * rule;
	char    * mstr; // matched string
	// result of parsing for each parts of `rule`
	ParsedStringBin * nest;
};
struct parsed_string_bin_ {
	ParsedString    * ps;
	ParsedStringBin * next;
};

/****
 * Cache Table Concept
 *
 * type :
 *   E = Parsed (| LR)
 *   RowE = [# size, E*]
 *   MaybeRowE = RowE*
 *   Table = ([# NamedPegRule], [# MaybeRowE])
 *
 * e.g.
 *           +----------- table->size ---------------+
 *           |                                       |
 *   +-------+----+----+----+----+----+----+----+----+
 *   |   /   |  3 |  * |  ( |  2 |  + |  4 |  ) | \0 |
 *   +-------+----+----+----+----+----+----+====+----+
 *   | add   |    |    |    |    |    |    | / /|    |
 *   +-------+----+----+----+----+----+----|/ / |----+    +-----------------------+
 *   | mul   |    |    |    |    |    |    | / /|  +----> | [ParsedString (| LR)] |
 *   +-------+----+----+----+----+----+----|/ / |----+    +-----------------------+
 *   | prim  |    |    |    |    |    |    | / /|    |
 *   +-------+----+----+----+----+----+----|/ / |----+
 *   | deci  |    |    |    |    |    |    | / /|    |
 *   +-------+----+----+----+----+----+----+=+==+----+
 *                                           |    [row_cache_table]
 *                                           |    +-------------------------+
 *                                           +--> | add | mul | prim | deci |
 *                                                +-------------------------+
 * ****/

// cache entry for result of parsing
typedef
	struct cache_elem_ {
		ParsedString * result_tree; // Maybe ParseResult
	}
cache_elem;

// row of cache table
typedef
	struct row_cache_table_ {
		size_t size;
		cache_elem ** es;
	}
row_cache_table;

/**
 * row_cache *  = Maybe row_cache
 * row_cache ** = [# Maybe row_cache]
 */
typedef
	struct cache_table_ {
		size_t size;        // == strlen(str) == count(rs)
		row_cache_table ** rs;
//		char const * str;	// use cache table with outer string
	}
PegCacheTable;

typedef
	struct peg_parser_ {
		size_t size;
		NamedPegRule ** nps;
	}
PegParser;

// weak reference to a string
typedef struct substring_ {
	char const * str;
	size_t len;
} substring;

typedef
	ParsedString * (*peg_parser) (PegParser const *, PegRule const *, char const *, PegCacheTable);


/// synonym
extern peg_rule_bin * (* const cons_peg_rule)(PegRule *, peg_rule_bin *);

// ctor
PegRule      * make_peg_rule(PEG_KIND kind, void * body);
peg_rule_bin * make_peg_rule_bin (PegRule * ref, peg_rule_bin * next);
NamedPegRule * make_named_peg_rule(char const * name, PegRule * rule);
PegParser * make_peg_parser(void);

// dtor
void free_parsed_string(ParsedString    * ps);
void free_peg_parser(PegParser * p);
void free_peg_rule(PegRule * pr);

// register a rule to a set of parsers
bool push_back_peg_parser(PegParser * p, NamedPegRule * npr);

// pretty printer
void print_peg_rule(PegRule const * pr);
void print_named_peg_rule (NamedPegRule const * npr);
void print_parsed_string(ParsedString const * ps);

// parse str with pegs
ParsedString * peg_parse_string(PegParser const * pegs, char const * str);

//// basis parsers provided by default
PegRule * peg_alphabet  (void);
PegRule * peg_digit     (void);
PegRule * peg_alphadigit(void);

// debug printer
void err_printf_row(char const * format, ...);
void err_printf(char const * file, int line, char const * func, char const * format, ...);

#endif    /* INHERT_PEG_INCLUDED */

