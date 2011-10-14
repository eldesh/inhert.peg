/****
 *
 * INHERT.PEG Generator Library
 *
 * 	 PEG: Parsing Expression Grammer
 *                                                                             ****/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>

#define PP_STRINGIZE(s) PP_STRINGIZE_I(s)
#define PP_STRINGIZE_I(s) #s

#define WARN(...)    WARN_I(__VA_ARGS__)
#define WARN_I(...) (fprintf(stderr, "%10s:%5d [%-20s] > ", __FILE__, __LINE__, __func__), \
		             fprintf(stderr, __VA_ARGS__))

#define NOTIMPL   WARN("not implement yet... \n")

//#define LOG_HEAP
#define ALLOC(ty, n) ALLOC_I(ty, n)
#if defined LOG_HEAP
#  define ALLOC_I(ty, n) ((ty*)MALLOC_LOG(__FILE__, __LINE__, __func__, sizeof(ty) * (n)))
#  define free(p) FREE_LOG(__FILE__, __LINE__, __func__, p)
#else
#  define ALLOC_I(ty, n) ((ty*)malloc(sizeof(ty) * (n)))
#endif

#if defined LOG_HEAP
void * MALLOC_LOG(char const * file, int line, char const * func, size_t byte) {
	void * p = malloc(byte);
	fprintf(stderr, "%10s:%5d [%-20s] > alloc (%5d) (%p)\n", file, line, func, byte, p);
	return p;
}
void FREE_LOG(char const * file, int line, char const * func, void * p) {
	fprintf(stderr, "%10s:%5d [%-20s] > free (%p)\n", file, line, func, p);
	(free)(p);
}
#endif


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
		PEG_IDENT,      // Expr, Term, Factor(nonterminal symbol)
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
 * | Rule +--------------- (mstr)
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

typedef
	struct peg_parser_ {
		size_t size;
		NamedPegRule const ** nps;
	}
PegParser;

// weak reference to a string
typedef struct substring_ {
	char const * str;
	size_t len;
} substring;

typedef
	ParsedString * (*peg_parser) (PegParser const *, PegRule const *, char const *);


//////// forward referece

//// ctor
PegRule      * make_peg_rule(PEG_KIND kind, void * body);
peg_rule_bin * make_peg_rule_bin (PegRule * ref, peg_rule_bin * next);
ParsedString * make_parsed_string (char const * ident, PegRule const * rule, size_t len, char const * str, ParsedStringBin * nest);
NamedPegRule * make_named_peg_rule(char const * name, PegRule * rule);
PegParser * make_peg_parser(void);

//// dtor
void free_peg_rule(PegRule * pr);
void free_named_peg_rule(NamedPegRule * npr);
void free_parsed_string    (ParsedString    * ps);
void free_parsed_string_bin(ParsedStringBin * psb);
void free_peg_parser(PegParser * p);

//// parser for each PEG rue
//
// parse the given string with each PEG rule.
// return NULL if parsing fail.
// if the parser don't consume a given string, return result with rest of the string.
//
ParsedString * peg_parse_string_negative(PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_and     (PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_exists  (PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_plus    (PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_repeat  (PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_any     (PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_class   (PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_seq     (PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_choice  (PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_ident   (PegParser const * rs, PegRule const * r, char const * str);
ParsedString * peg_parse_string_pattern (PegParser const * rs, PegRule const * r, char const * str);

//// printer
void print_peg_rule           (PegRule const * pr);
void print_peg_rule_impl      (PegRule const * pr, size_t depth);
void print_named_peg_rule     (NamedPegRule const * pr);
void print_named_peg_rule_impl(NamedPegRule const * pr, size_t depth);
void print_parsed_string     (ParsedString const * ps);
void print_parsed_string_impl(ParsedString const * ps, size_t depth);
void print_parsed_string_bin(PEG_KIND kind, ParsedStringBin const * psb, size_t depth);
void print_parsed_string_bin_impl(char const * open
								, ParsedStringBin const * psb
								, char const * sep
								, char const * close
								, size_t depth);

//// parse
ParsedString * peg_parse_string     (PegParser const * pegs, char const * str);
ParsedString * peg_parse_string_impl(PegParser const * rs, PegRule const * r, char const * str);

//// aux
bool push_back_peg_parser(PegParser * p, NamedPegRule * npr);
size_t length_peg_rule_bin (peg_rule_bin const * rs);
static bool is_alter_rule (PEG_KIND kind);
static void print_ntimes(char const * str, int n);
bool push_back_peg_parser(PegParser * p, NamedPegRule * npr);
PegRule      * dup_peg_rule     (PegRule      const * rule);
peg_rule_bin * dup_peg_rule_bin (peg_rule_bin const * rs);


/// synonym
peg_rule_bin * (* const cons_peg_rule)(PegRule *, peg_rule_bin *) = make_peg_rule_bin;


//////// function

char * strdup(char const * str) {
	size_t size = strlen(str);
	char * s = ALLOC(char, size+1);
	return strcpy(s, str);
}
char * strndup(char const * str, size_t size) {
	char * s = ALLOC(char, size+1);
	strncpy(s, str, size);
	s[size] = '\0';
	return s;
}

PegRule * make_peg_rule(PEG_KIND kind
						, void * body) /* ident / peg_rule / peg_rule_bin */
{
	PegRule * rule = ALLOC(PegRule, 1);
	rule->kind = kind;
	switch (kind) {
	case PEG_NEGATIVE:
	case PEG_AND     :
	case PEG_EXISTS  :
	case PEG_PLUS    :
	case PEG_REPEAT  :
	case PEG_ANY     :
		rule->body.ref = (PegRule*)body;
		break;
	case PEG_CHOICE  :
	case PEG_SEQ     :
		rule->body.refs = (peg_rule_bin*)body;
		break;
	case PEG_CLASS   :
		NOTIMPL;
		break;
	case PEG_IDENT   :
	case PEG_PATTERN :
		rule->body.str = strdup((char const*)body);
		break;
	default:
		WARN("unkown PEG rule is specified (%d)\n", kind);
		return NULL;
	}
	return rule;
}

peg_rule_bin * dup_peg_rule_bin (peg_rule_bin const * rs) {
	if (!rs)
		return NULL;
	{
		peg_rule_bin * rrs = ALLOC(peg_rule_bin, 1);
		rrs->ref  = dup_peg_rule(rs->ref);
		rrs->next = dup_peg_rule_bin(rs->next);
		return rrs;
	}
}

PegRule * dup_peg_rule (PegRule const * rule) {
	PegRule * newrule = ALLOC(PegRule, 1);
	newrule->kind = rule->kind;
	switch (newrule->kind) {
	case PEG_NEGATIVE:
	case PEG_AND     :
	case PEG_EXISTS  :
	case PEG_PLUS    :
	case PEG_REPEAT  :
	case PEG_ANY     :
		newrule->body.ref = dup_peg_rule(rule->body.ref);
		break;
	case PEG_CHOICE  :
	case PEG_SEQ     :
		newrule->body.refs = dup_peg_rule_bin(rule->body.refs);
		break;
	case PEG_CLASS   :
		NOTIMPL;
		break;
	case PEG_IDENT   :
	case PEG_PATTERN :
		newrule->body.str = strdup(rule->body.str);
		break;
	default:
		WARN("unkown PEG rule is specified (%d)\n", newrule->kind);
		return NULL;
	}
	return newrule;
}

peg_rule_bin * make_peg_rule_bin (PegRule * ref, peg_rule_bin * next) {
	peg_rule_bin * p = ALLOC(peg_rule_bin, 1);
	p->ref = ref;
	p->next = next;
	return p;
}

NamedPegRule * make_named_peg_rule (char const * name, PegRule * rule) {
	NamedPegRule * pr = ALLOC(NamedPegRule, 1);
	pr->name = strdup(name);
	pr->rule = rule;
	return pr;
}

PegParser * make_peg_parser(void) {
	PegParser * p = ALLOC(PegParser, 1);
	p->size = 0;
	p->nps  = NULL;
	return p;
}

bool push_back_peg_parser(PegParser * p, NamedPegRule * npr) {
	if (p) {
		size_t const newsize = p->size+1;
		NamedPegRule const ** extend = (NamedPegRule const **)realloc(p->nps, sizeof(NamedPegRule*)*newsize);
		if (extend) {
			p->nps = extend;
			p->size = newsize;
			p->nps[p->size-1] = npr;
			return true;
		}
	}
	return false;
}

size_t length_peg_rule_bin (peg_rule_bin const * rs) {
	peg_rule_bin const * iter=rs;
	size_t len=0;
	while (iter) {
		++len;
		iter = iter->next;
	}
	return len;
}

void free_peg_rule(PegRule * pr) {
	if (pr) {
		switch (pr->kind) {
			case PEG_NEGATIVE:
			case PEG_AND     :
			case PEG_SEQ     :
			case PEG_EXISTS  :
			case PEG_PLUS    :
			case PEG_REPEAT  :
			case PEG_ANY     :
				free(pr->body.ref);
				pr->body.ref = NULL;
				break;
			case PEG_CLASS   :     
				NOTIMPL;
				break;
			case PEG_CHOICE  :	   
				free(pr->body.ref);
				pr->body.ref = NULL;
				break;
			case PEG_IDENT   :     
			case PEG_PATTERN :
				free(pr->body.str);
				pr->body.str = NULL;
				break;
			default:
				WARN("unkown PEG rule is specified (%d)\n", pr->kind);
				return;
		}
		free(pr);
	}
}

void free_named_peg_rule(NamedPegRule * npr) {
	if (npr) {
		free(npr->name);
		npr->name = NULL;
		free_peg_rule(npr->rule);
		free(npr);
	}
}

substring make_substring(char const * str, size_t len) {
	substring ss;
	ss.str = str;
	ss.len = len;
	return ss;
}

char * substring_string(substring ss) {
	char * s = ALLOC(char, ss.len+1);
	return strncpy(s, ss.str, ss.len+1);
}

ParsedString * make_parsed_string (char const * ident, PegRule const * rule, size_t len, char const * str, ParsedStringBin * nest) {
	ParsedString * r = ALLOC(ParsedString, 1);
	r->ident = ident ? strdup(ident) : NULL;
	r->rule = dup_peg_rule(rule);
	r->nest = nest;
	r->mstr = strndup(str, len);
	return r;
}
ParsedStringBin * make_parsed_string_bin (ParsedString * ps, ParsedStringBin * next) {
	ParsedStringBin * psb = ALLOC(ParsedStringBin, 1);
	psb->ps   = ps;
	psb->next = next;
	return psb;
}
void free_parsed_string_bin(ParsedStringBin * psb) {
	if (psb) {
		free_parsed_string_bin(psb->next);
		psb->next = NULL;
		free_parsed_string(psb->ps);
		psb->ps = NULL;
		free(psb);
	}
}
void free_parsed_string(ParsedString * ps) {
	if (ps) {
		free(ps->ident);
		ps->ident = NULL;
		if (ps->rule) {
			free_parsed_string_bin(ps->nest);
			ps->nest = NULL;
		}
		free(ps->mstr);
		ps->mstr = NULL;
		free_peg_rule(ps->rule);
		ps->rule = NULL;
		free(ps);
	}
}

void free_peg_parser(PegParser * p) {
	if (p) {
		size_t i;
		for (i=0; i<p->size; ++i) {
			free_named_peg_rule((NamedPegRule *)p->nps[i]);
			p->nps[i] = NULL;
		}
		free(p->nps);
		p->nps = NULL;
		p->size = 0;
		free(p);
	}
}

static PegRule const * next_rule(PegRule const * x) {
	if (!x)
		return NULL;
	switch (x->kind) {
		case PEG_IDENT:
		case PEG_PATTERN:
			return NULL;
		case PEG_NEGATIVE:
		case PEG_AND:
		case PEG_SEQ:
		case PEG_EXISTS:
		case PEG_PLUS:
		case PEG_REPEAT:
		case PEG_ANY:
		case PEG_CLASS:
		case PEG_CHOICE:
			return x->body.ref;
		default:
			WARN("unkown peg rule is specified\n");
			return NULL;
	}
}

void print_peg_rule_impl (PegRule const * pr, size_t depth) {
	if (pr) {
		switch (pr->kind) {
			case PEG_NEGATIVE: printf("!"); print_peg_rule_impl(pr->body.ref, depth+1); break;
			case PEG_AND     : printf("&"); print_peg_rule_impl(pr->body.ref, depth+1); break;
			case PEG_SEQ:
			{
				peg_rule_bin const * iter=pr->body.refs;
				size_t const len=length_peg_rule_bin(iter);
				if (1<len)
					printf("(");
				while (iter) {
					print_peg_rule_impl(iter->ref, depth+1);
					printf(" ");
					iter = iter->next;
				}
				if (1<len)
					printf(")");
				break;
			}
			case PEG_EXISTS: print_peg_rule_impl(pr->body.ref, depth+1); printf("?"); break;
			case PEG_PLUS  : print_peg_rule_impl(pr->body.ref, depth+1); printf("+"); break;
			case PEG_REPEAT: print_peg_rule_impl(pr->body.ref, depth+1); printf("*"); break;
			case PEG_ANY:
				printf(".(Any)");
				break;
			case PEG_CLASS:
				NOTIMPL;
				break;
			case PEG_CHOICE:
			{
				peg_rule_bin const * iter=pr->body.refs;
				size_t const len=length_peg_rule_bin(iter);
				if (1<len)
					printf("(");
				while (iter) {
					print_peg_rule_impl(iter->ref, depth+1);
					printf(" / ");
					iter = iter->next;
				}
				if (1<len)
					printf(")");
				break;
			}
			case PEG_IDENT  : printf("%s", pr->body.str);     break;
			case PEG_PATTERN: printf("\"%s\"", pr->body.str); break;
			default:
				WARN("unkown PEG rule is specified (%d)\n", pr->kind);
				break;
		}
	}
}

void print_peg_rule (PegRule const * pr) {
	print_peg_rule_impl(pr, 0);
	printf("\n");
}

void print_named_peg_rule_impl (NamedPegRule const * npr, size_t depth) {
	print_ntimes("\t", depth);
		printf("(%s : ", npr->name);

		print_peg_rule_impl(npr->rule, depth+1);

	print_ntimes("\t", depth);
		printf(") : %s\n", npr->name);
}

void print_named_peg_rule (NamedPegRule const * npr) {
	print_named_peg_rule_impl(npr, 0);
}

static peg_parser const ps[NUM_OF_PEG_TYPE] = {	// jump table for each parsing rule
	peg_parse_string_negative,
	peg_parse_string_and,
	peg_parse_string_seq,
	peg_parse_string_exists,
	peg_parse_string_plus,
	peg_parse_string_repeat,
	peg_parse_string_any,
	peg_parse_string_class,
	peg_parse_string_choice,
	peg_parse_string_ident,
	peg_parse_string_pattern
};

ParsedString * peg_parse_string_negative(PegParser const * rs, PegRule const * r, char const * str) {
	ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str);
	if (!p) {
		return make_parsed_string(NULL, r, 0, str, NULL);
	}
	free_parsed_string(p);
	return NULL;
}
ParsedString * peg_parse_string_and(PegParser const * rs, PegRule const * r, char const * str) {
	ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str);
	if (p) {
		ParsedString * px = make_parsed_string(NULL, r, 0, str, NULL);
		free_parsed_string(p);
		return px;
	}
	return NULL;
}
ParsedString * peg_parse_string_exists  (PegParser const * rs, PegRule const * r, char const * str) {
	ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str);
	if (p)
		return make_parsed_string(NULL, r, strlen(p->mstr), str, make_parsed_string_bin(p, NULL));
	else
		return make_parsed_string(NULL, r,               0, str, NULL);
}

void push_back_parsed_string (ParsedString * ps, ParsedString * p) {
	if (ps->nest==NULL) {
		ps->nest= make_parsed_string_bin(p, NULL);
	} else {
		ParsedStringBin * iter = ps->nest;
		while (iter->next)
			iter = iter->next;
		iter->next = make_parsed_string_bin(p, NULL);
	}
}

size_t count_parsed_string_bin (ParsedStringBin const * xs) {
	size_t count=0;
	for (; xs; xs=xs->next)
		++count;
	return count;
}

ParsedString * peg_parse_string_plus(PegParser const * rs, PegRule const * r, char const * str) {
	ParsedString * ps = make_parsed_string(NULL, r, 0, str, NULL);
	size_t sumlen=ps ? strlen(ps->mstr) : 0;
	while (1) {
		ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str+sumlen);
		if(!p)
			break;
		push_back_parsed_string(ps, p);
		/// extend matched string
		sumlen += strlen(p->mstr);
		free(ps->mstr);
		ps->mstr = strndup(str, sumlen);

		if (strlen(p->mstr)==0) // consume no charactors
			break;
	}
	if (0<count_parsed_string_bin(ps->nest))
		return ps;
	else {
		free_parsed_string(ps);
		return NULL;
	}
}
ParsedString * peg_parse_string_repeat(PegParser const * rs, PegRule const * r, char const * str) {
	ParsedString * ps = make_parsed_string(NULL, r, 0, str, NULL);
	size_t sumlen=ps ? strlen(ps->mstr) : 0;
	while (ps) {
		ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str+sumlen);
		if (!p)
			break;
		push_back_parsed_string(ps, p);

		sumlen += strlen(p->mstr);
		free(p->mstr);
		p->mstr = strndup(str, sumlen);

		if (strlen(p->mstr)==0)
			break;
	}
	if (ps)
		return ps;
	else
		return make_parsed_string(NULL, r, 0, str, NULL);
}
ParsedString * peg_parse_string_any(PegParser const * rs, PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_class(PegParser const * rs, PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_seq(PegParser const * rs, PegRule const * r, char const * str) {
	ParsedString * ps = make_parsed_string(NULL, r, 0, str, NULL);
	peg_rule_bin const * iter = r->body.refs;
	size_t sumlen = 0;
	for (; iter; iter=iter->next) {
		ParsedString * p = peg_parse_string_impl(rs, iter->ref, str+sumlen);
		if (!p) {
			free_parsed_string(ps);
			return NULL;
		}
		sumlen += strlen(p->mstr);
		push_back_parsed_string(ps, p);
	}
	return ps;
}
ParsedString * peg_parse_string_choice(PegParser const * rs, PegRule const * r, char const * str) {
	ParsedString * ps = make_parsed_string(NULL, r, 0, str, NULL);
	peg_rule_bin const * iter = r->body.refs;
	for (; iter; iter=iter->next) {
		ParsedString * p = peg_parse_string_impl(rs, iter->ref, str);
		if (p) {
			push_back_parsed_string(ps, p);
			return ps;
		}
	}
	free_parsed_string(ps);
	return NULL;
}
ParsedString * peg_parse_string_ident   (PegParser const * rs, PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}

ParsedString * peg_parse_string_pattern (PegParser const * rs, PegRule const * r, char const * str) {
	ASSERT(r && r->kind==PEG_PATTERN, "require kind 'pattern'\n"); {
	size_t const len=strlen(r->body.str);
	if (!strncmp(r->body.str, str, len))
		return make_parsed_string(NULL, r, len, str, NULL);
	else
		return NULL;
} }

// parse input string with `rule`
ParsedString * peg_parse_string_impl(PegParser const * rs, PegRule const * r, char const * str) {
	return ps[r->kind](rs, r, str);
}

ParsedString * peg_parse_string(PegParser const * pegs, char const * str) {
	ASSERT(pegs && (0<pegs->size), "parse execute without rules :(\n");
	return peg_parse_string_impl(pegs, pegs->nps[0]->rule, str);
}

static void print_ntimes(char const * str, int n) {
	int i;
	for (i=0; i<n; ++i)
		printf("%s", str);
}

static bool is_alter_rule (PEG_KIND kind) {
	switch (kind) {
		case PEG_IDENT:
		case PEG_PATTERN:
		case PEG_NEGATIVE:
		case PEG_AND:
		case PEG_EXISTS:
		case PEG_PLUS:
		case PEG_REPEAT:
		case PEG_ANY:
		case PEG_CLASS:
			return false;
		case PEG_SEQ:
		case PEG_CHOICE:
			return true;
		default:
			WARN("unkown peg rule is specified\n");
			return false;
	}
}

void print_parsed_string_bin_impl(char const * open
								, ParsedStringBin const * psb
								, char const * sep
								, char const * close
								, size_t depth) 
{
	ParsedStringBin const * iter=psb;
	printf("%s", open);
	while (iter) {
		print_parsed_string_impl(iter->ps, depth+1);
		printf("%s", sep);
		iter = iter->next;
	}
	printf("%s", close);
}

void print_parsed_string_bin(PEG_KIND kind, ParsedStringBin const * psb, size_t depth) {
	switch (kind) {
		case PEG_SEQ:
			print_parsed_string_bin_impl("", psb, " / ", "", depth);
			break;
		case PEG_CHOICE:
			print_parsed_string_bin_impl("", psb, " "  , "", depth);
			break;
		case PEG_IDENT:
		case PEG_PATTERN:
		case PEG_NEGATIVE:
		case PEG_AND:
		case PEG_EXISTS:
		case PEG_PLUS:
		case PEG_REPEAT:
		case PEG_ANY:
		case PEG_CLASS:
			print_parsed_string_impl(psb->ps, depth);
			break;
		default:
			ASSERT(false, "invalid kind is specified\n");
	}
}

void print_parsed_string_impl(ParsedString const * ps, size_t depth) {
	if (!ps)
		return;
	{
		print_ntimes("\t", depth);
			printf("(%s : ", ps->ident ? ps->ident : "");

			print_peg_rule_impl(ps->rule, depth); puts("");

			print_ntimes("\t", depth+1);
				printf("==> %s\n", ps->mstr);

			if (ps->nest)
				print_parsed_string_bin(ps->rule->kind, ps->nest, depth+1);

		print_ntimes("\t", depth);
			printf(") : %s\n", ps->ident ? ps->ident : "");
	}
}
void print_parsed_string(ParsedString const * ps) {
	return print_parsed_string_impl(ps, 0);
}

int main (void) {
	print_peg_rule(make_peg_rule(PEG_IDENT, "fact"));
	print_peg_rule(make_peg_rule(PEG_SEQ, NULL));
	free_peg_rule(make_peg_rule(PEG_IDENT, "fact"));
	free_peg_rule(make_peg_rule(PEG_SEQ, NULL));

	NamedPegRule * add =
				make_named_peg_rule("add",
					make_peg_rule(PEG_CHOICE,
						cons_peg_rule(make_peg_rule(PEG_SEQ,
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"mul"),
							cons_peg_rule(make_peg_rule(PEG_PATTERN,"+"), 
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"add"), NULL)))),
						cons_peg_rule(
							make_peg_rule(PEG_IDENT, "mul"), NULL))));

	NamedPegRule * mul =
				make_named_peg_rule("mul",
					make_peg_rule(PEG_CHOICE,
						cons_peg_rule(make_peg_rule(PEG_SEQ,
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"prim"),
							cons_peg_rule(make_peg_rule(PEG_PATTERN,"*"),
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"mul"), NULL)))),
						cons_peg_rule(
							make_peg_rule(PEG_IDENT, "prim"), NULL))));

	NamedPegRule * prim=
				make_named_peg_rule("prim",
					make_peg_rule(PEG_CHOICE,
						cons_peg_rule(make_peg_rule(PEG_SEQ,
							cons_peg_rule(make_peg_rule(PEG_PATTERN,"("),
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"add"),
							cons_peg_rule(make_peg_rule(PEG_PATTERN,")"), NULL)))),
						cons_peg_rule(
							make_peg_rule(PEG_IDENT, "deci"), NULL))));
	PegParser * peg = make_peg_parser();

	print_named_peg_rule(add);
	print_named_peg_rule(mul);
	print_named_peg_rule(prim);

	push_back_peg_parser(peg, add);
	push_back_peg_parser(peg, mul);
	push_back_peg_parser(peg, prim);

	free_peg_parser(peg);

	{
		NamedPegRule * pat=make_named_peg_rule("hello", make_peg_rule(PEG_PATTERN, "hellopeg"));
		PegParser * pat_peg = make_peg_parser();
		push_back_peg_parser(pat_peg, pat);
		ParsedString * r=peg_parse_string(pat_peg, "hellopeg");

		print_named_peg_rule(pat);
		print_parsed_string(r);

		free_parsed_string(r);
		free_peg_parser(pat_peg);
	}

	{
		NamedPegRule * abc = make_named_peg_rule("aplus", make_peg_rule(PEG_PLUS, make_peg_rule(PEG_PATTERN, "a")));
		PegParser * abc_parser = make_peg_parser();
		ParsedString * r = NULL;

		print_named_peg_rule(abc);

		push_back_peg_parser(abc_parser, abc);

		ASSERT(peg_parse_string(abc_parser, "")==NULL, "don't match!\n");

		r = peg_parse_string(abc_parser, "a");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(abc_parser, "aa");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(abc_parser, "aaaaaaaaaaaaaaaa");
		print_parsed_string(r);
		free_parsed_string(r);

		free_peg_parser(abc_parser);
	}

	{
		NamedPegRule * bstar = make_named_peg_rule("bstar", make_peg_rule(PEG_REPEAT, make_peg_rule(PEG_PATTERN, "b")));
		PegParser * bstar_parser = make_peg_parser();
		ParsedString * r = NULL;

		print_named_peg_rule(bstar);

		push_back_peg_parser(bstar_parser, bstar);

		r = peg_parse_string(bstar_parser, "");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(bstar_parser, "b");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(bstar_parser, "bb");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(bstar_parser, "bbbbbbbbbbbbbbbbb");
		print_parsed_string(r);
		free_parsed_string(r);

		free_peg_parser(bstar_parser);
	}

	{
		NamedPegRule * abalter = make_named_peg_rule("abalter", make_peg_rule(PEG_CHOICE,
																	make_peg_rule_bin(make_peg_rule(PEG_PATTERN, "a"),
																	make_peg_rule_bin(make_peg_rule(PEG_PATTERN, "b"), NULL))));
		PegParser * abalter_parser = make_peg_parser();
		ParsedString * r = NULL;

		print_named_peg_rule(abalter);

		push_back_peg_parser(abalter_parser, abalter);

		r = peg_parse_string(abalter_parser, "");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(abalter_parser, "a");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(abalter_parser, "b");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(abalter_parser, "ab");
		print_parsed_string(r);
		free_parsed_string(r);

		ASSERT(peg_parse_string(abalter_parser, "c")==NULL, "don't match!\n");

		free_peg_parser(abalter_parser);
	}

	{
		NamedPegRule * abcseq = make_named_peg_rule("abcseq", make_peg_rule(PEG_SEQ,
																	make_peg_rule_bin(make_peg_rule(PEG_PATTERN, "a"),
																	make_peg_rule_bin(make_peg_rule(PEG_PATTERN, "b"),
																	make_peg_rule_bin(make_peg_rule(PEG_PATTERN, "c"), NULL)))));
		PegParser * abcseq_parser = make_peg_parser();
		ParsedString * r = NULL;

		print_named_peg_rule(abcseq);

		push_back_peg_parser(abcseq_parser, abcseq);

		ASSERT(peg_parse_string(abcseq_parser, ""   )==NULL, "don't match!\n");
		ASSERT(peg_parse_string(abcseq_parser, "a"  )==NULL, "don't match!\n");
		ASSERT(peg_parse_string(abcseq_parser, "ab" )==NULL, "don't match!\n");
		ASSERT(peg_parse_string(abcseq_parser, "abb")==NULL, "don't match!\n");
		ASSERT(peg_parse_string(abcseq_parser, "bc" )==NULL, "don't match!\n");

		r = peg_parse_string(abcseq_parser, "abc");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(abcseq_parser, "abcd");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(abcseq_parser, "abcabcabcabc");
		print_parsed_string(r);
		free_parsed_string(r);

		free_peg_parser(abcseq_parser);
	}
	printf("end\n");
	return 0;
}


