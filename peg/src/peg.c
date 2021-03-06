/**** *****************************************************************************
 *
 * INHERT.PEG Parser Generator Library
 *
 *
 * PEG Parser Generator Library
 * -----------------------------------
 *
 *  PEG is abbreviation of 'P'arsing 'E'xpression 'G'rammar.
 *  This is the way to define grammars formally.
 *  This library implements a 'parser combinator' for parsing PEG-ruled grammars.
 *  The combinators built with this library,
 *  with memoization of temporal results and lazy building of cache tables,
 *  parse given strings at linear time.
 *
 *  including:
 *  - parser combinators
 *  - combinator builders
 *  - pretty printer (combinators and grammars and their results)
 *
 * Info
 * ----------
 *
 *  License:         Modified-BSD license
 *  Portability:     to be portable :)
 *  Ported to:       GCC4.5, MSVC10
 *  Stability:       experimental
 *  Maintainer:      eldesh <nephits@gmail.com>
 *
 *
 * References
 * ----------
 *
 * [1] Packrat Parsers Can Support Left Recursion
 *     Alessandro Warth, James R. Douglass, Todd Millstein
 *     VPRI Technical Report TR-2007-002
 *
 * [2] Packrat Parsing: Simple, Powerful, Lazy, Linear Time
 *     Bryan Ford
 *     Functional Pearl ICFP '02 Proceedings of the seventh ACM SIGPLAN
 *     international conference on Functional programming 
 *
 * [3] Parsing expression grammars: a recognition-based syntactic foundation
 *     Bryan Ford 
 *     Proceedings of the 31st ACM SIGPLAN-SIGACT symposium on
 *     Principles of programming languages
 *
 ***************************************************************************** ****/

/**
 * compile :
 * 	> gcc -g -Wall -I peg/include -o libpeg.o -c peg/src/peg.c
 */
// ignore warnings
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#include <stdio.h>
// detecting memory leaks
#if defined _WIN32 && defined _DEBUG
#  define _CRTDBG_MAP_ALLOC
#  include <stdlib.h>
#  include <crtdbg.h>
#else
#  include <stdlib.h>
#endif
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <inhert/peg.h>

#define PP_STRINGIZE(s) PP_STRINGIZE_I(s)
#define PP_STRINGIZE_I(s) #s

//#define LOG_HEAP
#define ALLOC(ty, n) ALLOC_I(ty, n)
#if defined LOG_HEAP
#  define ALLOC_I(ty, n) ((ty*)MALLOC_LOG(__FILE__, __LINE__, __func__, (sizeof(ty) * (n))))
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
	(free)(p); /* avoid replacing macro(free) recursively */
}
#endif /* defined LOG_HEAP */


//////// forward referece

//// ctor
PegRule      * make_peg_rule(PEG_KIND kind, void * body);
peg_rule_bin * make_peg_rule_bin (PegRule * ref, peg_rule_bin * next);
ParsedString * make_parsed_string (char const * ident, PegRule const * rule, size_t len, char const * str, ParsedStringBin * nest);
ParsedStringBin * make_parsed_string_bin (ParsedString * ps, ParsedStringBin * next);
NamedPegRule * make_named_peg_rule(char const * name, PegRule * rule);
PegParser * make_peg_parser(void);
row_cache_table * make_row_cache_table(PegParser const * rs);

//// dtor
void free_peg_rule(PegRule * pr);
void free_named_peg_rule(NamedPegRule * npr);
void free_parsed_string    (ParsedString    * ps);
void free_parsed_string_bin(ParsedStringBin * psb);
void free_fail_parsed_string    (ParsedString    * ps);
void free_fail_parsed_string_bin(ParsedStringBin * psb);
void free_peg_parser(PegParser * p);

void free_peg_cache_table(PegCacheTable * table);
	void free_row_cache_table(row_cache_table * rs);
	void free_cache_elem(cache_elem * e);

//// comparator
bool equal_string (char const * lhs, char const * rhs); // compare NULL as an address of pointer, different from strcmp(3)
bool equal_peg_rule    (PegRule      const * lhs, PegRule      const * rhs);
bool equal_peg_rule_bin(peg_rule_bin const * lhs, peg_rule_bin const * rhs);
bool equal_parsed_string    (ParsedString    const * lhs, ParsedString    const * rhs);
bool equal_parsed_string_bin(ParsedStringBin const * lhs, ParsedStringBin const * rhs);

//// parser for each PEG rule
//
// parse the given string with each PEG rule.
// return NULL if parsing fail.
// if the parser don't consume a given string, return result with rest of the string.
//
ParsedString * peg_parse_string_negative(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_and     (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_exists  (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_plus    (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_repeat  (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_any     (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_class   (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_seq     (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_choice  (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_ident   (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);
ParsedString * peg_parse_string_pattern (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);

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
void print_peg_cache_table(PegCacheTable const * table);

//// parse
ParsedString * peg_parse_string     (PegParser const * pegs, char const * str);
ParsedString * peg_parse_string_impl(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table);

//// duplcator
PegRule      * dup_peg_rule     (PegRule      const * rule);
peg_rule_bin * dup_peg_rule_bin (peg_rule_bin const * rs);
ParsedString * dup_parsed_string(ParsedString const * ps);
ParsedStringBin * dup_parsed_string_bin(ParsedStringBin const * ps);

//// aux
bool push_back_peg_parser(PegParser * p, NamedPegRule * npr);
// add a rule to set of pasers as a start parsing rule
bool push_back_peg_parser_as_root(PegParser * p, NamedPegRule * npr);
size_t length_peg_rule_bin (peg_rule_bin const * rs);
static bool is_alter_rule (PEG_KIND kind);
static void print_ntimes(char const * str, int n);
char const * kind_to_string(PEG_KIND k);
PegCacheTable advance_peg_cache_table (PegCacheTable table, size_t n);

NamedPegRule const * find_named_peg_rule(PegParser const * rs, char const * ident);

//// basis parsers provided by default
PegRule * peg_alphabet  (void);
PegRule * peg_digit     (void);
PegRule * peg_alphadigit(void);


/// synonym
peg_rule_bin * (* const cons_peg_rule)(PegRule *, peg_rule_bin *) = make_peg_rule_bin;

//////// function

#if !defined _WIN32
char * strdup(char const * str) {
	size_t size = strlen(str);
	char * s = ALLOC(char, size+1);
	return strcpy(s, str);
}
#endif
char * strndup(char const * str, size_t size) {
	char * s = ALLOC(char, size+1);
	strncpy(s, str, size);
	s[size] = '\0';
	return s;
}

void err_printf_row(char const * format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}
void err_printf(char const * file, int line, char const * func, char const * format, ...)
{
	va_list ap;
	fprintf(stderr, "%10s:%5d [%-20s] > ", file, line, func);
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
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
		rule->body.ref = (PegRule*)body;
		break;
	case PEG_ANY     :
		rule->body.ref = NULL;
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
		newrule->body.ref = dup_peg_rule(rule->body.ref);
		break;
	case PEG_ANY:
		ASSERT(rule->body.ref==NULL, "any has no alternatives");
		newrule->body.ref = NULL;
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
	p->size  = 0;
	p->nps   = NULL;
	return p;
}

bool push_back_peg_parser_as_root(PegParser * p, NamedPegRule * npr) {
	NOTIMPL;
	return false;
}

bool push_back_peg_parser(PegParser * p, NamedPegRule * npr) {
	if (p) {
		size_t const newsize = p->size+1;
		NamedPegRule ** extend = (NamedPegRule **)realloc(p->nps, sizeof(NamedPegRule*)*newsize);
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


void free_peg_rule_bin(peg_rule_bin * p) {
	if (p) {
		free_peg_rule(p->ref);
		p->ref = NULL;
		free_peg_rule_bin(p->next);
		p->next = NULL;
		free(p);
	}
}

void free_peg_rule(PegRule * pr) {
	if (pr) {
		switch (pr->kind) {
			case PEG_NEGATIVE:
			case PEG_AND     :
			case PEG_EXISTS  :
			case PEG_PLUS    :
			case PEG_REPEAT  :
			case PEG_ANY     :
				free_peg_rule(pr->body.ref);
				pr->body.ref = NULL;
				break;
			case PEG_CLASS   :     
				NOTIMPL;
				break;
			case PEG_SEQ     :
			case PEG_CHOICE  :	   
				free_peg_rule_bin(pr->body.refs);
				pr->body.refs = NULL;
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

void free_fail_parsed_string_bin(ParsedStringBin * psb) {
	if (psb) {
		free_fail_parsed_string_bin(psb->next);
		psb->next = NULL;
		free_fail_parsed_string(psb->ps);
		psb->ps = NULL;
		free(psb);
	}
}

void free_parsed_string(ParsedString * ps) {
	if (ps) {
		free(ps->ident);
		ps->ident = NULL;
		free_parsed_string_bin(ps->nest);
		ps->nest = NULL;
		free(ps->mstr);
		ps->mstr = NULL;
		free_peg_rule(ps->rule);
		ps->rule = NULL;
		free(ps);
	}
}

void free_fail_parsed_string(ParsedString * ps) {
	if (ps && !ps->ident) {
		free_fail_parsed_string_bin(ps->nest);
		ps->nest = NULL;
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
				if (iter)
					print_peg_rule_impl(iter->ref, depth+1);    // display 'sep' between rules
				for (iter=iter->next; iter; iter=iter->next) {  //
					printf(" / ");
					print_peg_rule_impl(iter->ref, depth+1);    // ref0 sep1 ref1 sep2 ref2 ... sepN refN
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

ParsedString * peg_parse_string_negative(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str, table);
	if (!p) {
		return make_parsed_string(NULL, r, 0, str, NULL);
	}
	free_parsed_string(p);
	return NULL;
}
ParsedString * peg_parse_string_and(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str, table);
	if (p) {
		ParsedString * px = make_parsed_string(NULL, r, 0, str, NULL);
		free_parsed_string(p);
		return px;
	}
	return NULL;
}
ParsedString * peg_parse_string_exists  (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str, table);
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
	{
		size_t len = (ps->mstr ? strlen(ps->mstr) : 0) + (p->mstr ? strlen(p->mstr) : 0) +1;
		char * buff = ALLOC(char, len+1);
		strcpy(buff, ps->mstr);
		strcpy(buff+strlen(ps->mstr), p->mstr);
		buff[len-1] = '\0';
		free(ps->mstr);
		ps->mstr = buff;
	}
}

size_t count_parsed_string_bin (ParsedStringBin const * xs) {
	size_t count=0;
	for (; xs; xs=xs->next)
		++count;
	return count;
}

ParsedString * peg_parse_string_plus(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	ParsedString * ps = make_parsed_string(NULL, r, 0, str, NULL);
	size_t sumlen=ps ? strlen(ps->mstr) : 0;
	while (1) {
		ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str+sumlen, advance_peg_cache_table(table, sumlen));
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
		free_fail_parsed_string(ps);
		return NULL;
	}
}
ParsedString * peg_parse_string_repeat(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	ParsedString * ps = make_parsed_string(NULL, r, 0, str, NULL);
	size_t sumlen=ps ? strlen(ps->mstr) : 0;
	while (ps) {
		ParsedString * p = peg_parse_string_impl(rs, r->body.ref, str+sumlen, advance_peg_cache_table(table, sumlen));
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
ParsedString * peg_parse_string_any(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	if (strlen(str))
		return make_parsed_string(NULL, r, 1, str, NULL);
	else
		return NULL;
}
ParsedString * peg_parse_string_class(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	NOTIMPL;
	return NULL;
}

PegCacheTable advance_peg_cache_table (PegCacheTable table, size_t n) {
	PegCacheTable t_;
	t_.size = table.size - n;
	t_.rs   = &table.rs[n];
	return t_;
}

ParsedString * peg_parse_string_seq(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	ParsedString * ps = make_parsed_string(NULL, r, 0, str, NULL);
	peg_rule_bin const * iter = r->body.refs;
	size_t sumlen = 0;
//	printf("seq start:"); print_peg_cache_table(&table);
	for (; iter; iter=iter->next) {
		ParsedString * p = peg_parse_string_impl(rs, iter->ref, str+sumlen, advance_peg_cache_table(table, sumlen));
		if (!p) {
			free_fail_parsed_string(ps);
			return NULL;
		}
		sumlen += strlen(p->mstr);
		push_back_parsed_string(ps, p);
	}
//	printf("seq end:"); print_peg_cache_table(&table);
	return ps;
}
ParsedString * peg_parse_string_choice(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	ParsedString * ps = make_parsed_string(NULL, r, 0, str, NULL);
	peg_rule_bin const * iter = r->body.refs;
	for (; iter; iter=iter->next) {
		ParsedString * p = peg_parse_string_impl(rs, iter->ref, str, table);
		if (p) {
			push_back_parsed_string(ps, p);
			return ps;
		}
	}
	free_fail_parsed_string(ps);
	return NULL;
}

NamedPegRule const * find_named_peg_rule(PegParser const * rs, char const * ident) {
	size_t i;
	for (i=0; i<rs->size; ++i) {
		if (!strcmp(ident, rs->nps[i]->name))
			return rs->nps[i];
	}
	return NULL;
}

cache_elem * make_cache_elem (ParsedString * r) {
	cache_elem * e = ALLOC(cache_elem, 1);
	e->result_tree = r;
	return e;
}

row_cache_table * make_row_cache_table(PegParser const * rs) {
	size_t i;
	row_cache_table * r = ALLOC(row_cache_table, 1);
	r->size = rs->size;
	r->es   = ALLOC(cache_elem*, r->size);
	for (i=0; i<r->size; ++i)
		r->es[i] = make_cache_elem(NULL);
	return r;
}

size_t index_of_ident(PegParser const * rs, char const * ident) {
	size_t i;
	for (i=0; i<rs->size; ++i) {
		if (!strcmp(ident, rs->nps[i]->name))
			return i;
	}
	ASSERT(false, "unknown identifier is passed\n");
	return 0;
}

ParsedString * peg_parse_string_ident(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	NamedPegRule const * r_ = find_named_peg_rule(rs, r->body.str);
	ASSERT(r_!=NULL, "It is certainly found.\n");
//	printf(" ident(%s) <- %s\n", r->body.str, str); print_peg_cache_table(&table);
	if (table.size) {
		size_t idx = index_of_ident(rs, r->body.str);
		if (!table.rs[0])
			 table.rs[0] = make_row_cache_table(rs); // construct table for current position of input string
//		printf(" ident(%s) <- %s\n", r->body.str, str); print_peg_cache_table(&table);
		if (!table.rs[0]->es[idx]->result_tree) {
			 ParsedString * rn = peg_parse_string_impl(rs, r_->rule, str, table);
			 if (rn) {
				 table.rs[0]->es[idx]->result_tree // store to the cache table
					 = make_parsed_string(r->body.str, r, strlen(rn->mstr), rn->mstr, make_parsed_string_bin(rn,NULL));
			 }
		}
//		printf(" ident(%s) <- %s\n", r->body.str, str); print_peg_cache_table(&table);
		return table.rs[0]->es[idx]->result_tree;
	}
	return peg_parse_string_impl(rs, r_->rule, str, table);
}

ParsedString * peg_parse_string_pattern (PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	ASSERT(r && r->kind==PEG_PATTERN, "require kind 'pattern'\n"); {
	size_t const len=strlen(r->body.str);
	if (!strncmp(r->body.str, str, len))
		return make_parsed_string(NULL, r, len, str, NULL);
	else
		return NULL;
} }

// parse input string with rule 'r'
ParsedString * peg_parse_string_impl(PegParser const * rs, PegRule const * r, char const * str, PegCacheTable table) {
	return ps[r->kind](rs, r, str, table);
}

//row_cache_table ** make_cache_tables (PegParser

PegCacheTable * make_peg_cache_table(char const * str) {
	PegCacheTable * table = ALLOC(PegCacheTable, 1);
	size_t len = strlen(str)+1;
	size_t i;
	table->rs   = ALLOC(row_cache_table*, len);
	for (i=0; i<len; ++i)
		table->rs[i] = NULL;
	table->size = len;
//	table->str  = str;
	return table;
}

void free_cache_elem(cache_elem * e) {
	if (e) {
		ParsedString * ps =e->result_tree;
		if (ps) {
			if (ps->ident) {
				free(ps->ident);
				ps->ident = NULL;
				free_peg_rule(ps->rule);
				ps->rule = NULL;
				free(ps->mstr);
				ps->mstr = NULL;
				// delete children if not 'IDENT'
				// ('IDENT':ParsedString*) is cached
				free_fail_parsed_string_bin(ps->nest);
				ps->nest = NULL;
			} else {
				ASSERT(false, "a rule is cached except for IDENT-rules\n");
			}
			free(ps);
		}
		free(e);
	}
}

void free_row_cache_table(row_cache_table * rs) {
	if (rs) {
		size_t i;
		for (i=0; i<rs->size; ++i) {
			free_cache_elem(rs->es[i]);
			rs->es[i] = NULL;
		}
		free(rs->es);
		rs->es = NULL;
		rs->size = 0;
		free(rs);
	}
}

void free_peg_cache_table(PegCacheTable * table) {
	if (table) {
		size_t i;
		for (i=0; i<table->size; ++i) {
			free_row_cache_table(table->rs[i]);
			table->rs[i] = NULL;
//			printf("row:del(%d)\n", i); print_peg_cache_table(table);
		}
		free(table->rs);
		table->rs   = NULL;
		table->size = 0;
//		table->str  = NULL; // have no ownership
		free(table);
	}
}

ParsedStringBin * dup_parsed_string_bin(ParsedStringBin const * ps) {
	ParsedStringBin * ps_ = NULL;
	if (ps) {
		ps_ = ALLOC(ParsedStringBin, 1);
		ps_->ps = dup_parsed_string(ps->ps);
		ps_->next = dup_parsed_string_bin(ps->next);
	}
	return ps_;
}

ParsedString * dup_parsed_string(ParsedString const * ps) {
	ParsedString * ps_ = NULL;
	if (ps) {
		ps_ = ALLOC(ParsedString, 1);
		ps_->ident = ps->ident ? strdup(ps->ident) : NULL;
		ps_->rule  = dup_peg_rule(ps->rule);
		ps_->mstr  = strdup(ps->mstr);
		ps_->nest  = dup_parsed_string_bin(ps->nest);
	}
	return ps_;
}

ParsedString * peg_parse_string(PegParser const * pegs, char const * str) {
	ASSERT(pegs && (0<pegs->size), "parse execute without rules :(\n"); {
		PegCacheTable * table = make_peg_cache_table(str);
		PegRule       * start_rule = make_peg_rule(PEG_IDENT, pegs->nps[0]->name);
		ParsedString  * result = dup_parsed_string(peg_parse_string_impl(pegs, start_rule, str, *table));
		//	printf("R root\n"); print_peg_cache_table(table);
		free_peg_rule(start_rule);
		free_peg_cache_table(table);
		return result;
	}
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
	ParsedStringBin const * iter=NULL;
	printf("%s", open);
	for (iter=psb; iter; iter=iter->next) {
		print_parsed_string_impl(iter->ps, depth);
		puts("");
//		printf("%s", sep);
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
			print_parsed_string_impl(psb->ps, depth); puts("");
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
				printf("==> [%s]\n", ps->mstr);

			if (ps->nest)
				print_parsed_string_bin(ps->rule->kind, ps->nest, depth+1);

		print_ntimes("\t", depth);
			printf(") : %s", ps->ident ? ps->ident : "");
	}
}

void print_parsed_string(ParsedString const * ps) {
	print_parsed_string_impl(ps, 0);
	puts("");
}

char const * kind_to_string(PEG_KIND k) {
	switch (k) {
	case PEG_NEGATIVE: return "PEG_NEGATIVE";
	case PEG_AND     : return "PEG_AND";
	case PEG_EXISTS  : return "PEG_EXISTS";
	case PEG_PLUS    : return "PEG_PLUS";
	case PEG_REPEAT  : return "PEG_REPEAT";
	case PEG_ANY     : return "PEG_ANY";
	case PEG_CHOICE  : return "PEG_CHOICE";
	case PEG_SEQ     : return "PEG_SEQ";
	case PEG_CLASS   : return "PEG_CLASS";
	case PEG_IDENT   : return "PEG_IDENT";
	case PEG_PATTERN : return "PEG_PATTERN";
	default:
					   return "UNKNOWN PEG_KIND IS PASSED";
	}
}

void print_cache_elem(cache_elem const * elem) {
	if (elem && elem->result_tree)
	{
		printf("%s:", kind_to_string(elem->result_tree->rule->kind));
		if (elem->result_tree->ident)
			printf("%s", elem->result_tree->ident);
	} else {
		printf("(NONE)");
	}
}

void print_row_cache_table(row_cache_table const * rc) {
	size_t i;
	if (!rc)
		return;
	for (i=0; i<rc->size; ++i) {
		print_cache_elem(rc->es[i]);
		printf(" |");
	}
}

void print_peg_cache_table(PegCacheTable const * table) {
	size_t i;
	print_ntimes("-", 64); puts("");
	if (table) {
		for (i=0; i<table->size; ++i) {
			printf("[%3d] row:", i);
			print_row_cache_table(table->rs[i]); puts("");
		}
	}
	print_ntimes("-", 64); puts("");
	fflush(stdout);
}

char * char_str(char c) {
	char * cc = ALLOC(char, 2);
	cc[0] = c;
	cc[1] = '\0';
	return cc;
}
peg_rule_bin * cons_chars_as_peg_rule (size_t size, char const * const strs[]) {
	int i;
	peg_rule_bin * rs=NULL;
	for (i=size-1; 0<=i; --i) // add rules from backward for preserve order of strs
		rs = cons_peg_rule(make_peg_rule(PEG_PATTERN, (void*)strs[i]), rs);
	return rs;
}

PegRule * peg_alphabet  (void) {
	static char const * alpha[] =
	{
		"a","b","c","d","e","f","g","h","i","j","k","l","m",
		"n","o","p","q","r","s","t","u","v","w","x","y","z",
		"A","B","C","D","E","F","G","H","I","J","K","L","M",
		"N","O","P","Q","R","S","T","U","V","W","X","Y","Z"
	};
	return make_peg_rule(PEG_CHOICE, cons_chars_as_peg_rule(52, alpha));
}
PegRule * peg_digit (void) {
	static char const * digit[] = {"0","1","2","3","4","5","6","7","8","9"};
	return make_peg_rule(PEG_CHOICE, cons_chars_as_peg_rule(10, digit));
}
PegRule * peg_alphadigit (void) {
	return make_peg_rule(PEG_CHOICE,
			cons_peg_rule(peg_alphabet(),
			cons_peg_rule(peg_digit   (), NULL)));
}

bool equal_string (char const * lhs, char const * rhs) {
	if ((!lhs && !rhs) || (lhs==rhs))
		return true;
	if ((lhs && !rhs) || (!lhs && rhs))
		return false;
	return !strcmp(lhs, rhs);
}

bool equal_peg_rule(PegRule const * lhs, PegRule const * rhs) {
	if ((!lhs && !rhs) || (lhs==rhs))
		return true;
	if ((lhs && !rhs) || (!lhs && rhs))
		return false;
	if (lhs->kind != rhs->kind)
		return false;

	switch (lhs->kind) {
		case PEG_NEGATIVE:
		case PEG_AND     :
		case PEG_EXISTS  :
		case PEG_PLUS    :
		case PEG_REPEAT  :
			return equal_peg_rule(lhs->body.ref, rhs->body.ref);
		case PEG_ANY     :
			return lhs->body.ref == rhs->body.ref;
		case PEG_CHOICE  :
		case PEG_SEQ     :
			return equal_peg_rule_bin(lhs->body.refs, rhs->body.refs);
		case PEG_CLASS   :
			NOTIMPL;
			break;
		case PEG_IDENT   :
		case PEG_PATTERN :
			return !strcmp(lhs->body.str, rhs->body.str);
		default:
			WARN("unkown PEG rule is specified (%d)\n", lhs->kind);
	}
	return false;
}

bool equal_peg_rule_bin(peg_rule_bin const * lhs, peg_rule_bin const * rhs) {
	if ((!lhs && !rhs) || (lhs==rhs))
		return true;
	if ((lhs && !rhs) || (!lhs && rhs))
		return false;
	return equal_peg_rule(lhs->ref, rhs->ref)
		&& equal_peg_rule_bin(lhs->next, rhs->next);
}

bool equal_parsed_string(ParsedString const * lhs, ParsedString const * rhs) {
	if ((!lhs && !rhs) || (lhs==rhs))
		return true;
	if ((lhs && !rhs) || (!lhs && rhs))
		return false;

	return equal_string(lhs->ident, rhs->ident)
		&& equal_peg_rule(lhs->rule, rhs->rule)
		&& equal_string(lhs->mstr, rhs->mstr)
		&& equal_parsed_string_bin(lhs->nest, rhs->nest);
}

bool equal_parsed_string_bin(ParsedStringBin const * lhs, ParsedStringBin const * rhs) {
	if ((!lhs && !rhs) || (lhs==rhs))
		return true;
	if ((lhs && !rhs) || (!lhs && rhs))
		return false;

	return equal_parsed_string    (lhs->ps  , rhs->ps)
		&& equal_parsed_string_bin(lhs->next, rhs->next);
}

