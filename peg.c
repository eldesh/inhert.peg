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

#define ALLOC(ty, n) ALLOC_I(ty, n)
#define ALLOC_I(ty, n) ((ty*)malloc(sizeof(ty) * (n)))

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
	enum peg_type {		// king of match
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
	PEG_KIND kind;
	union {
		char * str;
		struct peg_rule     * ref;
		struct peg_rule_bin * refs;
	} body;
};
struct peg_rule_bin {
	struct peg_rule     * ref;
	struct peg_rule_bin * next;
};
typedef struct peg_rule_bin peg_rule_bin;

typedef
	struct named_peg_rule_ {
		char * name;
		PegRule * rule;
	}
NamedPegRule;

struct parsed_string_;
typedef struct parsed_string_ ParsedString;
struct parsed_string_bin_;
typedef struct parsed_string_bin_ ParsedStringBin;

struct parsed_string_ {
	char    * ident; // Maybe name(of rule)
	PegRule * rule;
	char    * mstr; // matched string
	// result of parsing for each parts of `rule`
	union {
		// determined with rule->kind
		ParsedString    * p;
		ParsedStringBin * ps;
	} nest; // rec
};
struct parsed_string_bin_ {
	ParsedString    * ps;
	ParsedStringBin * next;
};

typedef struct substring_ {
	char const * str;
	size_t len;
} substring;

typedef
	ParsedString * (*peg_parser) (PegRule const *, char const *);


//////// forward referece

//// ctor
ParsedString * make_parsed_string (char const * ident, PegRule const * rule, size_t len, char const * str, void * nest);
NamedPegRule * make_named_peg_rule(char const * name, PegRule * rule);

//// dtor
void free_peg_rule(PegRule * pr);
void free_named_peg_rule(NamedPegRule * npr);
void free_parsed_string    (ParsedString    * ps);
void free_parsed_string_bin(ParsedStringBin * psb);

//// parser for each PEG rue
//
// parse the given string with each PEG rule.
// return NULL if parsing fail.
// if the parser don't consume a given string, return result with rest of the string.
//
ParsedString * peg_parse_string_negative(PegRule const * r, char const * str);
ParsedString * peg_parse_string_and     (PegRule const * r, char const * str);
ParsedString * peg_parse_string_exists  (PegRule const * r, char const * str);
ParsedString * peg_parse_string_plus    (PegRule const * r, char const * str);
ParsedString * peg_parse_string_repeat  (PegRule const * r, char const * str);
ParsedString * peg_parse_string_any     (PegRule const * r, char const * str);
ParsedString * peg_parse_string_class   (PegRule const * r, char const * str);
ParsedString * peg_parse_string_seq     (PegRule const * r, char const * str);
ParsedString * peg_parse_string_choice  (PegRule const * r, char const * str);
ParsedString * peg_parse_string_ident   (PegRule const * r, char const * str);
ParsedString * peg_parse_string_pattern (PegRule const * r, char const * str);

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

//// aux
static bool is_alter_rule (PEG_KIND kind);
static void print_ntimes(char const * str, int n);


//////// function

static char * strdup(char const * str) {
	size_t size = strlen(str);
	char * s = ALLOC(char, size);
	return strcpy(s, str);
}
static char * strndup(char const * str, size_t size) {
	char * s = ALLOC(char, size);
	return strncpy(s, str, size);
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

PegRule * dup_peg_rule (PegRule const * rule) {
	return make_peg_rule(rule->kind, rule->body.str);
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

size_t length_peg_rule_bin (peg_rule_bin const * rs) {
	peg_rule_bin const * iter=rs;
	size_t len=0;
	while (iter) {
		++len;
		iter = iter->next;
	}
	return len;
}

peg_rule_bin * (* const cons_peg_rule)(PegRule *, peg_rule_bin *) = make_peg_rule_bin;

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

ParsedString * make_parsed_string (char const * ident, PegRule const * rule, size_t len, char const * str, void * nest) {
	ParsedString * r = ALLOC(ParsedString, 1);
	r->ident = ident ? strdup(ident) : NULL;
	r->rule = dup_peg_rule(rule);
	if (is_alter_rule(r->rule->kind))
		r->nest.p = nest;
	else
		r->nest.ps = nest;
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
			if (is_alter_rule(ps->rule->kind)) {
				free_parsed_string_bin(ps->nest.ps);
				ps->nest.ps = NULL;
			} else {
				free_parsed_string(ps->nest.p);
				ps->nest.p = NULL;
			}
		}
		free(ps->mstr);
		ps->mstr = NULL;
		free_peg_rule(ps->rule);
		ps->rule = NULL;
		free(ps);
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

ParsedString * peg_parse_string_negative(PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_and     (PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_exists  (PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_plus    (PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_repeat  (PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_any     (PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_class   (PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_seq     (PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_choice  (PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}
ParsedString * peg_parse_string_ident   (PegRule const * r, char const * str) {
	NOTIMPL;
	return NULL;
}

ParsedString * peg_parse_string_pattern (PegRule const * r, char const * str) {
	ASSERT(r && r->kind==PEG_PATTERN, "require kind 'pattern'\n"); {
	size_t const len=strlen(r->body.str);
	if (!strncmp(r->body.str, str, len))
		return make_parsed_string(NULL, r, len, str, NULL);
	else
		return NULL;
} }

// parse input string with `rule`
ParsedString * peg_parse_string(PegRule const * r, char const * str) {
	return ps[r->kind](r, str);
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
		print_parsed_string_impl(psb->ps, depth);
		printf("%s", sep);
		iter = iter->next;
	}
	printf("%s", close);
}
void print_parsed_string_bin(PEG_KIND kind, ParsedStringBin const * psb, size_t depth) {
	if (kind==PEG_SEQ)
		print_parsed_string_bin_impl("", psb, " / ", "", depth+1);
	else if (kind==PEG_CHOICE)
		print_parsed_string_bin_impl("", psb, " "  , "", depth+1);
	else
		ASSERT(false, "invalid kind is specified\n");
}

void print_parsed_string_impl(ParsedString const * ps, size_t depth) {
	if (!ps)
		return;
	{
		print_ntimes("\t", depth);
			printf("(%s : ", ps->ident ? ps->ident : "");

			print_peg_rule_impl(ps->rule, depth);

			print_ntimes("\t", depth+1);
				printf("==> %s\n", ps->mstr);

			if (is_alter_rule(ps->rule->kind))
				print_parsed_string_bin(ps->rule->kind, ps->nest.ps, depth+1);
			else
				print_parsed_string_impl(ps->nest.p, depth+1);

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

	print_named_peg_rule(add);
	print_named_peg_rule(mul);
	print_named_peg_rule(prim);

	free_named_peg_rule(add);
	free_named_peg_rule(mul);
	free_named_peg_rule(prim);

	{
		PegRule * pat=make_peg_rule(PEG_PATTERN, "hellopeg");
		ParsedString * r=peg_parse_string(pat, "hellopeg");

		print_peg_rule(pat);
		print_parsed_string(r);

		free_peg_rule(pat);
		free_parsed_string(r);
	}

	printf("end\n");
	return 0;
}


