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

static char * strdup(char const * str) {
	size_t size = strlen(str);
	char * s = ALLOC(char, size);
	return strcpy(s, str);
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

peg_rule_bin * make_peg_rule_bin (PegRule * ref, peg_rule_bin * next) {
	peg_rule_bin * p = ALLOC(peg_rule_bin, 1);
	p->ref = ref;
	p->next = next;
	return p;
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

void pprint_peg_rule_impl (PegRule const * pr, size_t depth) {
	if (pr) {
		switch (pr->kind) {
			case PEG_NEGATIVE: printf("!"); pprint_peg_rule_impl(pr->body.ref, depth+1); break;
			case PEG_AND     : printf("&"); pprint_peg_rule_impl(pr->body.ref, depth+1); break;
			case PEG_SEQ:
			{
				peg_rule_bin const * iter=pr->body.refs;
				size_t const len=length_peg_rule_bin(iter);
				if (1<len)
					printf("(");
				while (iter) {
					pprint_peg_rule_impl(iter->ref, depth+1);
					printf(" ");
					iter = iter->next;
				}
				if (1<len)
					printf(")");
				break;
			}
			case PEG_EXISTS: pprint_peg_rule_impl(pr->body.ref, depth+1); printf("?"); break;
			case PEG_PLUS  : pprint_peg_rule_impl(pr->body.ref, depth+1); printf("+"); break;
			case PEG_REPEAT: pprint_peg_rule_impl(pr->body.ref, depth+1); printf("*"); break;
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
					pprint_peg_rule_impl(iter->ref, depth+1);
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

void pprint_peg_rule (PegRule const * pr) {
	pprint_peg_rule_impl(pr, 0);
	printf("\n");
}

int main (void) {
	pprint_peg_rule(make_peg_rule(PEG_IDENT, "fact"));
	pprint_peg_rule(make_peg_rule(PEG_SEQ, NULL));
	free_peg_rule(make_peg_rule(PEG_IDENT, "fact"));
	free_peg_rule(make_peg_rule(PEG_SEQ, NULL));

	PegRule * add = make_peg_rule(PEG_CHOICE,
						cons_peg_rule(make_peg_rule(PEG_SEQ,
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"mul"),
							cons_peg_rule(make_peg_rule(PEG_PATTERN,"+"), 
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"add"), NULL)))),
						cons_peg_rule(
							make_peg_rule(PEG_IDENT, "mul"), NULL)));

	PegRule * mul = make_peg_rule(PEG_CHOICE,
						cons_peg_rule(make_peg_rule(PEG_SEQ,
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"prim"),
							cons_peg_rule(make_peg_rule(PEG_PATTERN,"*"),
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"mul"), NULL)))),
						cons_peg_rule(
							make_peg_rule(PEG_IDENT, "prim"), NULL)));

	PegRule * prim= make_peg_rule(PEG_CHOICE,
						cons_peg_rule(make_peg_rule(PEG_SEQ,
							cons_peg_rule(make_peg_rule(PEG_PATTERN,"("),
							cons_peg_rule(make_peg_rule(PEG_IDENT  ,"add"),
							cons_peg_rule(make_peg_rule(PEG_PATTERN,")"), NULL)))),
						cons_peg_rule(
							make_peg_rule(PEG_IDENT, "deci"), NULL)));

	pprint_peg_rule(add);
	pprint_peg_rule(mul);
	pprint_peg_rule(prim);
	return 0;
}


