
// detecting memory leaks
#if defined(_WIN32) && defined(_DEBUG)
#define _CRTDBG_MAP_ALLOC
#  include <stdlib.h>
#  include <crtdbg.h>
#endif
#include <inhert/peg.h>


void sample (void) {
	{
		print_peg_rule(make_peg_rule(PEG_IDENT, "fact"));
		print_peg_rule(make_peg_rule(PEG_SEQ, NULL));
		free_peg_rule(make_peg_rule(PEG_IDENT, "fact"));
		free_peg_rule(make_peg_rule(PEG_SEQ, NULL));
	}

	{
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

		NamedPegRule * deci = make_named_peg_rule("deci", peg_digit());

		PegParser * peg = make_peg_parser();
		ParsedString * r    = NULL;

		print_named_peg_rule(add);
		print_named_peg_rule(mul);
		print_named_peg_rule(prim);
		print_named_peg_rule(deci);

		push_back_peg_parser(peg, add);
		push_back_peg_parser(peg, mul);
		push_back_peg_parser(peg, prim);
		push_back_peg_parser(peg, deci);

		assert(!peg_parse_string(peg, ""));

		r = peg_parse_string(peg, "9");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(peg, "(7)");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(peg, "1+2");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(peg, "3*(4+2)");
		print_parsed_string(r);
		free_parsed_string(r);

		free_peg_parser(peg);
	}

	{
		NamedPegRule * pat  = make_named_peg_rule("hello", make_peg_rule(PEG_PATTERN, "HelloPEG"));
		PegParser * pat_peg = make_peg_parser();
		ParsedString * r    = NULL;
		push_back_peg_parser(pat_peg, pat);
		r = peg_parse_string(pat_peg, "HelloPEG");

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

	{
		NamedPegRule * any = make_named_peg_rule("any", make_peg_rule(PEG_ANY, NULL));
		PegParser * any_parser = make_peg_parser();
		ParsedString * r = NULL;

		print_named_peg_rule(any);
		push_back_peg_parser(any_parser, any);

		ASSERT(peg_parse_string(any_parser, ""  )==NULL, "don't match!\n");

		r = peg_parse_string(any_parser, "a");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(any_parser, "b");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(any_parser, " ");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(any_parser, ".");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(any_parser, "()");
		print_parsed_string(r);
		free_parsed_string(r);

		free_peg_parser(any_parser);
	}

	{
		NamedPegRule * fizz     = make_named_peg_rule("fizz", make_peg_rule(PEG_PATTERN, "fizz"));
		NamedPegRule * bazz     = make_named_peg_rule("bazz", make_peg_rule(PEG_PATTERN, "bazz"));
		NamedPegRule * fizzbazz = make_named_peg_rule("fizzbazz",
															make_peg_rule(PEG_SEQ,
																make_peg_rule_bin(make_peg_rule(PEG_PATTERN, "1"),
																make_peg_rule_bin(make_peg_rule(PEG_PATTERN, "2"),
																make_peg_rule_bin(make_peg_rule(PEG_PATTERN, "3"),
																make_peg_rule_bin(make_peg_rule(PEG_IDENT, "fizz"),
																make_peg_rule_bin(make_peg_rule(PEG_IDENT, "bazz"), NULL)))))));
		PegParser * fizzbazz_parser = make_peg_parser();
		ParsedString * r = NULL;

		print_named_peg_rule(fizz);
		print_named_peg_rule(bazz);
		print_named_peg_rule(fizzbazz);

		push_back_peg_parser(fizzbazz_parser, fizzbazz);
		push_back_peg_parser(fizzbazz_parser, bazz);
		push_back_peg_parser(fizzbazz_parser, fizz);

		ASSERT(peg_parse_string(fizzbazz_parser, "")            ==NULL, "don't match!\n");
		ASSERT(peg_parse_string(fizzbazz_parser, "1")           ==NULL, "don't match!\n");
		ASSERT(peg_parse_string(fizzbazz_parser, "12")          ==NULL, "don't match!\n");
		ASSERT(peg_parse_string(fizzbazz_parser, "123")         ==NULL, "don't match!\n");
		ASSERT(peg_parse_string(fizzbazz_parser, "123fizzbaz")  ==NULL, "don't match!\n");
		ASSERT(peg_parse_string(fizzbazz_parser, " 123fizzbazz")==NULL, "don't match!\n");

		r = peg_parse_string(fizzbazz_parser, "123fizzbazz");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(fizzbazz_parser, " 123fizzbazz");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(fizzbazz_parser, "123FIZZBAZZ");
		print_parsed_string(r);
		free_parsed_string(r);

		free_peg_parser(fizzbazz_parser);
	}

	// direct recursive test
	/*
	{
		// x <- x + one
		// one <- '1'
		NamedPegRule * x = make_named_peg_rule("x", make_peg_rule(PEG_SEQ,
														make_peg_rule_bin(make_peg_rule(PEG_IDENT  , "x"),
														make_peg_rule_bin(make_peg_rule(PEG_PATTERN, "+"),
														make_peg_rule_bin(make_peg_rule(PEG_IDENT  , "one"), NULL)))));
		NamedPegRule * one = make_named_peg_rule("one", make_peg_rule(PEG_PATTERN, "1"));
		PegParser * direct_rec_parser = make_peg_parser();
		ParsedString * r = NULL;

		print_named_peg_rule(x);
		print_named_peg_rule(one);

		push_back_peg_parser(direct_rec_parser, x);
		push_back_peg_parser(direct_rec_parser, one);

//		ASSERT(peg_parse_string(direct_rec_parser, "")            ==NULL, "don't match!\n");

		r = peg_parse_string(direct_rec_parser, "1");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(direct_rec_parser, "1+1");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(direct_rec_parser, "1+1+1");
		print_parsed_string(r);
		free_parsed_string(r);

		r = peg_parse_string(direct_rec_parser, "1+1+1+1");
		print_parsed_string(r);
		free_parsed_string(r);

		free_peg_parser(direct_rec_parser);
	}
	*/

	printf("end\n");
}

int main (void) {
	sample();
#if defined(_WIN32) && defined(_DEBUG)
	if (_CrtDumpMemoryLeaks())
		printf("Memory Leaks is found :(\n");
	else
		printf("Memory Leaks is not found :D\n");
#endif
	return 0;
}



