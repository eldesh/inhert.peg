
LIB = peg/libinhertpeg.a

.PHONY: $(LIB)
$(LIB):
	$(MAKE) -C peg

.PHONY:	sample
sample:
	$(MAKE) -C sample

.PHONY: clean
clean:
	$(MAKE) clean -C peg
	$(MAKE) clean -C sample

