DEMODIR = demo
TESTSDIR = tests
BUILDDIR = build
KEYDIR = keys

DEMO = like_demo
PERFS = like_mesure
.PHONY: $(DEMO) $(PERFS) finale clean mrproper

all: finale

finale: $(DEMO) $(PERFS)

$(DEMO):
	@(cd $(DEMODIR) && $(MAKE))

$(PERFS):
	@(cd $(TESTSDIR) && $(MAKE))

finale:
	@(mv $(DEMODIR)/$(DEMO) .)
	@(mv $(TESTSDIR)/$(PERFS) .)

clean:
	rm -rf $(BUILDDIR)/*.o
	rm -rf $(KEYDIR)/*.pem

mrproper: clean
	rm -rf $(DEMO) $(PERFS)