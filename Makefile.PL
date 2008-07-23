
open DUMP, ">Makefile" or die $!;
print DUMP << "EOMF"
default: Build Makefile
	./Build

Makefile: Makefile.PL
	$^X Makefile.PL

Build: Build.PL
	$^X Build.PL

.PHONY: default distclean

distclean: Build Makefile
	./Build \$@

test: Build Makefile
	./Build \$@

dist: Build Makefile
	./Build \$@

.SUFFIXES:  # This turns off the built in rules.  It is necessary to do so because of the %: rule

%:
	./Build \$@

EOMF

# meh
