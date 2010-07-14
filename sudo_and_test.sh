#!/bin/bash
# vi:syntax=gentoo-init-d:

set -e

unset TEST_DEVICE
export PERL_MM_USE_DEFAULT=1
perl Makefile.PL
make

# I use pub, ymmv, this is for my testing purposes
echo ${DEV:-pub} > device
sudo make test
echo -n > device

