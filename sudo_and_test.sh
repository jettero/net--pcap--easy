#!/bin/bash
# vi:syntax=gentoo-init-d:

set -e

unset TEST_DEVICE
export PERL_MM_USE_DEFAULT=1
perl Makefile.PL
make

# I use eth2, ymmv, this is for my testing purposes
echo eth2 > device
sudo make test
echo skip > device

