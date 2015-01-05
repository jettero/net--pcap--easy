#!/bin/bash
# vi:syntax=gentoo-init-d:

set -e

unset TEST_DEVICE
export PERL_MM_USE_DEFAULT=1
perl Makefile.PL
make


def_route_dev=$(ip route | grep ^default | head -n 1 | perl -nE 'say $1 if m/dev\s+(\S+)/')
echo ${DEV:-$def_route_dev} > device
echo -n "using device="; cat device
sudo prove
echo -n > device

