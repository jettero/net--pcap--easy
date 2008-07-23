#!/usr/bin/perl

use strict;
use lib ("blib/lib", "blib/arch");
use Net::Pcap::Easy;
use WWW::Mechanize;
use File::Slurp qw(slurp);

use Test;
plan tests => 10*2;

# NOTE: there's little doubt with all the time sensitive things going on
# here that I'll see this on the CPAN tresters reports eventually...

my $dev;
if( -s "device" ) {
    $dev = slurp('device');
    chomp $dev;
}

unless( $dev ) {
    warn "   [skipping tests: no device given]\n";
    skip(1, 0,0) for 1 .. 20;
    exit 0;
}

$SIG{ALRM} = sub { exit 1 }; alarm 15;

my $ppid = $$;
my $kpid = fork;
if( not $kpid ) {
    my $val = 1;
    $SIG{HUP} = sub { $val = 0; };

    sleep 1 while $val;

    my $mech = new WWW::Mechanize;
       $mech->get("http://www.google.com/") for 1 .. 10;

    exit 0;
}

my $npe = eval { Net::Pcap::Easy->new(
    dev              => $dev,
    filter           => "tcp and port 80",
    promiscuous      => 0,
    packets_per_loop => 10,

    tcp_callback => sub {
        my ($ether, $ip, $tcp) = @_;

        ok( $ip->{src_ip},  qr(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) );
        ok( $ip->{dest_ip}, qr(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) );
    },
)};
my $skip;
if( $@ ) {
    if( $@ =~ m/(?:permission|permitted)/i ) {
        $skip = 1;

    } else {
        die "problem loading npe: $@";
    }
}

kill 1, $kpid;
if( $skip ) {
    warn "   [skipping tests: permission denied, try running as root]\n";
    skip(1, 0,0) for 1 .. 20;

} else {
    $npe->loop;
}

waitpid $kpid, 0;
exit 0;
