#!/usr/bin/perl

BEGIN { exec "sudo" => $0 => @ARGV unless $> == 0 }
BEGIN { system("make || (perl Makefile.PL && make)") == 0 or die }

use strict;
use lib ("blib/lib", "blib/arch");
use Net::Pcap::Easy;
use WWW::Mechanize;

use Test;
plan tests => 10*2;

my $ppid = $$;
if( my $kpid = fork ) {
    my $val = 1;
    local $SIG{HUP} = sub { $val = 0; };

    sleep 1 while $val;

    my $mech = new WWW::Mechanize;
       $mech->get("http://www.google.com/") for 1 .. 10;

    waitpid $kpid, 0;
    exit 0;
}

my $npe = Net::Pcap::Easy->new(
    dev              => 'eth0',
    filter           => "tcp and port 80",
    promiscuous      => 1,
    packets_per_loop => 10,

    tcp_callback => sub {
        my ($ether, $ip, $tcp) = @_;

        ok( $ip->{src_ip},  qr(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) );
        ok( $ip->{dest_ip}, qr(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) );
    },
);

kill 1, $ppid;
$npe->loop;
