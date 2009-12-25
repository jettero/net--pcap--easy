#!/usr/bin/perl

use strict;
use warnings;
use Net::Pcap::Easy;

# all arguments to new are optoinal
my $npe = Net::Pcap::Easy->new(
    dev              => "lo",
    filter           => "host 127.0.0.1 and icmp",
    packets_per_loop => 10,
    bytes_to_capture => 1024,
    timeout_in_ms    => 0, # 0ms means forever
    promiscuous      => 0, # true or false

    icmp_callback => sub {
        my ($npe, $ether, $ip, $icmp) = @_;

        print "ICMP: $ether->{src_mac}:$ip->{src_ip} -> $ether->{dest_mac}:$ip->{dest_ip}\n";
    },
);

1 while $npe->loop;

