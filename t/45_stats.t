
use strict;
use Net::Pcap::Easy;
use Test;
use Data::Dumper;
use File::Slurp qw(slurp);

plan tests => my $max = 3;

my $dev;
if( -s "device" ) {
    $dev = slurp('device');
    chomp $dev;
}

unless( $dev ) {
    warn "   [skipping tests: no device given]\n";
    skip(1, 0,0) for 1 .. $max;
    exit 0;
}

my $npe = Net::Pcap::Easy->new(
    dev              => $dev,
    promiscuous      => 1,
    packets_per_loop => 1,
    default_callback => sub {},
);

$npe->loop;

my $stats = $npe->stats;

ok( $stats->{recv}, 1 );
ok( defined($stats->{drop})   and $stats->{drop}   >= 0 );
ok( defined($stats->{ifdrop}) and $stats->{ifdrop} >= 0 );
