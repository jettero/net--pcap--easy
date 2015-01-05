
use strict;
use Test;
use Net::Pcap::Easy;
use File::Slurp qw(slurp);

plan tests => my $max = 50;

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

if( eval q{ use Unix::Process; 1; } ) {

    for(1 .. 50) {
        my $npe = Net::Pcap::Easy->new( bytes_to_capture => 4096, dev=>$dev, ipv4_callback=>sub{} );
    }

    my $first = Unix::Process->vsz($$);
    for(1 .. 50) {
        my $npe = Net::Pcap::Easy->new( bytes_to_capture => 4096, dev=>$dev, ipv4_callback=>sub{} );
        my $last = Unix::Process->vsz($$);

        ok( $last, $first );
        $first = $last;
    }

} else {
    warn " [skipping test, set install Unix::Process to test for memory leaks]\n";
    skip(1, 0,0) for 1 .. $max;
    exit 0;
}

