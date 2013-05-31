
use strict;
use Test;
use Net::Pcap::Easy;
use File::Slurp qw(slurp);

plan tests => my $max = 1;

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
    my $first = Unix::Process->vsz($$);
    for(1 .. 100) {
        my $npe = Net::Pcap::Easy->new( bytes_to_capture => 4096, dev=>$dev, ipv4_callback=>sub{} );
    }
    my $last = Unix::Process->vsz($$);

    # we should not grow significantly between runs but if we do... then we
    # should admit to being a total failure
    if( $last <= $first*1.5 ) {
        ok(1);

    } else {
        warn " ugh, before run vsz=$first; after is vsz=$last.  This is not acceptable.\n";
        ok(0);
    }

} else {
    warn " [skipping test, set install Unix::Process to test for memory leaks]\n";
    skip(1, 0,0) for 1 .. $max;
    exit 0;
}

