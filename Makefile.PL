# vi:set syntax=perl:

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'          => 'Net::Pcap::Easy',
    'VERSION_FROM'  => 'Easy.pm',

    'PREREQ_PM'     => { 
        # NOTE: They have to be root *and* specify a device to run the tests on, 
        # if they're going to get that interactive they're probably not CPAN testers anyway.
        #
        # 'WWW::Mechanize' => 0,
        # 'Net::Ping'      => 0,
        'File::Slurp'         => 0, # the tests won't compile at all without this though

        'Net::Pcap'           => 0,
        'NetPacket::Ethernet' => 0,
        'NetPacket::IP'       => 0,
        'NetPacket::TCP'      => 0,
        'NetPacket::UDP'      => 0,
        'NetPacket::ARP'      => 0,
        'NetPacket::ICMP'     => 0,
        'Net::Netmask'        => 0,
        'Socket'              => 0,
    },

    clean => { FILES => 'device' },
);

my $dev = $ENV{TEST_DEVICE} || &get_dev;

open OUT, ">device" or die $!;
print OUT $dev;
close OUT;

sub get_dev {
    local $| = 1;
    print "network device on which to run tests (must be root) [e.g. eth0, default: skip]: ";

    my $d = <STDIN>; chomp $d;

    return $d;
}
