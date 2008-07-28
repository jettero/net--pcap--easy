
use Module::Build;
my $build = Module::Build->new(
    module_name       => 'Net::Pcap::Easy',
    dist_version_from => "Easy.pm",
    license           => 'lgpl',
     pm_files         => { 'Easy.pm'  => 'lib/Net/Pcap/Easy.pm'  },
    pod_files         => { 'Easy.pod' => 'lib/Net/Pcap/Easy.pod'  },

    build_requires    => {
        # NOTE: They have to be root *and* specify a device to run the tests on, 
        # if they're going to get that interactive they're probably not CPAN testers anyway.
        #
        # 'WWW::Mechanize' => 0,
        # 'Net::Ping'      => 0,

        'File::Slurp' => 0, # the tests won't compile at all without this though
    },

    requires          => {
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

    add_to_cleanup => ['device'],
);

if( my $d = ($ENV{TEST_DEVICE} || $build->prompt("network device on which to run tests", "skip")) ) {
    $d = '' if $d eq "skip";

    open my $out, ">device" or die $!;
    print $out $d;
    close $out;
}

$build->create_build_script;

