
use Module::Build;
my $build = Module::Build->new(
    module_name       => 'Net::Pcap::Easy',
    dist_version_from => "Easy.pm",
    license           => 'lgpl',
     pm_files         => { 'Easy.pm'  => 'lib/Net/Pcap/Easy.pm'  },
    pod_files         => { 'Easy.pod' => 'lib/Net/Pcap/Easy.pod'  },
    build_requires    => { 'WWW::Mechanize' => 0, },
    requires          => {
        'Net::Pcap'           => 0,
        'NetPacket::Ethernet' => 0,
        'NetPacket::IP'       => 0,
        'NetPacket::TCP'      => 0,
        'NetPacket::UDP'      => 0,
        'NetPacket::ARP'      => 0,
        'NetPacket::ICMP'     => 0,
    }
);
$build->create_build_script;

