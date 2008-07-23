
package Net::Pcap::Easy;

use strict;
use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::ICMP;

our $VERSION = "1.0";

sub new {
    my $class = shift;
    my $this = bless {}, $class;



    $this;
}

"true";
