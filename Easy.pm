
package Net::Pcap::Easy;

use strict;
use Carp;
use Net::Pcap;
use NetPacket::Ethernet qw(:types);
use NetPacket::IP qw(:protos);
use NetPacket::ARP qw(:opcodes);
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::ICMP;

our $VERSION     = "1.0";
our $MIN_SNAPLEN = 256;
our $DEFAULT_PPL = 32;

sub DESTROY {
    my $this = shift;

    Net::Pcap::close($this->{pcap});
}

sub new {
    my $class = shift;
    my $this = bless { @_ }, $class;

    my $err;
    my $dev = ($this->{dev});
    unless( $dev ) {
        $dev = $this->{dev} = Net::Pcap::lookupdev(\$err);
        croak "ERROR while trying to find a device: $err" unless $dev;
    }

    my ($addr, $netmask);
    if (Net::Pcap::lookupnet($dev, \$addr, \$netmask, \$err)) {
        croak "ERROR finding net and netmask for $dev: $err";

    } else {
        $this->{address} = $addr;
        $this->{netmask} = $netmask;
    }

    my $ppl = $this->{packets_per_loop};
       $ppl = $this->{packets_per_loop} = $DEFAULT_PPL unless defined $ppl and $ppl > 0;

    my $ttl = $this->{timeout_in_ms} || 0;
       $ttl = 0 if $ttl < 0;

    my $snaplen = $this->{bytes_to_capture} || 1024;
       $snaplen = $MIN_SNAPLEN unless $snaplen >= 256;

    my $pcap = $this->{pcap} = Net::Pcap::open_live($dev, $snaplen, $this->{promiscuous}, $ttl, \$err);
    croak "ERROR opening pacp session: $err" if $err or not $pcap;

    if( my $f = $this->{filter} ) {
        my $filter;
        Net::Pcap::compile( $pcap, \$filter, $f, 1, $netmask ) && croak 'ERROR compiling pcap filter';
        Net::Pcap::setfilter( $pcap, $filter ) && die 'ERROR Applying pcap filter';
    }

    $this->{_mcb} = sub {
        my ($user_data, $header, $packet) = @_;
        my $ether = NetPacket::Ethernet->decode($packet);

        my $type = $ether->{type};
        my $cb;

        return $this->ipv4(  $ether, NetPacket::IP  -> decode($ether->{data})) if $type == ETH_TYPE_IP;
        return $this->arp(  $ether, NetPacket::ARP -> decode($ether->{data})) if $type == ETH_TYPE_ARP;
        
        return $cb->($ether) if $type == ETH_TYPE_IPv6      and $cb = $this->{ipv6_callback};
        return $cb->($ether) if $type == ETH_TYPE_SNMP      and $cb = $this->{snmp_callback};
        return $cb->($ether) if $type == ETH_TYPE_PPP       and $cb = $this->{ppp_callback};
        return $cb->($ether) if $type == ETH_TYPE_APPLETALK and $cb = $this->{appletalk_callback};

        return $cb->($ether) if $cb = $this->{default_callback};
    };

    return $this;
}

sub ipv4 {
    my ($this, $ether, $ip) = @_;

    my $cb;
    return $cb->($ether, $ip) if $cb = $this->{ipv4_callback};

    my $proto = $ip->{proto};
    return $cb->($ether, $ip, NetPacket::TCP  -> decode($ip->{data})) if $proto == IP_PROTO_TCP  and $cb = $this->{tcp_callback};
    return $cb->($ether, $ip, NetPacket::TCP  -> decode($ip->{data})) if $proto == IP_PROTO_UDP  and $cb = $this->{udp_callback};
    return $cb->($ether, $ip, NetPacket::ICMP -> decode($ip->{data})) if $proto == IP_PROTO_ICMP and $cb = $this->{icmp_callback};
    return $cb->($ether, $ip, NetPacket::IGMP -> decode($ip->{data})) if $proto == IP_PROTO_IGMP and $cb = $this->{igmp_callback};

    return $cb->($ether, $ip) if $cb = $this->{default_callback};
}

sub arp {
    my ($this, $ether, $arp) = @_;

    my $cb;
    return $cb->($ether, $arp) if $cb = $this->{arp_callback};

    my $op = $this->{opcode};
    return $cb->($ether, $arp) if $op ==  ARP_OPCODE_REQUEST and $cb = $this->{arpreq_callback};
    return $cb->($ether, $arp) if $op ==  ARP_OPCODE_REPLY   and $cb = $this->{arpreply_callback};
    return $cb->($ether, $arp) if $op == RARP_OPCODE_REQUEST and $cb = $this->{rarpreq_callback};
    return $cb->($ether, $arp) if $op == RARP_OPCODE_REPLY   and $cb = $this->{rarpreply_callback};

    return $cb->($ether, $arp) if $cb = $this->{default_callback};
}

sub loop {
    my $this = shift;

    Net::Pcap::loop($this->{pcap}, $this->{packets_per_loop}, $this->{_mcb}, "user data");
}

"true";
