
package Net::Pcap::Easy;

use strict;
use Carp;
use Socket;
use Net::Pcap;
use Net::Netmask;
use NetPacket::Ethernet qw(:types);
use NetPacket::IP qw(:protos);
use NetPacket::ARP qw(:opcodes);
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::IGMP;
use NetPacket::ICMP qw(:types);

our $VERSION     = "1.2";
our $MIN_SNAPLEN = 256;
our $DEFAULT_PPL = 32;

my %KNOWN_CALLBACKS = (map {($_=>1)} qw(
    appletalk_callback arp_callback arpreply_callback arpreq_callback default_callback icmp_callback
    icmpechoreply_callback icmpunreach_callback icmpsourcequench_callback icmpredirect_callback
    icmpecho_callback icmprouteradvert_callback icmproutersolicit_callback icmptimxceed_callback
    icmpparamprob_callback icmptstamp_callback icmptstampreply_callback icmpireq_callback
    icmpireqreply_callback igmp_callback ipv4_callback ipv6_callback ppp_callback rarpreply_callback
    rarpreq_callback snmp_callback tcp_callback udp_callback
));

sub DESTROY {
    my $this = shift;

    my $p = delete $this->{pcap};
    Net::Pcap::close($p) if $p;
}

sub dev {
    my $this = shift;
    $this->{dev}
}

sub network {
    my $this = shift;

    Socket::inet_ntoa(scalar reverse pack("l", $this->{network}));
}

sub netmask {
    my $this = shift;

    Socket::inet_ntoa(scalar reverse pack("l", $this->{netmask}));
}

sub cidr {
    my $this = shift;
    my $nm = $this->{nm};
       $nm = $this->{nm} = Net::Netmask->new($this->network . "/" . $this->netmask) unless $this->{nm};

    $nm;
}

sub is_local {
    my $this = shift;
    my $nm = $this->cidr;

    my $r = eval { $nm->contains( @_ ) }; croak $@ if $@;
    return $r;
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

    my ($network, $netmask);
    if (Net::Pcap::lookupnet($dev, \$network, \$netmask, \$err)) {
        croak "ERROR finding net and netmask for $dev: $err";

    } else {
        $this->{network} = $network;
        $this->{netmask} = $netmask;
    }

    for my $f (grep {m/_callback$/} keys %$this) {
        croak "the $f option does not point to a CODE ref" unless ref($this->{$f}) eq "CODE";
        warn  "the $f option is not a known callback and will never get called" unless $KNOWN_CALLBACKS{$f};
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

        return $this->ipv4( $ether, NetPacket::IP  -> decode($ether->{data})) if $type == ETH_TYPE_IP;
        return $this->arp(  $ether, NetPacket::ARP -> decode($ether->{data})) if $type == ETH_TYPE_ARP;
        
        return $cb->($this, $ether) if $type == ETH_TYPE_IPv6      and $cb = $this->{ipv6_callback};
        return $cb->($this, $ether) if $type == ETH_TYPE_SNMP      and $cb = $this->{snmp_callback};
        return $cb->($this, $ether) if $type == ETH_TYPE_PPP       and $cb = $this->{ppp_callback};
        return $cb->($this, $ether) if $type == ETH_TYPE_APPLETALK and $cb = $this->{appletalk_callback};

        return $cb->($this, $ether) if $cb = $this->{default_callback};
    };

    return $this;
}

sub icmp {
    my ($this, $ether, $ip, $icmp) = @_;

    my $cb;
    my $type = $icmp->{type};

    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_ECHOREPLY     and $cb = $this->{icmpechoreply_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_UNREACH       and $cb = $this->{icmpunreach_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_SOURCEQUENCH  and $cb = $this->{icmpsourcequench_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_REDIRECT      and $cb = $this->{icmpredirect_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_ECHO          and $cb = $this->{icmpecho_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_ROUTERADVERT  and $cb = $this->{icmprouteradvert_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_ROUTERSOLICIT and $cb = $this->{icmproutersolicit_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_TIMXCEED      and $cb = $this->{icmptimxceed_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_PARAMPROB     and $cb = $this->{icmpparamprob_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_TSTAMP        and $cb = $this->{icmptstamp_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_TSTAMPREPLY   and $cb = $this->{icmptstampreply_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_IREQ          and $cb = $this->{icmpireq_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_IREQREPLY     and $cb = $this->{icmpireqreply_callback};

    # NOTE: MASKREQ is exported as MASREQ ... grrz: http://rt.cpan.org/Ticket/Display.html?id=37931
    return $cb->($this, $ether, $ip, $icmp) if $type == NetPacket::ICMP::ICMP_MASKREQ() and $cb = $this->{icmpmaskreq_callback};
    return $cb->($this, $ether, $ip, $icmp) if $type == ICMP_MASKREPLY     and $cb = $this->{icmpmaskreply_callback};

    return $cb->($this, $ether, $ip, $icmp) if $cb = $this->{icmp_callback};
    return $cb->($this, $ether, $ip, $icmp) if $cb = $this->{ipv4_callback};
    return $cb->($this, $ether, $ip, $icmp) if $cb = $this->{default_callback};
}

sub ipv4 {
    my ($this, $ether, $ip) = @_;

    my $cb;
    my $proto = $ip->{proto};

    # NOTE: this could probably be made slightly more efficient and less repeatative.

    return $cb->($this, $ether, $ip, NetPacket::TCP  -> decode($ip->{data})) if $proto == IP_PROTO_TCP  and $cb = $this->{tcp_callback};
    return $cb->($this, $ether, $ip, NetPacket::UDP  -> decode($ip->{data})) if $proto == IP_PROTO_UDP  and $cb = $this->{udp_callback};
    return $this->icmp($ether,$ip,   NetPacket::ICMP -> decode($ip->{data})) if $proto == IP_PROTO_ICMP;
    return $cb->($this, $ether, $ip, NetPacket::IGMP -> decode($ip->{data})) if $proto == IP_PROTO_IGMP and $cb = $this->{igmp_callback};

    my $spo;
       $spo = NetPacket::TCP  -> decode($ip->{data}) if $proto == IP_PROTO_TCP;
       $spo = NetPacket::UDP  -> decode($ip->{data}) if $proto == IP_PROTO_UDP;
       $spo = NetPacket::IGMP -> decode($ip->{data}) if $proto == IP_PROTO_IGMP;

    return $cb->($this, $ether, $ip, $spo) if $cb = $this->{ipv4_callback};
    return $cb->($this, $ether, $ip, $spo) if $cb = $this->{default_callback};
}

sub arp {
    my ($this, $ether, $arp) = @_;

    my $cb;
    my $op = $this->{opcode};

    return $cb->($this, $ether, $arp) if $op ==  ARP_OPCODE_REQUEST and $cb = $this->{arpreq_callback};
    return $cb->($this, $ether, $arp) if $op ==  ARP_OPCODE_REPLY   and $cb = $this->{arpreply_callback};
    return $cb->($this, $ether, $arp) if $op == RARP_OPCODE_REQUEST and $cb = $this->{rarpreq_callback};
    return $cb->($this, $ether, $arp) if $op == RARP_OPCODE_REPLY   and $cb = $this->{rarpreply_callback};

    return $cb->($this, $ether, $arp) if $cb = $this->{arp_callback};
    return $cb->($this, $ether, $arp) if $cb = $this->{default_callback};
}

sub loop {
    my $this = shift;

    my $ret = Net::Pcap::loop($this->{pcap}, $this->{packets_per_loop}, $this->{_mcb}, "user data");

    return unless $ret == 0;
    return 1;
}

"true";
