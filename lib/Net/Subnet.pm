package Net::Subnet;

use strict;
use Socket;
use Socket6;

use base 'Exporter';
our @EXPORT = qw(subnet_matcher subnet_classifier sort_subnets);

our $VERSION = '1.00';

sub cidr2mask_v4 {
    my ($length) = @_;
    return pack "N", 0xffffffff << (32 - $length);
}

sub cidr2mask_v6 {
    my ($length) = @_;
    my $mask = "\x00" x 16;
    vec($mask, $_, 1) = 1 for 0 .. ($length - 1);
    return $mask;
}

sub subnet_matcher {
    @_ > 1 and goto &multi_matcher;

    my ($net, $mask) = split m[/], shift;
    return $net =~ /:/
        ? ipv6_matcher($net, $mask)
        : ipv4_matcher($net, $mask);
}

sub ipv4_matcher {
    my ($net, $mask) = @_;

    $net = inet_aton($net);
    $mask = $mask =~ /\./ ? inet_aton($mask) : cidr2mask_v4($mask);

    my $masked_net = $net & $mask;

    return sub { (inet_aton(shift) & $mask) eq $masked_net };
}

sub ipv6_matcher {
    my ($net, $mask) = @_;

    $net = inet_pton(AF_INET6, $net);
    $mask = $mask =~ /:/ ? inet_pton(AF_INET6, $mask) : cidr2mask_v6($mask);

    my $masked_net = $net & $mask;

    return sub { (inet_pton(AF_INET6, shift) & $mask) eq $masked_net };
}

sub multi_matcher {
    my @v4 = map subnet_matcher($_), grep !/:/, @_;
    my @v6 = map subnet_matcher($_), grep  /:/, @_;

    return sub {
        $_->($_[0]) and return 1 for $_[0] =~ /:/ ? @v6 : @v4;
        return !!0;
    }
}

sub subnet_classifier {
    my @v4 = map [ subnet_matcher($_), $_ ], grep !/:/, @_;
    my @v6 = map [ subnet_matcher($_), $_ ], grep  /:/, @_;

    return sub {
        $_->[0]->($_[0]) and return $_->[1] for $_[0] =~ /:/ ? @v6 : @v4;
        return undef;
    }
}

sub sort_subnets {
    my @unsorted;
    for (@_) {
        my ($net, $mask) = split m[/];

        $mask = $net =~ /:/
            ? ($mask =~ /:/ ? inet_pton(AF_INET6, $mask) : cidr2mask_v6($mask))
            : ($mask =~ /\./ ? inet_aton($mask) : cidr2mask_v4($mask));

        $net = $net =~ /:/
            ? inet_pton(AF_INET6, $net)
            : inet_aton($net);

        push @unsorted, sprintf "%-16s%-16s%s", ($net & $mask), $mask, $_;
    }

    return map substr($_, 32), reverse sort @unsorted;
}

1;

__END__

=head1 NAME

Net::Subnet - Fast IP-in-subnet matcher for IPv4 and IPv6, CIDR or mask.

=head1 SYNOPSIS

    use Net::Subnet;

    # CIDR notation
    my $is_rfc1918 = subnet_matcher(
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    );

    # Subnet mask notation
    my $is_rfc1918 = subnet_matcher(
        "10.0.0.0/255.0.0.0",
        "172.16.0.0/255.240.0.0",
        "192.168.0.0/255.255.0.0",
    );

    print $is_rfc1918->("192.168.1.1") ? "yes" : "no";  # prints "yes"
    print $is_rfc1918->("8.8.8.8")     ? "yes" : "no";  # prints "no"

    # Mixed IPv4 and IPv6
    my $in_office_network = subnet_matcher(
        "192.168.1.0/24", "2001:db8:1337::/48"
    );

    print $in_office_network->("192.168.1.1");            # prints 1
    print $in_office_network->("2001:db8:dead:beef::5");  # prints nothing

    my $classifier = subnet_classifier(
        "192.168.1.0/24",
        "2001:db8:1337::/48",
        "10.0.0.0/255.0.0.0",
    );

    $x = $classifier->("192.168.1.250");        # $x is "192.168.1.0/24"
    $x = $classifier->("2001:db8:1337::babe");  # $x is "2001:db8:1337::/48"
    $x = $classifier->("10.2.127.1");           # $x is "10.0.0.0/255.0.0.0"
    $x = $classifier->("8.8.8.8");              # $x is undef

    # More significant subnets (smaller subnets) must be listed first
    my @subnets = sort_subnets(
        "192.168.0.0/24",  # second
        "192.168.0.1/32",  # first
        "192.168.0.0/16",  # third
    );
    my $classifier = subnet_classifier(@subnets);

=head1 DESCRIPTION

This is a simple but fast pure Perl module for determining whether a given IP
address is in a given set of IP subnets. It's iterative, and it doesn't use any
fancy tries, but because it uses simple bitwise operations on strings it's
still very fast.

All documented functions are exported by default.

Subnets have to be given in "address/mask" or "address/length" (CIDR) format.
The Socket and Socket6 modules are used to normalise addresses, which means
that any of the address formats supported by inet_aton and inet_pton can be
used with Net::Subnet.

=head1 FUNCTIONS

=head1 subnet_matcher(@subnets)

Returns a reference to a function that returns true if the given IP address is
in @subnets, false it it's not.

=head1 subnet_classifier(@subnets)

Returns a reference to a function that returns the element from @subnets that
matches the given IP address, or undef if none matched.

=head1 sort_subnets(@subnets)

Returns @subnets in reverse order of prefix length and prefix; use this with
subnet_matcher or subnet_classifier if your subnet list has overlapping ranges
and it's not already sorted most-significant-first.

=head1 CAVEATS

No argument verification is done; garbage in, garbage out. If you give it
hostnames, DNS may be used to resolve them, courtesy of the Socket and Socket6
modules.

=head1 AUTHOR

Juerd Waalboer <#####@juerd.nl>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
