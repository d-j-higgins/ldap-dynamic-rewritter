#!/usr/bin/perl
# Copyright (c) 2006 Hans Klunder <hans.klunder@bigfoot.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

# It's modified by Dobrica Pavlinusic <dpavlin@rot13.org> to include following:
#
# * rewrite LDAP bind request cn: username@domain.com -> uid=username,dc=domain,dc=com
# * rewrite search responses:
# ** expand key:value pairs from hrEduPersonUniqueNumber into hrEduPersonUniqueNumber_key
# ** augment response with yaml/dn.yaml data (for external data import)

use strict;
use warnings;

use IO::Select;
use IO::Socket;
use IO::Socket::SSL;
use warnings;
use Data::Dump qw/dump/;
use Convert::ASN1 qw(asn_read);
use Net::LDAP::ASN qw(LDAPRequest LDAPResponse);
our $VERSION = '0.3';
use fields qw(socket target);
use YAML qw/LoadFile/;
use Carp;
our $sel; # IO::Select;
our $server_sock;    # list of all sockets

$SIG{__DIE__} = sub { Carp::confess @_ };

my $debug = 0;

my $config = {
    yaml_dir       => './yaml/',
    outfilter_dir  => './outfilter/',
    infilter_dir   => './infilter/',
    listen         => shift @ARGV || ':1389',
    upstream_ldap  => 'ldap.hp.com',
    upstream_ssl   => 1,
    overlay_prefix => 'ffzg-',
    log_file       => 'log/ldap-rewrite.log',
};

my $log_fh;

sub log
{
    return unless $config->{log_file};

    if ( !$log_fh )
    {
        open( $log_fh, '>>', $config->{log_file} ) || die "can't open ", $config->{log_file}, ": $!";
        print $log_fh "# " . time;
    }
    $log_fh->autoflush(1);
    print $log_fh join( "\n", @_ ), "\n";
}

BEGIN
{
    $SIG{'__WARN__'} = sub { warn @_; main::log(@_); }
}

if ( !-d $config->{yaml_dir} )
{
    warn "DISABLE ", $config->{yaml_dir}, " data overlay";
}


sub handleserverdata
{
    my $clientsocket = shift;
    my $serversocket = shift;

    # read from server
    asn_read( $serversocket, my $respdu );
    if ( !$respdu )
    {
        warn "server closed connection\n";
        return 0;
    }
    $respdu = log_response($respdu);

    # and send the result to the client
    print $clientsocket $respdu || return 0;

    return 1;    # more expected
}

sub handleclientreq
{
    my $clientsocket = shift;
    my $serversocket = shift;

    # read from client
    asn_read( $clientsocket, my $reqpdu );
    if ( !$reqpdu )
    {
        warn "client closed connection\n";
        return 0;
    }
    $reqpdu = log_request($reqpdu);

    # send to server
    print $serversocket $reqpdu || return 0;

    return 1;
}

sub log_request
{
    my $pdu = shift;

    die "empty pdu" unless $pdu;

    #	print '-' x 80,"\n";
    #	print "Request ASN 1:\n";
    #	Convert::ASN1::asn_hexdump(\*STDOUT,$pdu);
    #	print "Request Perl:\n";
    my $request = $LDAPRequest->decode($pdu);
    my $filtered;

    # WARN: this has security implication, we do NOT want to log this packet ever, but it is useful for writing infilters
    #    warn "## request = ", dump($request);
    warn "## Received request" if $debug;

    # do dynamic filters
    foreach my $filter (@{$config->{infilters}})
    {
        warn( "running filter: " . $filter );

        eval {
            my $filterobj = new $filter;
            $filterobj->filter($request);
            $filtered=1;
        };
        if ($@)
        {
            warn "Unable to run filter $filter: $@";
        }
    }

    $pdu = $LDAPRequest->encode($request) if $filtered;
    return $pdu;
}


sub load_filters
{
    my ( $dir, $store ) = @_;

    opendir( my $dh, "$dir" );
    foreach my $file ( grep /^([^\.]+)\.pm$/, readdir $dh )
    {
        $file =~ m/^([^\.]+)\.pm$/;
        my $filter = $1;
        warn( "load filter: " . $filter );
        eval { require "$dir/$file"; };

        if ($@)
        {
            warn "Unable to load $file: $@";
        }
        else
        {
            push @$store, $filter;
        }

    }
    closedir($dh);
}

sub log_response
{
    my $pdu = shift;
    die "empty pdu" unless $pdu;

    #	print '-' x 80,"\n";
    #	print "Response ASN 1:\n";
    #	Convert::ASN1::asn_hexdump(\*STDOUT,$pdu);
    #	print "Response Perl:\n";
    my $response = $LDAPResponse->decode($pdu);

    if ( defined $response->{protocolOp}->{searchResEntry} )
    {
        my $uid = $response->{protocolOp}->{searchResEntry}->{objectName};
        warn "## objectName $uid";

        # searchResEntry has format { attributes => [ { type => ATTRNAME, vals => [actual values] } , ... ], objectName => 'DN' }

        # do dynamic filters
        foreach my $filter (@{$config->{outfilters}})
        {
            warn( "running filter: " . $filter );

            eval {
                my $filterobj = new $filter;
                my $res       = $filterobj->filter( $response->{protocolOp}->{searchResEntry} );
            };
            if ($@)
            {
                warn "Unable to run filter $filter: $@";
            }
        }

        # do YAML attributes
        # YAML file may be a DN-named file or attributename/value ending in .yaml
        # ie gidNumber/3213.yaml
        my @additional_yamls = ($uid);
        foreach my $attr ( @{ $response->{protocolOp}->{searchResEntry}->{attributes} } )
        {
            foreach my $v ( @{ $attr->{vals} } )
            {
                push @additional_yamls, $attr->{type} . '/' . $v;
            }
        }

        #warn "# additional_yamls ",dump( @additional_yamls );
        foreach my $path (@additional_yamls)
        {
            my $full_path = $config->{yaml_dir} . '/' . $path . '.yaml';
            next unless -e $full_path;

            my $data = LoadFile($full_path);
            warn "# $full_path yaml = ", dump($data);

            foreach my $type ( keys %$data )
            {
                my $vals = $data->{$type};

                push @{ $response->{protocolOp}->{searchResEntry}->{attributes} },
                  {
                    type => $config->{overlay_prefix} . $type,
                    vals => ref($vals) eq 'ARRAY' ? $vals : [$vals],
                  };
            }
        }

        $pdu = $LDAPResponse->encode($response);
    }

    #    warn "## response = ", dump($response);

    return $pdu;
}



sub connect_to_server
{
    my $sock;
    if ( $config->{upstream_ssl} )
    {
        $sock = IO::Socket::SSL->new( $config->{upstream_ldap} . ':ldaps' );
    }
    else
    {
        $sock = IO::Socket::INET->new(
            Proto    => 'tcp',
            PeerAddr => $config->{upstream_ldap},
            PeerPort => 389,
        );
    }

    if ( !$sock )
    {
        warn "can't open ", $config->{upstream_ldap}, " $!\n";
        return undef;
    }

    warn "## connected to ", $sock->peerhost, ":", $sock->peerport, "\n";
    return $sock;
}

sub disconnect
{
    my $fh = shift;

    # one of two connection has closed. terminate
    no warnings;
    warn "## remove $fh " . time;

    my $srv;
    my $client;
    $srv    = $server_sock->{$fh}->{server};
    $client = $server_sock->{$fh}->{client};
    $sel->remove($srv);
    $sel->remove($client);
    $srv->close    if $srv;
    $client->close if $client;
    delete $server_sock->{$client};
    delete $server_sock->{$srv};
    use warnings;

    # we have finished with the socket
}

my $listenersock = IO::Socket::INET->new(
    Listen    => 5,
    Proto     => 'tcp',
    Reuse     => 1,
    LocalAddr => $config->{listen},
) || die "can't open listen socket: $!";

$sel = IO::Select->new($listenersock);
$config->{outfilters}=[];
$config->{infilters}=[];
load_filters( $config->{outfilter_dir},$config->{outfilters} );
load_filters( $config->{infilter_dir}, $config->{infilters} );
warn "# config = ", dump($config);

while ( my @ready = $sel->can_read )
{
    warn "## fh poll " . time if $debug;
    foreach my $fh (@ready)
    {
        warn "## fh ready $fh " . time if $debug;
        if ( $fh == $listenersock )
        {

            # listener is ready, meaning we have a new connection req waiting
            my $psock = $listenersock->accept;
            $server_sock->{$psock} = { client => $psock };
            $sel->add($psock);
            warn "## add $psock " . time if $debug;
        }
        elsif ( $fh == $server_sock->{$fh}->{client} )
        {

            # a client socket is ready, a request has come in on it
            warn "## fh new client $fh " . time;

            my $t = { server => connect_to_server, client => $fh };
            if ( !$t->{server} )
            {
                disconnect( $t->{client} );
                next;
            }

            $server_sock->{ $t->{client} } = $t;
            $server_sock->{ $t->{server} } = $t;
            if ( !handleclientreq( $server_sock->{$fh}->{client}, $server_sock->{$fh}->{server} ) )
            {
                disconnect($fh);
            }
            warn "## handled $fh " . time if $debug;

            # server socket did not disconnect, meaning the server has more data to send to us. add the socket to the selector
            $sel->add( $server_sock->{$fh}->{server} );
        }
        else
        {
            warn "unrequested server data " . time if $debug;
            if ( !handleserverdata( $server_sock->{$fh}->{client}, $server_sock->{$fh}->{server} ) )
            {
                disconnect($fh);
            }
        }
    }
}

1;
