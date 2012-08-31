#!/usr/bin/perl
# Copyright (c) 2006 Hans Klunder <hans.klunder@bigfoot.com>. All rights reserved.
# Copyright (c) 2009 Dobrica Pavlinusic <dpavlin@rot13.org> All rights reserved.
# Copyright (c) 2012 Hewlett-Packard Development Company, L.P
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

# It's modified by Dobrica Pavlinusic <dpavlin@rot13.org> to include following:
#
# * rewrite LDAP bind request cn: username@domain.com -> uid=username,dc=domain,dc=com
# * rewrite search responses:
# ** expand key:value pairs from hrEduPersonUniqueNumber into hrEduPersonUniqueNumber_key
# ** augment response with yaml/dn.yaml data (for external data import)
#
# Modified by Daniel Higgins <dhiggins@hp.com>
# * fix some socket-reading bugs for large server replies
# * simplify workflow
# * implement dynamic filters support
# * move original bind request and search response filtering to dynamic filters
# * implement addGidNumber dynamic filter

use strict;
use warnings;

use IO::Select;
use IO::Socket;
use IO::Socket::SSL;
use Data::Dump qw/dump/;
use Convert::ASN1 qw(asn_read);
use Net::LDAP::ASN qw(LDAPRequest LDAPResponse);
use fields qw(socket target);
use YAML qw/LoadFile/;
use Carp;
use File::Spec;
use File::Basename;

use lib 'lib';
require ReqCache;

our $VERSION = '0.3';
our $sel;            # IO::Select;
our $server_sock;    # list of all sockets
my %msgidcache;      # store messageids for cache association purpose
my $cache = new ReqCache;
my $log_fh;

# load config
my $y      = LoadFile("./etc/config.yaml");
my %debug  = %{ $y->{debug} };
my $config = $y->{config};

BEGIN
{

    # move to the proper relative directory
    my $SCRIPTDIR = dirname( File::Spec->rel2abs($0) );
    chdir("$SCRIPTDIR/..") || die("cannot chdir: $!");

    $SIG{__DIE__} = sub { Carp::confess @_ };
    $SIG{'__WARN__'} = sub { warn @_; main::log(@_); };
}

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

sub handleserverdata
{
    my $clientsocket = shift;
    my $serversocket = shift;

    # read from server
    asn_read( $serversocket, my $respdu );
    if ( !$respdu )
    {
        warn "server closed connection\n" if $debug{net};
        return 0;
    }
    my $response = $LDAPResponse->decode($respdu);
    $respdu = log_response($clientsocket,$serversocket,$response);

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
        warn "client closed connection\n" if $debug{net};
        return 0;
    }
    my $decodedpdu = $LDAPRequest->decode($reqpdu);
    $decodedpdu = log_request($clientsocket,$serversocket,$decodedpdu);

    # check the cache for this request. forward to server if it's not found, or to client if it is
    my ( $key, $cdata ) = $cache->get( $decodedpdu->{searchRequest} );
    if ( !$cdata )
    {
        warn "Request not cached" if $debug{cache};

        # send to server
        $msgidcache{ $clientsocket."-".$decodedpdu->{messageID} } = $key;

        warn dump( \%msgidcache, "nocache", $key, $decodedpdu->{messageID} ) if $debug{cache2};
        print $serversocket $LDAPRequest->encode($decodedpdu) || return 0;
    }
    else
    {
        warn "Request IS cached" if $debug{cache};

        # return the cached response, but replace the messageID since it's obviously outdated now
        foreach my $response (@$cdata)
        {
            $response->{messageID} = $decodedpdu->{messageID};
            warn "MSGID:" . $decodedpdu->{messageID} . " key: $key" if $debug{cache};
            warn dump( "pkt", $decodedpdu, $response ) if $debug{cache};
            print $clientsocket $LDAPResponse->encode($response);
        }
    }

    return 1;
}

sub log_request
{
    my $clientsocket = shift;
    my $serversocket = shift;
    my $request = shift;

    die "empty pdu" unless $request;

    #	print '-' x 80,"\n";
    #	print "Request ASN 1:\n";
    #	Convert::ASN1::asn_hexdump(\*STDOUT,$pdu);
    #	print "Request Perl:\n";

    warn "## Received request" if $debug{net};
    warn "Request: " . dump($request) if $debug{pkt};

    # do dynamic filters
    foreach my $filter ( @{ $config->{infilters} } )
    {
        warn( "running filter: " . $filter ) if $debug{filter};

        eval {
            my $filterobj = new $filter;
            $filterobj->filter($request);
        };
        if ($@)
        {
            warn "Unable to run filter $filter: $@" if $debug{filter};
        }
    }

    return $request;
}

sub load_filters
{
    my ( $dir, $store ) = @_;

    opendir( my $dh, "$dir" );
    foreach my $file ( grep /^([^\.]+)\.pm$/, readdir $dh )
    {
        $file =~ m/^([^\.]+)\.pm$/;
        my $filter = $1;
        warn( "load filter: " . $filter ) if $debug{filter};
        eval { require "$dir/$file"; };

        if ($@)
        {
            warn "Unable to load $file: $@" if $debug{filter};
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
    my $clientsocket = shift;
    my $serversocket = shift;
    my $response = shift;
    die "empty pdu" unless $response;

    #	print '-' x 80,"\n";
    #	print "Response ASN 1:\n";
    #	Convert::ASN1::asn_hexdump(\*STDOUT,$pdu);
    #	print "Response Perl:\n";
    warn "Response: " . dump($response) if $debug{pkt};

    if ( defined $response->{protocolOp}->{searchResEntry} )
    {
        my $uid = $response->{protocolOp}->{searchResEntry}->{objectName};
        warn "## objectName $uid" if $debug{filter};

        # searchResEntry has format { attributes => [ { type => ATTRNAME, vals => [actual values] } , ... ], objectName => 'DN' }

        # do dynamic filters
        foreach my $filter ( @{ $config->{outfilters} } )
        {
            warn( "running filter: " . $filter ) if $debug{filter};

            eval {
                my $filterobj = new $filter;
                my $res       = $filterobj->filter( $response->{protocolOp}->{searchResEntry} );
            };
            if ($@)
            {
                warn "Unable to run filter $filter: $@" if $debug{filter};
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
            warn "# $full_path yaml = ", dump($data) if $debug{filter};

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

    }
    ##cache storage
    if ( $_ = $msgidcache{$clientsocket."-".$response->{messageID} } )
    {
        warn "CACHE: Previous request: $_" if $debug{cache};
        warn dump($response) if $debug{cache2};
        my $cached = $cache->get($_);
        if ($cached)
        {
            push @$cached, $response;
        }
        else
        {
            $cached = [$response];
        }
        $cache->set( $_, $cached );
    }
    else
    {

        #            warn "CACHE: no previous request for $response->{messageID}";
    }
    ##
    my $pdu = $LDAPResponse->encode($response);

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
        warn "can't open ", $config->{upstream_ldap}, " $!\n" if $debug{net};
        return undef;
    }

    warn "## connected to ", $sock->peerhost, ":", $sock->peerport, "\n" if $debug{net};
    return $sock;
}

sub disconnect
{
    my $fh = shift;

    # one of two connection has closed. terminate
    no warnings;
    warn "## remove $fh " . time if $debug{net};

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

if ( !-d $config->{yaml_dir} )
{
    warn "DISABLE ", $config->{yaml_dir}, " data overlay" if $debug{warn};
}

my $listenersock = IO::Socket::INET->new(
    Listen    => 5,
    Proto     => 'tcp',
    Reuse     => 1,
    LocalAddr => $config->{listen},
) || die "can't open listen socket: $!";

$sel                  = IO::Select->new($listenersock);
$config->{outfilters} = [];
$config->{infilters}  = [];
load_filters( $config->{outfilter_dir}, $config->{outfilters} );
load_filters( $config->{infilter_dir},  $config->{infilters} );
warn "# config = ", dump($config);

while ( my @ready = $sel->can_read )
{
    warn "## fh poll " . time if $debug{net};
    foreach my $fh (@ready)
    {
        warn "## fh ready $fh " . time if $debug{net};
        if ( $fh == $listenersock )
        {

            # listener is ready, meaning we have a new connection req waiting
            my $psock = $listenersock->accept;
            $server_sock->{$psock} = { client => $psock };
            $sel->add($psock);
            warn "## add $psock " . time if $debug{net};
        }
        elsif ( $fh == $server_sock->{$fh}->{client} )
        {

            # a client socket is ready, a request has come in on it
            warn "## fh new client $fh " . time if $debug{net};

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
            warn "## handled $fh " . time if $debug{net};

            # server socket did not disconnect, meaning the server has more data to send to us. add the socket to the selector
            $sel->add( $server_sock->{$fh}->{server} );
        }
        else
        {
            warn "unrequested server data " . time if $debug{net};
            if ( !handleserverdata( $server_sock->{$fh}->{client}, $server_sock->{$fh}->{server} ) )
            {
                disconnect($fh);
            }
        }
    }
}

1;
