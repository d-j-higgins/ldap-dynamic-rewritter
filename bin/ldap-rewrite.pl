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
require RRObj;

our $VERSION = '0.3';
our $sel;            # IO::Select;
our $server_sock;    # list of all sockets
my %msgidcache;      # store messageids for cache association purpose
my $log_fh;

# load config
our %debug ;
our $config ;
loadconfig();

my $cache = new ReqCache(expire => $config->{cacheexpire});

BEGIN
{

    # move to the proper relative directory
    my $SCRIPTDIR = dirname( File::Spec->rel2abs($0) );
    chdir("$SCRIPTDIR/..") || die("cannot chdir: $!");

    $SIG{__DIE__} = sub { Carp::confess @_ };
#    $SIG{__WARN__} = sub { Carp::cluck @_ };
    $SIG{'__WARN__'} = sub { warn @_; main::log(@_); };
}

sub loadconfig
{

my $y      = LoadFile("./etc/config.yaml");
%debug  = %{ $y->{debug} };
$config = $y->{config};
$config->{last}=time();
#warn "reloading config\n";
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
    print $log_fh localtime()." - ".join( "\n".localtime()." - ", @_ ), "\n";
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
        disconnect($clientsocket);
        disconnect($serversocket);
        return undef;
    }
    my $decodedpdu = $LDAPRequest->decode($reqpdu);

    if ( $debug{pkt} )
    {
        print '-' x 80, "\n";
        print "Request ASN 1:\n";
        Convert::ASN1::asn_hexdump( \*STDOUT, $reqpdu );
        print "Request Perl:\n";
        print dump($decodedpdu);
    }

    if ( $decodedpdu->{extendedReq} && $decodedpdu->{extendedReq}->{requestName} eq '1.3.6.1.4.1.1466.20037' )
        {
        # this is an SSL request. not implemented yet
        #TODO
        disconnect($clientsocket);
        disconnect($serversocket);
        warn("CRIT: SSL/TLS request but this feature is not implemented");
        return;
        }

    if ( $decodedpdu->{unbindRequest} && $decodedpdu->{unbindRequest} == 1)
    {
    warn "Client requested unbind (disconnect)" if $debug{net};
    disconnect($clientsocket);
    disconnect($serversocket);
    return undef;
    }
    $decodedpdu = log_request($clientsocket,$serversocket,$decodedpdu);


    # check the cache for this request. forward to server if it's not found, or to client if it is
    my $key;
    my $cdata; 
    # only search requests are allowed to be cached
    # to verify: i believe that a bindrequest include a blank searchRequest 
    if ($decodedpdu->{searchRequest} && ! $decodedpdu->{bindRequest} )
	{
    	( $key, $cdata ) = $cache->get( $decodedpdu->{searchRequest} );

        if ( !$cdata || !$cdata->iscompleted())
        {
            warn "Request not cached" if $debug{cache};
    
            # store the messageid so that we can cache the response later
            # this is a client request, we always need to store this id
            warn "Caching msgid" if $debug{cache};
            $msgidcache{ $clientsocket."-".$decodedpdu->{messageID} } = $key;
        
            
            # do not make a new cached object of the cache simply isnt completed
            if (!$cdata)
            {
            # no cache entry, make a new one and cache it right away                                                                       
            warn "caching new request" if $debug{cache};                                                                 
            $cdata = new RRObj();
            $cdata->source($clientsocket."-".$decodedpdu->{messageID});
            $cdata->request($decodedpdu->{searchRequest});
            $cache->set( $decodedpdu->{searchRequest}, $cdata );        
            }
        
        	
        
            # send to server
            warn dump( \%msgidcache, "nocache", $key, $decodedpdu->{messageID} ) if $debug{cache2};
            my $eres= $LDAPRequest->encode($decodedpdu);
            return $eres;
        }
        else
        {
            warn "Request IS cached" if $debug{cache};

            # return the cached response, but replace the messageID since it's obviously outdated now
            foreach my $response (@{$cdata->response()})
            {
                 $response->{messageID} = $decodedpdu->{messageID};
                 warn "MSGID:" . $decodedpdu->{messageID} . " key: $key" if $debug{cache};
                 warn dump( "pkt", $decodedpdu, $response ) if $debug{cache};
                 print $clientsocket $LDAPResponse->encode($response);
            }
            return undef;  # return undef to indicate no more work is needed on this job because we could serve everything from cache
        }
    }
    # always send bind requests to server
    # and other requests
#   	if (! $decodedpdu->{bindRequest})
#    {
        warn dump( \%msgidcache, "nocache-bind", $key, $decodedpdu->{messageID} ) if $debug{cache2};
        my $eres= $LDAPRequest->encode($decodedpdu);
        return $eres;
#    }

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
    warn "Request: " . dump($request) if $debug{pktsecure};

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

	if ( $config->{filtervalidate} == 1 )
		{
		my $req= $LDAPRequest->encode($request);
			if (! defined($req))
				{
				die("ERROR: after running filter $filter, the request does not compile anymore! this probably means the filter corrupted the data structure!");
			
				}
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
	if ( $config->{filtervalidate} == 1 )
		{
		my $eres= $LDAPResponse->encode($response);
			if (! defined($eres))
				{
				die("WARNING: after running filter $filter, the response does not compile anymore!");
				}
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
        # obj not in cache, create a new one and cache that. otherwise append to it:
        # responses might be more than one element
        if (! $cached)
        {
            my $cached= new RRObj();
        }

        if ( $response->{protocolOp}->{searchResDone})
        {
                $cached->iscompleted(1);
        } 
        $cached->response($response);
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

    my $item= $server_sock->{endp($fh)};
    $srv    = $item->{server};
    $client = $item->{client};
    my $tmpendp;

    if ($srv)
    {
    $tmpendp=endp($srv);
    warn "removed srv ".$tmpendp if $debug{net};
        $sel->remove($srv);
        $srv->close;
        delete $server_sock->{ $tmpendp };
    }

    if ($client)
    {
    $tmpendp=endp($client);
    warn "removed client ".$tmpendp if $debug{net};
        $sel->remove($client);
        $client->close;
        delete $server_sock->{ $tmpendp };
    }
    use warnings;

    # we have finished with the socket
}

sub handleClientConnection
{
    my $sel = shift;    # IO::Selector
    my $fh  = shift;    # socket to handle

    my $clientreq = handleclientreq( $server_sock->{endp($fh)}->{client}, undef );
    if ( !defined($clientreq) )
    {
        # handleclientreq returned undef, meaning it handled all the work itself
        return 1;
    }

    # we have data to proxy, connect to the server now. 
    # if we don't already have a socket connection
    my $srv = $server_sock->{endp($fh)}->{server} ;
    if ( !$srv )
     {
     $srv= connect_to_server;
     my $t = { server => $srv, client => $fh };
     if ( !$t->{server} )
         {
             disconnect( $t->{client} );
             return 0;
         }
    
    $server_sock->{ endp($t->{client}) } = $t;
    $server_sock->{ endp($t->{server}) } = $t;
     }
    # and send the data
    print $srv $clientreq;

    warn "## handled ".endp($fh)." " . time if $debug{net};

    # we should also listen for the server's reply
    $sel->add( $srv );

    return 1;
}

sub endp
{
    my $fh = shift;

    no warnings;
    return undef if ! $fh;
    return $fh->peerhost . ":" . $fh->peerport.":".$fh->sockport;
}

#MAIN


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
    if ($config->{last}+15<= time())
	{
	# reload config every 15 seconds, subject to connections being made
	# this allows changing log levels on the fly
	loadconfig();
	}
    # on long running server, msgidcache will fill up the memory
    # this is a crude hack to get it back under control: when the server is idle, flush the cache
    if ( scalar keys %$server_sock == 0)
	{
	%msgidcache=();

    # purge the cache of requestcaches as well
    $cache->purge();
	}


    warn "## fh poll " . time if $debug{net};
    foreach my $fh (@ready)
    {
        warn "## fh ready ". endp($fh)." " . time if $debug{net};
        if ( $fh == $listenersock )
        {

            # listener is ready, meaning we have a new connection req waiting
            my $psock = $listenersock->accept;
            $server_sock->{endp($psock)} = { client => $psock };
            $sel->add($psock);
            warn "## add ".endp($psock)." " . time if $debug{net};
        }
        elsif ( endp($fh) eq endp($server_sock->{endp($fh)}->{client}) )
        {

            # a client socket is ready, a request has come in on it
            warn "## fh new client ".endp($fh)." " . time if $debug{net};
            handleClientConnection($sel,$fh);

        }
        else
        {
            warn "unrequested server data ".endp($fh)." " . time if $debug{net};
            if ( !handleserverdata( $server_sock->{endp($fh)}->{client}, $server_sock->{endp($fh)}->{server} ) )
            {
                disconnect($fh);
            }
        }
    }
}


1;
