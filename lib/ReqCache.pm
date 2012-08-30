package ReqCache;

use strict;
use warnings;
use Data::Dumper;
use Cache::FileCache;
use Storable qw/freeze/;
use Digest::SHA1 qw/sha1_base64/;

sub new
{
    my ( $class, %args ) = @_;
    my $self = {};
    $self = { %$self, %args };

    $self->{expire} ||= 3600;
    $self->{c} = new Cache::FileCache( { default_expires_in => $self->{expire} . ' seconds', autopurge_on_set => 0, namespace => "ldap", cache_root => "./cache" } );
    bless $self, $class;

    return $self;
}

sub genkey
{
    my ( $self, $struct ) = @_;

    return $struct if ref \$struct ne "REF";

    my $key    = freeze($struct);
    my $newkey = sha1_base64($key);

    #warn ("Frozen $key");
    #warn ("$newkey");

    return $newkey;
}

sub get
{
    my ( $self, $aKey ) = @_;
    my $key = $self->genkey($aKey);

    my $data = $self->{c}->get($key);
    if ($data)
    {
        return ( $key, $data );
    }
    return undef;
}

sub set
{
    my ( $self, $aKey, $data ) = @_;
    my $key = $self->genkey($aKey);

    $self->{c}->set( $key, $data );
    return 1;
}

1;
