package addGidNumber;

use lib 'lib/';
use GidCache;

sub new()
{
    my ($class) = @_;

    my $self = {};
    bless $self, $class;

    return $self;
}

# searchResEntry has format { attributes => [ { type => ATTRNAME, vals => [actual values] } , ... ], objectName => 'DN' }
sub filter
{
    my ( $self, $res ) = @_;
    warn "addgid filter";

    my $found = 0;
    foreach my $attr ( @{ $res->{attributes} } )
    {

        # res already has a gidNumber, do not add another one
        if ( $attr->{type} =~ m/^gidNumber/i )
        {
            $found = 1;
            last;
        }
    }

    if ( !$found )
    {
        warn "no gid number found, adding";
        push @{ $res->{attributes} }, { type => "gidNumber",   vals => [ GidCache::encodeGidNumber( GidCache::getGroupGid( $res->{objectName} ) ) ] };
        push @{ $res->{attributes} }, { type => "objectClass", vals => ['posixGroup'] };
    }

}

1;
