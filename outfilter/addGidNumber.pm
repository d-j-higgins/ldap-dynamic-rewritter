package addGidNumber;
# adds a gidNumber to every entry (as well as a posixGroup objectclass)
# this is to satisfy things which REQUIRES the gid to be present when your ldap server does not provide it: ie: web authentication using pam_ldap in nginx

# the gid generated will be unique per entry and consistent across calls (at least until somebody deletes the database of local gid ...)

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
    #warn "addgid filter";

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
    #    warn "no gid number found, adding";
        push @{ $res->{attributes} }, { type => "gidNumber",   vals => [ GidCache::encodeGidNumber( GidCache::getGroupGid( $res->{objectName} ) ) ] };
        push @{ $res->{attributes} }, { type => "objectClass", vals => ['posixGroup'] };
    }

}

1;
