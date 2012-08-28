package replaceGidSearch;

use Data::Dumper;
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
    warn "search gid filter";

    warn Dumper($res);

    foreach my $op ( keys %{ $res->{searchRequest}->{filter} } )
    {
        foreach my $cur ( @{ $res->{searchRequest}->{filter}->{$op} } )
        {
            next if ( $cur->{equalityMatch}->{attributeDesc} !~ /gidNumber/ );

            my $dgid = GidCache::decodeGidNumber( $cur->{equalityMatch}->{assertionValue} );
            my $name = GidCache::getGroupFromGid($dgid);
            next if ( $name =~ /ou=People/ );

            if ($name)
            {
                $cur->{equalityMatch}->{attributeDesc} = 'cn';
                $name =~ /cn=(.*?),/;
                $cur->{equalityMatch}->{assertionValue} = $1;
            }

        }

    }

    warn Dumper($res);
    return;

}

1;

