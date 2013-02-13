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
#    warn "search gid filter";

    #    warn Dumper($res);

    return if (! $res->{searchRequest} ); # no search request, nothing to filter
    return if (! $res->{searchRequest}->{filter} ); # no filter in search request, nothing to rewrite

    foreach my $op ( keys %{ $res->{searchRequest}->{filter} } )
    {
        my $oparr;
        if ( ref $res->{searchRequest}->{filter}->{$op} eq 'HASH' )
        {
            $oparr = [ { $res->{searchRequest}->{filter}->{$op} } ];
        }
        else
        {
            $oparr = $res->{searchRequest}->{filter}->{$op};
        }
        foreach my $cur ( @{$oparr} )
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

#    warn Dumper($res);
    return;

}
1;
