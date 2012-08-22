package template;

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
    my ( $self, $asn ) = @_;

    # do stuff here

    return $asn;
}


1;
