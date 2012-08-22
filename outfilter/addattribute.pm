package template;

sub new()
{
    my ($class) = @_;

    my $self = {};
    bless $self, $class;

    return $self;
}

sub filter
{
    my ( $self, $asn ) = @_;

    # do stuff here

    return $asn;
}
