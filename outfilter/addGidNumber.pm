package addGidNumber;

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
    my ( $self, $res) = @_;

    my $found=0;
    foreach my $attr ( @{ $res->{attributes} } )
        {
        # res already has a gidNumber, do not add another one
        last if ( $attr->{type} =~ m/gidNumber/i );
        $found=1;
        }

    push @{ $res->{attributes} }, { type=>"gidNumber", vals => [123456] };
    # do stuff here
}


1;
