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
    my ( $self, $searchResEntry) = @_;

    # do stuff here

        # searchResEntry has format { attributes => [ { type => ATTRNAME, vals => [actual values] } , ... ], objectName => 'DN' }

        my @newattrs;
        foreach my $attr ( @{ $searchResEntry->{attributes} } )
        {
            # ? values of attribute date is rewritten as YY-MM-DD
            if ( $attr->{type} =~ m/date/i )
            {
                foreach my $i ( 0 .. $#{ $attr->{vals} } )
                {
                    $attr->{vals}->[$i] = "$1-$2-$3" if $attr->{vals}->[$i] =~ m/^([12]\d\d\d)([01]\d+)([0123]\d+)$/;
                }
            }
            elsif ( $attr->{type} eq 'hrEduPersonUniqueNumber' )
            {
            # ? values of hrEduPersonUniqueNumber is rewritten from a colon-separated list 1:2 2:3to multiple different attributes hrEduPersonUniqueNumber_1 = 2  hrEduPersonUniqueNumber_2 = 3
                foreach my $val ( @{ $attr->{vals} } )
                {
                    next if $val !~ m{.+:.+};
                    my ( $n, $v ) = split( /\s*:\s*/, $val );
                    push @newattrs, { type => $attr->{type} . '_' . $n, vals => [$v] };
                }
            }
            elsif ( $attr->{type} eq 'hrEduPersonGroupMember' )
            {
            # ? values of hrEduPersonGroupMember is checked for an invalid unicode char and removed
                foreach my $i ( 0 .. $#{ $attr->{vals} } )
                {
                    $attr->{vals}->[$i] =~ s/^u2010/p2010/gs && warn "FIXME group";
                }
            }
        }

        warn "# ++ attrs ", dump(@newattrs);

        push @{ $response->{protocolOp}->{searchResEntry}->{attributes} }, $_ foreach @newattrs;
    return $searchResEntry;
}
