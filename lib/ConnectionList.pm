package ConnectionList;

sub new
{
    my ( $class, %args ) = @_;
    my $self = {};
    $self->{list}={};
    $self->{sel}=undef;
    $self = { %$self, %args };

    bless $self, $class;
    return $self;
}

sub serverBusy
{
    my ($self)= @_;
    return scalar keys %{$self->{list}};

}
# generate an endpoint identifier from a socket filehandle
sub _endp
{
    my $fh = shift;

    no warnings;
    return undef if ! $fh;
    return $fh->peerhost . ":" . $fh->peerport.":".$fh->sockport;
}

sub newClient
{
    my ($self, $psock) =@_;
    my $endp= _endp($psock);
    $self->{list}->{$endp} = new ConnectionPair( clientid=>$endp, client => $psock );
    $self->{sel}->add($psock); # add it to IO::Select
    return $endp
}
sub newServer
{
    my ($self, $pair, $serverfh) =@_;
    my $endp= _endp($serverfh);
    $pair->{server}=$serverfh;
    $pair->{serverid}=$endp;

    $self->{list}->{$endp}=$pair;
    $self->{sel}->add($serverfh); # add it to IO::Select
    return $endp
}

sub findPair
{
    my ($self, $fh) =@_;
    my $endp= _endp($fh);
    return $self->{list}->{$endp};
}
sub isClient
{
    my ($self, $fh) =@_;
    return $self->findPair($fh)->{client} == $fh;
}
sub isServer
{
    my ($self, $fh) =@_;
    return $self->findPair($fh)->{server} == $fh;
}
    
sub disconnectPair
{
    my ($self, $pair) =@_;

    # one of two connection has closed. terminate
    no warnings;
    warn "## remove $fh " . time if $debug{net};
    delete $self->{list}->{$pair->{serverid}};
    delete $self->{list}->{$pair->{clientid}};
    $pair->disconnect($self->{sel});

    use warnings;

    # we have finished with the socket
}

# find the pair from an FH and disconnect it
sub disconnectFh
{
    my ($self, $fh) =@_;
    my $pair = $self->findPair($fh);
    $self->disconnectPair($pair);

}

1;
