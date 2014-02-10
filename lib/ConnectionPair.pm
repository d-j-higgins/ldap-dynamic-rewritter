package ConnectionPair;

sub new
{

    my ( $class, %args ) = @_;
    my $self = {};
    $self->{client}=undef;
    $self->{server}=undef;
    $self->{serverid}=undef;
    $self->{clientid}=undef;
    $self->{request}=undef; # stores the request string
    $self->{clientmsgid}=undef; # stores the msgid of the current request
    $self = { %$self, %args };


    bless $self, $class;
    return $self;
}

sub clientid
{
    my ($self) =@_;
    return $self->{clientid};
}
sub serverid
{
    my ($self) =@_;
    return $self->{serverid};
}

sub disconnect
{
    my ($self,$sel) =@_;

    foreach my $kfh ("client","server")
    {
            my $fh=$self->{$kfh};
            next if ! $fh;
            $sel->remove($fh);
            $fh->close;

    }
}

sub client
{
        my ($self) =@_;
        return $self->{client};
}
sub server
{
        my ($self) =@_;
        return $self->{server};
}

#sub id
#{
#    my ($self)=@_;
#
##    no warnings;
##    return undef if ! $fh;
##    return $fh->peerhost . ":" . $fh->peerport.":".$fh->sockport;
#
#}
1;
