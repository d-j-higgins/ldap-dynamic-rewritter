package RRObj;
# Request and Response Object
#WIP

sub new
{

    my ( $class) = @_;
    my $self = {};
    $self->{source}=undef; # the source of the request
    $self->{complete}=0; # request is not complete
    $self->{request}=null;
    $self->{response}=[];


    bless $self, $class;
    return $self;
}

sub iscompleted
{
    my ($self, $set) = @_;
    return $self->{complete} if (!$set);
    return $self->{complete} = $set;
}

sub source 
{
    my ($self, $set) = @_;
    return $self->{source} if (!$set);
    return $self->{source} = $set;
}
sub request
{
    my ($self, $set) = @_;
    return $self->{request} if (!$set);
    return $self->{request} = $set;
}
sub response
{
    my ($self, $set) = @_;
    return $self->{response} if (!$set);
    push @{$self->{response}}, $set;
    return $self->{response};
}

1;
