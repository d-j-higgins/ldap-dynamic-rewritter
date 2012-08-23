package addGidNumber;

use Fcntl qw(:flock SEEK_END);    # import LOCK_* and SEEK_END constants
use Cache::FileCache;

my $dbpath = "./db";
my $lock   = "$dbpath/.lock";
our $c = new Cache::FileCache( { default_expires_in => $EXPIRES_NEVER, autopurge_on_set => 0, namespace => "gidNumber", cache_root => "./db" } );

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
    warn "addgid filter";

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
        warn "no gid number found, adding";
        push @{ $res->{attributes} }, { type => "gidNumber", vals => [ encodeGidNumber( getGroupGid( $res->{objectName} ) ) ] };
    }

}

## expects a 24bit unique gid number
# returns a 32bit gid with the high bit set to 1. since typical gidnumbers are assigned from 0 growing up we do not expect collisions
sub encodeGidNumber
{
    my $lowgid = shift;
    my $rawgid;
    my $gid;
    vec( $rawgid, 31, 1 ) = 1;
    vec( $rawgid, 0,  8 ) = $lowgid & 0xFF;
    vec( $rawgid, 1,  8 ) = $lowgid >> 8;
    vec( $rawgid, 2,  8 ) = $lowgid >> 16;
    $gid = unpack( "L", $rawgid );
#    warn "encoded $gid";
    return $gid;
}

# find the last "local" gid number assigned in our database
sub findLastGid
{
    my $lastgid = $c->get("gid: last");
    if ( !$lastgid )
    {

        # this will be slow, but should never occur because of the set("gid: last") cache
        my @lastgid = grep ( /^gid:/, $c->get_keys );
        my @lastgid = sort { $a =~ /gid: (.*)/; $An = $1; $b =~ /gid: (.*)/; $An <=> $1 } @lastgid;
        $lastgid = $lastgid[-1];
        $lastgid =~ /^gid: (.*)/;
        $lastgid = $1;

        #       print "calculated lastgid: $lastgid\n";
        $c->set( "gid: last", $lastgid );
    }

    #   print "lastgid: $lastgid\n";
    return $lastgid;
}

# get or generate a gid number.
sub getGroupGid
{
    my $groupname = shift;

    my $gid = $c->get("group: $groupname");
    if ( !$gid )
    {

        # no gid for this group, make a new one
        my $thislock = filelock($lock);
        my $lastgid  = findLastGid;
        $gid = $lastgid + 1;
        $c->set( "gid: last",         $gid );
        $c->set( "gid: $gid",         "$groupname" );
        $c->set( "group: $groupname", "$gid" );
        unlock($thislock);
    }

    return $gid;
}

sub filelock
{
    my ($file) = @_;

    #    warn "lock $file";
    open( my $fh, ">>", "$file" ) or die "Can't open $file: $!";
    flock( $fh, LOCK_EX ) or die "Cannot lock- $!\n";

    # and, in case someone appended while we were waiting...
    seek( $fh, 0, SEEK_END ) or die "Cannot seek - $!\n";
    return $fh;
}

sub unlock
{
    my ($fh) = @_;

    #   warn "unlock";
    flock( $fh, LOCK_UN ) or die "Cannot unlock - $!\n";
}
1;
