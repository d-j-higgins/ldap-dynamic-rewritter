package LDAP::Virtual;

use strict;
use warnings;

use Net::LDAP::Constant qw(
	LDAP_SUCCESS
	LDAP_STRONG_AUTH_NOT_SUPPORTED
	LDAP_UNAVAILABLE
	LDAP_OPERATIONS_ERROR
);
use Net::LDAP::Server;
use Net::LDAP::Filter;
use base qw(Net::LDAP::Server);
use fields qw(upstream);

use Net::LDAP;

use URI::Escape;	# uri_escape
use IO::Socket::INET;
use IO::Select;

use YAML qw/DumpFile/;

use Data::Dump qw/dump/;

=head1 NAME

LDAP::Virtual

=cut

=head1 DESCRIPTION

Provide LDAP server functionality somewhat similar to C<slapo-rwm>

=head1 METHODS

=head2 run

  my $pid = LDAP::Virtual->run({ port => 1389, fork => 0 });

=cut

our $pids;

sub run {
	my $self = shift;

	my $args = shift;
	# default LDAP port
	my $port = $args->{port} ||= 1389;

	if ( $args->{fork} ) {
		defined(my $pid = fork()) or die "Can't fork: $!";
		if ( $pid ) {
			$pids->{ $port } = $pid;
			warn "# pids = ",dump( $pids );
			sleep 1;
			return $pid;
		}
	}

	my $sock = IO::Socket::INET->new(
		Listen => 5,
		Proto => 'tcp',
		Reuse => 1,
		LocalPort => $port,
	) or die "can't listen on port $port: $!\n";

	warn "LDAP server listening on port $port\n";

	my $sel = IO::Select->new($sock) or die "can't select socket: $!\n";
	my %Handlers;
	while (my @ready = $sel->can_read) {
		foreach my $fh (@ready) {
			if ($fh == $sock) {
				# let's create a new socket
				my $psock = $sock->accept;
				$sel->add($psock);
				$Handlers{*$psock} = LDAP::Virtual->new($psock);
			} else {
				my $result = $Handlers{*$fh}->handle;
				if ($result) {
					# we have finished with the socket
					$sel->remove($fh);
					$fh->close;
					delete $Handlers{*$fh};
				}
			}
		}
	}
}

=head2 stop

  my $stopped_pids = LDAP::Virtual->stop;

=cut

sub stop {
	warn "## stop pids = ",dump( $pids );
	return unless $pids;
	my $stopped = 0;
	foreach my $port ( keys %$pids ) {
		my $pid = delete($pids->{$port}) or die "no pid?";
		warn "# Shutdown LDAP server at port $port pid $pid\n";
		kill(9,$pid) or die "can't kill $pid: $!";
		waitpid($pid,0) or die "waitpid $pid: $!";
		$stopped++;
	}
	warn "## stopped $stopped processes\n";
	return $stopped;
}

use constant RESULT_OK => {
	'matchedDN' => '',
	'errorMessage' => '',
	'resultCode' => LDAP_SUCCESS
};

# constructor
sub new {
	my ($class, $sock) = @_;
	my $self = $class->SUPER::new($sock);
	printf "Accepted connection from: %s\n", $sock->peerhost();
	return $self;
}

# the bind operation
sub bind {
	my ($self,$req) = @_;

	warn "## bind req = ",dump($req);

	defined($req->{authentication}->{simple}) or return {
		matchedDN => '',
		errorMessage => '',
		resultCode => LDAP_STRONG_AUTH_NOT_SUPPORTED,
	};

	$self->{upstream} ||= Net::LDAP->new( 'ldaps://ldap.ffzg.hr/' ) or return {
		matchedDN => '',
		errorMessage => $@,
		resultCode => LDAP_UNAVAILABLE,
	};

	warn "## upstream = ",dump( $self->{upstream} );
	warn "upstream not Net::LDAP but ",ref($self->{upstream}) unless ref($self->{upstream}) eq 'Net::LDAP';

	my $msg;

	# FIXME we would need to unbind because VLDAP binds us automatically, but that doesn't really work
	#$msg = $self->{upstream}->unbind;
	#warn "# unbind msg = ",dump( $msg );

	my $bind;
	$bind->{dn} = $req->{name} if $req->{name};

	if ( $bind->{dn} =~ m{@} ) {

			$bind->{dn} =~ s/[@\.]/,dc=/g;
			$bind->{dn} =~ s/^/uid=/;

	}

	$bind->{password} = $req->{authentication}->{simple} if $req->{authentication}->{simple};
	warn "# bind ",dump( $bind );
	$msg = $self->{upstream}->bind( %$bind );

	#warn "# bind msg = ",dump( $msg );
	if ( $msg->code != LDAP_SUCCESS ) {
		warn "ERROR: ", $msg->code, ": ", $msg->server_error, "\n";
		return {
			matchedDN => '',
			errorMessage => $msg->server_error,
			resultCode => $msg->code,
		};
	}

	return RESULT_OK;
}

# the search operation
sub search {
	my ($self,$req) = @_;

	warn "## search req = ",dump( $req );

	if ( ! $self->{upstream} ) {
		warn "search without bind";
		return {
			matchedDN => '',
			errorMessage => 'dude, bind first',
			resultCode => LDAP_OPERATIONS_ERROR,
		};
	}

	my $filter;
	if (defined $req->{filter}) {
		# $req->{filter} is a ASN1-decoded tree; luckily, this is exactly the
		# internal representation Net::LDAP::Filter uses.  [FIXME] Eventually
		# Net::LDAP::Filter should provide a corresponding constructor.
		bless($req->{filter}, 'Net::LDAP::Filter');
		$filter = $req->{filter}->as_string;
#		$filter = '(&' . $req->{filter}->as_string
#					   . '(objectClass=hrEduPerson)(host=aai.irb.hr))';
	}

	warn "search upstream for $filter\n";

	my $search = $self->{upstream}->search(
		base => $req->{baseObject},
		scope => $req->{scope},
		deref => $req->{derefAliases},
		sizelimit => $req->{sizeLimit},
		timelimit => $req->{timeLimit},
		typesonly => $req->{typesOnly},
		filter => $filter,
		attrs => $req->{attributes},
		raw => qr/.*/,
	);

#	warn "# search = ",dump( $search );

	if ( $search->code != LDAP_SUCCESS ) {
		warn "ERROR: ",$search->code,": ",$search->server_error;
		return {
			matchedDN => '',
			errorMessage => $search->server_error,
			resultCode => $search->code,
		};
	};

	my @entries = $search->entries;
	warn "## got ", $search->count, " entries for $filter\n";
	foreach my $entry (@entries) {
#		$entry->changetype('add');  # Don't record changes.
#		foreach my $attr ($entry->attributes) {
#			if ($attr =~ /;lang-en$/) { 
#				$entry->delete($attr);
#			}
#		}
	}

	warn "## entries = ",dump( @entries );

	my $path = 'var/' . uri_escape( $filter ) . '.yml';
	DumpFile( $path, \@entries );
	warn "# created $path ", -s $path, " bytes";

	return RESULT_OK, @entries;
}

# the rest of the operations will return an "unwilling to perform"

1;
