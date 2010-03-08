package Catalyst::Authentication::Store::DBI::User;
use strict;
use warnings;

use Moose;
extends 'Catalyst::Authentication::User';

has 'store' => ( isa => 'HashRef' , is => 'ro' , required => 1 );

has 'user' => (
	isa => 'HashRef'
	, is => 'ro'
	, required => 1
	, traits => ['Hash']
	, handles => { 'get' => 'get' }
);

## Currently requires user-role to be joined on single key
has 'roles' => (
	isa  => 'ArrayRef'
	, is => 'ro'
	, default => sub {
		my $self = shift;
		#my $dbh = $c->model('DBI')->dbh;
		my $dbh   = $self->store->config->{'dbh'};
		
		my @field = (
			'role_table', 'role_name',
			'role_table',
			'user_role_table',
			'user_role_table', 'user_role_role_key',
			'role_table', 'role_key',
			'user_role_table', 'user_role_user_key',
		);

		my $sql = sprintf(
			'SELECT %s.%s FROM %s INNER JOIN %s ON %s.%s = %s.%s WHERE %s.%s = ?'
			, map { $dbh->quote_identifier($self->store->config->{$_}) } @field
		);

		my $sth = $dbh->prepare_cached($sql) or die($dbh->errstr());

		my $role;
		$sth->execute( $self->get($self->store->config->{'user_key'}) ) or
				die( $dbh->errstr() );
		$sth->bind_columns(\$role) or die($dbh->errstr());
		
		my @roles;
		while ($sth->fetch()) {
			push @roles, $role;
		}
		$sth->finish();

		return \@roles;
	}
);

sub id {
	my $self = shift;
	my $user_key = $self->store->config->{'user_key'};
	return $self->get($user_key);
}

# sub supports is implemented by the base class, so supported_features is enough
sub supported_features { +{ session => 1, roles => 1 } }

sub BUILDARGS {
	my $class = shift;
	my ( $store, $user ) = @_;
	
	scalar @_ == 1
		? $class->SUPER::BUILDARGS(@_)
		: { store => $store, user => $user }
	;

}

sub get_object { +shift->user }
sub obj { +shift->user }

1;

__END__

=head1 NAME

Catalyst::Authentication::Store::DBI::User - User object representing a
database record

=head1 DESCRIPTION

This class represents users found in the database and implements methods to
access the contained information.

=head1 METHODS

=head2 new

=head2 id

=head2 supported_features

=head2 get

I<DEPRECATED> use C<user> instead

=head2 get_object

I<DEPRECATED> use C<user> instead

This method returns the actual contents of the user, i.e. the hashref.

=head2 obj

Method alias to get_object for your convenience.

=head2 roles

=head1 SEE ALSO

=over 4

=item L<Catalyst::Authentication::Store::DBI>

=back

=head1 AUTHOR

Simon Bertrang, E<lt>simon.bertrang@puzzworks.comE<gt>

=head1 COPYRIGHT

Copyright (c) 2008 PuzzWorks OHG, L<http://puzzworks.com/>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
