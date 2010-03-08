package Catalyst::Authentication::Store::DBI;
use strict;
use warnings;

use Moose;
use Catalyst::Authentication::Store::DBI::User;

our $VERSION = '0.01';

has 'config' => ( isa => 'HashRef', is => 'ro', required => 1 );

# locates a user using data contained in the hashref, this is rather awkward
# and inconsistant with the rest of the module-design which is only provides
# selectivity on user_key
sub find_user {
	my ($self, $authinfo, $c) = @_;
	my $dbh = $c->model('DBI')->dbh;

	my @col = map { $_ } sort keys %$authinfo;

	my $sql =
		'SELECT * FROM ' . $self->config->{'user_table'}
		. ' WHERE ' .	join( ' AND ', map "$_ = ?", @col )
	;

	my $sth = $dbh->prepare($sql) or die($dbh->errstr());
	$sth->execute(@$authinfo{@col}) or die($dbh->errstr());

	my %user;
	$sth->bind_columns(\( @user{ @{ $sth->{'NAME_lc'} } } )) or
	die($dbh->errstr());
	unless ($sth->fetch()) {
		$sth->finish();
		return undef;
	}
	$sth->finish();

	## Fail silently clause
	return undef
		unless exists $user{$self->config->{'user_key'}}
		&& length $user{$self->config->{'user_key'}}
	;

	return Catalyst::Authentication::Store::DBI::User->new( {store=> $self, user => \%user} );
}

sub for_session {
	my ($self, $c, $user) = @_;
	return $user->id;
}

sub from_session {
	my ($self, $c, $frozen) = @_;
	my $dbh = $c->model('DBI')->dbh;

	my $sql = sprintf(
		'SELECT * FROM %s WHERE %s = ?'
		, $self->config->{'user_table'}
		, $self->config->{'user_key'}
	);

	my $sth = $dbh->prepare($sql) or die($dbh->errstr());
	$sth->execute($frozen) or die($dbh->errstr());

	my %user;
	$sth->bind_columns(\( @user{ @{ $sth->{'NAME_lc'} } } )) or
	die($dbh->errstr());
	unless ($sth->fetch()) {
		$sth->finish();
		return undef;
	}
	$sth->finish();

	## Fail silently clause
	return undef
		unless exists $user{$self->config->{'user_key'}}
		&& length $user{$self->config->{'user_key'}}
	;

	return Catalyst::Authentication::Store::DBI::User->new( {store=> $self, user => \%user} );

}

sub user_supports {
	my $self = shift;
	return;
}

sub BUILDARGS {
	my $class = shift;
	my ( $config, $app, $realm ) = @_;

	scalar @_ == 1
		? $class->SUPER::BUILDARGS(@_)
		: { config => $config, app => $app, realm => $realm }
	;

}

1;

__END__

=head1 NAME

Catalyst::Authentication::Store::DBI - Storage class for Catalyst
Authentication using DBI

=head1 SYNOPSIS

  use Catalyst qw(Authentication);

  __PACKAGE__->config->{'authentication'} = {
    'default_realm' => 'default',
    'realms' => {
      'default' => {
        'credential' => {
          'class'               => 'Password',
          'password_field'      => 'password',
          'password_type'       => 'hashed',
          'password_hash_type'  => 'SHA-1',
        },
        'store' => {
          'class'              => 'DBI',
          'user_table'         => 'login',
          'user_key'           => 'id',
          'user_name'          => 'name',
          'role_table'         => 'authority',
          'role_key'           => 'id',
          'role_name'          => 'name',
          'user_role_table'    => 'competence',
          'user_role_user_key' => 'login',
          'user_role_role_key' => 'authority',
        },
      },
    },
  };

  sub login :Global
  {
    my ($self, $c) = @_;
    my $req = $c->request();

    # catch login failures
    unless ($c->authenticate({
      'name'     => $req->param('name'),
      'password' => $req->param('password'),
      })) {
      ...
    }

    ...
  }

  sub something :Path
  {
    my ($self, $c) = @_;

    # handle missing role case
    unless ($c->check_user_roles('editor')) {
      ...
    }

    ...
  }

=head1 DESCRIPTION

This module implements the L<Catalyst::Authentication> API using
L<Catalyst::Model::DBI>.

It uses DBI to let your application authenticate users against a database and it
provides support for L<Catalyst::Plugin::Authorization::Roles>.

=head1 METHODS

=head2 new

=head2 find_user

=head2 for_session

=head2 from_session

=head2 user_supports

=head1 SEE ALSO

=over 4

=item L<Catalyst::Plugin::Authentication>

=item L<Catalyst::Model::DBI>

=item L<Catalyst::Plugin::Authorization::Roles>

=back

=head1 AUTHOR

Simon Bertrang, E<lt>simon.bertrang@puzzworks.comE<gt>

=head1 COPYRIGHT

Copyright (c) 2008 PuzzWorks OHG, L<http://puzzworks.com/>

=head1 LICENSE

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
