use inc::Module::Install;

name     'Catalyst-Authentication-Store-DBI';
all_from 'lib/Catalyst/Authentication/Store/DBI.pm';
author   q{Evan Carroll <me@evancarroll.com>};
license  'perl';

build_requires 'Test::More';

requires 'Catalyst::Plugin::Authentication';
requires 'Catalyst::Model::DBI';
requires 'Moose' => 0.98;

resources(
	'homepage'     => 'http://www.evancarroll.com/'
	, 'repository' => 'git://github.com/EvanCarroll/Catalyst-Authentication-Store-DBI.git'
);


auto_install;

WriteAll;
