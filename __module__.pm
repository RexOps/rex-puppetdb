package PuppetDB;

use Moose;
use MooseX::Params::Validate;
use namespace::autoclean;
use Carp;

use LWP::UserAgent;
use JSON::XS;
use MIME::Base64;
use HTTP::Request;
use YAML;
use URI::Escape;

use Rex;
use Data::Dumper;
use PuppetDB::Server;

has SSL_verify_hostname => ( is => 'ro', isa => 'Int', default => sub { 0 } );
has url => ( is => 'ro', isa => 'Str', required => 1 );
has keyfile => (is => 'ro', isa => 'Str', default => sub { '/etc/rex/puppetdb.pem' });
has certfile => (is => 'ro', isa => 'Str', default => sub { '/etc/rex/puppetdb.crt' });

has ua => (
  is      => 'ro',
  lazy    => 1,
  default => sub {
    my ($self) = @_;
    my $lwp_useragent_version = $LWP::UserAgent::VERSION;

    my $ua;
    if ( $lwp_useragent_version <= 6 ) {
      $ENV{HTTPS_KEY_FILE}               = $self->keyfile;
      $ENV{HTTPS_CERT_FILE}              = $self->certfile;
      $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = $self->SSL_verify_hostname;
      $ua                                = LWP::UserAgent->new;
    }
    else {
      $ua = LWP::UserAgent->new(
        ssl_opts => {
          verify_hostname => $self->SSL_verify_hostname,
          SSL_key_file    => $self->keyfile,
          SSL_cert_file   => $self->certfile,
        }
      );
    }
    $ua;
  }
);

sub get_hosts {
  my $self = shift;
  my $options;

  if ( ref $_[0] eq "HASH" ) {
    $options = shift;
  }
  else {
    $options = {@_};
  }

  my $server_url = $self->url;
  $server_url =~ s/\/$//;

  my @options;
  for my $opt ( keys %{$options} ) {
    my $o = $opt;
    $o =~ s/^facts\.//;
    push @options, [ "=", [ "fact", $o ], $options->{$opt} ];
  }

  my $url =
    "$server_url/v3/nodes?query=" . $self->_format_query( [ "and", @options ] );

  my $res = $self->ua->get($url);

  if ( !$res->is_success ) {
    confess "Error accessing puppetdb.\n\nERROR: " . $res->content . "\n\n";
  }

  my $ref = decode_json $res->decoded_content;
  return map { $_ = PuppetDB::Server->new( name => $_->{name} ) } @{$ref};
}

sub all_nodes {
  my $self = shift;

  my $server_url = $self->url;
  $server_url =~ s/\/$//;

  my $url = "$server_url/v3/nodes";

  my $res = $self->ua->get($url);

  if ( !$res->is_success ) {
    confess "Error accessing puppetdb.\n\nERROR: " . $res->content . "\n\n";
  }

  my $ref = decode_json $res->decoded_content;
  my @nodes = map { $_ = $_->{name} } grep { ! $_->{deactivated} } @{ $ref };
  my @ret = ();
  for my $node (@nodes) {
    push @ret, PuppetDB::Server->new(name => $node);
  }
  
  return @ret;
}

sub get_facts {
  my $self = shift;
  my $node = shift;

  my $server_url = $self->url;
  $server_url =~ s/\/$//;

  my $fact_url = "$server_url/v3/facts?query=" . $self->_format_query(["=", "certname", $node]);
  my $node_res = $self->ua->get($fact_url);

  if ( !$node_res->is_success ) {
    confess "Error accessing puppetdb to query node facts: $node.\n\nERROR: " . $node_res->content . "\n\n";
  }
  
  my %facts;
  my $node_ref = decode_json $node_res->decoded_content;
  for my $d (@{ $node_ref }) {
    $facts{$d->{name}} = $d->{value};
  }
  
  return \%facts;
}

sub get_host {
  my $self = shift;

  my %opt;
  if ( ref $_[0] eq "HASH" ) {
    %opt = %{ $_[0] };
  }
  else {
    %opt = @_;
  }

  if ( exists $opt{host} ) {
    return PuppetDB::Server->new( name => $opt{host} );
  }
}

sub get_connected_hosts {
  my $self = shift;
  my (%option) = validated_hash(
    \@_,
    node     => { isa => 'Str' },
    resource => { isa => 'Str' },
  );

  my $server_url = $self->url;
  $server_url =~ s/\/$//;

  my $url =
    "$server_url/v3/nodes/$option{node}/resources/$option{resource}?query="
    . $self->_format_query( [ "and", [ "=", "exported", JSON::XS::true ] ] );
  my $res = $self->ua->get($url);

  if ( !$res->is_success ) {
    confess "Error accessing puppetdb.\n\nERROR: " . $res->content . "\n\n";
  }

  my $ref = decode_json $res->decoded_content;

  my $tag   = $ref->[0]->{parameters}->{tag};
  my $title = $ref->[0]->{title};

  my $query =
    [ "and", [ "=", "exported", JSON::XS::false ], [ "=", "tag", $tag ] ];

  $url = "$server_url/v3/resources/$option{resource}/$title?query="
    . $self->_format_query($query);
  $res = $self->ua->get($url);

  if ( !$res->is_success ) {
    confess "Error accessing puppetdb.\n\nERROR: " . $res->content . "\n\n";
  }

  my $ref2 = decode_json $res->decoded_content;

  return map { $_->{certname} } @{$ref2};
}

sub _format_query {
  my ( $self, $query ) = @_;

  my $json = encode_json $query;
  return uri_escape $json;
}

1;

__END__

=pod

=head1 NAME

PuppetDB - Module to query PuppetDB

=head1 SYNOPSIS

 use PuppetDB;
 my $p = PuppetDB->new( url => "https://puppetdb:8081" );
 my @hosts = $p->get_hosts(fact1 => "value1", fact2 => "value2");

=head1 COPYRIGHT

Copyright 2015 FILIADATA GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

