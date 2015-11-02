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

use Rex -base;
use Data::Dumper;
use PuppetDB::Server;

has url => (is => 'ro', isa => 'Str', required => 1);
has ua  => (is => 'ro', default => sub {
                    my $lwp_useragent_version = $LWP::UserAgent::VERSION;

                    my $hostname = qx{hostname -f 2>/dev/null};
                    chomp $hostname;

                    my $key_file  = "/etc/rex/puppetdb.pem";
                    my $cert_file = "/etc/rex/puppetdb.crt";

                    my $ua;
                    if($lwp_useragent_version <= 6) {
                      $ENV{HTTPS_KEY_FILE}  = $key_file;
                      $ENV{HTTPS_CERT_FILE} = $cert_file;
                      $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;
                      $ua = LWP::UserAgent->new;
                    }
                    else {
                      $ua = LWP::UserAgent->new(
                        ssl_opts => 
                          {
                            verify_hostname => 0,
                            SSL_key_file    => $key_file,
                            SSL_cert_file   => $cert_file,
                          }
                        );
                    }
#                    $ua->env_proxy;
                    $ua;
                  });

#
# curl -XGET http://localhost:8080/v3/nodes --data-urlencode 'query=
# [
#  "and",
#    [ "=", ["fact", "project"], "nova" ],
#    [ "=", ["fact", "app_tier"], "lxdev" ],
#    [ "=", ["fact", "system_type"], "appsrv" ]
# ]'
#


sub get_hosts {
  my $self = shift;
  my $options;

  if(ref $_[0] eq "HASH") {
    $options = shift;
  }
  else {
    $options = { @_ };
  }

  my $server_url = $self->url;
  $server_url =~ s/\/$//;

  my @options;
  for my $opt (keys %{ $options }) {
    my $o = $opt;
    $o =~ s/^facts\.//;
    push @options, [ "=", [ "fact", $o ], $options->{$opt} ];
  }

  my $url = "$server_url/v3/nodes?query=" . $self->_format_query(["and", @options ]);

  my $res = $self->ua->get($url);

  if(! $res->is_success) {
    confess "Error accessing puppetdb.\n\nERROR: " . $res->content . "\n\n";
  }

  my $ref = decode_json $res->decoded_content;
  return map { $_ = PuppetDB::Server->new(name => $_->{name}) } @{ $ref };
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

  my $url = "$server_url/v3/nodes/$option{node}/resources/$option{resource}?query=" . $self->_format_query(["and", ["=", "exported", JSON::XS::true]]);
  my $res = $self->ua->get($url);

  if(! $res->is_success) {
    confess "Error accessing puppetdb.\n\nERROR: " . $res->content . "\n\n";
  }

  my $ref = decode_json $res->decoded_content;

  my $tag   = $ref->[0]->{parameters}->{tag};
  my $title = $ref->[0]->{title};

  my $query = [
    "and",
    ["=", "exported", JSON::XS::false],
    ["=", "tag", $tag]
  ];

  $url = "$server_url/v3/resources/$option{resource}/$title?query=" . $self->_format_query($query);
  $res = $self->ua->get($url);

  if(! $res->is_success) {
    confess "Error accessing puppetdb.\n\nERROR: " . $res->content . "\n\n";
  }

  my $ref2 = decode_json $res->decoded_content;

  return map { $_->{certname} } @{ $ref2 };
}

sub _format_query {
  my ($self, $query) = @_;

  my $json = encode_json $query;
  return uri_escape $json;
}

1;
