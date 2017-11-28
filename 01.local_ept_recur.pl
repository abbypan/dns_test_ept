#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;
use Crypt::PK::RSA;
use MIME::Base32;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;
use Net::DNS;
use IP::Random qw/random_ipv4/;
use String::Random qw/random_string/;
use Digest::MD5 qw(md5_hex);
use Socket qw/inet_ntoa inet_aton/;

our $EPT_CODE = 0xFD66;
our $EPT_DOM  = 'eptfortest.com';

our $EPT_KEY_PUB = Crypt::PK::RSA->new( 'key/ept.key.pub.pem' );

our $RELAY_RESOLVER = new Net::DNS::Resolver(
  nameservers => ['127.0.0.1'],
  recurse     => 1,

  #debug       => 1
);
$RELAY_RESOLVER->port( 53000 );

my $local_ept_recur = new Net::DNS::Nameserver(
  LocalAddr    => ['127.0.0.1'],
  LocalPort    => 52000,
  ReplyHandler => \&reply_handler,

  #debug => 1,
  #Verbose      => 1
) || die "couldn't create nameserver object\n";

$local_ept_recur->main_loop;

sub reply_handler {
  my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
  my ( $rcode, @ans, @auth, @add );

  print "----local_ept_recur----\n";

  #$query->print;
  print "recv from client: $qname\n";
  my ( $query_dom, $ept_opt, $xor_ip ) = gen_ept_opt( $EPT_KEY_PUB, $qname );
  print "send to relay_resolver: qname $query_dom, xor_ip $xor_ip\n";
  my $packet = new Net::DNS::Packet( $query_dom, 'IN', 'A' );
  push @{ $packet->{additional} }, $ept_opt;

  my $res_pkt = $RELAY_RESOLVER->send( $packet );

  for my $rr ( @{ $res_pkt->{answer} } ) {
    next unless ( $rr->{type} == 1 );

    print "recv from relay_resolver: " . $rr->plain . "\n";

    my $xor_n = $rr->{address} ^ inet_aton( $xor_ip );
    my $addr  = inet_ntoa( $xor_n );

    my $res_rr = new Net::DNS::RR(
      ttl     => $rr->{ttl},
      name    => $qname,
      type    => 'A',
      address => $addr,
    );
    print "send to client: " . $res_rr->plain . "\n";
    push @ans, $res_rr;
  }
  print "----end----\n";

  return ( 0, \@ans, \@auth, $query->{additional}, { aa => 1 } );
} ## end sub reply_handler

sub gen_ept_opt {
  my ( $pub_key, $dom ) = @_;
  my ( $ept_val, $xor_ip, $hash_s ) = gen_ept_val( $pub_key, $dom );
  my $qname = "$hash_s.$EPT_DOM";

  my $ept_opt = new Net::DNS::RR(
    type  => 'OPT',
    flags => 0,
    rcode => 0,
  );
  $ept_opt->option( $EPT_CODE => $ept_val );
  return ( $qname, $ept_opt, $xor_ip );
}

sub gen_ept_val {
  my ( $pub_key, $dom ) = @_;

  my $xor_ip = IP::Random::random_ipv4();

  my $salt_string_len = int( rand( 24 ) ) + 24;
  my $salt_string = random_string( join( "", ( "." ) x $salt_string_len ) );
  $salt_string =~ s/,//g;

  my $s = join( ",", $dom, $xor_ip, $salt_string );

  my $hash_s = md5_hex( $s );

  my $ct        = $pub_key->encrypt( $s );
  my $ct_base32 = MIME::Base32::encode( $ct );
  return ( $ct_base32, $xor_ip, $hash_s );
}
