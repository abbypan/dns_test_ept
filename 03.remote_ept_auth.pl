#!/usr/bin/perl 
use strict;
use warnings;
use Data::Dumper;
use Crypt::PK::RSA;
use Digest::MD5 qw(md5_hex);
use IP::Random qw/random_ipv4/;
use MIME::Base32;
use Net::DNS::Nameserver;
use Net::DNS::RR;
use Net::DNS::Resolver;
use Net::DNS;
use Socket qw/inet_ntoa inet_aton/;

our $EPT_CODE     = 0xFD66;
our $EPT_DOM      = 'eptfortest.com';
our $EPT_KEY_PRIV = Crypt::PK::RSA->new( 'key/ept.key.priv.pem' );

our $EPT_OWN_RESOLVER = new Net::DNS::Resolver(
  nameservers => ['127.0.0.1'],
  recurse     => 1,

  #debug       => 1
);

my $ept_auth = new Net::DNS::Nameserver(
  LocalAddr    => ['127.0.0.1'],
  LocalPort    => 54000,
  ReplyHandler => \&reply_handler,

  #debug => 1,
  #Verbose      => 1
) || die "couldn't create nameserver object\n";

$ept_auth->main_loop;

sub reply_handler {
  my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
  my ( $rcode, @ans, @auth, @add );

  #$query->print;
  print "----remote_ept_auth----\n";
  print "recv from relay_resolver: $qname\n";

  my ( $dom, $xor_ip, $hash_s ) = read_ept_val( $query );
  if ( lc( $qname ) ne lc( "$hash_s.$EPT_DOM" ) ) {
    print "error domain\n";
    return;
  }

  print "decrypt ept data: $dom, xor_ip $xor_ip\n";

  print "send query to ept_own_resolver: $dom\n";
  my $query_pkt = new Net::DNS::Packet( $dom, 'IN', 'A' );

  my $res_pkt = $EPT_OWN_RESOLVER->send( $query_pkt );

  for my $rr ( @{ $res_pkt->{answer} } ) {
    print "recv from ept_own_resolver: " . $rr->plain . "\n";

    #skip CNAME
    next unless ( $rr->{type} == 1 );

    my $xor_n = $rr->{address} ^ inet_aton( $xor_ip );
    my $addr  = inet_ntoa( $xor_n );

    my $res_rr = new Net::DNS::RR(
      ttl     => $rr->{ttl},
      name    => $qname,
      type    => 'A',
      address => $addr,
    );
    print "send to relay_resolver: " . $res_rr->plain . "\n";
    push @ans, $res_rr;
  } ## end for my $rr ( @{ $res_pkt...})

  print "----end----\n";
  return ( 0, \@ans, \@auth, $query->{additional}, { aa => 1 } );
} ## end sub reply_handler

sub read_ept_val {
  my ( $query ) = @_;
  my $opt = $query->edns;
  return unless ( $opt );

  my $ept_val = $opt->{option}{$EPT_CODE};
  return unless ( $ept_val );

  my $ct    = MIME::Base32::decode( $ept_val );
  my $plain = $EPT_KEY_PRIV->decrypt( $ct );

  my $hash_s = md5_hex( $plain );

  my ( $dom, $xor_ip, $salt_string ) = split /,/, $plain;
  return ( $dom, $xor_ip, $hash_s );
} ## end sub read_ept_val
