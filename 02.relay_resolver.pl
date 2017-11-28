#!/usr/bin/perl 
use strict;
use warnings;
use Net::DNS::Nameserver;
use Net::DNS::Resolver;
use Net::DNS;
use Data::Dumper;

our $EPT_DOM_AUTH = new Net::DNS::Resolver(
    nameservers => ['127.0.0.1'],
    recurse     => 0,
    #debug       => 1
);
$EPT_DOM_AUTH->port(54000);

my $relay_resolver = new Net::DNS::Nameserver(
    LocalAddr    => ['127.0.0.1'],
    LocalPort    => 53000,
    ReplyHandler => \&reply_handler,
    Truncate     => 0,
    #Verbose      => 1
) || die "couldn't create nameserver object\n";

$relay_resolver->main_loop;

sub reply_handler {
    my ( $qname, $qclass, $qtype, $peerhost, $query, $conn ) = @_;
    my ( $rcode, @ans, @auth, @add );
  
    print "----relay_resolver----\n";
    print "this is a recursive resolver\n";
    # ... nomarl ns query ... 
    # $relay_resolver find $qname 's authority server is $EPT_DOM_AUTH
    print "find $qname 's authority server, then send the query\n";
    my $res_pkt = $EPT_DOM_AUTH->send($query);

    if ($res_pkt) {
        for my $rr (@{$res_pkt->{answer}}){
            print "reply: ".$rr->plain."\n";
        }
    }
    print "----end----\n";

    if($res_pkt){
        return ( $res_pkt->header->rcode, 
            $res_pkt->{answer}, $res_pkt->{authority}, $res_pkt->{additional},
            { aa => 0 }
        );
    }else{
        return ( 0, \@ans, \@auth, \@add, { aa => 0 } );
    }
}
