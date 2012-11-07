use strict; use warnings; use autodie; use lib 'lib/';
use Email::Address::List;

my $file = 't/data/RFC5233.single.valid.txt';

open my $fh, '<', $file;
my @list = split /(?:\r*\n){2,}/, do { local $/; <$fh> };
close $fh;

my %CRE = %Email::Address::List::CRE;

foreach my $e (splice @list) {
    my ($desc, $mailbox) = split /\r*\n/, $e, 2;
    $desc =~ s/^#\s*//;

    my %res = (
        description => $desc,
        mailbox     => $mailbox,
    );

    my @parse;
    die "Failed to parse $mailbox"
        unless @parse = ($mailbox =~ /^($CRE{'mailbox'})$/);

    my (undef, $display_name, $local_part, $domain, @comments)
        = Email::Address::List->_process_mailbox( @parse );

    $res{'display-name'} = $display_name;
    $res{'address'} = "$local_part\@$domain";
    $res{'domain'} = $domain;
    $res{'comments'} = \@comments;
    push @list, \%res;
}

use JSON;
$file =~ s/txt$/json/;
open $fh, '>', $file;
print $fh JSON->new->pretty->encode(\@list);
close $fh;