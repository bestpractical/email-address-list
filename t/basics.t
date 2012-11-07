use strict; use warnings;
use Test::More tests => 3;
use_ok 'Email::Address::List';

use Scalar::Util qw(blessed);
{
    my @addresses = Email::Address::List->parse(q{ruz@bestpractical.com});
    is scalar @addresses, 1;
    is $addresses[0]->format, q{ruz@bestpractical.com};
}

