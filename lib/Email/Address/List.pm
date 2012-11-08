use strict; use warnings; use 5.008;

package Email::Address::List;

our $VERSION = '0.01';
use Email::Address;

=head1 NAME

Email::Address::List - RFC close address list parsing

=head1 DESCRIPTION

Parser for From, To, Cc, Bcc, Reply-To, Sender and
previous prefixed with Resent- (eg Resent-From) headers.

=head1 REASONING

L<Email::Address> is good at parsing addresses out of any text
even mentioned headers and this module is derived work
from Email::Address.

=cut

#   mailbox         =   name-addr / addr-spec
#   display-name    =   phrase
#
#   from            =   "From:" mailbox-list CRLF
#   sender          =   "Sender:" mailbox CRLF
#   reply-to        =   "Reply-To:" address-list CRLF
#
#   to              =   "To:" address-list CRLF
#   cc              =   "Cc:" address-list CRLF
#   bcc             =   "Bcc:" [address-list / CFWS] CRLF
#
#   resent-from     =   "Resent-From:" mailbox-list CRLF
#   resent-sender   =   "Resent-Sender:" mailbox CRLF
#   resent-to       =   "Resent-To:" address-list CRLF
#   resent-cc       =   "Resent-Cc:" address-list CRLF
#   resent-bcc      =   "Resent-Bcc:" [address-list / CFWS] CRLF
#
#   obs-from        =   "From" *WSP ":" mailbox-list CRLF
#   obs-sender      =   "Sender" *WSP ":" mailbox CRLF
#   obs-reply-to    =   "Reply-To" *WSP ":" address-list CRLF
#
#   obs-to          =   "To" *WSP ":" address-list CRLF
#   obs-cc          =   "Cc" *WSP ":" address-list CRLF
#   obs-bcc         =   "Bcc" *WSP ":" (address-list / (*([CFWS] ",") [CFWS])) CRLF
#
#   obs-resent-from =   "Resent-From" *WSP ":" mailbox-list CRLF
#   obs-resent-send =   "Resent-Sender" *WSP ":" mailbox CRLF
#   obs-resent-date =   "Resent-Date" *WSP ":" date-time CRLF
#   obs-resent-to   =   "Resent-To" *WSP ":" address-list CRLF
#   obs-resent-cc   =   "Resent-Cc" *WSP ":" address-list CRLF
#   obs-resent-bcc  =   "Resent-Bcc" *WSP ":" (address-list / (*([CFWS] ",") [CFWS])) CRLF
#   obs-resent-mid  =   "Resent-Message-ID" *WSP ":" msg-id CRLF
#   obs-resent-rply =   "Resent-Reply-To" *WSP ":" address-list CRLF

our $COMMENT_NEST_LEVEL ||= 2;

our %RE;
our %CRE;

$RE{'CTL'}            = q{\x00-\x1F\x7F};
$RE{'special'}        = q{()<>\\[\\]:;@\\\\,."};

$RE{'text'}           = qr/[^\x0A\x0D]/;

$RE{'quoted_pair'}    = qr/\\$RE{'text'}/;

$RE{'atext'}          = qr/[^$RE{'CTL'}$RE{'special'}\s]/;
$RE{'ctext'}          = qr/(?>[^()\\]+)/;
$RE{'qtext'}          = qr/[^\\"]/;

($RE{'ccontent'}, $RE{'comment'}) = (q{})x2;
for (1 .. $COMMENT_NEST_LEVEL) {
  $RE{'ccontent'} = qr/$RE{'ctext'}|$RE{'quoted_pair'}|$RE{'comment'}/;
  $RE{'comment'}  = qr/\s*\((?:\s*$RE{'ccontent'})*\s*\)\s*/;
}
$RE{'cfws'}           = qr/$RE{'comment'}|\s+/;

$RE{'qcontent'}       = qr/$RE{'qtext'}|$RE{'quoted_pair'}/;
$RE{'quoted_string'}  = qr/$RE{'cfws'}*"$RE{'qcontent'}+"$RE{'cfws'}*/;

# by the spec:
# word            =   atom / quoted-string   = qr/$RE{'atom'}|$RE{'quoted_string'}/;
# atom            =   [CFWS] 1*atext [CFWS]  = qr/$RE{'cfws'}*$RE{'atext'}+$RE{'cfws'}*/;
# with some inlining:
# word            = qr/$RE{'cfws'}* (?:$RE{'atom'} | "$RE{'qcontent'}+") $RE{'cfws'}*/x;
# however:
# phrase          =   1*word / obs-phrase
# obs-phrase      =   word *(word / "." / CFWS)
# after combining:
# phrase          =   word *(word / "." / CFWS)

$RE{'atom'}           = qr/$RE{'cfws'}*$RE{'atext'}+$RE{'cfws'}*/;
$CRE{'atom'}           = qr/($RE{'cfws'}*)($RE{'atext'}+)($RE{'cfws'}*)/;

$RE{'word'}           = qr/$RE{'cfws'}* (?: $RE{'atom'} |      "$RE{'qcontent'}+" ) $RE{'cfws'}*/x;
$RE{'dword'}          = qr/$RE{'cfws'}* (?: $RE{'atom'} | \. | "$RE{'qcontent'}+" ) $RE{'cfws'}*/x;
$CRE{'dword'}         = qr/($RE{'cfws'}*) (?: ($RE{'atom'} | \.) | "($RE{'qcontent'}+)" ) ($RE{'cfws'}*)/x;
$RE{'phrase'}         = qr/$RE{'word'} $RE{'dword'}*/x;
$RE{'display_name'}   = $RE{'phrase'};

$RE{'dot_atom_text'}  = qr/$RE{'atext'}+(?:\.$RE{'atext'}+)*/;
$RE{'dot_atom'}       = qr/$RE{'cfws'}*$RE{'dot_atom_text'}$RE{'cfws'}*/;
$RE{'local_part'}     = qr/$RE{'dot_atom'}|$RE{'quoted_string'}/;

$RE{'dtext'}          = qr/[^\[\]\\]/;
$RE{'dcontent'}       = qr/$RE{'dtext'}|$RE{'quoted_pair'}/;
$RE{'domain_literal'} = qr/$RE{'cfws'}*\[(?:\s*$RE{'dcontent'})*\s*\]$RE{'cfws'}*/;
$RE{'domain'}         = qr/$RE{'dot_atom'}|$RE{'domain_literal'}/;
$CRE{'domain'}        = qr/
    ($RE{'cfws'}*)
    ($RE{'dot_atom_text'}|\[(?:\s*$RE{'dcontent'})*\s*\])
    ($RE{'cfws'}*)
/x;

$RE{'addr_spec'}      = qr/$RE{'local_part'}\@$RE{'domain'}/;
$CRE{'addr_spec'}     = qr/
    ($RE{'cfws'}*)
    ($RE{'dot_atom_text'}|"$RE{'qcontent'}+")
    ($RE{'cfws'}*)
    \@$CRE{'domain'}
/x;
$RE{'obs-route'}      = qr/
    (?:$RE{'cfws'}|,)*
    \@$RE{'domain'}
    (?:,$RE{'cfws'}?(?:\@$RE{'domain'})?)*
    :
/x;
$RE{'angle_addr'}     = qr/$RE{'cfws'}* < $RE{'obs-route'}? $RE{'addr_spec'} > $RE{'cfws'}*/x;

$RE{'name_addr'}      = qr/$RE{'display_name'}?$RE{'angle_addr'}/;
$RE{'mailbox'}        = qr/(?:$RE{'name_addr'}|$RE{'addr_spec'})$RE{'comment'}*/;

$CRE{'mailbox'} = qr/
    (?:
        ($RE{'display_name'})?($RE{'cfws'}*)< $RE{'obs-route'}? ($RE{'addr_spec'})>($RE{'cfws'}*)
        |($RE{'addr_spec'})
    )($RE{'comment'}*)
/x;

sub parse {
    my $self = shift;
    my %args = @_%2? (line => @_) : @_;
    my $line = delete $args{'line'};

    my $in_group = 0;

    my @res;
    while ($line =~ /\S/) {
        # in obs- case we have number of optional comments/spaces/
        # address-list    =   (address *("," address)) / obs-addr-list
        # obs-addr-list   =   *([CFWS] ",") address *("," [address / CFWS]))
        $line =~ s/^(?:$RE{'cfws'}?,)+//o;
        $line =~ s/^\s+//o;

        # now it's only comma separated address where address is:
        # address         =   mailbox / group

        # deal with groups
        # group           =   display-name ":" [group-list] ";" [CFWS]
        # group-list      =   mailbox-list / CFWS / obs-group-list
        # obs-group-list  =   1*([CFWS] ",") [CFWS])
        if ( !$in_group && $line =~ s/^$RE{'display_name'}://o ) {
            $in_group = 1; next;
        }
        if ( $in_group && $line =~ s/^;// ) {
            $in_group = 0; next;
        }

        # now we got rid of groups and cfws, 'address = mailbox'
        # mailbox-list    =   (mailbox *("," mailbox)) / obs-mbox-list
        # obs-mbox-list   =   *([CFWS] ",") mailbox *("," [mailbox / CFWS]))

        # so address-list is now comma separated list of mailboxes:
        # address-list    = (mailbox *("," mailbox))
        if ( $line =~ s/^($CRE{'mailbox'})//o ) {
            my ($original, $phrase, $user, $host, @comments) = $self->_process_mailbox(
                $1,$2,$3,$4,$5,$6,$7
            );
            push @res, Email::Address->new(
                $phrase, "$user\@$host", join(' ', grep defined, @comments),
                $original,
            );
            next;
        }

        # if we got here then something unknown on our way
        # try to recorver
        if ( $line =~ s/^(.+?)\s*(?=(;)|,|$)//o ) {
            push @res, { type => 'unknown', value => $1 };
            if ($2) { $in_group = 1 }
        }
    }
    return @res;
}

sub _process_mailbox {
    my $self = $_[0];
    my ($original, $phrase) = ($_[1],$_[2]);
    my $address = $_[4] || $_[6];
    my @rest = ($_[3],$_[5],$_[7]);

    my @comments;

    if ( $phrase ) {
        my @tmp = $phrase =~ /$CRE{'dword'}/go; # must match everything
        $phrase = '';
        while ( my ($lcomment, $text, $quoted, $rcomment) = splice @tmp, 0, 4 ) {
            $phrase .= ' ' if $lcomment =~ /^\s|\s$/ && $phrase !~ /\s$/;
            push @comments, $lcomment;
            if (defined $text) {
                $text =~ s{($RE{'comment'})}{
                    push @comments, $1; $comments[-1]=~ /^\s|\s$/? ' ':''
                }xgeo;
                $text =~ s/\s+/ /g;
                $phrase .= $text;
            } else {
                $quoted =~ s/\\(.)/$1/g;
                $phrase .= $quoted;
            }
            $phrase .= ' ' if $rcomment =~ /^\s|\s$/ && $phrase !~ /\s$/;
            push @comments, $rcomment;
        }
    }
    push @comments, shift @rest;

    my ($user, $host);
    {
        $address =~ /^$CRE{'addr_spec'}$/;
        ($user, $host) = ($2, $5);
        push @comments, $1, $3, $4, $6;
    }
    push @comments, splice @rest;

    for ( $phrase, $user, $host, @comments ) {
        next unless defined $_;
        s/^\s+//;
        s/\s+$//;
        $_ = undef unless length $_;
    }
    return $original, $phrase, $user, $host, grep defined, @comments;
}

