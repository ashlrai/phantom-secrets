#!/usr/bin/perl
# RQ-SEC-RUNLOG-SCRUB: streaming token-shape scrubber. Usage:
#   scrub.pl            filter stdin->stdout, line buffered, replaces matches with [REDACTED:<kind>]
#   scrub.pl --check    read stdin, print only "<count>" of matches, exit 1 if any (never prints values)
#   scrub.pl --check --allow-fixtures   as --check, but on unified-diff input skips a match when BOTH
#       (a) the current file (from the "+++ b/" header) is a test path, and
#       (b) the token itself contains FAKE|EXAMPLE|DUMMY|TEST|XXXX (any case) or is AKIAIOSFODNN7EXAMPLE.
#       Removed (-) lines inside a diff file are skipped: they are already on the base.
#       Prints "<blocked> allowed=<n>". PEM blocks and text outside a diff file are never allowed.
use strict; use warnings; $| = 1;
my $check = (@ARGV && $ARGV[0] eq '--check');
my $allow = ($check && grep { $_ eq '--allow-fixtures' } @ARGV);
my $TESTPATH = qr{(?:^|/)(?:tests?|fixtures|benches|examples)/|_test\.[A-Za-z0-9]+$|\.(?:test|spec)\.[A-Za-z0-9]+$};
my $FAKE = qr/FAKE|EXAMPLE|DUMMY|TEST|XXXX/i;
my ($file, $allowed) = ('', 0);
my @R = (
 [slack_app   => qr/xapp-[0-9]+-[A-Za-z0-9-]{10,}/],
 [slack       => qr/xox[abposr]-[A-Za-z0-9-]{10,}/],
 [github      => qr/gh[pousr]_[A-Za-z0-9]{30,}/],
 [github_pat  => qr/github_pat_[A-Za-z0-9_]{30,}/],
 [gitlab      => qr/glpat-[A-Za-z0-9_-]{20,}/],
 [anthropic   => qr/sk-ant-[A-Za-z0-9_-]{20,}/],
 [openai      => qr/sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/],
 [stripe      => qr/[sr]k_(?:live|test)_[A-Za-z0-9]{16,}/],
 [stripe_wh   => qr/whsec_[A-Za-z0-9]{20,}/],
 [aws         => qr/(?:AKIA|ASIA)[A-Z0-9]{16}/],
 [shopify     => qr/shp(?:at|ss|ca|pa)_[A-Fa-f0-9]{32}/],
 [google      => qr/AIza[0-9A-Za-z_-]{35}/],
 [npm         => qr/npm_[A-Za-z0-9]{36}/],
 [jwt         => qr/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
 [url_cred    => qr{(?<=://)[^\s:/@\[]+:[^\s/@]+(?=@)}],
);
my ($inpem, $n) = (0, 0);
while (my $l = <STDIN>) {
  if ($inpem) { $n++; if ($l =~ /-----END [A-Z ]*PRIVATE KEY-----/) { $inpem = 0; $l = "[REDACTED:pem_end]\n" } else { $l = "" } print $l unless $check; next }
  if ($l =~ /-----BEGIN [A-Z ]*PRIVATE KEY-----/) {
    $n++; $inpem = ($l !~ /-----END [A-Z ]*PRIVATE KEY-----/);
    $l =~ s/-----BEGIN [A-Z ]*PRIVATE KEY-----.*/[REDACTED:pem]/s; $l .= "\n" unless $l =~ /\n\z/;
    print $l unless $check; next }
  if ($allow) {
    if ($l =~ m{^\+\+\+ (?:b/(.*?)|/dev/null)\s*$}) { $file = defined $1 ? $1 : ''; }
    elsif ($l =~ /^diff --git /) { $file = ''; }
    elsif ($l !~ m{^(?:[ +\-@\\]|index |new file|deleted file|old mode|new mode|similarity|rename |copy |Binary )} && $l ne "\n") { $file = ''; }
    # Removed lines inside a diff file are already on the base branch; deleting them exposes nothing new.
    if ($file ne "" && $l =~ /^-(?!--)/) { next }
    my $intest = ($file ne '' && $file =~ $TESTPATH);
    for my $r (@R) { my $k = $r->[0];
      $l =~ s/$r->[1]/ my $t = $&; if ($intest && $t =~ $FAKE) { $allowed++ } else { $n++ } "[REDACTED:$k]" /ge }
    next }
  for my $r (@R) { my $k = $r->[0]; $n += ($l =~ s/$r->[1]/[REDACTED:$k]/g) }
  print $l unless $check;
}
if ($check) { print $allow ? "$n allowed=$allowed\n" : "$n\n"; exit($n ? 1 : 0) }
