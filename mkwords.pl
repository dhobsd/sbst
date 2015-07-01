#!/usr/bin/perl

use strict;
use warnings;

die "Usage: mkwords.pl [nwords] [nfiles] [depth] [prefix]\n" if ($#ARGV < 3);

my $nwords = $ARGV[0];
my $nfiles = $ARGV[1];
my $depth = $ARGV[2];
my $prefix = $ARGV[3];

open FH, '</usr/share/dict/words';
my @words = <FH>;
close FH;

foreach my $f (1 .. $nfiles) {
	open OFH, ">words$f";

	foreach my $i (1 .. $nwords) {
		my $j = $depth;
		my $word = $prefix;

		while ($j--) {
			$word .= "/" . $words[rand @words];
			chomp($word);
		}

		print OFH "$word\n";
	}
	close OFH;
}
