#!/usr/bin/perl
#
# Msingh
#
# SCP hedgehog DSC files from nameservers

use warnings;
use strict;
use Getopt::Long;
use Net::SSH2;
use Net::SSH2::SFTP;
use Sys::Syslog qw(:standard :macros);
use File::Basename qw(basename);
use POSIX qw(strftime);

# options
# -h hostname
# -c cloud

my $SELF = basename(__FILE__);

usage() if (!@ARGV);

my( @opts_h, @opts_c );

GetOptions(
           'h=s{1,9}' => \@opts_h,
           'c=s{1,9}' => \@opts_c,
          );

if ( !(@opts_h) || !(@opts_c) ) {
        print "Must specify -h and -c\n";
        exit 3;
        }

    my $host = "@opts_h";
    my $cloud = "@opts_c";
        $host =~ /(.*?)\./;
    my $nsshort = $1;
    my $username = "netops";
    my $pass = "";
    my $pub = "/home/netops/.ssh/id_rsa.pub";
    my $pri = "/home/netops/.ssh/id_rsa";
    my $remotedir = "/usr/local/dsc/run";
    my $localdir =  join "", "/usr/local/var/hedgehog/data/Cloud-", @opts_c, "/",$nsshort,"/incoming/";
    my $xmlfiles = [];

    # Connect to host
    my $ssh = Net::SSH2->new();

    if (! $ssh->connect($host)) {
    print "Failed connection to $host\n";
    exit(1);
    }

    # Use either pub/pri keys or password to connect
    if ($pub ne "" && $pri ne "") {
        if (! $ssh->auth_publickey($username,$pub,$pri)) {
        print "FAILED SCP public/private key authentication for $username to $host\n";
        exit(1);
        }
    }

        # get a dirlist
        my $sftp = $ssh->sftp;
         my $dh = $sftp->opendir("$remotedir");
         while(my $item = $dh->read) {
                if ( $item->{'name'} =~ /.xml/ ) {
             #print $item->{'name'},"\n";
                map { push(@{$xmlfiles}, $_) } $item->{'name'}; 
                 }
        }

        if (!@{$xmlfiles}) {
                debug ("No xml files found");
                exit(1);
        }

    # Send in the files
    while ( my $file = shift @{$xmlfiles} ) {
        if (! $ssh->scp_get("$remotedir/$file", "$localdir/$file")) {
        $ssh->disconnect();
        debug ("ERROR: SCP get $remotedir/$file to $localdir/$file fail");
    } else {
        debug ("SCP got $remotedir/$file to $localdir/$file success");
          if (! $sftp->unlink("$remotedir/$file")) {
          debug ("ERROR: Delete $remotedir/$file fail");
          } else {
          debug ("$remotedir/$file delete success");
          }
   }

}
    #close($dh);
    $ssh->disconnect();
    exit(0); 

sub usage {
        print STDERR "usage: $0 [-h][-c]\n";
        print STDERR "  -h               hostname\n";
        print STDERR "  -c               cloud\n";
        exit 3;
}

sub debug {
        my $msg = shift;
        print "$host - $msg\n";
        syslog(LOG_INFO, "$host - $msg");
}
