#!/usr/bin/perl                                                                                                                                                                                              
# Msingh
# v1.0.1
# Hedgehog TLD UDP/TCP stats reporter

use strict;
use warnings;
use DBI;
use Time::Local;
use File::Basename qw(basename);
use Net::DNS;
use Getopt::Long;
use Mail::Sendmail;
use Sys::Hostname;
use Sys::Syslog qw(:standard :macros);
use Pod::Usage;
use POSIX qw(strftime mktime);
use Data::Dumper qw(Dumper);
use MIME::QuotedPrint;

my $filename = "/tmp/hedgehog.rpt";

my $SELF = basename(__FILE__);

my $host = "127.0.0.1";
my $from='netops@somedomain.net';
my $smtphost='localhost';
my $to='ops@somedomain.com';
my $content;

my $SRVquery;
my $dns = uc('ns1.somedomain.net');

my $database = "hedgehog";
my $table;
### Enter DB username and password here
my $username = "hedgehog";
my $password = "";
my $timeout = 10; 
my $res; 
my $cloud; 
my $ns; 
my $msg;
my %nameservers;
my $nameserver;
my %nsstats;
my %tldstats;
my $tldstats;
my $protocol;
my $ipv;
my $tld = '';
my $udptldtotal = '';
my $tcptldtotal = '';
my $udptotals;
my $tcptotals;

my        $starttime;
my        $node_id;
my        $key1;
my        $key2;
my        $value;
my        $name;
my        $region;
my        $display_name;

# initialise various variables:
my @errors      = ();
my @log         = ();
my $timefmt     = '%Y-%m-%d %H:%M:%S';
my $cache       = {};

my $day;
my $month;
my $year;
my @hosts;
my @cmdlhosts;
my @cloud = ( "a", "b" );

my ($debug, $noalerts, $help, $noisy, $networks);

my %octet2domain = (    '12' => 'com',
                        '14' => 'co.uk',
                        '15' => 'eu',
                        '28' => 'net',
                        '70' => 'co'
                   );
my %anycast_v4_pfx = ('A' => '192.168.0.', 'B' => '172.16.24.');
my %anycast_v6_pfx = ('A' => '2001:67c:1:', 'B' => '2a04:2b00:::1:');

usage() if (!@ARGV);

GetOptions(
           'day=i' => \$day,
           'month=i' => \$month,
           'year=i' => \$year,
           'hosts=s' => \@cmdlhosts,
           'h' => \$help,
          );

usage() if $help;

if ( !($month) && !($year) ) {
        print "Please specify month and year you want stats for\n";
        exit 3;
        }
if ( !($month) ) {
        print "Please specify month you want stats for\n";
        exit 3;
        }
if ( !($year) ) {
        print "Please specify year you want stats for\n";
        exit 3;
        }

if ( length $year ne 4 ) {
        print "Year must be 4 digits long\n";
        exit 3;
        }

        debug ("\nGetting current month year information");
        debug ( strftime('%Y-%m-%d',localtime) );

        #my @parts = localtime;
        #$parts[4]--; # decrement month
        #debug ("Last month date ");
        #debug ( strftime '%Y-%m-%d', localtime (mktime @parts) );
        #my $lmonth = strftime '%m', localtime (mktime @parts);
        #my $lyear = strftime '%Y', localtime (mktime @parts);

        # Find out days in month
        my $days = month_days( $year, $month );
        debug ("month $month $year has $days days\n");
        # Convert month to month name
        my $time = POSIX::mktime(1,1,1,1,$month-1,$year-1900);
        my $rmonth = strftime q{%b}, localtime ( $time );
        $month = strftime q{%m}, localtime ( $time );

pod2usage('-verbose' => 99, '-sections' => 'USAGE|OPTIONS') if ($help);

        debug('Connecting to database server on '.$host);
        my $dbh = DBI->connect(sprintf('DBI:Pg:database=%s;host=%s', $database, $host), $username, $password, { RaiseError => 1}) or add_error (sprintf("Couldn't connect to database: %s", DBI->errstr));;

foreach $cloud (@cloud) {

        print "CLOUD $cloud\n";
        sleep 2;

        if ( @{cmdlhosts} ) {
        @hosts = @{cmdlhosts};
                } else {
                # Query SRV records
                $res = Net::DNS::Resolver->new( nameservers => [$dns], tcp_timeout => $timeout, udp_timeout => $timeout, retry => 3, 'persistent_tcp' => 1, 'persistent_udp' => 1, 'debug' => $noisy );
                $SRVquery = sprintf("_dns._udp.%s.dns.xyz.net", $cloud);
                @hosts = SRVquery ( $SRVquery, $dns );
        }

        foreach $ns ( sort @{hosts}) {

                if ( $ns =~ /(^ns\-\d{1,2})/ ) {
                        $nameserver = $1;
                        #push ( @nameserver, $nameserver );
                        }

        $table = sprintf("data_cloud_%s_server_addr_vs_trans_%s_%s", $cloud, $year, $month);

        # Check the table exists
        my $sth = $dbh->table_info("", "", $table, "TABLE");
                if (!($sth->fetch)) {
                debug ("Table $table does not exist");
                next;
                }
        $sth->finish;

        # Get the data from the table
        my $sth1 = $dbh->prepare(sprintf('select starttime, name, key1, key2, value, region from %s, node WHERE node.id = %s.node_id AND node.name = \'%s\' ORDER BY starttime desc', $table, $table, $nameserver ) ) ||  die "$DBI::errstr";
        $sth1->execute();

                if ($sth1->rows >= 1) {
                debug (sprintf(">> Found %d records in table %s", $sth1->rows, $table));

                     while (my $results = $sth1->fetchrow_hashref) {
                         $starttime = $results->{starttime};
                         $name = $results->{name};
                         $key1 = $results->{key1};
                         $key2 = $results->{key2};
                         $value = $results->{value};
                         $region = $results->{region};
                         $display_name = $results->{display_name};

                        #debug (sprintf("    +--- %s %s %s %s %s %s", $starttime, $name, $key1, $key2, $value, $region));
                        $nameservers{$nameserver}{$key2}{$key1} += $value;

                        }
                $sth1->finish;

                }

        }  # End Foreach nameserver

}  # End Foreach cloud

        debug ("Disconnecting from database server");
        $dbh->disconnect;

debug (Dumper \%nameservers);

for my $key ( keys %nameservers ) {
        print "$key\n";
    }

sleep 1;

debug ("Hash content");

    my $rHoH = \%nameservers;

# Go through each nameserver hash
    foreach my $ns ( sort keys %$rHoH ) {
        debug ("ns: $ns");
        foreach my $protocol ( keys %{$rHoH->{ $ns }} ) {
            debug ("protocol: $protocol \t $rHoH->{ $ns }\t");
            foreach my $ip ( keys %{$rHoH->{ $ns }{ $protocol }} ) {
                debug ("ip: $protocol $ip \t $rHoH->{ $ns }{ $protocol }{ $ip }\t");
                foreach my $cloud (sort keys %anycast_v4_pfx) {

                        if ( $ip =~ /$anycast_v4_pfx{$cloud}/ ) {
                        my ($lastoctet) = $ip =~ /.*\.(.*)/;
                                #debug ("$cloud\t");
                                my $tld = $octet2domain{$lastoctet};
                                if (defined($tld)) {
                                        $nsstats{$ns}{$protocol}{'ipv4'}{$tld} += $rHoH->{ $ns }{ $protocol }{ $ip };
                                }
                        }
                } # End foreach
                foreach my $cloud (sort keys %anycast_v6_pfx) {

                        if ( $ip =~ /$anycast_v6_pfx{$cloud}/ ) {
                        my ($lastoctet) = $ip =~ /.*\:(.*)/;
                                #debug ("$cloud\t");
                                my $tld = $octet2domain{$lastoctet};
                                if (defined($tld)) {
                                        $nsstats{$ns}{$protocol}{'ipv6'}{$tld} += $rHoH->{ $ns }{ $protocol }{ $ip };
                                }
                        }
               } # End foreach
            } # End foreach ip
        } # End foreach protocol
    } # End foreach nameserver

debug (Dumper \%nsstats);

format HEDGEHOG_RPT =
  @<<<<<<<<<<<<<<<<  @>>>>>>>>>>>>>>>>>>>>>>>  @>>>>>>>>>>>>>>>>>>>>>>>
  $tld, $udptldtotal, $tcptldtotal;
.

format HEDGEHOG_RPT_TOP =
  @||||||||||||||||||||||||||||||||||||||||||||||
  "Centralnic TLD (UDP/TCP) Stats $rmonth-$year", 

  TLD                UDP Queries Received      TCP Queries Received
  -----------------  ------------------------  ------------------------
.

format HEDGEHOG_RPT_TOTAL =
  -----------------  ------------------------  ------------------------
  @<<<<<<<<<<<<<<<<  @>>>>>>>>>>>>>>>>>>>>>>>  @>>>>>>>>>>>>>>>>>>>>>>>
  "Totals", $udptotals, $tcptotals;
.

# Sort the stats into new hash array
        foreach my $name (sort keys %nsstats) {
                foreach $protocol (keys %{ $nsstats{$name} }) {
                    foreach $ipv (keys %{ $nsstats{$name}{$protocol} }) {
                        #debug ("$ipv, $protocol");
                                foreach $tld (keys %{ $nsstats{$name}{$protocol}{$ipv} }) {
                                debug ("$name, $protocol: $ipv: $tld: $nsstats{$name}{$protocol}{$ipv}{$tld}");
                                $tldstats{$tld}{$protocol} += $nsstats{$name}{$protocol}{$ipv}{$tld};
                                }
                        }
                }
        }


debug (Dumper \%tldstats);

open(HEDGEHOG_RPT, '>', "$filename") or die "Could not open file '$filename' $!";

$~ = "HEDGEHOG_RPT_TOP";
write(HEDGEHOG_RPT);

select(STDOUT);

open (my $fh, '>', '/tmp/report') or die "Could not open file $!";
#print $fh @log;

local $Data::Dumper::Terse = 1;   # no '$VAR1 = '
local $Data::Dumper::Useqq = 1;   # double quoted strings
#print $fh Dumper \%nameservers;
print $fh Dumper \%nsstats;
print $fh "Tally tld stats from all nameservers";
print $fh Dumper \%tldstats;
close $fh;


# Create Report
my $dsdattachmentname = "dsd-output_$year-$month";
my $dsdfilename = "/tmp/$dsdattachmentname";
open ( my $dsdfh, '>', $dsdfilename);

        $~ = "HEDGEHOG_RPT";
foreach $tld (sort keys %tldstats) {
                $udptldtotal = 0;
                $tcptldtotal = 0;
                my $dsd_udptldtotal = 0;
                my $dsd_tcptldtotal = 0;
        foreach $protocol ( sort keys $tldstats{$tld} ) {
                if ( $protocol eq "udp" ) {
                        $dsd_udptldtotal = $tldstats{$tld}{$protocol};
                        $udptldtotal = reverse( (reverse $tldstats{$tld}{$protocol}) =~ s/[0-9]{3}\K(?=[0-9])/,/gr );
                        $udptotals += $tldstats{$tld}{$protocol};
                        }
                if ( $protocol eq "tcp" ) {
                        $dsd_tcptldtotal = $tldstats{$tld}{$protocol};
                        $tcptldtotal = reverse( (reverse $tldstats{$tld}{$protocol}) =~ s/[0-9]{3}\K(?=[0-9])/,/gr );
                        $tcptotals += $tldstats{$tld}{$protocol};
                        }
                debug ("$tld, $protocol: $tldstats{$tld}{$protocol}");
                }
        print $dsdfh "UPDATE icann_reports SET dns_udp_queries_received = $dsd_udptldtotal, dns_udp_queries_responded = $dsd_udptldtotal, dns_tcp_queries_received = $dsd_tcptldtotal, dns_tcp_queries_responded = $dsd_tcptldtotal WHERE ( suffix = \"$tld\" AND year = $year AND month = $month)\;\n";
        write(HEDGEHOG_RPT);
        }

        $udptotals = reverse( (reverse $udptotals) =~ s/[0-9]{3}\K(?=[0-9])/,/gr );
        $tcptotals = reverse( (reverse $tcptotals) =~ s/[0-9]{3}\K(?=[0-9])/,/gr );
        select((select(HEDGEHOG_RPT), $~ = "HEDGEHOG_RPT_TOTAL")[0]);
        write(HEDGEHOG_RPT);

close ($dsdfh);
close (HEDGEHOG_RPT);

    open(my $HEDGEHOG_RPT, '<', "$filename") or die "Could not open file '$filename' $!";
    {
        local $/;
        $content = <$HEDGEHOG_RPT>;
    }
    close($HEDGEHOG_RPT);

    debug($content);
my $subject=sprintf("%s Hedgehog TLD (UDP/TCP) DSD Stats %s-%s\n", lc(hostname()), $rmonth, $year);

my %mail = (
                        'SMTP'          => sprintf('%s', $smtphost),
                        'From'          => sprintf('"%s" <%s>', lc(hostname()), $from),
                        'To'            => sprintf('%s', $to),
                        'Subject'       => sprintf('%s', $subject),
                );

                my $boundary = "====" . time . "====";
                $mail{'content-type'} = "multipart/mixed; boundary=\"$boundary\"";

                my $message = encode_qp( $subject . "\n" . $content );

                open (F, $dsdfilename) or die "Cannot read $dsdfilename $!";
                binmode F; undef $/;
                $mail{body} = encode_qp(<F>);
                close F;

                $boundary = '--'.$boundary;
                $mail{body} = <<END_OF_BODY;
$boundary
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable

$message
$boundary
Content-Type: text/plain; charset="iso-8859-1"; name="$dsdattachmentname"
Content-Transfer-Encoding: quoted-printable
Content-Disposition: attachment; filename="$dsdattachmentname"

$mail{body}
$boundary--
END_OF_BODY

                if (sendmail(%mail)) {
                        debug("Hedgehog report successfully sent to $to");

                } else {
                        syslog(LOG_NOTICE, $Mail::Sendmail::error);
                        exit(1);

                }

debug("done");

sub SRVquery {

    my ( $srvquery, $dns ) = @_;
    my $nameservers;

    $res->nameservers($dns);
    my $packet = $res->query($dns, "A");

    if ( !$packet ) {
        add_error ("Nameserver $dns not available");
        exit;
        }
# Run the SRV query to get list of anycast nameservers against chosen authorative server

        my $query = $res->query($srvquery, 'SRV');

                if ( !($query) ) {
                        add_error (sprintf(" *** Query failed: %s ***", $res->errorstring));
                } else {

                        foreach my $rr (grep{ $_->type eq 'SRV' }$query->answer) {
                                push( @{$nameservers}, $rr->target );
                        }
                }
        return @{$nameservers};
}

# emit a debug message, but also store it so that it can be included in the
# error report:
sub debug {
        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
        my $datestring = strftime "%a %b %e %H:%M:%S %Y", localtime;
        my $msg = shift;
        print "$msg\n";
        syslog(LOG_INFO, $msg);
        push(@log, sprintf("%s: %s\n", $datestring, $msg));
}

# log an error for inclusion in the report:
sub add_error {
        my $error = shift;
        debug "$error\n";
        syslog(LOG_ERR, "ERROR: $error");
        push(@errors, sprintf(
                "%s: ERROR: %s",
                strftime('%Y-%m-%d %H:%M:%S', localtime),
                $error
        ));
}

sub usage {
        print STDOUT "usage: $0 [-m][-y]\n";
        print STDOUT "  -d               day to query\n";
        print STDOUT "  -m               month to query\n";
        print STDOUT "  -y               year to query (4 digits)\n";
        exit 3;
}

sub month_days {

    my $cyear -= 1900;
    return (31,0,31,30,31,30,31,31,30,31,30,31)[$month-1] ||
           (timelocal(0,0,0,1,2,$cyear) - timelocal(0,0,0,1,1,$cyear))/86400; 
}

__END__

=pod

=head1 NAME

        hedgehog.dsd - hedgehog DSD stats

=head1 DESCRIPTION

C<hedgehog.dsd> is a Perl script which gathers dsd tld udp/tcp statistical volumes
and displays them in a report.

=head1 USAGE

        hedgehog.dsd [OPTIONS]

=head1 OPTIONS

=over

=item --help

Show this help.

=item --debug

Show verbose debugging messages.

=back

=cut
