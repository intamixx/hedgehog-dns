#!/usr/bin/perl                                                                                                                                                                                              
# Msingh
# v1.0.1 DRAFT VERSION
# Hedgehog anycast dns query volume collector

use strict;
use warnings;
#use CNic::Config;
#use CNic::DateUtils;
#use CNic::DB;
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

my $filename = "/tmp/hedgehog.rpt";

my $SELF = basename(__FILE__);

my $host = "127.0.0.1";
my $from='ops@admin.com';
my $smtphost='smtp.host.com';
my $to='ops@admin.com';
my $content;

my $SRVquery;
my $dns = uc('ns1.nameserver.net'); 

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

my        $starttime;
my        $node_id;
my        $key1;
my        $key2;
my        $value;
my        $name;
my        $region;

# initialise various variables:
my @errors      = ();
my @log         = ();
my $timefmt     = '%Y-%m-%d %H:%M:%S';
my $cache       = {};

my $tcpipv6;
my $tcpipv4;
my $udpipv6;
my $udpipv4;
my $totaltcpipv6;
my $totaltcpipv4;
my $totaludpipv6;
my $totaludpipv4;

my $day;
my $month;
my $year;
my @hosts;
my @cmdlhosts;
my @cloud = ( "a", "b" );

my ($debug, $noalerts, $help, $noisy, $networks);

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

format HEDGEHOG_RPT_TOP =
  @||||||||||||||||||||||||||||||||||||||||||||||
  "Centralnic Anycast DNS Query Volume $rmonth-$year", 

  Nameserver         UDP v6            TCP v6            UDP v4            TCP v4
  -----------------  ----------------  ----------------  ----------------  ----------------
.

format HEDGEHOG_RPT_TOTAL =
  -----------------  ----------------  ----------------  ----------------  ----------------
  @<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<
  "Totals", $totaludpipv6, $totaltcpipv6, $totaludpipv4, $totaltcpipv4; 
.

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
                $SRVquery = sprintf("_dns._udp.%s.dns.srvnet.net", $cloud);
                @hosts = SRVquery ( $SRVquery, $dns );
        }

        foreach $ns ( sort @{hosts}) {

                if ( $ns =~ /(^ns\-\d{1,2})/ ) {
                        $nameserver = $1;
                        #push ( @nameserver, $nameserver );
                        }


        $table = sprintf("data_cloud_%s_traffic_volume_queries_%s_%s", $cloud, $year, $month);

        # Check the table exists
        my $sth = $dbh->table_info("", "", $table, "TABLE");
                if (!($sth->fetch)) {
                debug ("Table $table does not exist");
                next;
                }
        $sth->finish;

        # Get the data from the table
        my $sth1 = $dbh->prepare(sprintf('SELECT starttime,node_id,key1,key2,value,name,region from %s, node WHERE id = node_id AND CAST(starttime AS DATE) >= \'%s-%s-01\' and CAST(starttime AS DATE) <= \'%s-%s-%s\' AND name = \'%s\' ORDER BY starttime desc', $table, $year, $month, $year, $month, $days, $nameserver ) ) ||  die "$DBI::errstr";
        $sth1->execute();

        if ($sth1->rows >= 1) {
        debug (sprintf(">> Found %d records in table %s", $sth1->rows, $table));

            while (my $results = $sth1->fetchrow_hashref) {
                $starttime = $results->{starttime};
                $node_id = $results->{node_id};
                $key1 = $results->{key1};
                $key2 = $results->{key2};
                $value = $results->{value};
                $name = $results->{name};
                $region = $results->{region};

#                        debug (sprintf("    +--- %s %s %s %s %s %s %s", $starttime, $node_id, $key1, $key2, $value, $name, $region));
                        if ( ( $key1 eq 'tcp' ) && ( $key2 eq 'IPv6') ) {
                                $tcpipv6 += $value;
                                $totaltcpipv6 += $value;
                        } elsif ( ( $key1 eq 'tcp' ) && ( $key2 eq 'IPv4') ) {
                                $tcpipv4 += $value;
                                $totaltcpipv4 += $value;
                        } elsif ( ( $key1 eq 'udp' ) && ( $key2 eq 'IPv6') ) {
                                $udpipv6 += $value;
                                $totaludpipv6 += $value;
                        } elsif ( ( $key1 eq 'udp' ) && ( $key2 eq 'IPv4') ) {
                                $udpipv4 += $value;
                                $totaludpipv4 += $value;
                        } else {
                                debug ("Problem reading data from this row\n");
                        }

                #debug (sprintf("    +--- %s %s %s %s %s %s %s", $starttime, $node_id, $key1, $key2, $value, $name, $region));

                }
        $sth1->finish;


        $nameservers{$nameserver}{tcp_ipv6} = $tcpipv6;
        $nameservers{$nameserver}{tcp_ipv4} = $tcpipv4;
        $nameservers{$nameserver}{udp_ipv6} = $udpipv6;
        $nameservers{$nameserver}{udp_ipv4} = $udpipv4;
        }

$tcpipv6 = '';
$tcpipv4 = '';
$udpipv6 = '';
$udpipv4 = '';

}  # End Foreach nameserver
print Dumper \%nameservers;

}  # End Foreach cloud

        debug ("Disconnecting from database server");
        $dbh->disconnect;

my $server;
format HEDGEHOG_RPT =
  @<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<
  $server, $udpipv6, $tcpipv6, $udpipv4, $tcpipv4; 
.

open(HEDGEHOG_RPT, '>', "$filename") or die "Could not open file '$filename' $!";

foreach my $nameserver ( sort keys %nameservers) {
        $server = $nameserver;
    while (my ($key, $value) = each %{ $nameservers{$nameserver} } ) {

        if ( $nameservers{$nameserver}{tcp_ipv6} ) {
        $tcpipv6 = $nameservers{$nameserver}{tcp_ipv6};
        } else {
        $tcpipv6 = 'n';
        }

        if ( $nameservers{$nameserver}{tcp_ipv4} ) {
        $tcpipv4 = $nameservers{$nameserver}{tcp_ipv4};
        } else {
        $tcpipv4 = 'n';
        }

        if ( $nameservers{$nameserver}{udp_ipv6} ) {
        $udpipv6 = $nameservers{$nameserver}{udp_ipv6};
        } else {
        $udpipv6 = 'n';
        }

        if ( $nameservers{$nameserver}{udp_ipv4} ) {
        $udpipv4 = $nameservers{$nameserver}{udp_ipv4};
        } else {
        $udpipv4 = 'n';
        }
    }
        write(HEDGEHOG_RPT);
}

        select((select(HEDGEHOG_RPT), $~ = "HEDGEHOG_RPT_TOTAL")[0]);
        write(HEDGEHOG_RPT);


close (HEDGEHOG_RPT);

    open(my $fh, '<', "$filename") or die "Could not open file '$filename' $!";
    {
        local $/;
        $content = <$fh>;
    }
    close($fh);

        print $content;

        my $subject=sprintf("%s Anycast DNS Query Volume %s-%s \n", lc(hostname()), $rmonth, $year);

my %mail = (
                        'SMTP'          => sprintf('%s', $smtphost),
                        'From'          => sprintf('"%s" <%s>', lc(hostname()), $from),
                        'To'            => sprintf('%s', $to),
                        'Subject'       => sprintf('%s', $subject),
                        'Body'          => sprintf(
                                                "%s Anycast DNS Query Volume %s-%s \n\n%s",
                                                uc(hostname()),
                                                $rmonth,
                                                $year,
                                                $content
                                        ),
                );

                map { debug($_) } split(/\n/, $mail{'Body'});

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
        my $msg = shift;
        print "$msg\n";
        syslog(LOG_DEBUG, $msg);
#        push(@log, sprintf("%s: %s", strftime($timefmt, time()), $msg));
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

        hedgehog.stats - hedgehog stats collector

=head1 DESCRIPTION

C<hedgehog.stats> is a Perl script which gathers anycast dns query volumes 
(tcp/udp) and displays them in a report.

=head1 USAGE

        hedgehog.stats [OPTIONS]

=head1 OPTIONS

=over

=item --help

Show this help.

=item --debug

Show verbose debugging messages.

=back

=cut
