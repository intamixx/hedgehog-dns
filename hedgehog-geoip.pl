#!/usr/bin/perl                                                                                                                                                                                              
# Msingh
# v1.0
# Hedgehog Anycast Busiest Client Subnets

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
use Geo::IP; 
use Net::Whois::IP qw(whoisip_query);

my $filename = "/tmp/hedgehog.rpt";

my $SELF = basename(__FILE__);

my $host = "127.0.0.1";
my $from='netops@mon-3.bfn.uk.erwer.net';
my $smtphost='localhost';
my $to='ops@erwer.com';
my $content;

my $SRVquery;
my $dns = uc('ns1.erwer.net'); 

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
my        $node_region;
my        $region;
my        $country;
my        $city;
my        $org;

my        $asnumber;
my        $isp;

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
my $limit = 10;
my $ipv4;
my $ipv6;
my $ipprot;
my $gi;
my $giorg;
my $giasnum;
my $r;

my ($debug, $noalerts, $help, $noisy, $networks);

usage() if (!@ARGV);

GetOptions(
           'day=i' => \$day,
           'month=i' => \$month,
           'year=i' => \$year,
           '4' => \$ipv4,
           '6' => \$ipv6,
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

$ipv4 = "IPv4" if ( !($ipv4) && !($ipv6) );
if ($ipv6) {
        $ipprot = "IPv6";
} else {
        $ipprot = "IPv4";
}

if ($ipv6) {
        $gi = Geo::IP->open( "/usr/share/GeoIP/GeoLiteCityv6.dat", GEOIP_STANDARD ) or die;
        $giasnum = Geo::IP->open( "/usr/share/GeoIP/GeoIPASNumv6.dat", GEOIP_STANDARD ) or die;
} else {
        $gi = Geo::IP->open( "/usr/share/GeoIP/GeoLiteCity.dat", GEOIP_STANDARD ) or die;
        $giasnum = Geo::IP->open( "/usr/share/GeoIP/GeoIPASNum.dat", GEOIP_STANDARD ) or die;
        $giorg = Geo::IP->open("/usr/share/GeoIP/GeoIPOrg.dat", GEOIP_STANDARD ) or die;
}

        printf ("\nGetting current month year information\n");
        printf ("%s\n", strftime('%Y-%m-%d',localtime) );

        # Find out days in month
        my $days = month_days( $year, $month );
        debug ("month $month $year has $days days\n\n");
        # Convert month to month name
        my $time = POSIX::mktime(1,1,1,1,$month-1,$year-1900);
        my $rmonth = strftime q{%b}, localtime ( $time );
        $month = strftime q{%m}, localtime ( $time );

pod2usage('-verbose' => 99, '-sections' => 'USAGE|OPTIONS') if ($help);

        debug (sprintf("Connecting to database server on %s\n", $host));
        my $dbh = DBI->connect(sprintf('DBI:Pg:database=%s;host=%s', $database, $host), $username, $password, { RaiseError => 1}) or add_error (sprintf("Couldn't connect to database: %s", DBI->errstr));;

        open(HEDGEHOG_RPT, '>', "$filename") or die "Could not open file '$filename' $!";
        print HEDGEHOG_RPT "$ipprot Centralnic Anycast Busiest Client Subnets $rmonth-$year\n";

foreach $cloud (@cloud) {

        print "\nCLOUD $cloud\n";

        if ( @{cmdlhosts} ) {
        @hosts = @{cmdlhosts};
                } else {
                # Query SRV records
                $res = Net::DNS::Resolver->new( nameservers => [$dns], tcp_timeout => $timeout, udp_timeout => $timeout, retry => 3, 'persistent_tcp' => 1, 'persistent_udp' => 1, 'debug' => $noisy );
                $SRVquery = sprintf("_dns._udp.%s.dns.erwer.net", $cloud);
                @hosts = SRVquery ( $SRVquery, $dns );
        }

        foreach $ns ( sort @{hosts}) {

                if ( $ns =~ /(^ns\-\d{1,2})/ ) {
                        $nameserver = $1;
                        #push ( @nameserver, $nameserver );
                        }


        $table = sprintf("data_cloud_%s_client_subnet_accum_%s_%s", $cloud, $year, $month);

        # Check the table exists
        my $sth = $dbh->table_info("", "", $table, "TABLE");
                if (!($sth->fetch)) {
                debug ("Table $table does not exist\n");
                next;
                }
        $sth->finish;

        # Get node_region
        my $sth1 = $dbh->prepare(sprintf('SELECT region FROM node WHERE name = \'%s\'', $nameserver ) ) ||  die "$DBI::errstr";
        $sth1->execute;
        $node_region = $sth1->fetchrow_array;
        $sth1->finish;

        my $sth2;
        # Get the data from the table
        if ($ipv6) {
                $sth2 = $dbh->prepare(sprintf('SELECT n1.key2, n1.value from (SELECT DISTINCT ON (key2) key2,value from %s,node WHERE node.id=%s.node_id AND name=\'%s\' AND key2 ~ \'\::\') n1 ORDER BY n1.value DESC LIMIT %d', $table, $table, $nameserver, $limit ) ) ||  die "$DBI::errstr";
        } else {
                $sth2 = $dbh->prepare(sprintf('SELECT n1.key2, n1.value from (SELECT DISTINCT ON (key2) key2,value from %s,node WHERE node.id=%s.node_id AND name=\'%s\' AND key2 ~ \'\.\') n1 ORDER BY n1.value DESC LIMIT %d', $table, $table, $nameserver, $limit ) ) ||  die "$DBI::errstr";
        }

        $sth2->execute();

        if ($sth2->rows >= 1) {
                select(HEDGEHOG_RPT);
                $~ = "TOP";
                write(HEDGEHOG_RPT);

                select(STDOUT);

                 debug (sprintf(">> Found %d records in table %s\n%s\n", $sth2->rows, $table, $nameserver));

            while (my $results = $sth2->fetchrow_hashref) {
                $key2 = $results->{key2};
                $value = $results->{value};
                $node_region = $results->{region};

                undef $asnumber;
                if ($ipv6) {
                        $r = $gi->record_by_name_v6($key2);
                        $asnumber = $giasnum->name_by_addr_v6($key2);
                } else {
                        $r = $gi->record_by_name($key2);
                        $asnumber = $giasnum->name_by_addr($key2);
                        #$org = $giorg->org_by_name($key2);
                }

                if ($r) {
                        undef $country;
                        undef $region;
                        undef $city;
                        undef $org;
                        my $response = whoisip_query($key2);
                        foreach (sort keys(%{$response}) ) {
                                $org = $response->{$_} if ( $_ =~ /netname|org-name|organization/i );
                                #$asnumber = $response->{$_} if ( $_ =~ /origin/i );
                                }
                        $country = "" if !($country);
                        $region = "" if !($region);
                        $city = "" if !($city);
                        $org = "" if !($org);
                        $asnumber = "" if !($asnumber);

                        $country = $r->country_name if $r->country_name;
                        $region = $r->region_name if $r->region_name;
                        $city = $r->city if $r->city;

                        debug (sprintf("    +--- %s (%s) - %s", $key2, $value, $country));
                        debug (sprintf(" - %s (%s)", $region, $city)) if ($region) || ($city);
                        debug (sprintf(" - %s", $org)) if ($org);
                        debug (sprintf(" - %s", $asnumber)) if ($asnumber);
                        debug ("\n");

                        select(HEDGEHOG_RPT);
                        $~ = "HEDGEHOG_RPT";
                        write(HEDGEHOG_RPT);
                        select(STDOUT);
                        }

                }
        $sth2->finish;

        }

}  # End Foreach nameserver

}  # End Foreach cloud
close (HEDGEHOG_RPT);

        debug ("Disconnecting from database server\n\n");
        $dbh->disconnect;

format HEDGEHOG_RPT =
  @<<<<<<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<<  @<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<<
  $key2, $value, $country, $region, $city, $org, $asnumber;
.

format TOP =

                                @<<<<< Cloud-@< @<<<<<<<<<<<<<<<<<<
$nameserver, $cloud, $node_region
  Network                Value             Country           Region            City              ISP / Org        ASNumber
  ---------------------  ----------------  ----------------  ----------------  ----------------  ---------------- ----------------
.

print "\n---------------\n";
print "@log";

    open(my $fh, '<', "$filename") or die "Could not open file '$filename' $!";
    {
        local $/;
        $content = <$fh>;
    }
    close($fh);

        print $content;

sleep 60;

        my $subject=sprintf("%s %s Anycast Busiest Client Subnets %s-%s \n", lc(hostname()), $ipprot, $rmonth, $year);

my %mail = (
                        'SMTP'          => sprintf('%s', $smtphost),
                        'From'          => sprintf('"%s" <%s>', lc(hostname()), $from),
                        'To'            => sprintf('%s', $to),
                        'Subject'       => sprintf('%s', $subject),
                        'Body'          => sprintf(
                                                "%s %s Anycast Busiest Client Subnets %s-%s \n\n%s",
                                                uc(hostname()),
                                                $ipprot,
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
        print "$msg";
        syslog(LOG_DEBUG, $msg);
        push(@log, sprintf("%s", $msg));
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
        print STDOUT "  -4               IPv4 Protocol (default)\n";
        print STDOUT "  -6               IPv6 Protocol\n";
        print STDOUT "  -hosts           hostname to query\n";
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
