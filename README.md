# hedgehog-dns
Scripts for Hedgehog visualisation tool for DNS statistics - https://github.com/dns-stats/hedgehog

Run hedgehog-scp.pl as a cronjob (requires parallel-20140822-1.of.el7.x86_64)

parallel --gnu --max-procs 10 -k --no-notice  /usr/bin/perl /home/scripts/hedgehog-scp.pl -h {} -c A  ::: `dig +tcp +short SRV _dns._udp.a.dns.srvgroup.net | cut -d " " -f 4 | sed 's/.$//'`

Run hedgehog-stats.pl;

/home/scripts/hedgehog-stats.pl -m 09 -y 2015

to generate stats for given month.
