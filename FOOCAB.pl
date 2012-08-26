#!/usr/bin/perl

use Getopt::Long;
use NetAddr::IP::Lite;

my $host;
my $node;

$result = GetOptions ("host=s" => \$host,
		      "node=s" => \$node);

open(NODEDB,"nodedb.txt");
open(SED,">foocab.sed");

$header = <NODEDB>;
chomp $header;

@vars = split /\t/, $header;

my $hi = undef;
my $ni = undef;
my $di = undef; # index of DHCPSTART

for ($i = 0 ; $i < @vars ; $i++)
{
    if (defined $host && ($vars[$i] eq "HOSTNAME")) {
	$hi = $i;
    }
    elsif (defined $node && ($vars[$i] eq "NODE")) {
	$ni = $i;
    }
    elsif ($vars[$i] eq "DHCPSTART") {
	$di = $i;
    }
}

my $logo = undef;
my $bridge = undef;
my $device = undef;
my $filter = undef;
my $pubifaces = undef;
my $privifaces = undef;
my $waniface = undef;
my $vpniface = "ptp";

my $hwclock = undef;

while(<NODEDB>) {
    chomp;
    @vals = split /\t/;

    if ((defined $hi && ($vals[$hi] eq $host)) ||
	(defined $ni && ($vals[$ni] eq $node)))
    {
	my $masklen = undef;
	my $pubaddr = undef;
	my $privaddr = undef;
	my $privmasklen = undef;

	for ($i = 0 ; $i < @vars ; $i++)
	{
            # provide an overridable default value for DHCPSTART
	    if ($i == $di && ((not defined($vals[$i])) || ($vals[$i] eq ""))) { 
		$vals[$i] = 5;
	    }
   
	    print SED "s/PTP_$vars[$i]_PTP/$vals[$i]/g\n";
	    if ($vars[$i] eq "PUBMASKLEN") {
		$masklen = $vals[$i];
	    }
	    if ($vars[$i] eq "PUBADDR") {
		$pubaddr = $vals[$i];
	    }
	    if ($vars[$i] eq "LOGOFILE") {
		$logo = $vals[$i];
	    }
	    if ($vars[$i] eq "BRIDGE") {
		$bridge = $vals[$i];
	    }
	    if ($vars[$i] eq "DEVICE") {
		$device = $vals[$i];
	    }
	    if ($vars[$i] eq "PRIVADDR") {
		$privaddr = $vals[$i];
	    }
	    if ($vars[$i] eq "PRIVMASKLEN") {
		$privmasklen = $vals[$i];
	    }
	    if ($vars[$i] eq "FILTER") {
		$filter = $vals[$i];
	    }
	    
	}

	# IPv6 prefix - this one belongs to PTP
	my $ipv6slash48 = "2001:470:e962";

	my @octets = split(/\./, $pubaddr);
	printf(SED "s/PTP_PUB6PREFIX_PTP/%s:%02x%02x::/g\n", $ipv6slash48, @octets[2], @octets[3]);
	printf(SED "s/PTP_VPN6ADDRESS_PTP/%s::%02x%02x/g\n", $ipv6slash48, @octets[2], @octets[3]);

	print "DEVICE=$device\n";

	if($device eq "WGT") {
	    $waniface = "eth0.1";
	    if ($bridge) {
		$pubifaces = "eth0.0";
		$privifaces = "";
	    } else {
	        $pubifaces = "";
	        $privifaces = "eth0.0";
	    }
	    print SED "s/PTP_ARCH_PTP/wgt634u/g\n";
	} elsif ($device eq "ALIX") {
	    $waniface = "eth0";
	    if ($bridge) {
	        $pubifaces = "eth1 eth2";
	        $privifaces = "";
	    } else {
		$pubifaces = "eth1";
		$privifaces = "eth2";
	    }
	    print SED "s/PTP_ARCH_PTP/alix2/g\n";
	    $hwclock = true;
	} elsif ($device eq "NET4521") {
	    $waniface = "eth0";
	    if ($bridge) {
		$pubifaces = "eth1";
		$privifaces = "";
	    } else {
	        $pubifaces = "";
	        $privifaces = "eth1";
	    }
	    print SED "s/PTP_ARCH_PTP/net4521/g\n";
	    $hwclock = true;
	} elsif ($device eq "MR3201A") {
	    $waniface = "eth0";
	    $pubifaces = "";
	    $privifaces = "";
    	    print SED "s/PTP_ARCH_PTP/atheros/g\n";
	}
	
	print SED "s/PTP_WANIFACE_PTP/$waniface/g\n";
	print SED "s/PTP_PRIVIFACES_PTP/$privifaces/g\n";
	print SED "s/PTP_PUBIFACES_PTP/$pubifaces/g\n";
	
	(defined $masklen && defined $pubaddr) || die "Not enough information to compute network!";
	
	my $ip = NetAddr::IP::Lite->new("$pubaddr/$masklen");
	my $network = $ip->network();
	my $netaddr = $network->addr();
	my $mask = $ip->mask();
	
	print SED "s/PTP_PUBNET_PTP/$netaddr/g\n";
	print SED "s/PTP_PUBNETMASK_PTP/$mask/g\n";
	
	if ($privifaces ne "") {
	    $ip = NetAddr::IP::Lite->new("$privaddr/$privmasklen");
	    $network = $ip->network();
	    $netaddr = $network->addr();
	    $mask = $ip->mask();
	    
	    print SED "s/PTP_PRIVNET_PTP/$netaddr/g\n";
	    print SED "s/PTP_PRIVNETMASK_PTP/$mask/g\n";
	}
    }
}

open(FILES,"find etc lib usr root -type f |");

while(<FILES>) {
    chomp;
    my $src = $_;
    my @path = split('/',$src);
    my $fname = pop @path;
    my $outdir = join('/',"output",@path);
    my $dest = join('/',"output",@path,$fname);

    # print "source = $src ; outdir = $outdir ; dest = $dest\n";

    ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($src);

    unless (-d $outdir) { system("mkdir -p $outdir"); }

    print "sed -f foocab.sed < $src > $dest\n";

    system("sed -f foocab.sed < $src > $dest");

    chmod($mode,$dest);
    chown($uid,$gid,$dest);
}

if ($device eq "ALIX" || $device eq "NET4521") {
    # if alix or net4521, remove the vlan configuration from etc/config/network
    system("mv output/etc/config/network output/etc/config/network.orig ; tail -n +`grep -n 'loopback' output/etc/config/network.orig | cut -d: -f 1` output/etc/config/network.orig > output/etc/config/network ; rm output/etc/config/network.orig");
}
if ($device eq "ALIX") {
    # delete the etc/config/wireless
    system("rm output/etc/config/wireless");
}
if ($privifaces eq "") {
    # delete the priv network configuration from etc/config/network
    open(NETWORKIN,"output/etc/config/network");
    open(NETWORKOUT,">output/etc/config/network.out");
    my $output = 1;
    while(<NETWORKIN>) {
	chomp;

	if($_ =~ /priv/) {
	  $output = 0;
	  print "output off\n";
	}
        if($_ =~ /pub/) {
	  $output = 1;
	}

	if ($output) {
	  print NETWORKOUT "$_\n";
	}
    }
    system("mv output/etc/config/network.out output/etc/config/network");

    # delete the priv network configuration from etc/config/dhcp
    open(DHCPIN,"output/etc/config/dhcp");
    open(DHCPOUT,">output/etc/config/dhcp.out");
    my $output = 1;
    while(<DHCPIN>) {
	chomp;

	if($_ =~ /^config dhcp priv/) {
	  $output = 0;
	  print "output off\n";
	}
        if($_ =~ /^config dhcp pub/) {
	  $output = 1;
	}

	if ($output) {
	  print DHCPOUT "$_\n";
	}
    }
    system("mv output/etc/config/dhcp.out output/etc/config/dhcp");

    # delete the priv network rules from etc/init.d/firewall_rss
    open(FIREWALLIN,"output/etc/init.d/firewall_rss");
    open(FIREWALLOUT,">output/etc/init.d/firewall_rss.out");
    while(<FIREWALLIN>) {
	chomp;

	if($_ !~ /PRIVNET/) {
	  print FIREWALLOUT "$_\n";
	}
    }
    system("mv output/etc/init.d/firewall_rss.out output/etc/init.d/firewall_rss");
    chmod(0755,"output/etc/init.d/firewall_rss");
}
    
open(LINKS,"find etc usr root www -type l |");

while(<LINKS>) {
    chomp;

    my $src = $_;
    my @path = split('/',$src);
    my $fname = pop @path;
    my $outdir = join('/',"output",@path);
    my $dest = join('/',"output",@path,$fname);

    unless (-d $outdir) { system("mkdir -p $outdir"); }

    print "cp -a $src $dest\n";

    system("cp -a $src $dest");
}

if ($filter ne "NONE") {
    # create filter script and /etc/rc.d link
    open(FILTER,">output/etc/init.d/filter");

    print FILTER 
	"#!/bin/sh /etc/rc.common
# Copyright (C) 2006 OpenWrt.org

START=96
STOP=96

start() {\n";

    if ($filter eq "WAN" || $filter eq "BOTH") {
	print FILTER
	    "        for i in \$(ip addr show dev $waniface | grep 'inet ' | awk '{ print \$2 }') ; do iptables -I FORWARD -i br-pub -d \$i -j DROP ; iptables -I FORWARD -i $vpniface -d \$i -j DROP ; done\n";
	print FILTER
	    "        for i in \$(ip addr show dev $waniface | grep inet6 | grep -v 'scope local' | awk '{ print \$2 }') ; do ip6tables -I FORWARD -i br-pub -d \$i -j DROP ; ip6tables -I FORWARD -i $vpniface -d \$i -j DROP ; done\n";
    }
    if (($privifaces ne "") && ($filter eq "PRIV" || $filter eq "BOTH")) {
	print FILTER
	    "        iptables -I FORWARD -o br-priv -i br-pub -j DROP\n";
	print FILTER
	    "        iptables -I FORWARD -o br-priv -i $vpniface -j DROP\n";
    }

    print FILTER 
	"}

stop() {\n";

    if ($filter eq "WAN" || $filter eq "BOTH") {
	print FILTER
	    "        for i in \$(ip addr show dev $waniface | grep 'inet ' | awk '{ print \$2 }') ; do iptables -D FORWARD -i br-pub -d \$i -j DROP ; iptables -D FORWARD -i $vpniface -d \$i -j DROP ; done\n";
	print FILTER
	    "        for i in \$(ip addr show dev $waniface | grep inet6 | grep -v 'scope local' | awk '{ print \$2 }') ; do ip6tables -D FORWARD -i br-pub -d \$i -j DROP ; ip6tables -D FORWARD -i $vpniface -d \$i -j DROP ; done\n";
    }
    if (($privifaces ne "") && ($filter eq "PRIV" || $filter eq "BOTH")) {
	print FILTER
	    "        iptables -D FORWARD -o br-priv -i br-pub -j DROP\n";
	print FILTER
	    "        iptables -D FORWARD -o br-priv -i $vpniface -j DROP\n";
    }

    print FILTER "}\n";

    close(FILTER);
    chmod 0755,"output/etc/init.d/filter";
    symlink "../init.d/filter","output/etc/rc.d/S96filter";
}

if($hwclock) {
	open(INITCLOCK,">output/etc/init.d/initclock");

	print INITCLOCK
		"#!/bin/sh /etc/rc.common
# Copyright (C) 2008 OpenWrt.org

START=11

start() {
	# set clock to hardware clock value
	/sbin/hwclock -s -u
}\n";

	close(INITCLOCK);
	chmod 0755,"output/etc/init.d/initclock";

	open(CRONTAB,">>output/etc/crontabs/root");
	print CRONTAB "0 0 * * *	/sbin/hwclock -w -u\n";
	close(CRONTAB);
}

open(WWW,"find www -type f | grep -v nodes |");

while(<WWW>) {
    chomp;
    my $src = $_;
    my @path = split('/',$src);
    my $fname = pop @path;
    my $outdir = join('/',"output",@path);
    my $dest = join('/',"output",@path,$fname);

    # print "source = $src ; outdir = $outdir ; dest = $dest\n";

    ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks)
	= stat($src);

    unless (-d $outdir) { system("mkdir -p $outdir"); }

    print "sed -f foocab.sed < $src > $dest\n";

    system("sed -f foocab.sed < $src > $dest");

    chmod($mode,$dest);
    chown($uid,$gid,$dest);
}

if (defined($logo) && $logo ne "") {
    my $src = "www/images/nodes/$logo";

    print "cp -p $src output/www/images/$logo\n";

    system("cp -p $src output/www/images/$logo");
}
