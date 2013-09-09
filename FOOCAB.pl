#!/usr/bin/perl

use Getopt::Long;
use NetAddr::IP::Lite;

my $host;
my $node;
my $wimax = 0;

$result = GetOptions ("host=s" => \$host,
		      "node=s" => \$node,
		      "wimax" => \$wimax);

print "wimax = $wimax\n";

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
	} elsif ($device eq "WNDR3800") {
	    $waniface = "eth1";
	    if ($bridge) {
	        $pubifaces = "eth0.1";
		$privifaces = "";
	    } else {
	        $pubiface = "";
		$privifaces = "eth0.1";
	    }
	} elsif ($device eq "WDR3600") {
	    $waniface = "eth0.2";
	    if ($bridge) {
	        $pubifaces = "eth0.1";
		$privifaces = "";
	    } else {
	        $pubiface = "";
		$privifaces = "eth0.1";
	    }
	} elsif ($device eq "WZR600DHP" || $device eq "AIRROUTER") {
	    $waniface = "eth1";
	    if ($bridge) {
	    	$pubifaces = "eth0";
		$privifaces = "";
	    } else {
	        $pubifaces = "";
		$privifaces = "eth0";
	    }
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

if ($device eq "ALIX" || $device eq "NET4521" || $device eq "MR3201A" || $device eq "WNDR3800" || $device eq "WZR600DHP" || $device eq "AIRROUTER") {
    # if alix or net4521 or mr3201a, remove the vlan configuration from etc/config/network
    system("mv output/etc/config/network output/etc/config/network.orig ; tail -n +`grep -n 'loopback' output/etc/config/network.orig | cut -d: -f 1` output/etc/config/network.orig > output/etc/config/network ; rm output/etc/config/network.orig");
}
if ($device eq "WNDR3800") {
    # if wndr3800, append vlan/led config taken from default r34240
    open(NETWORKOUT,">>output/etc/config/network");
    open(SYSTEMOUT,">>output/etc/config/system");
    print NETWORKOUT <<EOF;

config switch
	option name	rtl8366s
	option reset	1
	option enable_vlan 1
	# Blinkrate: 0=43ms; 1=84ms; 2=120ms; 3=170ms; 4=340ms; 5=670ms
	option blinkrate	2

config switch_vlan
	option device	rtl8366s
	option vlan 	1
	option ports	"0 1 2 3 5t"

config switch_port
	# Port 1 controls the GREEN configuration of LEDs for
	# the switch and the section does not correspond to a real
	# switch port.
	#
	# 0=LED off; 1=Collision/FDX; 2=Link/activity; 3=1000 Mb/s;
	# 4=100 Mb/s; 5=10 Mb/s; 6=1000 Mb/s+activity; 7=100 Mb/s+activity;
	# 8=10 Mb/s+activity; 9=10/100 Mb/s+activity; 10: Fiber;
	# 11: Fault; 12: Link/activity(tx); 13: Link/activity(rx);
	# 14: Link (master); 15: separate register

	option device		rtl8366s
	option port		1
	option led		6

config switch_port
	# Port 2 controls the ORANGE configuration of LEDs for
	# the switch and the section does not correspond to a real
	# switch port.
	#
	# See the key above for switch port 1 for the meaning of the
	# 'led' setting below.
	
	option device		rtl8366s
	option port		2
	option led		9

config switch_port
	# Port 5 controls the configuration of the WAN LED and the
	# section does not correspond to a real switch port.
	#
	# To toggle the use of green or orange LEDs for the WAN port,
	# see the LED setting for wndr3700:green:wan in /etc/config/system.
	#
	# See the key above for switch port 1 for the meaning of the
	# 'led' setting below.

	option device		rtl8366s
	option port		5
	option led		2
EOF
    print SYSTEMOUT <<EOF;

config led 'led_wan'
	option name 'WAN LED (green)'
	option sysfs 'wndr3700:green:wan'
	option default '0'

config led 'led_usb'
	option name 'USB'
	option sysfs 'wndr3700:green:usb'
	option trigger 'usbdev'
	option dev '1-1'
	option interval '50'
EOF
}
if ($device eq "WZR600DHP") {
    # if wzr600dhp, append vlan/led config taken from default r35052
    open(NETWORKOUT,">>output/etc/config/network");
    open(SYSTEMOUT,">>output/etc/config/system");
    print NETWORKOUT <<EOF;

config switch
	option reset '1'
	option enable_vlan '1'
	option name 'switch0'   
 
config switch_vlan
	option vlan '1'
	option ports '0 1 2 3 4'
	option device 'switch0' 
EOF

    print SYSTEMOUT <<EOF;

config led 'led_diag'
        option name 'DIAG'
        option sysfs 'buffalo:red:diag'
        option default '0'

config led 'led_router'
        option name 'ROUTER'
        option sysfs 'buffalo:green:router'
        option trigger 'netdev'
        option dev 'eth1'
        option mode 'link tx rx'

config led 'led_usb'
        option name 'USB'
        option sysfs 'buffalo:green:usb'
        option trigger 'usbdev'
        option dev '1-1'
        option interval '50'
EOF

    close(NETWORKOUT);
    close(SYSTEMOUT);
}

if ($device eq "WDR3600") {
    open(NETWORKOUT,">>output/etc/config/network");
    open(WIRELESSOUT,">output/etc/config/wireless");
    open(SYSTEMOUT,">>output/etc/config/system");

    print NETWORKOUT <<EOF;

config switch
        option name 'switch0'
        option reset '1'
        option enable_vlan '1'

config switch_vlan
        option device 'switch0'
        option vlan '1'
        option ports '0t 2 3 4 5'

config switch_vlan
        option device 'switch0'
        option vlan '2'
        option ports '0t 1'
EOF

    print WIRELESSOUT <<EOF;
config wifi-device  radio0
        option type     mac80211
        option channel  11
        option hwmode   11ng
        option path     'platform/ar934x_wmac'
        option htmode   HT20
        list ht_capab   LDPC
        list ht_capab   SHORT-GI-20
        list ht_capab   SHORT-GI-40
        list ht_capab   TX-STBC
        list ht_capab   RX-STBC1
        list ht_capab   DSSS_CCK-40
        # REMOVE THIS LINE TO ENABLE WIFI:
        option disabled 1

config wifi-iface
        option device   radio0
        option network  pub
        option mode     ap
        option ssid     www.personaltelco.net/notyet
        option encryption none

config wifi-device  radio1
        option type     mac80211
        option channel  36
        option hwmode   11na
        option path     'pci0000:00/0000:00:00.0'
        option htmode   HT20
        list ht_capab   LDPC
        list ht_capab   SHORT-GI-20
        list ht_capab   SHORT-GI-40
        list ht_capab   TX-STBC
        list ht_capab   RX-STBC1
        list ht_capab   DSSS_CCK-40
        # REMOVE THIS LINE TO ENABLE WIFI:
        option disabled 1

config wifi-iface
        option device   radio1
        option network  pub
        option mode     ap
        option ssid	www.personaltelco.net/notyet
        option encryption none
EOF

    print SYSTEMOUT <<EOF;
config led 'led_usb1'
        option name 'USB1'
        option sysfs 'tp-link:green:usb1'
        option trigger 'usbdev'
        option dev '1-1.1'
        option interval '50'

config led 'led_usb2'
        option name 'USB2'
        option sysfs 'tp-link:green:usb2'
        option trigger 'usbdev'
        option dev '1-1.2'
        option interval '50'

config led 'led_wlan2g'
        option name 'WLAN2G'
        option sysfs 'tp-link:blue:wlan2g'
        option trigger 'phy0tpt'

EOF

    close(SYSTEMOUT);
    close(WIRELESSOUT);
    close(NETWORKOUT);
}

if ($device eq "AIRROUTER") {
    # if airrouter, append vlan config taken from r37493
    open(NETWORKOUT,">>output/etc/config/network");
    open(WIRELESSOUT,">output/etc/config/wireless");

    print NETWORKOUT <<EOF;

config switch
	option name 'switch0'
	option reset '1'
	option enable_vlan '1'
			
config switch_vlan
	option device 'switch0'
	option vlan '1'
	option ports '0 1 2 3 4'
EOF

    print WIRELESSOUT <<EOF;
config wifi-device  radio0
	option type     mac80211
	option channel  1
	option hwmode   11ng
	option path     'pci0000:00/0000:00:00.0'
	option htmode   HT20
	list ht_capab   SHORT-GI-40
	list ht_capab   TX-STBC
	list ht_capab   RX-STBC1
	list ht_capab   DSSS_CCK-40
	# REMOVE THIS LINE TO ENABLE WIFI:
	# option disabled 1
       
config wifi-iface
	option device   radio0
	option network  pub  
	option mode     ap
	option ssid     www.personaltelco.net/notyet
	option encryption none
EOF

    close(NETWORKOUT);
    close(WIRELESSOUT);
}

if ($device eq "WNDR3800" || $device eq "WZR600DHP") {
    open(WIRELESSOUT,">output/etc/config/wireless");
    print WIRELESSOUT <<EOF;
config wifi-device  radio0
	option type     mac80211
	option channel  11
	option hwmode	11ng
	option path	'pci0000:00/0000:00:11.0'
	option htmode	HT20
	list ht_capab	SHORT-GI-40
	list ht_capab	TX-STBC
	list ht_capab	RX-STBC1
	list ht_capab	DSSS_CCK-40
	# REMOVE THIS LINE TO ENABLE WIFI:
	#option disabled 1

config wifi-iface
	option device   radio0
	option network	pub  
	option mode     ap
	option ssid     www.personaltelco.net/notyet
	option encryption none

config wifi-device  radio1
	option type     mac80211
	option channel  36
	option hwmode	11na
	option path	'pci0000:00/0000:00:12.0'
	option htmode	HT20
	list ht_capab	SHORT-GI-40
	list ht_capab	TX-STBC
	list ht_capab	RX-STBC1
	list ht_capab	DSSS_CCK-40
	# REMOVE THIS LINE TO ENABLE WIFI:
	#option disabled 1

config wifi-iface
	option device   radio1
	option network  pub
	option mode     ap
	option ssid	www.personaltelco.net/notyet
	option encryption none
EOF
    close(WIRELESSOUT);
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

if($wimax) {
	open(CRONTAB,">>output/etc/crontabs/root");
	print CRONTAB "*/5 * * * *     /usr/bin/motorola.sh > /dev/null 2>&1\n";
	close(CRONTAB);

	system("cp -a wimax/* output/");
}

# fetch_image.sh script

if($device eq "ALIX") { $imagename = "x86/openwrt-x86-alix2-combined-squashfs.img"; }
elsif($device eq "NET4521" || $device eq "NET4826") { $imagename = "x86/openwrt-x86-generic-combined-squashfs.img"; }
elsif($device eq "MR3201A") { $imagename = "atheros/openwrt-atheros-combined.squashfs.img"; }
elsif($device eq "WNDR3800") { $imagename = "ar71xx/openwrt-ar71xx-generic-wndr3800-squashfs-sysupgrade.bin"; }
elsif($device eq "WZR600DHP") { $imagename = "ar71xx/openwrt-ar71xx-generic-wzr-600dhp-squashfs-sysupgrade.bin"; }
elsif($device eq "WDR3600") { $imagename = "ar71xx/openwrt-ar71xx-generic-tl-wdr3600-v1-squashfs-sysupgrade.bin"; }
elsif($device eq "WGT") { $imagename = "brcm47xx/openwrt-brcm47xx-squashfs.trx"; }
elsif($device eq "AIRROUTER") { $imagename = "ar71xx/openwrt-ar71xx-generic-ubnt-airrouter-squashfs-sysupgrade.bin"; }
else { $imagename = ""; }

open(FIS,">output/usr/bin/fetch_image.sh");
print FIS <<EOF;
#!/bin/sh
cd /tmp
scp russell\@iris.personaltelco.net:src/openwrt/bin/$imagename /tmp/
EOF
system("chmod 755 output/usr/bin/fetch_image.sh");


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
