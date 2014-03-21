#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Long;
use NetAddr::IP::Lite;
use LWP::Simple;
use JSON qw( decode_json );
use Data::Dumper;

my $DEBUG = 1;

# IPv6 prefix - this one belongs to PTP
my $iPV6SLASH48 = "2001:470:e962";

my $host;
my $node;
my $wimax = 0;

my $APIBASE = "https://personaltelco.net/api/v0/nodes/";
my $IMGBASE = "https://personaltelco.net/splash/images/nodes/";

my $result = GetOptions(
	"host=s" => \$host,
	"node=s" => \$node,
	"wimax"  => \$wimax
);

print "wimax = $wimax\n";

my $nodeinfo = getNodeInfo($node);
if ( $nodeinfo->{'node'} ne $node ) {
	die "did not find node $node from $APIBASE";
	exit;
}

my $vpniface    = "ptp";
my $logo        = $nodeinfo->{'logo'};
my $bridge      = $nodeinfo->{'bridge'};
my $device      = $nodeinfo->{'device'};
my $filter      = $nodeinfo->{'filter'};
my $pubifaces   = $nodeinfo->{'pubifaces'};
my $privifaces  = $nodeinfo->{'privifaces'};
my $waniface    = $nodeinfo->{'waniface'};
my $masklen     = $nodeinfo->{'pubmasklen'};
my $pubaddr     = $nodeinfo->{'pubaddr'};
my $privaddr    = $nodeinfo->{'privaddr'};
my $privmasklen = $nodeinfo->{'privmasklen'};
my $hwclock     = $nodeinfo->{'hwclock'};

open( SED, ">foocab.sed" ) or die "can't open foocab.sed: " . $!;
foreach my $k ( keys %$nodeinfo ) {
	# too many slashes in the URLs for SED
	if ( $k ~~ [ 'wikiurl', 'url', 'rss' ] ) {    
		next;
	}

	#	print $k,' ',$nodeinfo->{$k},"\n";
	my $sed = "s/PTP_" . uc($k) . "_PTP/" . $nodeinfo->{$k} . "/g\n";
	print $sed if $DEBUG;
	print SED $sed;
}

if ( !defined( $nodeinfo->{'dhcpstart'} ) ) {
	$nodeinfo->{'dhcpstart'} = 5;
	print "dhcpstart not found, setting  to " . $nodeinfo->{'dhcpstart'}, "\n";
	my $sed = "s/PTP_DHCPSTART_PTP/" . $nodeinfo->{'dhcpstart'} . "/g\n";
	print $sed if $DEBUG;
	print SED $sed;
}

my @octets = split( /\./, $nodeinfo->{'pubaddr'} );
printf( SED "s/PTP_PUB6PREFIX_PTP/%s:%02x%02x::/g\n",
	$iPV6SLASH48, $octets[2], $octets[3] );
printf( SED "s/PTP_VPN6ADDRESS_PTP/%s::%02x%02x/g\n",
	$iPV6SLASH48, $octets[2], $octets[3] );

print "DEVICE=" . $nodeinfo->{'device'} . "\n";

if ( $device eq "WGT" ) {
	$waniface = "eth0.1";
	if ($bridge) {
		$pubifaces  = "eth0.0";
	} else {
		$privifaces = "eth0.0";
	}
	print SED "s/PTP_ARCH_PTP/wgt634u/g\n";
} elsif ( $device eq "ALIX" ) {
	$waniface = "eth0";
	if ($bridge) {
		$pubifaces  = "eth1 eth2";
	} else {
		$pubifaces  = "eth1";
		$privifaces = "eth2";
	}
	print SED "s/PTP_ARCH_PTP/alix2/g\n";
	$hwclock = 1;
} elsif ( $device eq "NET4521" ) {
	$waniface = "eth0";
	if ($bridge) {
		$pubifaces  = "eth1";
	}
	else {
		$privifaces = "eth1";
	}
	print SED "s/PTP_ARCH_PTP/net4521/g\n";
	$hwclock = 1;
} elsif ( $device eq "MR3201A" ) {
	$waniface   = "eth0";
	print SED "s/PTP_ARCH_PTP/atheros/g\n";
}
elsif ( $device eq "WNDR3800" ) {
	$waniface = "eth1";
	if ($bridge) {
		$pubifaces  = "eth0.1";
	} else {
		$privifaces = "eth0.1";
	}
} elsif ( $device eq "WDR3600" ) {
	$waniface = "eth0.2";
	if ($bridge) {
		$pubifaces  = "eth0.1";
	} else {
		$privifaces = "eth0.1";
	}
}
elsif ( $device eq "WZR600DHP" || $device eq "AIRROUTER" ) {
	$waniface = "eth1";
	if ($bridge) {
		$pubifaces  = "eth0";
	} else {
		$privifaces = "eth0";
	}
}

print SED "s/PTP_WANIFACE_PTP/$waniface/g\n";
print SED "s/PTP_PRIVIFACES_PTP/$privifaces/g\n";
print SED "s/PTP_PUBIFACES_PTP/$pubifaces/g\n";

if ( ! defined($masklen) ||  !defined($pubaddr) ) {
  die "Not enough information to compute network! pubaddr: " . $pubaddr . " masklen: " . $masklen ;
}

my $ip      = NetAddr::IP::Lite->new("$pubaddr/$masklen");
my $network = $ip->network();
my $netaddr = $network->addr();
my $mask    = $ip->mask();

print SED "s/PTP_PUBNET_PTP/$netaddr/g\n";
print SED "s/PTP_PUBNETMASK_PTP/$mask/g\n";

if ( defined($privifaces)) {
	$ip      = NetAddr::IP::Lite->new("$privaddr/$privmasklen");
	$network = $ip->network();
	$netaddr = $network->addr();
	$mask    = $ip->mask();

	print SED "s/PTP_PRIVNET_PTP/$netaddr/g\n";
	print SED "s/PTP_PRIVNETMASK_PTP/$mask/g\n";
}
close SED;

open( FILES, "find etc lib usr root -type f |" );

while (<FILES>) {
	chomp;
	my $src    = $_;
	my @path   = split( '/', $src );
	my $fname  = pop @path;
	my $outdir = join( '/', "output", @path );
	my $dest   = join( '/', "output", @path, $fname );

	# print "source = $src ; outdir = $outdir ; dest = $dest\n";

	my (
		$dev,  $ino,   $mode,  $nlink, $uid,     $gid, $rdev,
		$size, $atime, $mtime, $ctime, $blksize, $blocks
	) = stat($src);

	unless ( -d $outdir ) { 
		system("mkdir -p $outdir"); 
	}
    my $cmd = "sed -f foocab.sed < $src > $dest"; 
	print $cmd, "\n";
	system($cmd);

	chmod( $mode, $dest );
	chown( $uid, $gid, $dest );
}

if (   $device eq "ALIX"
	|| $device eq "NET4521"
	|| $device eq "MR3201A"
	|| $device eq "WNDR3800"
	|| $device eq "WZR600DHP"
	|| $device eq "AIRROUTER"
	|| $device eq "WDR3600" )
{

# if alix or net4521 or mr3201a, remove the vlan configuration from etc/config/network
	system(
"mv output/etc/config/network output/etc/config/network.orig ; tail -n +`grep -n 'loopback' output/etc/config/network.orig | cut -d: -f 1` output/etc/config/network.orig > output/etc/config/network ; rm output/etc/config/network.orig"
	);
}
if ( $device eq "WNDR3800" ) {

	# if wndr3800, append vlan/led config taken from default r34240
	open( NETWORKOUT, ">>output/etc/config/network" );
	open( SYSTEMOUT,  ">>output/etc/config/system" );
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
if ( $device eq "WZR600DHP" ) {

	# if wzr600dhp, append vlan/led config taken from default r35052
	open( NETWORKOUT, ">>output/etc/config/network" );
	open( SYSTEMOUT,  ">>output/etc/config/system" );
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

if ( $device eq "WDR3600" ) {
	open( NETWORKOUT,  ">>output/etc/config/network" );
	open( WIRELESSOUT, ">output/etc/config/wireless" );
	open( SYSTEMOUT,   ">>output/etc/config/system" );

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
        # option disabled 1

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
        # option disabled 1

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

if ( $device eq "AIRROUTER" ) {

	# if airrouter, append vlan config taken from r37493
	open( NETWORKOUT,  ">>output/etc/config/network" );
	open( WIRELESSOUT, ">output/etc/config/wireless" );

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

if ( $device eq "WNDR3800" || $device eq "WZR600DHP" ) {
	open( WIRELESSOUT, ">output/etc/config/wireless" );
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

if ( $device eq "ALIX" ) {

	# delete the etc/config/wireless
	system("rm output/etc/config/wireless");
}
if ( !defined($privifaces) ) {

	# delete the priv network configuration from etc/config/network
	open( NETWORKIN,  "output/etc/config/network" );
	open( NETWORKOUT, ">output/etc/config/network.out" );
	while (<NETWORKIN>) {
    	my $output = 1;
		chomp;

		if ( $_ =~ /priv/ ) {
			$output = 0;
			print "output off\n";
		}
		if ( $_ =~ /pub/ ) {
			$output = 1;
		}

		if ($output) {
			print NETWORKOUT "$_\n";
		}
	}
	system("mv output/etc/config/network.out output/etc/config/network");

	# delete the priv network configuration from etc/config/dhcp
	open( DHCPIN,  "output/etc/config/dhcp" );
	open( DHCPOUT, ">output/etc/config/dhcp.out" );
	while (<DHCPIN>) {
    	my $output = 1;
		chomp;

		if ( $_ =~ /^config dhcp priv/ ) {
			$output = 0;
			print "output off\n";
		}
		if ( $_ =~ /^config dhcp pub/ ) {
			$output = 1;
		}

		if ($output) {
			print DHCPOUT "$_\n";
		}
	}
	system("mv output/etc/config/dhcp.out output/etc/config/dhcp");

	# delete the priv network rules from etc/init.d/firewall_rss
	open( FIREWALLIN,  "output/etc/init.d/firewall_rss" );
	open( FIREWALLOUT, ">output/etc/init.d/firewall_rss.out" );
	while (<FIREWALLIN>) {
		chomp;

		if ( $_ !~ /PRIVNET/ ) {
			print FIREWALLOUT "$_\n";
		}
	}
	system(
		"mv output/etc/init.d/firewall_rss.out output/etc/init.d/firewall_rss");
	chmod( 0755, "output/etc/init.d/firewall_rss" );
}

open( LINKS, "find etc usr root www -type l |" );

while (<LINKS>) {
	chomp;

	my $src    = $_;
	my @path   = split( '/', $src );
	my $fname  = pop @path;
	my $outdir = join( '/', "output", @path );
	my $dest   = join( '/', "output", @path, $fname );

	unless ( -d $outdir ) { system("mkdir -p $outdir"); }

	print "cp -a $src $dest\n";

	system("cp -a $src $dest");
}

if ( $filter ne "NONE" ) {
	my $outdir = "output/etc/hotplug.d/iface";

	unless ( -d $outdir ) { system("mkdir -p $outdir"); }

	# create filter script and /etc/rc.d link
	open( FILTER, ">$outdir/60-filter" );

	print FILTER "#!/bin/sh\n\n";

	if ( $filter eq "WAN" || $filter eq "BOTH" ) {
		print FILTER "WANF=/tmp/run/wanfilter.net

[ \"\$INTERFACE\" = \"wan\" ] && {
	[ \"\$ACTION\" = ifup ] && {
		# prevent first-hop WAN destinations from being reached from the public or ptp (vpn) interfaces
		for wannet in \$(ip addr show dev \$DEVICE | grep 'inet ' | awk '{ print \$2 }') ; do 
			echo \$wannet >> \$WANF
			iptables -I FORWARD -i br-pub -d \$wannet -j DROP ; 
			iptables -I FORWARD -i $vpniface -d \$wannet -j DROP ; 
		done
		# not needed for ipv6 because we don't currently provision ipv6 from the upstream network
		# all ipv6 traffic goes via our vpn tunnel, and link-local addresses aren't relevent to 
		# FORWARDing (you don't need to drop link-local traffic at a routing boundary, it's not 
		# forwarded by definition, since it isn't link-local anymore).
	}
	[ \"\$ACTION\" = ifdown ] && {
		if [ -f \$WANF ]; then
			for wannet in \$(cat \$WANF) ; do
				iptables -D FORWARD -i br-pub -d \$wannet -j DROP
				iptables -D FORWARD -i $vpniface -d \$wannet -j DROP
			done
			rm \$WANF
		fi
	}
}\n";
	}

	if ( defined($privifaces) && ( $filter eq "PRIV" || $filter eq "BOTH" ) ) {
		print FILTER "
    
[ \"\$INTERFACE\" = \"priv\" ] && {
	[ \"\$ACTION\" = ifup ] && {
		# prevent PRIV destinations from being reached from the public or ptp (vpn) interfaces
		iptables -I FORWARD -o br-priv -i br-pub -j DROP
		iptables -I FORWARD -o br-priv -i $vpniface -j DROP
	}
	[ \"\$ACTION\" = ifdown ] && {
		iptables -D FORWARD -o br-priv -i br-pub -j DROP
		iptables -D FORWARD -o br-priv -i $vpniface -j DROP
	}
}\n";
	}

	close(FILTER);
}

if ($hwclock) {
	open( INITCLOCK, ">output/etc/init.d/initclock" );

	print INITCLOCK "#!/bin/sh /etc/rc.common
# Copyright (C) 2008 OpenWrt.org

START=11

start() {
	# set clock to hardware clock value
	/sbin/hwclock -s -u
}\n";

	close(INITCLOCK);
	chmod 0755, "output/etc/init.d/initclock";

	open( CRONTAB, ">>output/etc/crontabs/root" );
	print CRONTAB "0 0 * * *	/sbin/hwclock -w -u\n";
	close(CRONTAB);
}

if ($wimax) {
	open( CRONTAB, ">>output/etc/crontabs/root" );
	print CRONTAB "*/5 * * * *     /usr/bin/motorola.sh > /dev/null 2>&1\n";
	close(CRONTAB);

	system("cp -a wimax/* output/");
}

# fetch_image.sh script

my $imagename = "";
if ( $device eq "ALIX" ) {
	$imagename = "x86/openwrt-x86-alix2-combined-squashfs.img";
} elsif ( $device eq "NET4521" || $device eq "NET4826" ) {
	$imagename = "x86/openwrt-x86-generic-combined-squashfs.img";
} elsif ( $device eq "MR3201A" ) {
	$imagename = "atheros/openwrt-atheros-combined.squashfs.img";
} elsif ( $device eq "WNDR3800" ) {
	$imagename = "ar71xx/openwrt-ar71xx-generic-wndr3800-squashfs-sysupgrade.bin";
} elsif ( $device eq "WZR600DHP" ) {
	$imagename =
	  "ar71xx/openwrt-ar71xx-generic-wzr-600dhp-squashfs-sysupgrade.bin";
} elsif ( $device eq "WDR3600" ) {
	$imagename =
	  "ar71xx/openwrt-ar71xx-generic-tl-wdr3600-v1-squashfs-sysupgrade.bin";
} elsif ( $device eq "WGT" ) {
	$imagename = "brcm47xx/openwrt-brcm47xx-squashfs.trx";
} elsif ( $device eq "AIRROUTER" ) {
	$imagename =
	  "ar71xx/openwrt-ar71xx-generic-ubnt-airrouter-squashfs-sysupgrade.bin";
}

open( FIS, ">output/usr/bin/fetch_image.sh" );
print FIS <<EOF;
#!/bin/sh
cd /tmp
scp russell\@iris.personaltelco.net:src/openwrt/bin/$imagename /tmp/
EOF
system("chmod 755 output/usr/bin/fetch_image.sh");

open( WWW, "find www -type f | grep -v nodes |" );

while (<WWW>) {
	chomp;
	my $src    = $_;
	my @path   = split( '/', $src );
	my $fname  = pop @path;
	my $outdir = join( '/', "output", @path );
	my $dest   = join( '/', "output", @path, $fname );

	# print "source = $src ; outdir = $outdir ; dest = $dest\n";

	my (
		$dev,  $ino,   $mode,  $nlink, $uid,     $gid, $rdev,
		$size, $atime, $mtime, $ctime, $blksize, $blocks
	) = stat($src);

	unless ( -d $outdir ) { system("mkdir -p $outdir"); }

	print "sed -f foocab.sed < $src > $dest\n";

	system("sed -f foocab.sed < $src > $dest");

	chmod( $mode, $dest );
	chown( $uid, $gid, $dest );
}

sub getNodeInfo {
	my $node     = shift;
	my $nodeinfo = {};
	my $url      = $APIBASE . $node;
	print $url, "\n" if $DEBUG;
	my $json = get($url);
	print Dumper($json) if $DEBUG;
	if ( defined($json) ) {

		$nodeinfo = decode_json($json);
		my $ret = $nodeinfo->{'data'};
		print Dumper($ret) if $DEBUG;
		return $ret;
	}

}

sub getLogo {
	my $logo = shift;
	my $url  = $IMGBASE . $logo;
	print $url, "\n" if $DEBUG;
	my $img = get($url);
	if ( defined($img) ) {
		open( IMGOUT, "> output/www/images/" . $logo )
		  or die "couldn't write out downloaded image $logo: " . $!;
		print IMGOUT $img;
		close IMGOUT;
	}
}

