find /sys/kernel/debug/ieee80211/phy*/netdev\:wlan*/stations/ -type d | awk -F/ '$9 != "" { print $6,$7,$9,$0 }' | while read radio iface mac fname ; do 
	echo $radio $(echo $iface | sed 's/^netdev://') $mac $(cd $fname ; cat last_signal rx_bytes tx_bytes) "$(grep $mac /tmp/dhcp.leases)" $(cat $fname/last_signal) ;
done  
