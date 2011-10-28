#!/bin/sh

INTERFACE=$1

# PTPnet IPv6
ip -6 addr add PTP_VPN6ADDRESS_PTP/64 dev $INTERFACE

exit 0

