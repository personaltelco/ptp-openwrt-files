#!/bin/sh

ip n | awk '{ print $3,$5,$0 }' | sort
