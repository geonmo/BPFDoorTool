#!/bin/bash

####################
# Check Permission #
####################
if [ "$EUID" -ne 0 ]; then
	echo "[!] root privilege required"
	exit 1
fi

###############
# Print Usage #
###############
pid=$1
if [ -z "$pid" ]; then
	echo "[*] Usage: $0 <PID>"
	exit 1
fi

if [ ! -r "/proc/$pid/maps" ]; then
	echo "[!] Not Found: $pid"
	exit 1
fi

#########################################
# Read maps data to locate binary paths #
#########################################
readarray -t maps_paths < <(awk '{ if ($6 ~ /^\//) print $6 }' /proc/$pid/maps | sort -u)

###################################################
# Find patterns in each binary                    #
# => patterns : 55720000, 93530000 (magic values) #
###################################################
for path in "${maps_paths[@]}"; do
	if [ ! -r "$path" ]; then
		echo "[-] $path (deleted / suspicious)"
	else
		hexdata=$(hexdump -ve '1/1 "%02x"' "$path")

		pattern1="55720000"
		pattern2="93520000"

		count_a=$(echo "$hexdata" | grep -o "$pattern1" | wc -l)
		count_b=$(echo "$hexdata" | grep -o "$pattern2" | wc -l)

		if [ "$count_a" -eq 2 ] && [ "$count_b" -eq 1 ]; then
			echo "[!] $path (suspicious)"
		fi
	fi
done

