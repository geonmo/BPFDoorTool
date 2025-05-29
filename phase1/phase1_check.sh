#!/bin/bash

ss -0pb | grep -EB1 --colour "$((0x7255))|$((0x5293))|$((0x39393939))"
DIRS="/dev /var /bin /usr /opt /local /share"
netstat -lpn | grep -E ':42[3-9][0-9]{2}|43[0-3][0-9]{2}'
for path in $DIRS; do
	echo $path
	find $path ! \( -type d \( -path '/var/lib/cvmfs' -o -path '/var/lib/condor/execute' -o -path '/share/geonmo2' -o -path '/share/kong91' -o -path '/var/lib/rpm' -o -path '/var/log' \) -prune \) -type f -exec sh -c 'hexdump -ve "1/1 \"%.2x\"" "$1" | grep -q "c6459049c6459135c645922ac6459341c6459459c6459562" && echo "$1"' _ {} \;
done
