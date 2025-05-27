#!/bin/bash

####################
# Check Permission #
####################
if [ "$EUID" -ne 0 ]; then
        echo "[!] root privilege required"
        exit 1
fi

########################################################################
# Check Type-1 : find processes capturing 3 protocols (icmp, tcp, udp) #
# => ss -apn | grep -E ":1 |:6 |:17 "                                  #
########################################################################
matched_lines=$(ss -apn | grep -E ":1 |:6 |:17 ")
if echo $"$matched_lines" | grep -q 'pid='; then
	pids=$(echo "$matched_lines" | grep -oP 'pid=\K[0-9]+')
else
	pids=$(echo "$matched_lines" | grep -oP 'users:\(\(".*?",\K[0-9]+')
fi
common_pid=$(echo "$pids" | sort | uniq -c | awk '$1 == 3 {print $2}')
if [ -n "$common_pid" ]; then
	final_pids+=' '$common_pid
fi

###################################################################
# Check Type-2 : find processes with 'ip:*' as Local Address:Port #
# => ss -apn | grep "ip:\*" | grep "UNCONN"                       #
###################################################################
matched_lines=$(ss -apn | grep "ip:\*" | grep "UNCONN")
if echo $"$matched_lines" | grep -q 'pid='; then
	pids=$(echo "$matched_lines" | grep -oP 'pid=\K[0-9]+')
else
	pids=$(echo "$matched_lines" | grep -oP 'users:\(\(".*?",\K[0-9]+')
fi
if [ -n "$pids" ]; then
	final_pids+=' '$pids
fi

####################################################################
# Check Type-3 : find processes using bpf filter with magic values #
# => ss -0pb | grep -EB1 $((0x5293)) | grep -EB1 $((0x7255)        #
####################################################################
matched_lines=$(ss -0pb | grep -EB1 $((0x5293)) | grep -EB1 $((0x7255)))
if echo $"$matched_lines" | grep -q 'pid='; then
	pids=$(echo "$matched_lines" | grep -oP 'pid=\K[0-9]+')
else
	pids=$(echo "$matched_lines" | grep -oP 'users:\(\(".*?",\K[0-9]+')
fi
if [ -n "$pids" ]; then
	final_pids+=' '$pids
fi

##############################################
# Show suspicious processes with their names #
##############################################
output=$(echo $final_pids | tr ' ' '\n' | sort -u | tr '\n' ' ')
if [ -n "$output" ]; then
	for pid in $output; do
		cmdline=$(tr '\0' ' ' < /proc/$pid/cmdline | sed 's/[[:space:]]*$//')
		echo "[!] PID $pid  $cmdline (suspicious)"
	done
fi
