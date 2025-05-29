#!/bin/bash
echo "PID, lock 파일 검색"
ls -l /var/run/*.pid | awk '$5 == 0 {print $9}'
ls -l /var/run/*.lock | awk '$5 == 0 {print $9}'
stat -c "%a %s %n" /var/run/*.pid /var/run/*.lock 2>/dev/null | awk '$1=="644" && $2==0 { print $3 }'

echo "sysconfig 설정 확인"
grep -Er '\[\s*-f\s+/[^]]+\]\s*&&\s*/' /etc/sysconfig/
echo $?

echo "BPF 필터의 매직 넘머 확인"
ss -0pb | grep -E "21139|29269|960051513|36204|40783"
echo $?

echo "SOCKET RAW 및 DGRAM 점검"
#lsof 2>/dev/null | grep -E "IP type=SOCK_RAW|IP type=SOCK_DGRAM" | awk '{print $2}' | sort -u | xargs -r ps -fp
##  고부하
#awk '$4=="0800" && $5=="0" {print $9}' /proc/net/packet | while read inode; do sudo grep -r "ino:\s*$inode" /proc/*/fdinfo/ 2>/dev/null | awk -F/ '{print $3}' | sort -u | xargs -r sudo ps -fp; done


echo "BPF 환경변수 점검"
./bpfdoor_env.sh

echo "포트 확인 및 패킷 점검"
sudo netstat -tulpn 2>/dev/null | awk '{match($0, /:([0-9]+)/, a); if ((a[1] >= 42391 && a[1] <= 43390) || $0 ~ /:8000([^0-9]|$)/) print $0}'
sudo netstat -tulpn 2>/dev/null | awk '$1=="tcp"&&($6=="LISTEN"||$6=="ESTABLISHED"){lp=substr($4,index($4,":")+1);rp=substr($5,index($5,":")+1);if((lp>=42391&&lp<=43390)||lp==8000||(rp>=42391&&rp<=43390)||rp==8000)print}'

echo "의심 프로세스 점검"
sudo ps -ef | grep -E '/usr/sbin/abrtd|/sbin/udevd|cmathreshd|/sbin/sgaSolAgent|/usr/sbin/atd|pickup'| egrep -v "grep -E"

echo "BPF 점검 스크립트 실행"
./bpfdoor_bpf.sh
