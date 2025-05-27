  가. 배경 및 목적  
    ○ 최근 국내기업 주요시스템 커널 영역에서 실행되며 공격자의 신호 대기 후 원격 명령을 수행하는 악성코드가 확인되었으며 감염시 매우 심각한 해킹 피해를 발생시킬 수 있음  
    ○ 리눅스 악성코드(BPFDoor) 보안위협 관련 기관에서 운영중인 정보시스템 현황파악 및 긴급 점검 필요  
    
  나. 점검대상 : 리눅스를 사용하는 전체 시스템(PC, 서버, 워크스테이션 등 포함)  
  
  다. 점검방법 : 배포된 악성코드 점검도구, 가이드[붙임1]을 활용하여 자체 점검 실시  
    ※ 각 차수(1차~4차)별로 점검방법이 상이하며 모든 점검 실시 필요  
    
  라. 제출방법 : 5/28(수) 16:00까지 [붙임2]를 작성하여 협조문으로 제출  
    ○ 해당 정보시스템을 운영하지 않는 부서에서는 "해당사항 없음"으로 제출  
    ○ 기존 발송문서(정보보호팀-329(시행일자:2025.05.20)를 본 문서로 대체하여 작성  
    
  마. 관련문의 : 정보보호팀 송태욱(☏0798)


 ------------------------ 점검 방법 -------------------------------------
## 아래 phase 1-4 를 단계별로 실행

# phase1
1) ss -0pb | grep -EB1 --colour "$((0x7255))|$((0x5293))|$((0x39393939))"
2) find . -type f -exec sh -c 'hexdump -ve "1/1 \"%.2x\"" "$1" | grep -q "c6459049c6459135c645922ac6459341c6459459c6459562" && echo "$1"' _ {} \;
3) netstat -lpn | grep -E ':42[3-9][0-9]{2}|43[0-3][0-9]{2}'

![image](https://github.com/user-attachments/assets/4bb476e4-f21f-4def-823a-6e4f361fd7d3)
![image](https://github.com/user-attachments/assets/a10d167c-1c62-4e91-b8c0-1b42cb8319ac)

# phase2
1) ps -ef | grep "abrtd"
2) "1)" 탐지내역이 있는 경우  
   ls -l /proc/{의심프로세스PID}/exe
   
![image](https://github.com/user-attachments/assets/4f6cd3af-92a8-404a-80af-d8da8fcce998)

![image](https://github.com/user-attachments/assets/48c48bf3-3aa3-471e-a4be-25b1bc9d0176)

# phase3 
1-check-network.sh  
<img src="https://github.com/user-attachments/assets/9bcc7e24-cb30-47a7-9500-0524a77b8a7d" style="width:600px;">  

2-check-files-with-pid.sh  
<img src="https://github.com/user-attachments/assets/7a161c80-84db-45ad-9e8f-ccd8ea2eaa42" style="width:600px;">

# phase4
bpfdoor_bpf.sh  
bpfdoor_env.sh  
bpfdoor.yar
