#!/bin/bash
DIRS="/dev /var /bin /usr /opt /local"
for path in $DIRS; 
do
	echo $path
	./BPFDoor_File_Scan.sh $path
done
