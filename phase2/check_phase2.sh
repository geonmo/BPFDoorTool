#!/bin/bash
echo "Check abrtd"
CHECKABRTD=$(ps -ef | grep "abrtd"| egrep -v "grep")
COUNT=$(echo -n $CHECKABRTD | wc -l)
echo ${CHECKABRTD}
echo "Checked End!"

echo $COUNT
if [ $COUNT -ne 0 ]; then
	echo "Something Wrong"
	for LINE in ${CHECKABRTD}; 
	do
		echo $LINE
	done
fi
