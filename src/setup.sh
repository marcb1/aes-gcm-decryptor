#!/bin/bash
if [  $# -le 1 ] 
then 
	echo "./setup.sh plain_text_file password"
	exit 1
fi 
./encrypt_main -e $1 $2 password_file
./encrypt_main -d /tmp/test $2 password_file
diff /tmp/test $1
rm /tmp/test
