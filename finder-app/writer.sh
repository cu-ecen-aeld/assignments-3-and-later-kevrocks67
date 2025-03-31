#!/bin/bash

writefile=$1
writestr=$2

if [ "$#" -ne 2 ];then
    >&2 echo "Usage: writer.sh writefile writestr"
    exit 1
fi

echo -e "$writestr" > $writefile

ret=$?
if [ $ret -ne 0 ];then
    >&2 echo "Couldnt write to file"
    exit 1
fi
