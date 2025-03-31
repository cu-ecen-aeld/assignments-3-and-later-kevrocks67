#!/bin/bash

filesdir=$1
searchstr=$2

if [ "$#" -ne 2 ];then
    >&2 echo "Usage: finder.sh filesdir searchstr"
    exit 1
fi

if ! [ -d $filesdir ];then
    >&2 echo "filesdir must be a directory"
    exit 1
fi

num_files=$(ls -l $filesdir | tail -n +2 | wc -l)
num_matches=0

for i in $(grep -hsc "$searchstr" $filesdir/*);do num_matches=$((num_matches+$i));done

echo "The number of files are $num_files and the number of matching lines are $num_matches"
