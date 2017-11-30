#!/bin/bash

# Parse cmd line args.
while getopts ":k:m:t:" opt; do
  case $opt in
    k)
      k=$OPTARG
      ;;
    m)
      m=$OPTARG
      ;;
    t)
      t=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

if [ -z $k ]
  then
    echo 'key file not specified'
    exit 1
fi
if [ -z $m ]
  then
    echo 'message file not specified'
    exit 1
fi
if [ -z $t ]
  then
    echo 'tag file not specified'
    exit 1
fi

python3.6 src/cbcmac.py t $k $m $t