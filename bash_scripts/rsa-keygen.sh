#!/bin/bash

# Parse cmd line args.
while getopts ":p:r:s:n:" opt; do
  case $opt in
    p)
      p=$OPTARG
      ;;
    s)
      s=$OPTARG
      ;;
    r)
      r=$OPTARG
      ;;
    n)
      n=$OPTARG
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

if [ -z $p ]
  then
    echo 'public key file not specified'
    exit 1
fi
if [ -z $n ]
  then
    echo 'number of bits not specified'
    exit 1
fi
if [ -z $r ]
  then
    echo 'Private key file not specifed'
    exit 1
fi

if [ -z $s ]
  then
    python3.6 src/rsaSign.py k $p $r $n
    exit 0
fi

python3.6 src/rsaSign.py k $p $r $s $n