#!/bin/bash

# Parse cmd line args.
while getopts ":k:m:s:" opt; do
  case $opt in
    k)
      k=$OPTARG
      ;;
    m)
      m=$OPTARG
      ;;
    s)
      s=$OPTARG
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
    echo 'input file not specified'
    exit 1
fi
if [ -z $s ]
  then
    echo 'output file not specified'
    exit 1
fi

python3.6 src/rsaSign.py s $k $m $s