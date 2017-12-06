#!/bin/bash

# Parse cmd line args.
while getopts ":d:p:r:vk:" opt; do
  case $opt in
    d)
      d=$OPTARG
      ;;
    p)
      p=$OPTARG
      ;;
    r)
      r=$OPTARG
      ;;
    v)
      v=$OPTARG
      ;;
    k)
      k=$OPTARG
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

if [ -z $d ]
  then
    echo 'directory not specified'
    exit 1
fi
if [ -z $p ]
  then
    echo 'action public key not specified'
    exit 1
fi
if [ -z $r ]
  then
    echo 'action private key not specifed'
    exit 1
fi
if [ -z $v ] && [ -z $k ]
  then
    echo 'validating public key not specified'
    exit 1
fi

python3.6 src/dirlock.py u $d $p $r $k