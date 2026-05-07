#!/bin/bash

# Parse command line options
while getopts "i:h" opt; do
  case ${opt} in
    i )
      KEY_PATH=$OPTARG
      ;;
    h )
      echo "Usage: $0 -i path/of/key"
      exit 0
      ;;
    \? )
      echo "Usage: $0 -i path/of/key"
      exit 1
      ;;
  esac
done

# Check key path variable
if [ -z "$KEY_PATH" ]; then
  echo "Error: Key path required."
  echo "Usage: $0 -i path/of/key"
  exit 1
fi

echo "Changing working directory"

echo "Compressing rusicata directory"
tar --exclude='rusicata/env' --exclude='rusicata/.env' --exclude='rusicata/__pycache__' --exclude='rusicata/.git' -czf rusicata.tar.gz rusicata

echo "Transferring tarball via SCP"
scp -i "$KEY_PATH" rusicata.tar.gz root@vm:/opt

echo "Transferring setup via SCP"
scp -i "$KEY_PATH" setup.sh root@vm:/opt/setup.sh

echo "Transferring destroy_rusicata via SCP"
scp -i "$KEY_PATH" destroy_rusicata.sh root@vm:/opt/destroy_rusicata.sh

echo "Script execution completed"
