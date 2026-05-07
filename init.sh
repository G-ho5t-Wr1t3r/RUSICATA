#!/bin/bash

DEBUG=false

while getopts "i:hD" opt; do
  case ${opt} in
    i )
      KEY_PATH=$OPTARG
      ;;
    D )
      DEBUG=true
      ;;
    h )
      echo "Usage: $0 -i path/of/key [-D]"
      echo "Options:"
      echo "  -i    Path to SSH key (required)"
      echo "  -D    Enable Debug mode (transfers destroy_rusicata.sh & hot_reload.sh)"
      echo "  -h    Show this help message"
      exit 0
      ;;
    \? )
      echo "Usage: $0 -i path/of/key [-D]"
      exit 1
      ;;
  esac
done

if [ -z "$KEY_PATH" ]; then
  echo "Error: Key path required."
  echo "Usage: $0 -i path/of/key [-D]"
  exit 1
fi

echo "Changing working directory"

echo "Compressing rusicata directory"
tar --exclude='rusicata/env' --exclude='rusicata/.env' --exclude='rusicata/__pycache__' --exclude='rusicata/.git' -czf rusicata.tar.gz rusicata

echo "Transferring tarball via SCP"
scp -i "$KEY_PATH" rusicata.tar.gz root@vm:/opt

echo "Transferring setup via SCP"
scp -i "$KEY_PATH" setup.sh root@vm:/opt/setup.sh

if [ "$DEBUG" = true ]; then
  echo "[DEBUG MODE] Transferring destroy_rusicata via SCP"
  scp -i "$KEY_PATH" destroy_rusicata.sh root@vm:/opt/destroy_rusicata.sh

  echo "[DEBUG MODE] Transferring hot_reload via SCP"
  scp -i "$KEY_PATH" hot_reload.sh root@vm:/opt/hot_reload.sh
else
  echo "Skipping debug scripts (run with -D to transfer destroy_rusicata and hot_reload)"
fi

echo "Script execution completed"