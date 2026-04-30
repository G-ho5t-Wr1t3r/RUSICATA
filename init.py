#!/bin/bash

cd /home/giovanni/Desktop/PARROT/CCIT/RUSICATA
tar --exclude='rusicata/env' --exclude='rusicata/.env' --exclude='rusicata/__pycache__' --exclude='rusicata/.git' -czf rusicata.tar.gz rusicata
scp -i /home/giovanni/Downloads/game_28_04 rusicata.tar.gz root@vm:/opt
scp -i /home/giovanni/Downloads/game_28_04 setup.sh root@vm:/opt/setup.sh
