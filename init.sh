#!/bin/bash

#cd /home/giovanni/Desktop/PARROT/CCIT/RUSICATA
cd /home/g_host/Desktop/Rusicata
tar --exclude='rusicata/env' --exclude='rusicata/.env' --exclude='rusicata/__pycache__' --exclude='rusicata/.git' -czf rusicata.tar.gz rusicata
#scp -i /home/giovanni/Downloads/game_28_04 rusicata.tar.gz root@vm:/opt
#scp -i /home/giovanni/Downloads/game_28_04 setup.sh root@vm:/opt/setup.sh
scp -i /home/g_host/Desktop/sim_ssh rusicata.tar.gz root@vm:/opt
scp -i /home/g_host/Desktop/sim_ssh setup.sh root@vm:/opt/setup.sh
