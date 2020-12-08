#!/bin/bash

make
sudo insmod minifw.ko
echo "Is module loaded? "`lsmod | grep minifw`
