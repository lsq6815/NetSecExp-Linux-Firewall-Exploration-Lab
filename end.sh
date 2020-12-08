#!/bin/bash

sudo rmmod minifw.ko
dmesg | tail -10
make clean
