#!/bin/bash

read -p "input speed(0-255) and ENTER: " SPEED
[[ -z $SPEED ]] && SPEED=170
echo $SPEED | sudo tee /sys/class/hwmon/hwmon1/pwm1
