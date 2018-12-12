#!/bin/bash
echo "*** $@ will start & kill -STOP"
$@ &
PID=$!
kill -STOP $PID
echo "*** $@ have been suspended"
echo "*** press Enter to contine"
read temp
kill -CONT $PID

