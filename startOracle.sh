#!/bin/bash

count=`ps -ef | grep ssbcOracle | grep -v "grep" | wc -l`
if [ $count -gt 0 ]; then
  echo "ssbcOracle service is running...."
  exit
else
  echo "start ssbcOracle service"
fi

nohup ./ssbcOracle n0 > oracle_n0.log 2>&1 &
nohup ./ssbcOracle n1 > oracle_n1.log 2>&1 &
nohup ./ssbcOracle n2 > oracle_n2.log 2>&1 &
