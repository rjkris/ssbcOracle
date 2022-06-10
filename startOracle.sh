#!/bin/bash

count=`ps -ef | grep ssbcOracle | grep -v "grep" | wc -l`
if [ $count -gt 0 ]; then
  echo "ssbcOracle service is running...."
  exit
fi

if [ ! -d "log" ]; then
  mkdir "log"
fi

nohup ./ssbcOracle n0 > log/oracle_n0.log 2>&1 &
nohup ./ssbcOracle n1 > log/oracle_n1.log 2>&1 &
nohup ./ssbcOracle n2 > log/oracle_n2.log 2>&1 &
nohup ./ssbcOracle n3 > log/oracle_n3.log 2>&1 &

echo "start ssbcOracle service"