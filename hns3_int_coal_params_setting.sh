#!/bin/bash

# setting optimizing interrupt coalesce parameters for hns3 nic

for hns3_devname_path in /sys/bus/pci/drivers/hns3/*/net/*
do
	if [ -d "$hns3_devname_path" ]
	then
		hns3_devname=${hns3_devname_path##*/}
		echo "setting $hns3_devname interrupt coalesce parameters"
		ethtool -C $hns3_devname adaptive-rx off adaptive-tx off
		ethtool -C $hns3_devname rx-usecs 15 tx-usecs 15
	fi
done
