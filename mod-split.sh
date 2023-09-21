#!/bin/bash

CoreFilelist=$1
BaseFilelist=$2
ExtrasFilelist=$3
ModuleDependency=$4

remove_nonexistent()
{
	for i in `cat $2 | grep ".ko" | sed 's#/lib/modules/%{KernelVer}/kernel/##g' | sed 's#\.xz##g'`;
	do
		grep -q "$i" $1
		if [ $? -eq 1 ];
		then
			echo "Warning: Can not find $i, remove it from filelist"
			sed -i "/${i//\//\\/}/d" $2
		fi
	done
}

find_misses()
{
	for i in `cat $1`;
	do
		grep -q "$i" $CoreFilelist
		if [ $? -eq 0 ];
		then
			continue;
		fi
		grep -q "$i" $BaseFilelist
		if [ $? -eq 0 ];
		then
			continue;
		fi
		grep -q "$i" $ExtrasFilelist
		if [ $? -eq 1 ];
		then
			echo "Warning: $i doesn't exist in filelists, add it to kernel-modules-extras"
			echo "/lib/modules/%{KernelVer}/kernel/$i.xz" >> $ExtrasFilelist
		fi
	done
}

find_depends()
{
	for i in `cat $CoreFilelist | grep ".ko" | sed 's#/lib/modules/%{KernelVer}/kernel/##g' | sed 's#\.xz##g'`;
	do
		dep_modules=`grep "$i:" $ModuleDependency | awk '{$1="";print $0}'`
		if [ -n "$dep_modules" ];
		then
			for mod in $dep_modules;
			do
				grep -q $mod $CoreFilelist
				if [ $? -eq 1 ];
				then
					echo "Warning: $i depends on $mod, add $mod to kernel-core"
					echo "/lib/modules/%{KernelVer}/$mod.xz" >> $CoreFilelist
					sed -i "/${mod//\//\\/}/d" $BaseFilelist
					sed -i "/${mod//\//\\/}/d" $ExtrasFilelist
				fi
			done
		fi
	done

	sort $CoreFilelist | uniq > tmp
	mv -f tmp $CoreFilelist

	for i in `cat $BaseFilelist | sed 's#/lib/modules/%{KernelVer}/kernel/##g' | sed 's#\.xz##g'`;
	do
		dep_modules=`grep "$i:" $ModuleDependency | awk '{$1="";print $0}'`
		if [ -n "$dep_modules" ];
		then
			for mod in $dep_modules;
			do
				grep -q $mod $ExtrasFilelist
				if [ $? -eq 0 ];
				then
					echo "Warning: $i depends on $mod, add $mod to kernel-modules"
					echo "/lib/modules/%{KernelVer}/$mod.xz" >> $BaseFilelist
					sed -i "/${mod//\//\\/}/d" $ExtrasFilelist
				fi
			done
		fi
	done

	sort $ExtrasFilelist | uniq > tmp
	mv -f tmp $ExtrasFilelist
}

find -type f -name "*.ko" | sed 's#\./##g' > modlist

remove_nonexistent modlist $CoreFilelist
remove_nonexistent modlist $BaseFilelist
remove_nonexistent modlist $ExtrasFilelist

find_misses modlist

find_depends

rm -rf modlist
