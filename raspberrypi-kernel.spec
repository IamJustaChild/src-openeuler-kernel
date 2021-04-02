%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global KernelVer %{version}-%{release}.raspi.%{_target_cpu}

%global hulkrelease 4.18.0

%global debug_package %{nil}

Name:	 raspberrypi-kernel
Version: 5.10.0
Release: %{hulkrelease}.9
Summary: Linux Kernel
License: GPLv2
URL:	 http://www.kernel.org/
Source0: kernel.tar.gz

BuildRequires: module-init-tools, patch >= 2.5.4, bash >= 2.03, tar
BuildRequires: bzip2, xz, findutils, gzip, m4, perl, make >= 3.78, diffutils, gawk
BuildRequires: gcc >= 3.4.2, binutils >= 2.12
BuildRequires: hostname, net-tools, bc
BuildRequires: xmlto, asciidoc
BuildRequires: openssl-devel
BuildRequires: hmaccalc
BuildRequires: ncurses-devel
BuildRequires: elfutils-libelf-devel
BuildRequires: rpm >= 4.14.2
BuildRequires: elfutils-devel zlib-devel binutils-devel newt-devel perl(ExtUtils::Embed) bison
BuildRequires: audit-libs-devel
BuildRequires: pciutils-devel gettext
BuildRequires: rpm-build, elfutils
BuildRequires: numactl-devel python3-devel glibc-static python3-docutils
BuildRequires: perl-generators perl(Carp) libunwind-devel gtk2-devel libbabeltrace-devel java-1.8.0-openjdk
AutoReq: no
AutoProv: yes

Provides: raspberrypi-kernel-aarch64 = %{version}-%{release}

ExclusiveArch: aarch64
ExclusiveOS: Linux

%description
The Linux Kernel image for RaspberryPi.

%prep
%setup -q -n kernel-%{version} -c
mv kernel linux-%{version}
cp -rl linux-%{version} linux-%{KernelVer}

cd linux-%{KernelVer}

find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null
find . -name .gitignore -exec rm -f {} \; >/dev/null

%build
cd linux-%{KernelVer}

perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}.raspi.%{_target_cpu}/" Makefile

make ARCH=%{Arch} %{?_smp_mflags} bcm2711_defconfig

make ARCH=%{Arch} %{?_smp_mflags} KERNELRELEASE=%{KernelVer}

%install
cd linux-%{KernelVer}

## install linux

make ARCH=%{Arch} INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=%{KernelVer}
rm -rf $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/source $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build

mkdir -p $RPM_BUILD_ROOT/boot
TargetImage=$(make -s image_name)
TargetImage=${TargetImage%.*}
install -m 755 $TargetImage $RPM_BUILD_ROOT/boot/vmlinuz-%{KernelVer}
install -m 644 .config $RPM_BUILD_ROOT/boot/config-%{KernelVer}
install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-%{KernelVer}

mkdir -p $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/overlays
install -m 644 $(find arch/%{Arch}/boot/dts/broadcom/ -name "*.dtb") $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/
install -m 644 $(find arch/%{Arch}/boot/dts/overlays/ -name "*.dtbo") $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/overlays/
if ls arch/%{Arch}/boot/dts/overlays/*.dtb > /dev/null 2>&1; then
    install -m 644 $(find arch/%{Arch}/boot/dts/overlays/ -name "*.dtb") $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/overlays/
fi
install -m 644 arch/%{Arch}/boot/dts/overlays/README $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/overlays/

%postun
version_old=0
if [ "$1" == "0" ]; then
    version_old=old
else
    version_tmp=0
    name_len=`echo -n %{name}-|wc -c`
    for item in `rpm -qa %{name} 2>/dev/null`
    do
        cur_version=${item:name_len}
        cpu_version=${cur_version##*.}
        if [ "$cpu_version" == "%{_target_cpu}" ]; then
            cur_version=${cur_version%.*}
            cur_version=$cur_version.raspi.$cpu_version
            if [[ "$cur_version" != "%{KernelVer}" && "$cur_version" > "$version_tmp" ]]; then
                version_tmp=$cur_version
            fi
        fi
    done
    if [[ "$version_tmp" < "%{KernelVer}" ]]; then
        version_old=$version_tmp
    fi
fi
if [ "$version_old" != "0" ]; then
    if [ -f /boot/vmlinuz-$version_old ] && [ -d /boot/dtb-$version_old ] && ( [ "$version_old" == "old" ] || [ -d /lib/modules/$version_old ] ); then
        ls /boot/dtb-$version_old/overlays/*.dtbo > /dev/null 2>&1
        if [ "$?" == "0" ]; then
            ls /boot/dtb-$version_old/*.dtb > /dev/null 2>&1
            if [ "$?" == "0" ]; then
                rm -rf /boot/*.dtb /boot/overlays /boot/kernel8.img
                mkdir /boot/overlays
                install -m 755 /boot/vmlinuz-$version_old /boot/kernel8.img
                for file in `ls /boot/dtb-$version_old/*.dtb 2>/dev/null`
                do
                    if [ -f $file ]; then
                        install -m 644 $file /boot/`basename $file`
                    fi
                done
                install -m 644 $(find /boot/dtb-$version_old/overlays/ -name "*.dtbo") /boot/overlays/
                if ls /boot/dtb-$version_old/overlays/*.dtb > /dev/null 2>&1; then
                    install -m 644 $(find /boot/dtb-$version_old/overlays/ -name "*.dtb") /boot/overlays/
                fi
                install -m 644 /boot/dtb-$version_old/overlays/README /boot/overlays/
            else
                echo "warning: files in /boot/dtb-$version_old/*.dtb missing when resetting kernel as $version_old, something may go wrong when starting this device next time."
            fi
        else
            echo "warning: files in /boot/dtb-$version_old/overlays missing when resetting kernel as $version_old, something may go wrong when starting this device next time."
        fi
    else
        echo "warning: files missing when resetting kernel as $version_old, something may go wrong when starting this device next time."
    fi
fi

%posttrans
if [ "$1" == "1" ]; then
    if [ ! -f /boot/vmlinuz-old ] && [ -f /boot/kernel8.img ]; then
        mkdir /boot/dtb-old
        mv /boot/*.dtb /boot/dtb-old
        mv /boot/overlays /boot/dtb-old/
        mv /boot/kernel8.img /boot/vmlinuz-old
    fi
fi
rm -rf /boot/*.dtb /boot/overlays /boot/kernel8.img
mkdir -p /boot/overlays
install -m 755 /boot/vmlinuz-%{KernelVer} /boot/kernel8.img
for file in `ls /boot/dtb-%{KernelVer}/*.dtb 2>/dev/null`
do
    if [ -f $file ]; then
        install -m 644 $file /boot/`basename $file`
    fi
done
install -m 644 $(find /boot/dtb-%{KernelVer}/overlays/ -name "*.dtbo") /boot/overlays/
if ls /boot/dtb-%{KernelVer}/overlays/*.dtb > /dev/null 2>&1; then
    install -m 644 $(find /boot/dtb-%{KernelVer}/overlays/ -name "*.dtb") /boot/overlays/
fi
install -m 644 /boot/dtb-%{KernelVer}/overlays/README /boot/overlays/


%files
%defattr (-, root, root)
%doc
/boot/config-*
/boot/System.map-*
/boot/vmlinuz-*
/boot/dtb-*
/lib/modules/%{KernelVer}

%changelog
* Fri Mar 27 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-4.18.0.9
- arm64: mm: fixes reserve_crashkernel twice by mistake

* Wed Mar 24 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-4.17.0.8
- scsi: megaraid_sas: Replace undefined MFI_BIG_ENDIAN macro with __BIG_ENDIAN_BITFIELD macro
- scsi: megaraid_sas: Set no_write_same only for Virtual Disk

* Sat Mar 20 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-4.16.0.7
- Revert "scsi: megaraid_sas: Set no_write_same only for Virtual Disk"  for openEuler issue I3BC45
- Revert "scsi: megaraid_sas: Replace undefined MFI_BIG_ENDIAN macro with __BIG_ENDIAN_BITFIELD macro" for openEuler issue I3BC45

* Fri Mar 19 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-4.15.0.6
- RDMA/hns: Optimize the base address table config for MTR
- fbdev: keep the original function for non-RPi
- Speed up console framebuffer imageblit function

* Fri Mar 19 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-4.14.0.5
- Revert "Speed up console framebuffer imageblit function"
- arm64/mpam: fix a memleak in add_schema
- fs: fix files.usage bug when move tasks
- files_cgroup: fix error pointer when kvm_vm_worker_thread
- fs/filescontrol: add a switch to enable / disable accounting of open fds
- cgroup/files: use task_get_css() to get a valid css during dup_fd()
- cgroups: Resource controller for open files
- openeuler_defconfig: enable CONFIG_CGROUP_FILES by default
- ima: fix a memory leak in ima_del_digest_data_entry
- x86: config: disable CONFIG_BOOTPARAM_HOTPLUG_CPU0 by default
- scsi: iscsi: Verify lengths on passthrough PDUs
- scsi: iscsi: Ensure sysfs attributes are limited to PAGE_SIZE
- scsi: iscsi: Restrict sessions and handles to admin capabilities
- of: unittest: Fix build on architectures without CONFIG_OF_ADDRESS
- mm: Remove examples from enum zone_type comment
- arm64: mm: Set ZONE_DMA size based on early IORT scan
- arm64: mm: Set ZONE_DMA size based on devicetree's dma-ranges
- of: unittest: Add test for of_dma_get_max_cpu_address()
- of/address: Introduce of_dma_get_max_cpu_address()
- arm64: mm: Move zone_dma_bits initialization into zone_sizes_init()
- arm64: mm: Move reserve_crashkernel() into mem_init()
- mm: improve physical page collecting method of pin memory

* Fri Mar 12 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-4.12.0.4
- arm64: Uninstall cpu park after cpu up
- sysrq: avoid concurrently info printing by 'sysrq-trigger'
- cacheinfo: workaround cacheinfo's info_list uninitialized error

* Fri Mar 12 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-4.11.0.3
- park: Reserve park mem before kexec reserved
- pmem: Enable legacy pmem on openEuler
- arm64: Add memmap parameter and register pmem
- etmem: Modify the memig feature name to etmem
- arm: keep the original function for non-RPi

* Tue Mar 9  2021 Yafen Fang<yafen@iscas.ac.cn> - 5.10.0-4.9.0.2
- arm64: ipi_nmi: fix compile error when CONFIG_KGDB is disabled
- kbuild: fix compile error in Makefile.lib
- kbuild: keep the original function for non-RPi
- arm64: keep the original function for non-RPi
- usb: keep the original function for non-RPi
- mm: keep the original function for non-RPi
- video&logo: keep the original function for non-RPi
- serial: keep the original function for non-RPi
- some drivers: keep the original function for non-RPi
- net: keep the original function for non-RPi
- gpio:keep the original function for non-RPi
- arm64: add Raspberry Pi specific config: CONFIG_OPENEULER_RASPBERRYPI for openEuler

* Thu Mar 4  2021 Yafen Fang<yafen@iscas.ac.cn> - 5.10.0-4.7.0.1
- package init based on openEuler 5.10.0-4.7.0
