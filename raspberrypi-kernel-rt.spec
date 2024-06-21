%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global KernelVer %{version}-%{release}.raspi.%{_target_cpu}

%global hulkrelease 209.0.0

%global debug_package %{nil}

Name:	 raspberrypi-kernel-rt
Version: 5.10.0
Release: %{hulkrelease}.rt62.12
Summary: Linux Kernel
License: GPLv2
URL:	 http://www.kernel.org/
Source0: kernel.tar.gz
Patch0000: 0000-raspberrypi-kernel.patch
Patch0001: 0001-apply-preempt-RT-patch.patch
Patch0002: 0002-modify-bcm2711_defconfig-for-rt-rpi-kernel.patch
Patch0003: 0003-rpi4-extern.patch

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

Provides: raspberrypi-kernel-rt-aarch64 = %{version}-%{release}

ExclusiveArch: aarch64
ExclusiveOS: Linux

%description
The Linux Kernel preempt-rt image for RaspberryPi.

%package devel
Summary: Development package for building kernel modules to match the %{KernelVer} raspberrypi-kernel
AutoReqProv: no
Provides: raspberrypi-kernel-rt-devel-uname-r = %{KernelVer}
Provides: raspberrypi-kernel-rt-devel-%{_target_cpu} = %{version}-%{release}
Requires: perl findutils

%description devel
This package provides raspberrypi kernel headers and makefiles sufficient to build modules
against the %{KernelVer} raspberrypi-kernel-rt package.

%prep
%setup -q -n kernel-%{version} -c
mv kernel linux-%{version}
cp -a linux-%{version} linux-%{KernelVer}

cd linux-%{KernelVer}
%patch0000 -p1
%patch0001 -p1
%patch0002 -p1
%patch0003 -p1

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

mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build

############ to do collect devel file  #########
# 1. Makefile And Kconfig, .config sysmbol
# 2. scrpits dir
# 3. .h file
find -type f \( -name "Makefile*" -o -name "Kconfig*" \) -exec cp --parents {} $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build \;
for f in Module.symvers System.map Module.markers .config;do
    test -f $f || continue
    cp $f $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build
done

cp -a scripts $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build
if [ -d arch/%{Arch}/scripts ]; then
    cp -a arch/%{Arch}/scripts $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/arch/%{_arch} || :
fi
if [ -f arch/%{Arch}/*lds ]; then
    cp -a arch/%{Arch}/*lds $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/arch/%{_arch}/ || :
fi
find $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/scripts/ -name "*.o" -exec rm -rf {} \;

if [ -d arch/%{Arch}/include ]; then
    cp -a --parents arch/%{Arch}/include $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
fi
cp -a include $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include

if [ -f arch/%{Arch}/kernel/module.lds ]; then
    cp -a --parents arch/%{Arch}/kernel/module.lds $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
fi

# module.lds is moved to scripts by commit 596b0474d3d9 in linux 5.10.
if [ -f scripts/module.lds ]; then
    cp -a --parents scripts/module.lds $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
fi

%ifarch aarch64
    cp -a --parents arch/arm/include/asm $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
%endif

# copy objtool for raspberrypi-kernel-devel (needed for building external modules)
if grep -q CONFIG_STACK_VALIDATION=y .config; then
    mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/tools/objtool
    cp -a tools/objtool/objtool $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/tools/objtool
fi

# Make sure the Makefile and version.h have a matching timestamp so that
# external modules can be built
touch -r $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/Makefile $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include/generated/uapi/linux/version.h
touch -r $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/.config $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include/generated/autoconf.h
# for make prepare
if [ ! -f $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include/config/auto.conf ];then
    cp .config $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/include/config/auto.conf
fi

mkdir -p %{buildroot}/usr/src/kernels
mv $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build $RPM_BUILD_ROOT/usr/src/kernels/%{KernelVer}

find $RPM_BUILD_ROOT/usr/src/kernels/%{KernelVer} -name ".*.cmd" -exec rm -f {} \;

pushd $RPM_BUILD_ROOT/lib/modules/%{KernelVer}
ln -sf /usr/src/kernels/%{KernelVer} build
ln -sf build source
popd


%postun
version_old=0
if [ "$1" == "0" ]; then
    echo "warning: something may go wrong when starting this device next time after uninstalling raspberrypi-kernel-rt."
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
    if [ -f /boot/vmlinuz-$version_old ] && [ -d /boot/dtb-$version_old ] && [ -d /lib/modules/$version_old ]; then
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
                echo "warning: files in /boot/dtb-$version_old/*.dtb missing when resetting raspberrypi-kernel-rt as $version_old, something may go wrong when starting this device next time."
            fi
        else
            echo "warning: files in /boot/dtb-$version_old/overlays missing when resetting raspberrypi-kernel-rt as $version_old, something may go wrong when starting this device next time."
        fi
    else
        echo "warning: files missing when resetting raspberrypi-kernel-rt as $version_old, something may go wrong when starting this device next time."
    fi
fi

%posttrans
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

%post devel
if [ -f /etc/sysconfig/kernel ]
then
    . /etc/sysconfig/kernel || exit $?
fi
if [ "$HARDLINK" != "no" -a -x /usr/sbin/hardlink ]
then
    (cd /usr/src/kernels/%{KernelVer} &&
     /usr/bin/find . -type f | while read f; do
       hardlink -c /usr/src/kernels/*.oe*.*/$f $f
     done)
fi


%files
%defattr (-, root, root)
%doc
/boot/config-*
/boot/System.map-*
/boot/vmlinuz-*
/boot/dtb-*
/lib/modules/%{KernelVer}

%files devel
%defattr (-, root, root)
%doc
/lib/modules/%{KernelVer}/source
/lib/modules/%{KernelVer}/build
/usr/src/kernels/%{KernelVer}

%changelog
* Fri Jun 21 2024 zhangyu <zhangyu4@kylinos.cn> - 5.10.0-209.0.0.12
- - update preempt-RT to openEuler 5.10.0-209.0.0

* Tue Jun 18 2024 zhangyu <zhangyu4@kylinos.cn> - 5.10.0-208.0.0.11
- - update preempt-RT to openEuler 5.10.0-208.0.0

* Mon Dec 30 2023 zhangyu <zhangyu4@kylinos.cn> - 5.10.0-161.0.0.10
- - update preempt-RT to openEuler 5.10.0-161.0.0

* Mon Nov 20 2022 zhangyu <zhangyu4@kylinos.cn> - 5.10.0-126.0.0.9
- - update preempt-RT to openEuler 5.10.0-126.0.0

* Mon Jun 27 2022 zhangyuanhang <zhangyuanhang@kylinos.cn> - 5.10.0-99.0.0.8
- - update preempt-RT to openEuler 5.10.0-99.0.0

* Tue Jun 21 2022 zhangyuanhang <zhangyuanhang@kylinos.cn> - 5.10.0-98.0.0.7
- - update preempt-RT to openEuler 5.10.0-98.0.0

* Mon Jun 6 2022 zhangyuanhang <zhangyuanhang@kylinos.cn> - 5.10.0-95.0.0.6
- - add preempt-RT to openEuler 5.10.0-95.0.0

* Fri Mar 11 2022 Yafen Fang <yafen@iscas.ac.cn> - 5.10.0-52.0.0.5
- update warning info when uninstall or update raspberrypi-kernel

* Fri Mar 11 2022 Yafen Fang <yafen@iscas.ac.cn> - 5.10.0-52.0.0.4
- update kernel version to openEuler 5.10.0-52.0.0
- update Raspberry Pi patch, last commit (b0272c695e99a8dcc3a01298db56361333f1fdcf): net: phy: lan87xx: Decrease phy polling rate

* Mon Oct 25 2021 Yafen Fang <yafen@iscas.ac.cn> - 5.10.0-15.0.0.3
- update kernel version to openEuler 5.10.0-15.0.0

* Wed Oct 20 2021 Yafen Fang <yafen@iscas.ac.cn> - 5.10.0-14.0.0.2
- update Raspberry Pi patch, last commit (03ab8875d1fc756bd6d2fd8fdb211532eff33062): gpio: bcm-virt: Fix the get() method

* Tue Oct 19 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-14.0.0.1
- Revert "time: Handle negative seconds correctly in timespec64_to_ns()"
- Revert "posix-cpu-timers: Force next expiration recalc after itimer reset"
- Revert "block: nbd: add sanity check for first_minor"
- Revert "Bluetooth: Move shutdown callback before flushing tx and rx queue"
- clk: kirkwood: Fix a clocking boot regression
- backlight: pwm_bl: Improve bootloader/kernel device handover
- fbmem: don't allow too huge resolutions
- IMA: remove the dependency on CRYPTO_MD5
- IMA: remove -Wmissing-prototypes warning
- fuse: flush extending writes
- fuse: truncate pagecache on atomic_o_trunc
- ARM: dts: at91: add pinctrl-{names, 0} for all gpios
- KVM: nVMX: Unconditionally clear nested.pi_pending on nested VM-Enter
- KVM: VMX: avoid running vmx_handle_exit_irqoff in case of emulation
- KVM: x86: Update vCPU's hv_clock before back to guest when tsc_offset is adjusted
- KVM: s390: index kvm->arch.idle_mask by vcpu_idx
- Revert "KVM: x86: mmu: Add guest physical address check in translate_gpa()"
- x86/resctrl: Fix a maybe-uninitialized build warning treated as error
- perf/x86/amd/ibs: Extend PERF_PMU_CAP_NO_EXCLUDE to IBS Op
- tty: Fix data race between tiocsti() and flush_to_ldisc()
- bio: fix page leak bio_add_hw_page failure
- io_uring: IORING_OP_WRITE needs hash_reg_file set
- time: Handle negative seconds correctly in timespec64_to_ns()
- f2fs: guarantee to write dirty data when enabling checkpoint back
- iwlwifi Add support for ax201 in Samsung Galaxy Book Flex2 Alpha
- ASoC: rt5682: Remove unused variable in rt5682_i2c_remove()
- ipv4: fix endianness issue in inet_rtm_getroute_build_skb()
- octeontx2-af: Set proper errorcode for IPv4 checksum errors
- octeontx2-af: Fix static code analyzer reported issues
- octeontx2-af: Fix loop in free and unmap counter
- net: qualcomm: fix QCA7000 checksum handling
- net: sched: Fix qdisc_rate_table refcount leak when get tcf_block failed
- ipv4: make exception cache less predictible
- ipv6: make exception cache less predictible
- brcmfmac: pcie: fix oops on failure to resume and reprobe
- bcma: Fix memory leak for internally-handled cores
- atlantic: Fix driver resume flow.
- ath6kl: wmi: fix an error code in ath6kl_wmi_sync_point()
- ice: Only lock to update netdev dev_addr
- iwlwifi: skip first element in the WTAS ACPI table
- iwlwifi: follow the new inclusive terminology
- ASoC: wcd9335: Disable irq on slave ports in the remove function
- ASoC: wcd9335: Fix a memory leak in the error handling path of the probe function
- ASoC: wcd9335: Fix a double irq free in the remove function
- tty: serial: fsl_lpuart: fix the wrong mapbase value
- usb: bdc: Fix a resource leak in the error handling path of 'bdc_probe()'
- usb: bdc: Fix an error handling path in 'bdc_probe()' when no suitable DMA config is available
- usb: ehci-orion: Handle errors of clk_prepare_enable() in probe
- i2c: xlp9xx: fix main IRQ check
- i2c: mt65xx: fix IRQ check
- CIFS: Fix a potencially linear read overflow
- bpf: Fix possible out of bound write in narrow load handling
- mmc: moxart: Fix issue with uninitialized dma_slave_config
- mmc: dw_mmc: Fix issue with uninitialized dma_slave_config
- mmc: sdhci: Fix issue with uninitialized dma_slave_config
- ASoC: Intel: Skylake: Fix module resource and format selection
- ASoC: Intel: Skylake: Leave data as is when invoking TLV IPCs
- ASoC: Intel: kbl_da7219_max98927: Fix format selection for max98373
- rsi: fix an error code in rsi_probe()
- rsi: fix error code in rsi_load_9116_firmware()
- gfs2: init system threads before freeze lock
- i2c: hix5hd2: fix IRQ check
- i2c: fix platform_get_irq.cocci warnings
- i2c: s3c2410: fix IRQ check
- i2c: iop3xx: fix deferred probing
- Bluetooth: add timeout sanity check to hci_inquiry
- lkdtm: replace SCSI_DISPATCH_CMD with SCSI_QUEUE_RQ
- mm/swap: consider max pages in iomap_swapfile_add_extent
- usb: gadget: mv_u3d: request_irq() after initializing UDC
- firmware: raspberrypi: Fix a leak in 'rpi_firmware_get()'
- firmware: raspberrypi: Keep count of all consumers
- i2c: synquacer: fix deferred probing
- clk: staging: correct reference to config IOMEM to config HAS_IOMEM
- arm64: dts: marvell: armada-37xx: Extend PCIe MEM space
- nfsd4: Fix forced-expiry locking
- lockd: Fix invalid lockowner cast after vfs_test_lock
- locking/local_lock: Add missing owner initialization
- locking/lockdep: Mark local_lock_t
- mac80211: Fix insufficient headroom issue for AMSDU
- libbpf: Re-build libbpf.so when libbpf.map changes
- usb: phy: tahvo: add IRQ check
- usb: host: ohci-tmio: add IRQ check
- PM: cpu: Make notifier chain use a raw_spinlock_t
- Bluetooth: Move shutdown callback before flushing tx and rx queue
- samples: pktgen: add missing IPv6 option to pktgen scripts
- devlink: Clear whole devlink_flash_notify struct
- selftests/bpf: Fix test_core_autosize on big-endian machines
- usb: gadget: udc: renesas_usb3: Fix soc_device_match() abuse
- usb: phy: twl6030: add IRQ checks
- usb: phy: fsl-usb: add IRQ check
- usb: gadget: udc: s3c2410: add IRQ check
- usb: gadget: udc: at91: add IRQ check
- usb: dwc3: qcom: add IRQ check
- usb: dwc3: meson-g12a: add IRQ check
- ASoC: rt5682: Properly turn off regulators if wrong device ID
- ASoC: rt5682: Implement remove callback
- net/mlx5: Fix unpublish devlink parameters
- net/mlx5: Register to devlink ingress VLAN filter trap
- drm/msm/dsi: Fix some reference counted resource leaks
- Bluetooth: fix repeated calls to sco_sock_kill
- ASoC: Intel: Fix platform ID matching
- cgroup/cpuset: Fix violation of cpuset locking rule
- cgroup/cpuset: Miscellaneous code cleanup
- counter: 104-quad-8: Return error when invalid mode during ceiling_write
- arm64: dts: exynos: correct GIC CPU interfaces address range on Exynos7
- drm/msm/dpu: make dpu_hw_ctl_clear_all_blendstages clear necessary LMs
- drm/msm/mdp4: move HW revision detection to earlier phase
- drm/msm/mdp4: refactor HW revision detection into read_mdp_hw_revision
- selftests/bpf: Fix bpf-iter-tcp4 test to print correctly the dest IP
- PM: EM: Increase energy calculation precision
- Bluetooth: increase BTNAMSIZ to 21 chars to fix potential buffer overflow
- debugfs: Return error during {full/open}_proxy_open() on rmmod
- soc: qcom: smsm: Fix missed interrupts if state changes while masked
- bpf, samples: Add missing mprog-disable to xdp_redirect_cpu's optstring
- PCI: PM: Enable PME if it can be signaled from D3cold
- PCI: PM: Avoid forcing PCI_D0 for wakeup reasons inconsistently
- media: venus: venc: Fix potential null pointer dereference on pointer fmt
- media: em28xx-input: fix refcount bug in em28xx_usb_disconnect
- leds: trigger: audio: Add an activate callback to ensure the initial brightness is set
- leds: lt3593: Put fwnode in any case during ->probe()
- i2c: highlander: add IRQ check
- net/mlx5: Fix missing return value in mlx5_devlink_eswitch_inline_mode_set()
- devlink: Break parameter notification sequence to be before/after unload/load driver
- arm64: dts: renesas: hihope-rzg2-ex: Add EtherAVB internal rx delay
- arm64: dts: renesas: rzg2: Convert EtherAVB to explicit delay handling
- Bluetooth: mgmt: Fix wrong opcode in the response for add_adv cmd
- net: cipso: fix warnings in netlbl_cipsov4_add_std
- drm: mxsfb: Clear FIFO_CLEAR bit
- drm: mxsfb: Increase number of outstanding requests on V4 and newer HW
- drm: mxsfb: Enable recovery on underflow
- cgroup/cpuset: Fix a partition bug with hotplug
- net/mlx5e: Block LRO if firmware asks for tunneled LRO
- net/mlx5e: Prohibit inner indir TIRs in IPoIB
- ARM: dts: meson8b: ec100: Fix the pwm regulator supply properties
- ARM: dts: meson8b: mxq: Fix the pwm regulator supply properties
- ARM: dts: meson8b: odroidc1: Fix the pwm regulator supply properties
- ARM: dts: meson8: Use a higher default GPU clock frequency
- tcp: seq_file: Avoid skipping sk during tcp_seek_last_pos
- drm/amdgpu/acp: Make PM domain really work
- 6lowpan: iphc: Fix an off-by-one check of array index
- Bluetooth: sco: prevent information leak in sco_conn_defer_accept()
- media: atomisp: fix the uninitialized use and rename "retvalue"
- media: coda: fix frame_mem_ctrl for YUV420 and YVU420 formats
- media: rockchip/rga: fix error handling in probe
- media: rockchip/rga: use pm_runtime_resume_and_get()
- media: go7007: remove redundant initialization
- media: go7007: fix memory leak in go7007_usb_probe
- media: dvb-usb: Fix error handling in dvb_usb_i2c_init
- media: dvb-usb: fix uninit-value in vp702x_read_mac_addr
- media: dvb-usb: fix uninit-value in dvb_usb_adapter_dvb_init
- ionic: cleanly release devlink instance
- driver core: Fix error return code in really_probe()
- firmware: fix theoretical UAF race with firmware cache and resume
- gfs2: Fix memory leak of object lsi on error return path
- libbpf: Fix removal of inner map in bpf_object__create_map
- soc: qcom: rpmhpd: Use corner in power_off
- i40e: improve locking of mac_filter_hash
- arm64: dts: renesas: r8a77995: draak: Remove bogus adv7511w properties
- ARM: dts: aspeed-g6: Fix HVI3C function-group in pinctrl dtsi
- libbpf: Fix the possible memory leak on error
- gve: fix the wrong AdminQ buffer overflow check
- drm/of: free the iterator object on failure
- bpf: Fix potential memleak and UAF in the verifier.
- bpf: Fix a typo of reuseport map in bpf.h.
- drm/of: free the right object
- media: cxd2880-spi: Fix an error handling path
- soc: rockchip: ROCKCHIP_GRF should not default to y, unconditionally
- leds: is31fl32xx: Fix missing error code in is31fl32xx_parse_dt()
- media: TDA1997x: enable EDID support
- ASoC: mediatek: mt8183: Fix Unbalanced pm_runtime_enable in mt8183_afe_pcm_dev_probe
- drm/gma500: Fix end of loop tests for list_for_each_entry
- drm/panfrost: Fix missing clk_disable_unprepare() on error in panfrost_clk_init()
- EDAC/i10nm: Fix NVDIMM detection
- spi: spi-zynq-qspi: use wait_for_completion_timeout to make zynq_qspi_exec_mem_op not interruptible
- spi: sprd: Fix the wrong WDG_LOAD_VAL
- regulator: vctrl: Avoid lockdep warning in enable/disable ops
- regulator: vctrl: Use locked regulator_get_voltage in probe path
- blk-crypto: fix check for too-large dun_bytes
- spi: davinci: invoke chipselect callback
- x86/mce: Defer processing of early errors
- tpm: ibmvtpm: Avoid error message when process gets signal while waiting
- certs: Trigger creation of RSA module signing key if it's not an RSA key
- crypto: qat - use proper type for vf_mask
- irqchip/gic-v3: Fix priority comparison when non-secure priorities are used
- spi: coldfire-qspi: Use clk_disable_unprepare in the remove function
- block: nbd: add sanity check for first_minor
- clocksource/drivers/sh_cmt: Fix wrong setting if don't request IRQ for clock source channel
- lib/mpi: use kcalloc in mpi_resize
- irqchip/loongson-pch-pic: Improve edge triggered interrupt support
- genirq/timings: Fix error return code in irq_timings_test_irqs()
- spi: spi-pic32: Fix issue with uninitialized dma_slave_config
- spi: spi-fsl-dspi: Fix issue with uninitialized dma_slave_config
- block: return ELEVATOR_DISCARD_MERGE if possible
- m68k: Fix invalid RMW_INSNS on CPUs that lack CAS
- rcu: Fix stall-warning deadlock due to non-release of rcu_node ->lock
- rcu: Add lockdep_assert_irqs_disabled() to rcu_sched_clock_irq() and callees
- rcu: Fix to include first blocked task in stall warning
- sched: Fix UCLAMP_FLAG_IDLE setting
- sched/numa: Fix is_core_idle()
- m68k: emu: Fix invalid free in nfeth_cleanup()
- power: supply: cw2015: use dev_err_probe to allow deferred probe
- s390/ap: fix state machine hang after failure to enable irq
- s390/debug: fix debug area life cycle
- s390/debug: keep debug data on resize
- s390/pci: fix misleading rc in clp_set_pci_fn()
- s390/kasan: fix large PMD pages address alignment check
- udf_get_extendedattr() had no boundary checks.
- fcntl: fix potential deadlock for &fasync_struct.fa_lock
- crypto: qat - do not export adf_iov_putmsg()
- crypto: qat - fix naming for init/shutdown VF to PF notifications
- crypto: qat - fix reuse of completion variable
- crypto: qat - handle both source of interrupt in VF ISR
- crypto: qat - do not ignore errors from enable_vf2pf_comms()
- crypto: omap - Fix inconsistent locking of device lists
- libata: fix ata_host_start()
- s390/zcrypt: fix wrong offset index for APKA master key valid state
- s390/cio: add dev_busid sysfs entry for each subchannel
- power: supply: max17042_battery: fix typo in MAx17042_TOFF
- power: supply: smb347-charger: Add missing pin control activation
- nvmet: pass back cntlid on successful completion
- nvme-rdma: don't update queue count when failing to set io queues
- nvme-tcp: don't update queue count when failing to set io queues
- blk-throtl: optimize IOPS throttle for large IO scenarios
- bcache: add proper error unwinding in bcache_device_init
- isofs: joliet: Fix iocharset=utf8 mount option
- udf: Fix iocharset=utf8 mount option
- udf: Check LVID earlier
- hrtimer: Ensure timerfd notification for HIGHRES=n
- hrtimer: Avoid double reprogramming in __hrtimer_start_range_ns()
- posix-cpu-timers: Force next expiration recalc after itimer reset
- EDAC/mce_amd: Do not load edac_mce_amd module on guests
- rcu/tree: Handle VM stoppage in stall detection
- sched/deadline: Fix missing clock update in migrate_task_rq_dl()
- crypto: omap-sham - clear dma flags only after omap_sham_update_dma_stop()
- power: supply: axp288_fuel_gauge: Report register-address on readb / writeb errors
- sched/deadline: Fix reset_on_fork reporting of DL tasks
- crypto: mxs-dcp - Check for DMA mapping errors
- regulator: tps65910: Silence deferred probe error
- regmap: fix the offset of register error log
- locking/mutex: Fix HANDOFF condition
- PCI: Call Max Payload Size-related fixup quirks early
- x86/reboot: Limit Dell Optiplex 990 quirk to early BIOS versions
- xhci: fix unsafe memory usage in xhci tracing
- xhci: fix even more unsafe memory usage in xhci tracing
- usb: mtu3: fix the wrong HS mult value
- usb: mtu3: use @mult for HS isoc or intr
- usb: mtu3: restore HS function when set SS/SSP
- usb: gadget: tegra-xudc: fix the wrong mult value for HS isoc or intr
- usb: host: xhci-rcar: Don't reload firmware after the completion
- ALSA: usb-audio: Add registration quirk for JBL Quantum 800
- blk-mq: clearing flush request reference in tags->rqs[]
- netfilter: nftables: clone set element expression template
- netfilter: nf_tables: initialize set before expression setup
- blk-mq: fix is_flush_rq
- blk-mq: fix kernel panic during iterating over flush request
- x86/events/amd/iommu: Fix invalid Perf result due to IOMMU PMC power-gating
- Revert "r8169: avoid link-up interrupt issue on RTL8106e if user enables ASPM"
- tty: drop termiox user definitions
- net: linux/skbuff.h: combine SKB_EXTENSIONS + KCOV handling
- serial: 8250: 8250_omap: Fix unused variable warning
- net: kcov: don't select SKB_EXTENSIONS when there is no NET
- net: ll_temac: Remove left-over debug message
- USB: serial: mos7720: improve OOM-handling in read_mos_reg()
- livepatch: Adapt livepatch-sample for stop_machine model
- livepatch: Add klp_{register,unregister}_patch for stop_machine model
- media: stkwebcam: fix memory leak in stk_camera_probe
- fuse: fix illegal access to inode with reused nodeid
- new helper: inode_wrong_type()
- spi: Switch to signed types for *_native_cs SPI controller fields
- ALSA: pcm: fix divide error in snd_pcm_lib_ioctl
- ALSA: hda/realtek: Workaround for conflicting SSID on ASUS ROG Strix G17
- ALSA: hda/realtek: Quirk for HP Spectre x360 14 amp setup
- cryptoloop: add a deprecation warning
- perf/x86/amd/power: Assign pmu.module
- perf/x86/amd/ibs: Work around erratum #1197
- ceph: fix possible null-pointer dereference in ceph_mdsmap_decode()
- perf/x86/intel/pt: Fix mask of num_address_ranges
- qede: Fix memset corruption
- net: macb: Add a NULL check on desc_ptp
- qed: Fix the VF msix vectors flow
- reset: reset-zynqmp: Fixed the argument data type
- gpu: ipu-v3: Fix i.MX IPU-v3 offset calculations for (semi)planar U/V formats
- ARM: OMAP1: ams-delta: remove unused function ams_delta_camera_power
- xtensa: fix kconfig unmet dependency warning for HAVE_FUTEX_CMPXCHG
- static_call: Fix unused variable warn w/o MODULE
- Revert "Add a reference to ucounts for each cred"
- Revert "cred: add missing return error code when set_cred_ucounts() failed"
- Revert "ucounts: Increase ucounts reference counter before the security hook"
- ubifs: report correct st_size for encrypted symlinks
- f2fs: report correct st_size for encrypted symlinks
- ext4: report correct st_size for encrypted symlinks
- fscrypt: add fscrypt_symlink_getattr() for computing st_size
- bpf: Fix potentially incorrect results with bpf_get_local_storage()
- audit: move put_tree() to avoid trim_trees refcount underflow and UAF
- net: don't unconditionally copy_from_user a struct ifreq for socket ioctls
- Revert "parisc: Add assembly implementations for memset, strlen, strcpy, strncpy and strcat"
- Revert "floppy: reintroduce O_NDELAY fix"
- arm64: dts: qcom: msm8994-angler: Fix gpio-reserved-ranges 85-88
- lkdtm: Enable DOUBLE_FAULT on all architectures
- net: dsa: mt7530: fix VLAN traffic leaks again
- usb: typec: ucsi: Clear pending after acking connector change
- usb: typec: ucsi: Work around PPM losing change information
- usb: typec: ucsi: acpi: Always decode connector change information
- tracepoint: Use rcu get state and cond sync for static call updates
- srcu: Provide polling interfaces for Tiny SRCU grace periods
- srcu: Make Tiny SRCU use multi-bit grace-period counter
- srcu: Provide internal interface to start a Tiny SRCU grace period
- srcu: Provide polling interfaces for Tree SRCU grace periods
- srcu: Provide internal interface to start a Tree SRCU grace period
- riscv: Fixup patch_text panic in ftrace
- riscv: Fixup wrong ftrace remove cflag
- Bluetooth: btusb: check conditions before enabling USB ALT 3 for WBS
- tipc: call tipc_wait_for_connect only when dlen is not 0
- mtd: spinand: Fix incorrect parameters for on-die ECC
- pipe: do FASYNC notifications for every pipe IO, not just state changes
- pipe: avoid unnecessary EPOLLET wakeups under normal loads
- btrfs: fix race between marking inode needs to be logged and log syncing
- net/rds: dma_map_sg is entitled to merge entries
- drm/nouveau/kms/nv50: workaround EFI GOP window channel format differences
- drm/nouveau/disp: power down unused DP links during init
- drm: Copy drm_wait_vblank to user before returning
- blk-mq: don't grab rq's refcount in blk_mq_check_expired()
- drm/amd/pm: change the workload type for some cards
- Revert "drm/amd/pm: fix workload mismatch on vega10"
- qed: Fix null-pointer dereference in qed_rdma_create_qp()
- qed: qed ll2 race condition fixes
- tools/virtio: fix build
- vringh: Use wiov->used to check for read/write desc order
- virtio_vdpa: reject invalid vq indices
- virtio_pci: Support surprise removal of virtio pci device
- virtio: Improve vq->broken access to avoid any compiler optimization
- cpufreq: blocklist Qualcomm sm8150 in cpufreq-dt-platdev
- opp: remove WARN when no valid OPPs remain
- iwlwifi: pnvm: accept multiple HW-type TLVs
- clk: renesas: rcar-usb2-clock-sel: Fix kernel NULL pointer dereference
- perf/x86/intel/uncore: Fix integer overflow on 23 bit left shift of a u32
- dt-bindings: sifive-l2-cache: Fix 'select' matching
- usb: gadget: u_audio: fix race condition on endpoint stop
- drm/i915: Fix syncmap memory leak
- net: stmmac: fix kernel panic due to NULL pointer dereference of plat->est
- net: stmmac: add mutex lock to protect est parameters
- Revert "mmc: sdhci-iproc: Set SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN on BCM2711"
- rtnetlink: Return correct error on changing device netns
- cxgb4: dont touch blocked freelist bitmap after free
- ipv4: use siphash instead of Jenkins in fnhe_hashfun()
- ipv6: use siphash in rt6_exception_hash()
- net/sched: ets: fix crash when flipping from 'strict' to 'quantum'
- ucounts: Increase ucounts reference counter before the security hook
- net: marvell: fix MVNETA_TX_IN_PRGRS bit number
- xgene-v2: Fix a resource leak in the error handling path of 'xge_probe()'
- ip_gre: add validation for csum_start
- RDMA/efa: Free IRQ vectors on error flow
- e1000e: Do not take care about recovery NVM checksum
- e1000e: Fix the max snoop/no-snoop latency for 10M
- igc: Use num_tx_queues when iterating over tx_ring queue
- igc: fix page fault when thunderbolt is unplugged
- net: usb: pegasus: fixes of set_register(s) return value evaluation;
- ice: do not abort devlink info if board identifier can't be found
- RDMA/bnxt_re: Remove unpaired rtnl unlock in bnxt_re_dev_init()
- IB/hfi1: Fix possible null-pointer dereference in _extend_sdma_tx_descs()
- RDMA/bnxt_re: Add missing spin lock initialization
- scsi: core: Fix hang of freezing queue between blocking and running device
- usb: dwc3: gadget: Stop EP0 transfers during pullup disable
- usb: dwc3: gadget: Fix dwc3_calc_trbs_left()
- usb: renesas-xhci: Prefer firmware loading on unknown ROM state
- USB: serial: option: add new VID/PID to support Fibocom FG150
- Revert "USB: serial: ch341: fix character loss at high transfer rates"
- drm/amdgpu: Cancel delayed work when GFXOFF is disabled
- Revert "btrfs: compression: don't try to compress if we don't have enough pages"
- riscv: Ensure the value of FP registers in the core dump file is up to date
- ceph: correctly handle releasing an embedded cap flush
- can: usb: esd_usb2: esd_usb2_rx_event(): fix the interchange of the CAN RX and TX error counters
- net: mscc: Fix non-GPL export of regmap APIs
- ovl: fix uninitialized pointer read in ovl_lookup_real_one()
- blk-iocost: fix lockdep warning on blkcg->lock
- netfilter: conntrack: collect all entries in one cycle
- ARC: Fix CONFIG_STACKDEPOT
- ASoC: component: Remove misplaced prefix handling in pin control functions
- ASoC: rt5682: Adjust headset volume button threshold
- bpf: Fix NULL pointer dereference in bpf_get_local_storage() helper
- bpf: Fix ringbuf helper function compatibility
- ARM: spectre-v2: turn off the mitigation via boot cmdline param
- ext4: fix potential uninitialized access to retval in kmmpd
- take LOOKUP_{ROOT,ROOT_GRABBED,JUMPED} out of LOOKUP_... space
- switch file_open_root() to struct path
- kyber: introduce kyber_depth_updated()
- perf annotate: Add itrace options support
- mm: Fix the uninitialized use in overcommit_policy_handler
- memcg: enable accounting for ldt_struct objects
- memcg: enable accounting for posix_timers_cache slab
- memcg: enable accounting for signals
- memcg: enable accounting for new namesapces and struct nsproxy
- memcg: enable accounting for fasync_cache
- memcg: enable accounting for mnt_cache entries
- memcg: charge fs_context and legacy_fs_context
- memcg: enable accounting for pids in nested pid namespaces
- blk-mq: fix divide by zero crash in tg_may_dispatch()
- ext4: prevent getting empty inode buffer
- ext4: move ext4_fill_raw_inode() related functions
- ext4: factor out ext4_fill_raw_inode()
- ext4: make the updating inode data procedure atomic
- ext4: move inode eio simulation behind io completeion
- sched: Aware multi-core system for optimize loadtracking
- livepatch: Fix compile warnning
- md: revert io stats accounting
- sched/idle: Reported an error when an illegal negative value is passed
- sched/idle: Optimize the loop time algorithm to reduce multicore disturb
- serial: 8250: 8250_omap: Fix possible array out of bounds access
- once: Fix panic when module unload
- ext4: wipe ext4_dir_entry2 upon file deletion
- livepatch: move arch_klp_mem_recycle after the return value judgment
- livepatch/x86: only check stack top
- livepatch/ppc64: only check stack top
- livepatch/ppc32: only check stack top
- livepatch/arm: only check stack top
- livepatch/arm64: only check stack top
- livepatch: checks only if the replaced instruction is on the stack
- livepatch: Add state describe for force
- blk-mq: clear active_queues before clearing BLK_MQ_F_TAG_QUEUE_SHARED
- sysctl: Refactor IAS framework
- io_uring: ensure symmetry in handling iter types in loop_rw_iter()
- ext4: fix race writing to an inline_data file while its xattrs are changing
- memcg: enable accounting of ipc resources
- vt_kdsetmode: extend console locking
- net: qrtr: fix another OOB Read in qrtr_endpoint_post
- btrfs: fix NULL pointer dereference when deleting device by invalid id
- acpi: acpica: fix acpi parse and parseext cache leaks
- acpi: acpica: fix acpi operand cache leak in dsutils.c
- sctp: add param size validation for SCTP_PARAM_SET_PRIMARY
- sctp: validate chunk size in __rcv_asconf_lookup
- ARM: footbridge: remove personal server platform
- hfs: fix null-ptr-deref in hfs_find_init()
- io_uring: only assign io_uring_enter() SQPOLL error in actual error case
- io_uring: fix xa_alloc_cycle() error return value check
- fs: warn about impending deprecation of mandatory locks
- mm: memcontrol: fix occasional OOMs due to proportional memory.low reclaim
- ASoC: intel: atom: Fix breakage for PCM buffer address setup
- ALSA: hda/realtek: Limit mic boost on HP ProBook 445 G8
- PCI: Increase D3 delay for AMD Renoir/Cezanne XHCI
- s390/pci: fix use after free of zpci_dev
- ALSA: hda/via: Apply runtime PM workaround for ASUS B23E
- btrfs: prevent rename2 from exchanging a subvol with a directory from different parents
- mmc: sdhci-iproc: Set SDHCI_QUIRK_CAP_CLOCK_BASE_BROKEN on BCM2711
- mmc: sdhci-iproc: Cap min clock frequency on BCM2711
- ALSA: hda/realtek: Enable 4-speaker output for Dell XPS 15 9510 laptop
- ipack: tpci200: fix memory leak in the tpci200_register
- ipack: tpci200: fix many double free issues in tpci200_pci_probe
- slimbus: ngd: reset dma setup during runtime pm
- slimbus: messaging: check for valid transaction id
- slimbus: messaging: start transaction ids from 1 instead of zero
- tracing / histogram: Fix NULL pointer dereference on strcmp() on NULL event name
- ALSA: hda - fix the 'Capture Switch' value change notifications
- clk: qcom: gdsc: Ensure regulator init state matches GDSC state
- clk: imx6q: fix uart earlycon unwork
- mmc: sdhci-msm: Update the software timeout value for sdhc
- mmc: mmci: stm32: Check when the voltage switch procedure should be done
- mmc: dw_mmc: Fix hang on data CRC error
- Revert "flow_offload: action should not be NULL when it is referenced"
- iavf: Fix ping is lost after untrusted VF had tried to change MAC
- i40e: Fix ATR queue selection
- r8152: fix writing USB_BP2_EN
- iommu/vt-d: Fix incomplete cache flush in intel_pasid_tear_down_entry()
- iommu/vt-d: Consolidate duplicate cache invaliation code
- ovs: clear skb->tstamp in forwarding path
- net: mdio-mux: Handle -EPROBE_DEFER correctly
- net: mdio-mux: Don't ignore memory allocation errors
- sch_cake: fix srchost/dsthost hashing mode
- ixgbe, xsk: clean up the resources in ixgbe_xsk_pool_enable error path
- net: qlcnic: add missed unlock in qlcnic_83xx_flash_read32
- virtio-net: use NETIF_F_GRO_HW instead of NETIF_F_LRO
- virtio-net: support XDP when not more queues
- vrf: Reset skb conntrack connection on VRF rcv
- bnxt_en: Add missing DMA memory barriers
- bnxt_en: Disable aRFS if running on 212 firmware
- ptp_pch: Restore dependency on PCI
- net: 6pack: fix slab-out-of-bounds in decode_data
- bnxt: count Tx drops
- bnxt: make sure xmit_more + errors does not miss doorbells
- bnxt: disable napi before canceling DIM
- bnxt: don't lock the tx queue from napi poll
- bpf: Clear zext_dst of dead insns
- drm/mediatek: Add AAL output size configuration
- drm/mediatek: Fix aal size config
- soc / drm: mediatek: Move DDP component defines into mtk-mmsys.h
- vdpa/mlx5: Avoid destroying MR on empty iotlb
- vhost: Fix the calculation in vhost_overflow()
- bus: ti-sysc: Fix error handling for sysc_check_active_timer()
- vhost-vdpa: Fix integer overflow in vhost_vdpa_process_iotlb_update()
- virtio: Protect vqs list access
- dccp: add do-while-0 stubs for dccp_pr_debug macros
- cpufreq: armada-37xx: forbid cpufreq for 1.2 GHz variant
- iommu: Check if group is NULL before remove device
- arm64: dts: qcom: msm8992-bullhead: Remove PSCI
- arm64: dts: qcom: c630: fix correct powerdown pin for WSA881x
- Bluetooth: hidp: use correct wait queue when removing ctrl_wait
- drm/amd/display: workaround for hard hang on HPD on native DP
- drm/amd/display: Fix Dynamic bpp issue with 8K30 with Navi 1X
- net: usb: lan78xx: don't modify phy_device state concurrently
- net: usb: pegasus: Check the return value of get_geristers() and friends;
- ARM: dts: nomadik: Fix up interrupt controller node names
- qede: fix crash in rmmod qede while automatic debug collection
- drm/amdgpu: fix the doorbell missing when in CGPG issue for renoir.
- scsi: core: Fix capacity set to zero after offlinining device
- scsi: core: Avoid printing an error if target_alloc() returns -ENXIO
- scsi: scsi_dh_rdac: Avoid crash during rdac_bus_attach()
- scsi: megaraid_mm: Fix end of loop tests for list_for_each_entry()
- scsi: pm80xx: Fix TMF task completion race condition
- dmaengine: of-dma: router_xlate to return -EPROBE_DEFER if controller is not yet available
- ARM: dts: am43x-epos-evm: Reduce i2c0 bus speed for tps65218
- net: xfrm: Fix end of loop tests for list_for_each_entry
- spi: spi-mux: Add module info needed for autoloading
- dmaengine: usb-dmac: Fix PM reference leak in usb_dmac_probe()
- dmaengine: xilinx_dma: Fix read-after-free bug when terminating transfers
- USB: core: Fix incorrect pipe calculation in do_proc_control()
- USB: core: Avoid WARNings for 0-length descriptor requests
- KVM: X86: Fix warning caused by stale emulation context
- KVM: x86: Factor out x86 instruction emulation with decoding
- media: drivers/media/usb: fix memory leak in zr364xx_probe
- media: zr364xx: fix memory leaks in probe()
- media: zr364xx: propagate errors from zr364xx_start_readpipe()
- mtd: cfi_cmdset_0002: fix crash when erasing/writing AMD cards
- ath9k: Postpone key cache entry deletion for TXQ frames reference it
- ath: Modify ath_key_delete() to not need full key entry
- ath: Export ath_hw_keysetmac()
- ath9k: Clear key cache explicitly on disabling hardware
- ath: Use safer key clearing with key cache entries
- net: dsa: microchip: ksz8795: Use software untagging on CPU port
- net: dsa: microchip: ksz8795: Fix VLAN untagged flag change on deletion
- net: dsa: microchip: ksz8795: Reject unsupported VLAN configuration
- net: dsa: microchip: ksz8795: Fix PVID tag insertion
- net: dsa: microchip: Fix probing KSZ87xx switch with DT node for host port
- KVM: nSVM: always intercept VMLOAD/VMSAVE when nested (CVE-2021-3656)
- KVM: nSVM: avoid picking up unsupported bits from L2 in int_ctl (CVE-2021-3653)
- vmlinux.lds.h: Handle clang's module.{c,d}tor sections
- ceph: take snap_empty_lock atomically with snaprealm refcount change
- ceph: clean up locking annotation for ceph_get_snap_realm and __lookup_snap_realm
- ceph: add some lockdep assertions around snaprealm handling
- vboxsf: Add support for the atomic_open directory-inode op
- vboxsf: Add vboxsf_[create|release]_sf_handle() helpers
- KVM: nVMX: Use vmx_need_pf_intercept() when deciding if L0 wants a #PF
- KVM: VMX: Use current VMCS to query WAITPKG support for MSR emulation
- efi/libstub: arm64: Double check image alignment at entry
- powerpc/smp: Fix OOPS in topology_init()
- PCI/MSI: Protect msi_desc::masked for multi-MSI
- PCI/MSI: Use msi_mask_irq() in pci_msi_shutdown()
- PCI/MSI: Correct misleading comments
- PCI/MSI: Do not set invalid bits in MSI mask
- PCI/MSI: Enforce MSI[X] entry updates to be visible
- PCI/MSI: Enforce that MSI-X table entry is masked for update
- PCI/MSI: Mask all unused MSI-X entries
- PCI/MSI: Enable and mask MSI-X early
- genirq/timings: Prevent potential array overflow in __irq_timings_store()
- genirq/msi: Ensure deactivation on teardown
- x86/resctrl: Fix default monitoring groups reporting
- x86/ioapic: Force affinity setup before startup
- x86/msi: Force affinity setup before startup
- genirq: Provide IRQCHIP_AFFINITY_PRE_STARTUP
- x86/tools: Fix objdump version check again
- efi/libstub: arm64: Relax 2M alignment again for relocatable kernels
- efi/libstub: arm64: Force Image reallocation if BSS was not reserved
- arm64: efi: kaslr: Fix occasional random alloc (and boot) failure
- nbd: Aovid double completion of a request
- vsock/virtio: avoid potential deadlock when vsock device remove
- xen/events: Fix race in set_evtchn_to_irq
- drm/i915: Only access SFC_DONE when media domain is not fused off
- net: igmp: increase size of mr_ifc_count
- tcp_bbr: fix u32 wrap bug in round logic if bbr_init() called after 2B packets
- net: linkwatch: fix failure to restore device state across suspend/resume
- net: bridge: fix memleak in br_add_if()
- net: bridge: fix flags interpretation for extern learn fdb entries
- net: bridge: validate the NUD_PERMANENT bit when adding an extern_learn FDB entry
- net: dsa: sja1105: fix broken backpressure in .port_fdb_dump
- net: dsa: lantiq: fix broken backpressure in .port_fdb_dump
- net: dsa: lan9303: fix broken backpressure in .port_fdb_dump
- net: igmp: fix data-race in igmp_ifc_timer_expire()
- net: Fix memory leak in ieee802154_raw_deliver
- net: dsa: microchip: ksz8795: Fix VLAN filtering
- net: dsa: microchip: Fix ksz_read64()
- drm/meson: fix colour distortion from HDR set during vendor u-boot
- net/mlx5: Fix return value from tracer initialization
- net/mlx5: Synchronize correct IRQ when destroying CQ
- bareudp: Fix invalid read beyond skb's linear data
- psample: Add a fwd declaration for skbuff
- iavf: Set RSS LUT and key in reset handle path
- ice: don't remove netdev->dev_addr from uc sync list
- ice: Prevent probing virtual functions
- net: sched: act_mirred: Reset ct info when mirror/redirect skb
- net/smc: fix wait on already cleared link
- ppp: Fix generating ifname when empty IFLA_IFNAME is specified
- net: phy: micrel: Fix link detection on ksz87xx switch"
- bpf: Fix integer overflow involving bucket_size
- libbpf: Fix probe for BPF_PROG_TYPE_CGROUP_SOCKOPT
- platform/x86: pcengines-apuv2: Add missing terminating entries to gpio-lookup tables
- net: mvvp2: fix short frame size on s390
- net: dsa: mt7530: add the missing RxUnicast MIB counter
- ASoC: cs42l42: Fix LRCLK frame start edge
- pinctrl: tigerlake: Fix GPIO mapping for newer version of software
- netfilter: nf_conntrack_bridge: Fix memory leak when error
- ASoC: cs42l42: Remove duplicate control for WNF filter frequency
- ASoC: cs42l42: Fix inversion of ADC Notch Switch control
- ASoC: SOF: Intel: hda-ipc: fix reply size checking
- ASoC: cs42l42: Don't allow SND_SOC_DAIFMT_LEFT_J
- ASoC: cs42l42: Correct definition of ADC Volume control
- pinctrl: mediatek: Fix fallback behavior for bias_set_combo
- ieee802154: hwsim: fix GPF in hwsim_new_edge_nl
- ieee802154: hwsim: fix GPF in hwsim_set_edge_lqi
- drm/amdgpu: don't enable baco on boco platforms in runpm
- drm/amd/display: use GFP_ATOMIC in amdgpu_dm_irq_schedule_work
- drm/amd/display: Remove invalid assert for ODM + MPC case
- libnvdimm/region: Fix label activation vs errors
- ACPI: NFIT: Fix support for virtual SPA ranges
- ceph: reduce contention in ceph_check_delayed_caps()
- ARC: fp: set FPU_STATUS.FWE to enable FPU_STATUS update on context switch
- net: ethernet: ti: cpsw: fix min eth packet size for non-switch use-cases
- seccomp: Fix setting loaded filter count during TSYNC
- scsi: lpfc: Move initialization of phba->poll_list earlier to avoid crash
- cifs: create sd context must be a multiple of 8
- i2c: dev: zero out array used for i2c reads from userspace
- ASoC: intel: atom: Fix reference to PCM buffer address
- ASoC: tlv320aic31xx: Fix jack detection after suspend
- ASoC: uniphier: Fix reference to PCM buffer address
- ASoC: xilinx: Fix reference to PCM buffer address
- ASoC: amd: Fix reference to PCM buffer address
- iio: adc: Fix incorrect exit of for-loop
- iio: humidity: hdc100x: Add margin to the conversion time
- iio: adis: set GPIO reset pin direction
- iio: adc: ti-ads7950: Ensure CS is deasserted after reading channels
- net: xilinx_emaclite: Do not print real IOMEM pointer
- ovl: prevent private clone if bind mount is not allowed
- ppp: Fix generating ppp unit id when ifname is not specified
- ALSA: hda: Add quirk for ASUS Flow x13
- ALSA: hda/realtek: fix mute/micmute LEDs for HP ProBook 650 G8 Notebook PC
- ALSA: pcm: Fix mmap breakage without explicit buffer setup
- USB:ehci:fix Kunpeng920 ehci hardware problem
- vboxsf: Make vboxsf_dir_create() return the handle for the created file
- vboxsf: Honor excl flag to the dir-inode create op
- arm64: dts: renesas: beacon: Fix USB ref clock references
- arm64: dts: renesas: beacon: Fix USB extal reference
- arm64: dts: renesas: rzg2: Add usb2_clksel to RZ/G2 M/N/H
- mm: make zone_to_nid() and zone_set_nid() available for DISCONTIGMEM
- Revert "selftests/resctrl: Use resctrl/info for feature detection"
- bpf: Add lockdown check for probe_write_user helper
- firmware: tee_bnxt: Release TEE shm, session, and context during kexec
- tee: Correct inappropriate usage of TEE_SHM_DMA_BUF flag
- KVM: SVM: Fix off-by-one indexing when nullifying last used SEV VMCB
- sched: Add menuconfig option for CONFIG_SCHED_OPTIMIZE_LOAD_TRACKING
- sched/rt: Fix double enqueue caused by rt_effective_prio
- Revert "sched/rt: Fix double enqueue caused by rt_effective_prio"
- drm/amdgpu/display: only enable aux backlight control for OLED panels
- smb3: rc uninitialized in one fallocate path
- net/qla3xxx: fix schedule while atomic in ql_wait_for_drvr_lock and ql_adapter_reset
- alpha: Send stop IPI to send to online CPUs
- net: qede: Fix end of loop tests for list_for_each_entry
- virt_wifi: fix error on connect
- reiserfs: check directory items on read from disk
- reiserfs: add check for root_inode in reiserfs_fill_super
- libata: fix ata_pio_sector for CONFIG_HIGHMEM
- drm/i915: avoid uninitialised var in eb_parse()
- sched/rt: Fix double enqueue caused by rt_effective_prio
- perf/x86/amd: Don't touch the AMD64_EVENTSEL_HOSTONLY bit inside the guest
- soc: ixp4xx/qmgr: fix invalid __iomem access
- drm/i915: Correct SFC_DONE register offset
- interconnect: qcom: icc-rpmh: Ensure floor BW is enforced for all nodes
- interconnect: Always call pre_aggregate before aggregate
- interconnect: Zero initial BW after sync-state
- spi: meson-spicc: fix memory leak in meson_spicc_remove
- interconnect: Fix undersized devress_alloc allocation
- soc: ixp4xx: fix printing resources
- arm64: vdso: Avoid ISB after reading from cntvct_el0
- KVM: x86/mmu: Fix per-cpu counter corruption on 32-bit builds
- KVM: Do not leak memory for duplicate debugfs directories
- KVM: x86: accept userspace interrupt only if no event is injected
- md/raid10: properly indicate failure when ending a failed write request
- ARM: omap2+: hwmod: fix potential NULL pointer access
- Revert "gpio: mpc8xxx: change the gpio interrupt flags."
- bus: ti-sysc: AM3: RNG is GP only
- selinux: correct the return value when loads initial sids
- pcmcia: i82092: fix a null pointer dereference bug
- net/xfrm/compat: Copy xfrm_spdattr_type_t atributes
- xfrm: Fix RCU vs hash_resize_mutex lock inversion
- timers: Move clearing of base::timer_running under base:: Lock
- fpga: dfl: fme: Fix cpu hotplug issue in performance reporting
- serial: 8250_pci: Avoid irq sharing for MSI(-X) interrupts.
- serial: 8250_pci: Enumerate Elkhart Lake UARTs via dedicated driver
- MIPS: Malta: Do not byte-swap accesses to the CBUS UART
- serial: 8250: Mask out floating 16/32-bit bus bits
- serial: 8250_mtk: fix uart corruption issue when rx power off
- serial: tegra: Only print FIFO error message when an error occurs
- ext4: fix potential htree corruption when growing large_dir directories
- pipe: increase minimum default pipe size to 2 pages
- media: rtl28xxu: fix zero-length control request
- drivers core: Fix oops when driver probe fails
- staging: rtl8712: error handling refactoring
- staging: rtl8712: get rid of flush_scheduled_work
- staging: rtl8723bs: Fix a resource leak in sd_int_dpc
- tpm_ftpm_tee: Free and unregister TEE shared memory during kexec
- optee: fix tee out of memory failure seen during kexec reboot
- optee: Refuse to load the driver under the kdump kernel
- optee: Fix memory leak when failing to register shm pages
- tee: add tee_shm_alloc_kernel_buf()
- optee: Clear stale cache entries during initialization
- arm64: stacktrace: avoid tracing arch_stack_walk()
- tracepoint: Fix static call function vs data state mismatch
- tracepoint: static call: Compare data on transition from 2->1 callees
- tracing: Fix NULL pointer dereference in start_creating
- tracing: Reject string operand in the histogram expression
- tracing / histogram: Give calculation hist_fields a size
- scripts/tracing: fix the bug that can't parse raw_trace_func
- clk: fix leak on devm_clk_bulk_get_all() unwind
- usb: otg-fsm: Fix hrtimer list corruption
- usb: typec: tcpm: Keep other events when receiving FRS and Sourcing_vbus events
- usb: host: ohci-at91: suspend/resume ports after/before OHCI accesses
- usb: gadget: f_hid: idle uses the highest byte for duration
- usb: gadget: f_hid: fixed NULL pointer dereference
- usb: gadget: f_hid: added GET_IDLE and SET_IDLE handlers
- usb: cdns3: Fixed incorrect gadget state
- usb: gadget: remove leaked entry from udc driver list
- usb: dwc3: gadget: Avoid runtime resume if disabling pullup
- ALSA: usb-audio: Add registration quirk for JBL Quantum 600
- ALSA: usb-audio: Fix superfluous autosuspend recovery
- ALSA: hda/realtek: Fix headset mic for Acer SWIFT SF314-56 (ALC256)
- ALSA: hda/realtek: add mic quirk for Acer SF314-42
- ALSA: pcm - fix mmap capability check for the snd-dummy driver
- drm/amdgpu/display: fix DMUB firmware version info
- firmware_loader: fix use-after-free in firmware_fallback_sysfs
- firmware_loader: use -ETIMEDOUT instead of -EAGAIN in fw_load_sysfs_fallback
- USB: serial: ftdi_sio: add device ID for Auto-M3 OP-COM v2
- USB: serial: ch341: fix character loss at high transfer rates
- USB: serial: option: add Telit FD980 composition 0x1056
- USB: usbtmc: Fix RCU stall warning
- Bluetooth: defer cleanup of resources in hci_unregister_dev()
- blk-iolatency: error out if blk_get_queue() failed in iolatency_set_limit()
- net: vxge: fix use-after-free in vxge_device_unregister
- net: fec: fix use-after-free in fec_drv_remove
- net: pegasus: fix uninit-value in get_interrupt_interval
- bnx2x: fix an error code in bnx2x_nic_load()
- mips: Fix non-POSIX regexp
- MIPS: check return value of pgtable_pmd_page_ctor
- net: sched: fix lockdep_set_class() typo error for sch->seqlock
- net: dsa: qca: ar9331: reorder MDIO write sequence
- net: ipv6: fix returned variable type in ip6_skb_dst_mtu
- nfp: update ethtool reporting of pauseframe control
- sctp: move the active_key update after sh_keys is added
- RDMA/mlx5: Delay emptying a cache entry when a new MR is added to it recently
- gpio: tqmx86: really make IRQ optional
- net: natsemi: Fix missing pci_disable_device() in probe and remove
- net: phy: micrel: Fix detection of ksz87xx switch
- net: dsa: sja1105: match FDB entries regardless of inner/outer VLAN tag
- net: dsa: sja1105: be stateless with FDB entries on SJA1105P/Q/R/S/SJA1110 too
- net: dsa: sja1105: invalidate dynamic FDB entries learned concurrently with statically added ones
- net: dsa: sja1105: overwrite dynamic FDB entries with static ones in .port_fdb_add
- net, gro: Set inner transport header offset in tcp/udp GRO hook
- dmaengine: imx-dma: configure the generic DMA type to make it work
- ARM: dts: stm32: Fix touchscreen IRQ line assignment on DHCOM
- ARM: dts: stm32: Disable LAN8710 EDPD on DHCOM
- media: videobuf2-core: dequeue if start_streaming fails
- scsi: sr: Return correct event when media event code is 3
- spi: imx: mx51-ecspi: Fix low-speed CONFIGREG delay calculation
- spi: imx: mx51-ecspi: Reinstate low-speed CONFIGREG delay
- dmaengine: stm32-dmamux: Fix PM usage counter unbalance in stm32 dmamux ops
- dmaengine: stm32-dma: Fix PM usage counter imbalance in stm32 dma ops
- clk: tegra: Implement disable_unused() of tegra_clk_sdmmc_mux_ops
- dmaengine: uniphier-xdmac: Use readl_poll_timeout_atomic() in atomic state
- omap5-board-common: remove not physically existing vdds_1v8_main fixed-regulator
- ARM: dts: am437x-l4: fix typo in can@0 node
- clk: stm32f4: fix post divisor setup for I2S/SAI PLLs
- ALSA: usb-audio: fix incorrect clock source setting
- arm64: dts: armada-3720-turris-mox: remove mrvl,i2c-fast-mode
- arm64: dts: armada-3720-turris-mox: fixed indices for the SDHC controllers
- ARM: dts: imx: Swap M53Menlo pinctrl_power_button/pinctrl_power_out pins
- ARM: imx: fix missing 3rd argument in macro imx_mmdc_perf_init
- ARM: dts: colibri-imx6ull: limit SDIO clock to 25MHz
- arm64: dts: ls1028: sl28: fix networking for variant 2
- ARM: dts: imx6qdl-sr-som: Increase the PHY reset duration to 10ms
- ARM: imx: add missing clk_disable_unprepare()
- ARM: imx: add missing iounmap()
- arm64: dts: ls1028a: fix node name for the sysclk
- net: xfrm: fix memory leak in xfrm_user_rcv_msg
- bus: ti-sysc: Fix gpt12 system timer issue with reserved status
- ALSA: seq: Fix racy deletion of subscriber
- Revert "ACPICA: Fix memory leak caused by _CID repair function"
- sched/idle: Add IAS_SMART_HALT_POLL config for smart halt polling feature
- sched/idle: introduce smart halt polling
- arm: Optimize ttwu IPI
- kthread: Fix PF_KTHREAD vs to_kthread() race
- mtd: mtdconcat: Check _read,_write callbacks existence before assignment
- mtd: mtdconcat: Judge callback existence based on the master
- lib: use PFN_PHYS() in devmem_is_allowed()
- arm64: fix compat syscall return truncation
- blk: reuse lookup_sem to serialize partition operations
- Revert "[Backport] block: take bd_mutex around delete_partitions in del_gendisk"
- Revert "[Huawei] block: avoid creating invalid symlink file for patitions"
- block: ensure the memory order between bi_private and bi_status
- amba-pl011: Fix no irq issue due to no IRQ domain found
- arm64: seccomp: fix the incorrect name of syscall __NR_compat_exit in secure computing mode
- seqlock: avoid -Wshadow warnings
- asm-generic: fix ffs -Wshadow warning
- spi: mediatek: Fix fifo transfer
- selftest/bpf: Verifier tests for var-off access
- bpf, selftests: Adjust few selftest outcomes wrt unreachable code
- bpf: Update selftests to reflect new error states
- bpf, selftests: Adjust few selftest result_unpriv outcomes
- selftest/bpf: Adjust expected verifier errors
- selftests/bpf: Add a test for ptr_to_map_value on stack for helper access
- Revert "watchdog: iTCO_wdt: Account for rebooting on second timeout"
- firmware: arm_scmi: Add delayed response status check
- firmware: arm_scmi: Ensure drivers provide a probe function
- Revert "Bluetooth: Shutdown controller after workqueues are flushed or cancelled"
- ACPI: fix NULL pointer dereference
- drm/amd/display: Fix max vstartup calculation for modes with borders
- drm/amd/display: Fix comparison error in dcn21 DML
- nvme: fix nvme_setup_command metadata trace event
- efi/mokvar: Reserve the table only if it is in boot services data
- ASoC: ti: j721e-evm: Check for not initialized parent_clk_id
- ASoC: ti: j721e-evm: Fix unbalanced domain activity tracking during startup
- net: Fix zero-copy head len calculation.
- ASoC: rt5682: Fix the issue of garbled recording after powerd_dbus_suspend
- qed: fix possible unpaired spin_{un}lock_bh in _qed_mcp_cmd_and_union()
- r8152: Fix potential PM refcount imbalance
- ASoC: tlv320aic31xx: fix reversed bclk/wclk master bits
- spi: stm32h7: fix full duplex irq handler handling
- regulator: rt5033: Fix n_voltages settings for BUCK and LDO
- regulator: rtmv20: Fix wrong mask for strobe-polarity-high
- btrfs: fix lost inode on log replay after mix of fsync, rename and inode eviction
- btrfs: fix race causing unnecessary inode logging during link and rename
- Revert "drm/i915: Propagate errors on awaiting already signaled fences"
- drm/i915: Revert "drm/i915/gem: Asynchronous cmdparser"
- powerpc/kprobes: Fix kprobe Oops happens in booke
- sched: Fix branch prediction error in static_key
- sched: Access control for sysctl_update_load_latency
- mm,hwpoison: return -EHWPOISON to denote that the page has already been poisoned
- mm/memory-failure: use a mutex to avoid memory_failure() races
- can: j1939: j1939_session_deactivate(): clarify lifetime of session object
- i40e: Add additional info to PHY type error
- Revert "perf map: Fix dso->nsinfo refcounting"
- powerpc/pseries: Fix regression while building external modules
- SMB3: fix readpage for large swap cache
- bpf: Fix pointer arithmetic mask tightening under state pruning
- bpf: verifier: Allocate idmap scratch in verifier env
- bpf: Remove superfluous aux sanitation on subprog rejection
- bpf: Fix leakage due to insufficient speculative store bypass mitigation
- bpf: Introduce BPF nospec instruction for mitigating Spectre v4
- can: hi311x: fix a signedness bug in hi3110_cmd()
- sis900: Fix missing pci_disable_device() in probe and remove
- tulip: windbond-840: Fix missing pci_disable_device() in probe and remove
- sctp: fix return value check in __sctp_rcv_asconf_lookup
- net/mlx5e: Fix nullptr in mlx5e_hairpin_get_mdev()
- net/mlx5: Fix flow table chaining
- skmsg: Make sk_psock_destroy() static
- drm/msm/dp: Initialize the INTF_CONFIG register
- drm/msm/dpu: Fix sm8250_mdp register length
- net: llc: fix skb_over_panic
- KVM: x86: Check the right feature bit for MSR_KVM_ASYNC_PF_ACK access
- mlx4: Fix missing error code in mlx4_load_one()
- octeontx2-pf: Fix interface down flag on error
- tipc: do not write skb_shinfo frags when doing decrytion
- ionic: count csum_none when offload enabled
- ionic: fix up dim accounting for tx and rx
- ionic: remove intr coalesce update from napi
- net: qrtr: fix memory leaks
- net: Set true network header for ECN decapsulation
- tipc: fix sleeping in tipc accept routine
- tipc: fix implicit-connect for SYN+
- i40e: Fix log TC creation failure when max num of queues is exceeded
- i40e: Fix queue-to-TC mapping on Tx
- i40e: Fix firmware LLDP agent related warning
- i40e: Fix logic of disabling queues
- netfilter: nft_nat: allow to specify layer 4 protocol NAT only
- netfilter: conntrack: adjust stop timestamp to real expiry value
- mac80211: fix enabling 4-address mode on a sta vif after assoc
- bpf: Fix OOB read when printing XDP link fdinfo
- RDMA/bnxt_re: Fix stats counters
- cfg80211: Fix possible memory leak in function cfg80211_bss_update
- nfc: nfcsim: fix use after free during module unload
- blk-iocost: fix operation ordering in iocg_wake_fn()
- drm/amdgpu: Fix resource leak on probe error path
- drm/amdgpu: Avoid printing of stack contents on firmware load error
- drm/amd/display: ensure dentist display clock update finished in DCN20
- NIU: fix incorrect error return, missed in previous revert
- HID: wacom: Re-enable touch by default for Cintiq 24HDT / 27QHDT
- alpha: register early reserved memory in memblock
- can: esd_usb2: fix memory leak
- can: ems_usb: fix memory leak
- can: usb_8dev: fix memory leak
- can: mcba_usb_start(): add missing urb->transfer_dma initialization
- can: peak_usb: pcan_usb_handle_bus_evt(): fix reading rxerr/txerr values
- can: raw: raw_setsockopt(): fix raw_rcv panic for sock UAF
- can: j1939: j1939_xtp_rx_dat_one(): fix rxtimer value between consecutive TP.DT to 750ms
- ocfs2: issue zeroout to EOF blocks
- ocfs2: fix zero out valid data
- KVM: add missing compat KVM_CLEAR_DIRTY_LOG
- x86/kvm: fix vcpu-id indexed array sizes
- ACPI: DPTF: Fix reading of attributes
- Revert "ACPI: resources: Add checks for ACPI IRQ override"
- btrfs: mark compressed range uptodate only if all bio succeed
- btrfs: fix rw device counting in __btrfs_free_extra_devids
- pipe: make pipe writes always wake up readers
- x86/asm: Ensure asm/proto.h can be included stand-alone
- io_uring: fix null-ptr-deref in io_sq_offload_start()
- selftest: fix build error in tools/testing/selftests/vm/userfaultfd.c
- ipv6: ip6_finish_output2: set sk into newly allocated nskb
- ARM: dts: versatile: Fix up interrupt controller node names
- iomap: remove the length variable in iomap_seek_hole
- iomap: remove the length variable in iomap_seek_data
- cifs: fix the out of range assignment to bit fields in parse_server_interfaces
- firmware: arm_scmi: Fix range check for the maximum number of pending messages
- firmware: arm_scmi: Fix possible scmi_linux_errmap buffer overflow
- hfs: add lock nesting notation to hfs_find_init
- hfs: fix high memory mapping in hfs_bnode_read
- hfs: add missing clean-up in hfs_fill_super
- drm/ttm: add a check against null pointer dereference
- ipv6: allocate enough headroom in ip6_finish_output2()
- rcu-tasks: Don't delete holdouts within trc_wait_for_one_reader()
- rcu-tasks: Don't delete holdouts within trc_inspect_reader()
- sctp: move 198 addresses from unusable to private scope
- net: annotate data race around sk_ll_usec
- net/802/garp: fix memleak in garp_request_join()
- net/802/mrp: fix memleak in mrp_request_join()
- cgroup1: fix leaked context root causing sporadic NULL deref in LTP
- workqueue: fix UAF in pwq_unbound_release_workfn()
- af_unix: fix garbage collect vs MSG_PEEK
- KVM: x86: determine if an exception has an error code only when injecting it.
- io_uring: fix link timeout refs
- tools: Allow proper CC/CXX/... override with LLVM=1 in Makefile.include
- perf annotate: Add error log in symbol__annotate()
- perf env: Normalize aarch64.* and arm64.* to arm64 in normalize_arch()
- skbuff: Fix build with SKB extensions disabled
- xhci: add xhci_get_virt_ep() helper
- sfc: ensure correct number of XDP queues
- drm/i915/gvt: Clear d3_entered on elsp cmd submission.
- usb: ehci: Prevent missed ehci interrupts with edge-triggered MSI
- perf inject: Close inject.output on exit
- Documentation: Fix intiramfs script name
- skbuff: Release nfct refcount on napi stolen or re-used skbs
- bonding: fix build issue
- PCI: Mark AMD Navi14 GPU ATS as broken
- net: dsa: mv88e6xxx: enable SerDes PCS register dump via ethtool -d on Topaz
- net: dsa: mv88e6xxx: enable SerDes RX stats for Topaz
- drm/amdgpu: update golden setting for sienna_cichlid
- drm: Return -ENOTTY for non-drm ioctls
- driver core: Prevent warning when removing a device link from unregistered consumer
- nds32: fix up stack guard gap
- misc: eeprom: at24: Always append device id even if label property is set.
- rbd: always kick acquire on "acquired" and "released" notifications
- rbd: don't hold lock_rwsem while running_list is being drained
- hugetlbfs: fix mount mode command line processing
- memblock: make for_each_mem_range() traverse MEMBLOCK_HOTPLUG regions
- userfaultfd: do not untag user pointers
- io_uring: remove double poll entry on arm failure
- io_uring: explicitly count entries for poll reqs
- selftest: use mmap instead of posix_memalign to allocate memory
- posix-cpu-timers: Fix rearm racing against process tick
- bus: mhi: core: Validate channel ID when processing command completions
- ixgbe: Fix packet corruption due to missing DMA sync
- media: ngene: Fix out-of-bounds bug in ngene_command_config_free_buf()
- btrfs: check for missing device in btrfs_trim_fs
- tracing: Synthetic event field_pos is an index not a boolean
- tracing: Fix bug in rb_per_cpu_empty() that might cause deadloop.
- tracing/histogram: Rename "cpu" to "common_cpu"
- tracepoints: Update static_call before tp_funcs when adding a tracepoint
- firmware/efi: Tell memblock about EFI iomem reservations
- usb: typec: stusb160x: register role switch before interrupt registration
- usb: dwc2: gadget: Fix sending zero length packet in DDMA mode.
- usb: dwc2: gadget: Fix GOUTNAK flow for Slave mode.
- usb: gadget: Fix Unbalanced pm_runtime_enable in tegra_xudc_probe
- USB: serial: cp210x: add ID for CEL EM3588 USB ZigBee stick
- USB: serial: cp210x: fix comments for GE CS1000
- USB: serial: option: add support for u-blox LARA-R6 family
- usb: renesas_usbhs: Fix superfluous irqs happen after usb_pkt_pop()
- usb: max-3421: Prevent corruption of freed memory
- USB: usb-storage: Add LaCie Rugged USB3-FW to IGNORE_UAS
- usb: hub: Fix link power management max exit latency (MEL) calculations
- usb: hub: Disable USB 3 device initiated lpm if exit latency is too high
- KVM: PPC: Book3S HV Nested: Sanitise H_ENTER_NESTED TM state
- KVM: PPC: Book3S: Fix H_RTAS rets buffer overflow
- xhci: Fix lost USB 2 remote wake
- usb: xhci: avoid renesas_usb_fw.mem when it's unusable
- Revert "usb: renesas-xhci: Fix handling of unknown ROM state"
- ALSA: pcm: Fix mmap capability check
- ALSA: pcm: Call substream ack() method upon compat mmap commit
- ALSA: hdmi: Expose all pins on MSI MS-7C94 board
- ALSA: hda/realtek: Fix pop noise and 2 Front Mic issues on a machine
- ALSA: sb: Fix potential ABBA deadlock in CSP driver
- ALSA: usb-audio: Add registration quirk for JBL Quantum headsets
- ALSA: usb-audio: Add missing proc text entry for BESPOKEN type
- s390/boot: fix use of expolines in the DMA code
- s390/ftrace: fix ftrace_update_ftrace_func implementation
- mmc: core: Don't allocate IDA for OF aliases
- proc: Avoid mixing integer types in mem_rw()
- cifs: fix fallocate when trying to allocate a hole.
- cifs: only write 64kb at a time when fallocating a small region of a file
- drm/panel: raspberrypi-touchscreen: Prevent double-free
- net: sched: cls_api: Fix the the wrong parameter
- net: dsa: sja1105: make VID 4095 a bridge VLAN too
- tcp: disable TFO blackhole logic by default
- sctp: update active_key for asoc when old key is being replaced
- nvme: set the PRACT bit when using Write Zeroes with T10 PI
- r8169: Avoid duplicate sysfs entry creation error
- afs: Fix tracepoint string placement with built-in AFS
- Revert "USB: quirks: ignore remote wake-up on Fibocom L850-GL LTE modem"
- nvme-pci: don't WARN_ON in nvme_reset_work if ctrl.state is not RESETTING
- ceph: don't WARN if we're still opening a session to an MDS
- ipv6: fix another slab-out-of-bounds in fib6_nh_flush_exceptions
- net/sched: act_skbmod: Skip non-Ethernet packets
- spi: spi-bcm2835: Fix deadlock
- ALSA: hda: intel-dsp-cfg: add missing ElkhartLake PCI ID
- net/tcp_fastopen: fix data races around tfo_active_disable_stamp
- net: hisilicon: rename CACHE_LINE_MASK to avoid redefinition
- bnxt_en: Check abort error state in bnxt_half_open_nic()
- bnxt_en: Validate vlan protocol ID on RX packets
- bnxt_en: Add missing check for BNXT_STATE_ABORT_ERR in bnxt_fw_rset_task()
- bnxt_en: Refresh RoCE capabilities in bnxt_ulp_probe()
- bnxt_en: don't disable an already disabled PCI device
- ACPI: Kconfig: Fix table override from built-in initrd
- spi: cadence: Correct initialisation of runtime PM again
- scsi: target: Fix protect handling in WRITE SAME(32)
- scsi: iscsi: Fix iface sysfs attr detection
- netrom: Decrease sock refcount when sock timers expire
- sctp: trim optlen when it's a huge value in sctp_setsockopt
- net: sched: fix memory leak in tcindex_partial_destroy_work
- KVM: PPC: Fix kvm_arch_vcpu_ioctl vcpu_load leak
- KVM: PPC: Book3S: Fix CONFIG_TRANSACTIONAL_MEM=n crash
- net: decnet: Fix sleeping inside in af_decnet
- efi/tpm: Differentiate missing and invalid final event log table.
- dma-mapping: handle vmalloc addresses in dma_common_{mmap,get_sgtable}
- usb: hso: fix error handling code of hso_create_net_device
- net: fix uninit-value in caif_seqpkt_sendmsg
- bpftool: Check malloc return value in mount_bpffs_for_pin
- bpf, sockmap, udp: sk_prot needs inuse_idx set for proc stats
- bpf, sockmap, tcp: sk_prot needs inuse_idx set for proc stats
- bpf, sockmap: Fix potential memory leak on unlikely error case
- s390/bpf: Perform r1 range checking before accessing jit->seen_reg[r1]
- liquidio: Fix unintentional sign extension issue on left shift of u16
- timers: Fix get_next_timer_interrupt() with no timers pending
- xdp, net: Fix use-after-free in bpf_xdp_link_release
- bpf: Fix tail_call_reachable rejection for interpreter when jit failed
- bpf, test: fix NULL pointer dereference on invalid expected_attach_type
- ASoC: rt5631: Fix regcache sync errors on resume
- spi: mediatek: fix fifo rx mode
- regulator: hi6421: Fix getting wrong drvdata
- regulator: hi6421: Use correct variable type for regmap api val argument
- spi: stm32: fixes pm_runtime calls in probe/remove
- spi: imx: add a check for speed_hz before calculating the clock
- ASoC: wm_adsp: Correct wm_coeff_tlv_get handling
- perf sched: Fix record failure when CONFIG_SCHEDSTATS is not set
- perf lzma: Close lzma stream on exit
- perf script: Fix memory 'threads' and 'cpus' leaks on exit
- perf report: Free generated help strings for sort option
- perf env: Fix memory leak of cpu_pmu_caps
- perf test maps__merge_in: Fix memory leak of maps
- perf dso: Fix memory leak in dso__new_map()
- perf test event_update: Fix memory leak of evlist
- perf test session_topology: Delete session->evlist
- perf env: Fix sibling_dies memory leak
- perf probe: Fix dso->nsinfo refcounting
- perf map: Fix dso->nsinfo refcounting
- perf inject: Fix dso->nsinfo refcounting
- KVM: x86/pmu: Clear anythread deprecated bit when 0xa leaf is unsupported on the SVM
- nvme-pci: do not call nvme_dev_remove_admin from nvme_remove
- mptcp: fix warning in __skb_flow_dissect() when do syn cookie for subflow join
- cxgb4: fix IRQ free race during driver unload
- pwm: sprd: Ensure configuring period and duty_cycle isn't wrongly skipped
- selftests: icmp_redirect: IPv6 PMTU info should be cleared after redirect
- selftests: icmp_redirect: remove from checking for IPv6 route get
- stmmac: platform: Fix signedness bug in stmmac_probe_config_dt()
- ipv6: fix 'disable_policy' for fwd packets
- bonding: fix incorrect return value of bond_ipsec_offload_ok()
- bonding: fix suspicious RCU usage in bond_ipsec_offload_ok()
- bonding: Add struct bond_ipesc to manage SA
- bonding: disallow setting nested bonding + ipsec offload
- bonding: fix suspicious RCU usage in bond_ipsec_del_sa()
- ixgbevf: use xso.real_dev instead of xso.dev in callback functions of struct xfrmdev_ops
- bonding: fix null dereference in bond_ipsec_add_sa()
- bonding: fix suspicious RCU usage in bond_ipsec_add_sa()
- net: add kcov handle to skb extensions
- gve: Fix an error handling path in 'gve_probe()'
- igb: Fix position of assignment to *ring
- igb: Check if num of q_vectors is smaller than max before array access
- iavf: Fix an error handling path in 'iavf_probe()'
- e1000e: Fix an error handling path in 'e1000_probe()'
- fm10k: Fix an error handling path in 'fm10k_probe()'
- igb: Fix an error handling path in 'igb_probe()'
- igc: Fix an error handling path in 'igc_probe()'
- ixgbe: Fix an error handling path in 'ixgbe_probe()'
- igc: change default return of igc_read_phy_reg()
- igb: Fix use-after-free error during reset
- igc: Fix use-after-free error during reset
- sched: Add frequency control for load update in scheduler_tick
- sched: Add switch for update_blocked_averages
- sched: Introcude config option SCHED_OPTIMIZE_LOAD_TRACKING
- udp: annotate data races around unix_sk(sk)->gso_size
- drm/panel: nt35510: Do not fail if DSI read fails
- bpf: Track subprog poke descriptors correctly and fix use-after-free
- bpftool: Properly close va_list 'ap' by va_end() on error
- tools: bpf: Fix error in 'make -C tools/ bpf_install'
- tcp: call sk_wmem_schedule before sk_mem_charge in zerocopy path
- ipv6: tcp: drop silly ICMPv6 packet too big messages
- tcp: fix tcp_init_transfer() to not reset icsk_ca_initialized
- tcp: annotate data races around tp->mtu_info
- tcp: consistently disable header prediction for mptcp
- ARM: dts: tacoma: Add phase corrections for eMMC
- ARM: dts: aspeed: Fix AST2600 machines line names
- kbuild: do not suppress Kconfig prompts for silent build
- dma-buf/sync_file: Don't leak fences on merge failure
- net: fddi: fix UAF in fza_probe
- net: dsa: properly check for the bridge_leave methods in dsa_switch_bridge_leave()
- Revert "mm/shmem: fix shmem_swapin() race with swapoff"
- net: validate lwtstate->data before returning from skb_tunnel_info()
- net: send SYNACK packet with accepted fwmark
- net: ti: fix UAF in tlan_remove_one
- net: qcom/emac: fix UAF in emac_remove
- net: moxa: fix UAF in moxart_mac_probe
- net: ip_tunnel: fix mtu calculation for ETHER tunnel devices
- net: bcmgenet: Ensure all TX/RX queues DMAs are disabled
- net: netdevsim: use xso.real_dev instead of xso.dev in callback functions of struct xfrmdev_ops
- net: bridge: sync fdb to new unicast-filtering ports
- net/sched: act_ct: remove and free nf_table callbacks
- vmxnet3: fix cksum offload issues for tunnels with non-default udp ports
- net/sched: act_ct: fix err check for nf_conntrack_confirm
- netfilter: ctnetlink: suspicious RCU usage in ctnetlink_dump_helpinfo
- net: ipv6: fix return value of ip6_skb_dst_mtu
- net: dsa: mv88e6xxx: enable devlink ATU hash param for Topaz
- net: dsa: mv88e6xxx: enable .rmu_disable() on Topaz
- net: dsa: mv88e6xxx: use correct .stats_set_histogram() on Topaz
- net: dsa: mv88e6xxx: enable .port_set_policy() on Topaz
- net: bcmgenet: ensure EXT_ENERGY_DET_MASK is clear
- usb: cdns3: Enable TDL_CHK only for OUT ep
- mm/page_alloc: fix memory map initialization for descending nodes
- mm/userfaultfd: fix uffd-wp special cases for fork()
- mm/thp: simplify copying of huge zero page pmd when fork
- f2fs: Show casefolding support only when supported
- Revert "swap: fix do_swap_page() race with swapoff"
- arm64: dts: marvell: armada-37xx: move firmware node to generic dtsi file
- firmware: turris-mox-rwtm: add marvell,armada-3700-rwtm-firmware compatible string
- cifs: prevent NULL deref in cifs_compose_mount_options()
- s390: introduce proper type handling call_on_stack() macro
- s390/traps: do not test MONITOR CALL without CONFIG_BUG
- thermal/core/thermal_of: Stop zone device before unregistering it
- perf/x86/intel/uncore: Clean up error handling path of iio mapping
- sched/fair: Fix CFS bandwidth hrtimer expiry type
- scsi: qedf: Add check to synchronize abort and flush
- scsi: libfc: Fix array index out of bound exception
- scsi: aic7xxx: Fix unintentional sign extension issue on left shift of u8
- rtc: max77686: Do not enforce (incorrect) interrupt trigger type
- arch/arm64/boot/dts/marvell: fix NAND partitioning scheme
- kbuild: mkcompile_h: consider timestamp if KBUILD_BUILD_TIMESTAMP is set
- thermal/drivers/sprd: Add missing of_node_put for loop iteration
- thermal/drivers/imx_sc: Add missing of_node_put for loop iteration
- thermal/drivers/rcar_gen3_thermal: Do not shadow rcar_gen3_ths_tj_1
- thermal/core: Correct function name thermal_zone_device_unregister()
- arm64: dts: imx8mq: assign PCIe clocks
- arm64: dts: ls208xa: remove bus-num from dspi node
- firmware: tegra: bpmp: Fix Tegra234-only builds
- soc/tegra: fuse: Fix Tegra234-only builds
- ARM: OMAP2+: Block suspend for am3 and am4 if PM is not configured
- ARM: dts: stm32: fix stpmic node for stm32mp1 boards
- ARM: dts: stm32: Rename spi-flash/mx66l51235l@N to flash@N on DHCOM SoM
- ARM: dts: stm32: Drop unused linux,wakeup from touchscreen node on DHCOM SoM
- ARM: dts: stm32: fix the Odyssey SoM eMMC VQMMC supply
- ARM: dts: stm32: move stmmac axi config in ethernet node on stm32mp15
- ARM: dts: stm32: fix i2c node name on stm32f746 to prevent warnings
- ARM: dts: rockchip: fix supply properties in io-domains nodes
- arm64: dts: juno: Update SCPI nodes as per the YAML schema
- ARM: dts: bcm283x: Fix up GPIO LED node names
- ARM: dts: bcm283x: Fix up MMC node names
- firmware: arm_scmi: Fix the build when CONFIG_MAILBOX is not selected
- firmware: arm_scmi: Add SMCCC discovery dependency in Kconfig
- memory: tegra: Fix compilation warnings on 64bit platforms
- ARM: dts: stm32: fix timer nodes on STM32 MCU to prevent warnings
- ARM: dts: stm32: fix RCC node name on stm32f429 MCU
- ARM: dts: stm32: fix gpio-keys node on STM32 MCU boards
- ARM: dts: stm32: fix stm32mp157c-odyssey card detect pin
- ARM: dts: stm32: Fix touchscreen node on dhcom-pdk2
- ARM: dts: stm32: Remove extra size-cells on dhcom-pdk2
- arm64: dts: qcom: sc7180: Move rmtfs memory region
- ARM: tegra: nexus7: Correct 3v3 regulator GPIO of PM269 variant
- ARM: tegra: wm8903: Fix polarity of headphones-detection GPIO in device-trees
- arm64: dts: ti: k3-am654x/j721e/j7200-common-proc-board: Fix MCU_RGMII1_TXC direction
- ARM: dts: OMAP2+: Replace underscores in sub-mailbox node names
- ARM: dts: am335x: fix ti,no-reset-on-init flag for gpios
- ARM: dts: am437x-gp-evm: fix ti,no-reset-on-init flag for gpios
- ARM: dts: am57xx-cl-som-am57x: fix ti,no-reset-on-init flag for gpios
- kbuild: sink stdout from cmd for silent build
- rtc: mxc_v2: add missing MODULE_DEVICE_TABLE
- ARM: dts: imx6dl-riotboard: configure PHY clock and set proper EEE value
- ARM: dts: ux500: Fix orientation of accelerometer
- ARM: dts: ux500: Rename gpio-controller node
- ARM: dts: ux500: Fix interrupt cells
- arm64: dts: rockchip: fix regulator-gpio states array
- ARM: imx: pm-imx5: Fix references to imx5_cpu_suspend_info
- ARM: dts: imx6: phyFLEX: Fix UART hardware flow control
- ARM: dts: Hurricane 2: Fix NAND nodes names
- ARM: dts: BCM63xx: Fix NAND nodes names
- ARM: NSP: dts: fix NAND nodes names
- ARM: Cygnus: dts: fix NAND nodes names
- ARM: brcmstb: dts: fix NAND nodes names
- reset: ti-syscon: fix to_ti_syscon_reset_data macro
- arm64: dts: rockchip: Fix power-controller node names for rk3399
- arm64: dts: rockchip: Fix power-controller node names for rk3328
- arm64: dts: rockchip: Fix power-controller node names for px30
- ARM: dts: rockchip: Fix power-controller node names for rk3288
- ARM: dts: rockchip: Fix power-controller node names for rk3188
- ARM: dts: rockchip: Fix power-controller node names for rk3066a
- ARM: dts: rockchip: Fix IOMMU nodes properties on rk322x
- ARM: dts: rockchip: Fix the timer clocks order
- arm64: dts: rockchip: fix pinctrl sleep nodename for rk3399.dtsi
- ARM: dts: rockchip: fix pinctrl sleep nodename for rk3036-kylin and rk3288
- ARM: dts: rockchip: Fix thermal sensor cells o rk322x
- ARM: dts: gemini: add device_type on pci
- ARM: dts: gemini: rename mdio to the right name
- scsi: scsi_dh_alua: Fix signedness bug in alua_rtpg()
- MIPS: vdso: Invalid GIC access through VDSO
- mips: disable branch profiling in boot/decompress.o
- mips: always link byteswap helpers into decompressor
- static_call: Fix static_call_text_reserved() vs __init
- jump_label: Fix jump_label_text_reserved() vs __init
- sched/uclamp: Ignore max aggregation if rq is idle
- scsi: be2iscsi: Fix an error handling path in beiscsi_dev_probe()
- arm64: dts: rockchip: Re-add regulator-always-on for vcc_sdio for rk3399-roc-pc
- arm64: dts: rockchip: Re-add regulator-boot-on, regulator-always-on for vdd_gpu on rk3399-roc-pc
- firmware: turris-mox-rwtm: show message about HWRNG registration
- firmware: turris-mox-rwtm: fail probing when firmware does not support hwrng
- firmware: turris-mox-rwtm: report failures better
- firmware: turris-mox-rwtm: fix reply status decoding function
- thermal/drivers/rcar_gen3_thermal: Fix coefficient calculations
- ARM: dts: imx6q-dhcom: Add gpios pinctrl for i2c bus recovery
- ARM: dts: imx6q-dhcom: Fix ethernet plugin detection problems
- ARM: dts: imx6q-dhcom: Fix ethernet reset time properties
- thermal/drivers/sprd: Add missing MODULE_DEVICE_TABLE
- ARM: dts: am437x: align ti,pindir-d0-out-d1-in property with dt-shema
- ARM: dts: am335x: align ti,pindir-d0-out-d1-in property with dt-shema
- ARM: dts: dra7: Fix duplicate USB4 target module node
- arm64: dts: allwinner: a64-sopine-baseboard: change RGMII mode to TXID
- memory: fsl_ifc: fix leak of private memory on probe failure
- memory: fsl_ifc: fix leak of IO mapping on probe failure
- arm64: dts: ti: k3-j721e-main: Fix external refclk input to SERDES
- arm64: dts: renesas: r8a779a0: Drop power-domains property from GIC node
- reset: bail if try_module_get() fails
- ARM: dts: BCM5301X: Fixup SPI binding
- dt-bindings: i2c: at91: fix example for scl-gpios
- firmware: arm_scmi: Reset Rx buffer to max size during async commands
- firmware: tegra: Fix error return code in tegra210_bpmp_init()
- arm64: dts: qcom: trogdor: Add no-hpd to DSI bridge node
- ARM: dts: stm32: Rework LAN8710Ai PHY reset on DHCOM SoM
- ARM: dts: stm32: Connect PHY IRQ line on DH STM32MP1 SoM
- arm64: dts: renesas: r8a7796[01]: Fix OPP table entry voltages
- arm64: dts: renesas: Add missing opp-suspend properties
- arm64: dts: ti: j7200-main: Enable USB2 PHY RX sensitivity workaround
- ARM: dts: r8a7779, marzen: Fix DU clock names
- arm64: dts: renesas: v3msk: Fix memory size
- rtc: fix snprintf() checking in is_rtc_hctosys()
- ARM: dts: sun8i: h3: orangepi-plus: Fix ethernet phy-mode
- memory: pl353: Fix error return code in pl353_smc_probe()
- reset: brcmstb: Add missing MODULE_DEVICE_TABLE
- memory: atmel-ebi: add missing of_node_put for loop iteration
- memory: stm32-fmc2-ebi: add missing of_node_put for loop iteration
- ARM: dts: exynos: fix PWM LED max brightness on Odroid XU4
- ARM: dts: exynos: fix PWM LED max brightness on Odroid HC1
- ARM: dts: exynos: fix PWM LED max brightness on Odroid XU/XU3
- ARM: exynos: add missing of_node_put for loop iteration
- reset: a10sr: add missing of_match_table reference
- reset: RESET_INTEL_GW should depend on X86
- reset: RESET_BRCMSTB_RESCAL should depend on ARCH_BRCMSTB
- ARM: dts: gemini-rut1xx: remove duplicate ethernet node
- hexagon: use common DISCARDS macro
- hexagon: handle {,SOFT}IRQENTRY_TEXT in linker script
- NFSv4/pNFS: Don't call _nfs4_pnfs_v3_ds_connect multiple times
- NFSv4/pnfs: Fix layoutget behaviour after invalidation
- NFSv4/pnfs: Fix the layout barrier update
- vdpa/mlx5: Clear vq ready indication upon device reset
- ALSA: isa: Fix error return code in snd_cmi8330_probe()
- nfsd: Reduce contention for the nfsd_file nf_rwsem
- nvme-tcp: can't set sk_user_data without write_lock
- virtio_net: move tx vq operation under tx queue lock
- vdpa/mlx5: Fix possible failure in umem size calculation
- vdpa/mlx5: Fix umem sizes assignments on VQ create
- PCI: tegra194: Fix tegra_pcie_ep_raise_msi_irq() ill-defined shift
- pwm: imx1: Don't disable clocks at device remove time
- PCI: intel-gw: Fix INTx enable
- x86/fpu: Limit xstate copy size in xstateregs_set()
- x86/fpu: Fix copy_xstate_to_kernel() gap handling
- f2fs: fix to avoid adding tab before doc section
- PCI: iproc: Support multi-MSI only on uniprocessor kernel
- PCI: iproc: Fix multi-MSI base vector number allocation
- ubifs: Set/Clear I_LINKABLE under i_lock for whiteout inode
- nfs: fix acl memory leak of posix_acl_create()
- SUNRPC: prevent port reuse on transports which don't request it.
- watchdog: jz4740: Fix return value check in jz4740_wdt_probe()
- watchdog: aspeed: fix hardware timeout calculation
- ubifs: journal: Fix error return code in ubifs_jnl_write_inode()
- ubifs: Fix off-by-one error
- um: fix error return code in winch_tramp()
- um: fix error return code in slip_open()
- misc: alcor_pci: fix inverted branch condition
- NFSv4: Fix an Oops in pnfs_mark_request_commit() when doing O_DIRECT
- NFSv4: Initialise connection to the server in nfs4_alloc_client()
- power: supply: rt5033_battery: Fix device tree enumeration
- PCI/sysfs: Fix dsm_label_utf16s_to_utf8s() buffer overrun
- remoteproc: k3-r5: Fix an error message
- f2fs: compress: fix to disallow temp extension
- f2fs: add MODULE_SOFTDEP to ensure crc32 is included in the initramfs
- x86/signal: Detect and prevent an alternate signal stack overflow
- NFSD: Fix TP_printk() format specifier in nfsd_clid_class
- f2fs: atgc: fix to set default age threshold
- virtio_console: Assure used length from device is limited
- virtio_net: Fix error handling in virtnet_restore()
- virtio-blk: Fix memory leak among suspend/resume procedure
- PCI: rockchip: Register IRQ handlers after device and data are ready
- ACPI: video: Add quirk for the Dell Vostro 3350
- ACPI: AMBA: Fix resource name in /proc/iomem
- pwm: tegra: Don't modify HW state in .remove callback
- pwm: img: Fix PM reference leak in img_pwm_enable()
- drm/amdkfd: fix sysfs kobj leak
- power: supply: ab8500: add missing MODULE_DEVICE_TABLE
- power: supply: charger-manager: add missing MODULE_DEVICE_TABLE
- NFS: nfs_find_open_context() may only select open files
- drm/gma500: Add the missed drm_gem_object_put() in psb_user_framebuffer_create()
- ceph: remove bogus checks and WARN_ONs from ceph_set_page_dirty
- orangefs: fix orangefs df output.
- PCI: tegra: Add missing MODULE_DEVICE_TABLE
- remoteproc: core: Fix cdev remove and rproc del
- x86/fpu: Return proper error codes from user access functions
- watchdog: iTCO_wdt: Account for rebooting on second timeout
- watchdog: imx_sc_wdt: fix pretimeout
- watchdog: Fix possible use-after-free by calling del_timer_sync()
- watchdog: sc520_wdt: Fix possible use-after-free in wdt_turnoff()
- watchdog: Fix possible use-after-free in wdt_startup()
- PCI: pciehp: Ignore Link Down/Up caused by DPC
- NFSv4: Fix delegation return in cases where we have to retry
- PCI/P2PDMA: Avoid pci_get_slot(), which may sleep
- ARM: 9087/1: kprobes: test-thumb: fix for LLVM_IAS=1
- power: reset: gpio-poweroff: add missing MODULE_DEVICE_TABLE
- power: supply: max17042: Do not enforce (incorrect) interrupt trigger type
- PCI: hv: Fix a race condition when removing the device
- power: supply: ab8500: Avoid NULL pointers
- PCI: ftpci100: Rename macro name collision
- pwm: spear: Don't modify HW state in .remove callback
- power: supply: sc2731_charger: Add missing MODULE_DEVICE_TABLE
- power: supply: sc27xx: Add missing MODULE_DEVICE_TABLE
- kcov: add __no_sanitize_coverage to fix noinstr for all architectures
- lib/decompress_unlz4.c: correctly handle zero-padding around initrds.
- phy: intel: Fix for warnings due to EMMC clock 175Mhz change in FIP
- i2c: core: Disable client irq on reboot/shutdown
- intel_th: Wait until port is in reset before programming it
- staging: rtl8723bs: fix macro value for 2.4Ghz only device
- leds: turris-omnia: add missing MODULE_DEVICE_TABLE
- ALSA: firewire-motu: fix detection for S/PDIF source on optical interface in v2 protocol
- ALSA: usb-audio: scarlett2: Fix 6i6 Gen 2 line out descriptions
- ALSA: hda: Add IRQ check for platform_get_irq()
- backlight: lm3630a: Fix return code of .update_status() callback
- ASoC: Intel: kbl_da7219_max98357a: shrink platform_id below 20 characters
- powerpc/boot: Fixup device-tree on little endian
- usb: gadget: hid: fix error return code in hid_bind()
- usb: gadget: f_hid: fix endianness issue with descriptors
- ALSA: usb-audio: scarlett2: Fix scarlett2_*_ctl_put() return values
- ALSA: usb-audio: scarlett2: Fix data_mutex lock
- ALSA: usb-audio: scarlett2: Fix 18i8 Gen 2 PCM Input count
- ALSA: bebob: add support for ToneWeal FW66
- Input: hideep - fix the uninitialized use in hideep_nvm_unlock()
- s390/mem_detect: fix tprot() program check new psw handling
- s390/mem_detect: fix diag260() program check new psw handling
- s390/ipl_parm: fix program check new psw handling
- s390/processor: always inline stap() and __load_psw_mask()
- habanalabs: remove node from list before freeing the node
- habanalabs/gaudi: set the correct cpu_id on MME2_QM failure
- ASoC: soc-core: Fix the error return code in snd_soc_of_parse_audio_routing()
- powerpc/mm/book3s64: Fix possible build error
- gpio: pca953x: Add support for the On Semi pca9655
- selftests/powerpc: Fix "no_handler" EBB selftest
- ALSA: ppc: fix error return code in snd_pmac_probe()
- scsi: storvsc: Correctly handle multiple flags in srb_status
- gpio: zynq: Check return value of irq_get_irq_data
- gpio: zynq: Check return value of pm_runtime_get_sync
- ASoC: soc-pcm: fix the return value in dpcm_apply_symmetry()
- iommu/arm-smmu: Fix arm_smmu_device refcount leak in address translation
- iommu/arm-smmu: Fix arm_smmu_device refcount leak when arm_smmu_rpm_get fails
- powerpc/ps3: Add dma_mask to ps3_dma_region
- ALSA: sb: Fix potential double-free of CSP mixer elements
- selftests: timers: rtcpie: skip test if default RTC device does not exist
- s390: disable SSP when needed
- s390/sclp_vt220: fix console name to match device
- serial: tty: uartlite: fix console setup
- fsi: Add missing MODULE_DEVICE_TABLE
- ASoC: img: Fix PM reference leak in img_i2s_in_probe()
- mfd: cpcap: Fix cpcap dmamask not set warnings
- mfd: da9052/stmpe: Add and modify MODULE_DEVICE_TABLE
- scsi: qedi: Fix cleanup session block/unblock use
- scsi: qedi: Fix TMF session block/unblock use
- scsi: qedi: Fix race during abort timeouts
- scsi: qedi: Fix null ref during abort handling
- scsi: iscsi: Fix shost->max_id use
- scsi: iscsi: Fix conn use after free during resets
- scsi: iscsi: Add iscsi_cls_conn refcount helpers
- scsi: megaraid_sas: Handle missing interrupts while re-enabling IRQs
- scsi: megaraid_sas: Early detection of VD deletion through RaidMap update
- scsi: megaraid_sas: Fix resource leak in case of probe failure
- fs/jfs: Fix missing error code in lmLogInit()
- scsi: scsi_dh_alua: Check for negative result value
- scsi: core: Fixup calling convention for scsi_mode_sense()
- scsi: mpt3sas: Fix deadlock while cancelling the running firmware event
- tty: serial: 8250: serial_cs: Fix a memory leak in error handling path
- ALSA: ac97: fix PM reference leak in ac97_bus_remove()
- scsi: core: Cap scsi_host cmd_per_lun at can_queue
- scsi: lpfc: Fix crash when lpfc_sli4_hba_setup() fails to initialize the SGLs
- scsi: lpfc: Fix "Unexpected timeout" error in direct attach topology
- scsi: arcmsr: Fix doorbell status being updated late on ARC-1886
- w1: ds2438: fixing bug that would always get page0
- usb: common: usb-conn-gpio: fix NULL pointer dereference of charger
- Revert "ALSA: bebob/oxfw: fix Kconfig entry for Mackie d.2 Pro"
- ALSA: usx2y: Don't call free_pages_exact() with NULL address
- ALSA: usx2y: Avoid camelCase
- iio: magn: bmc150: Balance runtime pm + use pm_runtime_resume_and_get()
- iio: gyro: fxa21002c: Balance runtime pm + use pm_runtime_resume_and_get().
- partitions: msdos: fix one-byte get_unaligned()
- ASoC: intel/boards: add missing MODULE_DEVICE_TABLE
- misc: alcor_pci: fix null-ptr-deref when there is no PCI bridge
- misc/libmasm/module: Fix two use after free in ibmasm_init_one
- serial: fsl_lpuart: disable DMA for console and fix sysrq
- tty: serial: fsl_lpuart: fix the potential risk of division or modulo by zero
- rcu: Reject RCU_LOCKDEP_WARN() false positives
- srcu: Fix broken node geometry after early ssp init
- scsi: arcmsr: Fix the wrong CDB payload report to IOP
- dmaengine: fsl-qdma: check dma_set_mask return value
- ASoC: Intel: sof_sdw: add mutual exclusion between PCH DMIC and RT715
- leds: tlc591xx: fix return value check in tlc591xx_probe()
- net: bridge: multicast: fix MRD advertisement router port marking race
- net: bridge: multicast: fix PIM hello router port marking race
- Revert "drm/ast: Remove reference to struct drm_device.pdev"
- drm/ingenic: Switch IPU plane to type OVERLAY
- drm/ingenic: Fix non-OSD mode
- drm/dp_mst: Add missing drm parameters to recently added call to drm_dbg_kms()
- drm/dp_mst: Avoid to mess up payload table by ports in stale topology
- drm/dp_mst: Do not set proposed vcpi directly
- fbmem: Do not delete the mode that is still in use
- cgroup: verify that source is a string
- drm/i915/gt: Fix -EDEADLK handling regression
- drm/i915/gtt: drop the page table optimisation
- tracing: Do not reference char * as a string in histograms
- scsi: zfcp: Report port fc_security as unknown early during remote cable pull
- scsi: core: Fix bad pointer dereference when ehandler kthread is invalid
- KVM: X86: Disable hardware breakpoints unconditionally before kvm_x86->run()
- KVM: nSVM: Check the value written to MSR_VM_HSAVE_PA
- KVM: x86/mmu: Do not apply HPA (memory encryption) mask to GPAs
- KVM: x86: Use guest MAXPHYADDR from CPUID.0x8000_0008 iff TDP is enabled
- KVM: mmio: Fix use-after-free Read in kvm_vm_ioctl_unregister_coalesced_mmio
- cifs: handle reconnect of tcon when there is no cached dfs referral
- certs: add 'x509_revocation_list' to gitignore
- f2fs: fix to avoid racing on fsync_entry_slab by multi filesystem instances
- smackfs: restrict bytes count in smk_set_cipso()
- jfs: fix GPF in diFree
- drm/ast: Remove reference to struct drm_device.pdev
- pinctrl: mcp23s08: Fix missing unlock on error in mcp23s08_irq()
- dm writecache: write at least 4k when committing
- io_uring: fix clear IORING_SETUP_R_DISABLED in wrong function
- media: uvcvideo: Fix pixel format change for Elgato Cam Link 4K
- media: gspca/sunplus: fix zero-length control requests
- media: gspca/sq905: fix control-request direction
- media: zr364xx: fix memory leak in zr364xx_start_readpipe
- media: dtv5100: fix control-request directions
- media: subdev: disallow ioctl for saa6588/davinci
- PCI: aardvark: Implement workaround for the readback value of VEND_ID
- PCI: aardvark: Fix checking for PIO Non-posted Request
- PCI: Leave Apple Thunderbolt controllers on for s2idle or standby
- dm writecache: flush origin device when writing and cache is full
- dm zoned: check zone capacity
- coresight: tmc-etf: Fix global-out-of-bounds in tmc_update_etf_buffer()
- coresight: Propagate symlink failure
- ipack/carriers/tpci200: Fix a double free in tpci200_pci_probe
- tracing: Resize tgid_map to pid_max, not PID_MAX_DEFAULT
- tracing: Simplify & fix saved_tgids logic
- rq-qos: fix missed wake-ups in rq_qos_throttle try two
- seq_buf: Fix overflow in seq_buf_putmem_hex()
- extcon: intel-mrfld: Sync hardware and software state on init
- selftests/lkdtm: Fix expected text for CR4 pinning
- lkdtm/bugs: XFAIL UNALIGNED_LOAD_STORE_WRITE
- nvmem: core: add a missing of_node_put
- mfd: syscon: Free the allocated name field of struct regmap_config
- power: supply: ab8500: Fix an old bug
- thermal/drivers/int340x/processor_thermal: Fix tcc setting
- ipmi/watchdog: Stop watchdog timer when the current action is 'none'
- qemu_fw_cfg: Make fw_cfg_rev_attr a proper kobj_attribute
- i40e: fix PTP on 5Gb links
- ASoC: tegra: Set driver_name=tegra for all machine drivers
- fpga: stratix10-soc: Add missing fpga_mgr_free() call
- clocksource/arm_arch_timer: Improve Allwinner A64 timer workaround
- cpu/hotplug: Cure the cpusets trainwreck
- arm64: tlb: fix the TTL value of tlb_get_level
- ata: ahci_sunxi: Disable DIPM
- mmc: core: Allow UHS-I voltage switch for SDSC cards if supported
- mmc: core: clear flags before allowing to retune
- mmc: sdhci: Fix warning message when accessing RPMB in HS400 mode
- mmc: sdhci-acpi: Disable write protect detection on Toshiba Encore 2 WT8-B
- drm/i915/display: Do not zero past infoframes.vsc
- drm/nouveau: Don't set allow_fb_modifiers explicitly
- drm/arm/malidp: Always list modifiers
- drm/msm/mdp4: Fix modifier support enabling
- drm/tegra: Don't set allow_fb_modifiers explicitly
- drm/amd/display: Reject non-zero src_y and src_x for video planes
- pinctrl/amd: Add device HID for new AMD GPIO controller
- drm/amd/display: fix incorrrect valid irq check
- drm/rockchip: dsi: remove extra component_del() call
- drm/dp: Handle zeroed port counts in drm_dp_read_downstream_info()
- drm/vc4: hdmi: Prevent clock unbalance
- drm/vc4: crtc: Skip the TXP
- drm/vc4: txp: Properly set the possible_crtcs mask
- drm/radeon: Call radeon_suspend_kms() in radeon_pci_shutdown() for Loongson64
- drm/radeon: Add the missed drm_gem_object_put() in radeon_user_framebuffer_create()
- drm/amdgpu: enable sdma0 tmz for Raven/Renoir(V2)
- drm/amdgpu: Update NV SIMD-per-CU to 2
- powerpc/powernv/vas: Release reference to tgid during window close
- powerpc/barrier: Avoid collision with clang's __lwsync macro
- powerpc/mm: Fix lockup on kernel exec fault
- arm64: dts: rockchip: Enable USB3 for rk3328 Rock64
- arm64: dts: rockchip: add rk3328 dwc3 usb controller node
- ath11k: unlock on error path in ath11k_mac_op_add_interface()
- MIPS: MT extensions are not available on MIPS32r1
- selftests/resctrl: Fix incorrect parsing of option "-t"
- MIPS: set mips32r5 for virt extensions
- MIPS: loongsoon64: Reserve memory below starting pfn to prevent Oops
- sctp: add size validation when walking chunks
- sctp: validate from_addr_param return
- flow_offload: action should not be NULL when it is referenced
- bpf: Fix false positive kmemleak report in bpf_ringbuf_area_alloc()
- sched/fair: Ensure _sum and _avg values stay consistent
- Bluetooth: btusb: fix bt fiwmare downloading failure issue for qca btsoc.
- Bluetooth: mgmt: Fix the command returns garbage parameter value
- Bluetooth: btusb: Add support USB ALT 3 for WBS
- Bluetooth: L2CAP: Fix invalid access on ECRED Connection response
- Bluetooth: L2CAP: Fix invalid access if ECRED Reconfigure fails
- Bluetooth: btusb: Add a new QCA_ROME device (0cf3:e500)
- Bluetooth: Shutdown controller after workqueues are flushed or cancelled
- Bluetooth: Fix alt settings for incoming SCO with transparent coding format
- Bluetooth: Fix the HCI to MGMT status conversion table
- Bluetooth: btusb: Fixed too many in-token issue for Mediatek Chip.
- RDMA/cma: Fix rdma_resolve_route() memory leak
- net: ip: avoid OOM kills with large UDP sends over loopback
- media, bpf: Do not copy more entries than user space requested
- IB/isert: Align target max I/O size to initiator size
- mac80211_hwsim: add concurrent channels scanning support over virtio
- mac80211: consider per-CPU statistics if present
- cfg80211: fix default HE tx bitrate mask in 2G band
- wireless: wext-spy: Fix out-of-bounds warning
- sfc: error code if SRIOV cannot be disabled
- sfc: avoid double pci_remove of VFs
- iwlwifi: pcie: fix context info freeing
- iwlwifi: pcie: free IML DMA memory allocation
- iwlwifi: mvm: fix error print when session protection ends
- iwlwifi: mvm: don't change band on bound PHY contexts
- RDMA/rxe: Don't overwrite errno from ib_umem_get()
- vsock: notify server to shutdown when client has pending signal
- atm: nicstar: register the interrupt handler in the right place
- atm: nicstar: use 'dma_free_coherent' instead of 'kfree'
- net: fec: add ndo_select_queue to fix TX bandwidth fluctuations
- MIPS: add PMD table accounting into MIPS'pmd_alloc_one
- rtl8xxxu: Fix device info for RTL8192EU devices
- mt76: mt7915: fix IEEE80211_HE_PHY_CAP7_MAX_NC for station mode
- drm/amdkfd: Walk through list with dqm lock hold
- drm/amdgpu: fix bad address translation for sienna_cichlid
- io_uring: fix false WARN_ONCE
- net: sched: fix error return code in tcf_del_walker()
- net: ipa: Add missing of_node_put() in ipa_firmware_load()
- net: fix mistake path for netdev_features_strings
- mt76: mt7615: fix fixed-rate tx status reporting
- ice: mark PTYPE 2 as reserved
- ice: fix incorrect payload indicator on PTYPE
- bpf: Fix up register-based shifts in interpreter to silence KUBSAN
- drm/amdkfd: Fix circular lock in nocpsch path
- drm/amdkfd: fix circular locking on get_wave_state
- cw1200: add missing MODULE_DEVICE_TABLE
- wl1251: Fix possible buffer overflow in wl1251_cmd_scan
- wlcore/wl12xx: Fix wl12xx get_mac error if device is in ELP
- dm writecache: commit just one block, not a full page
- xfrm: Fix error reporting in xfrm_state_construct.
- drm/amd/display: Verify Gamma & Degamma LUT sizes in amdgpu_dm_atomic_check
- r8169: avoid link-up interrupt issue on RTL8106e if user enables ASPM
- selinux: use __GFP_NOWARN with GFP_NOWAIT in the AVC
- fjes: check return value after calling platform_get_resource()
- drm/amdkfd: use allowed domain for vmbo validation
- net: sgi: ioc3-eth: check return value after calling platform_get_resource()
- selftests: Clean forgotten resources as part of cleanup()
- net: phy: realtek: add delay to fix RXC generation issue
- drm/amd/display: Fix off-by-one error in DML
- drm/amd/display: Set DISPCLK_MAX_ERRDET_CYCLES to 7
- drm/amd/display: Release MST resources on switch from MST to SST
- drm/amd/display: Update scaling settings on modeset
- drm/amd/display: Fix DCN 3.01 DSCCLK validation
- net: moxa: Use devm_platform_get_and_ioremap_resource()
- net: micrel: check return value after calling platform_get_resource()
- net: mvpp2: check return value after calling platform_get_resource()
- net: bcmgenet: check return value after calling platform_get_resource()
- net: mscc: ocelot: check return value after calling platform_get_resource()
- virtio_net: Remove BUG() to avoid machine dead
- ice: fix clang warning regarding deadcode.DeadStores
- ice: set the value of global config lock timeout longer
- pinctrl: mcp23s08: fix race condition in irq handler
- net: bridge: mrp: Update ring transitions.
- dm: Fix dm_accept_partial_bio() relative to zone management commands
- dm writecache: don't split bios when overwriting contiguous cache content
- dm space maps: don't reset space map allocation cursor when committing
- RDMA/cxgb4: Fix missing error code in create_qp()
- net: tcp better handling of reordering then loss cases
- drm/amdgpu: remove unsafe optimization to drop preamble ib
- drm/amd/display: Avoid HDCP over-read and corruption
- MIPS: ingenic: Select CPU_SUPPORTS_CPUFREQ && MIPS_EXTERNAL_TIMER
- MIPS: cpu-probe: Fix FPU detection on Ingenic JZ4760(B)
- ipv6: use prandom_u32() for ID generation
- virtio-net: Add validation for used length
- drm: bridge: cdns-mhdp8546: Fix PM reference leak in
- clk: tegra: Ensure that PLLU configuration is applied properly
- clk: tegra: Fix refcounting of gate clocks
- RDMA/rtrs: Change MAX_SESS_QUEUE_DEPTH
- net: stmmac: the XPCS obscures a potential "PHY not found" error
- drm: rockchip: add missing registers for RK3066
- drm: rockchip: add missing registers for RK3188
- net/mlx5: Fix lag port remapping logic
- net/mlx5e: IPsec/rep_tc: Fix rep_tc_update_skb drops IPsec packet
- clk: renesas: r8a77995: Add ZA2 clock
- drm/bridge: cdns: Fix PM reference leak in cdns_dsi_transfer()
- igb: fix assignment on big endian machines
- igb: handle vlan types with checker enabled
- e100: handle eeprom as little endian
- drm/vc4: hdmi: Fix PM reference leak in vc4_hdmi_encoder_pre_crtc_co()
- drm/vc4: Fix clock source for VEC PixelValve on BCM2711
- udf: Fix NULL pointer dereference in udf_symlink function
- drm/sched: Avoid data corruptions
- drm/scheduler: Fix hang when sched_entity released
- pinctrl: equilibrium: Add missing MODULE_DEVICE_TABLE
- net/sched: cls_api: increase max_reclassify_loop
- net: mdio: provide shim implementation of devm_of_mdiobus_register
- drm/virtio: Fix double free on probe failure
- reiserfs: add check for invalid 1st journal block
- drm/bridge: lt9611: Add missing MODULE_DEVICE_TABLE
- net: mdio: ipq8064: add regmap config to disable REGCACHE
- drm/mediatek: Fix PM reference leak in mtk_crtc_ddp_hw_init()
- net: Treat __napi_schedule_irqoff() as __napi_schedule() on PREEMPT_RT
- atm: nicstar: Fix possible use-after-free in nicstar_cleanup()
- mISDN: fix possible use-after-free in HFC_cleanup()
- atm: iphase: fix possible use-after-free in ia_module_exit()
- hugetlb: clear huge pte during flush function on mips platform
- clk: renesas: rcar-usb2-clock-sel: Fix error handling in .probe()
- drm/amd/display: fix use_max_lb flag for 420 pixel formats
- net: pch_gbe: Use proper accessors to BE data in pch_ptp_match()
- drm/bridge: nwl-dsi: Force a full modeset when crtc_state->active is changed to be true
- drm/vc4: fix argument ordering in vc4_crtc_get_margins()
- drm/amd/amdgpu/sriov disable all ip hw status by default
- drm/amd/display: fix HDCP reset sequence on reinitialize
- drm/ast: Fixed CVE for DP501
- drm/zte: Don't select DRM_KMS_FB_HELPER
- drm/mxsfb: Don't select DRM_KMS_FB_HELPER
- perf data: Close all files in close_dir()
- perf test bpf: Free obj_buf
- perf probe-file: Delete namelist in del_events() on the error path
- igmp: Add ip_mc_list lock in ip_check_mc_rcu
- ACPI / PPTT: get PPTT table in the first beginning
- Revert "[Huawei] sched: export sched_setscheduler symbol"
- kcsan: Never set up watchpoints on NULL pointers
- ext4: inline jbd2_journal_[un]register_shrinker()
- jbd2: export jbd2_journal_[un]register_shrinker()
- fs: remove bdev_try_to_free_page callback
- ext4: remove bdev_try_to_free_page() callback
- jbd2: simplify journal_clean_one_cp_list()
- jbd2,ext4: add a shrinker to release checkpointed buffers
- jbd2: remove redundant buffer io error checks
- jbd2: don't abort the journal when freeing buffers
- jbd2: ensure abort the journal if detect IO error when writing original buffer back
- jbd2: remove the out label in __jbd2_journal_remove_checkpoint()
- net: spnic: add NIC layer
- net: spnic: initial commit the common module of Ramaxel NIC driver
- spraid: Add CONFIG_RAMAXEL_SPRAID in defconfig of arch arm64 and x86
- spraid: support Ramaxel raid controller
- powerpc/preempt: Don't touch the idle task's preempt_count during hotplug
- iommu/dma: Fix compile warning in 32-bit builds
- cred: add missing return error code when set_cred_ucounts() failed
- s390: preempt: Fix preempt_count initialization
- crypto: qce - fix error return code in qce_skcipher_async_req_handle()
- scsi: core: Retry I/O for Notify (Enable Spinup) Required error
- media: exynos4-is: remove a now unused integer
- mmc: vub3000: fix control-request direction
- mmc: block: Disable CMDQ on the ioctl path
- io_uring: fix blocking inline submission
- block: return the correct bvec when checking for gaps
- erofs: fix error return code in erofs_read_superblock()
- tpm: Replace WARN_ONCE() with dev_err_once() in tpm_tis_status()
- fscrypt: fix derivation of SipHash keys on big endian CPUs
- fscrypt: don't ignore minor_hash when hash is 0
- mailbox: qcom-ipcc: Fix IPCC mbox channel exhaustion
- scsi: target: cxgbit: Unmap DMA buffer before calling target_execute_cmd()
- scsi: fc: Correct RHBA attributes length
- exfat: handle wrong stream entry size in exfat_readdir()
- csky: syscache: Fixup duplicate cache flush
- csky: fix syscache.c fallthrough warning
- perf llvm: Return -ENOMEM when asprintf() fails
- selftests/vm/pkeys: refill shadow register after implicit kernel write
- selftests/vm/pkeys: handle negative sys_pkey_alloc() return code
- selftests/vm/pkeys: fix alloc_random_pkey() to make it really, really random
- lib/math/rational.c: fix divide by zero
- mm/z3fold: use release_z3fold_page_locked() to release locked z3fold page
- mm/z3fold: fix potential memory leak in z3fold_destroy_pool()
- include/linux/huge_mm.h: remove extern keyword
- hugetlb: remove prep_compound_huge_page cleanup
- mm/hugetlb: remove redundant check in preparing and destroying gigantic page
- mm/hugetlb: use helper huge_page_order and pages_per_huge_page
- mm/huge_memory.c: don't discard hugepage if other processes are mapping it
- mm/huge_memory.c: add missing read-only THP checking in transparent_hugepage_enabled()
- mm/huge_memory.c: remove dedicated macro HPAGE_CACHE_INDEX_MASK
- mm/pmem: avoid inserting hugepage PTE entry with fsdax if hugepage support is disabled
- vfio/pci: Handle concurrent vma faults
- arm64: dts: marvell: armada-37xx: Fix reg for standard variant of UART
- serial: mvebu-uart: correctly calculate minimal possible baudrate
- serial: mvebu-uart: do not allow changing baudrate when uartclk is not available
- ALSA: firewire-lib: Fix 'amdtp_domain_start()' when no AMDTP_OUT_STREAM stream is found
- powerpc/papr_scm: Make 'perf_stats' invisible if perf-stats unavailable
- powerpc/64s: Fix copy-paste data exposure into newly created tasks
- powerpc/papr_scm: Properly handle UUID types and API
- powerpc: Offline CPU in stop_this_cpu()
- serial: 8250: 8250_omap: Fix possible interrupt storm on K3 SoCs
- serial: 8250: 8250_omap: Disable RX interrupt after DMA enable
- selftests/ftrace: fix event-no-pid on 1-core machine
- leds: ktd2692: Fix an error handling path
- leds: as3645a: Fix error return code in as3645a_parse_node()
- ASoC: fsl_spdif: Fix unexpected interrupt after suspend
- ASoC: Intel: sof_sdw: add SOF_RT715_DAI_ID_FIX for AlderLake
- ASoC: atmel-i2s: Fix usage of capture and playback at the same time
- powerpc/powernv: Fix machine check reporting of async store errors
- extcon: max8997: Add missing modalias string
- extcon: sm5502: Drop invalid register write in sm5502_reg_data
- phy: ti: dm816x: Fix the error handling path in 'dm816x_usb_phy_probe()
- phy: uniphier-pcie: Fix updating phy parameters
- soundwire: stream: Fix test for DP prepare complete
- scsi: mpt3sas: Fix error return value in _scsih_expander_add()
- habanalabs: Fix an error handling path in 'hl_pci_probe()'
- mtd: rawnand: marvell: add missing clk_disable_unprepare() on error in marvell_nfc_resume()
- of: Fix truncation of memory sizes on 32-bit platforms
- ASoC: cs42l42: Correct definition of CS42L42_ADC_PDN_MASK
- iio: prox: isl29501: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: light: vcnl4035: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- serial: 8250: Actually allow UPF_MAGIC_MULTIPLIER baud rates
- staging: mt7621-dts: fix pci address for PCI memory range
- coresight: core: Fix use of uninitialized pointer
- staging: rtl8712: fix memory leak in rtl871x_load_fw_cb
- staging: rtl8712: fix error handling in r871xu_drv_init
- staging: gdm724x: check for overflow in gdm_lte_netif_rx()
- staging: gdm724x: check for buffer overflow in gdm_lte_multi_sdu_pkt()
- ASoC: fsl_spdif: Fix error handler with pm_runtime_enable
- iio: light: vcnl4000: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: magn: rm3100: Fix alignment of buffer in iio_push_to_buffers_with_timestamp()
- iio: adc: ti-ads8688: Fix alignment of buffer in iio_push_to_buffers_with_timestamp()
- iio: adc: mxs-lradc: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: adc: hx711: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: adc: at91-sama5d2: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- thunderbolt: Bond lanes only when dual_link_port != NULL in alloc_dev_default()
- eeprom: idt_89hpesx: Restore printing the unsupported fwnode name
- eeprom: idt_89hpesx: Put fwnode in matching case during ->probe()
- usb: dwc2: Don't reset the core after setting turnaround time
- usb: gadget: f_fs: Fix setting of device and driver data cross-references
- ASoC: mediatek: mtk-btcvsd: Fix an error handling path in 'mtk_btcvsd_snd_probe()'
- ASoC: rt5682-sdw: set regcache_cache_only false before reading RT5682_DEVICE_ID
- ASoC: rt5682: fix getting the wrong device id when the suspend_stress_test
- ASoC: rt715-sdw: use first_hw_init flag on resume
- ASoC: rt711-sdw: use first_hw_init flag on resume
- ASoC: rt700-sdw: use first_hw_init flag on resume
- ASoC: rt5682-sdw: use first_hw_init flag on resume
- ASoC: rt1308-sdw: use first_hw_init flag on resume
- ASoC: max98373-sdw: use first_hw_init flag on resume
- iommu/dma: Fix IOVA reserve dma ranges
- selftests: splice: Adjust for handler fallback removal
- s390: appldata depends on PROC_SYSCTL
- s390: enable HAVE_IOREMAP_PROT
- s390/irq: select HAVE_IRQ_EXIT_ON_IRQ_STACK
- iommu/amd: Fix extended features logging
- visorbus: fix error return code in visorchipset_init()
- fsi/sbefifo: Fix reset timeout
- fsi/sbefifo: Clean up correct FIFO when receiving reset request from SBE
- fsi: occ: Don't accept response from un-initialized OCC
- fsi: scom: Reset the FSI2PIB engine for any error
- fsi: core: Fix return of error values on failures
- mfd: rn5t618: Fix IRQ trigger by changing it to level mode
- mfd: mp2629: Select MFD_CORE to fix build error
- scsi: iscsi: Flush block work before unblock
- scsi: FlashPoint: Rename si_flags field
- leds: lp50xx: Put fwnode in error case during ->probe()
- leds: lm3697: Don't spam logs when probe is deferred
- leds: lm3692x: Put fwnode in any case during ->probe()
- leds: lm36274: Put fwnode in error case during ->probe()
- leds: lm3532: select regmap I2C API
- leds: class: The -ENOTSUPP should never be seen by user space
- tty: nozomi: Fix the error handling path of 'nozomi_card_init()'
- firmware: stratix10-svc: Fix a resource leak in an error handling path
- char: pcmcia: error out if 'num_bytes_read' is greater than 4 in set_protocol()
- staging: mmal-vchiq: Fix incorrect static vchiq_instance.
- mtd: rawnand: arasan: Ensure proper configuration for the asserted target
- mtd: partitions: redboot: seek fis-index-block in the right node
- perf scripting python: Fix tuple_set_u64()
- Input: hil_kbd - fix error return code in hil_dev_connect()
- ASoC: rsnd: tidyup loop on rsnd_adg_clk_query()
- backlight: lm3630a_bl: Put fwnode in error case during ->probe()
- ASoC: hisilicon: fix missing clk_disable_unprepare() on error in hi6210_i2s_startup()
- ASoC: rk3328: fix missing clk_disable_unprepare() on error in rk3328_platform_probe()
- iio: potentiostat: lmp91000: Fix alignment of buffer in iio_push_to_buffers_with_timestamp()
- iio: cros_ec_sensors: Fix alignment of buffer in iio_push_to_buffers_with_timestamp()
- iio: chemical: atlas: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: light: tcs3472: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: light: tcs3414: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: light: isl29125: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: magn: bmc150: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: magn: hmc5843: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: prox: as3935: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: prox: pulsed-light: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: prox: srf08: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: humidity: am2315: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: gyro: bmg160: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: adc: vf610: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: adc: ti-ads1015: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: accel: stk8ba50: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: accel: stk8312: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: accel: mxc4005: Fix overread of data and alignment issue.
- iio: accel: kxcjk-1013: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: accel: hid: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: accel: bma220: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: accel: bma180: Fix buffer alignment in iio_push_to_buffers_with_timestamp()
- iio: adis16475: do not return ints in irq handlers
- iio: adis16400: do not return ints in irq handlers
- iio: adis_buffer: do not return ints in irq handlers
- mwifiex: re-fix for unaligned accesses
- tty: nozomi: Fix a resource leak in an error handling function
- serial: 8250_omap: fix a timeout loop condition
- serial: fsl_lpuart: remove RTSCTS handling from get_mctrl()
- serial: fsl_lpuart: don't modify arbitrary data on lpuart32
- rcu: Invoke rcu_spawn_core_kthreads() from rcu_spawn_gp_kthread()
- ASoC: rt5682: Disable irq on shutdown
- staging: fbtft: Don't spam logs when probe is deferred
- staging: fbtft: Rectify GPIO handling
- MIPS: Fix PKMAP with 32-bit MIPS huge page support
- RDMA/core: Always release restrack object
- RDMA/mlx5: Don't access NULL-cleared mpi pointer
- net: tipc: fix FB_MTU eat two pages
- net: sched: fix warning in tcindex_alloc_perfect_hash
- net: lwtunnel: handle MTU calculation in forwading
- writeback: fix obtain a reference to a freeing memcg css
- clk: si5341: Update initialization magic
- clk: si5341: Check for input clock presence and PLL lock on startup
- clk: si5341: Avoid divide errors due to bogus register contents
- clk: si5341: Wait for DEVICE_READY on startup
- clk: qcom: clk-alpha-pll: fix CAL_L write in alpha_pll_fabia_prepare
- clk: actions: Fix AHPPREDIV-H-AHB clock chain on Owl S500 SoC
- clk: actions: Fix bisp_factor_table based clocks on Owl S500 SoC
- clk: actions: Fix SD clocks factor table on Owl S500 SoC
- clk: actions: Fix UART clock dividers on Owl S500 SoC
- Bluetooth: Fix handling of HCI_LE_Advertising_Set_Terminated event
- Bluetooth: Fix Set Extended (Scan Response) Data
- Bluetooth: Fix not sending Set Extended Scan Response
- Bluetooth: mgmt: Fix slab-out-of-bounds in tlv_data_is_valid
- Revert "be2net: disable bh with spin_lock in be_process_mcc"
- gve: Fix swapped vars when fetching max queues
- RDMA/cma: Fix incorrect Packet Lifetime calculation
- bpfilter: Specify the log level for the kmsg message
- net: dsa: sja1105: fix NULL pointer dereference in sja1105_reload_cbs()
- e1000e: Check the PCIm state
- ipv6: fix out-of-bound access in ip6_parse_tlv()
- net: atlantic: fix the macsec key length
- net: phy: mscc: fix macsec key length
- net: macsec: fix the length used to copy the key for offloading
- RDMA/cma: Protect RMW with qp_mutex
- ibmvnic: free tx_pool if tso_pool alloc fails
- ibmvnic: set ltb->buff to NULL after freeing
- Revert "ibmvnic: remove duplicate napi_schedule call in open function"
- i40e: Fix missing rtnl locking when setting up pf switch
- i40e: Fix autoneg disabling for non-10GBaseT links
- i40e: Fix error handling in i40e_vsi_open
- bpf: Do not change gso_size during bpf_skb_change_proto()
- can: j1939: j1939_sk_setsockopt(): prevent allocation of j1939 filter for optlen == 0
- ipv6: exthdrs: do not blindly use init_net
- net: bcmgenet: Fix attaching to PYH failed on RPi 4B
- mac80211: remove iwlwifi specific workaround NDPs of null_response
- drm/msm/dpu: Fix error return code in dpu_mdss_init()
- drm/msm: Fix error return code in msm_drm_init()
- bpf: Fix null ptr deref with mixed tail calls and subprogs
- ieee802154: hwsim: avoid possible crash in hwsim_del_edge_nl()
- ieee802154: hwsim: Fix memory leak in hwsim_add_one
- tc-testing: fix list handling
- net: ti: am65-cpsw-nuss: Fix crash when changing number of TX queues
- net/ipv4: swap flow ports when validating source
- ip6_tunnel: fix GRE6 segmentation
- vxlan: add missing rcu_read_lock() in neigh_reduce()
- rtw88: 8822c: fix lc calibration timing
- iwlwifi: increase PNVM load timeout
- xfrm: Fix xfrm offload fallback fail case
- pkt_sched: sch_qfq: fix qfq_change_class() error path
- netfilter: nf_tables_offload: check FLOW_DISSECTOR_KEY_BASIC in VLAN transfer logic
- tls: prevent oversized sendfile() hangs by ignoring MSG_MORE
- net: sched: add barrier to ensure correct ordering for lockless qdisc
- vrf: do not push non-ND strict packets with a source LLA through packet taps again
- net: ethernet: ezchip: fix error handling
- net: ethernet: ezchip: fix UAF in nps_enet_remove
- net: ethernet: aeroflex: fix UAF in greth_of_remove
- mt76: mt7615: fix NULL pointer dereference in tx_prepare_skb()
- mt76: fix possible NULL pointer dereference in mt76_tx
- samples/bpf: Fix the error return code of xdp_redirect's main()
- samples/bpf: Fix Segmentation fault for xdp_redirect command
- RDMA/rtrs-srv: Set minimal max_send_wr and max_recv_wr
- bpf: Fix libelf endian handling in resolv_btfids
- xsk: Fix broken Tx ring validation
- xsk: Fix missing validation for skb and unaligned mode
- selftests/bpf: Whitelist test_progs.h from .gitignore
- RDMA/rxe: Fix qp reference counting for atomic ops
- netfilter: nft_tproxy: restrict support to TCP and UDP transport protocols
- netfilter: nft_osf: check for TCP packet before further processing
- netfilter: nft_exthdr: check for IPv6 packet before further processing
- RDMA/mlx5: Don't add slave port to unaffiliated list
- netlabel: Fix memory leak in netlbl_mgmt_add_common
- ath11k: send beacon template after vdev_start/restart during csa
- ath10k: Fix an error code in ath10k_add_interface()
- ath11k: Fix an error handling path in ath11k_core_fetch_board_data_api_n()
- cw1200: Revert unnecessary patches that fix unreal use-after-free bugs
- brcmsmac: mac80211_if: Fix a resource leak in an error handling path
- brcmfmac: Fix a double-free in brcmf_sdio_bus_reset
- brcmfmac: correctly report average RSSI in station info
- brcmfmac: fix setting of station info chains bitmask
- ssb: Fix error return code in ssb_bus_scan()
- wcn36xx: Move hal_buf allocation to devm_kmalloc in probe
- clk: imx8mq: remove SYS PLL 1/2 clock gates
- ieee802154: hwsim: Fix possible memory leak in hwsim_subscribe_all_others
- wireless: carl9170: fix LEDS build errors & warnings
- ath10k: add missing error return code in ath10k_pci_probe()
- ath10k: go to path err_unsupported when chip id is not supported
- tools/bpftool: Fix error return code in do_batch()
- drm: qxl: ensure surf.data is ininitialized
- clk: vc5: fix output disabling when enabling a FOD
- drm/vc4: hdmi: Fix error path of hpd-gpios
- drm/pl111: Actually fix CONFIG_VEXPRESS_CONFIG depends
- RDMA/rxe: Fix failure during driver load
- drm/pl111: depend on CONFIG_VEXPRESS_CONFIG
- RDMA/core: Sanitize WQ state received from the userspace
- net/sched: act_vlan: Fix modify to allow 0
- xfrm: remove the fragment check for ipv6 beet mode
- clk: tegra30: Use 300MHz for video decoder by default
- ehea: fix error return code in ehea_restart_qps()
- RDMA/rtrs-clt: Fix memory leak of not-freed sess->stats and stats->pcpu_stats
- RDMA/rtrs-clt: Check if the queue_depth has changed during a reconnection
- RDMA/rtrs-srv: Fix memory leak when having multiple sessions
- RDMA/rtrs-srv: Fix memory leak of unfreed rtrs_srv_stats object
- RDMA/rtrs: Do not reset hb_missed_max after re-connection
- RDMA/rtrs-clt: Check state of the rtrs_clt_sess before reading its stats
- RDMA/srp: Fix a recently introduced memory leak
- mptcp: generate subflow hmac after mptcp_finish_join()
- mptcp: fix pr_debug in mptcp_token_new_connect
- drm/rockchip: cdn-dp: fix sign extension on an int multiply for a u64 result
- drm/rockchip: lvds: Fix an error handling path
- drm/rockchip: dsi: move all lane config except LCDC mux to bind()
- drm/rockchip: cdn-dp-core: add missing clk_disable_unprepare() on error in cdn_dp_grf_write()
- drm: rockchip: set alpha_en to 0 if it is not used
- net: ftgmac100: add missing error return code in ftgmac100_probe()
- clk: meson: g12a: fix gp0 and hifi ranges
- net: qrtr: ns: Fix error return code in qrtr_ns_init()
- drm/vmwgfx: Fix cpu updates of coherent multisample surfaces
- drm/vmwgfx: Mark a surface gpu-dirty after the SVGA3dCmdDXGenMips command
- pinctrl: renesas: r8a77990: JTAG pins do not have pull-down capabilities
- pinctrl: renesas: r8a7796: Add missing bias for PRESET# pin
- net: pch_gbe: Propagate error from devm_gpio_request_one()
- net: mvpp2: Put fwnode in error case during ->probe()
- video: fbdev: imxfb: Fix an error message
- drm/ast: Fix missing conversions to managed API
- drm/amd/dc: Fix a missing check bug in dm_dp_mst_detect()
- drm/bridge: Fix the stop condition of drm_bridge_chain_pre_enable()
- drm/bridge/sii8620: fix dependency on extcon
- xfrm: xfrm_state_mtu should return at least 1280 for ipv6
- mm: memcg/slab: properly set up gfp flags for objcg pointer array
- mm/shmem: fix shmem_swapin() race with swapoff
- swap: fix do_swap_page() race with swapoff
- mm/debug_vm_pgtable: ensure THP availability via has_transparent_hugepage()
- mm/debug_vm_pgtable/basic: iterate over entire protection_map[]
- mm/debug_vm_pgtable/basic: add validation for dirtiness after write protect
- dax: fix ENOMEM handling in grab_mapping_entry()
- ocfs2: fix snprintf() checking
- blk-mq: update hctx->dispatch_busy in case of real scheduler
- cpufreq: Make cpufreq_online() call driver->offline() on errors
- ACPI: bgrt: Fix CFI violation
- ACPI: Use DEVICE_ATTR_<RW|RO|WO> macros
- extcon: extcon-max8997: Fix IRQ freeing at error path
- clocksource/drivers/timer-ti-dm: Save and restore timer TIOCP_CFG
- mark pstore-blk as broken
- ACPI: sysfs: Fix a buffer overrun problem with description_show()
- nvme-pci: look for StorageD3Enable on companion ACPI device instead
- block: avoid double io accounting for flush request
- ACPI: PM / fan: Put fan device IDs into separate header file
- PM / devfreq: Add missing error code in devfreq_add_device()
- media: video-mux: Skip dangling endpoints
- media: v4l2-async: Clean v4l2_async_notifier_add_fwnode_remote_subdev
- psi: Fix race between psi_trigger_create/destroy
- crypto: nx - Fix RCU warning in nx842_OF_upd_status
- spi: spi-sun6i: Fix chipselect/clock bug
- lockdep/selftests: Fix selftests vs PROVE_RAW_LOCK_NESTING
- lockdep: Fix wait-type for empty stack
- sched/uclamp: Fix uclamp_tg_restrict()
- sched/rt: Fix Deadline utilization tracking during policy change
- sched/rt: Fix RT utilization tracking during policy change
- x86/sev: Split up runtime #VC handler for correct state tracking
- x86/sev: Make sure IRQs are disabled while GHCB is active
- btrfs: clear log tree recovering status if starting transaction fails
- regulator: hi655x: Fix pass wrong pointer to config.driver_data
- KVM: arm64: Don't zero the cycle count register when PMCR_EL0.P is set
- perf/arm-cmn: Fix invalid pointer when access dtc object sharing the same IRQ number
- KVM: x86/mmu: Fix return value in tdp_mmu_map_handle_target_level()
- KVM: nVMX: Don't clobber nested MMU's A/D status on EPTP switch
- KVM: nVMX: Ensure 64-bit shift when checking VMFUNC bitmap
- KVM: nVMX: Sync all PGDs on nested transition with shadow paging
- hwmon: (max31790) Fix fan speed reporting for fan7..12
- hwmon: (max31722) Remove non-standard ACPI device IDs
- hwmon: (lm70) Revert "hwmon: (lm70) Add support for ACPI"
- hwmon: (lm70) Use device_get_match_data()
- media: s5p-g2d: Fix a memory leak on ctx->fh.m2m_ctx
- media: subdev: remove VIDIOC_DQEVENT_TIME32 handling
- arm64/mm: Fix ttbr0 values stored in struct thread_info for software-pan
- arm64: consistently use reserved_pg_dir
- mmc: usdhi6rol0: fix error return code in usdhi6_probe()
- crypto: sm2 - fix a memory leak in sm2
- crypto: sm2 - remove unnecessary reset operations
- crypto: x86/curve25519 - fix cpu feature checking logic in mod_exit
- crypto: omap-sham - Fix PM reference leak in omap sham ops
- crypto: nitrox - fix unchecked variable in nitrox_register_interrupts
- regulator: fan53880: Fix vsel_mask setting for FAN53880_BUCK
- media: siano: Fix out-of-bounds warnings in smscore_load_firmware_family2()
- m68k: atari: Fix ATARI_KBD_CORE kconfig unmet dependency warning
- media: gspca/gl860: fix zero-length control requests
- media: tc358743: Fix error return code in tc358743_probe_of()
- media: au0828: fix a NULL vs IS_ERR() check
- media: exynos4-is: Fix a use after free in isp_video_release
- media: rkvdec: Fix .buf_prepare
- locking/lockdep: Reduce LOCKDEP dependency list
- pata_ep93xx: fix deferred probing
- media: rc: i2c: Fix an error message
- crypto: ccp - Fix a resource leak in an error handling path
- crypto: sa2ul - Fix pm_runtime enable in sa_ul_probe()
- crypto: sa2ul - Fix leaks on failure paths with sa_dma_init()
- x86/elf: Use _BITUL() macro in UAPI headers
- evm: fix writing <securityfs>/evm overflow
- pata_octeon_cf: avoid WARN_ON() in ata_host_activate()
- kbuild: Fix objtool dependency for 'OBJECT_FILES_NON_STANDARD_<obj> := n'
- sched/uclamp: Fix locking around cpu_util_update_eff()
- sched/uclamp: Fix wrong implementation of cpu.uclamp.min
- media: I2C: change 'RST' to "RSET" to fix multiple build errors
- pata_rb532_cf: fix deferred probing
- sata_highbank: fix deferred probing
- crypto: ux500 - Fix error return code in hash_hw_final()
- crypto: ixp4xx - update IV after requests
- crypto: ixp4xx - dma_unmap the correct address
- media: hantro: do a PM resume earlier
- media: s5p_cec: decrement usage count if disabled
- media: venus: Rework error fail recover logic
- spi: Avoid undefined behaviour when counting unused native CSs
- spi: Allow to have all native CSs in use along with GPIOs
- writeback, cgroup: increment isw_nr_in_flight before grabbing an inode
- ia64: mca_drv: fix incorrect array size calculation
- kthread_worker: fix return value when kthread_mod_delayed_work() races with kthread_cancel_delayed_work_sync()
- block: fix discard request merge
- mailbox: qcom: Use PLATFORM_DEVID_AUTO to register platform device
- cifs: fix missing spinlock around update to ses->status
- HID: wacom: Correct base usage for capacitive ExpressKey status bits
- ACPI: tables: Add custom DSDT file as makefile prerequisite
- tpm_tis_spi: add missing SPI device ID entries
- clocksource: Check per-CPU clock synchronization when marked unstable
- clocksource: Retry clock read if long delays detected
- ACPI: EC: trust DSDT GPE for certain HP laptop
- cifs: improve fallocate emulation
- PCI: hv: Add check for hyperv_initialized in init_hv_pci_drv()
- EDAC/Intel: Do not load EDAC driver when running as a guest
- nvmet-fc: do not check for invalid target port in nvmet_fc_handle_fcp_rqst()
- nvme-pci: fix var. type for increasing cq_head
- platform/x86: toshiba_acpi: Fix missing error code in toshiba_acpi_setup_keyboard()
- platform/x86: asus-nb-wmi: Revert "add support for ASUS ROG Zephyrus G14 and G15"
- platform/x86: asus-nb-wmi: Revert "Drop duplicate DMI quirk structures"
- block: fix race between adding/removing rq qos and normal IO
- ACPI: resources: Add checks for ACPI IRQ override
- ACPI: bus: Call kobject_put() in acpi_init() error path
- ACPICA: Fix memory leak caused by _CID repair function
- fs: dlm: fix memory leak when fenced
- drivers: hv: Fix missing error code in vmbus_connect()
- open: don't silently ignore unknown O-flags in openat2()
- random32: Fix implicit truncation warning in prandom_seed_state()
- fs: dlm: cancel work sync othercon
- blk-mq: clear stale request in tags->rq[] before freeing one request pool
- blk-mq: grab rq->refcount before calling ->fn in blk_mq_tagset_busy_iter
- ACPI: EC: Make more Asus laptops use ECDT _GPE
- platform/x86: touchscreen_dmi: Add info for the Goodix GT912 panel of TM800A550L tablets
- platform/x86: touchscreen_dmi: Add an extra entry for the upside down Goodix touchscreen on Teclast X89 tablets
- Input: goodix - platform/x86: touchscreen_dmi - Move upside down quirks to touchscreen_dmi.c
- lib: vsprintf: Fix handling of number field widths in vsscanf
- hv_utils: Fix passing zero to 'PTR_ERR' warning
- ACPI: processor idle: Fix up C-state latency if not ordered
- EDAC/ti: Add missing MODULE_DEVICE_TABLE
- HID: do not use down_interruptible() when unbinding devices
- ACPI: video: use native backlight for GA401/GA502/GA503
- media: Fix Media Controller API config checks
- regulator: da9052: Ensure enough delay time for .set_voltage_time_sel
- regulator: mt6358: Fix vdram2 .vsel_mask
- KVM: s390: get rid of register asm usage
- lockding/lockdep: Avoid to find wrong lock dep path in check_irq_usage()
- locking/lockdep: Fix the dep path printing for backwards BFS
- btrfs: disable build on platforms having page size 256K
- btrfs: don't clear page extent mapped if we're not invalidating the full page
- btrfs: sysfs: fix format string for some discard stats
- btrfs: abort transaction if we fail to update the delayed inode
- btrfs: fix error handling in __btrfs_update_delayed_inode
- KVM: PPC: Book3S HV: Fix TLB management on SMT8 POWER9 and POWER10 processors
- drivers/perf: fix the missed ida_simple_remove() in ddr_perf_probe()
- hwmon: (max31790) Fix pwmX_enable attributes
- hwmon: (max31790) Report correct current pwm duty cycles
- media: imx-csi: Skip first few frames from a BT.656 source
- media: siano: fix device register error path
- media: dvb_net: avoid speculation from net slot
- crypto: shash - avoid comparing pointers to exported functions under CFI
- spi: meson-spicc: fix memory leak in meson_spicc_probe
- spi: meson-spicc: fix a wrong goto jump for avoiding memory leak.
- mmc: via-sdmmc: add a check against NULL pointer dereference
- mmc: sdhci-sprd: use sdhci_sprd_writew
- memstick: rtsx_usb_ms: fix UAF
- media: dvd_usb: memory leak in cinergyt2_fe_attach
- Makefile: fix GDB warning with CONFIG_RELR
- media: st-hva: Fix potential NULL pointer dereferences
- media: bt8xx: Fix a missing check bug in bt878_probe
- media: v4l2-core: Avoid the dangling pointer in v4l2_fh_release
- media: cedrus: Fix .buf_prepare
- media: hantro: Fix .buf_prepare
- media: em28xx: Fix possible memory leak of em28xx struct
- media: bt878: do not schedule tasklet when it is not setup
- media: i2c: ov2659: Use clk_{prepare_enable,disable_unprepare}() to set xvclk on/off
- sched/fair: Fix ascii art by relpacing tabs
- arm64: perf: Convert snprintf to sysfs_emit
- crypto: qce: skcipher: Fix incorrect sg count for dma transfers
- crypto: qat - remove unused macro in FW loader
- crypto: qat - check return code of qat_hal_rd_rel_reg()
- media: imx: imx7_mipi_csis: Fix logging of only error event counters
- media: pvrusb2: fix warning in pvr2_i2c_core_done
- media: hevc: Fix dependent slice segment flags
- media: cobalt: fix race condition in setting HPD
- media: cpia2: fix memory leak in cpia2_usb_probe
- media: sti: fix obj-$(config) targets
- crypto: nx - add missing MODULE_DEVICE_TABLE
- hwrng: exynos - Fix runtime PM imbalance on error
- sched/core: Initialize the idle task with preemption disabled
- regulator: uniphier: Add missing MODULE_DEVICE_TABLE
- spi: omap-100k: Fix the length judgment problem
- spi: spi-topcliff-pch: Fix potential double free in pch_spi_process_messages()
- spi: spi-loopback-test: Fix 'tx_buf' might be 'rx_buf'
- media: exynos-gsc: fix pm_runtime_get_sync() usage count
- media: exynos4-is: fix pm_runtime_get_sync() usage count
- media: sti/bdisp: fix pm_runtime_get_sync() usage count
- media: sunxi: fix pm_runtime_get_sync() usage count
- media: s5p-jpeg: fix pm_runtime_get_sync() usage count
- media: mtk-vcodec: fix PM runtime get logic
- media: sh_vou: fix pm_runtime_get_sync() usage count
- media: am437x: fix pm_runtime_get_sync() usage count
- media: s5p: fix pm_runtime_get_sync() usage count
- media: mdk-mdp: fix pm_runtime_get_sync() usage count
- media: marvel-ccic: fix some issues when getting pm_runtime
- staging: media: rkvdec: fix pm_runtime_get_sync() usage count
- Add a reference to ucounts for each cred
- spi: Make of_register_spi_device also set the fwnode
- thermal/cpufreq_cooling: Update offline CPUs per-cpu thermal_pressure
- fuse: reject internal errno
- fuse: check connected before queueing on fpq->io
- fuse: ignore PG_workingset after stealing
- fuse: Fix infinite loop in sget_fc()
- fuse: Fix crash if superblock of submount gets killed early
- fuse: Fix crash in fuse_dentry_automount() error path
- evm: Refuse EVM_ALLOW_METADATA_WRITES only if an HMAC key is loaded
- loop: Fix missing discard support when using LOOP_CONFIGURE
- powerpc/stacktrace: Fix spurious "stale" traces in raise_backtrace_ipi()
- seq_buf: Make trace_seq_putmem_hex() support data longer than 8
- tracepoint: Add tracepoint_probe_register_may_exist() for BPF tracing
- tracing/histograms: Fix parsing of "sym-offset" modifier
- rsi: fix AP mode with WPA failure due to encrypted EAPOL
- rsi: Assign beacon rate settings to the correct rate_info descriptor field
- ssb: sdio: Don't overwrite const buffer if block_write fails
- ath9k: Fix kernel NULL pointer dereference during ath_reset_internal()
- serial_cs: remove wrong GLOBETROTTER.cis entry
- serial_cs: Add Option International GSM-Ready 56K/ISDN modem
- serial: sh-sci: Stop dmaengine transfer in sci_stop_tx()
- serial: mvebu-uart: fix calculation of clock divisor
- iio: accel: bma180: Fix BMA25x bandwidth register values
- iio: ltr501: ltr501_read_ps(): add missing endianness conversion
- iio: ltr501: ltr559: fix initialization of LTR501_ALS_CONTR
- iio: ltr501: mark register holding upper 8 bits of ALS_DATA{0,1} and PS_DATA as volatile, too
- iio: light: tcs3472: do not free unallocated IRQ
- iio: frequency: adf4350: disable reg and clk on error in adf4350_probe()
- rtc: stm32: Fix unbalanced clk_disable_unprepare() on probe error path
- clk: agilex/stratix10: fix bypass representation
- clk: agilex/stratix10: remove noc_clk
- clk: agilex/stratix10/n5x: fix how the bypass_reg is handled
- f2fs: Prevent swap file in LFS mode
- s390: mm: Fix secure storage access exception handling
- s390/cio: dont call css_wait_for_slow_path() inside a lock
- KVM: x86/mmu: Use MMU's role to detect CR4.SMEP value in nested NPT walk
- KVM: x86/mmu: Treat NX as used (not reserved) for all !TDP shadow MMUs
- KVM: PPC: Book3S HV: Workaround high stack usage with clang
- KVM: nVMX: Handle split-lock #AC exceptions that happen in L2
- mm/gup: fix try_grab_compound_head() race with split_huge_page()
- bus: mhi: Wait for M2 state during system resume
- mac80211: remove iwlwifi specific workaround that broke sta NDP tx
- can: peak_pciefd: pucan_handle_status(): fix a potential starvation issue in TX path
- can: j1939: j1939_sk_init(): set SOCK_RCU_FREE to call sk_destruct() after RCU is done
- can: isotp: isotp_release(): omit unintended hrtimer restart on socket release
- can: gw: synchronize rcu operations before removing gw job entry
- can: bcm: delay release of struct bcm_op after synchronize_rcu()
- ext4: use ext4_grp_locked_error in mb_find_extent
- ext4: fix avefreec in find_group_orlov
- ext4: remove check for zero nr_to_scan in ext4_es_scan()
- ext4: correct the cache_nr in tracepoint ext4_es_shrink_exit
- ext4: return error code when ext4_fill_flex_info() fails
- ext4: fix overflow in ext4_iomap_alloc()
- ext4: fix kernel infoleak via ext4_extent_header
- btrfs: clear defrag status of a root if starting transaction fails
- btrfs: compression: don't try to compress if we don't have enough pages
- btrfs: send: fix invalid path for unlink operations after parent orphanization
- ARM: dts: at91: sama5d4: fix pinctrl muxing
- ARM: dts: ux500: Fix LED probing
- crypto: ccp - Annotate SEV Firmware file names
- crypto: nx - Fix memcpy() over-reading in nonce
- Input: joydev - prevent use of not validated data in JSIOCSBTNMAP ioctl
- iov_iter_fault_in_readable() should do nothing in xarray case
- copy_page_to_iter(): fix ITER_DISCARD case
- selftests/lkdtm: Avoid needing explicit sub-shell
- ntfs: fix validity check for file name attribute
- gfs2: Fix error handling in init_statfs
- gfs2: Fix underflow in gfs2_page_mkwrite
- xhci: solve a double free problem while doing s4
- usb: typec: Add the missed altmode_id_remove() in typec_register_altmode()
- usb: dwc3: Fix debugfs creation flow
- USB: cdc-acm: blacklist Heimann USB Appset device
- usb: renesas-xhci: Fix handling of unknown ROM state
- usb: gadget: eem: fix echo command packet response issue
- net: can: ems_usb: fix use-after-free in ems_usb_disconnect()
- Input: usbtouchscreen - fix control-request directions
- media: dvb-usb: fix wrong definition
- ALSA: hda/realtek: fix mute/micmute LEDs for HP EliteBook 830 G8 Notebook PC
- ALSA: hda/realtek: Apply LED fixup for HP Dragonfly G1, too
- ALSA: hda/realtek: Fix bass speaker DAC mapping for Asus UM431D
- ALSA: hda/realtek: Improve fixup for HP Spectre x360 15-df0xxx
- ALSA: hda/realtek: fix mute/micmute LEDs for HP EliteBook x360 830 G8
- ALSA: hda/realtek: Add another ALC236 variant support
- ALSA: hda/realtek: fix mute/micmute LEDs for HP ProBook 630 G8
- ALSA: hda/realtek: fix mute/micmute LEDs for HP ProBook 445 G8
- ALSA: hda/realtek: fix mute/micmute LEDs for HP ProBook 450 G8
- ALSA: intel8x0: Fix breakage at ac97 clock measurement
- ALSA: usb-audio: scarlett2: Fix wrong resume call
- ALSA: firewire-motu: fix stream format for MOTU 8pre FireWire
- ALSA: usb-audio: Fix OOB access at proc output
- ALSA: usb-audio: fix rate on Ozone Z90 USB headset
- Bluetooth: Remove spurious error message
- Bluetooth: btqca: Don't modify firmware contents in-place
- Bluetooth: hci_qca: fix potential GPF
- Revert "evm: Refuse EVM_ALLOW_METADATA_WRITES only if an HMAC key is loaded"
- configfs: fix memleak in configfs_release_bin_file
- init: only move down lockup_detector_init() when sdei_watchdog is enabled
- arm64: fix AUDIT_ARCH_AARCH64ILP32 bug on audit subsystem
- ext4: cleanup in-core orphan list if ext4_truncate() failed to get a transaction handle
- ext4: fix WARN_ON_ONCE(!buffer_uptodate) after an error writing the superblock
- tty/serial/imx: Enable TXEN bit in imx_poll_init().
- xen/events: reset active flag for lateeoi events later
- Hexagon: change jumps to must-extend in futex_atomic_*
- Hexagon: add target builtins to kernel
- Hexagon: fix build errors
- media: uvcvideo: Support devices that report an OT as an entity source
- KVM: PPC: Book3S HV: Save and restore FSCR in the P9 path
- ubifs: Remove ui_mutex in ubifs_xattr_get and change_xattr
- ubifs: Fix races between xattr_{set|get} and listxattr operations
- block: stop wait rcu once we can ensure no io while elevator init
- writeback: don't warn on an unregistered BDI in __mark_inode_dirty
- mm/page_isolation: do not isolate the max order page
- mm/zswap: fix passing zero to 'PTR_ERR' warning
- mm/page_alloc: speed up the iteration of max_order
- mm: hugetlb: fix type of delta parameter and related local variables in gather_surplus_pages()
- mm: vmalloc: prevent use after free in _vm_unmap_aliases
- arm32: kaslr: Fix the bitmap error
- net: make sure devices go through netdev_wait_all_refs
- net: fib_notifier: don't return positive values on fib registration
- netfilter: nftables: avoid potential overflows on 32bit arches
- netfilter: Dissect flow after packet mangling
- net: fix a concurrency bug in l2tp_tunnel_register()
- ext4: fix possible UAF when remounting r/o a mmp-protected file system
- SUNRPC: Should wake up the privileged task firstly.
- SUNRPC: Fix the batch tasks count wraparound.
- Revert "KVM: x86/mmu: Drop kvm_mmu_extended_role.cr4_la57 hack"
- RDMA/mlx5: Block FDB rules when not in switchdev mode
- gpio: AMD8111 and TQMX86 require HAS_IOPORT_MAP
- drm/nouveau: fix dma_address check for CPU/GPU sync
- gpio: mxc: Fix disabled interrupt wake-up support
- scsi: sr: Return appropriate error code when disk is ejected
- arm64: seccomp: fix compilation error with ILP32 support
- scsi: sd: block: Fix regressions in read-only block device handling
- integrity: Load mokx variables into the blacklist keyring
- certs: Add ability to preload revocation certs
- certs: Move load_system_certificate_list to a common function
- certs: Add EFI_CERT_X509_GUID support for dbx entries
- Revert "drm: add a locked version of drm_is_current_master"
- netfs: fix test for whether we can skip read when writing beyond EOF
- swiotlb: manipulate orig_addr when tlb_addr has offset
- KVM: SVM: Call SEV Guest Decommission if ASID binding fails
- mm, futex: fix shared futex pgoff on shmem huge page
- mm/thp: another PVMW_SYNC fix in page_vma_mapped_walk()
- mm/thp: fix page_vma_mapped_walk() if THP mapped by ptes
- mm: page_vma_mapped_walk(): get vma_address_end() earlier
- mm: page_vma_mapped_walk(): use goto instead of while (1)
- mm: page_vma_mapped_walk(): add a level of indentation
- mm: page_vma_mapped_walk(): crossing page table boundary
- mm: page_vma_mapped_walk(): prettify PVMW_MIGRATION block
- mm: page_vma_mapped_walk(): use pmde for *pvmw->pmd
- mm: page_vma_mapped_walk(): settle PageHuge on entry
- mm: page_vma_mapped_walk(): use page for pvmw->page
- mm: thp: replace DEBUG_VM BUG with VM_WARN when unmap fails for split
- mm/thp: unmap_mapping_page() to fix THP truncate_cleanup_page()
- mm/thp: fix page_address_in_vma() on file THP tails
- mm/thp: fix vma_address() if virtual address below file offset
- mm/thp: try_to_unmap() use TTU_SYNC for safe splitting
- mm/thp: make is_huge_zero_pmd() safe and quicker
- mm/thp: fix __split_huge_pmd_locked() on shmem migration entry
- mm, thp: use head page in __migration_entry_wait()
- mm/rmap: use page_not_mapped in try_to_unmap()
- mm/rmap: remove unneeded semicolon in page_not_mapped()
- mm: add VM_WARN_ON_ONCE_PAGE() macro
- x86/fpu: Make init_fpstate correct with optimized XSAVE
- x86/fpu: Preserve supervisor states in sanitize_restored_user_xstate()
- kthread: prevent deadlock when kthread_mod_delayed_work() races with kthread_cancel_delayed_work_sync()
- kthread_worker: split code for canceling the delayed work timer
- ceph: must hold snap_rwsem when filling inode for async create
- i2c: robotfuzz-osif: fix control-request directions
- KVM: do not allow mapping valid but non-reference-counted pages
- s390/stack: fix possible register corruption with stack switch helper
- nilfs2: fix memory leak in nilfs_sysfs_delete_device_group
- gpiolib: cdev: zero padding during conversion to gpioline_info_changed
- i2c: i801: Ensure that SMBHSTSTS_INUSE_STS is cleared when leaving i801_access
- pinctrl: stm32: fix the reported number of GPIO lines per bank
- perf/x86: Track pmu in per-CPU cpu_hw_events
- net: ll_temac: Avoid ndo_start_xmit returning NETDEV_TX_BUSY
- net: ll_temac: Add memory-barriers for TX BD access
- PCI: Add AMD RS690 quirk to enable 64-bit DMA
- recordmcount: Correct st_shndx handling
- mac80211: handle various extensible elements correctly
- mac80211: reset profile_periodicity/ema_ap
- net: qed: Fix memcpy() overflow of qed_dcbx_params()
- KVM: selftests: Fix kvm_check_cap() assertion
- r8169: Avoid memcpy() over-reading of ETH_SS_STATS
- sh_eth: Avoid memcpy() over-reading of ETH_SS_STATS
- r8152: Avoid memcpy() over-reading of ETH_SS_STATS
- net/packet: annotate accesses to po->ifindex
- net/packet: annotate accesses to po->bind
- net: caif: fix memory leak in ldisc_open
- riscv32: Use medany C model for modules
- net: phy: dp83867: perform soft reset and retain established link
- net/packet: annotate data race in packet_sendmsg()
- inet: annotate date races around sk->sk_txhash
- net: annotate data race in sock_error()
- ping: Check return value of function 'ping_queue_rcv_skb'
- inet: annotate data race in inet_send_prepare() and inet_dgram_connect()
- net: ethtool: clear heap allocations for ethtool function
- mac80211: drop multicast fragments
- net: ipv4: Remove unneed BUG() function
- dmaengine: mediatek: use GFP_NOWAIT instead of GFP_ATOMIC in prep_dma
- dmaengine: mediatek: do not issue a new desc if one is still current
- dmaengine: mediatek: free the proper desc in desc_free handler
- dmaengine: rcar-dmac: Fix PM reference leak in rcar_dmac_probe()
- cfg80211: call cfg80211_leave_ocb when switching away from OCB
- mac80211_hwsim: drop pending frames on stop
- mac80211: remove warning in ieee80211_get_sband()
- dmaengine: xilinx: dpdma: Limit descriptor IDs to 16 bits
- dmaengine: xilinx: dpdma: Add missing dependencies to Kconfig
- dmaengine: stm32-mdma: fix PM reference leak in stm32_mdma_alloc_chan_resourc()
- dmaengine: zynqmp_dma: Fix PM reference leak in zynqmp_dma_alloc_chan_resourc()
- perf/x86/intel/lbr: Zero the xstate buffer on allocation
- perf/x86/lbr: Remove cpuc->lbr_xsave allocation from atomic context
- locking/lockdep: Improve noinstr vs errors
- x86/xen: Fix noinstr fail in exc_xen_unknown_trap()
- x86/entry: Fix noinstr fail in __do_fast_syscall_32()
- drm/vc4: hdmi: Make sure the controller is powered in detect
- drm/vc4: hdmi: Move the HSM clock enable to runtime_pm
- Revert "PCI: PM: Do not read power state in pci_enable_device_flags()"
- spi: spi-nxp-fspi: move the register operation after the clock enable
- arm64: Ignore any DMA offsets in the max_zone_phys() calculation
- MIPS: generic: Update node names to avoid unit addresses
- mmc: meson-gx: use memcpy_to/fromio for dram-access-quirk
- ARM: 9081/1: fix gcc-10 thumb2-kernel regression
- drm/amdgpu: wait for moving fence after pinning
- drm/radeon: wait for moving fence after pinning
- drm/nouveau: wait for moving fence after pinning v2
- drm: add a locked version of drm_is_current_master
- Revert "drm/amdgpu/gfx10: enlarge CP_MEC_DOORBELL_RANGE_UPPER to cover full doorbell."
- Revert "drm/amdgpu/gfx9: fix the doorbell missing when in CGPG issue."
- module: limit enabling module.sig_enforce
- scsi: core: Treat device offline as a failure
- blk-wbt: make sure throttle is enabled properly
- blk-wbt: introduce a new disable state to prevent false positive by rwb_enabled()
- arm64: fpsimd: run kernel mode NEON with softirqs disabled
- arm64: assembler: introduce wxN aliases for wN registers
- arm64: assembler: remove conditional NEON yield macros
- crypto: arm64/crc-t10dif - move NEON yield to C code
- crypto: arm64/aes-ce-mac - simplify NEON yield
- crypto: arm64/aes-neonbs - remove NEON yield calls
- crypto: arm64/sha512-ce - simplify NEON yield
- crypto: arm64/sha3-ce - simplify NEON yield
- crypto: arm64/sha2-ce - simplify NEON yield
- crypto: arm64/sha1-ce - simplify NEON yield
- arm64: assembler: add cond_yield macro
- mm: fix page reference leak in soft_offline_page()
- block_dump: remove comments in docs
- block_dump: remove block_dump feature
- block_dump: remove block_dump feature in mark_inode_dirty()
- crypto: sun8i-ce - fix error return code in sun8i_ce_prng_generate()
- crypto: nx - add missing call to of_node_put()
- net: hns3: fix a return value error in hclge_get_reset_status()
- net: hns3: check vlan id before using it
- net: hns3: check queue id range before using
- net: hns3: fix misuse vf id and vport id in some logs
- net: hns3: fix inconsistent vf id print
- net: hns3: fix change RSS 'hfunc' ineffective issue
- net: hns3: fix the timing issue of VF clearing interrupt sources
- net: hns3: fix the exception when query imp info
- net: hns3: disable mac in flr process
- net: hns3: change affinity_mask to numa node range
- net: hns3: pad the short tunnel frame before sending to hardware
- net: hns3: make hclgevf_cmd_caps_bit_map0 and hclge_cmd_caps_bit_map0 static
- imans: Use initial ima namespace domain tag when IMANS is disabled.
- IOMMU: SMMUv2: Bypass SMMU in default for some SoCs
- arm64: phytium: using MIDR_PHYTIUM_FT2000PLUS instead of ARM_CPU_IMP_PHYTIUM
- arm64: Add MIDR encoding for PHYTIUM CPUs
- arm64: Add MIDR encoding for HiSilicon Taishan CPUs
- usb: xhci: Add workaround for phytium
- arm64: topology: Support PHYTIUM CPU
- hugetlb: pass head page to remove_hugetlb_page()
- userfaultfd: hugetlbfs: fix new flag usage in error path
- hugetlb: fix uninitialized subpool pointer
- percpu: flush tlb in pcpu_reclaim_populated()
- percpu: implement partial chunk depopulation
- percpu: use pcpu_free_slot instead of pcpu_nr_slots - 1
- percpu: factor out pcpu_check_block_hint()
- percpu: split __pcpu_balance_workfn()
- percpu: fix a comment about the chunks ordering
- slub: fix kmalloc_pagealloc_invalid_free unit test
- slub: fix unreclaimable slab stat for bulk free
- net: hns3: remove unnecessary spaces
- net: hns3: add some required spaces
- net: hns3: clean up a type mismatch warning
- net: hns3: refine function hns3_set_default_feature()
- net: hns3: uniform parameter name of hclge_ptp_clean_tx_hwts()
- net: hnss3: use max() to simplify code
- net: hns3: modify a print format of hns3_dbg_queue_map()
- net: hns3: refine function hclge_dbg_dump_tm_pri()
- net: hns3: reconstruct function hclge_ets_validate()
- net: hns3: reconstruct function hns3_self_test
- net: hns3: initialize each member of structure array on a separate line
- net: hns3: add required space in comment
- net: hns3: remove unnecessary "static" of local variables in function
- net: hns3: don't config TM DWRR twice when set ETS
- net: hns3: add new function hclge_get_speed_bit()
- net: hns3: refactor function hclgevf_parse_capability()
- net: hns3: refactor function hclge_parse_capability()
- net: hns3: add trace event in hclge_gen_resp_to_vf()
- net: hns3: uniform type of function parameter cmd
- net: hns3: merge some repetitive macros
- net: hns3: package new functions to simplify hclgevf_mbx_handler code
- net: hns3: remove redundant param to simplify code
- net: hns3: use memcpy to simplify code
- net: hns3: remove redundant param mbx_event_pending
- net: hns3: add hns3_state_init() to do state initialization
- net: hns3: add macros for mac speeds of firmware command
- sched: bugfix setscheduler unlock cpuset_rwsem
- ima: fix db size overflow and Kconfig issues
- mm: page_poison: print page info when corruption is caught
- kasan: fix conflict with page poisoning
- mm: fix page_owner initializing issue for arm32
- net: hns3: add ethtool support for CQE/EQE mode configuration
- net: hns3: add support for EQE/CQE mode configuration
- ethtool: extend coalesce setting uAPI with CQE mode
- ethtool: add two coalesce attributes for CQE mode
- ethtool: add ETHTOOL_COALESCE_ALL_PARAMS define
- net: hns3: fix get wrong pfc_en when query PFC configuration
- net: hns3: fix GRO configuration error after reset
- net: hns3: change the method of getting cmd index in debugfs
- net: hns3: fix duplicate node in VLAN list
- net: hns3: fix speed unknown issue in bond 4
- net: hns3: add waiting time before cmdq memory is released
- net: hns3: clear hardware resource when loading driver
- net: hns3: make array spec_opcode static const, makes object smaller
- digest list: disable digest lists in non-root ima namespaces
- ima: Introduce ima-ns-sig template
- ima: fix a potential crash owing to the compiler optimisation
- ima: Set ML template per ima namespace
- ima: Add dummy boot aggregate to per ima namespace measurement list
- ima: Load per ima namespace x509 certificate
- integrity: Add key domain tag to the search criteria
- ima: Add key domain to the ima namespace
- keys: Allow to set key domain tag separately from the key type
- keys: Include key domain tag in the iterative search
- keys: Add domain tag to the keyring search criteria
- ima: Remap IDs of subject based rules if necessary
- user namespace: Add function that checks if the UID map is defined
- ima: Parse per ima namespace policy file
- ima: Configure the new ima namespace from securityfs
- ima: Change the owning user namespace of the ima namespace if necessary
- ima: Add the violation counter to the namespace
- ima: Extend permissions to the ima securityfs entries
- ima: Add a reader counter to the integrity inode data
- ima: Add per namespace view of the measurement list
- ima: Add a new ima template that includes namespace ID
- ima: Check ima namespace ID during digest entry lookup
- ima: Keep track of the measurment list per ima namespace
- ima: Add ima namespace id to the measurement list related structures
- ima: Enable per ima namespace policy settings
- ima: Add integrity inode related data to the ima namespace
- ima: Extend the APIs in the integrity subsystem
- ima: Add ima namespace to the ima subsystem APIs
- ima: Add methods for parsing ima policy configuration string
- ima: Add ima policy related data to the ima namespace
- ima: Bind ima namespace to the file descriptor
- ima: Add a list of the installed ima namespaces
- ima: Introduce ima namespace
- mm/page_alloc: further fix __alloc_pages_bulk() return value
- mm/page_alloc: correct return value when failing at preparing
- mm/page_alloc: avoid page allocator recursion with pagesets.lock held
- mm: vmscan: shrink deferred objects proportional to priority
- mm: memcontrol: reparent nr_deferred when memcg offline
- mm: vmscan: don't need allocate shrinker->nr_deferred for memcg aware shrinkers
- mm: vmscan: use per memcg nr_deferred of shrinker
- mm: vmscan: add per memcg shrinker nr_deferred
- mm: vmscan: use a new flag to indicate shrinker is registered
- mm: vmscan: add shrinker_info_protected() helper
- mm: memcontrol: rename shrinker_map to shrinker_info
- mm: vmscan: use kvfree_rcu instead of call_rcu
- mm: vmscan: remove memcg_shrinker_map_size
- mm: vmscan: use shrinker_rwsem to protect shrinker_maps allocation
- mm: vmscan: consolidate shrinker_maps handling code
- mm: vmscan: use nid from shrink_control for tracepoint
- scsi/hifc: Fix memory leakage bug
- crypto: hisilicon/qm - set a qp error flag for userspace
- vfio/hisilicon: add acc live migration driver
- vfio/hisilicon: modify QM for live migration driver
- vfio/pci: provide customized live migration VFIO driver framework
- PCI: Set dma-can-stall for HiSilicon chips
- PCI: Add a quirk to set pasid_no_tlp for HiSilicon chips
- PCI: PASID can be enabled without TLP prefix
- crypto: hisilicon/sec - fix the CTR mode BD configuration
- crypto: hisilicon/sec - fix the max length of AAD for the CCM mode
- crypto: hisilicon/sec - fixup icv checking enabled on Kunpeng 930
- crypto: hisilicon - check _PS0 and _PR0 method
- crypto: hisilicon - change parameter passing of debugfs function
- crypto: hisilicon - support runtime PM for accelerator device
- crypto: hisilicon - add runtime PM ops
- crypto: hisilicon - using 'debugfs_create_file' instead of 'debugfs_create_regset32'
- crypto: hisilicon/sec - modify the hardware endian configuration
- crypto: hisilicon/sec - fix the abnormal exiting process
- crypto: hisilicon - enable hpre device clock gating
- crypto: hisilicon - enable sec device clock gating
- crypto: hisilicon - enable zip device clock gating
- crypto: hisilicon/sec - fix the process of disabling sva prefetching

* Web Sep 15 2021 Zheng Zengkai <zhengzengkai@huawei.com> - 5.10.0-6.0.0.0
- mm/page_alloc: correct return value of populated elements if bulk array is populated
- mm: fix oom killing for disabled pid
- X86/config: Enable CONFIG_USERSWAP
- eulerfs: change default config file
- eulerfs: add Kconfig and Makefile
- eulerfs: add super_operations and module_init/exit
- eulerfs: add inode_operations for symlink inode
- eulerfs: add file_operations for dir inode
- eulerfs: add inode_operations for dir inode and special inode
- eulerfs: add file operations and inode operations for regular file
- eulerfs: add dax operations
- eulerfs: add inode related interfaces
- eulerfs: add dependency operations
- eulerfs: add nv dict operations
- eulerfs: add filename interfaces
- eulerfs: add interfaces for page wear
- eulerfs: add interfaces for inode lock transfer
- eulerfs: add flush interfaces
- eulerfs: add memory allocation interfaces
- eulerfs: add kmeme_cache definitions and interfaces
- eulerfs: common definitions
- vfio/pci: Fix wrong return value when get iommu attribute DOMAIN_ATTR_NESTING
- net: hns3: remove always exist devlink pointer check
- net: hns3: add support ethtool extended link state
- net: hns3: add header file hns3_ethtoo.h
- ethtool: add two link extended substates of bad signal integrity
- docs: ethtool: Add two link extended substates of bad signal integrity
- net: hns3: add support for triggering reset by ethtool

* Mon Aug 16 2021 Yafen Fang<yafen@iscas.ac.cn> - 5.10.0-5.3.0.2
- package init based on openEuler 5.10.0-5.3.0

* Mon Aug 9  2021 Yafen Fang<yafen@iscas.ac.cn> - 5.10.0-5.1.0.1
- package init based on openEuler 5.10.0-5.1.0
