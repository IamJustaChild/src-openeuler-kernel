%define with_signmodules  1
%define with_kabichk 0

# Default without toolchain_clang
%bcond_with toolchain_clang

%if %{with toolchain_clang}
%global toolchain clang
%endif

%bcond_with clang_lto

%if %{with clang_lto} && "%{toolchain}" != "clang"
{error:clang_lto requires --with toolchain_clang}
%endif

%define modsign_cmd %{SOURCE10}

%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/ -e s/riscv.*/riscv/ -e s/powerpc64le/powerpc/)

%global KernelVer %{version}-%{release}.%{_target_cpu}
%global debuginfodir /usr/lib/debug

%global upstream_version    6.6
%global upstream_sublevel   0
%global devel_release       6
%global maintenance_release .0.0
%global pkg_release         .3

%define with_debuginfo 1
# Do not recompute the build-id of vmlinux in find-debuginfo.sh
%global _missing_build_ids_terminate_build 1
%global _no_recompute_build_ids 1
%undefine _include_minidebuginfo
%undefine _include_gdb_index
%undefine _unique_build_ids

%define with_source 1

%define with_python2 0

# failed if there is new config options
%define listnewconfig_fail 0

%ifarch aarch64
%define with_64kb  %{?_with_64kb: 1} %{?!_with_64kb: 0}
%if %{with_64kb}
%global package64kb -64kb
%endif
%else
%define with_64kb  0
%endif

#default is enabled. You can disable it with --without option
%define with_perf    %{?_without_perf: 0} %{?!_without_perf: 1}

Name:	 kernel%{?package64kb}
Version: %{upstream_version}.%{upstream_sublevel}
Release: %{devel_release}%{?maintenance_release}%{?pkg_release}
Summary: Linux Kernel
License: GPLv2
URL:	 http://www.kernel.org/
Source0: kernel.tar.gz
Source10: sign-modules
Source11: x509.genkey
Source12: extra_certificates
# openEuler RPM PGP certificates:
# 1. openeuler <openeuler@compass-ci.com>
Source13: RPM-GPG-KEY-openEuler-compass-ci
Source14: process_pgp_certs.sh

%if 0%{?with_kabichk}
Source18: check-kabi
Source20: Module.kabi_aarch64
Source21: Module.kabi_x86_64
%endif

Source200: mkgrub-menu-aarch64.sh

Source2000: cpupower.service
Source2001: cpupower.config

%if 0%{?with_patch}
Source9000: apply-patches
Source9001: guards
Source9002: series.conf
Source9998: patches.tar.bz2
%endif

Patch0002: 0002-cpupower-clang-compile-support.patch
Patch0003: 0003-x86_energy_perf_policy-clang-compile-support.patch
Patch0004: 0004-turbostat-clang-compile-support.patch

#BuildRequires:
BuildRequires: module-init-tools, patch >= 2.5.4, bash >= 2.03, tar
BuildRequires: bzip2, xz, findutils, gzip, m4, perl, make >= 3.78, diffutils, gawk
BuildRequires: libcap-devel, libcap-ng-devel, rsync
BuildRequires: gcc >= 3.4.2, binutils >= 2.12
BuildRequires: hostname, net-tools, bc
BuildRequires: xmlto, asciidoc
BuildRequires: openssl-devel openssl
BuildRequires: hmaccalc
BuildRequires: ncurses-devel
#BuildRequires: pesign >= 0.109-4
BuildRequires: elfutils-libelf-devel
BuildRequires: rpm >= 4.14.2
#BuildRequires: sparse >= 0.4.1
%if 0%{?with_python2}
BuildRequires: python-devel
%endif

BuildRequires: elfutils-devel zlib-devel binutils-devel newt-devel perl(ExtUtils::Embed) bison
BuildRequires: audit-libs-devel libpfm-devel libtraceevent-devel
BuildRequires: pciutils-devel gettext
BuildRequires: rpm-build, elfutils
BuildRequires: numactl-devel python3-devel glibc-static python3-docutils
BuildRequires: perl-generators perl(Carp) libunwind-devel gtk2-devel libbabeltrace-devel java-1.8.0-openjdk java-1.8.0-openjdk-devel perl-devel
AutoReq: no
AutoProv: yes

Conflicts: device-mapper-libs < 1.02.63-2 e2fsprogs < 1.37-4 initscripts < 7.23 iptables < 1.3.2-1
Conflicts: ipw2200-firmware < 2.4 isdn4k-utils < 3.2-32 iwl4965-firmware < 228.57.2 jfsutils < 1.1.7-2
Conflicts: mdadm < 3.2.1-5 nfs-utils < 1.0.7-12 oprofile < 0.9.1-2 ppp < 2.4.3-3 procps < 3.2.5-6.3
Conflicts: reiserfs-utils < 3.6.19-2 selinux-policy-targeted < 1.25.3-14 squashfs-tools < 4.0
Conflicts: udev < 063-6 util-linux < 2.12 wireless-tools < 29-3 xfsprogs < 2.6.13-4

Provides: kernel-%{_target_cpu} = %{version}-%{release} kernel-drm = 4.3.0 kernel-drm-nouveau = 16 kernel-modeset = 1
Provides: kernel-uname-r = %{KernelVer} kernel=%{KernelVer}

Requires: dracut >= 001-7 grubby >= 8.28-2 initscripts >= 8.11.1-1 linux-firmware >= 20100806-2 module-init-tools >= 3.16-2

ExclusiveArch: noarch aarch64 i686 x86_64 riscv64 ppc64le
ExclusiveOS: Linux

%if %{with_perf}
BuildRequires: flex xz-devel libzstd-devel
BuildRequires: java-devel
%endif

BuildRequires: dwarves
BuildRequires: clang >= 10.0.0
BuildRequires: llvm
%if %{with clang_lto}
BuildRequires: lld
%endif

%description
The Linux Kernel, the operating system core itself.

%package headers
Summary: Header files for the Linux kernel for use by glibc
Obsoletes: glibc-kernheaders < 3.0-46
Provides: glibc-kernheaders = 3.0-46
%description headers
Kernel-headers includes the C header files that specify the interface
between the Linux kernel and userspace libraries and programs.  The
header files define structures and constants that are needed for
building most standard programs and are also needed for rebuilding the
glibc package.


%package devel
Summary: Development package for building kernel modules to match the %{KernelVer} kernel
AutoReqProv: no
Provides: kernel-devel-uname-r = %{KernelVer}
Provides: kernel-devel-%{_target_cpu} = %{version}-%{release}
Requires: perl findutils

%description devel
This package provides kernel headers and makefiles sufficient to build modules
against the %{KernelVer} kernel package.

%package tools
Summary: Assortment of tools for the Linux kernel
Provides: %{name}-tools-libs
Obsoletes: %{name}-tools-libs
Provides:  cpufreq-utils = 1:009-0.6.p1
Provides:  cpufrequtils = 1:009-0.6.p1
Obsoletes: cpufreq-utils < 1:009-0.6.p1
Obsoletes: cpufrequtils < 1:009-0.6.p1
Obsoletes: cpuspeed < 1:1.5-16
%description tools
This package contains the tools/ directory from the kernel source
and the supporting documentation.

%package tools-devel
Summary: Assortment of tools for the Linux kernel
Requires: %{name}-tools = %{version}-%{release}
Requires: %{name}-tools-libs = %{version}-%{release}
Provides: %{name}-tools-libs-devel = %{version}-%{release}
Obsoletes: %{name}-tools-libs-devel
%description tools-devel
This package contains the development files for the tools/ directory from
the kernel source.

%if %{with_perf}
%package -n perf
Summary: Performance monitoring for the Linux kernel
%description -n perf
This package contains the perf tool, which enables performance monitoring
of the Linux kernel.

%if 0%{?with_python2}
%package -n python2-perf
Provides: python-perf = %{version}-%{release}
Obsoletes: python-perf
Summary: Python bindings for apps which will manipulate perf events

%description -n python2-perf
A Python module that permits applications written in the Python programming
language to use the interface to manipulate perf events.
%endif

%package -n python3-perf
Summary: Python bindings for apps which will manipulate perf events
%description -n python3-perf
A Python module that permits applications written in the Python programming
language to use the interface to manipulate perf events.
# with_perf
%endif

%package -n bpftool
Summary: Inspection and simple manipulation of eBPF programs and maps
%description -n bpftool
This package contains the bpftool, which allows inspection and simple
manipulation of eBPF programs and maps.

%package source
Summary: the kernel source
%description source
This package contains vaious source files from the kernel.

%if 0%{?with_debuginfo}
%define _debuginfo_template %{nil}
%define _debuginfo_subpackages 0

%define debuginfo_template(n:) \
%package -n %{-n*}-debuginfo\
Summary: Debug information for package %{-n*}\
Group: Development/Debug\
AutoReq: 0\
AutoProv: 1\
%description -n %{-n*}-debuginfo\
This package provides debug information for package %{-n*}.\
Debug information is useful when developing applications that use this\
package or when debugging this package.\
%{nil}

%debuginfo_template -n kernel
%files -n kernel-debuginfo -f kernel-debugfiles.list -f debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} --keep-section '.BTF' -p '.*/%{KernelVer}/.*|.*/vmlinux|XXX' -o kernel-debugfiles.list}

%debuginfo_template -n bpftool
%files -n bpftool-debuginfo -f bpftool-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_sbindir}/bpftool.*(\.debug)?|XXX' -o bpftool-debugfiles.list}

%debuginfo_template -n kernel-tools
%files -n kernel-tools-debuginfo -f kernel-tools-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_bindir}/centrino-decode.*(\.debug)?|.*%{_bindir}/powernow-k8-decode.*(\.debug)?|.*%{_bindir}/cpupower.*(\.debug)?|.*%{_libdir}/libcpupower.*|.*%{_libdir}/libcpupower.*|.*%{_bindir}/turbostat.(\.debug)?|.*%{_bindir}/.*gpio.*(\.debug)?|.*%{_bindir}/.*iio.*(\.debug)?|.*%{_bindir}/tmon.*(.debug)?|XXX' -o kernel-tools-debugfiles.list}

%if %{with_perf}
%debuginfo_template -n perf
%files -n perf-debuginfo -f perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_bindir}/perf.*(\.debug)?|.*%{_libexecdir}/perf-core/.*|.*%{_libdir}/traceevent/.*|XXX' -o perf-debugfiles.list}

%if 0%{?with_python2}
%debuginfo_template -n python2-perf
%files -n python2-perf-debuginfo -f python2-perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{python2_sitearch}/perf.*(.debug)?|XXX' -o python2-perf-debugfiles.list}
%endif

%debuginfo_template -n python3-perf
%files -n python3-perf-debuginfo -f python3-perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{python3_sitearch}/perf.*(.debug)?|XXX' -o python3-perf-debugfiles.list}
#with_perf
%endif

%endif

%prep

%setup -q -n kernel-%{version} -c

%if 0%{?with_patch}
tar -xjf %{SOURCE9998}
%endif

mv kernel linux-%{KernelVer}
cd linux-%{KernelVer}

# process PGP certs
cp %{SOURCE13} .
cp %{SOURCE14} .
sh %{SOURCE14}
cp pubring.gpg certs

%if 0%{?with_patch}
cp %{SOURCE9000} .
cp %{SOURCE9001} .
cp %{SOURCE9002} .

if [ ! -d patches ];then
    mv ../patches .
fi

Applypatches()
{
    set -e
    set -o pipefail
    local SERIESCONF=$1
    local PATCH_DIR=$2
    sed -i '/^#/d'  $SERIESCONF
    sed -i '/^[\s]*$/d' $SERIESCONF
    (
        echo "trap 'echo \"*** patch \$_ failed ***\"' ERR"
        echo "set -ex"
        cat $SERIESCONF | \
        sed "s!^!patch -s -F0 -E -p1 --no-backup-if-mismatch -i $PATCH_DIR/!" \
    ) | sh
}

Applypatches series.conf %{_builddir}/kernel-%{version}/linux-%{KernelVer}
%endif

%if "%toolchain" == "clang"
%patch0002 -p1
%patch0003 -p1
%patch0004 -p1
%endif

find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null
find . -name .gitignore -exec rm -f {} \; >/dev/null

%if 0%{?with_signmodules}
    cp %{SOURCE11} certs/.
%endif

%if 0%{?with_source}
# Copy directory backup for kernel-source
cp -a ../linux-%{KernelVer} ../linux-%{KernelVer}-source
find ../linux-%{KernelVer}-source -type f -name "\.*" -exec rm -rf {} \; >/dev/null
%endif

cp -a tools/perf tools/python3-perf

%build
cd linux-%{KernelVer}

perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}.%{_target_cpu}/" Makefile

## make linux
make mrproper %{_smp_mflags}

%if %{with_64kb}
sed -i arch/arm64/configs/openeuler_defconfig -e 's/^CONFIG_ARM64_4K_PAGES.*/CONFIG_ARM64_64K_PAGES=y/'
sed -i arch/arm64/configs/openeuler_defconfig -e 's/^CONFIG_ARM64_PA_BITS=.*/CONFIG_ARM64_PA_BITS=52/'
sed -i arch/arm64/configs/openeuler_defconfig -e 's/^CONFIG_ARM64_PA_BITS_.*/CONFIG_ARM64_PA_BITS_52=y/'
sed -i arch/arm64/configs/openeuler_defconfig -e 's/^CONFIG_ARM64_VA_BITS=.*/CONFIG_ARM64_VA_BITS=52/'
sed -i arch/arm64/configs/openeuler_defconfig -e 's/^CONFIG_ARM64_VA_BITS_.*/CONFIG_ARM64_VA_BITS_52=y/'
%endif

%if "%toolchain" == "clang"

%ifarch s390x ppc64le
%global llvm_ias 0
%else
%global llvm_ias 1
%endif

%global clang_make_opts HOSTCC=clang CC=clang LLVM_IAS=%{llvm_ias}

%if %{with clang_lto}
%global clang_make_opts %{clang_make_opts} HOSTLD=ld.lld LD=ld.lld AR=llvm-ar NM=llvm-nm HOSTAR=llvm-ar HOSTNM=llvm-nm
%endif

%endif

%global make %{__make} %{?clang_make_opts} HOSTCFLAGS="%{?build_cflags}" HOSTLDFLAGS="%{?build_ldflags}"

%{make} ARCH=%{Arch} openeuler_defconfig

%if %{with clang_lto}
scripts/config -e LTO_CLANG_FULL
sed -i 's/# CONFIG_LTO_CLANG_FULL is not set/CONFIG_LTO_CLANG_FULL=y/' .config
sed -i 's/CONFIG_LTO_NONE=y/# CONFIG_LTO_NONE is not set/' .config
%endif

TargetImage=$(basename $(make -s image_name))

%{make} ARCH=%{Arch} $TargetImage %{?_smp_mflags}
%{make} ARCH=%{Arch} modules %{?_smp_mflags}

%if 0%{?with_kabichk}
    chmod 0755 %{SOURCE18}
    if [ -e $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu} ]; then
        %{SOURCE18} -k $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu} -s Module.symvers || exit 1
    else
        echo "**** NOTE: Cannot find reference Module.kabi file. ****"
    fi
%endif

# aarch64 make dtbs
%ifarch aarch64 riscv64
    %{make} ARCH=%{Arch} dtbs
%endif

## make tools
%if %{with_perf}
# perf
%global perf_make \
    make %{?clang_make_opts} EXTRA_LDFLAGS="%[ "%{toolchain}" == "clang" ? "-z now" : "" ]" EXTRA_CFLAGS="%[ "%{toolchain}" == "clang" ? "" : "-Wl,-z,now" ] -g -Wall -fstack-protector-strong -fPIC" EXTRA_PERFLIBS="-fpie -pie" %{?_smp_mflags} -s V=1 WERROR=0 NO_LIBUNWIND=1 HAVE_CPLUS_DEMANGLE=1 NO_GTK2=1 NO_LIBNUMA=1 NO_STRLCPY=1 prefix=%{_prefix}
%if 0%{?with_python2}
%global perf_python2 -C tools/perf PYTHON=%{__python2}
%global perf_python3 -C tools/python3-perf PYTHON=%{__python3}
%else
%global perf_python3 -C tools/perf PYTHON=%{__python3}
%endif

chmod +x tools/perf/check-headers.sh
# perf
%if 0%{?with_python2}
%{perf_make} %{perf_python2} all
%endif

# make sure check-headers.sh is executable
chmod +x tools/python3-perf/check-headers.sh
%{perf_make} %{perf_python3} all

pushd tools/perf/Documentation/
%{make} %{?_smp_mflags} man
popd
%endif

# bpftool
pushd tools/bpf/bpftool
%{make}
popd

# cpupower
chmod +x tools/power/cpupower/utils/version-gen.sh
%{make} %{?_smp_mflags} -C tools/power/cpupower CPUFREQ_BENCH=false
%ifarch %{ix86}
    pushd tools/power/cpupower/debug/i386
    %{make} %{?_smp_mflags} centrino-decode powernow-k8-decode
    popd
%endif
%ifarch x86_64
    pushd tools/power/cpupower/debug/x86_64
    %{make} %{?_smp_mflags} centrino-decode powernow-k8-decode
    popd
%endif
%ifarch %{ix86} x86_64
    pushd tools/power/x86/x86_energy_perf_policy/
    %{make}
    popd
    pushd tools/power/x86/turbostat
    %{make}
    popd
%endif
# thermal
pushd tools/thermal/tmon/
%{make}
popd
# iio
pushd tools/iio/
%{make}
popd
# gpio
pushd tools/gpio/
%{make}
popd
# kvm
pushd tools/kvm/kvm_stat/
%{make} %{?_smp_mflags} man
popd

%install
%if 0%{?with_source}
    %define _python_bytecompile_errors_terminate_build 0
    mkdir -p $RPM_BUILD_ROOT/usr/src/
    mv linux-%{KernelVer}-source $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}
    cp linux-%{KernelVer}/.config $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}/
%endif

cd linux-%{KernelVer}

## install linux

# deal with kernel-source, now we don't need kernel-source
#mkdir $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}
#tar cf - --exclude SCCS --exclude BitKeeper --exclude .svn --exclude CVS --exclude .pc --exclude .hg --exclude .git --exclude=.tmp_versions --exclude=*vmlinux* --exclude=*.o --exclude=*.ko --exclude=*.cmd --exclude=Documentation --exclude=.config.old --exclude=.missing-syscalls.d --exclude=patches . | tar xf - -C %{buildroot}/usr/src/linux-%{KernelVer}

mkdir -p $RPM_BUILD_ROOT/boot
dd if=/dev/zero of=$RPM_BUILD_ROOT/boot/initramfs-%{KernelVer}.img bs=1M count=20

install -m 755 $(make -s image_name) $RPM_BUILD_ROOT/boot/vmlinuz-%{KernelVer}
pushd $RPM_BUILD_ROOT/boot
sha512hmac ./vmlinuz-%{KernelVer} >./.vmlinuz-%{KernelVer}.hmac
popd

install -m 644 .config $RPM_BUILD_ROOT/boot/config-%{KernelVer}
install -m 644 System.map $RPM_BUILD_ROOT/boot/System.map-%{KernelVer}

gzip -c9 < Module.symvers > $RPM_BUILD_ROOT/boot/symvers-%{KernelVer}.gz

mkdir -p $RPM_BUILD_ROOT%{_sbindir}
install -m 755 %{SOURCE200} $RPM_BUILD_ROOT%{_sbindir}/mkgrub-menu-%{version}-%{devel_release}%{?maintenance_release}%{?pkg_release}.sh


%if 0%{?with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/%{KernelVer}
    cp vmlinux $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/%{KernelVer}
%endif

# deal with module, if not kdump
%{make} ARCH=%{Arch} INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=%{KernelVer} mod-fw=
######## to collect ko to module.filelist about netwoking. block. drm. modesetting ###############
pushd $RPM_BUILD_ROOT/lib/modules/%{KernelVer}
find -type f -name "*.ko" >modnames

# mark modules executable so that strip-to-file can strip them
xargs --no-run-if-empty chmod u+x < modnames

# Generate a list of modules for block and networking.

grep -F /drivers/ modnames | xargs --no-run-if-empty nm -upA |
sed -n 's,^.*/\([^/]*\.ko\):  *U \(.*\)$,\1 \2,p' > drivers.undef

collect_modules_list()
{
    sed -r -n -e "s/^([^ ]+) \\.?($2)\$/\\1/p" drivers.undef |
    LC_ALL=C sort -u > modules.$1
    if [ ! -z "$3" ]; then
        sed -r -e "/^($3)\$/d" -i modules.$1
    fi
}

collect_modules_list networking \
			 'register_netdev|ieee80211_register_hw|usbnet_probe|phy_driver_register|rt2x00(pci|usb)_probe|register_netdevice'
collect_modules_list block \
		 'ata_scsi_ioctl|scsi_add_host|scsi_add_host_with_dma|blk_alloc_queue|blk_init_queue|register_mtd_blktrans|scsi_esp_register|scsi_register_device_handler|blk_queue_physical_block_size|ahci_platform_get_resources' 'pktcdvd.ko|dm-mod.ko'
collect_modules_list drm \
			 'drm_open|drm_init'
collect_modules_list modesetting \
			 'drm_crtc_init'

# detect missing or incorrect license tags
rm -f modinfo
while read i
do
    echo -n "$i " >> modinfo
    /sbin/modinfo -l $i >> modinfo
done < modnames

grep -E -v \
	  'GPL( v2)?$|Dual BSD/GPL$|Dual MPL/GPL$|GPL and additional rights$' \
  modinfo && exit 1

rm -f modinfo modnames drivers.undef

for i in alias alias.bin builtin.bin ccwmap dep dep.bin ieee1394map inputmap isapnpmap ofmap pcimap seriomap symbols symbols.bin usbmap
do
    rm -f $RPM_BUILD_ROOT/lib/modules/$KernelVer/modules.$i
done
popd
# modsign module ko;need after find-debuginfo,strip
%define __modsign_install_post \
    if [ "%{with_signmodules}" -eq "1" ];then \
        cp certs/signing_key.pem . \
        cp certs/signing_key.x509 . \
        chmod 0755 %{modsign_cmd} \
        %{modsign_cmd} $RPM_BUILD_ROOT/lib/modules/%{KernelVer} || exit 1 \
    fi \
    find $RPM_BUILD_ROOT/lib/modules/ -type f -name '*.ko' | xargs -n1 -P`nproc --all` xz; \
%{nil}

# deal with header
%{make} ARCH=%{Arch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr KBUILD_SRC= headers_install
find $RPM_BUILD_ROOT/usr/include -name "\.*"  -exec rm -rf {} \;

# dtbs install
%ifarch aarch64 riscv64
    mkdir -p $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}
    install -m 644 $(find arch/%{Arch}/boot -name "*.dtb") $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/
    rm -f $(find arch/$Arch/boot -name "*.dtb")
%endif

# deal with vdso
%{make} -s ARCH=%{Arch} INSTALL_MOD_PATH=$RPM_BUILD_ROOT vdso_install KERNELRELEASE=%{KernelVer}
if [ ! -s ldconfig-kernel.conf ]; then
    echo "# Placeholder file, no vDSO hwcap entries used in this kernel." >ldconfig-kernel.conf
fi
install -D -m 444 ldconfig-kernel.conf $RPM_BUILD_ROOT/etc/ld.so.conf.d/kernel-%{KernelVer}.conf

# deal with /lib/module/ path- sub path: build source kernel
rm -f $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build
rm -f $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/source
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/extra
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/updates
mkdir -p $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/weak-updates
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

# copy objtool for kernel-devel (needed for building external modules)
if grep -q CONFIG_OBJTOOL=y .config; then
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


# deal with doc , now we don't need


# deal with kernel abi whitelists. now we don't need


## install tools
%if %{with_perf}
# perf
# perf tool binary and supporting scripts/binaries
%if 0%{?with_python2}
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} lib=%{_lib} install-bin
%else
%{perf_make} %{perf_python3} DESTDIR=%{buildroot} lib=%{_lib} install-bin
%endif
# remove the 'trace' symlink.
rm -f %{buildroot}%{_bindir}/trace

# remove examples
rm -rf %{buildroot}/usr/lib/perf/examples
# remove the stray header file that somehow got packaged in examples
rm -rf %{buildroot}/usr/lib/perf/include/bpf/

# python-perf extension
%{perf_make} %{perf_python3} DESTDIR=%{buildroot} install-python_ext
%if 0%{?with_python2}
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} install-python_ext
%endif

# perf man pages (note: implicit rpm magic compresses them later)
install -d %{buildroot}/%{_mandir}/man1
install -pm0644 tools/kvm/kvm_stat/kvm_stat.1 %{buildroot}/%{_mandir}/man1/
install -pm0644 tools/perf/Documentation/*.1 %{buildroot}/%{_mandir}/man1/
%endif

# bpftool
pushd tools/bpf/bpftool
%{make} DESTDIR=%{buildroot} prefix=%{_prefix} bash_compdir=%{_sysconfdir}/bash_completion.d/ mandir=%{_mandir} install doc-install
popd

# resolve_btfids
mkdir -p %{buildroot}/usr/src/kernels/%{KernelVer}/tools/bpf/resolve_btfids
cp tools/bpf/resolve_btfids/resolve_btfids %{buildroot}/usr/src/kernels/%{KernelVer}/tools/bpf/resolve_btfids

# cpupower
%{make} -C tools/power/cpupower DESTDIR=%{buildroot} libdir=%{_libdir} mandir=%{_mandir} CPUFREQ_BENCH=false install
rm -f %{buildroot}%{_libdir}/*.{a,la}
%find_lang cpupower
mv cpupower.lang ../
%ifarch %{ix86}
    pushd tools/power/cpupower/debug/i386
    install -m755 centrino-decode %{buildroot}%{_bindir}/centrino-decode
    install -m755 powernow-k8-decode %{buildroot}%{_bindir}/powernow-k8-decode
    popd
%endif
%ifarch x86_64
    pushd tools/power/cpupower/debug/x86_64
    install -m755 centrino-decode %{buildroot}%{_bindir}/centrino-decode
    install -m755 powernow-k8-decode %{buildroot}%{_bindir}/powernow-k8-decode
    popd
%endif
chmod 0755 %{buildroot}%{_libdir}/libcpupower.so*
mkdir -p %{buildroot}%{_unitdir} %{buildroot}%{_sysconfdir}/sysconfig
install -m644 %{SOURCE2000} %{buildroot}%{_unitdir}/cpupower.service
install -m644 %{SOURCE2001} %{buildroot}%{_sysconfdir}/sysconfig/cpupower
%ifarch %{ix86} x86_64
    mkdir -p %{buildroot}%{_mandir}/man8
    pushd tools/power/x86/x86_energy_perf_policy
    %{make} DESTDIR=%{buildroot} install
    popd
    pushd tools/power/x86/turbostat
    %{make} DESTDIR=%{buildroot} install
    popd
%endif
# thermal
pushd tools/thermal/tmon
%{make} INSTALL_ROOT=%{buildroot} install
popd
# iio
pushd tools/iio
%{make} DESTDIR=%{buildroot} install
popd
# gpio
pushd tools/gpio
%{make} DESTDIR=%{buildroot} install
popd
# kvm
pushd tools/kvm/kvm_stat
%{make} INSTALL_ROOT=%{buildroot} install-tools
popd

%define __spec_install_post\
%{?__debug_package:%{__debug_install_post}}\
%{__arch_install_post}\
%{__os_install_post}\
%{__modsign_install_post}\
%{nil}

%post
%{_sbindir}/new-kernel-pkg --package kernel --install %{KernelVer} || exit $?

%preun
if [ `uname -i` == "aarch64" ] &&
        [ -f /boot/EFI/grub2/grub.cfg ]; then
    /usr/bin/sh  %{_sbindir}/mkgrub-menu-%{version}-%{devel_release}%{?maintenance_release}%{?pkg_release}.sh %{version}-%{release}.aarch64  /boot/EFI/grub2/grub.cfg  remove
fi

%postun
%{_sbindir}/new-kernel-pkg --rminitrd --rmmoddep --remove %{KernelVer} || exit $?
if [ -x %{_sbindir}/weak-modules ]
then
    %{_sbindir}/weak-modules --remove-kernel %{KernelVer} || exit $?
fi

# remove empty directory
if [ -d /lib/modules/%{KernelVer} ] && [ "`ls -A  /lib/modules/%{KernelVer}`" = "" ]; then
    rm -rf /lib/modules/%{KernelVer}
fi

%posttrans
%{_sbindir}/new-kernel-pkg --package kernel --mkinitrd --dracut --depmod --update %{KernelVer} || exit $?
%{_sbindir}/new-kernel-pkg --package kernel --rpmposttrans %{KernelVer} || exit $?
if [ `uname -i` == "aarch64" ] &&
        [ -f /boot/EFI/grub2/grub.cfg ]; then
	/usr/bin/sh %{_sbindir}/mkgrub-menu-%{version}-%{devel_release}%{?maintenance_release}%{?pkg_release}.sh %{version}-%{release}.aarch64  /boot/EFI/grub2/grub.cfg  update
fi
if [ -x %{_sbindir}/weak-modules ]
then
    %{_sbindir}/weak-modules --add-kernel %{KernelVer} || exit $?
fi
%{_sbindir}/new-kernel-pkg --package kernel --mkinitrd --dracut --depmod --update %{KernelVer} || exit $?
%{_sbindir}/new-kernel-pkg --package kernel --rpmposttrans %{KernelVer} || exit $?

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

%post -n %{name}-tools
/sbin/ldconfig
%systemd_post cpupower.service

%preun -n %{name}-tools
%systemd_preun cpupower.service

%postun -n %{name}-tools
/sbin/ldconfig
%systemd_postun cpupower.service

%files
%defattr (-, root, root)
%doc
/boot/config-*
%ifarch aarch64 riscv64
/boot/dtb-*
%endif
/boot/symvers-*
/boot/System.map-*
/boot/vmlinuz-*
%ghost /boot/initramfs-%{KernelVer}.img
/boot/.vmlinuz-*.hmac
/etc/ld.so.conf.d/*
/lib/modules/%{KernelVer}/
%exclude /lib/modules/%{KernelVer}/source
%exclude /lib/modules/%{KernelVer}/build
%{_sbindir}/mkgrub-menu*.sh

%files devel
%defattr (-, root, root)
%doc
/lib/modules/%{KernelVer}/source
/lib/modules/%{KernelVer}/build
/usr/src/kernels/%{KernelVer}

%files headers
%defattr (-, root, root)
/usr/include/*

%if %{with_perf}
%files -n perf
%{_bindir}/perf
%{_libdir}/libperf-jvmti.so
%{_libexecdir}/perf-core
%{_datadir}/perf-core/
%{_mandir}/man[1-8]/perf*
%{_sysconfdir}/bash_completion.d/perf
%doc linux-%{KernelVer}/tools/perf/Documentation/examples.txt
%dir %{_datadir}/doc/perf-tip
%{_datadir}/doc/perf-tip/*
%license linux-%{KernelVer}/COPYING

%if 0%{?with_python2}
%files -n python2-perf
%license linux-%{KernelVer}/COPYING
%{python2_sitearch}/*
%endif

%files -n python3-perf
%license linux-%{KernelVer}/COPYING
%{python3_sitearch}/*
%endif

%files -n %{name}-tools -f cpupower.lang
%{_bindir}/cpupower
%ifarch %{ix86} x86_64
%{_bindir}/centrino-decode
%{_bindir}/powernow-k8-decode
%endif
%{_unitdir}/cpupower.service
%{_datadir}/bash-completion/completions/cpupower
%{_mandir}/man[1-8]/cpupower*
%config(noreplace) %{_sysconfdir}/sysconfig/cpupower
%ifarch %{ix86} x86_64
%{_bindir}/x86_energy_perf_policy
%{_mandir}/man8/x86_energy_perf_policy*
%{_bindir}/turbostat
%{_mandir}/man8/turbostat*
%endif
%{_bindir}/tmon
%{_bindir}/iio_event_monitor
%{_bindir}/iio_generic_buffer
%{_bindir}/lsiio
%{_bindir}/lsgpio
%{_bindir}/gpio-hammer
%{_bindir}/gpio-event-mon
%{_bindir}/gpio-watch
%{_mandir}/man1/kvm_stat*
%{_bindir}/kvm_stat
%{_libdir}/libcpupower.so.1
%{_libdir}/libcpupower.so.0.0.1
%license linux-%{KernelVer}/COPYING

%files -n %{name}-tools-devel
%{_libdir}/libcpupower.so
%{_includedir}/cpufreq.h
%{_includedir}/cpuidle.h

%files -n bpftool
%{_sbindir}/bpftool
%{_sysconfdir}/bash_completion.d/bpftool
%{_mandir}/man8/bpftool-cgroup.8.gz
%{_mandir}/man8/bpftool-map.8.gz
%{_mandir}/man8/bpftool-prog.8.gz
%{_mandir}/man8/bpftool-perf.8.gz
%{_mandir}/man8/bpftool.8.gz
%{_mandir}/man8/bpftool-btf.8.gz
%{_mandir}/man8/bpftool-feature.8.gz
%{_mandir}/man8/bpftool-gen.8.gz
%{_mandir}/man8/bpftool-iter.8.gz
%{_mandir}/man8/bpftool-link.8.gz
%{_mandir}/man8/bpftool-net.8.gz
%{_mandir}/man8/bpftool-struct_ops.8.gz
%license linux-%{KernelVer}/COPYING

%if 0%{?with_source}
%files source
%defattr(-,root,root)
/usr/src/linux-%{KernelVer}/*
/usr/src/linux-%{KernelVer}/.config
%endif

%changelog
* Mon Jan 29 2024 jiahua.yu <jiahua.yu@shingroup.cn> - 6.6.0-6.0.0.4
- init support for arch ppc64le

* Tue Jan 23 2024 Zheng Zengkai <zhengzengkai@huawei.com> - 6.6.0-6.0.0.3
- !4087  backport two page_owner patchsets:
- mm/page_owner: record and dump free_pid and free_tgid
- tools/mm: update the usage output to be more organized
- tools/mm: fix the default case for page_owner_sort
- tools/mm: filter out timestamps for correct collation
- tools/mm: remove references to free_ts from page_owner_sort
- mm/page_owner: remove free_ts from page_owner output
- !4070  Backport etmem feature to OLK 6.6
- etmem: enable etmem configurations
- etmem: add original kernel swap enabled options
- etmem: add etmem swap feature
- mm: Export symbol reclaim_pages
- etmem: add etmem scan feature
- mm: Export symbol walk_page_range
- mm: Export symbol __pud_trans_huge_lock
- etmem: add ETMEM scan feature CONFIG to mm/Kconfig
- etmem: add ETMEM feature CONFIG to mm/Kconfig
- !3444  LoongArch: fix some pci problems
- LoongArch: pci root bridige set acpi companion only when not acpi_disabled.
- PCI: irq: Add early_param pci_irq_limit to limit pci irq numbers
- PCI: fix X server auto probe fail when both ast and etnaviv drm present
- PCI: LS7A2000: fix GPU card error
- PCI: LS7A2000: fix pm transition of devices under pcie port
- LoongArch: fix some PCIE card not scanning properly
- PCI: fix kabi error caused by pm_suspend_target_state
- PCI: PM: fix pcie mrrs restoring
- PCI: Check if the pci controller can use both CFG0 and CFG1 mode to access configuration space
- PCI: Check if entry->offset already exist for mem resource
- LS7A2000: Add quirk for OHCI device rev 0x02
- !4027 [OLK-6.6] Intel RDT non-contiguous CBM support
- Documentation/x86: Document resctrl's new sparse_masks
- x86/resctrl: Add sparse_masks file in info
- x86/resctrl: Enable non-contiguous CBMs in Intel CAT
- x86/resctrl: Rename arch_has_sparse_bitmaps
- !4098  sched: programmable: Fix is_cpu_allowed build error
- sched: programmable: Fix is_cpu_allowed build error
- !4072 cgroup/misc: openeuler_defconfig open misc config by default
- cgroup/misc: openeuler_defconfig open misc config by default
- !4053  sched: basic infrastructure for scheduler bpf
- openeuler_defconfig: enable CONFIG_BPF_SCHED
- sched: programmable: Add hook in can_migrate_task()
- sched: programmable: Add hook in select_task_rq_fair()
- sched: introduce bpf_sched_enable()
- sched: basic infrastructure for scheduler bpf
- sched: programmable: Add user interface of task tag
- sched: programmable: Add user interface of task group tag
- sched: programmable: Add a tag for the task group
- sched: programmable: Add a tag for the task
- sched: programmable: Introduce bpf sched
- !4068  mm/oom_kill: fix NULL pointer dereference in memcg_print_bad_task()
- mm/oom_kill: fix NULL pointer dereference in memcg_print_bad_task()
- !4036  ubi: fix slab-out-of-bounds in ubi_eba_get_ldesc+0xfb/0x130
- ubi: fix slab-out-of-bounds in ubi_eba_get_ldesc+0xfb/0x130
- !3971  optimize inlining
- make OPTIMIZE_INLINING config editable
- Revert "compiler: remove CONFIG_OPTIMIZE_INLINING entirely"
- !3631  drm: fix free illegal pointer when create drm_property_blob failed
- drm: fix free illegal pointer when create drm_property_blob failed
- !3958  Revert "drm/prime: Unexport helpers for fd/handle conversion"
- Revert "drm/prime: Unexport helpers for fd/handle conversion"
- !3670 Add initial openeuler_defconfig for riscv64
- config: add initial openeuler_defconfig for riscv64
- !3895  Spark SQL scenario bpf readahead optimization synchronization to OLK-6.6
- selftests/bpf: Update the demo file_read_pattern to run on libbpf 1.0+
- VFS: Rolling Back the fmode macro definition and structure members
- selftests/bpf: add demo for file read pattern detection
- ext4: add trace for the read and release of regular file
- xfs: add trace for read and release of regular file
- fs: add helper fs_file_read_do_trace()
- vfs: add bare tracepoints for vfs read and release
- readahead: introduce FMODE_CTL_WILLNEED to read first 2MB of file
- !3964  drivers: hooks: add bonding driver vendor hooks
- drivers: hooks: add bonding driver vendor hooks
- !3996  hfs: fix null-ptr-deref in hfs_find_init()
- hfs: fix null-ptr-deref in hfs_find_init()
- !3976  Introduce dynamic pool feature
- mm/dynamic_pool: enable CONFIG_DYNAMIC_POOL on x86_64 and arm64 by default
- mm/dynamic_pool: add Document for dynamic hugetlb feature
- mm/dynamic_pool: compatible with memory hwpoison
- mm/dynamic_pool: compatible with HugeTLB Vmemmap
- mm/dynamic_pool: compatible with HugeTLB dissolve
- mm/dynamic_pool: disable THP for task attached with dpool
- mm/dynamic_pool: fill dpool with pagelist
- mm/dynamic_pool: add tracepoints for dpool
- mm/dynamic_pool: support HugeTLB page allocation from dpool
- mm/dynamic_pool: check resv for HugeTLB allocation from dpool
- mm/dynamic_pool: speed up allocation by percpu pages pool
- mm/dynamic_pool: support page allocation from dpool
- mm/dynamic_pool: prevent task attach to another dpool
- mm/dynamic_pool: call mem_cgroup_force_empty before restore pool
- mm/dynamic_pool: migrate used pages before promote to huge page
- mm/dynamic_pool: support to flow pages between 2M and 4K pages pool
- mm/dynamic_pool: support to flow pages between 1G and 2M pages pool
- mm/dynamic_pool: add restore_pool ops to reclaim memory and restore hugepages
- mm/dynamic_pool: add interface to configure the count of hugepages
- mm/dynamic_pool: fill dpool with HugeTLB 1G pages
- mm/dynamic_pool: create dpool by dhugetlb.nr_pages interface
- mm/dynamic_pool: introduce PG_pool to mark pages allocated from dpool
- mm/dynamic_pool: introduce PG_dpool to mark free pages in dpool
- mm/dynamic_pool: introduce per-memcg memory pool
- mm/memcg: introduce memcg_has_children to check memcg
- mm/memcg: introduce mem_cgroup_scan_cgroups to scan all memcgs
- !3833  xfs: fix block space problems
- xfs: longest free extent no need consider postalloc
- xfs: fix xfs shutdown since we reserve more blocks in agfl fixup
- xfs: set minleft correctly for randomly sparse inode allocations
- xfs: account extra freespace btree splits for multiple allocations
- !3902  xfs: update the last_sync_lsn with ctx start lsn
- xfs: update the last_sync_lsn with ctx start lsn
- !3977  Terrace Service Acceleration
- bpf, sockmap: Add sk_rmem_alloc check for sockmap
- bpf: Add new bpf helper to get SO_ORIGINAL_DST/REPLY_SRC
- bpf: Add bpf_get_sockops_uid_gid helper function
- net: core: Add a GID field to struct sock.
- !3974  Add support for mbigen to generate SPIs
- dt-bindings/irqchip/mbigen: add example of MBIGEN generate SPIs
- irqchip/mbigen: add support for a MBIGEN generating SPIs
- irqchip/mbigen: rename register marcros
- !3963  block: Add config to show info about opening a mounted device for write
- add config about writing mounted devices in openeuler_defconfig
- block: Show info about opening a lower device for write while upper-layers mounted
- block: Add config option to show info about opening a mounted device for write
- block: Add config option to detect writing to part0 while partitions mounted
- block: Expand the meaning of bdev_allow_write_mounted
- block: Record writing and mounting regardless of whether bdev_allow_write_mounted is set
- !3921  mm: mem_reliable: Introduce memory reliable
- config: enable MEMORY_RELIABLE by default
- mm: mem_reliable: Show debug info about memory reliable if oom occurs
- mm: mem_reliable: Introduce proc interface to disable memory reliable features
- proc: mem_reliable: Count reliable memory usage of reliable tasks
- mm: mem_reliable: Introduce fallback mechanism for memory reliable
- mm: mem_reliable: Add limiting the usage of reliable memory
- mm: mem_reliable: Show reliable meminfo
- mm: mem_reliable: Count reliable shmem usage
- mm: mem_reliable: Count reliable page cache usage
- mm: mem_reliable: Add cmdline reliable_debug to enable separate feature
- mm/hugetlb: Allocate non-mirrored memory by default
- mm/memblock: Introduce ability to alloc memory from specify memory region
- mm: mem_reliable: Add memory reliable support during hugepaged collapse
- mm: mem_reliable: Alloc pagecache from reliable region
- shmem: mem_reliable: Alloc shmem from reliable region
- mm: mem_reliable: Alloc task memory from reliable region
- mm: mem_reliable: Introduce memory reliable
- efi: Disable mirror feature during crashkernel
- proc: introduce proc_hide_ents to hide proc files
- !3935  pid_ns: Make pid_max per namespace
- pid_ns: Make pid_max per namespace
- !3913  arm64: Add non nmi ipi backtrace support
- arm64: Add non nmi ipi backtrace support
- !3785 【OLK-6.6】PSI cgroupv1 and PSI fine grained
- sched/psi: enable PSI_CGROUP_V1 and PSI_FINE_GRAINED in openeuler_defconfig
- sched/psi: add cpu fine grained stall tracking in pressure.stat
- sched/psi: add more memory fine grained stall tracking in pressure.stat
- sched/psi: Introduce pressure.stat in psi
- sched/psi: Introduce avgs and total calculation for cgroup reclaim
- sched/psi: Introduce fine grained stall time collect for cgroup reclaim
- sched/psi: introduce tracepoints for psi_memstall_{enter, leave}
- sched/psi: update psi irqtime when the irq delta is nozero
- sched/psi: Export cgroup psi from cgroupv2 to cgroupv1
- sched/psi: Bail out early from irq time accounting
- !3907  cgroup: Support iocost for cgroup v1
- openeuler_defconfig: enable iocost in openeuler_defconfig for x86 and arm64
- cgroup: Support iocost for cgroup v1
- !3897  Some simple extensions of the kfence feature
- arm64: kfence: scale sample_interval to support early init for kfence.
- kfence: Add a module parameter to adjust kfence objects
- !3888  fs/dcache.c: avoid panic while lockref of dentry overflow
- fs/dcache.c: avoid panic while lockref of dentry overflow
- !3894  Add swap control for memcg
- config: enable memcg swap qos for x86_64 and arm64 by default
- memcg/swap: add ability to disable memcg swap
- mm: swap_slots: add per-type slot cache
- mm/swapfile: introduce per-memcg swapfile control
- memcg: add restrict to swap to cgroup1
- memcg: introduce per-memcg swapin interface
- memcg: introduce memcg swap qos feature
- memcg: make sysctl registration more extensible
- memcg: add page type to memory.reclaim interface
- !3827  backport mainline md patch
- dm-raid: delay flushing event_work() after reconfig_mutex is released
- md/raid1: support read error check
- md: factor out a helper exceed_read_errors() to check read_errors
- md: Whenassemble the array, consult the superblock of the freshest device
- md/raid1: remove unnecessary null checking
- md: split MD_RECOVERY_NEEDED out of mddev_resume
- md: fix stopping sync thread
- md: fix missing flush of sync_work
- md: synchronize flush io with array reconfiguration
- md/md-multipath: remove rcu protection to access rdev from conf
- md/raid5: remove rcu protection to access rdev from conf
- md/raid1: remove rcu protection to access rdev from conf
- md/raid10: remove rcu protection to access rdev from conf
- md: remove flag RemoveSynchronized
- Revert "md/raid5: Wait for MD_SB_CHANGE_PENDING in raid5d"
- md: bypass block throttle for superblock update
- md: cleanup pers->prepare_suspend()
- md-cluster: check for timeout while a new disk adding
- md: rename __mddev_suspend/resume() back to mddev_suspend/resume()
- md: remove old apis to suspend the array
- md: suspend array in md_start_sync() if array need reconfiguration
- md/raid5: replace suspend with quiesce() callback
- md/md-linear: cleanup linear_add()
- md: cleanup mddev_create/destroy_serial_pool()
- md: use new apis to suspend array before mddev_create/destroy_serial_pool
- md: use new apis to suspend array for ioctls involed array reconfiguration
- md: use new apis to suspend array for adding/removing rdev from state_store()
- md: use new apis to suspend array for sysfs apis
- md/raid5: use new apis to suspend array
- md/raid5-cache: use new apis to suspend array
- md/md-bitmap: use new apis to suspend array for location_store()
- md/dm-raid: use new apis to suspend array
- md: add new helpers to suspend/resume and lock/unlock array
- md: add new helpers to suspend/resume array
- md: replace is_md_suspended() with 'mddev->suspended' in md_check_recovery()
- md/raid5-cache: use READ_ONCE/WRITE_ONCE for 'conf->log'
- md: use READ_ONCE/WRITE_ONCE for 'suspend_lo' and 'suspend_hi'
- md/raid1: don't split discard io for write behind
- md: do not require mddev_lock() for all options in array_state_store()
- md: simplify md_seq_ops
- md: factor out a helper from mddev_put()
- md: replace deprecated strncpy with memcpy
- md: don't check 'mddev->pers' and 'pers->quiesce' from suspend_lo_store()
- md: don't check 'mddev->pers' from suspend_hi_store()
- md-bitmap: suspend array earlier in location_store()
- md-bitmap: remove the checking of 'pers->quiesce' from location_store()
- md: initialize 'writes_pending' while allocating mddev
- md: initialize 'active_io' while allocating mddev
- md: delay remove_and_add_spares() for read only array to md_start_sync()
- md: factor out a helper rdev_addable() from remove_and_add_spares()
- md: factor out a helper rdev_is_spare() from remove_and_add_spares()
- md: factor out a helper rdev_removeable() from remove_and_add_spares()
- md: delay choosing sync action to md_start_sync()
- md: factor out a helper to choose sync action from md_check_recovery()
- md: use separate work_struct for md_start_sync()
- !3857  scsi: fix use-after-free problem in scsi_remove_target
- scsi: fix use-after-free problem in scsi_remove_target
- !3906  sched/core: Change depends of SCHED_CORE
- sched/core: Change depends of SCHED_CORE
- !3747  Introduce multiple qos level
- config: Enable CONFIG_QOS_SCHED_MULTILEVEL
- sched/fair: Introduce multiple qos level
- !3899  fs/dirty_pages: dump the number of dirty pages for each inode
- fs/dirty_pages: dump the number of dirty pages for each inode
- !3815  JFFS2: Fix the race issues caused by the GC of jffs2
- jffs2: reset pino_nlink to 0 when inode creation failed
- jffs2: make the overwritten xattr invisible after remount
- jffs2: handle INO_STATE_CLEARING in jffs2_do_read_inode()
- jffs2: protect no-raw-node-ref check of inocache by erase_completion_lock
- !3891  block: support to account io_ticks precisely
- block: support to account io_ticks precisely
- !3881  iommu: set CONFIG_SMMU_BYPASS_DEV=y
- iommu: set CONFIG_SMMU_BYPASS_DEV=y
- !3819  support ext3/ext4 netlink error report.
- Add new config 'CONFIG_EXT4_ERROR_REPORT' to control ext3/4 error reporting
- ext4: report error to userspace by netlink
- !3720  blk-mq: make fair tag sharing configurable
- scsi_lib: disable fair tag sharing by default if total tags is less than 128
- scsi: core: make fair tag sharing configurable via sysfs
- blk-mq: add apis to disable fair tag sharing
- !3090  fs/dcache.c: avoid softlock since too many negative dentry
- fs/dcache.c: avoid softlock since too many negative dentry
- !3656  iommu: Enable smmu-v3 when 3408iMR/3416iMRraid card exist
- iommu: Enable smmu-v3 when 3408iMR/3416iMRraid card exist
- !3843 [OLK-6.6] export cgroup.stat from cgroupv2 to cgroupv1
- cgroup: Export cgroup.stat from cgroupv2 to cgroupv1
- !3828  openeuler_defconfig: enable erofs ondemand for x86 and arm64
- openeuler_defconfig: enable erofs ondemand for x86 and arm64
- !3851  ext4: fix slab-out-of-bounds in ext4_find_extent()
- ext4: check magic even the extent block bh is verified
- ext4: avoid recheck extent for EXT4_EX_FORCE_CACHE
- !3850  aio: add timeout validity check for io_[p
- aio: add timeout validity check for io_[p]getevents
- !3849  pipe: Fix endless sleep problem due to the out-of-order
- pipe: Fix endless sleep problem due to the out-of-order
- !3787  scsi: sd: unregister device if device_add_disk() failed in sd_probe()
- scsi: sd: unregister device if device_add_disk() failed in sd_probe()
- !3450  Backport nbd bugfix patch
- nbd: pass nbd_sock to nbd_read_reply() instead of index
- nbd: fix null-ptr-dereference while accessing 'nbd->config'
- nbd: factor out a helper to get nbd_config without holding 'config_lock'
- nbd: fold nbd config initialization into nbd_alloc_config()
- !3675  block mainline bugfix backport
- block: Set memalloc_noio to false on device_add_disk() error path
- block: add check of 'minors' and 'first_minor' in device_add_disk()
- block: add check that partition length needs to be aligned with block size
- !3786  ubi: block: fix memleak in ubiblock_create()
- ubi: block: fix memleak in ubiblock_create()
- !3448  ubi: block: Fix use-after-free in ubiblock_cleanup
- ubi: block: Fix use-after-free in ubiblock_cleanup
- !3760  Add huge page allocation limit
- openeuler_defconfig: enable HUGETLB_ALLOC_LIMIT
- hugetlb: Add huge page allocation limit
- !3818 [sync] PR-1989:  support Android vendor hooks
- openeuler_defconfig: enable CONFIG_VENDOR_HOOKS for x86 and arm64
- vendor_hooks: make android vendor hooks feature generic.
- ANDROID: fixup restricted hooks after tracepont refactoring
- ANDROID: simplify vendor hooks for non-GKI builds
- ANDROID: vendor_hooks: fix __section macro
- ANDROID: use static_call() for restricted hooks
- ANDROID: fix redefinition error for restricted vendor hooks
- ANDROID: add support for vendor hooks
- !3502  ARM: LPAE: Use phys_addr_t instead of unsigned long in outercache hooks
- ARM: LPAE: Use phys_addr_t instead of unsigned long in outercache hooks
- !3755  livepatch/core: Fix miss disable ro for MOD_RO_AFTER_INIT memory
- livepatch/core: Fix miss disable ro for MOD_RO_AFTER_INIT memory
- !3813  kernel: add OPENEULER_VERSION_CODE to version.h
- kernel: add OPENEULER_VERSION_CODE to version.h
- !3744  Add NUMA-awareness to qspinlock
- config: Enable CONFIG_NUMA_AWARE_SPINLOCKS on x86
- locking/qspinlock: Disable CNA by default
- locking/qspinlock: Introduce the shuffle reduction optimization into CNA
- locking/qspinlock: Avoid moving certain threads between waiting queues in CNA
- locking/qspinlock: Introduce starvation avoidance into CNA
- locking/qspinlock: Introduce CNA into the slow path of qspinlock
- locking/qspinlock: Refactor the qspinlock slow path
- locking/qspinlock: Rename mcs lock/unlock macros and make them more generic
- !3517  support CLOCKSOURCE_VALIDATE_LAST_CYCLE on
- config: make CLOCKSOURCE_VALIDATE_LAST_CYCLE not set by default
- timekeeping: Make CLOCKSOURCE_VALIDATE_LAST_CYCLE configurable
- !3710  Backport 6.6.7 LTS Patches
- drm/amdgpu: Restrict extended wait to PSP v13.0.6
- drm/amdgpu: update retry times for psp BL wait
- drm/amdgpu: Fix refclk reporting for SMU v13.0.6
- riscv: Kconfig: Add select ARM_AMBA to SOC_STARFIVE
- gcc-plugins: randstruct: Update code comment in relayout_struct()
- ASoC: qcom: sc8280xp: Limit speaker digital volumes
- netfilter: nft_set_pipapo: skip inactive elements during set walk
- MIPS: Loongson64: Enable DMA noncoherent support
- MIPS: Loongson64: Handle more memory types passed from firmware
- MIPS: Loongson64: Reserve vgabios memory on boot
- perf metrics: Avoid segv if default metricgroup isn't set
- perf list: Fix JSON segfault by setting the used skip_duplicate_pmus callback
- KVM: SVM: Update EFER software model on CR0 trap for SEV-ES
- KVM: s390/mm: Properly reset no-dat
- MIPS: kernel: Clear FPU states when setting up kernel threads
- cifs: Fix flushing, invalidation and file size with FICLONE
- cifs: Fix flushing, invalidation and file size with copy_file_range()
- USB: gadget: core: adjust uevent timing on gadget unbind
- powerpc/ftrace: Fix stack teardown in ftrace_no_trace
- x86/CPU/AMD: Check vendor in the AMD microcode callback
- devcoredump: Send uevent once devcd is ready
- serial: 8250_omap: Add earlycon support for the AM654 UART controller
- serial: 8250: 8250_omap: Do not start RX DMA on THRI interrupt
- serial: 8250: 8250_omap: Clear UART_HAS_RHR_IT_DIS bit
- serial: sc16is7xx: address RX timeout interrupt errata
- ARM: PL011: Fix DMA support
- usb: typec: class: fix typec_altmode_put_partner to put plugs
- smb: client: fix potential NULL deref in parse_dfs_referrals()
- Revert "xhci: Loosen RPM as default policy to cover for AMD xHC 1.1"
- cifs: Fix non-availability of dedup breaking generic/304
- parport: Add support for Brainboxes IX/UC/PX parallel cards
- serial: ma35d1: Validate console index before assignment
- serial: 8250_dw: Add ACPI ID for Granite Rapids-D UART
- nvmem: Do not expect fixed layouts to grab a layout driver
- usb: gadget: f_hid: fix report descriptor allocation
- kprobes: consistent rcu api usage for kretprobe holder
- ASoC: ops: add correct range check for limiting volume
- gpiolib: sysfs: Fix error handling on failed export
- x86/sev: Fix kernel crash due to late update to read-only ghcb_version
- perf: Fix perf_event_validate_size()
- drm/amdgpu: disable MCBP by default
- arm64: dts: mt8183: kukui: Fix underscores in node names
- arm64: dts: mediatek: add missing space before {
- parisc: Fix asm operand number out of range build error in bug table
- parisc: Reduce size of the bug_table on 64-bit kernel by half
- LoongArch: BPF: Don't sign extend function return value
- LoongArch: BPF: Don't sign extend memory load operand
- perf vendor events arm64: AmpereOne: Add missing DefaultMetricgroupName fields
- misc: mei: client.c: fix problem of return '-EOVERFLOW' in mei_cl_write
- misc: mei: client.c: return negative error code in mei_cl_write
- coresight: ultrasoc-smb: Fix uninitialized before use buf_hw_base
- coresight: ultrasoc-smb: Config SMB buffer before register sink
- coresight: ultrasoc-smb: Fix sleep while close preempt in enable_smb
- hwtracing: hisi_ptt: Add dummy callback pmu::read()
- coresight: Fix crash when Perf and sysfs modes are used concurrently
- coresight: etm4x: Remove bogous __exit annotation for some functions
- arm64: dts: mediatek: mt8186: Change gpu speedbin nvmem cell name
- arm64: dts: mediatek: mt8186: fix clock names for power domains
- arm64: dts: mediatek: mt8183-evb: Fix unit_address_vs_reg warning on ntc
- arm64: dts: mediatek: mt8183: Move thermal-zones to the root node
- arm64: dts: mediatek: mt8183: Fix unit address for scp reserved memory
- arm64: dts: mediatek: mt8195: Fix PM suspend/resume with venc clocks
- arm64: dts: mediatek: mt8173-evb: Fix regulator-fixed node names
- arm64: dts: mediatek: cherry: Fix interrupt cells for MT6360 on I2C7
- arm64: dts: mediatek: mt8183-kukui-jacuzzi: fix dsi unnecessary cells properties
- arm64: dts: mediatek: mt7622: fix memory node warning check
- arm64: dts: mt7986: fix emmc hs400 mode without uboot initialization
- arm64: dts: mt7986: define 3W max power to both SFP on BPI-R3
- arm64: dts: mt7986: change cooling trips
- drm/i915: Skip some timing checks on BXT/GLK DSI transcoders
- drm/i915/mst: Reject modes that require the bigjoiner
- drm/i915/mst: Fix .mode_valid_ctx() return values
- drm/atomic-helpers: Invoke end_fb_access while owning plane state
- md/raid6: use valid sector values to determine if an I/O should wait on the reshape
- powercap: DTPM: Fix missing cpufreq_cpu_put() calls
- mm/memory_hotplug: fix error handling in add_memory_resource()
- mm: fix oops when filemap_map_pmd() without prealloc_pte
- mm/memory_hotplug: add missing mem_hotplug_lock
- drivers/base/cpu: crash data showing should depends on KEXEC_CORE
- hugetlb: fix null-ptr-deref in hugetlb_vma_lock_write
- workqueue: Make sure that wq_unbound_cpumask is never empty
- platform/surface: aggregator: fix recv_buf() return value
- regmap: fix bogus error on regcache_sync success
- r8169: fix rtl8125b PAUSE frames blasting when suspended
- packet: Move reference count in packet_sock to atomic_long_t
- nfp: flower: fix for take a mutex lock in soft irq context and rcu lock
- leds: trigger: netdev: fix RTNL handling to prevent potential deadlock
- tracing: Fix a possible race when disabling buffered events
- tracing: Fix incomplete locking when disabling buffered events
- tracing: Disable snapshot buffer when stopping instance tracers
- tracing: Stop current tracer when resizing buffer
- tracing: Always update snapshot buffer size
- checkstack: fix printed address
- cgroup_freezer: cgroup_freezing: Check if not frozen
- lib/group_cpus.c: avoid acquiring cpu hotplug lock in group_cpus_evenly
- nilfs2: prevent WARNING in nilfs_sufile_set_segment_usage()
- nilfs2: fix missing error check for sb_set_blocksize call
- highmem: fix a memory copy problem in memcpy_from_folio
- ring-buffer: Force absolute timestamp on discard of event
- ring-buffer: Test last update in 32bit version of __rb_time_read()
- ALSA: hda/realtek: Add quirk for Lenovo Yoga Pro 7
- ALSA: hda/realtek: Add Framework laptop 16 to quirks
- ALSA: hda/realtek: add new Framework laptop to quirks
- ALSA: hda/realtek: Enable headset on Lenovo M90 Gen5
- ALSA: hda/realtek: fix speakers on XPS 9530 (2023)
- ALSA: hda/realtek: Apply quirk for ASUS UM3504DA
- ALSA: pcm: fix out-of-bounds in snd_pcm_state_names
- ALSA: usb-audio: Add Pioneer DJM-450 mixer controls
- io_uring: fix mutex_unlock with unreferenced ctx
- nvme-pci: Add sleep quirk for Kingston drives
- io_uring/af_unix: disable sending io_uring over sockets
- ASoC: amd: yc: Fix non-functional mic on ASUS E1504FA
- rethook: Use __rcu pointer for rethook::handler
- scripts/gdb: fix lx-device-list-bus and lx-device-list-class
- kernel/Kconfig.kexec: drop select of KEXEC for CRASH_DUMP
- md: don't leave 'MD_RECOVERY_FROZEN' in error path of md_set_readonly()
- riscv: errata: andes: Probe for IOCP only once in boot stage
- riscv: fix misaligned access handling of C.SWSP and C.SDSP
- arm64: dts: rockchip: Fix eMMC Data Strobe PD on rk3588
- ARM: dts: imx28-xea: Pass the 'model' property
- ARM: dts: imx7: Declare timers compatible with fsl,imx6dl-gpt
- arm64: dts: imx8-apalis: set wifi regulator to always-on
- ARM: imx: Check return value of devm_kasprintf in imx_mmdc_perf_init
- arm64: dts: imx93: correct mediamix power
- arm64: dts: freescale: imx8-ss-lsio: Fix #pwm-cells
- arm64: dts: imx8-ss-lsio: Add PWM interrupts
- scsi: be2iscsi: Fix a memleak in beiscsi_init_wrb_handle()
- tracing: Fix a warning when allocating buffered events fails
- io_uring/kbuf: check for buffer list readiness after NULL check
- io_uring/kbuf: Fix an NULL vs IS_ERR() bug in io_alloc_pbuf_ring()
- ARM: dts: imx6ul-pico: Describe the Ethernet PHY clock
- arm64: dts: imx8mp: imx8mq: Add parkmode-disable-ss-quirk on DWC3
- drm/bridge: tc358768: select CONFIG_VIDEOMODE_HELPERS
- RDMA/irdma: Avoid free the non-cqp_request scratch
- RDMA/irdma: Fix support for 64k pages
- RDMA/irdma: Ensure iWarp QP queue memory is OS paged aligned
- RDMA/core: Fix umem iterator when PAGE_SIZE is greater then HCA pgsz
- ASoC: wm_adsp: fix memleak in wm_adsp_buffer_populate
- firmware: arm_scmi: Fix possible frequency truncation when using level indexing mode
- firmware: arm_scmi: Simplify error path in scmi_dvfs_device_opps_add()
- firmware: arm_scmi: Fix frequency truncation by promoting multiplier type
- firmware: arm_scmi: Extend perf protocol ops to get information of a domain
- firmware: arm_scmi: Extend perf protocol ops to get number of domains
- hwmon: (nzxt-kraken2) Fix error handling path in kraken2_probe()
- ASoC: codecs: lpass-tx-macro: set active_decimator correct default value
- hwmon: (acpi_power_meter) Fix 4.29 MW bug
- ARM: dts: bcm2711-rpi-400: Fix delete-node of led_act
- ARM: dts: rockchip: Fix sdmmc_pwren's pinmux setting for RK3128
- ARM: dts: imx6q: skov: fix ethernet clock regression
- arm64: dt: imx93: tqma9352-mba93xxla: Fix LPUART2 pad config
- RDMA/irdma: Fix UAF in irdma_sc_ccq_get_cqe_info()
- RDMA/bnxt_re: Correct module description string
- RDMA/rtrs-clt: Remove the warnings for req in_use check
- RDMA/rtrs-clt: Fix the max_send_wr setting
- RDMA/rtrs-srv: Destroy path files after making sure no IOs in-flight
- RDMA/rtrs-srv: Free srv_mr iu only when always_invalidate is true
- RDMA/rtrs-srv: Check return values while processing info request
- RDMA/rtrs-clt: Start hb after path_up
- RDMA/rtrs-srv: Do not unconditionally enable irq
- ASoC: fsl_sai: Fix no frame sync clock issue on i.MX8MP
- arm64: dts: rockchip: Expand reg size of vdec node for RK3399
- arm64: dts: rockchip: Expand reg size of vdec node for RK3328
- RDMA/irdma: Add wait for suspend on SQD
- RDMA/irdma: Do not modify to SQD on error
- RDMA/hns: Fix unnecessary err return when using invalid congest control algorithm
- RDMA/core: Fix uninit-value access in ib_get_eth_speed()
- tee: optee: Fix supplicant based device enumeration
- mm/damon/sysfs: eliminate potential uninitialized variable warning
- drm/amdkfd: get doorbell's absolute offset based on the db_size
- drm/amd/amdgpu/amdgpu_doorbell_mgr: Correct misdocumented param 'doorbell_index'
- net/smc: fix missing byte order conversion in CLC handshake
- net: dsa: microchip: provide a list of valid protocols for xmit handler
- drop_monitor: Require 'CAP_SYS_ADMIN' when joining "events" group
- psample: Require 'CAP_NET_ADMIN' when joining "packets" group
- bpf: sockmap, updating the sg structure should also update curr
- net: tls, update curr on splice as well
- net: dsa: mv88e6xxx: Restore USXGMII support for 6393X
- tcp: do not accept ACK of bytes we never sent
- netfilter: xt_owner: Fix for unsafe access of sk->sk_socket
- netfilter: nf_tables: validate family when identifying table via handle
- netfilter: nf_tables: bail out on mismatching dynset and set expressions
- netfilter: nf_tables: fix 'exist' matching on bigendian arches
- netfilter: bpf: fix bad registration on nf_defrag
- dt-bindings: interrupt-controller: Allow #power-domain-cells
- octeontx2-af: Update Tx link register range
- octeontx2-af: Add missing mcs flr handler call
- octeontx2-af: Fix mcs stats register address
- octeontx2-af: Fix mcs sa cam entries size
- octeontx2-af: Adjust Tx credits when MCS external bypass is disabled
- net: hns: fix fake link up on xge port
- net: hns: fix wrong head when modify the tx feature when sending packets
- net: atlantic: Fix NULL dereference of skb pointer in
- ipv4: ip_gre: Avoid skb_pull() failure in ipgre_xmit()
- ionic: Fix dim work handling in split interrupt mode
- ionic: fix snprintf format length warning
- tcp: fix mid stream window clamp.
- net: bnxt: fix a potential use-after-free in bnxt_init_tc
- iavf: validate tx_coalesce_usecs even if rx_coalesce_usecs is zero
- i40e: Fix unexpected MFS warning message
- ice: Restore fix disabling RX VLAN filtering
- octeontx2-af: fix a use-after-free in rvu_npa_register_reporters
- xsk: Skip polling event check for unbound socket
- net: stmmac: fix FPE events losing
- octeontx2-pf: consider both Rx and Tx packet stats for adaptive interrupt coalescing
- arcnet: restoring support for multiple Sohard Arcnet cards
- platform/mellanox: Check devm_hwmon_device_register_with_groups() return value
- platform/mellanox: Add null pointer checks for devm_kasprintf()
- mlxbf-bootctl: correctly identify secure boot with development keys
- r8152: Add RTL8152_INACCESSIBLE to r8153_aldps_en()
- r8152: Add RTL8152_INACCESSIBLE to r8153_pre_firmware_1()
- r8152: Add RTL8152_INACCESSIBLE to r8156b_wait_loading_flash()
- r8152: Add RTL8152_INACCESSIBLE checks to more loops
- r8152: Hold the rtnl_lock for all of reset
- hv_netvsc: rndis_filter needs to select NLS
- bpf: Fix a verifier bug due to incorrect branch offset comparison with cpu=v4
- octeontx2-af: Check return value of nix_get_nixlf before using nixlf
- octeontx2-pf: Add missing mutex lock in otx2_get_pauseparam
- ipv6: fix potential NULL deref in fib6_add()
- platform/x86: wmi: Skip blocks with zero instances
- of: dynamic: Fix of_reconfig_get_state_change() return value documentation
- platform/x86: asus-wmi: Move i8042 filter install to shared asus-wmi code
- dt: dt-extract-compatibles: Don't follow symlinks when walking tree
- dt: dt-extract-compatibles: Handle cfile arguments in generator function
- x86/tdx: Allow 32-bit emulation by default
- x86/entry: Do not allow external 0x80 interrupts
- x86/entry: Convert INT 0x80 emulation to IDTENTRY
- x86/coco: Disable 32-bit emulation by default on TDX and SEV
- x86: Introduce ia32_enabled()
- dm-crypt: start allocating with MAX_ORDER
- drm/amdgpu: correct chunk_ptr to a pointer to chunk.
- drm/amdgpu: finalizing mem_partitions at the end of GMC v9 sw_fini
- drm/amdgpu: Do not program VF copy regs in mmhub v1.8 under SRIOV (v2)
- kconfig: fix memory leak from range properties
- modpost: fix section mismatch message for RELA
- tg3: Increment tx_dropped in tg3_tso_bug()
- tg3: Move the [rt]x_dropped counters to tg3_napi
- zstd: Fix array-index-out-of-bounds UBSAN warning
- nouveau: use an rwlock for the event lock.
- netfilter: ipset: fix race condition between swap/destroy and kernel side add/del/test
- i2c: ocores: Move system PM hooks to the NOIRQ phase
- i2c: designware: Fix corrupted memory seen in the ISR
- hrtimers: Push pending hrtimers away from outgoing CPU earlier
- scsi: sd: Fix sshdr use in sd_suspend_common()
- vdpa/mlx5: preserve CVQ vringh index
- !3749 support nokaslr and memmap parameter for kaslr collision detection
- kaslr: enable CONFIG_SKIP_KASLR_MEM_RANGE in openeuler defconfig
- x86/boot: add x86 nokaslr memory regions
- efi/libstub: add arm64 nokaslr memory regions
- efi/libstub: arm64: Fix KASLR and memmap= collision
- efi/libstub: arm64: support strchr function for EFI stub
- efi/libstub: add arm64 kaslr memory region avoid support
- !3737  arm64: Fix compilation error with ILP32
- config: Disable CONFIG_COMPAT_BINFMT_ELF as default
- arm64: Fix compilation error with ILP32 support
- Revert "Kconfig: regularize selection of CONFIG_BINFMT_ELF"
- !3743  Fix ppc32 build error
- powerpc: Fix ppc32 build
- !3713  Introduce CPU inspect feature
- openeuler_defconfig: enable CPU inspect for arm64 by default
- cpuinspect: add ATF inspector
- cpuinspect: add CPU-inspect infrastructure
- !3730  ARM: spectre-v2: turn off the mitigation via boot cmdline param
- ARM: spectre-v2: turn off the mitigation via boot cmdline param
- !3732  tcp_comp: implement tcp compression
- tcp_comp: implement tcp compression
- !3748  jffs2: move jffs2_init_inode_info() just after allocating inode
- jffs2: move jffs2_init_inode_info() just after allocating inode
- !3542  Support kernel livepatching
- livepatch/powerpc: Add arch_klp_module_check_calltrace
- livepatch/powerpc: Support breakpoint exception optimization
- livepatch/ppc64: Sample testcase fix ppc64
- livepatch/ppc64: Implement livepatch without ftrace for ppc64be
- livepatch: Bypass dead thread when check calltrace
- livepatch/arm: Add arch_klp_module_check_calltrace
- livepatch/arm64: Add arch_klp_module_check_calltrace
- livepatch/x86: Add arch_klp_module_check_calltrace
- livepatch: Add klp_module_delete_safety_check
- livepatch/arm: Support breakpoint exception optimization
- livepatch/arm64: Support breakpoint exception optimization
- livepatch: Add arch_klp_init
- livepatch/x86: Support breakpoint exception optimization
- livepatch: Use breakpoint exception to optimize enabling livepatch
- livepatch/ppc32: Support livepatch without ftrace
- livepatch/arm: Support livepatch without ftrace
- livepatch/core: Add support for arm for klp relocation
- arm/module: Use plt section indices for relocations
- livepatch: Enable livepatch configs in openeuler_defconfig
- livepatch/core: Revert module_enable_ro and module_disable_ro
- livepatch/arm64: Support livepatch without ftrace
- livepatch/core: Avoid conflict with static {call,key}
- livepatch: Fix patching functions which have static_call
- livepatch: Fix crash when access the global variable in hook
- livepatch/core: Support jump_label
- livepatch: samples: Adapt livepatch-sample for solution without ftrace
- livepatch/core: Support load and unload hooks
- livepatch/core: Restrict livepatch patched/unpatched when plant kprobe
- livepatch/core: Disable support for replacing
- livepatch/x86: Support livepatch without ftrace
- Revert "x86/insn: Make insn_complete() static"
- livepatch/core: Reuse common codes in the solution without ftrace
- livepatch/core: Allow implementation without ftrace
- !3678  timer_list: avoid other cpu soft lockup when printing timer list
- timer_list: avoid other cpu soft lockup when printing timer list
- !3733  drm/radeon: check the alloc_workqueue return value in radeon_crtc_init()
- drm/radeon: check the alloc_workqueue return value in radeon_crtc_init()
- !3734  Introduce qos smt expeller for co-location
- sched/fair: Add cmdline nosmtexpell
- sched/fair: Introduce QOS_SMT_EXPELL priority reversion mechanism
- sched/fair: Start tracking qos_offline tasks count in cfs_rq
- config: Enable CONFIG_QOS_SCHED_SMT_EXPELLER
- sched: Add tracepoint for qos smt expeller
- sched: Add statistics for qos smt expeller
- sched: Implement the function of qos smt expeller
- sched: Introduce qos smt expeller for co-location
- !3629  x86/kdump: make crash kernel boot faster
- x86/kdump: make crash kernel boot faster
- !3722  add memmap interface to reserved memory
- arm64: Request resources for reserved memory via memmap
- arm64: Add support for memmap kernel parameters
- !3724  lib/clear_user: ensure loop in __arch_clear_user cache-aligned v2
- config: enable CONFIG_CLEAR_USER_WORKAROUND by default
- lib/clear_user: ensure loop in __arch_clear_user cache-aligned v2
- !3688  Support priority load balance for qos scheduler
- sched: Introduce priority load balance for qos scheduler
- !3712  sched: steal tasks to improve CPU utilization
- config: enable CONFIG_SCHED_STEAL by default
- sched/fair: introduce SCHED_STEAL
- disable stealing by default
- sched/fair: Provide idle search schedstats
- sched/fair: disable stealing if too many NUMA nodes
- sched/fair: Steal work from an overloaded CPU when CPU goes idle
- sched/fair: Provide can_migrate_task_llc
- sched/fair: Generalize the detach_task interface
- sched/fair: Hoist idle_stamp up from idle_balance
- sched/fair: Dynamically update cfs_overload_cpus
- sched/topology: Provide cfs_overload_cpus bitmap
- sched/topology: Provide hooks to allocate data shared per LLC
- sched: Provide sparsemask, a reduced contention bitmap
- !3701  mm: Add sysctl to clear free list pages
- mm: Add sysctl to clear free list pages
- !3598  arm64: add config switch and kernel parameter for cpu0 hotplug
- config: disable config ARM64_BOOTPARAM_HOTPLUG_CPU0 by default
- arm64: Add config switch and kernel parameter for CPU0 hotplug
- !3649  x86/kdump: add log before booting crash kernel
- x86/kdump: add log before booting crash kernel
- !3700  Backport 6.6.6 LTS Patches
- Revert "wifi: cfg80211: fix CQM for non-range use"
- !3565  blk-throttle: enable hierarchical throttle in cgroup v1
- blk-throttle: enable hierarchical throttle in cgroup v1
- !3608  xfs: fix two corruption problems
- xfs: shutdown xfs once inode double free
- xfs: shutdown to ensure submits buffers on LSN boundaries
- !3674  mm/hugetlb: Introduce alloc_hugetlb_folio_size()
- mm/hugetlb: Introduce alloc_hugetlb_folio_size()
- !3651  nbd: get config_lock before sock_shutdown
- nbd: get config_lock before sock_shutdown
- !3573  Support dynamic affinity scheduler
- sched/fair: Modify idle cpu judgment in dynamic affinity
- sched/fair: Remove invalid cpu selection logic in dynamic affinity
- config: enable CONFIG_QOS_SCHED_DYNAMIC_AFFINITY by default
- sched: Add cmdline for dynamic affinity
- sched: Add statistics for scheduler dynamic affinity
- sched: Adjust cpu allowed in load balance dynamicly
- sched: Adjust wakeup cpu range according CPU util dynamicly
- cpuset: Introduce new interface for scheduler dynamic affinity
- sched: Introduce dynamic affinity for cfs scheduler
- !3599  arm64: Add framework to turn IPI as NMI
- arm64: kgdb: Roundup cpus using IPI as NMI
- kgdb: Expose default CPUs roundup fallback mechanism
- arm64: ipi_nmi: Add support for NMI backtrace
- nmi: backtrace: Allow runtime arch specific override
- arm64: smp: Assign and setup an IPI as NMI
- irqchip/gic-v3: Enable support for SGIs to act as NMIs
- arm64: Add framework to turn IPI as NMI
- !3638  memcg: support OOM priority for memcg
- memcg: enable CONFIG_MEMCG_OOM_PRIORITY by default
- memcg: Add sysctl memcg_qos_enable
- memcg: support priority for oom
- !3602  xfs: fix attr inactive problems
- xfs: atomic drop extent entries when inactiving attr
- xfs: factor out __xfs_da3_node_read()
- xfs: force shutdown xfs when xfs_attr_inactive fails
- !3601  xfs: fix perag leak when growfs fails
- xfs: fix perag leak when growfs fails
- xfs: add lock protection when remove perag from radix tree
- !3575  ubi: Enhance fault injection capability for the UBI driver
- mtd: Add several functions to the fail_function list
- ubi: Reserve sufficient buffer length for the input mask
- ubi: Add six fault injection type for testing
- ubi: Split io_failures into write_failure and erase_failure
- ubi: Use the fault injection framework to enhance the fault injection capability
- !3588 files cgroups
- enable CONFIG_CGROUP_FILES in openeuler_defconfig for x86 and arm64
- cgroup/files: support boot parameter to control if disable files cgroup
- fs/filescontrol: add a switch to enable / disable accounting of open fds
- cgroups: Resource controller for open files
- !3605  openeuler_defconfig: enable CONFIG_UNICODE for x86 and arm64
- openeuler_defconfig: enable CONFIG_UNICODE for x86 and arm64
- !3600  iommu/arm-smmu-v3: Add a SYNC command to avoid broken page table prefetch
- iommu/arm-smmu-v3: Add a SYNC command to avoid broken page table prefetch
- !3397  xfs: fix some growfs problems
- xfs: fix dir3 block read verify fail during log recover
- xfs: keep growfs sb log item active until ail flush success
- xfs: fix mounting failed caused by sequencing problem in the log records
- xfs: fix the problem of mount failure caused by not refreshing mp->m_sb
- !3582  Add support for memory limit
- mm: support pagecache limit
- mm: support periodical memory reclaim
- !3323  LoongArch: add cpufreq and ls2k500 bmc support
- LoongArch: fix ls2k500 bmc not work when installing iso
- LoongArch: defconfig: enable CONFIG_FB_LS2K500=m.
- ipmi: add ls2k500 bmc ipmi support.
- fbdev: add ls2k500sfb driver for ls2k500 bmc.
- cpufreq: Add cpufreq driver for LoongArch
- !3363  xfs: fix some misc issue
- xfs: xfs_trans_cancel() path must check for log shutdown
- xfs: don't verify agf length when log recovery
- xfs: fix a UAF in xfs_iflush_abort_clean
- xfs: fix a UAF when inode item push
- !3495  xfs: fix hung and warning
- xfs: fix warning in xfs_vm_writepages()
- xfs: fix hung when transaction commit fail in xfs_inactive_ifree
- xfs: fix dead loop when do mount with IO fault injection
- !3525 ARM: support kaslr feature in arm32 platform
- arm32: kaslr: Fix clock_gettime and gettimeofday performance degradation when configure CONFIG_RANDOMIZE_BASE
- arm32: kaslr: Fix the bug of symbols relocation
- arm32: kaslr: print kaslr offset when kernel panic
- arm32: kaslr: pop visibility when compile decompress boot code as we need relocate BSS by GOT.
- arm32: kaslr: When boot with vxboot, we must adjust dtb address before kaslr_early_init, and store dtb address after init.
- No idea why this broke ...
- ARM: decompressor: add KASLR support
- ARM: decompressor: explicitly map decompressor binary cacheable
- ARM: kernel: implement randomization of the kernel load address
- arm: vectors: use local symbol names for vector entry points
- ARM: kernel: refer to swapper_pg_dir via its symbol
- ARM: mm: export default vmalloc base address
- ARM: kernel: use PC relative symbol references in suspend/resume code
- ARM: kernel: use PC-relative symbol references in MMU switch code
- ARM: kernel: make vmlinux buildable as a PIE executable
- ARM: kernel: switch to relative exception tables
- arm-soc: various: replace open coded VA->PA calculation of pen_release
- arm-soc: mvebu: replace open coded VA->PA conversion
- arm-soc: exynos: replace open coded VA->PA conversions
- asm-generic: add .data.rel.ro sections to __ro_after_init
- !3563  memcg: support ksm merge any mode per cgroup
- memcg: support ksm merge any mode per cgroup
- !3528  Print rootfs and tmpfs files charged by memcg
- config: enable CONFIG_MEMCG_MEMFS_INFO by default
- mm/memcg_memfs_info: show files that having pages charged in mem_cgroup
- fs: move {lock, unlock}_mount_hash to fs/mount.h
- !3489  ascend: export interfaces required by ascend drivers
- ascend: export interfaces required by ascend drivers
- !3381 cgroupv1 cgroup writeback enable
- openeuler_defconfig: enable CONFIG_CGROUP_V1_WRITEBACK in openeuler_defconfig for x86 and arm64
- cgroup: support cgroup writeback on cgroupv1
- cgroup: factor out __cgroup_get_from_id() for cgroup v1
- !3537 backport cgroup bugs from olk5.10
- cgroup: disable kernel memory accounting for all memory cgroups by default
- cgroup: Return ERSCH when add Z process into task
- cgroup: wait for cgroup destruction to complete when umount
- cgroup: check if cgroup root is alive in cgroupstats_show()
- !3439  security: restrict init parameters by configuration
- security: restrict init parameters by configuration
- !3475  kaslr: ppc64: Introduce KASLR for PPC64
- powerpc/fsl_booke/kaslr: Fix preserved memory size for int-vectors issue
- powerpc/fsl_booke/kaslr: Provide correct r5 value for relocated kernel
- powerpc/fsl_booke/kaslr: rename kaslr-booke32.rst to kaslr-booke.rst and add 64bit part
- powerpc/fsl_booke/64: clear the original kernel if randomized
- powerpc/fsl_booke/64: do not clear the BSS for the second pass
- powerpc/fsl_booke/64: implement KASLR for fsl_booke64
- powerpc/fsl_booke/64: introduce reloc_kernel_entry() helper
- powerpc/fsl_booke/kaslr: refactor kaslr_legal_offset() and kaslr_early_init()
- !3486  sync smmu patches for olk-6.6
- iommu/arm-smmu-v3: disable stall for quiet_cd
- iommu/iova: Manage the depot list size
- iommu/iova: Make the rcache depot scale better
- !3434  arm64/ascend: Add new enable_oom_killer interface for oom contrl
- arm64/ascend: Add new enable_oom_killer interface for oom contrl
- !3479  cache: Workaround HiSilicon Linxicore DC CVAU
- cache: Workaround HiSilicon Linxicore DC CVAU
- !3367  ipv4: igmp: fix refcnt uaf issue when receiving igmp query packet
- ipv4: igmp: fix refcnt uaf issue when receiving igmp query packet
- !3471  add redis sockmap sample code
- tools: add sample sockmap code for redis
- net: add local_skb parameter to identify local tcp connection
- net: let sockops can use bpf_get_current_comm()
- !3432  ACPI / APEI: Notify all ras err to driver
- ACPI / APEI: Notify all ras err to driver

* Tue Dec 26 2023 Zheng Zengkai <zhengzengkai@huawei.com> - 6.6.0-2.0.0.2
- !3435  iommu/arm-smmu-v3: Add suspend and resume support
- !3315  Backport 6.6.5 LTS Patches
- !3314  Backport 6.6.4 LTS Patches
- !3286 block: Add config option to not allow writing to mounted devices
- !3430  Add support for hisi HBM devices
- !3431  memcg reclaim and cgroup kill
- iommu/arm-smmu-v3: Add suspend and resume support
- config: enable CONFIG_MEMCG_V1_RECLAIM and CONFIG_CGROUP_V1_KILL
- memcg: introduce per-memcg reclaim interface
- memcg: export high_async_ratio to userland
- memcg: enable memcg async reclaim
- memcg: Export memory.events{local} from cgroupv2 to cgroupv1
- memcg: Export memcg.{min/low/high} from cgroupv2 to cgroupv1
- cgroup: Export cgroup.kill from cgroupv2 to cgroupv1
- soc: hisilicon: hisi_hbmdev: Add hbm acls repair and query methods
- soc: hbmcache: Add support for online and offline the hbm cache
- soc: hisilicon: hisi_hbmdev: Provide extra memory topology information
- ACPI: memhotplug: export the state of each hotplug device
- soc: hisilicon: hisi_hbmdev: Add power domain control methods
- ACPI: OSL: Export the symbol of acpi_hotplug_schedule
- !3391  nbd_genl_status: null check for nla_nest_start
- !3352  support userswap feature
- !3383  Support Qos Scheduler
- nbd_genl_status: null check for nla_nest_start
- sched: Enable qos scheduler config
- sched: Introduce handle priority reversion mechanism
- sched: Support kill boost for offline task
- sched: Throttle qos cfs_rq when current cpu is running online task
- sched: Introduce qos scheduler for co-location
- !3306  improve gettimeofday() performance in user space
- !3331  kabi: add kabi helper macros and tools
- mm/userswap: openeuler_defconfig: enable userswap
- mm/userswap: provide cpu info in userfault msg
- mm/userswap: introduce UFFDIO_COPY_MODE_DIRECT_MAP
- mm/userswap: support userswap via userfaultfd
- mm/userswap: introduce MREMAP_USWAP_SET_PTE
- mm/userswap: add enable_userswap boot option
- mm/userswap: add VM_USWAP and SWP_USERSWAP_ENTRY
- !3326  config: Open CONFIG_AARCH32_EL0 and keep CONFIG_ARM64_ILP32 closed
- kabi: add kABI reference checking tool
- kabi: add a tool to generate the kabi reference relationship
- kabi: add script tools to check kabi symbol
- kabi: deduplication friendly structs
- kabi: Generalize naming of kabi helper macros
- openeuler_defconfig: Enable CONFIG_KABI_RESERVE for x86 and arm64
- KABI: Add CONFIG_KABI_RESERVE to control KABI padding reserve
- kabi: enables more stringent kabi checks
- kabi: add KABI_SIZE_ALIGN_CHECKS for more stringent kabi checks
- kabi: add kabi helper macros
- !3298  ARM: Add unwinding annotations to __loop.*delay functions
- config: Open CONFIG_AARCH32_EL0 and keep CONFIG_ARM64_ILP32 closed
- !3300  Add sharepool support v3
- vfio: Drop vfio_file_iommu_group() stub to fudge around a KVM wart
- x86/xen: fix percpu vcpu_info allocation
- vfio/pds: Fix possible sleep while in atomic context
- vfio/pds: Fix mutex lock->magic != lock warning
- drm/amd/display: Fix MPCC 1DLUT programming
- drm/amd/display: Simplify brightness initialization
- drm/amd/display: Reduce default backlight min from 5 nits to 1 nits
- drm/amd/display: refactor ILR to make it work
- iommu: Fix printk arg in of_iommu_get_resv_regions()
- drm/amd/pm: fix a memleak in aldebaran_tables_init
- cpufreq/amd-pstate: Only print supported EPP values for performance governor
- cpufreq/amd-pstate: Fix scaling_min_freq and scaling_max_freq update
- drm/panel: nt36523: fix return value check in nt36523_probe()
- drm/panel: starry-2081101qfh032011-53g: Fine tune the panel power sequence
- drm/i915/gsc: Mark internal GSC engine with reserved uabi class
- iommu/vt-d: Make context clearing consistent with context mapping
- iommu/vt-d: Disable PCI ATS in legacy passthrough mode
- iommu/vt-d: Omit devTLB invalidation requests when TES=0
- cpufreq: imx6q: Don't disable 792 Mhz OPP unnecessarily
- drm/amd/display: Remove power sequencing check
- drm/amd/display: Refactor edp power control
- s390/cmma: fix handling of swapper_pg_dir and invalid_pg_dir
- powerpc/pseries/iommu: enable_ddw incorrectly returns direct mapping for SR-IOV device
- net: ravb: Keep reverse order of operations in ravb_remove()
- net: ravb: Stop DMA in case of failures on ravb_open()
- net: ravb: Start TX queues after HW initialization succeeded
- net: ravb: Make write access to CXR35 first before accessing other EMAC registers
- net: ravb: Use pm_runtime_resume_and_get()
- net: ravb: Check return value of reset_control_deassert()
- ice: Fix VF Reset paths when interface in a failed over aggregate
- bpf, sockmap: af_unix stream sockets need to hold ref for pair sock
- ethtool: don't propagate EOPNOTSUPP from dumps
- ravb: Fix races between ravb_tx_timeout_work() and net related ops
- r8169: prevent potential deadlock in rtl8169_close
- efi/unaccepted: Fix off-by-one when checking for overlapping ranges
- neighbour: Fix __randomize_layout crash in struct neighbour
- octeontx2-pf: Restore TC ingress police rules when interface is up
- octeontx2-pf: Fix adding mbox work queue entry when num_vfs > 64
- net: stmmac: xgmac: Disable FPE MMC interrupts
- octeontx2-af: Fix possible buffer overflow
- selftests/net: mptcp: fix uninitialized variable warnings
- selftests/net: unix: fix unused variable compiler warning
- selftests/net: fix a char signedness issue
- selftests/net: ipsec: fix constant out of range
- uapi: propagate __struct_group() attributes to the container union
- bpf: Add missed allocation hint for bpf_mem_cache_alloc_flags()
- dpaa2-eth: recycle the RX buffer only after all processing done
- dpaa2-eth: increase the needed headroom to account for alignment
- net: dsa: mv88e6xxx: fix marvell 6350 probe crash
- net: dsa: mv88e6xxx: fix marvell 6350 switch probing
- wifi: mac80211: do not pass AP_VLAN vif pointer to drivers during flush
- wifi: iwlwifi: mvm: fix an error code in iwl_mvm_mld_add_sta()
- ipv4: igmp: fix refcnt uaf issue when receiving igmp query packet
- net: rswitch: Fix missing dev_kfree_skb_any() in error path
- net: rswitch: Fix return value in rswitch_start_xmit()
- net: rswitch: Fix type of ret in rswitch_start_xmit()
- netdevsim: Don't accept device bound programs
- media: v4l2-subdev: Fix a 64bit bug
- pinctrl: stm32: fix array read out of bound
- pinctrl: stm32: Add check for devm_kcalloc
- wifi: cfg80211: fix CQM for non-range use
- io_uring/kbuf: recycle freed mapped buffer ring entries
- io_uring/kbuf: defer release of mapped buffer rings
- io_uring: enable io_mem_alloc/free to be used in other parts
- btrfs: fix 64bit compat send ioctl arguments not initializing version member
- btrfs: free the allocated memory if btrfs_alloc_page_array() fails
- btrfs: make error messages more clear when getting a chunk map
- btrfs: send: ensure send_fd is writable
- btrfs: fix off-by-one when checking chunk map includes logical address
- btrfs: ref-verify: fix memory leaks in btrfs_ref_tree_mod()
- btrfs: add dmesg output for first mount and last unmount of a filesystem
- parisc: Mark altinstructions read-only and 32-bit aligned
- parisc: Ensure 32-bit alignment on parisc unwind section
- parisc: Mark jump_table naturally aligned
- parisc: Drop the HP-UX ENOSYM and EREMOTERELEASE error codes
- parisc: Mark lock_aligned variables 16-byte aligned on SMP
- parisc: Use natural CPU alignment for bug_table
- parisc: Mark ex_table entries 32-bit aligned in uaccess.h
- parisc: Mark ex_table entries 32-bit aligned in assembly.h
- powerpc: Don't clobber f0/vs0 during fp|altivec register save
- KVM: PPC: Book3S HV: Fix KVM_RUN clobbering FP/VEC user registers
- iommu/vt-d: Add MTL to quirk list to skip TE disabling
- ext2: Fix ki_pos update for DIO buffered-io fallback case
- bcache: revert replacing IS_ERR_OR_NULL with IS_ERR
- iommu: Avoid more races around device probe
- io_uring: don't guard IORING_OFF_PBUF_RING with SETUP_NO_MMAP
- dma-buf: fix check in dma_resv_add_fence
- cpufreq/amd-pstate: Fix the return value of amd_pstate_fast_switch()
- powercap: DTPM: Fix unneeded conversions to micro-Watts
- nouveau: find the smallest page allocation to cover a buffer alloc.
- io_uring: free io_buffer_list entries via RCU
- iommu/vt-d: Fix incorrect cache invalidation for mm notification
- io_uring: don't allow discontig pages for IORING_SETUP_NO_MMAP
- ACPI: video: Use acpi_video_device for cooling-dev driver data
- r8169: fix deadlock on RTL8125 in jumbo mtu mode
- nvme: check for valid nvme_identify_ns() before using it
- dm verity: don't perform FEC for failed readahead IO
- dm verity: initialize fec io before freeing it
- drm/amd/display: force toggle rate wa for first link training for a retimer
- drm/amd/display: fix ABM disablement
- drm/amd/display: Update min Z8 residency time to 2100 for DCN314
- drm/amd/display: Use DRAM speed from validation for dummy p-state
- drm/amd/display: Remove min_dst_y_next_start check for Z8
- drm/amd/display: Include udelay when waiting for INBOX0 ACK
- drm/amdgpu: Update EEPROM I2C address for smu v13_0_0
- drm/amdgpu: fix memory overflow in the IB test
- drm/amdgpu: Force order between a read and write to the same address
- drm/amdgpu: correct the amdgpu runtime dereference usage count
- drm/amd: Enable PCIe PME from D3
- scsi: ufs: core: Clear cmd if abort succeeds in MCQ mode
- scsi: sd: Fix system start for ATA devices
- scsi: Change SCSI device boolean fields to single bit flags
- dm-verity: align struct dm_verity_fec_io properly
- net: libwx: fix memory leak on msix entry
- ALSA: hda/realtek: Add supported ALC257 for ChromeOS
- ALSA: hda/realtek: Headset Mic VREF to 100%
- ALSA: hda: Disable power-save on KONTRON SinglePC
- drm/i915: Also check for VGA converter in eDP probe
- mmc: block: Be sure to wait while busy in CQE error recovery
- mmc: block: Do not lose cache flush during CQE error recovery
- mmc: block: Retry commands in CQE error recovery
- mmc: cqhci: Fix task clearing in CQE error recovery
- mmc: cqhci: Warn of halt or task clear failure
- mmc: cqhci: Increase recovery halt timeout
- mmc: sdhci-sprd: Fix vqmmc not shutting down after the card was pulled
- mmc: sdhci-pci-gli: Disable LPM during initialization
- firewire: core: fix possible memory leak in create_units()
- pinctrl: avoid reload of p state in list iteration
- ksmbd: fix possible deadlock in smb2_open
- smb: client: report correct st_size for SMB and NFS symlinks
- smb: client: fix missing mode bits for SMB symlinks
- cifs: Fix FALLOC_FL_INSERT_RANGE by setting i_size after EOF moved
- cifs: Fix FALLOC_FL_ZERO_RANGE by setting i_size if EOF moved
- leds: class: Don't expose color sysfs entry
- USB: dwc3: qcom: fix wakeup after probe deferral
- USB: dwc3: qcom: fix software node leak on probe errors
- usb: dwc3: set the dma max_seg_size
- usb: dwc3: Fix default mode initialization
- USB: dwc2: write HCINT with INTMASK applied
- usb: typec: tcpm: Skip hard reset when in error recovery
- usb: typec: tcpm: Fix sink caps op current check
- USB: serial: option: don't claim interface 4 for ZTE MF290
- USB: serial: option: fix FM101R-GL defines
- USB: serial: option: add Fibocom L7xx modules
- usb: cdnsp: Fix deadlock issue during using NCM gadget
- usb: config: fix iteration issue in 'usb_get_bos_descriptor()'
- USB: xhci-plat: fix legacy PHY double init
- bcache: fixup lock c->root error
- bcache: fixup init dirty data errors
- bcache: prevent potential division by zero error
- bcache: check return value from btree_node_alloc_replacement()
- veth: Use tstats per-CPU traffic counters
- dm-delay: fix a race between delay_presuspend and delay_bio
- ALSA: hda/realtek: Add quirks for ASUS 2024 Zenbooks
- ALSA: hda: ASUS UM5302LA: Added quirks for cs35L41/10431A83 on i2c bus
- cifs: fix leak of iface for primary channel
- cifs: account for primary channel in the interface list
- cifs: distribute channels across interfaces based on speed
- Revert "phy: realtek: usb: Add driver for the Realtek SoC USB 2.0 PHY"
- Revert "phy: realtek: usb: Add driver for the Realtek SoC USB 3.0 PHY"
- Revert "usb: phy: add usb phy notify port status API"
- hv_netvsc: Mark VF as slave before exposing it to user-mode
- hv_netvsc: Fix race of register_netdevice_notifier and VF register
- hv_netvsc: fix race of netvsc and VF register_netdevice
- platform/x86: ideapad-laptop: Set max_brightness before using it
- platform/x86/amd/pmc: adjust getting DRAM size behavior
- USB: serial: option: add Luat Air72*U series products
- usb: misc: onboard-hub: add support for Microchip USB5744
- dt-bindings: usb: microchip,usb5744: Add second supply
- platform/x86: hp-bioscfg: Fix error handling in hp_add_other_attributes()
- platform/x86: hp-bioscfg: move mutex_lock() down in hp_add_other_attributes()
- platform/x86: hp-bioscfg: Simplify return check in hp_add_other_attributes()
- s390/dasd: protect device queue against concurrent access
- io_uring/fs: consider link->flags when getting path for LINKAT
- bcache: fixup multi-threaded bch_sectors_dirty_init() wake-up race
- md: fix bi_status reporting in md_end_clone_io
- bcache: replace a mistaken IS_ERR() by IS_ERR_OR_NULL() in btree_gc_coalesce()
- io_uring: fix off-by one bvec index
- tls: fix NULL deref on tls_sw_splice_eof() with empty record
- swiotlb-xen: provide the "max_mapping_size" method
- ACPI: PM: Add acpi_device_fix_up_power_children() function
- ACPI: resource: Skip IRQ override on ASUS ExpertBook B1402CVA
- ACPI: processor_idle: use raw_safe_halt() in acpi_idle_play_dead()
- ACPI: video: Use acpi_device_fix_up_power_children()
- thunderbolt: Set lane bonding bit only for downstream port
- drm/ast: Disconnect BMC if physical connector is connected
- drm/msm/dpu: Add missing safe_lut_tbl in sc8280xp catalog
- kselftest/arm64: Fix output formatting for za-fork
- prctl: Disable prctl(PR_SET_MDWE) on parisc
- mm: add a NO_INHERIT flag to the PR_SET_MDWE prctl
- lockdep: Fix block chain corruption
- USB: dwc3: qcom: fix ACPI platform device leak
- USB: dwc3: qcom: fix resource leaks on probe deferral
- nvmet: nul-terminate the NQNs passed in the connect command
- nvme: blank out authentication fabrics options if not configured
- afs: Fix file locking on R/O volumes to operate in local mode
- afs: Return ENOENT if no cell DNS record can be found
- net: ipa: fix one GSI register field width
- net: axienet: Fix check for partial TX checksum
- vsock/test: fix SEQPACKET message bounds test
- i40e: Fix adding unsupported cloud filters
- amd-xgbe: propagate the correct speed and duplex status
- amd-xgbe: handle the corner-case during tx completion
- amd-xgbe: handle corner-case during sfp hotplug
- net: veth: fix ethtool stats reporting
- octeontx2-pf: Fix ntuple rule creation to direct packet to VF with higher Rx queue than its PF
- arm/xen: fix xen_vcpu_info allocation alignment
- arm64: mm: Fix "rodata=on" when CONFIG_RODATA_FULL_DEFAULT_ENABLED=y
- s390/ipl: add missing IPL_TYPE_ECKD_DUMP case to ipl_init()
- net/smc: avoid data corruption caused by decline
- net: usb: ax88179_178a: fix failed operations during ax88179_reset
- drm/panel: boe-tv101wum-nl6: Fine tune Himax83102-j02 panel HFP and HBP
- ipv4: Correct/silence an endian warning in __ip_do_redirect
- HID: fix HID device resource race between HID core and debugging support
- accel/ivpu/37xx: Fix hangs related to MMIO reset
- accel/ivpu: Do not initialize parameters on power up
- bpf: Fix dev's rx stats for bpf_redirect_peer traffic
- net: Move {l,t,d}stats allocation to core and convert veth & vrf
- net, vrf: Move dstats structure to core
- PM: tools: Fix sleepgraph syntax error
- drm/rockchip: vop: Fix color for RGB888/BGR888 format on VOP full
- libfs: getdents() should return 0 after reaching EOD
- block: update the stable_writes flag in bdev_add
- filemap: add a per-mapping stable writes flag
- drm/i915: do not clean GT table on error path
- ata: pata_isapnp: Add missing error check for devm_ioport_map()
- octeontx2-pf: Fix memory leak during interface down
- wireguard: use DEV_STATS_INC()
- net: wangxun: fix kernel panic due to null pointer
- drm/panel: simple: Fix Innolux G101ICE-L01 timings
- drm/panel: simple: Fix Innolux G101ICE-L01 bus flags
- fs: Pass AT_GETATTR_NOSEC flag to getattr interface function
- drm/panel: auo,b101uan08.3: Fine tune the panel power sequence
- blk-cgroup: avoid to warn !rcu_read_lock_held() in blkg_lookup()
- afs: Make error on cell lookup failure consistent with OpenAFS
- afs: Fix afs_server_list to be cleaned up with RCU
- rxrpc: Defer the response to a PING ACK until we've parsed it
- rxrpc: Fix RTT determination to use any ACK as a source
- s390/ism: ism driver implies smc protocol
- drm/msm/dsi: use the correct VREG_CTRL_1 value for 4nm cphy
- sched/fair: Fix the decision for load balance
- sched/eevdf: Fix vruntime adjustment on reweight
- hv/hv_kvp_daemon: Some small fixes for handling NM keyfiles
- irqchip/gic-v3-its: Flush ITS tables correctly in non-coherent GIC designs
- NFSD: Fix checksum mismatches in the duplicate reply cache
- NFSD: Fix "start of NFS reply" pointer passed to nfsd_cache_update()
- !3310  kasan: fix the compilation error for memcpy_mcs()
- kasan: fix the compilation error for memcpy_mcs()
- arm64: arch_timer: disable CONFIG_ARM_ARCH_TIMER_WORKAROUND_IN_USERSPACE
- vdso: do cntvct workaround in the VDSO
- arm64: arch_timer: Disable CNTVCT_EL0 trap if workaround is enabled
- mm/sharepool: Protect the va reserved for sharepool
- mm/sharepool: support fork() and exit() to handle the mm
- mm/sharepool: Add proc interfaces to show sp info
- mm/sharepool: Implement mg_sp_config_dvpp_range()
- mm/sharepool: Implement mg_sp_id_of_current()
- mm/sharepool: Implement mg_sp_group_id_by_pid()
- mm/sharepool: Implement mg_sp_group_add_task()
- mm/sharepool: Implement mg_sp_make_share_k2u()
- mm/sharepool: Implement mg_sp_alloc()
- mm/sharepool: Implement mg_sp_free()
- mm/sharepool: Implement mg_sp_walk_page_range()
- mm/sharepool: Implement mg_sp_unshare_kva
- mm/sharepool: Implement mg_sp_make_share_u2k()
- mm/sharepool: Reserve the va space for share_pool
- mm/sharepool: Add sp_area management code
- mm/sharepool: Add base framework for share_pool
- mm: Extend mmap assocated functions to accept mm_struct
- mm/vmalloc: Extend vmalloc usage about hugepage
- mm/hugetlb: Introduce hugetlb_insert_hugepage_pte[_by_pa]
- ARM: Add unwinding annotations to __loop.*delay functions
- !3285  arm64: errata: add option to disable cache readunique prefetch on HIP08
- !3280  arm64: add machine check safe support
- !3036  Added SM3 as module signing algorithm
- ext4: Block writes to journal device
- xfs: Block writes to log device
- fs: Block writes to mounted block devices
- btrfs: Do not restrict writes to btrfs devices
- block: Add config option to not allow writing to mounted devices
- arm64: errata: enable HISILICON_ERRATUM_HIP08_RU_PREFETCH
- arm64: errata: add option to disable cache readunique prefetch on HIP08
- arm64: add machine check safe sysctl interface
- arm64: introduce copy_mc_to_kernel() implementation
- arm64: support copy_mc_[user]_highpage()
- mm/hwpoison: return -EFAULT when copy fail in copy_mc_[user]_highpage()
- arm64: add uaccess to machine check safe
- arm64: add support for machine check error safe
- uaccess: add generic fallback version of copy_mc_to_user()
- !3275  arm64: kernel: disable CNP on LINXICORE9100
- !3099  block: Make blkdev_get_by_*() return
- arm64: kernel: disable CNP on LINXICORE9100
- !3111  openeuler_defconfig: enable some mm new
- !3211  Add SDEI Watchdog Support
- !3041  Random boot-time optimization
- !3026  Backport ARM64-ILP32 patches
- !3156  xfs: fix intent item leak during reovery
- !3137  LoongArch: add old BPI compatibility
- !3218  ipvlan: Introduce l2e mode
- !3209  exec: Remove redundant check in do_open_execat/uselib
- ipvlan: Introduce local xmit queue for l2e mode
- ipvlan: Introduce l2e mode
- arm64: kexec: only clear EOI for SDEI in NMI context
- stop_machine: mask sdei before running the callback
- openeuler_defconfig: Enable SDEI Watchdog
- kprobes/arm64: Blacklist sdei watchdog callback functions
- init: only move down lockup_detector_init() when sdei_watchdog is enabled
- sdei_watchdog: avoid possible false hardlockup
- sdei_watchdog: set secure timer period base on 'watchdog_thresh'
- sdei_watchdog: clear EOI of the secure timer before kdump
- watchdog: add nmi_watchdog support for arm64 based on SDEI
- lockup_detector: init lockup detector after all the init_calls
- firmware: arm_sdei: make 'sdei_api_event_disable/enable' public
- firmware: arm_sdei: add interrupt binding api
- exec: Remove redundant check in do_open_execat/uselib
- xfs: abort intent items when recovery intents fail
- xfs: factor out xfs_defer_pending_abort
- !3141 Backport 6.6.3 LTS Patches
- drm/amd/display: Change the DMCUB mailbox memory location from FB to inbox
- drm/amd/display: Clear dpcd_sink_ext_caps if not set
- drm/amd/display: Enable fast plane updates on DCN3.2 and above
- drm/amd/display: fix a NULL pointer dereference in amdgpu_dm_i2c_xfer()
- drm/amd/display: Fix DSC not Enabled on Direct MST Sink
- drm/amd/display: Guard against invalid RPTR/WPTR being set
- drm/amdgpu: Fix possible null pointer dereference
- drm/amdgpu: lower CS errors to debug severity
- drm/amdgpu: fix error handling in amdgpu_bo_list_get()
- drm/amdgpu: fix error handling in amdgpu_vm_init
- drm/amdgpu: don't use ATRM for external devices
- drm/amdgpu: add a retry for IP discovery init
- drm/amdgpu: fix GRBM read timeout when do mes_self_test
- drm/amdgpu: don't use pci_is_thunderbolt_attached()
- drm/amdgpu/smu13: drop compute workload workaround
- drm/amd/pm: Fix error of MACO flag setting code
- drm/i915: Flush WC GGTT only on required platforms
- drm/i915: Fix potential spectre vulnerability
- drm/i915: Bump GLK CDCLK frequency when driving multiple pipes
- drm/i915/mtl: Support HBR3 rate with C10 phy and eDP in MTL
- drm/amd/display: Add Null check for DPP resource
- x86/srso: Move retbleed IBPB check into existing 'has_microcode' code block
- drm: bridge: it66121: ->get_edid callback must not return err pointers
- drm/amd/pm: Handle non-terminated overdrive commands.
- ext4: fix racy may inline data check in dio write
- ext4: properly sync file size update after O_SYNC direct IO
- ext4: add missed brelse in update_backups
- ext4: remove gdb backup copy for meta bg in setup_new_flex_group_blocks
- ext4: correct the start block of counting reserved clusters
- ext4: correct return value of ext4_convert_meta_bg
- ext4: mark buffer new if it is unwritten to avoid stale data exposure
- ext4: correct offset of gdb backup in non meta_bg group to update_backups
- ext4: apply umask if ACL support is disabled
- ext4: make sure allocate pending entry not fail
- ext4: no need to generate from free list in mballoc
- ext4: fix race between writepages and remount
- Revert "net: r8169: Disable multicast filter for RTL8168H and RTL8107E"
- Revert "HID: logitech-dj: Add support for a new lightspeed receiver iteration"
- media: qcom: camss: Fix csid-gen2 for test pattern generator
- media: qcom: camss: Fix invalid clock enable bit disjunction
- media: qcom: camss: Fix set CSI2_RX_CFG1_VC_MODE when VC is greater than 3
- media: qcom: camss: Fix missing vfe_lite clocks check
- media: qcom: camss: Fix VFE-480 vfe_disable_output()
- media: qcom: camss: Fix VFE-17x vfe_disable_output()
- media: qcom: camss: Fix vfe_get() error jump
- media: qcom: camss: Fix pm_domain_on sequence in probe
- mmc: sdhci-pci-gli: GL9750: Mask the replay timer timeout of AER
- r8169: add handling DASH when DASH is disabled
- r8169: fix network lost after resume on DASH systems
- selftests: mptcp: fix fastclose with csum failure
- mptcp: fix setsockopt(IP_TOS) subflow locking
- mptcp: add validity check for sending RM_ADDR
- mptcp: deal with large GSO size
- mm: kmem: drop __GFP_NOFAIL when allocating objcg vectors
- mm: fix for negative counter: nr_file_hugepages
- mmc: sdhci-pci-gli: A workaround to allow GL9750 to enter ASPM L1.2
- riscv: kprobes: allow writing to x0
- riscv: correct pt_level name via pgtable_l5/4_enabled
- riscv: mm: Update the comment of CONFIG_PAGE_OFFSET
- riscv: put interrupt entries into .irqentry.text
- riscv: Using TOOLCHAIN_HAS_ZIHINTPAUSE marco replace zihintpause
- swiotlb: fix out-of-bounds TLB allocations with CONFIG_SWIOTLB_DYNAMIC
- swiotlb: do not free decrypted pages if dynamic
- tracing: fprobe-event: Fix to check tracepoint event and return
- LoongArch: Mark __percpu functions as always inline
- NFSD: Update nfsd_cache_append() to use xdr_stream
- nfsd: fix file memleak on client_opens_release
- dm-verity: don't use blocking calls from tasklets
- dm-bufio: fix no-sleep mode
- drm/mediatek/dp: fix memory leak on ->get_edid callback error path
- drm/mediatek/dp: fix memory leak on ->get_edid callback audio detection
- media: ccs: Correctly initialise try compose rectangle
- media: venus: hfi: add checks to handle capabilities from firmware
- media: venus: hfi: fix the check to handle session buffer requirement
- media: venus: hfi_parser: Add check to keep the number of codecs within range
- media: sharp: fix sharp encoding
- media: lirc: drop trailing space from scancode transmit
- f2fs: split initial and dynamic conditions for extent_cache
- f2fs: avoid format-overflow warning
- f2fs: set the default compress_level on ioctl
- f2fs: do not return EFSCORRUPTED, but try to run online repair
- i2c: i801: fix potential race in i801_block_transaction_byte_by_byte
- gfs2: don't withdraw if init_threads() got interrupted
- net: phylink: initialize carrier state at creation
- net: dsa: lan9303: consequently nested-lock physical MDIO
- net: ethtool: Fix documentation of ethtool_sprintf()
- s390/ap: fix AP bus crash on early config change callback invocation
- i2c: designware: Disable TX_EMPTY irq while waiting for block length byte
- sbsa_gwdt: Calculate timeout with 64-bit math
- lsm: fix default return value for inode_getsecctx
- lsm: fix default return value for vm_enough_memory
- Revert "i2c: pxa: move to generic GPIO recovery"
- Revert ncsi: Propagate carrier gain/loss events to the NCSI controller
- ALSA: hda/realtek: Add quirks for HP Laptops
- ALSA: hda/realtek: Enable Mute LED on HP 255 G10
- ALSA: hda/realtek - Enable internal speaker of ASUS K6500ZC
- ALSA: hda/realtek - Add Dell ALC295 to pin fall back table
- ALSA: hda/realtek: Enable Mute LED on HP 255 G8
- ALSA: info: Fix potential deadlock at disconnection
- btrfs: zoned: wait for data BG to be finished on direct IO allocation
- xfs: recovery should not clear di_flushiter unconditionally
- cifs: Fix encryption of cleared, but unset rq_iter data buffers
- cifs: do not pass cifs_sb when trying to add channels
- cifs: do not reset chan_max if multichannel is not supported at mount
- cifs: force interface update before a fresh session setup
- cifs: reconnect helper should set reconnect for the right channel
- smb: client: fix mount when dns_resolver key is not available
- smb: client: fix potential deadlock when releasing mids
- smb: client: fix use-after-free in smb2_query_info_compound()
- smb: client: fix use-after-free bug in cifs_debug_data_proc_show()
- smb3: fix caching of ctime on setxattr
- smb3: allow dumping session and tcon id to improve stats analysis and debugging
- smb3: fix touch -h of symlink
- smb3: fix creating FIFOs when mounting with "sfu" mount option
- xhci: Enable RPM on controllers that support low-power states
- parisc: fix mmap_base calculation when stack grows upwards
- parisc/power: Fix power soft-off when running on qemu
- parisc/pgtable: Do not drop upper 5 address bits of physical address
- parisc: Prevent booting 64-bit kernels on PA1.x machines
- selftests/resctrl: Extend signal handler coverage to unmount on receiving signal
- selftests/resctrl: Make benchmark command const and build it with pointers
- selftests/resctrl: Simplify span lifetime
- selftests/resctrl: Remove bw_report and bm_type from main()
- rcutorture: Fix stuttering races and other issues
- torture: Make torture_hrtimeout_ns() take an hrtimer mode parameter
- drm/amd/display: enable dsc_clk even if dsc_pg disabled
- Bluetooth: btusb: Add 0bda:b85b for Fn-Link RTL8852BE
- Bluetooth: btusb: Add RTW8852BE device 13d3:3570 to device tables
- apparmor: Fix regression in mount mediation
- apparmor: pass cred through to audit info.
- apparmor: rename audit_data->label to audit_data->subj_label
- apparmor: combine common_audit_data and apparmor_audit_data
- apparmor: Fix kernel-doc warnings in apparmor/policy.c
- apparmor: Fix kernel-doc warnings in apparmor/resource.c
- apparmor: Fix kernel-doc warnings in apparmor/lib.c
- apparmor: Fix kernel-doc warnings in apparmor/audit.c
- cxl/port: Fix delete_endpoint() vs parent unregistration race
- cxl/region: Fix x1 root-decoder granularity calculations
- i3c: master: svc: fix random hot join failure since timeout error
- i3c: master: svc: fix SDA keep low when polling IBIWON timeout happen
- i3c: master: svc: fix check wrong status register in irq handler
- i3c: master: svc: fix ibi may not return mandatory data byte
- i3c: master: svc: fix wrong data return when IBI happen during start frame
- i3c: master: svc: fix race condition in ibi work thread
- i3c: master: cdns: Fix reading status register
- cxl/region: Do not try to cleanup after cxl_region_setup_targets() fails
- mtd: cfi_cmdset_0001: Byte swap OTP info
- mm: make PR_MDWE_REFUSE_EXEC_GAIN an unsigned long
- mm/memory_hotplug: use pfn math in place of direct struct page manipulation
- mm/hugetlb: use nth_page() in place of direct struct page manipulation
- mm/cma: use nth_page() in place of direct struct page manipulation
- s390/cmma: fix detection of DAT pages
- s390/mm: add missing arch_set_page_dat() call to gmap allocations
- s390/mm: add missing arch_set_page_dat() call to vmem_crst_alloc()
- dmaengine: stm32-mdma: correct desc prep when channel running
- mcb: fix error handling for different scenarios when parsing
- driver core: Release all resources during unbind before updating device links
- tracing: Have the user copy of synthetic event address use correct context
- selftests/clone3: Fix broken test under !CONFIG_TIME_NS
- i2c: core: Run atomic i2c xfer when !preemptible
- mips: use nth_page() in place of direct struct page manipulation
- fs: use nth_page() in place of direct struct page manipulation
- scripts/gdb/vmalloc: disable on no-MMU
- kernel/reboot: emergency_restart: Set correct system_state
- quota: explicitly forbid quota files from being encrypted
- jbd2: fix potential data lost in recovering journal raced with synchronizing fs bdev
- ASoC: codecs: wsa-macro: fix uninitialized stack variables with name prefix
- hid: lenovo: Resend all settings on reset_resume for compact keyboards
- selftests/resctrl: Reduce failures due to outliers in MBA/MBM tests
- selftests/resctrl: Fix feature checks
- selftests/resctrl: Refactor feature check to use resource and feature name
- selftests/resctrl: Move _GNU_SOURCE define into Makefile
- selftests/resctrl: Remove duplicate feature check from CMT test
- selftests/resctrl: Fix uninitialized .sa_flags
- ASoC: codecs: wsa883x: make use of new mute_unmute_on_trigger flag
- ASoC: soc-dai: add flag to mute and unmute stream during trigger
- netfilter: nf_tables: split async and sync catchall in two functions
- netfilter: nf_tables: remove catchall element in GC sync path
- ima: detect changes to the backing overlay file
- ima: annotate iint mutex to avoid lockdep false positive warnings
- mfd: qcom-spmi-pmic: Fix revid implementation
- mfd: qcom-spmi-pmic: Fix reference leaks in revid helper
- leds: trigger: netdev: Move size check in set_device_name
- arm64: dts: qcom: ipq6018: Fix tcsr_mutex register size
- arm64: dts: qcom: ipq9574: Fix hwlock index for SMEM
- ACPI: FPDT: properly handle invalid FPDT subtables
- firmware: qcom_scm: use 64-bit calling convention only when client is 64-bit
- arm64: dts: qcom: ipq8074: Fix hwlock index for SMEM
- arm64: dts: qcom: ipq5332: Fix hwlock index for SMEM
- thermal: intel: powerclamp: fix mismatch in get function for max_idle
- btrfs: don't arbitrarily slow down delalloc if we're committing
- rcu: kmemleak: Ignore kmemleak false positives when RCU-freeing objects
- PM: hibernate: Clean up sync_read handling in snapshot_write_next()
- PM: hibernate: Use __get_safe_page() rather than touching the list
- dt-bindings: timer: renesas,rz-mtu3: Fix overflow/underflow interrupt names
- arm64: dts: qcom: ipq6018: Fix hwlock index for SMEM
- rcu/tree: Defer setting of jiffies during stall reset
- svcrdma: Drop connection after an RDMA Read error
- wifi: wilc1000: use vmm_table as array in wilc struct
- PCI: Lengthen reset delay for VideoPropulsion Torrent QN16e card
- PCI: exynos: Don't discard .remove() callback
- PCI: kirin: Don't discard .remove() callback
- PCI/ASPM: Fix L1 substate handling in aspm_attr_store_common()
- PCI: qcom-ep: Add dedicated callback for writing to DBI2 registers
- mmc: Add quirk MMC_QUIRK_BROKEN_CACHE_FLUSH for Micron eMMC Q2J54A
- mmc: sdhci_am654: fix start loop index for TAP value parsing
- mmc: vub300: fix an error code
- ksmbd: fix slab out of bounds write in smb_inherit_dacl()
- ksmbd: handle malformed smb1 message
- ksmbd: fix recursive locking in vfs helpers
- clk: qcom: ipq6018: drop the CLK_SET_RATE_PARENT flag from PLL clocks
- clk: qcom: ipq8074: drop the CLK_SET_RATE_PARENT flag from PLL clocks
- integrity: powerpc: Do not select CA_MACHINE_KEYRING
- clk: visconti: Fix undefined behavior bug in struct visconti_pll_provider
- clk: socfpga: Fix undefined behavior bug in struct stratix10_clock_data
- powercap: intel_rapl: Downgrade BIOS locked limits pr_warn() to pr_debug()
- cpufreq: stats: Fix buffer overflow detection in trans_stats()
- parisc/power: Add power soft-off when running on qemu
- parisc/pdc: Add width field to struct pdc_model
- parisc/agp: Use 64-bit LE values in SBA IOMMU PDIR table
- pmdomain: imx: Make imx pgc power domain also set the fwnode
- arm64: module: Fix PLT counting when CONFIG_RANDOMIZE_BASE=n
- arm64: Restrict CPU_BIG_ENDIAN to GNU as or LLVM IAS 15.x or newer
- pmdomain: amlogic: Fix mask for the second NNA mem PD domain
- PCI: keystone: Don't discard .probe() callback
- PCI: keystone: Don't discard .remove() callback
- KEYS: trusted: Rollback init_trusted() consistently
- KEYS: trusted: tee: Refactor register SHM usage
- pmdomain: bcm: bcm2835-power: check if the ASB register is equal to enable
- sched/core: Fix RQCF_ACT_SKIP leak
- genirq/generic_chip: Make irq_remove_generic_chip() irqdomain aware
- mmc: meson-gx: Remove setting of CMD_CFG_ERROR
- wifi: ath12k: fix dfs-radar and temperature event locking
- wifi: ath12k: fix htt mlo-offset event locking
- wifi: ath11k: fix gtk offload status event locking
- wifi: ath11k: fix htt pktlog locking
- wifi: ath11k: fix dfs radar event locking
- wifi: ath11k: fix temperature event locking
- regmap: Ensure range selector registers are updated after cache sync
- ACPI: resource: Do IRQ override on TongFang GMxXGxx
- parisc: Add nop instructions after TLB inserts
- mm/damon/sysfs: check error from damon_sysfs_update_target()
- mm/damon/core.c: avoid unintentional filtering out of schemes
- mm/damon/sysfs-schemes: handle tried regions sysfs directory allocation failure
- mm/damon/sysfs-schemes: handle tried region directory allocation failure
- mm/damon/core: avoid divide-by-zero during monitoring results update
- mm/damon: implement a function for max nr_accesses safe calculation
- mm/damon/ops-common: avoid divide-by-zero during region hotness calculation
- mm/damon/lru_sort: avoid divide-by-zero in hot threshold calculation
- dm crypt: account large pages in cc->n_allocated_pages
- fbdev: stifb: Make the STI next font pointer a 32-bit signed offset
- iommufd: Fix missing update of domains_itree after splitting iopt_area
- watchdog: move softlockup_panic back to early_param
- mm/damon/sysfs: update monitoring target regions for online input commit
- mm/damon/sysfs: remove requested targets when online-commit inputs
- PCI/sysfs: Protect driver's D3cold preference from user space
- hvc/xen: fix event channel handling for secondary consoles
- hvc/xen: fix error path in xen_hvc_init() to always register frontend driver
- hvc/xen: fix console unplug
- acpi/processor: sanitize _OSC/_PDC capabilities for Xen dom0
- tty: serial: meson: fix hard LOCKUP on crtscts mode
- tty/sysrq: replace smp_processor_id() with get_cpu()
- proc: sysctl: prevent aliased sysctls from getting passed to init
- audit: don't WARN_ON_ONCE(!current->mm) in audit_exe_compare()
- audit: don't take task_lock() in audit_exe_compare() code path
- sched: psi: fix unprivileged polling against cgroups
- mmc: sdhci-pci-gli: GL9755: Mask the replay timer timeout of AER
- KVM: x86: Fix lapic timer interrupt lost after loading a snapshot.
- KVM: x86: Clear bit12 of ICR after APIC-write VM-exit
- KVM: x86: Ignore MSR_AMD64_TW_CFG access
- KVM: x86: hyper-v: Don't auto-enable stimer on write from user-space
- x86/cpu/hygon: Fix the CPU topology evaluation for real
- x86/apic/msi: Fix misconfigured non-maskable MSI quirk
- x86/PCI: Avoid PME from D3hot/D3cold for AMD Rembrandt and Phoenix USB4
- crypto: x86/sha - load modules based on CPU features
- x86/shstk: Delay signal entry SSP write until after user accesses
- scsi: ufs: core: Fix racing issue between ufshcd_mcq_abort() and ISR
- scsi: qla2xxx: Fix system crash due to bad pointer access
- scsi: ufs: qcom: Update PHY settings only when scaling to higher gears
- scsi: megaraid_sas: Increase register read retry rount from 3 to 30 for selected registers
- scsi: mpt3sas: Fix loop logic
- bpf: Fix precision tracking for BPF_ALU | BPF_TO_BE | BPF_END
- bpf: Fix check_stack_write_fixed_off() to correctly spill imm
- spi: Fix null dereference on suspend
- randstruct: Fix gcc-plugin performance mode to stay in group
- powerpc/perf: Fix disabling BHRB and instruction sampling
- perf intel-pt: Fix async branch flags
- media: venus: hfi: add checks to perform sanity on queue pointers
- drivers: perf: Check find_first_bit() return value
- perf: arm_cspmu: Reject events meant for other PMUs
- i915/perf: Fix NULL deref bugs with drm_dbg() calls
- perf/core: Fix cpuctx refcounting
- cifs: fix check of rc in function generate_smb3signingkey
- cifs: spnego: add ';' in HOST_KEY_LEN
- scsi: ufs: core: Expand MCQ queue slot to DeviceQueueDepth + 1
- tools/power/turbostat: Enable the C-state Pre-wake printing
- tools/power/turbostat: Fix a knl bug
- macvlan: Don't propagate promisc change to lower dev in passthru
- net: sched: do not offload flows with a helper in act_ct
- net/mlx5e: Check return value of snprintf writing to fw_version buffer for representors
- net/mlx5e: Check return value of snprintf writing to fw_version buffer
- net/mlx5e: Reduce the size of icosq_str
- net/mlx5: Increase size of irq name buffer
- net/mlx5e: Update doorbell for port timestamping CQ before the software counter
- net/mlx5e: Track xmit submission to PTP WQ after populating metadata map
- net/mlx5e: Avoid referencing skb after free-ing in drop path of mlx5e_sq_xmit_wqe
- net/mlx5e: Don't modify the peer sent-to-vport rules for IPSec offload
- net/mlx5e: Fix pedit endianness
- net/mlx5e: fix double free of encap_header in update funcs
- net/mlx5e: fix double free of encap_header
- net/mlx5: Decouple PHC .adjtime and .adjphase implementations
- net/mlx5: Free used cpus mask when an IRQ is released
- Revert "net/mlx5: DR, Supporting inline WQE when possible"
- io_uring/fdinfo: remove need for sqpoll lock for thread/pid retrieval
- gve: Fixes for napi_poll when budget is 0
- pds_core: fix up some format-truncation complaints
- pds_core: use correct index to mask irq
- net: stmmac: avoid rx queue overrun
- net: stmmac: fix rx budget limit check
- netfilter: nf_tables: bogus ENOENT when destroying element which does not exist
- netfilter: nf_tables: fix pointer math issue in nft_byteorder_eval()
- netfilter: nf_conntrack_bridge: initialize err to 0
- af_unix: fix use-after-free in unix_stream_read_actor()
- net: ethernet: cortina: Fix MTU max setting
- net: ethernet: cortina: Handle large frames
- net: ethernet: cortina: Fix max RX frame define
- bonding: stop the device in bond_setup_by_slave()
- ptp: annotate data-race around q->head and q->tail
- blk-mq: make sure active queue usage is held for bio_integrity_prep()
- xen/events: fix delayed eoi list handling
- ppp: limit MRU to 64K
- net: mvneta: fix calls to page_pool_get_stats
- tipc: Fix kernel-infoleak due to uninitialized TLV value
- net: hns3: fix VF wrong speed and duplex issue
- net: hns3: fix VF reset fail issue
- net: hns3: fix variable may not initialized problem in hns3_init_mac_addr()
- net: hns3: fix out-of-bounds access may occur when coalesce info is read via debugfs
- net: hns3: fix incorrect capability bit display for copper port
- net: hns3: add barrier in vf mailbox reply process
- net: hns3: fix add VLAN fail issue
- xen/events: avoid using info_for_irq() in xen_send_IPI_one()
- net: ti: icssg-prueth: Fix error cleanup on failing pruss_request_mem_region
- net: ti: icssg-prueth: Add missing icss_iep_put to error path
- tty: Fix uninit-value access in ppp_sync_receive()
- ipvlan: add ipvlan_route_v6_outbound() helper
- net: set SOCK_RCU_FREE before inserting socket into hashtable
- bpf: fix control-flow graph checking in privileged mode
- bpf: fix precision backtracking instruction iteration
- bpf: handle ldimm64 properly in check_cfg()
- gcc-plugins: randstruct: Only warn about true flexible arrays
- vhost-vdpa: fix use after free in vhost_vdpa_probe()
- vdpa_sim_blk: allocate the buffer zeroed
- riscv: split cache ops out of dma-noncoherent.c
- drm/i915/tc: Fix -Wformat-truncation in intel_tc_port_init
- gfs2: Silence "suspicious RCU usage in gfs2_permission" warning
- riscv: provide riscv-specific is_trap_insn()
- RISC-V: hwprobe: Fix vDSO SIGSEGV
- SUNRPC: Fix RPC client cleaned up the freed pipefs dentries
- NFSv4.1: fix SP4_MACH_CRED protection for pnfs IO
- SUNRPC: Add an IS_ERR() check back to where it was
- NFSv4.1: fix handling NFS4ERR_DELAY when testing for session trunking
- drm/i915/mtl: avoid stringop-overflow warning
- mtd: rawnand: meson: check return value of devm_kasprintf()
- mtd: rawnand: intel: check return value of devm_kasprintf()
- SUNRPC: ECONNRESET might require a rebind
- dt-bindings: serial: fix regex pattern for matching serial node children
- samples/bpf: syscall_tp_user: Fix array out-of-bound access
- samples/bpf: syscall_tp_user: Rename num_progs into nr_tests
- sched/core: Optimize in_task() and in_interrupt() a bit
- wifi: iwlwifi: Use FW rate for non-data frames
- mtd: rawnand: tegra: add missing check for platform_get_irq()
- pwm: Fix double shift bug
- drm/amdgpu: fix software pci_unplug on some chips
- ALSA: hda/realtek: Add quirk for ASUS UX7602ZM
- drm/qxl: prevent memory leak
- ASoC: ti: omap-mcbsp: Fix runtime PM underflow warnings
- i2c: dev: copy userspace array safely
- riscv: VMAP_STACK overflow detection thread-safe
- kgdb: Flush console before entering kgdb on panic
- gfs2: Fix slab-use-after-free in gfs2_qd_dealloc
- drm/amd/display: Avoid NULL dereference of timing generator
- media: imon: fix access to invalid resource for the second interface
- media: ccs: Fix driver quirk struct documentation
- media: cobalt: Use FIELD_GET() to extract Link Width
- gfs2: fix an oops in gfs2_permission
- gfs2: ignore negated quota changes
- media: ipu-bridge: increase sensor_name size
- media: vivid: avoid integer overflow
- media: gspca: cpia1: shift-out-of-bounds in set_flicker
- i3c: master: mipi-i3c-hci: Fix a kernel panic for accessing DAT_data.
- virtio-blk: fix implicit overflow on virtio_max_dma_size
- i2c: sun6i-p2wi: Prevent potential division by zero
- i2c: fix memleak in i2c_new_client_device()
- i2c: i801: Add support for Intel Birch Stream SoC
- i3c: mipi-i3c-hci: Fix out of bounds access in hci_dma_irq_handler
- 9p: v9fs_listxattr: fix %s null argument warning
- 9p/trans_fd: Annotate data-racy writes to file::f_flags
- usb: gadget: f_ncm: Always set current gadget in ncm_bind()
- usb: host: xhci: Avoid XHCI resume delay if SSUSB device is not present
- f2fs: fix error handling of __get_node_page
- f2fs: fix error path of __f2fs_build_free_nids
- soundwire: dmi-quirks: update HP Omen match
- usb: ucsi: glink: use the connector orientation GPIO to provide switch events
- usb: dwc3: core: configure TX/RX threshold for DWC3_IP
- phy: qualcomm: phy-qcom-eusb2-repeater: Zero out untouched tuning regs
- phy: qualcomm: phy-qcom-eusb2-repeater: Use regmap_fields
- dt-bindings: phy: qcom,snps-eusb2-repeater: Add magic tuning overrides
- tty: vcc: Add check for kstrdup() in vcc_probe()
- thunderbolt: Apply USB 3.x bandwidth quirk only in software connection manager
- iio: adc: stm32-adc: harden against NULL pointer deref in stm32_adc_probe()
- mfd: intel-lpss: Add Intel Lunar Lake-M PCI IDs
- exfat: support handle zero-size directory
- HID: Add quirk for Dell Pro Wireless Keyboard and Mouse KM5221W
- crypto: hisilicon/qm - prevent soft lockup in receive loop
- ASoC: Intel: soc-acpi-cht: Add Lenovo Yoga Tab 3 Pro YT3-X90 quirk
- PCI: Use FIELD_GET() in Sapphire RX 5600 XT Pulse quirk
- misc: pci_endpoint_test: Add Device ID for R-Car S4-8 PCIe controller
- PCI: dwc: Add missing PCI_EXP_LNKCAP_MLW handling
- PCI: dwc: Add dw_pcie_link_set_max_link_width()
- PCI: Disable ATS for specific Intel IPU E2000 devices
- PCI: Extract ATS disabling to a helper function
- PCI: Use FIELD_GET() to extract Link Width
- scsi: libfc: Fix potential NULL pointer dereference in fc_lport_ptp_setup()
- PCI: Do error check on own line to split long "if" conditions
- atm: iphase: Do PCI error checks on own line
- PCI: mvebu: Use FIELD_PREP() with Link Width
- PCI: tegra194: Use FIELD_GET()/FIELD_PREP() with Link Width fields
- gpiolib: of: Add quirk for mt2701-cs42448 ASoC sound
- ALSA: hda: Fix possible null-ptr-deref when assigning a stream
- ARM: 9320/1: fix stack depot IRQ stack filter
- HID: lenovo: Detect quirk-free fw on cptkbd and stop applying workaround
- jfs: fix array-index-out-of-bounds in diAlloc
- jfs: fix array-index-out-of-bounds in dbFindLeaf
- fs/jfs: Add validity check for db_maxag and db_agpref
- fs/jfs: Add check for negative db_l2nbperpage
- scsi: ibmvfc: Remove BUG_ON in the case of an empty event pool
- scsi: hisi_sas: Set debugfs_dir pointer to NULL after removing debugfs
- RDMA/hfi1: Use FIELD_GET() to extract Link Width
- ASoC: SOF: ipc4: handle EXCEPTION_CAUGHT notification from firmware
- crypto: pcrypt - Fix hungtask for PADATA_RESET
- ASoC: cs35l56: Use PCI SSID as the firmware UID
- ASoC: Intel: sof_sdw: Copy PCI SSID to struct snd_soc_card
- ASoC: SOF: Pass PCI SSID to machine driver
- ASoC: soc-card: Add storage for PCI SSID
- ASoC: mediatek: mt8188-mt6359: support dynamic pinctrl
- selftests/efivarfs: create-read: fix a resource leak
- arm64: dts: ls208xa: use a pseudo-bus to constrain usb dma size
- arm64: dts: rockchip: Add NanoPC T6 PCIe e-key support
- soc: qcom: pmic: Fix resource leaks in a device_for_each_child_node() loop
- drm/amd: check num of link levels when update pcie param
- drm/amd/display: fix num_ways overflow error
- drm/amd: Disable PP_PCIE_DPM_MASK when dynamic speed switching not supported
- drm/amdgpu: Fix a null pointer access when the smc_rreg pointer is NULL
- drm/amdkfd: Fix shift out-of-bounds issue
- drm/panel: st7703: Pick different reset sequence
- drm/amdgpu/vkms: fix a possible null pointer dereference
- drm/radeon: fix a possible null pointer dereference
- drm/panel/panel-tpo-tpg110: fix a possible null pointer dereference
- drm/panel: fix a possible null pointer dereference
- drm/amdgpu: Fix potential null pointer derefernce
- drm/amd: Fix UBSAN array-index-out-of-bounds for Polaris and Tonga
- drm/amd: Fix UBSAN array-index-out-of-bounds for SMU7
- drm/msm/dp: skip validity check for DP CTS EDID checksum
- drm: vmwgfx_surface.c: copy user-array safely
- drm_lease.c: copy user-array safely
- kernel: watch_queue: copy user-array safely
- kernel: kexec: copy user-array safely
- string.h: add array-wrappers for (v)memdup_user()
- drm/amd/display: use full update for clip size increase of large plane source
- drm/amd: Update `update_pcie_parameters` functions to use uint8_t arguments
- drm/amdgpu: update retry times for psp vmbx wait
- drm/amdkfd: Fix a race condition of vram buffer unref in svm code
- drm/amdgpu: not to save bo in the case of RAS err_event_athub
- md: don't rely on 'mddev->pers' to be set in mddev_suspend()
- drm/edid: Fixup h/vsync_end instead of h/vtotal
- drm/amd/display: add seamless pipe topology transition check
- drm/amd/display: Don't lock phantom pipe on disabling
- drm/amd/display: Blank phantom OTG before enabling
- drm/komeda: drop all currently held locks if deadlock happens
- drm/amdkfd: ratelimited SQ interrupt messages
- drm/gma500: Fix call trace when psb_gem_mm_init() fails
- platform/x86: thinkpad_acpi: Add battery quirk for Thinkpad X120e
- of: address: Fix address translation when address-size is greater than 2
- platform/chrome: kunit: initialize lock for fake ec_dev
- gpiolib: acpi: Add a ignore interrupt quirk for Peaq C1010
- tsnep: Fix tsnep_request_irq() format-overflow warning
- ACPI: EC: Add quirk for HP 250 G7 Notebook PC
- Bluetooth: Fix double free in hci_conn_cleanup
- Bluetooth: btusb: Add date->evt_skb is NULL check
- wifi: iwlwifi: mvm: fix size check for fw_link_id
- bpf: Ensure proper register state printing for cond jumps
- vsock: read from socket's error queue
- net: sfp: add quirk for FS's 2.5G copper SFP
- wifi: ath10k: Don't touch the CE interrupt registers after power up
- wifi: ath12k: mhi: fix potential memory leak in ath12k_mhi_register()
- net: annotate data-races around sk->sk_dst_pending_confirm
- net: annotate data-races around sk->sk_tx_queue_mapping
- wifi: mt76: fix clang-specific fortify warnings
- wifi: mt76: mt7921e: Support MT7992 IP in Xiaomi Redmibook 15 Pro (2023)
- net: sfp: add quirk for Fiberstone GPON-ONU-34-20BI
- ACPI: APEI: Fix AER info corruption when error status data has multiple sections
- wifi: ath12k: fix possible out-of-bound write in ath12k_wmi_ext_hal_reg_caps()
- wifi: ath10k: fix clang-specific fortify warning
- wifi: ath12k: fix possible out-of-bound read in ath12k_htt_pull_ppdu_stats()
- wifi: ath9k: fix clang-specific fortify warnings
- bpf: Detect IP == ksym.end as part of BPF program
- atl1c: Work around the DMA RX overflow issue
- wifi: mac80211: don't return unset power in ieee80211_get_tx_power()
- wifi: mac80211_hwsim: fix clang-specific fortify warning
- wifi: ath12k: Ignore fragments from uninitialized peer in dp
- wifi: plfxlc: fix clang-specific fortify warning
- x86/mm: Drop the 4 MB restriction on minimal NUMA node memory size
- workqueue: Provide one lock class key per work_on_cpu() callsite
- cpu/hotplug: Don't offline the last non-isolated CPU
- smp,csd: Throw an error if a CSD lock is stuck for too long
- srcu: Only accelerate on enqueue time
- clocksource/drivers/timer-atmel-tcb: Fix initialization on SAM9 hardware
- clocksource/drivers/timer-imx-gpt: Fix potential memory leak
- selftests/lkdtm: Disable CONFIG_UBSAN_TRAP in test config
- srcu: Fix srcu_struct node grpmask overflow on 64-bit systems
- perf/core: Bail out early if the request AUX area is out of bound
- x86/retpoline: Make sure there are no unconverted return thunks due to KCSAN
- lib/generic-radix-tree.c: Don't overflow in peek()
- btrfs: abort transaction on generation mismatch when marking eb as dirty
- locking/ww_mutex/test: Fix potential workqueue corruption
- LoongArch: use arch specific phys_to_dma
- LoongArch: Fixed EIOINTC structure members
- LoongArch: Fix virtual machine startup error
- LoongArch: Old BPI compatibility
- LoongArch: add kernel setvirtmap for runtime
- arm64: openeuler_defconfig: update for new feature
- x86: openeuler_defconfig: update from new feature
- erofs: fix NULL dereference of dif->bdev_handle in fscache mode
- block: Remove blkdev_get_by_*() functions
- bcache: Fixup error handling in register_cache()
- xfs: Convert to bdev_open_by_path()
- reiserfs: Convert to bdev_open_by_dev/path()
- ocfs2: Convert to use bdev_open_by_dev()
- nfs/blocklayout: Convert to use bdev_open_by_dev/path()
- jfs: Convert to bdev_open_by_dev()
- f2fs: Convert to bdev_open_by_dev/path()
- ext4: Convert to bdev_open_by_dev()
- erofs: Convert to use bdev_open_by_path()
- btrfs: Convert to bdev_open_by_path()
- fs: Convert to bdev_open_by_dev()
- mm/swap: Convert to use bdev_open_by_dev()
- PM: hibernate: Drop unused snapshot_test argument
- PM: hibernate: Convert to bdev_open_by_dev()
- scsi: target: Convert to bdev_open_by_path()
- s390/dasd: Convert to bdev_open_by_path()
- nvmet: Convert to bdev_open_by_path()
- mtd: block2mtd: Convert to bdev_open_by_dev/path()
- md: Convert to bdev_open_by_dev()
- dm: Convert to bdev_open_by_dev()
- bcache: Convert to bdev_open_by_path()
- zram: Convert to use bdev_open_by_dev()
- xen/blkback: Convert to bdev_open_by_dev()
- rnbd-srv: Convert to use bdev_open_by_path()
- pktcdvd: Convert to bdev_open_by_dev()
- drdb: Convert to use bdev_open_by_path()
- block: Use bdev_open_by_dev() in disk_scan_partitions() and blkdev_bszset()
- block: Use bdev_open_by_dev() in blkdev_open()
- block: Provide bdev_open_* functions
- alinux: random: speed up the initialization of module
- keys: Allow automatic module signature with SM3
- arm64: fix image size inflation with CONFIG_COMPAT_TASK_SIZE
- arm64: set 32-bit compatible TASK_SIZE_MAX to fix U32 libc_write_01 error
- arm64: replace is_compat_task() with is_ilp32_compat_task() in TASK_SIZE_MAX
- arm64: fix address limit problem with TASK_SIZE_MAX
- ilp32: fix compile problem when ARM64_ILP32 and UBSAN are both enabled
- arm64: fix abi change caused by ILP32
- arm64: fix AUDIT_ARCH_AARCH64ILP32 bug on audit subsystem
- ilp32: skip ARM erratum 1418040 for ilp32 application
- ilp32: avoid clearing upper 32 bits of syscall return value for ilp32
- arm64: secomp: fix the secure computing mode 1 syscall check for ilp32
- arm64:ilp32: add ARM64_ILP32 to Kconfig
- arm64:ilp32: add vdso-ilp32 and use for signal return
- arm64: ptrace: handle ptrace_request differently for aarch32 and ilp32
- arm64: ilp32: introduce ilp32-specific sigframe and ucontext
- arm64: signal32: move ilp32 and aarch32 common code to separated file
- arm64: signal: share lp64 signal structures and routines to ilp32
- arm64: ilp32: introduce syscall table for ILP32
- arm64: ilp32: share aarch32 syscall handlers
- arm64: ilp32: introduce binfmt_ilp32.c
- arm64: change compat_elf_hwcap and compat_elf_hwcap2 prefix to a32
- arm64: introduce binfmt_elf32.c
- arm64: introduce AUDIT_ARCH_AARCH64ILP32 for ilp32
- arm64: ilp32: add is_ilp32_compat_{task,thread} and TIF_32BIT_AARCH64
- arm64: introduce is_a32_compat_{task,thread} for AArch32 compat
- arm64: uapi: set __BITS_PER_LONG correctly for ILP32 and LP64
- arm64: rename functions that reference compat term
- arm64: rename COMPAT to AARCH32_EL0
- arm64: ilp32: add documentation on the ILP32 ABI for ARM64
- thread: move thread bits accessors to separated file
- ptrace: Add compat PTRACE_{G,S}ETSIGMASK handlers
- arm64: signal: Make parse_user_sigframe() independent of rt_sigframe layout

* Tue Dec 5 2023 Zheng Zengkai <zhengzengkai@huawei.com> - 6.6.0-1.0.0.1
- !3058  tcp/dccp: Add another way to allocate local ports in connect()
- !3064  mm: PCP high auto-tuning
- !2985  hugetlbfs: avoid overflow in hugetlbfs_fallocate
- !3059  Handle more faults under the VMA lock
- mm, pcp: reduce detecting time of consecutive high order page freeing
- mm, pcp: decrease PCP high if free pages < high watermark
- mm: tune PCP high automatically
- mm: add framework for PCP high auto-tuning
- mm, page_alloc: scale the number of pages that are batch allocated
- mm: restrict the pcp batch scale factor to avoid too long latency
- mm, pcp: reduce lock contention for draining high-order pages
- cacheinfo: calculate size of per-CPU data cache slice
- mm, pcp: avoid to drain PCP when process exit
- mm: handle write faults to RO pages under the VMA lock
- mm: handle read faults under the VMA lock
- mm: handle COW faults under the VMA lock
- mm: handle shared faults under the VMA lock
- mm: call wp_page_copy() under the VMA lock
- mm: make lock_folio_maybe_drop_mmap() VMA lock aware
- tcp/dccp: Add another way to allocate local ports in connect()
- !3044  mm: hugetlb: Skip initialization of gigantic tail struct pages if freed by HVO
- !2980  io_uring: fix soft lockup in io_submit_sqes()
- !3014  anolis: bond: broadcast ARP or ND messages to all slaves
- !3018  folio conversions for numa balance
- mm: hugetlb: skip initialization of gigantic tail struct pages if freed by HVO
- memblock: introduce MEMBLOCK_RSRV_NOINIT flag
- memblock: pass memblock_type to memblock_setclr_flag
- mm: hugetlb_vmemmap: use nid of the head page to reallocate it
- mm: remove page_cpupid_xchg_last()
- mm: use folio_xchg_last_cpupid() in wp_page_reuse()
- mm: convert wp_page_reuse() and finish_mkwrite_fault() to take a folio
- mm: make finish_mkwrite_fault() static
- mm: huge_memory: use folio_xchg_last_cpupid() in __split_huge_page_tail()
- mm: migrate: use folio_xchg_last_cpupid() in folio_migrate_flags()
- sched/fair: use folio_xchg_last_cpupid() in should_numa_migrate_memory()
- mm: add folio_xchg_last_cpupid()
- mm: remove xchg_page_access_time()
- mm: huge_memory: use a folio in change_huge_pmd()
- mm: mprotect: use a folio in change_pte_range()
- sched/fair: use folio_xchg_access_time() in numa_hint_fault_latency()
- mm: add folio_xchg_access_time()
- mm: remove page_cpupid_last()
- mm: huge_memory: use folio_last_cpupid() in __split_huge_page_tail()
- mm: huge_memory: use folio_last_cpupid() in do_huge_pmd_numa_page()
- mm: memory: use folio_last_cpupid() in do_numa_page()
- mm: add folio_last_cpupid()
- mm_types: add virtual and _last_cpupid into struct folio
- sched/numa, mm: make numa migrate functions to take a folio
- mm: mempolicy: make mpol_misplaced() to take a folio
- mm: memory: make numa_migrate_prep() to take a folio
- mm: memory: use a folio in do_numa_page()
- mm: huge_memory: use a folio in do_huge_pmd_numa_page()
- mm: memory: add vm_normal_folio_pmd()
- mm: migrate: remove isolated variable in add_page_for_migration()
- mm: migrate: remove PageHead() check for HugeTLB in add_page_for_migration()
- mm: migrate: use a folio in add_page_for_migration()
- mm: migrate: use __folio_test_movable()
- mm: migrate: convert migrate_misplaced_page() to migrate_misplaced_folio()
- mm: migrate: convert numamigrate_isolate_page() to numamigrate_isolate_folio()
- mm: migrate: remove THP mapcount check in numamigrate_isolate_page()
- mm: migrate: remove PageTransHuge check in numamigrate_isolate_page()
- anolis: bond: broadcast ARP or ND messages to all slaves
- hugetlbfs: avoid overflow in hugetlbfs_fallocate
- io_uring: fix soft lockup in io_submit_sqes()
- !2971  net: sched: sch_qfq: Use non-work-conserving warning handler
- !2968  checkpatch: Update link tags to fix ci warning
- net: sched: sch_qfq: Use non-work-conserving warning handler
- checkpatch: Update check of link tags
- !2945 Backport linux 6.6.2 LTS patches
- btrfs: make found_logical_ret parameter mandatory for function queue_scrub_stripe()
- btrfs: use u64 for buffer sizes in the tree search ioctls
- Revert "mmc: core: Capture correct oemid-bits for eMMC cards"
- Revert "PCI/ASPM: Disable only ASPM_STATE_L1 when driver, disables L1"
- x86/amd_nb: Use Family 19h Models 60h-7Fh Function 4 IDs
- io_uring/net: ensure socket is marked connected on connect retry
- selftests: mptcp: fix wait_rm_addr/sf parameters
- selftests: mptcp: run userspace pm tests slower
- eventfs: Check for NULL ef in eventfs_set_attr()
- tracing/kprobes: Fix the order of argument descriptions
- fbdev: fsl-diu-fb: mark wr_reg_wa() static
- ALSA: hda/realtek: Add support dual speaker for Dell
- fbdev: imsttfb: fix a resource leak in probe
- fbdev: imsttfb: fix double free in probe()
- arm64/arm: arm_pmuv3: perf: Don't truncate 64-bit registers
- spi: spi-zynq-qspi: add spi-mem to driver kconfig dependencies
- ASoC: dapm: fix clock get name
- ASoC: hdmi-codec: register hpd callback on component probe
- ASoC: mediatek: mt8186_mt6366_rt1019_rt5682s: trivial: fix error messages
- ASoC: rt712-sdca: fix speaker route missing issue
- drm/syncobj: fix DRM_SYNCOBJ_WAIT_FLAGS_WAIT_AVAILABLE
- drm/vc4: tests: Fix UAF in the mock helpers
- fs: dlm: Simplify buffer size computation in dlm_create_debug_file()
- module/decompress: use kvmalloc() consistently
- drivers: perf: Do not broadcast to other cpus when starting a counter
- net: ti: icss-iep: fix setting counter value
- RISC-V: Don't fail in riscv_of_parent_hartid() for disabled HARTs
- net/sched: act_ct: Always fill offloading tuple iifidx
- netfilter: nat: fix ipv6 nat redirect with mapped and scoped addresses
- netfilter: xt_recent: fix (increase) ipv6 literal buffer length
- i2c: iproc: handle invalid slave state
- net: enetc: shorten enetc_setup_xdp_prog() error message to fit NETLINK_MAX_FMTMSG_LEN
- virtio/vsock: Fix uninit-value in virtio_transport_recv_pkt()
- r8169: respect userspace disabling IFF_MULTICAST
- vsock/virtio: remove socket from connected/bound list on shutdown
- blk-core: use pr_warn_ratelimited() in bio_check_ro()
- nbd: fix uaf in nbd_open
- tg3: power down device only on SYSTEM_POWER_OFF
- ice: Fix VF-VF direction matching in drop rule in switchdev
- ice: Fix VF-VF filter rules in switchdev mode
- ice: lag: in RCU, use atomic allocation
- ice: Fix SRIOV LAG disable on non-compliant aggregate
- riscv: boot: Fix creation of loader.bin
- nvme: fix error-handling for io_uring nvme-passthrough
- net/smc: put sk reference if close work was canceled
- net/smc: allow cdc msg send rather than drop it with NULL sndbuf_desc
- net/smc: fix dangling sock under state SMC_APPFINCLOSEWAIT
- octeontx2-pf: Free pending and dropped SQEs
- selftests: pmtu.sh: fix result checking
- net: stmmac: xgmac: Enable support for multiple Flexible PPS outputs
- Fix termination state for idr_for_each_entry_ul()
- net: r8169: Disable multicast filter for RTL8168H and RTL8107E
- dccp/tcp: Call security_inet_conn_request() after setting IPv6 addresses.
- dccp: Call security_inet_conn_request() after setting IPv4 addresses.
- net: page_pool: add missing free_percpu when page_pool_init fail
- octeontx2-pf: Fix holes in error code
- octeontx2-pf: Fix error codes
- inet: shrink struct flowi_common
- bpf: Check map->usercnt after timer->timer is assigned
- rxrpc: Fix two connection reaping bugs
- tipc: Change nla_policy for bearer-related names to NLA_NUL_STRING
- hsr: Prevent use after free in prp_create_tagged_frame()
- llc: verify mac len before reading mac header
- watchdog: ixp4xx: Make sure restart always works
- watchdog: marvell_gti_wdt: Fix error code in probe()
- Input: synaptics-rmi4 - fix use after free in rmi_unregister_function()
- pwm: brcmstb: Utilize appropriate clock APIs in suspend/resume
- pwm: sti: Reduce number of allocations and drop usage of chip_data
- drm/amdgpu: don't put MQDs in VRAM on ARM | ARM64
- drm/amdgpu/gfx10,11: use memcpy_to/fromio for MQDs
- regmap: prevent noinc writes from clobbering cache
- cpupower: fix reference to nonexistent document
- media: cec: meson: always include meson sub-directory in Makefile
- media: platform: mtk-mdp3: fix uninitialized variable in mdp_path_config()
- media: mediatek: vcodec: using encoder device to alloc/free encoder memory
- media: imx-jpeg: notify source chagne event when the first picture parsed
- media: mediatek: vcodec: Handle invalid encoder vsi
- media: verisilicon: Fixes clock list for rk3588 av1 decoder
- media: dvb-usb-v2: af9035: fix missing unlock
- media: cadence: csi2rx: Unregister v4l2 async notifier
- media: i2c: imx219: Drop IMX219_REG_CSI_LANE_MODE from common regs array
- media: i2c: imx219: Replace register addresses with macros
- media: i2c: imx219: Convert to CCI register access helpers
- media: cedrus: Fix clock/reset sequence
- media: vidtv: mux: Add check and kfree for kstrdup
- media: vidtv: psi: Add check for kstrdup
- media: s3c-camif: Avoid inappropriate kfree()
- media: mtk-jpegenc: Fix bug in JPEG encode quality selection
- media: amphion: handle firmware debug message
- media: bttv: fix use after free error due to btv->timeout timer
- media: ov5640: Fix a memory leak when ov5640_probe fails
- media: i2c: max9286: Fix some redundant of_node_put() calls
- media: ov5640: fix vblank unchange issue when work at dvp mode
- media: ov13b10: Fix some error checking in probe
- media: verisilicon: Do not enable G2 postproc downscale if source is narrower than destination
- media: hantro: Check whether reset op is defined before use
- media: imx-jpeg: initiate a drain of the capture queue in dynamic resolution change
- pcmcia: ds: fix possible name leak in error path in pcmcia_device_add()
- pcmcia: ds: fix refcount leak in pcmcia_device_add()
- pcmcia: cs: fix possible hung task and memory leak pccardd()
- cxl/hdm: Remove broken error path
- cxl/port: Fix @host confusion in cxl_dport_setup_regs()
- cxl/core/regs: Rename @dev to @host in struct cxl_register_map
- cxl/region: Fix cxl_region_rwsem lock held when returning to user space
- cxl/region: Use cxl_calc_interleave_pos() for auto-discovery
- cxl/region: Calculate a target position in a region interleave
- cxl/region: Prepare the decoder match range helper for reuse
- rtc: pcf85363: fix wrong mask/val parameters in regmap_update_bits call
- virt: sevguest: Fix passing a stack buffer as a scatterlist target
- cxl/mem: Fix shutdown order
- cxl/memdev: Fix sanitize vs decoder setup locking
- cxl/pci: Fix sanitize notifier setup
- cxl/pci: Clarify devm host for memdev relative setup
- cxl/pci: Remove inconsistent usage of dev_err_probe()
- cxl/pci: Cleanup 'sanitize' to always poll
- cxl/pci: Remove unnecessary device reference management in sanitize work
- rtc: brcmstb-waketimer: support level alarm_irq
- i3c: Fix potential refcount leak in i3c_master_register_new_i3c_devs
- rtla: Fix uninitialized variable found
- 9p/net: fix possible memory leak in p9_check_errors()
- perf vendor events intel: Add broadwellde two metrics
- perf vendor events intel: Fix broadwellde tma_info_system_dram_bw_use metric
- perf hist: Add missing puts to hist__account_cycles
- libperf rc_check: Make implicit enabling work for GCC
- perf machine: Avoid out of bounds LBR memory read
- powerpc/vmcore: Add MMU information to vmcoreinfo
- usb: host: xhci-plat: fix possible kernel oops while resuming
- xhci: Loosen RPM as default policy to cover for AMD xHC 1.1
- perf vendor events: Update PMC used in PM_RUN_INST_CMPL event for power10 platform
- powerpc/pseries: fix potential memory leak in init_cpu_associativity()
- powerpc/imc-pmu: Use the correct spinlock initializer.
- powerpc/vas: Limit open window failure messages in log bufffer
- perf trace: Use the right bpf_probe_read(_str) variant for reading user data
- powerpc: Hide empty pt_regs at base of the stack
- powerpc/xive: Fix endian conversion size
- powerpc/40x: Remove stale PTE_ATOMIC_UPDATES macro
- perf tools: Do not ignore the default vmlinux.h
- modpost: fix ishtp MODULE_DEVICE_TABLE built on big-endian host
- modpost: fix tee MODULE_DEVICE_TABLE built on big-endian host
- s390/ap: re-init AP queues on config on
- perf mem-events: Avoid uninitialized read
- perf parse-events: Fix for term values that are raw events
- perf build: Add missing comment about NO_LIBTRACEEVENT=1
- interconnect: fix error handling in qnoc_probe()
- powerpc: Only define __parse_fpscr() when required
- interconnect: qcom: osm-l3: Replace custom implementation of COUNT_ARGS()
- interconnect: qcom: sm8350: Set ACV enable_mask
- interconnect: qcom: sm8250: Set ACV enable_mask
- interconnect: qcom: sm8150: Set ACV enable_mask
- interconnect: qcom: sm6350: Set ACV enable_mask
- interconnect: qcom: sdm845: Set ACV enable_mask
- interconnect: qcom: sdm670: Set ACV enable_mask
- interconnect: qcom: sc8280xp: Set ACV enable_mask
- interconnect: qcom: sc8180x: Set ACV enable_mask
- interconnect: qcom: sc7280: Set ACV enable_mask
- interconnect: qcom: sc7180: Set ACV enable_mask
- interconnect: qcom: qdu1000: Set ACV enable_mask
- f2fs: fix to initialize map.m_pblk in f2fs_precache_extents()
- dmaengine: pxa_dma: Remove an erroneous BUG_ON() in pxad_free_desc()
- USB: usbip: fix stub_dev hub disconnect
- tools: iio: iio_generic_buffer ensure alignment
- debugfs: Fix __rcu type comparison warning
- misc: st_core: Do not call kfree_skb() under spin_lock_irqsave()
- tools/perf: Update call stack check in builtin-lock.c
- dmaengine: ti: edma: handle irq_of_parse_and_map() errors
- usb: chipidea: Simplify Tegra DMA alignment code
- usb: chipidea: Fix DMA overwrite for Tegra
- usb: dwc2: fix possible NULL pointer dereference caused by driver concurrency
- dmaengine: idxd: Register dsa_bus_type before registering idxd sub-drivers
- perf record: Fix BTF type checks in the off-cpu profiling
- perf vendor events arm64: Fix for AmpereOne metrics
- pinctrl: renesas: rzg2l: Make reverse order of enable() for disable()
- livepatch: Fix missing newline character in klp_resolve_symbols()
- perf parse-events: Fix tracepoint name memory leak
- tty: tty_jobctrl: fix pid memleak in disassociate_ctty()
- f2fs: fix to drop meta_inode's page cache in f2fs_put_super()
- f2fs: compress: fix to avoid redundant compress extension
- f2fs: compress: fix to avoid use-after-free on dic
- f2fs: compress: fix deadloop in f2fs_write_cache_pages()
- perf kwork: Set ordered_events to true in 'struct perf_tool'
- perf kwork: Add the supported subcommands to the document
- perf kwork: Fix incorrect and missing free atom in work_push_atom()
- pinctrl: baytrail: fix debounce disable case
- iio: frequency: adf4350: Use device managed functions and fix power down issue.
- perf stat: Fix aggr mode initialization
- apparmor: fix invalid reference on profile->disconnected
- scripts/gdb: fix usage of MOD_TEXT not defined when CONFIG_MODULES=n
- leds: trigger: ledtrig-cpu:: Fix 'output may be truncated' issue for 'cpu'
- leds: pwm: Don't disable the PWM when the LED should be off
- leds: turris-omnia: Do not use SMBUS calls
- mfd: arizona-spi: Set pdata.hpdet_channel for ACPI enumerated devs
- dt-bindings: mfd: mt6397: Split out compatible for MediaTek MT6366 PMIC
- mfd: dln2: Fix double put in dln2_probe
- mfd: core: Ensure disabled devices are skipped without aborting
- mfd: core: Un-constify mfd_cell.of_reg
- IB/mlx5: Fix init stage error handling to avoid double free of same QP and UAF
- erofs: fix erofs_insert_workgroup() lockref usage
- ASoC: ams-delta.c: use component after check
- crypto: qat - fix deadlock in backlog processing
- crypto: qat - fix ring to service map for QAT GEN4
- crypto: qat - use masks for AE groups
- crypto: qat - refactor fw config related functions
- crypto: qat - enable dc chaining service
- crypto: qat - consolidate services structure
- certs: Break circular dependency when selftest is modular
- padata: Fix refcnt handling in padata_free_shell()
- PCI: endpoint: Fix double free in __pci_epc_create()
- ASoC: Intel: Skylake: Fix mem leak when parsing UUIDs fails
- HID: logitech-hidpp: Move get_wireless_feature_index() check to hidpp_connect_event()
- HID: logitech-hidpp: Revert "Don't restart communication if not necessary"
- HID: logitech-hidpp: Don't restart IO, instead defer hid_connect() only
- sh: bios: Revive earlyprintk support
- HID: uclogic: Fix a work->entry not empty bug in __queue_work()
- HID: uclogic: Fix user-memory-access bug in uclogic_params_ugee_v2_init_event_hooks()
- hid: cp2112: Fix IRQ shutdown stopping polling for all IRQs on chip
- RDMA/hfi1: Workaround truncation compilation error
- scsi: ufs: core: Leave space for '\0' in utf8 desc string
- ASoC: fsl: Fix PM disable depth imbalance in fsl_easrc_probe
- ASoC: intel: sof_sdw: Stop processing CODECs when enough are found
- ASoC: SOF: core: Ensure sof_ops_free() is still called when probe never ran.
- RDMA/hns: Fix init failure of RoCE VF and HIP08
- RDMA/hns: Fix unnecessary port_num transition in HW stats allocation
- RDMA/hns: The UD mode can only be configured with DCQCN
- RDMA/hns: Add check for SL
- RDMA/hns: Fix signed-unsigned mixed comparisons
- RDMA/hns: Fix uninitialized ucmd in hns_roce_create_qp_common()
- RDMA/hns: Fix printing level of asynchronous events
- IB/mlx5: Fix rdma counter binding for RAW QP
- dlm: fix no ack after final message
- dlm: be sure we reset all nodes at forced shutdown
- dlm: fix remove member after close call
- dlm: fix creating multiple node structures
- fs: dlm: Fix the size of a buffer in dlm_create_debug_file()
- ASoC: fsl-asoc-card: Add comment for mclk in the codec_priv
- ASoC: Intel: sof_sdw_rt_sdca_jack_common: add rt713 support
- backlight: pwm_bl: Disable PWM on shutdown, suspend and remove
- ASoC: fsl: mpc5200_dma.c: Fix warning of Function parameter or member not described
- kselftest: vm: fix mdwe's mmap_FIXED test case
- ext4: move 'ix' sanity check to corrent position
- ext4: add missing initialization of call_notify_error in update_super_work()
- ARM: 9323/1: mm: Fix ARCH_LOW_ADDRESS_LIMIT when CONFIG_ZONE_DMA
- ARM: 9321/1: memset: cast the constant byte to unsigned char
- crypto: hisilicon/qm - fix PF queue parameter issue
- hid: cp2112: Fix duplicate workqueue initialization
- PCI: vmd: Correct PCI Header Type Register's multi-function check
- ASoC: SOF: ipc4-topology: Use size_add() in call to struct_size()
- crypto: qat - increase size of buffers
- crypto: caam/jr - fix Chacha20 + Poly1305 self test failure
- crypto: caam/qi2 - fix Chacha20 + Poly1305 self test failure
- nd_btt: Make BTT lanes preemptible
- libnvdimm/of_pmem: Use devm_kstrdup instead of kstrdup and check its return value
- ASoC: soc-pcm.c: Make sure DAI parameters cleared if the DAI becomes inactive
- scsi: ibmvfc: Fix erroneous use of rtas_busy_delay with hcall return code
- crypto: qat - fix unregistration of compression algorithms
- crypto: qat - fix unregistration of crypto algorithms
- crypto: qat - ignore subsequent state up commands
- crypto: qat - fix state machines cleanup paths
- RDMA/core: Use size_{add,sub,mul}() in calls to struct_size()
- hwrng: geode - fix accessing registers
- hwrng: bcm2835 - Fix hwrng throughput regression
- crypto: hisilicon/hpre - Fix a erroneous check after snprintf()
- crypto: ccp - Fix some unfused tests
- crypto: ccp - Fix sample application signature passing
- crypto: ccp - Fix DBC sample application error handling
- crypto: ccp - Fix ioctl unit tests
- crypto: ccp - Get a free page to use while fetching initial nonce
- KEYS: Include linux/errno.h in linux/verification.h
- ALSA: hda: cs35l41: Undo runtime PM changes at driver exit time
- ALSA: hda: cs35l41: Fix unbalanced pm_runtime_get()
- ASoC: cs35l41: Undo runtime PM changes at driver exit time
- ASoC: cs35l41: Verify PM runtime resume errors in IRQ handler
- ASoC: cs35l41: Fix broken shared boost activation
- ASoC: cs35l41: Initialize completion object before requesting IRQ
- ASoC: cs35l41: Handle mdsync_up reg write errors
- ASoC: cs35l41: Handle mdsync_down reg write errors
- module/decompress: use vmalloc() for gzip decompression workspace
- iommufd: Add iopt_area_alloc()
- ARM: dts: BCM5301X: Explicitly disable unused switch CPU ports
- soc: qcom: pmic_glink: fix connector type to be DisplayPort
- selftests/resctrl: Ensure the benchmark commands fits to its array
- selftests/pidfd: Fix ksft print formats
- arm64: tegra: Use correct interrupts for Tegra234 TKE
- memory: tegra: Set BPMP msg flags to reset IPC channels
- firmware: tegra: Add suspend hook and reset BPMP IPC early on resume
- arm64: tegra: Fix P3767 QSPI speed
- arm64: tegra: Fix P3767 card detect polarity
- arm64: dts: imx8mn: Add sound-dai-cells to micfil node
- arm64: dts: imx8mm: Add sound-dai-cells to micfil node
- arm64: dts: imx8mp-debix-model-a: Remove USB hub reset-gpios
- arm64: dts: imx8qm-ss-img: Fix jpegenc compatible entry
- clk: scmi: Free scmi_clk allocated when the clocks with invalid info are skipped
- ARM: dts: am3517-evm: Fix LED3/4 pinmux
- firmware: arm_ffa: Allow the FF-A drivers to use 32bit mode of messaging
- firmware: arm_ffa: Assign the missing IDR allocation ID to the FFA device
- arm64: dts: ti: Fix HDMI Audio overlay in Makefile
- arm64: dts: ti: k3-am62a7-sk: Drop i2c-1 to 100Khz
- arm64: dts: ti: k3-am625-beagleplay: Fix typo in ramoops reg
- arm64: dts: ti: verdin-am62: disable MIPI DSI bridge
- arm64: dts: ti: k3-j721s2-evm-gesi: Specify base dtb for overlay file
- firmware: ti_sci: Mark driver as non removable
- ARM: dts: stm32: stm32f7-pinctrl: don't use multiple blank lines
- kunit: test: Fix the possible memory leak in executor_test
- kunit: Fix possible memory leak in kunit_filter_suites()
- kunit: Fix the wrong kfree of copy for kunit_filter_suites()
- kunit: Fix missed memory release in kunit_free_suite_set()
- soc: qcom: llcc: Handle a second device without data corruption
- ARM: dts: qcom: mdm9615: populate vsdcc fixed regulator
- ARM: dts: qcom: apq8026-samsung-matisse-wifi: Fix inverted hall sensor
- arm64: dts: qcom: apq8016-sbc: Add missing ADV7533 regulators
- riscv: dts: allwinner: remove address-cells from intc node
- arm64: dts: qcom: msm8939: Fix iommu local address range
- arm64: dts: qcom: msm8976: Fix ipc bit shifts
- ARM64: dts: marvell: cn9310: Use appropriate label for spi1 pins
- arm64: dts: qcom: sdx75-idp: align RPMh regulator nodes with bindings
- arm64: dts: qcom: sdm845-mtp: fix WiFi configuration
- arm64: dts: qcom: sm8350: fix pinctrl for UART18
- arm64: dts: qcom: sm8150: add ref clock to PCIe PHYs
- arm64: dts: qcom: sc7280: drop incorrect EUD port on SoC side
- arm64: dts: qcom: sdm670: Fix pdc mapping
- arm64: dts: qcom: qrb2210-rb1: Fix regulators
- arm64: dts: qcom: qrb2210-rb1: Swap UART index
- arm64: dts: qcom: sc7280: Add missing LMH interrupts
- arm64: dts: qcom: sm6125: Pad APPS IOMMU address to 8 characters
- arm64: dts: qcom: msm8992-libra: drop duplicated reserved memory
- arm64: dts: qcom: msm8916: Fix iommu local address range
- arm64: dts: qcom: sc7280: link usb3_phy_wrapper_gcc_usb30_pipe_clk
- arm64: dts: qcom: sdm845: cheza doesn't support LMh node
- arm64: dts: qcom: sdm845: Fix PSCI power domain names
- ARM: dts: renesas: blanche: Fix typo in GP_11_2 pin name
- perf: hisi: Fix use-after-free when register pmu fails
- drivers/perf: hisi_pcie: Check the type first in pmu::event_init()
- perf/arm-cmn: Fix DTC domain detection
- drm/amd/pm: Fix a memory leak on an error path
- drivers/perf: hisi: use cpuhp_state_remove_instance_nocalls() for hisi_hns3_pmu uninit process
- drm: mediatek: mtk_dsi: Fix NO_EOT_PACKET settings/handling
- clocksource/drivers/arm_arch_timer: limit XGene-1 workaround
- drm/msm/dsi: free TX buffer in unbind
- drm/msm/dsi: use msm_gem_kernel_put to free TX buffer
- xen-pciback: Consider INTx disabled when MSI/MSI-X is enabled
- xen: irqfd: Use _IOW instead of the internal _IOC() macro
- xen: Make struct privcmd_irqfd's layout architecture independent
- xenbus: fix error exit in xenbus_init()
- drm/rockchip: Fix type promotion bug in rockchip_gem_iommu_map()
- arm64/arm: xen: enlighten: Fix KPTI checks
- drm/bridge: lt9611uxc: fix the race in the error path
- gpu: host1x: Correct allocated size for contexts
- drm/rockchip: cdn-dp: Fix some error handling paths in cdn_dp_probe()
- drm/msm/a6xx: Fix unknown speedbin case
- drm/msm/adreno: Fix SM6375 GPU ID
- accel/habanalabs/gaudi2: Fix incorrect string length computation in gaudi2_psoc_razwi_get_engines()
- drm/mediatek: Fix iommu fault during crtc enabling
- drm/mediatek: Fix iommu fault by swapping FBs after updating plane state
- drm/mediatek: Add mmsys_dev_num to mt8188 vdosys0 driver data
- io_uring/kbuf: Allow the full buffer id space for provided buffers
- io_uring/kbuf: Fix check of BID wrapping in provided buffers
- drm/amd/display: Bail from dm_check_crtc_cursor if no relevant change
- drm/amd/display: Refactor dm_get_plane_scale helper
- drm/amd/display: Check all enabled planes in dm_check_crtc_cursor
- drm/amd/display: Fix null pointer dereference in error message
- drm/amdkfd: Handle errors from svm validate and map
- drm/amdkfd: Remove svm range validated_once flag
- drm/amdkfd: fix some race conditions in vram buffer alloc/free of svm code
- drm/amdgpu: Increase IH soft ring size for GFX v9.4.3 dGPU
- drm: Call drm_atomic_helper_shutdown() at shutdown/remove time for misc drivers
- drm/bridge: tc358768: Fix tc358768_ns_to_cnt()
- drm/bridge: tc358768: Clean up clock period code
- drm/bridge: tc358768: Rename dsibclk to hsbyteclk
- drm/bridge: tc358768: Use dev for dbg prints, not priv->dev
- drm/bridge: tc358768: Print logical values, not raw register values
- drm/bridge: tc358768: Use struct videomode
- drm/bridge: tc358768: Fix bit updates
- drm/bridge: tc358768: Fix use of uninitialized variable
- x86/tdx: Zero out the missing RSI in TDX_HYPERCALL macro
- drm/mediatek: Fix coverity issue with unintentional integer overflow
- drm/ssd130x: Fix screen clearing
- drm/bridge: lt8912b: Add missing drm_bridge_attach call
- drm/bridge: lt8912b: Manually disable HPD only if it was enabled
- drm/bridge: lt8912b: Fix crash on bridge detach
- drm/bridge: lt8912b: Fix bridge_detach
- drm: bridge: it66121: Fix invalid connector dereference
- drm/radeon: Remove the references of radeon_gem_ pread & pwrite ioctls
- drm/radeon: possible buffer overflow
- drm/rockchip: vop2: Add missing call to crtc reset helper
- drm/rockchip: vop2: Don't crash for invalid duplicate_state
- drm/rockchip: vop: Fix call to crtc reset helper
- drm/rockchip: vop: Fix reset of state in duplicate state crtc funcs
- drm/loongson: Fix error handling in lsdc_pixel_pll_setup()
- drm: bridge: samsung-dsim: Fix waiting for empty cmd transfer FIFO on older Exynos
- drm: bridge: for GENERIC_PHY_MIPI_DPHY also select GENERIC_PHY
- drm: bridge: samsung-dsim: Initialize ULPS EXIT for i.MX8M DSIM
- spi: omap2-mcspi: Fix hardcoded reference clock
- spi: omap2-mcspi: switch to use modern name
- platform/chrome: cros_ec_lpc: Separate host command and irq disable
- hte: tegra: Fix missing error code in tegra_hte_test_probe()
- hwmon: (sch5627) Disallow write access if virtual registers are locked
- hwmon: (sch5627) Use bit macros when accessing the control register
- hwmon: (pmbus/mp2975) Move PGOOD fix
- Revert "hwmon: (sch56xx-common) Add automatic module loading on supported devices"
- Revert "hwmon: (sch56xx-common) Add DMI override table"
- hwmon: (coretemp) Fix potentially truncated sysfs attribute name
- hwmon: (axi-fan-control) Fix possible NULL pointer dereference
- regulator: qcom-rpmh: Fix smps4 regulator for pm8550ve
- platform/x86: wmi: Fix opening of char device
- platform/x86: wmi: Fix probe failure when failing to register WMI devices
- clk: mediatek: fix double free in mtk_clk_register_pllfh()
- clk: qcom: ipq5332: drop the CLK_SET_RATE_PARENT flag from GPLL clocks
- clk: qcom: ipq9574: drop the CLK_SET_RATE_PARENT flag from GPLL clocks
- clk: qcom: ipq5018: drop the CLK_SET_RATE_PARENT flag from GPLL clocks
- clk: qcom: apss-ipq-pll: Fix 'l' value for ipq5332_pll_config
- clk: qcom: apss-ipq-pll: Use stromer plus ops for stromer plus pll
- clk: qcom: clk-alpha-pll: introduce stromer plus ops
- clk: qcom: config IPQ_APSS_6018 should depend on QCOM_SMEM
- clk: mediatek: clk-mt2701: Add check for mtk_alloc_clk_data
- clk: mediatek: clk-mt7629: Add check for mtk_alloc_clk_data
- clk: mediatek: clk-mt7629-eth: Add check for mtk_alloc_clk_data
- clk: mediatek: clk-mt6797: Add check for mtk_alloc_clk_data
- clk: mediatek: clk-mt6779: Add check for mtk_alloc_clk_data
- clk: mediatek: clk-mt6765: Add check for mtk_alloc_clk_data
- clk: npcm7xx: Fix incorrect kfree
- clk: ti: fix double free in of_ti_divider_clk_setup()
- clk: keystone: pll: fix a couple NULL vs IS_ERR() checks
- clk: ralink: mtmips: quiet unused variable warning
- spi: nxp-fspi: use the correct ioremap function
- clk: linux/clk-provider.h: fix kernel-doc warnings and typos
- clk: renesas: rzg2l: Fix computation formula
- clk: renesas: rzg2l: Use FIELD_GET() for PLL register fields
- clk: renesas: rzg2l: Trust value returned by hardware
- clk: renesas: rzg2l: Lock around writes to mux register
- clk: renesas: rzg2l: Wait for status bit of SD mux before continuing
- clk: renesas: rcar-gen3: Extend SDnH divider table
- clk: imx: imx8qxp: Fix elcdif_pll clock
- clk: imx: imx8mq: correct error handling path
- clk: imx: imx8: Fix an error handling path in imx8_acm_clk_probe()
- clk: imx: imx8: Fix an error handling path if devm_clk_hw_register_mux_parent_data_table() fails
- clk: imx: imx8: Fix an error handling path in clk_imx_acm_attach_pm_domains()
- clk: imx: Select MXC_CLK for CLK_IMX8QXP
- regulator: mt6358: Fail probe on unknown chip ID
- gpio: sim: initialize a managed pointer when declaring it
- clk: qcom: gcc-sm8150: Fix gcc_sdcc2_apps_clk_src
- clk: qcom: mmcc-msm8998: Fix the SMMU GDSC
- clk: qcom: mmcc-msm8998: Don't check halt bit on some branch clks
- clk: qcom: clk-rcg2: Fix clock rate overflow for high parent frequencies
- clk: qcom: gcc-msm8996: Remove RPM bus clocks
- clk: qcom: ipq5332: Drop set rate parent from gpll0 dependent clocks
- spi: tegra: Fix missing IRQ check in tegra_slink_probe()
- regmap: debugfs: Fix a erroneous check after snprintf()
- ipvlan: properly track tx_errors
- net: add DEV_STATS_READ() helper
- virtio_net: use u64_stats_t infra to avoid data-races
- ipv6: avoid atomic fragment on GSO packets
- mptcp: properly account fastopen data
- ACPI: sysfs: Fix create_pnp_modalias() and create_of_modalias()
- bpf: Fix unnecessary -EBUSY from htab_lock_bucket
- Bluetooth: hci_sync: Fix Opcode prints in bt_dev_dbg/err
- Bluetooth: Make handle of hci_conn be unique
- Bluetooth: ISO: Pass BIG encryption info through QoS
- wifi: iwlwifi: empty overflow queue during flush
- wifi: iwlwifi: mvm: update IGTK in mvmvif upon D3 resume
- wifi: iwlwifi: pcie: synchronize IRQs before NAPI
- wifi: iwlwifi: mvm: fix netif csum flags
- wifi: iwlwifi: increase number of RX buffers for EHT devices
- wifi: iwlwifi: mvm: remove TDLS stations from FW
- wifi: iwlwifi: mvm: fix iwl_mvm_mac_flush_sta()
- wifi: iwlwifi: mvm: change iwl_mvm_flush_sta() API
- wifi: iwlwifi: mvm: Don't always bind/link the P2P Device interface
- wifi: iwlwifi: mvm: Fix key flags for IGTK on AP interface
- wifi: iwlwifi: mvm: Correctly set link configuration
- wifi: iwlwifi: yoyo: swap cdb and jacket bits values
- wifi: mac80211: Fix setting vif links
- wifi: mac80211: don't recreate driver link debugfs in reconfig
- wifi: iwlwifi: mvm: use correct sta ID for IGTK/BIGTK
- wifi: iwlwifi: mvm: fix removing pasn station for responder
- wifi: iwlwifi: mvm: update station's MFP flag after association
- tcp: fix cookie_init_timestamp() overflows
- chtls: fix tp->rcv_tstamp initialization
- thermal: core: Don't update trip points inside the hysteresis range
- selftests/bpf: Make linked_list failure test more robust
- net: skb_find_text: Ignore patterns extending past 'to'
- bpf: Fix missed rcu read lock in bpf_task_under_cgroup()
- thermal/drivers/mediatek: Fix probe for THERMAL_V2
- r8169: fix rare issue with broken rx after link-down on RTL8125
- thermal: core: prevent potential string overflow
- wifi: rtw88: Remove duplicate NULL check before calling usb_kill/free_urb()
- virtio-net: fix the vq coalescing setting for vq resize
- virtio-net: fix per queue coalescing parameter setting
- virtio-net: consistently save parameters for per-queue
- virtio-net: fix mismatch of getting tx-frames
- netfilter: nf_tables: Drop pointless memset when dumping rules
- wifi: wfx: fix case where rates are out of order
- PM / devfreq: rockchip-dfi: Make pmu regmap mandatory
- can: dev: can_put_echo_skb(): don't crash kernel if can_priv::echo_skb is accessed out of bounds
- can: dev: can_restart(): fix race condition between controller restart and netif_carrier_on()
- can: dev: can_restart(): don't crash kernel if carrier is OK
- wifi: ath11k: fix Tx power value during active CAC
- r8152: break the loop when the budget is exhausted
- selftests/bpf: Define SYS_NANOSLEEP_KPROBE_NAME for riscv
- selftests/bpf: Define SYS_PREFIX for riscv
- libbpf: Fix syscall access arguments on riscv
- can: etas_es58x: add missing a blank line after declaration
- can: etas_es58x: rework the version check logic to silence -Wformat-truncation
- ACPI: video: Add acpi_backlight=vendor quirk for Toshiba Portégé R100
- ACPI: property: Allow _DSD buffer data only for byte accessors
- wifi: rtlwifi: fix EDCA limit set by BT coexistence
- tcp_metrics: do not create an entry from tcp_init_metrics()
- tcp_metrics: properly set tp->snd_ssthresh in tcp_init_metrics()
- tcp_metrics: add missing barriers on delete
- wifi: ath: dfs_pattern_detector: Fix a memory initialization issue
- wifi: mt76: mt7921: fix the wrong rate selected in fw for the chanctx driver
- wifi: mt76: mt7921: fix the wrong rate pickup for the chanctx driver
- wifi: mt76: move struct ieee80211_chanctx_conf up to struct mt76_vif
- wifi: mt76: mt7915: fix beamforming availability check
- wifi: mt76: fix per-band IEEE80211_CONF_MONITOR flag comparison
- wifi: mt76: get rid of false alamrs of tx emission issues
- wifi: mt76: fix potential memory leak of beacon commands
- wifi: mt76: update beacon size limitation
- wifi: mt76: mt7996: fix TWT command format
- wifi: mt76: mt7996: fix rx rate report for CBW320-2
- wifi: mt76: mt7996: fix wmm queue mapping
- wifi: mt76: mt7996: fix beamformee ss subfield in EHT PHY cap
- wifi: mt76: mt7996: fix beamform mcu cmd configuration
- wifi: mt76: mt7996: set correct wcid in txp
- wifi: mt76: remove unused error path in mt76_connac_tx_complete_skb
- wifi: mt76: mt7603: improve stuck beacon handling
- wifi: mt76: mt7603: improve watchdog reset reliablity
- wifi: mt76: mt7603: rework/fix rx pse hang check
- cpufreq: tegra194: fix warning due to missing opp_put
- PM: sleep: Fix symbol export for _SIMPLE_ variants of _PM_OPS()
- wifi: mac80211: fix check for unusable RX result
- wifi: ath11k: fix boot failure with one MSI vector
- wifi: ath12k: fix DMA unmap warning on NULL DMA address
- wifi: rtw88: debug: Fix the NULL vs IS_ERR() bug for debugfs_create_file()
- net: ethernet: mtk_wed: fix EXT_INT_STATUS_RX_FBUF definitions for MT7986 SoC
- ice: fix pin assignment for E810-T without SMA control
- net: spider_net: Use size_add() in call to struct_size()
- tipc: Use size_add() in calls to struct_size()
- tls: Use size_add() in call to struct_size()
- mlxsw: Use size_mul() in call to struct_size()
- gve: Use size_add() in call to struct_size()
- bpf: Fix kfunc callback register type handling
- tcp: call tcp_try_undo_recovery when an RTOd TFO SYNACK is ACKed
- selftests/bpf: Skip module_fentry_shadow test when bpf_testmod is not available
- udplite: fix various data-races
- udplite: remove UDPLITE_BIT
- udp: annotate data-races around udp->encap_type
- udp: lockless UDP_ENCAP_L2TPINUDP / UDP_GRO
- udp: move udp->accept_udp_{l4|fraglist} to udp->udp_flags
- udp: add missing WRITE_ONCE() around up->encap_rcv
- udp: move udp->gro_enabled to udp->udp_flags
- udp: move udp->no_check6_rx to udp->udp_flags
- udp: move udp->no_check6_tx to udp->udp_flags
- udp: introduce udp->udp_flags
- wifi: cfg80211: fix kernel-doc for wiphy_delayed_work_flush()
- bpf, x64: Fix tailcall infinite loop
- selftests/bpf: Correct map_fd to data_fd in tailcalls
- iavf: Fix promiscuous mode configuration flow messages
- i40e: fix potential memory leaks in i40e_remove()
- wifi: iwlwifi: don't use an uninitialized variable
- wifi: iwlwifi: honor the enable_ini value
- wifi: mac80211: fix # of MSDU in A-MSDU calculation
- wifi: cfg80211: fix off-by-one in element defrag
- wifi: mac80211: fix RCU usage warning in mesh fast-xmit
- wifi: mac80211: move sched-scan stop work to wiphy work
- wifi: mac80211: move offchannel works to wiphy work
- wifi: mac80211: move scan work to wiphy work
- wifi: mac80211: move radar detect work to wiphy work
- wifi: cfg80211: add flush functions for wiphy work
- wifi: ath12k: fix undefined behavior with __fls in dp
- irqchip/sifive-plic: Fix syscore registration for multi-socket systems
- genirq/matrix: Exclude managed interrupts in irq_matrix_allocated()
- string: Adjust strtomem() logic to allow for smaller sources
- PCI/MSI: Provide stubs for IMS functions
- selftests/x86/lam: Zero out buffer for readlink()
- perf: Optimize perf_cgroup_switch()
- pstore/platform: Add check for kstrdup
- x86/nmi: Fix out-of-order NMI nesting checks & false positive warning
- drivers/clocksource/timer-ti-dm: Don't call clk_get_rate() in stop function
- srcu: Fix callbacks acceleration mishandling
- x86/apic: Fake primary thread mask for XEN/PV
- cpu/SMT: Make SMT control more robust against enumeration failures
- x86/boot: Fix incorrect startup_gdt_descr.size
- x86/sev-es: Allow copy_from_kernel_nofault() in earlier boot
- cgroup/cpuset: Fix load balance state in update_partition_sd_lb()
- ACPI/NUMA: Apply SRAT proximity domain to entire CFMWS window
- x86/numa: Introduce numa_fill_memblks()
- futex: Don't include process MM in futex key on no-MMU
- x86/srso: Fix unret validation dependencies
- x86/srso: Fix vulnerability reporting for missing microcode
- x86/srso: Print mitigation for retbleed IBPB case
- x86/srso: Fix SBPB enablement for (possible) future fixed HW
- writeback, cgroup: switch inodes with dirty timestamps to release dying cgwbs
- vfs: fix readahead(2) on block devices
- nfsd: Handle EOPENSTALE correctly in the filecache
- sched: Fix stop_one_cpu_nowait() vs hotplug
- objtool: Propagate early errors
- sched/uclamp: Ignore (util == 0) optimization in feec() when p_util_max = 0
- sched/uclamp: Set max_spare_cap_cpu even if max_spare_cap is 0
- iov_iter, x86: Be consistent about the __user tag on copy_mc_to_user()
- sched/fair: Fix cfs_rq_is_decayed() on !SMP
- sched/topology: Fix sched_numa_find_nth_cpu() in non-NUMA case
- sched/topology: Fix sched_numa_find_nth_cpu() in CPU-less case
- numa: Generalize numa_map_to_online_node()
- hwmon: (nct6775) Fix incorrect variable reuse in fan_div calculation
- !2933 Backport linux 6.6.1 LTS patches
- ASoC: SOF: sof-pci-dev: Fix community key quirk detection
- ALSA: hda: intel-dsp-config: Fix JSL Chromebook quirk detection
- serial: core: Fix runtime PM handling for pending tx
- misc: pci_endpoint_test: Add deviceID for J721S2 PCIe EP device support
- dt-bindings: serial: rs485: Add rs485-rts-active-high
- tty: 8250: Add Brainboxes Oxford Semiconductor-based quirks
- tty: 8250: Add support for Intashield IX cards
- tty: 8250: Add support for additional Brainboxes PX cards
- tty: 8250: Fix up PX-803/PX-857
- tty: 8250: Fix port count of PX-257
- tty: 8250: Add support for Intashield IS-100
- tty: 8250: Add support for Brainboxes UP cards
- tty: 8250: Add support for additional Brainboxes UC cards
- tty: 8250: Remove UC-257 and UC-431
- tty: n_gsm: fix race condition in status line change on dead connections
- Bluetooth: hci_bcm4377: Mark bcm4378/bcm4387 as BROKEN_LE_CODED
- usb: raw-gadget: properly handle interrupted requests
- usb: typec: tcpm: Fix NULL pointer dereference in tcpm_pd_svdm()
- usb: typec: tcpm: Add additional checks for contaminant
- usb: storage: set 1.50 as the lower bcdDevice for older "Super Top" compatibility
- PCI: Prevent xHCI driver from claiming AMD VanGogh USB3 DRD device
- ALSA: usb-audio: add quirk flag to enable native DSD for McIntosh devices
- eventfs: Use simple_recursive_removal() to clean up dentries
- eventfs: Delete eventfs_inode when the last dentry is freed
- eventfs: Save ownership and mode
- eventfs: Remove "is_freed" union with rcu head
- tracing: Have trace_event_file have ref counters
- perf evlist: Avoid frequency mode for the dummy event
- power: supply: core: Use blocking_notifier_call_chain to avoid RCU complaint
- drm/amd/display: Don't use fsleep for PSR exit waits
- !2927 dm ioctl: add DMINFO() to track dm device create/remove
- dm ioctl: add DMINFO() to track dm device create/remove
- !2900 Add initial openeuler_defconfig for arm64 and x86
- config: add initial openeuler_defconfig for x86
- config: add initial openeuler_defconfig for arm64
- kconfig: Add script to check & update openeuler_defconfig
- init from linux v6.6
