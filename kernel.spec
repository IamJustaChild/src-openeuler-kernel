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

%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/ -e s/riscv.*/riscv/ -e s/powerpc64le/powerpc)

%global KernelVer %{version}-%{release}.%{_target_cpu}
%global debuginfodir /usr/lib/debug

%global upstream_version    6.6
%global upstream_sublevel   0
%global devel_release       1
%global maintenance_release .0.0
%global pkg_release         .1

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
%ifnarch ppc64le
BuildRequires: clang >= 10.0.0
%endif
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
