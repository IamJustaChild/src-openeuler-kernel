

%define with_signmodules  1

%define with_kabichk 1

%define modsign_cmd %{SOURCE10}

%global Arch $(echo %{_host_cpu} | sed -e s/i.86/x86/ -e s/x86_64/x86/ -e s/aarch64.*/arm64/)

%global TarballVer 4.19.90

%global KernelVer %{version}-%{release}.%{_target_cpu}

%global hulkrelease 2311.1.0

%define with_patch 1

%define debuginfodir /usr/lib/debug

%define with_debuginfo 1

%define with_perf 1
# Do not recompute the build-id of vmlinux in find-debuginfo.sh
%global _missing_build_ids_terminate_build 1
%global _no_recompute_build_ids 1
%undefine _include_minidebuginfo
%undefine _include_gdb_index
%undefine _unique_build_ids

%define with_source 1

Name:	 kernel
Version: 4.19.90
Release: %{hulkrelease}.0235
Summary: Linux Kernel
License: GPLv2
URL:	 http://www.kernel.org/

Source0: kernel.tar.gz
Source10: sign-modules
Source11: x509.genkey
Source12: extra_certificates

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
Source9003: patches
#Source9998: patches.tar.bz2
%endif

#BuildRequires:
BuildRequires: module-init-tools, patch >= 2.5.4, bash >= 2.03, tar
BuildRequires: bzip2, xz, findutils, gzip, m4, perl, make >= 3.78, diffutils, gawk
BuildRequires: gcc >= 3.4.2, binutils >= 2.12
BuildRequires: hostname, net-tools, bc
BuildRequires: xmlto, asciidoc
BuildRequires: openssl openssl-devel
BuildRequires: hmaccalc
BuildRequires: ncurses-devel
#BuildRequires: pesign >= 0.109-4
BuildRequires: elfutils-libelf-devel
BuildRequires: rpm >= 4.14.2
#BuildRequires: sparse >= 0.4.1
BuildRequires: elfutils-devel zlib-devel binutils-devel newt-devel python-devel perl(ExtUtils::Embed) bison
BuildRequires: audit-libs-devel
BuildRequires: pciutils-devel gettext
BuildRequires: rpm-build, elfutils
BuildRequires: numactl-devel python3-devel glibc-static python3-docutils
BuildRequires: perl-generators perl(Carp) libunwind-devel gtk2-devel
%if 0%{?with_perf}
# libbabeltrace-devel >= 1.3.0
BuildRequires: libbabeltrace-devel java-1.8.0-openjdk-devel perl-devel
%endif
AutoReq: no
AutoProv: yes

Conflicts: device-mapper-libs < 1.02.63-2 e2fsprogs < 1.37-4 initscripts < 7.23 iptables < 1.3.2-1
Conflicts: ipw2200-firmware < 2.4 isdn4k-utils < 3.2-32 iwl4965-firmware < 228.57.2 jfsutils < 1.1.7-2
Conflicts: mdadm < 3.2.1-5 nfs-utils < 1.0.7-12 oprofile < 0.9.1-2 ppp < 2.4.3-3 procps < 3.2.5-6.3
Conflicts: reiserfs-utils < 3.6.19-2 selinux-policy-targeted < 1.25.3-14 squashfs-tools < 4.0
Conflicts: udev < 063-6 util-linux < 2.12 wireless-tools < 29-3 xfsprogs < 2.6.13-4

Provides: kernel-aarch64 = %{version}-%{release} kernel-drm = 4.3.0 kernel-drm-nouveau = 16 kernel-modeset = 1
Provides: kernel-uname-r = %{KernelVer} kernel=%{KernelVer}

Requires: dracut >= 001-7 grubby >= 8.28-2 initscripts >= 8.11.1-1 linux-firmware >= 20100806-2 module-init-tools >= 3.16-2

ExclusiveArch: noarch aarch64 i686 x86_64
ExclusiveOS: Linux

%description
The Linux Kernel, the operating system core itself.

%package devel
Summary: Development package for building kernel modules to match the %{KernelVer} kernel
AutoReqProv: no
Provides: %{name}-headers
Obsoletes: %{name}-headers
Provides: glibc-kernheaders
Provides: kernel-devel-uname-r = %{KernelVer}
Provides: kernel-devel-aarch64 = %{version}-%{release}
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
Requires: kernel-tools = %{version}-%{release}
Requires: kernel-tools-libs = %{version}-%{release}
Provides: kernel-tools-libs-devel = %{version}-%{release}
Obsoletes: kernel-tools-libs-devel
%description tools-devel
This package contains the development files for the tools/ directory from
the kernel source.

%if 0%{?with_perf}
%package -n perf
Summary: Performance monitoring for the Linux kernel
%description -n perf
This package contains the perf tool, which enables performance monitoring
of the Linux kernel.

%package -n python2-perf
Provides: python-perf = %{version}-%{release}
Obsoletes: python-perf
Summary: Python bindings for apps which will manipulate perf events

%description -n python2-perf
A Python module that permits applications written in the Python programming
language to use the interface to manipulate perf events.

%package -n python3-perf
Summary: Python bindings for apps which will manipulate perf events
%description -n python3-perf
A Python module that permits applications written in the Python programming
language to use the interface to manipulate perf events.
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
%files -n kernel-debuginfo -f debugfiles.list

%debuginfo_template -n bpftool
%files -n bpftool-debuginfo -f bpftool-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_sbindir}/bpftool.*(\.debug)?|XXX' -o bpftool-debugfiles.list}

%debuginfo_template -n kernel-tools
%files -n kernel-tools-debuginfo -f kernel-tools-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_bindir}/centrino-decode.*(\.debug)?|.*%{_bindir}/powernow-k8-decode.*(\.debug)?|.*%{_bindir}/cpupower.*(\.debug)?|.*%{_libdir}/libcpupower.*|.*%{_libdir}/libcpupower.*|.*%{_bindir}/turbostat.(\.debug)?|.*%{_bindir}/.*gpio.*(\.debug)?|.*%{_bindir}/.*iio.*(\.debug)?|.*%{_bindir}/tmon.*(.debug)?|XXX' -o kernel-tools-debugfiles.list}

%if 0%{?with_perf}
%debuginfo_template -n perf
%files -n perf-debuginfo -f perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{_bindir}/perf.*(\.debug)?|.*%{_libexecdir}/perf-core/.*|.*%{_libdir}/traceevent/.*|XXX' -o perf-debugfiles.list}


%debuginfo_template -n python2-perf
%files -n python2-perf-debuginfo -f python2-perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{python2_sitearch}/perf.*(.debug)?|XXX' -o python2-perf-debugfiles.list}

%debuginfo_template -n python3-perf
%files -n python3-perf-debuginfo -f python3-perf-debugfiles.list
%{expand:%%global _find_debuginfo_opts %{?_find_debuginfo_opts} -p '.*%{python3_sitearch}/perf.*(.debug)?|XXX' -o python3-perf-debugfiles.list}
%endif
%endif

%prep

%setup -q -n kernel-%{version} -c


mv kernel linux-%{KernelVer}
cd linux-%{KernelVer}

%if 0%{?with_patch}
cp %{SOURCE9000} .
cp %{SOURCE9001} .
cp %{SOURCE9002} .
cp %{SOURCE9003} . -r

if [ ! -d patches ];then
    mv ../patches .
fi

ignores_for_main="CONFIG_DESCRIPTION,FILE_PATH_CHANGES,GERRIT_CHANGE_ID,GIT_COMMIT_ID,UNKNOWN_COMMIT_ID,FROM_SIGN_OFF_MISMATCH,REPEATED_WORD,COMMIT_COMMENT_SYMBOL,BLOCK_COMMENT_STYLE,AVOID_EXTERNS,AVOID_BUG"

Checkpatches() {
  local SERIESCONF=$1
  local PATCH_DIR=$2
  echo "" >> $SERIESCONF
  sed -i '/^#/d'  $SERIESCONF
  sed -i '/^[\s]*$/d' $SERIESCONF

  set +e
  while read patch; do
    output=$(scripts/checkpatch.pl --ignore $ignores_for_main $PATCH_DIR/$patch)
    if echo "$output" | grep -q "ERROR:"; then
      echo "checkpatch $patch failed"
      set -e
      return 1
    fi
  done < "$SERIESCONF"

  set -e
  return 0
}

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

Checkpatches series.conf %{_builddir}/kernel-%{version}/linux-%{KernelVer}
Applypatches series.conf %{_builddir}/kernel-%{version}/linux-%{KernelVer}
%endif

touch .scmversion

find . \( -name "*.orig" -o -name "*~" \) -exec rm -f {} \; >/dev/null
find . -name .gitignore -exec rm -f {} \; >/dev/null

%if 0%{?with_signmodules}
    cp %{SOURCE11} certs/.
%endif

%if 0%{?with_source}
# Copy directory backup for kernel-source
cp -a ../linux-%{KernelVer} ../linux-%{KernelVer}-Source
find ../linux-%{KernelVer}-Source -type f -name "\.*" -exec rm -rf {} \; >/dev/null
%endif

%if 0%{?with_perf}
cp -a tools/perf tools/python3-perf
%endif

%build
cd linux-%{KernelVer}

perl -p -i -e "s/^EXTRAVERSION.*/EXTRAVERSION = -%{release}.%{_target_cpu}/" Makefile

## make linux
make mrproper %{_smp_mflags}

make ARCH=%{Arch} openeuler_defconfig
make ARCH=%{Arch} olddefconfig

TargetImage=$(basename $(make -s image_name))

make ARCH=%{Arch} $TargetImage %{?_smp_mflags}
make ARCH=%{Arch} modules %{?_smp_mflags}

%if 0%{?with_kabichk}
    chmod 0755 %{SOURCE18}
    if [ -e $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu} ]; then
        %{SOURCE18} -k $RPM_SOURCE_DIR/Module.kabi_%{_target_cpu} -s Module.symvers || exit 1
	echo "**** NOTE: now don't check Kabi. ****"
    else
        echo "**** NOTE: Cannot find reference Module.kabi file. ****"
    fi
%endif

# aarch64 make dtbs
%ifarch aarch64
    make ARCH=%{Arch} dtbs
%endif

## make tools
%if 0%{?with_perf}
# perf
%global perf_make \
    make EXTRA_CFLAGS="-Wl,-z,now -g -Wall -fstack-protector-strong -fPIC" EXTRA_PERFLIBS="-fpie -pie" %{?_smp_mflags} -s V=1 WERROR=0 NO_LIBUNWIND=1 HAVE_CPLUS_DEMANGLE=1 NO_GTK2=1 NO_LIBNUMA=1 NO_STRLCPY=1 prefix=%{_prefix}
%global perf_python2 -C tools/perf PYTHON=%{__python2}
%global perf_python3 -C tools/python3-perf PYTHON=%{__python3}
# perf
chmod +x tools/perf/check-headers.sh
%{perf_make} %{perf_python2} all

# make sure check-headers.sh is executable
chmod +x tools/python3-perf/check-headers.sh
%{perf_make} %{perf_python3} all

pushd tools/perf/Documentation/
make %{?_smp_mflags} man
popd
%endif

# bpftool
pushd tools/bpf/bpftool
make
popd

# cpupower
chmod +x tools/power/cpupower/utils/version-gen.sh
make %{?_smp_mflags} -C tools/power/cpupower CPUFREQ_BENCH=false
%ifarch %{ix86}
    pushd tools/power/cpupower/debug/i386
    make %{?_smp_mflags} centrino-decode powernow-k8-decode
    popd
%endif
%ifarch x86_64
    pushd tools/power/cpupower/debug/x86_64
    make %{?_smp_mflags} centrino-decode powernow-k8-decode
    popd
%endif
%ifarch %{ix86} x86_64
    pushd tools/power/x86/x86_energy_perf_policy/
    make
    popd
    pushd tools/power/x86/turbostat
    make
    popd
%endif
# thermal
pushd tools/thermal/tmon/
make
popd
# iio
pushd tools/iio/
make
popd
# gpio
pushd tools/gpio/
make
popd
# kvm
pushd tools/kvm/kvm_stat/
make %{?_smp_mflags} man
popd


%install
%define _python_bytecompile_errors_terminate_build 0
%if 0%{?with_source}
    mkdir -p $RPM_BUILD_ROOT/usr/src/
    mv linux-%{KernelVer}-Source $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}
    cp linux-%{KernelVer}/.config $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}/
    cp linux-%{KernelVer}/.scmversion $RPM_BUILD_ROOT/usr/src/linux-%{KernelVer}/
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

%if 0%{?with_kabichk}
    gzip -c9 < Module.symvers > $RPM_BUILD_ROOT/boot/symvers-%{KernelVer}.gz
%endif

mkdir -p $RPM_BUILD_ROOT%{_sbindir}
install -m 755 %{SOURCE200} $RPM_BUILD_ROOT%{_sbindir}/mkgrub-menu-%{hulkrelease}.sh


%if 0%{?with_debuginfo}
    mkdir -p $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/%{KernelVer}
    cp vmlinux $RPM_BUILD_ROOT%{debuginfodir}/lib/modules/%{KernelVer}
%endif

# deal with module, if not kdump
make ARCH=%{Arch} INSTALL_MOD_PATH=$RPM_BUILD_ROOT modules_install KERNELRELEASE=%{KernelVer} mod-fw=
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
%{nil}

# deal with header
make ARCH=%{Arch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr KBUILD_SRC= headers_install
make ARCH=%{Arch} INSTALL_HDR_PATH=$RPM_BUILD_ROOT/usr headers_check
find $RPM_BUILD_ROOT/usr/include -name "\.*"  -exec rm -rf {} \;

# aarch64 dtbs install
%ifarch aarch64
    mkdir -p $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}
    install -m 644 $(find arch/%{Arch}/boot -name "*.dtb") $RPM_BUILD_ROOT/boot/dtb-%{KernelVer}/
    rm -f $(find arch/$Arch/boot -name "*.dtb")
%endif

# deal with vdso
make -s ARCH=%{Arch} INSTALL_MOD_PATH=$RPM_BUILD_ROOT vdso_install KERNELRELEASE=%{KernelVer}
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

%ifarch aarch64
    # Needed for systemtap
    cp -a --parents arch/arm64/kernel/module.lds $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
    cp -a --parents arch/arm/include/asm $RPM_BUILD_ROOT/lib/modules/%{KernelVer}/build/
%endif

# copy objtool for kernel-devel (needed for building external modules)
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


# deal with doc , now we don't need


# deal with kernel abi whitelists. now we don't need


## install tools
%if 0%{?with_perf}
# perf
# perf tool binary and supporting scripts/binaries
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} lib=%{_lib} install-bin install-traceevent-plugins
# remove the 'trace' symlink.
rm -f %{buildroot}%{_bindir}/trace

# remove examples
rm -rf %{buildroot}/usr/lib/perf/examples
# remove the stray header file that somehow got packaged in examples
rm -rf %{buildroot}/usr/lib/perf/include/bpf/

# python-perf extension
%{perf_make} %{perf_python3} DESTDIR=%{buildroot} install-python_ext
%{perf_make} %{perf_python2} DESTDIR=%{buildroot} install-python_ext
%endif

install -d %{buildroot}/%{_mandir}/man1
install -pm0644 tools/kvm/kvm_stat/kvm_stat.1 %{buildroot}/%{_mandir}/man1/
# perf man pages (note: implicit rpm magic compresses them later)
%if 0%{?with_perf}
install -pm0644 tools/perf/Documentation/*.1 %{buildroot}/%{_mandir}/man1/
%endif

# bpftool
pushd tools/bpf/bpftool
make DESTDIR=%{buildroot} prefix=%{_prefix} bash_compdir=%{_sysconfdir}/bash_completion.d/ mandir=%{_mandir} install doc-install
popd
# cpupower
make -C tools/power/cpupower DESTDIR=%{buildroot} libdir=%{_libdir} mandir=%{_mandir} CPUFREQ_BENCH=false install
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
    make DESTDIR=%{buildroot} install
    popd
    pushd tools/power/x86/turbostat
    make DESTDIR=%{buildroot} install
    popd
%endif
# thermal
pushd tools/thermal/tmon
make INSTALL_ROOT=%{buildroot} install
popd
# iio
pushd tools/iio
make DESTDIR=%{buildroot} install
popd
# gpio
pushd tools/gpio
make DESTDIR=%{buildroot} install
popd
# kvm
pushd tools/kvm/kvm_stat
make INSTALL_ROOT=%{buildroot} install-tools
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
    /usr/bin/sh  %{_sbindir}/mkgrub-menu-%{hulkrelease}.sh %{version}-%{hulkrelease}.aarch64  /boot/EFI/grub2/grub.cfg  remove
fi

%postun
%{_sbindir}/new-kernel-pkg --rminitrd --rmmoddep --remove %{KernelVer} || exit $?
if [ -x %{_sbindir}/weak-modules ]
then
    %{_sbindir}/weak-modules --remove-kernel %{KernelVer} || exit $?
fi
if [ -d /lib/modules/%{KernelVer} ] && [ "`ls -A  /lib/modules/%{KernelVer}`" = "" ]; then
    rm -rf /lib/modules/%{KernelVer}
fi

%posttrans
%{_sbindir}/new-kernel-pkg --package kernel --mkinitrd --dracut --depmod --update %{KernelVer} || exit $?
%{_sbindir}/new-kernel-pkg --package kernel --rpmposttrans %{KernelVer} || exit $?
if [ `uname -i` == "aarch64" ] &&
        [ -f /boot/EFI/grub2/grub.cfg ]; then
	/usr/bin/sh %{_sbindir}/mkgrub-menu-%{hulkrelease}.sh %{version}-%{hulkrelease}.aarch64  /boot/EFI/grub2/grub.cfg  update  
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

%post -n kernel-tools
/sbin/ldconfig
%systemd_post cpupower.service

%preun -n kernel-tools
%systemd_preun cpupower.service

%postun -n kernel-tools
/sbin/ldconfig
%systemd_postun cpupower.service

%files
%defattr (-, root, root)
%doc
/boot/config-*
%ifarch aarch64
/boot/dtb-*
%endif
%if 0%{?with_kabichk}
/boot/symvers-*
%endif
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
/usr/include/*


%if 0%{?with_perf}
%files -n perf
%{_libdir}/libperf*
%{_bindir}/perf
%dir %{_libdir}/traceevent
%{_libdir}/traceevent/plugins/
%{_libexecdir}/perf-core
%{_datadir}/perf-core/
%{_mandir}/man[1-8]/perf*
%{_sysconfdir}/bash_completion.d/perf
%doc linux-%{KernelVer}/tools/perf/Documentation/examples.txt
%dir %{_datadir}/doc/perf-tip
%{_datadir}/doc/perf-tip/*
%license linux-%{KernelVer}/COPYING

%files -n python2-perf
%license linux-%{KernelVer}/COPYING
%{python2_sitearch}/*

%files -n python3-perf
%license linux-%{KernelVer}/COPYING
%{python3_sitearch}/*
%endif

%files -n kernel-tools -f cpupower.lang
%{_bindir}/cpupower
%ifarch %{ix86} x86_64
%{_bindir}/centrino-decode
%{_bindir}/powernow-k8-decode
%endif
%{_unitdir}/cpupower.service
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
%{_mandir}/man1/kvm_stat*
%{_bindir}/kvm_stat
%{_libdir}/libcpupower.so.0
%{_libdir}/libcpupower.so.0.0.1
%license linux-%{KernelVer}/COPYING

%files -n kernel-tools-devel
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
%{_mandir}/man7/bpf-helpers.7.gz
%license linux-%{KernelVer}/COPYING

%if 0%{?with_source}
%files source
%defattr(-,root,root)
/usr/src/linux-%{KernelVer}/*
/usr/src/linux-%{KernelVer}/.config
/usr/src/linux-%{KernelVer}/.scmversion
%endif

%changelog
* Mon Nov 6 2023 YunYi Yang <yangyunyi2@huawei.com> - 4.19.90-2311.1.0.0235
- Fix the header file location error and adjust the function and structure version.
- perf auxtrace arm64: Add support for parsing HiSilicon PCIe Trace packet
- perf auxtrace arm64: Add support for HiSilicon PCIe Tune and Trace device driver
- perf auxtrace arm: Refactor event list iteration in auxtrace_record__init()
- perf tools: No need to cache the PMUs in ARM SPE auxtrace init routine
- perf tools: Fix record failure when mixed with ARM SPE event
- perf pmu: Move EVENT_SOURCE_DEVICE_PATH to PMU header file

* Mon Nov 6 2023 Jiang Yi <jiangyi38@hisilicon.com> - 4.19.90-2311.1.0.0234
- spi: hisi-kunpeng: Fix the debugfs directory name incorrect
- spi: hisi-kunpeng: Add debugfs support
- spi: hisi-kunpeng: Fix Woverflow warning on conversion
- spi: Add HiSilicon SPI Controller Driver for Kunpeng SoCs
- Documentation: devres: add missing SPI helper
- spi: <linux/spi/spi.h>: add missing struct kernel-doc entry
- spi: Fix use-after-free with devm_spi_alloc_*
- spi: Introduce device-managed SPI controller allocation
- spi: core: allow reporting the effectivly used speed_hz for a transfer

* Fri Nov 3 2023 Yu Liao <liaoyu15@huawei.com> - 4.19.90-2310.4.0.0233
- arm64: HWCAP: add support for AT_HWCAP2
- arm64: Expose SVE2 features for userspace
- arm64: cpufeature: Fix missing ZFR0 in __read_sysreg_by_encoding()

* Thu Nov 2 2023 hongrongxuan <hongrongxuan@huawei.com> - 4.19.90-2311.1.0.0232
- remove linux-kernel-test.patch

* Wed Nov 1 2023 hongrongxuan <hongrongxuan@huawei.com> - 4.19.90-2311.1.0.0231
- perf/smmuv3: Add MODULE_ALIAS for module auto loading
- perf/smmuv3: Enable HiSilicon Erratum 162001900 quirk for HIP08/09
- perf/smmuv3: Enable HiSilicon Erratum 162001800 quirk
- Revert "perf/smmuv3_pmu: Enable HiSilicon Erratum 162001800 quirk"
- drivers/perf: hisi: add NULL check for name
- drivers/perf: hisi: Remove redundant initialized of pmu->name
- drivers/perf: hisi: Extract initialization of "cpa_pmu->pmu"
- drivers/perf: hisi: Simplify the parameters of hisi_pmu_init()
- drivers/perf: hisi: Advertise the PERF_PMU_CAP_NO_EXCLUDE capability
- perf: hisi: Extract hisi_pmu_init
- perf: hisi: Add configs for PMU isolation
- perf: hisi: Fix read sccl_id and ccl_id error in TSV200
- drivers/perf: fixed kabi broken for SLLC and PA PMU
- drivers/perf: fixed the issue that the kabi value changed
- drivers/perf: hisi: Don't migrate perf to the CPU going to teardown
- drivers/perf: hisi: Add TLP filter support
- docs: perf: Fix PMU instance name of hisi-pcie-pmu
- docs: fix 'make htmldocs' warning in perf
- docs: perf: Address some html build warnings
- docs: perf: Add description for HiSilicon PCIe PMU driver
- docs: perf: Add new description on HiSilicon uncore PMU v2
- docs: perf: move to the admin-guide
- drivers/perf: hisi: Fix some event id for hisi-pcie-pmu
- drivers/perf: hisi: Add Support for CPA PMU
- driver/perf: hisi: fix kabi broken for struct hisi_pmu
- drivers/perf: hisi: Associate PMUs in SICL with CPUs online
- drivers/perf: hisi: Add driver for HiSilicon PCIe PMU
- PCI: Add pci_dev_id() helper
- perf: hisi: Fix unexpected modifications in hisi_uncore_l3c_pmu.c
- perf: hisi: Add support for HiSilicon SoC LPDDRC PMU
- perf: hisi: Add support for HiSilicon SoC L3T PMU
- perf: hisi: Fix read sccl_id and ccl_id error in some platform
- perf: hisi: Make irq shared
- drivers/perf: hisi: Fix data source control
- perf/hisi: Use irq_set_affinity()
- drivers/perf: hisi: Add support for HiSilicon PA PMU driver
- drivers/perf: hisi: Add support for HiSilicon SLLC PMU driver
- drivers/perf: hisi: Update DDRC PMU for programmable counter
- drivers/perf: hisi: Add new functions for HHA PMU
- drivers/perf: hisi: Add new functions for L3C PMU
- drivers/perf: hisi: Add PMU version for uncore PMU drivers.
- drivers/perf: hisi: Refactor code for more uncore PMUs
- drivers/perf: hisi: Remove unnecessary check of counter index
- drivers/perf: hisi: Add identifier sysfs file
- perf: hisi: use devm_platform_ioremap_resource() to simplify code
- drivers: provide devm_platform_ioremap_resource()
- For drivers that do not support context exclusion let's advertise the PERF_PMU_CAP_NO_EXCLUDE capability. This ensures that perf will prevent us from handling events where any exclusion flags are set. Let's also remove the now unnecessary check for exclusion flags.
- drivers/perf: Fix kernel panic when rmmod PMU modules during perf sampling
- docs: perf: convert to ReST
- Revert "perf: hisi: remove duplicated code"
- Revert "drivers/perf: Fix kernel panic when rmmod PMU modules during perf sampling"
- Revert "perf: hisi: Add support for HiSilicon SoC PMU driver dt probe"
- Revert "perf: hisi: Add support for HiSilicon SoC LPDDRC PMU driver"
- Revert "perf: hisi: Add support for HiSilicon SoC L3T PMU driver"
- Revert "perf: hisi: Fix compile error if defined MODULE"

* Wed Nov 1 2023 Luo Shengwei <luoshengwei@huawei.com> - 4.19.90-2311.1.0.0230
- !2609  Fix CVE-2023-5717
- !2588 [openEuler-1.0-LTS] Add Phytium Display Engine support.
- !2627  ubi: Refuse attaching if mtd's erasesize is 0
- !2473  Revert irq reentrant warm log
- !1860 irqchip/gicv3-its: Add workaround for hip09 ITS erratum 162100801
- !2551  Avoid spin or livelock during panic
- !2314  can: raw: add missing refcount for memory leak fix
- !2396  efi: use 32-bit alignment for efi_guid_t literals
- ubi: Refuse attaching if mtd's erasesize is 0
- !2446  audit: fix possible soft lockup in __audit_inode_child()
- !2614  CVE-2022-44033
- DRM: Phytium display DRM document
- DRM: Phytium display DRM driver
- ASoC: hdmi-codec: Add an op to set callback function for plug event
- char: pcmcia: remove all the drivers
- tty: ipwireless: move Kconfig entry to tty
- !1974 CAN driver for phytium CPUs
- perf: Fix kabi breakage in struct perf_event
- perf: Disallow mis-matched inherited group reads
- !2577  media: dvb-core: Fix use-after-free due to race condition at dvb_ca_en50221
- can: can controller driver for phytium CPUs
- !2550  xen/events: replace evtchn_rwlock with RCU
- media: dvb-core: Fix use-after-free due to race condition at dvb_ca_en50221
- !2557  Bluetooth: hci_ldisc: check HCI_UART_PROTO_READY flag in HCIUARTGETPROTO
- Bluetooth: hci_ldisc: check HCI_UART_PROTO_READY flag in HCIUARTGETPROTO
- printk: Drop console_sem during panic
- printk: Avoid livelock with heavy printk during panic
- printk: disable optimistic spin during panic
- printk: Add panic_in_progress helper
- xen/events: replace evtchn_rwlock with RCU
- irqchip/gicv3-its: Add workaround for hip09 ITS erratum 162100801
- irqchip/gic-v3-its: Make is_v4 use a TYPER copy
- Revert "genirq: Introduce warn log when irq be reentrant"
- Revert "genirq: add printk safe in irq context"
- audit: fix possible soft lockup in __audit_inode_child()
- can: add phytium can driver document
- efi: use 32-bit alignment for efi_guid_t literals
- can: raw: add missing refcount for memory leak fix

* Tue Oct 31 2023 Yu Liao <liaoyu15@huawei.com> - 4.19.90-2310.4.0.0229
- add new line at the end of series.conf

* Tue Oct 31 2023 hongrongxuan <hongrongxuan@huawei.com> - 4.19.90-2310.4.0.0228
- drivers/perf: Add support for ARMv8.3-SPE
- perf arm-spe: Add support for ARMv8.3-SPE
- perf arm_spe: Decode memory tagging properties
- perf arm-spe: Add more sub classes for operation packet
- perf arm-spe: Refactor operation packet handling
- perf arm-spe: Add new function arm_spe_pkt_desc_op_type()
- perf arm-spe: Remove size condition checking for events
- perf arm-spe: Refactor event type handling
- perf arm-spe: Add new function arm_spe_pkt_desc_event()
- perf arm-spe: Refactor counter packet handling
- perf arm-spe: Add new function arm_spe_pkt_desc_counter()
- perf arm-spe: Refactor context packet handling
- perf arm-spe: Refactor address packet handling
- perf arm-spe: Add new function arm_spe_pkt_desc_addr()
- perf arm-spe: Refactor packet header parsing
- perf arm-spe: Refactor printing string to buffer
- perf arm-spe: Fix packet length handling
- perf arm-spe: Refactor arm_spe_get_events()

* Mon Oct 30 2023 Keyi Zhong <zhongkeyi1@huawei.com> - 4.19.90-2310.4.0.0227
- crypto: hisilicon - fix different version of devices driver compatibility issue

* Mon Oct 30 2023 Yu Liao <liaoyu15@huawei.com> - 4.19.90-2310.4.0.0226
- Add checkpatch check

* Sat Oct 28 2023 YunYi Yang <yangyunyi2@huawei.com> - 4.19.90-2310.4.0.0225
- config: arm64: Enable config of hisi ptt
- hwtracing: hisi_ptt: Add dummy callback pmu::read()
- hwtracing: hisi_ptt: Keep to advertise PERF_PMU_CAP_EXCLUSIVE
- hwtracing: hisi_ptt: Fix potential sleep in atomic context
- hwtracing: hisi_ptt: Advertise PERF_PMU_CAP_NO_EXCLUDE for PTT PMU
- hwtracing: hisi_ptt: Export available filters through sysfs
- hwtracing: hisi_ptt: Add support for dynamically updating the filter list
- hwtracing: hisi_ptt: Factor out filter allocation and release operation
- hwtracing: hisi_ptt: Only add the supported devices to the filters list
- hwtracing: hisi_ptt: Fix up for "iommu/dma: Make header private"
- MAINTAINERS: Add maintainer for HiSilicon PTT driver
- docs: trace: Add HiSilicon PTT device driver documentation
- hwtracing: hisi_ptt: Add tune function support for HiSilicon PCIe Tune and Trace device
- hwtracing: hisi_ptt: Add trace function support for HiSilicon PCIe Tune and Trace device
- genirq: Export affinity setter for modules
- iommu/arm-smmu-v3: Integrate the function for obtain the device domain type in bypass mode
- iommu/arm-smmu-v3: Make default domain type of HiSilicon PTT device to identity
- iommu: Add def_domain_type() callback in iommu_ops
- PCI: Support BAR sizes up to 8TB

* Fri Oct 27 2023 Luo Shengwei <luoshengwei@huawei.com> - 4.19.90-2310.4.0.0224
- open macro: with_patch and add file: series.conf, where patches defined can 
- be applied automatically.

* Tue Oct 24 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2310.4.0.0223
- !2334 ktask: add memory leak handling for ktask_works in ktask_init()
- !2333 ktask: add null-pointer checks for ktask_works in ktask_init()
- !2453  igb: set max size RX buffer when store bad packet is enabled
- ktask: add memory leak handling for ktask_works in ktask_init()
- ktask: add null-pointer checks for ktask_works in ktask_init()
- !2441  netfilter: xt_u32: validate user space input
- !2435  USB: ene_usb6250: Allocate enough memory for full object
- igb: set max size RX buffer when store bad packet is enabled
- netfilter: xt_u32: validate user space input
- USB: ene_usb6250: Allocate enough memory for full object

* Wed Oct 18 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2310.3.0.0222
- !2466  x86/microcode/AMD: Make stub function static inline
- !2461  perf/core: Fix reentry problem in perf_output_read_group()
- x86/microcode/AMD: Make stub function static inline
- perf/core: Fix reentry problem in perf_output_read_group()
- !2409  netfilter: nfnetlink_osf: avoid OOB read
- !2330 Add a check of uvhub_mask in init_per_cpu()
- x86/platform/uv: Fix missing checks of kcalloc() return values
- x86/platform/UV: Replace kmalloc() and memset() with k[cz]alloc() calls
- !2412  netfilter: xt_sctp: validate the flag_info count
- !2419  ext4: fix rec_len verify error
- ext4: fix rec_len verify error
- netfilter: xt_sctp: validate the flag_info count
- netfilter: nfnetlink_osf: avoid OOB read
- !2360  scsi: hisi_sas: Handle the NCQ error returned by D2H frame
- scsi: hisi_sas: Handle the NCQ error returned by D2H frame

* Wed Oct 11 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2310.2.0.0221
- !2322  net/sched: Retire rsvp classifier
- !2346  RDMA/irdma: Prevent zero-length STAG registration
- !2349  net: ipv4: fix one memleak in __inet_del_ifa()
- !2329  ipv4: fix null-deref in ipv4_link_failure
- !2342 linux-4.19.y inclusion
- !2345  Backport lts bugfix patch for macvlan
- !2344  PCI: acpiphp: linux-4.19.y bugfixes backport
- !2341  quota: fix warning in dqgrab()
- net: ipv4: fix one memleak in __inet_del_ifa()
- !1706  cgroup: fix missing cpus_read_{lock,unlock}() in cgroup_transfer_tasks()
- rtnetlink: Reject negative ifindexes in RTM_NEWLINK
- netfilter: nf_queue: fix socket leak
- net/sched: fix a qdisc modification with ambiguous command request
- net: xfrm: Amend XFRMA_SEC_CTX nla_policy structure
- net: fix the RTO timer retransmitting skb every 1ms if linear option is enabled
- sock: annotate data-races around prot->memory_pressure
- !2337  mm: memory-failure: use rcu lock instead of tasklist_lock when collect_procs()
- RDMA/irdma: Prevent zero-length STAG registration
- bonding: fix macvlan over alb bond support
- net: remove bond_slave_has_mac_rcu()
- PCI: acpiphp: Use pci_assign_unassigned_bridge_resources() only for non-root bus
- PCI: acpiphp: Reassign resources on bridge if necessary
- sock: Fix misuse of sk_under_memory_pressure()
- team: Fix incorrect deletion of ETH_P_8021AD protocol vid from slaves
- ip_vti: fix potential slab-use-after-free in decode_session6
- net: af_key: fix sadb_x_filter validation
- net: xfrm: Fix xfrm_address_filter OOB read
- serial: 8250: Fix oops for port->pm on uart_change_pm()
- quota: Properly disable quotas when add_dquot_ref() fails
- quota: fix warning in dqgrab()
- !2335  x86/topology: Fix erroneous smp_num_siblings on Intel Hybrid platforms
- mm: memory-failure: use rcu lock instead of tasklist_lock when collect_procs()
- x86/topology: Fix erroneous smp_num_siblings on Intel Hybrid platforms
- ipv4: fix null-deref in ipv4_link_failure
- net/sched: Retire rsvp classifier
- !2301  xfrm6: fix inet6_dev refcount underflow problem
- !2303  cifs: Release folio lock on fscache read hit.
- cifs: Release folio lock on fscache read hit.
- !2294  netfilter: ipset: add the missing IP_SET_HASH_WITH_NET0 macro for ip_set_hash_netportnet.c
- xfrm6: fix inet6_dev refcount underflow problem
- netfilter: ipset: add the missing IP_SET_HASH_WITH_NET0 macro for ip_set_hash_netportnet.c
- !2276  cpuidle: Fix kobject memory leaks in error paths
- cpuidle: Fix kobject memory leaks in error paths
- cgroup: fix missing cpus_read_{lock,unlock}() in cgroup_transfer_tasks()

* Mon Sep 25 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2309.5.0.0220
- !2274  cec-api: prevent leaking memory through hole in structure
- !2281  sdei_watchdog: Avoid exception during sdei handler
- sdei_watchdog: Avoid exception during sdei handler
- cec-api: prevent leaking memory through hole in structure
- !2262  crypto: hisilicon - reset before init the device
- crypto: hisilicon - reset before init the device
- !2212 [sync] PR-2210:  jbd2: Fix potential data lost in recovering journal raced with synchronizing fs bdev
- jbd2: Fix potential data lost in recovering journal raced with synchronizing fs bdev

* Wed Sep 20 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2309.4.0.0219
- !2168  net: sched: sch_qfq: Fix UAF in qfq_dequeue()
- !2226  crypto: hisilicon/qm - prevent soft lockup in qm_poll_qp()'s loop
- !2225  media: ttusb-dec: fix memory leak in ttusb_dec_exit_dvb()
- crypto: hisilicon/qm - prevent soft lockup in qm_poll_qp()'s loop
- media: ttusb-dec: fix memory leak in ttusb_dec_exit_dvb()
- !2177  sched/qos: Fix warning in CPU hotplug scenarios
- !2207  crypto:hisilicon/qm - cache write back before flr and poweroff
- !2206  Fix booting failure on arm64
- crypto:hisilicon/qm - cache write back before flr and poweroff
- !2205  crypto:hisilicon/sec - modify hw endian config
- Revert "efi: Make efi_rts_work accessible to efi page fault handler"
- Revert "efi/x86: Handle page faults occurring while running EFI runtime services"
- Revert "efi: Fix debugobjects warning on 'efi_rts_work'"
- Revert "efi: Fix build error due to enum collision between efi.h and ima.h"
- Revert "x86/efi: fix a -Wtype-limits compilation warning"
- Revert "arm64: efi: Restore register x18 if it was corrupted"
- Revert "efi: fix userspace infinite retry read efivars after EFI runtime services page fault"
- Revert "arm64: efi: Execute runtime services from a dedicated stack"
- Revert "arm64: efi: Recover from synchronous exceptions occurring in firmware"
- Revert "efi: rt-wrapper: Add missing include"
- Revert "arm64: efi: Make efi_rt_lock a raw_spinlock"
- crypto:hisilicon/sec - modify hw endian config
- !2118 Compiler: Backport value profile support to openEuler 20.03 LTS SP3.
- GCOV: Add value profile support for kernel.
- sched/qos: Fix warning in CPU hotplug scenarios
- !2154  netfilter: nftables: exthdr: fix 4-byte stack OOB write
- net: sched: sch_qfq: Fix UAF in qfq_dequeue()
- !2140  io_uring: ensure IOPOLL locks around deferred work
- !2056 i2c: hisi: Add gpio bus recovery support
- netfilter: nftables: exthdr: fix 4-byte stack OOB write
- !2082  fix CVE-2023-20588
- io_uring: ensure IOPOLL locks around deferred work
- i2c: hisi: Add gpio bus recovery support
- x86/CPU/AMD: Fix the DIV(0) initial fix attempt
- x86/CPU/AMD: Do not leak quotient data after a division by 0

* Wed Sep 13 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2309.3.0.0218
- !2084  af_unix: Fix null-ptr-deref in unix_stream_sendpage().
- !2071 【openEuler-1.0-LTS】net: openvswitch: don't send internal clone attribute to the userspace
- net: openvswitch: don't send internal clone attribute to the userspace.
- !2089  net/sched: sch_hfsc: Ensure inner classes have fsc curve
- !335 efi: fix crash due to EFI runtime service page faults
- net/sched: sch_hfsc: Ensure inner classes have fsc curve
- !2088 [openEuler-1.0-LTS] bugfixes of scsi
- scsi: fix kabi broken in struct Scsi_Host
- scsi: don't fail if hostt->module is NULL
- scsi: scsi_device_gets returns failure when the module is NULL.
- af_unix: Fix null-ptr-deref in unix_stream_sendpage().
- !2069  x86/speculation: Add Gather Data Sampling mitigation
- !1692  Mainline bugfix patches backport 4.19
- !2075  x86/cpu/amd: Enable Zenbleed fix for AMD Custom APU 0405
- !2079 [openEuler-1.0-LTS] stable inclusion from linux-4.19.y
- scsi: core: raid_class: Remove raid_component_add()
- scsi: core: Fix possible memory leak if device_add() fails
- scsi: core: Fix legacy /proc parsing buffer overflow
- serial: 8250_dw: Preserve original value of DLF register
- serial: 8250_dw: split Synopsys DesignWare 8250 common functions
- nbd: Add the maximum limit of allocated index in nbd_dev_add
- integrity: Fix possible multiple allocation in integrity_inode_get()
- !2070 net bugfixes inclusion from linux-4.19.y
- drivers: net: prevent tun_build_skb() to exceed the packet size limit
- net/packet: annotate data-races around tp->status
- tcp_metrics: fix data-race in tcpm_suck_dst() vs fastopen
- tcp_metrics: annotate data-races around tm->tcpm_net
- tcp_metrics: annotate data-races around tm->tcpm_vals[]
- tcp_metrics: annotate data-races around tm->tcpm_lock
- tcp_metrics: annotate data-races around tm->tcpm_stamp
- tcp_metrics: fix addr_same() helper
- virtio-net: set queues after driver_ok
- virtio-net: fix race between set queues and probe
- team: reset team's flags when down link is P2P device
- bonding: reset bond's flags when down link is P2P device
- tcp: annotate data-races around fastopenq.max_qlen
- tcp: annotate data-races around tp->notsent_lowat
- tcp: annotate data-races around rskq_defer_accept
- tcp: annotate data-races around tp->linger2
- net: Replace the limit of TCP_LINGER2 with TCP_FIN_TIMEOUT_MAX
- SUNRPC: Fix UAF in svc_tcp_listen_data_ready()
- net/sched: make psched_mtu() RTNL-less safe
- udp6: fix udp6_ehashfn() typo
- icmp6: Fix null-ptr-deref of ip6_null_entry->rt6i_idev in icmp6_dev().
- vrf: Increment Icmp6InMsgs on the original netdev
- netfilter: conntrack: Avoid nf_ct_helper_hash uses after free
- tcp: annotate data races in __tcp_oow_rate_limited()
- net: bridge: keep ports without IFF_UNICAST_FLT in BR_PROMISC mode
- ipvlan: Fix return value of ipvlan_queue_xmit()
- netlink: do not hard code device address lenth in fdb dumps
- netlink: Add __sock_i_ino() for __netlink_diag_dump().
- x86/cpu/amd: Enable Zenbleed fix for AMD Custom APU 0405
- !1987  tracing: Fix race issue between cpu buffer write and swap
- !2067  memcg: add refcnt for pcpu stock to avoid UAF problem in drain_all_stock()
- netlink: fix potential deadlock in netlink_set_err()
- x86/speculation: Mark all Skylake CPUs as vulnerable to GDS
- x86: Move gds_ucode_mitigated() declaration to header
- Documentation/x86: Fix backwards on/off logic about YMM support
- KVM: Add GDS_NO support to KVM
- x86/speculation: Add Kconfig option for GDS
- x86/speculation: Add force option to GDS mitigation
- x86/speculation: Add cpu_show_gds() prototype
- x86/speculation: Add Gather Data Sampling mitigation
- !2063  cpu/hotplug: Prevent self deadlock on CPU hot-unplug
- !2046  use precise io accounting apis
- memcg: add refcnt for pcpu stock to avoid UAF problem in drain_all_stock()
- cpu/hotplug: Prevent self deadlock on CPU hot-unplug
- !2050  memcg: fix a UAF problem in drain_all_stock()
- !1976  fix race between setxattr and write back
- memcg: fix a UAF problem in drain_all_stock()
- dm: switch to precise io accounting
- block: add precise io accouting apis
- tracing: Fix race issue between cpu buffer write and swap
- ext2: dump current reservation window info
- ext2: fix race between setxattr and write back
- ext2: introduce flag argument for ext2_new_blocks()
- ext2: remove ext2_new_block()
- arm64: efi: Make efi_rt_lock a raw_spinlock
- efi: rt-wrapper: Add missing include
- arm64: efi: Recover from synchronous exceptions occurring in firmware
- arm64: efi: Execute runtime services from a dedicated stack
- efi: fix userspace infinite retry read efivars after EFI runtime services page fault
- arm64: efi: Restore register x18 if it was corrupted
- x86/efi: fix a -Wtype-limits compilation warning
- efi: Fix build error due to enum collision between efi.h and ima.h
- efi: Fix debugobjects warning on 'efi_rts_work'
- efi/x86: Handle page faults occurring while running EFI runtime services
- efi: Make efi_rts_work accessible to efi page fault handler
- lib/genalloc.c: change return type to unsigned long for bitmap_set_ll
- iommu/amd: Restore IRTE.RemapEn bit after programming IRTE
- iommu/amd: Use cmpxchg_double() when updating 128-bit IRTE

* Tue Sep 05 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2309.1.0.0217
- !1964  crypto:padata: Fix return err for PADATA_RESET
- !1955  fuse: revalidate: don't invalidate if interrupted
- !1973  sched/smt: fix unbalance sched_smt_present dec/inc
- sched/smt: fix unbalance sched_smt_present dec/inc
- !1906  tracing: Fix memleak due to race between current_tracer and trace
- !1958  block: don't get gendisk if queue has not been registered
- crypto:padata: Fix return err for PADATA_RESET
- block: don't get gendisk if queue has not been registered
- fuse: revalidate: don't invalidate if interrupted
- !1902  tracing: Fix cpu buffers unavailable due to 'record_disabled' missed
- tracing: Fix memleak due to race between current_tracer and trace
- tracing: Fix cpu buffers unavailable due to 'record_disabled' missed

* Tue Aug 29 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2308.5.0.0216
- !1863  nbd: pass nbd_sock to nbd_read_reply() instead of index
- !1638 [openEuler-1.0-LTS] Add support for Hygon model 4h~6h processors
- !1884  ipvlan: Fix a reference count leak warning in ipvlan_ns_exit()
- !1882  ip6mr: Fix skb_under_panic in ip6mr_cache_report()
- ipvlan: Fix a reference count leak warning in ipvlan_ns_exit()
- ip6mr: Fix skb_under_panic in ip6mr_cache_report()
- EDAC/amd64: Add support for Hygon family 18h model 6h
- x86/amd_nb: Add support for Hygon family 18h model 6h
- hwmon/k10temp: Add support for Hygon family 18h model 5h
- EDAC/amd64: Add support for Hygon family 18h model 5h
- x86/amd_nb: Add support for Hygon family 18h model 5h
- x86/cpu: Get LLC ID for Hygon family 18h model 5h
- i2c-piix4: Remove the IMC detecting for Hygon SMBus
- hwmon/k10temp: Add support for Hygon family 18h model 4h
- EDAC/mce_amd: Use struct cpuinfo_x86.logical_die_id for Hygon NodeId
- EDAC/amd64: Adjust address translation for Hygon family 18h model 4h
- EDAC/amd64: Add support for Hygon family 18h model 4h
- EDAC/amd64: Get UMC channel from the 6th nibble for Hygon
- iommu/hygon: Add support for Hygon family 18h model 4h IOAPIC
- x86/amd_nb: Add northbridge support for Hygon family 18h model 4h
- x86/amd_nb: Add Hygon family 18h model 4h PCI IDs
- x86/microcode/hygon: Add microcode loading support for Hygon processors
- x86/cpu/hygon: Modify the CPU topology deriving method for Hygon
- x86/MCE/AMD: Use an u64 for bank_map
- EDAC/mc_sysfs: Increase legacy channel support to 12
- EDAC/amd64: Add new register offset support and related changes
- EDAC/amd64: Set memory type per DIMM
- rtc: mc146818-lib: Fix the AltCentury for AMD platforms
- EDAC/amd64: Add support for AMD Family 19h Models 10h-1Fh and A0h-AFh
- EDAC: Add RDDR5 and LRDDR5 memory types
- hwmon: (k10temp) Remove unused definitions
- hwmon: (k10temp) Remove residues of current and voltage
- hwmon: (k10temp) Rework the temperature offset calculation
- hwmon: (k10temp) Don't show Tdie for all Zen/Zen2/Zen3 CPU/APU
- x86/cstate: Allow ACPI C1 FFH MWAIT use on Hygon systems
- x86/topology: Make __max_die_per_package available unconditionally
- x86/cpu/amd: Set __max_die_per_package on AMD
- hwmon: (k10temp) Remove support for displaying voltage and current on Zen CPUs
- EDAC: Add DDR5 new memory type
- x86/topology: Set cpu_die_id only if DIE_TYPE found
- EDAC/mce_amd: Use struct cpuinfo_x86.cpu_die_id for AMD NodeId
- x86/CPU/AMD: Save AMD NodeId as cpu_die_id
- EDAC/amd64: Set proper family type for Family 19h Models 20h-2Fh
- hwmon: (k10temp) Add support for Zen3 CPUs
- x86/mce: Increase maximum number of banks to 64
- hwmon: (k10temp) Define SVI telemetry and current factors for Zen2 CPUs
- hwmon: (k10temp) Create common functions and macros for Zen CPU families
- i2c: designware: Add device HID for Hygon I2C controller
- hwmon: (k10temp) make some symbols static
- hwmon: (k10temp) Reorganize and simplify temperature support detection
- hwmon: (k10temp) Swap Tdie and Tctl on Family 17h CPUs
- hwmon: (k10temp) Display up to eight sets of CCD temperatures
- hwmon: (k10temp) Don't show temperature limits on Ryzen (Zen) CPUs
- hwmon: (k10temp) Show core and SoC current and voltages on Ryzen CPUs
- hwmon: (k10temp) Report temperatures per CPU die
- hmon: (k10temp) Convert to use devm_hwmon_device_register_with_info
- hwmon: (k10temp) Use bitops
- hwmon: Add convience macro to define simple static sensors
- hwmon: (k10temp) Auto-convert to use SENSOR_DEVICE_ATTR_{RO, RW, WO}
- hwmon: Introduce SENSOR_DEVICE_ATTR_{RO, RW, WO} and variants
- x86/umip: Make the UMIP activated message generic
- x86/umip: Print UMIP line only once
- x86/microcode/AMD: Clean up per-family patch size checks
- !1689 [openEuler-1.0-LTS] drm/atomic-helper: Bump vblank timeout to 100 ms
- nbd: pass nbd_sock to nbd_read_reply() instead of index
- !1807  Bluetooth: L2CAP: Fix use-after-free in l2cap_sock_ready_cb
- !1844  net: vmxnet3: fix possible NULL pointer dereference in vmxnet3_rq_cleanup()
- !1785  README: Remove out-of-date contribution guide
- !1849  fs: jfs: fix possible NULL pointer dereference in dbFree()
- fs: jfs: fix possible NULL pointer dereference in dbFree()
- !1836  tcp: Reduce chance of collisions in inet6_hashfn().
- net: vmxnet3: fix possible NULL pointer dereference in vmxnet3_rq_cleanup()
- tcp: Reduce chance of collisions in inet6_hashfn().
- Bluetooth: L2CAP: Fix use-after-free in l2cap_sock_ready_cb
- README: Remove out-of-date contribution guide
- drm/atomic-helper: Bump vblank timeout to 100 ms

* Tue Aug 22 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2308.4.0.0215
- !1831  fix NULL pointer dereference in __nf_nat_mangle_tcp_packet
- netfilter: nat: fix kabi change
- netfilter: nat: fix udp checksum corruption
- netfilter: nat: remove csum_recalc hook
- !1769  workqueue: Make flush_workqueue() also watch flush_work()
- !1803  net: vmxnet3: fix possible use-after-free bugs in vmxnet3_rq_alloc_rx_buf()
- net: vmxnet3: fix possible use-after-free bugs in vmxnet3_rq_alloc_rx_buf()
- !1767  bonding: Fix incorrect deletion of ETH_P_8021AD protocol vid from slaves
- workqueue: Assign a color to barrier work items
- workqueue: Mark barrier work with WORK_STRUCT_INACTIVE
- workqueue: Change the code of calculating work_flags in insert_wq_barrier()
- workqueue: Change arguement of pwq_dec_nr_in_flight()
- workqueue: Rename "delayed" (delayed by active management) to "inactive"
- bonding: Fix incorrect deletion of ETH_P_8021AD protocol vid from slaves

* Tue Aug 15 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2308.3.0.0214
- !1762  xen/netback: Fix buffer overrun triggered by unusual packet
- xen/netback: Fix buffer overrun triggered by unusual packet
- !1761 fix CVE-2023-4194
- net: tap_open(): set sk_uid from current_fsuid()
- net: tun_chr_open(): set sk_uid from current_fsuid()
- !1728  fix CVE-2023-4128
- !1673  sched: disable sched_autogroup by default
- net/sched: cls_fw: No longer copy tcf_result on update to avoid use-after-free
- net/sched: cls_route: No longer copy tcf_result on update to avoid use-after-free
- net/sched: cls_u32: No longer copy tcf_result on update to avoid use-after-free
- !1712  xfrm: add NULL check in xfrm_update_ae_params
- xfrm: add NULL check in xfrm_update_ae_params
- sched: disable sched_autogroup by default

* Tue Aug 08 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2308.2.0.0213
- !1699 dm bugfixes backport from mainline
- !1697  x86/cpu/amd: Add a Zenbleed fix
- md: Flush workqueue md_rdev_misc_wq in md_alloc()
- dm: don't lock fs when the map is NULL during suspend or resume
- dm: don't lock fs when the map is NULL in process of resume
- dm: requeue IO if mapping table not yet available
- Revert "dm: make sure dm_table is binded before queue request"
- dm thin metadata: check fail_io before using data_sm
- !1662  media: usb: siano: Fix CVE-2023-4132
- !1696  Revert "arm64/mpam: Fix mpam corrupt when cpu online"
- x86/cpu/amd: Add a Zenbleed fix
- !1694 linux-4.19.y bugfixes backport
- Revert "arm64/mpam: Fix mpam corrupt when cpu online"
- x86/apic: Fix kernel panic when booting with intremap=off and x2apic_phys
- sch_netem: fix issues in netem_change() vs get_dist_table()
- sch_netem: acquire qdisc lock in netem_change()
- cgroup: Do not corrupt task iteration when rebinding subsystem
- !1577  tracing: Fix warning in trace_buffered_event_disable()
- !1663  tty: fix pid memleak in disassociate_ctty()
- tty: fix pid memleak in disassociate_ctty()
- media: usb: siano: Fix warning due to null work_func_t function pointer
- media: usb: siano: Fix use after free bugs caused by do_submit_urb
- !1629  can: raw: fix receiver memory leak
- !1655  can: bcm: Fix UAF in bcm_proc_show()
- can: bcm: Fix UAF in bcm_proc_show()
- can: raw: fix lockdep issue in raw_release()
- can: raw: fix receiver memory leak
- !1625  Fix host zero page refcount overflow caused by kvm
- !1595  net: nfc: Fix CVE-2023-3863
- KVM: Don't set Accessed/Dirty bits for ZERO_PAGE
- KVM: fix overflow of zero page refcount with ksm running
- net: nfc: Fix use-after-free caused by nfc_llcp_find_local
- nfc: llcp: simplify llcp_sock_connect() error paths
- nfc: llcp: nullify llcp_sock->dev on connect() error paths
- nfc: Fix to check for kmemdup failure
- tracing: Fix warning in trace_buffered_event_disable()

* Tue Aug 01 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2308.1.0.0212
- !1571 【openEuler-1.0-LTS】net: hns: fix wrong head when modify the tx feature when sending packets
- !1570 【openEuler-1.0-LTS】net: hns3: bugfixes for hns3 drivers 2023.07.29
- net: hns: update hns version to 23.7.1
- net: hns: fix wrong head when modify the tx feature when sending packets
- net: hns3: update hns3 version to 23.7.1
- net: hns3: fix tx timeout issue
- net: hns3: fix incorrect hw rss hash type of rx packet
- net: hns3: add barrier in vf mailbox reply process
- net: hns3: fix use-after-free bug in hclgevf_send_mbx_msg
- net: hns3: fix not call nic_call_event() problem when reset failed
- !1556  net/sched: cls_fw: Fix improper refcount update leads to use-after-free
- !1568  net/sched: cls_u32: Fix reference counter leak leading to overflow
- net/sched: cls_u32: Fix reference counter leak leading to overflow
- net/sched: cls_fw: Fix improper refcount update leads to use-after-free
- !1549  binder: fix UAF caused by faulty buffer cleanup
- binder: fix UAF caused by faulty buffer cleanup

* Tue Jul 25 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2307.5.0.0211
- !1534 arm64/mpam: fix missing kfree domain's ctrl_val arrray
- arm64/mpam: fix missing kfree domain's ctrl_val arrray
- !1529  net/sched: sch_qfq: account for stab overhead in qfq_enqueue
- net/sched: sch_qfq: account for stab overhead in qfq_enqueue
- !1474 [openEuler-1.0-LTS] pmu: remove uncore code for Zhaoxin Platform
- !1498  media: dvb-core: Fix use-after-free due on race condition at dvb_net
- media: dvb-core: Fix use-after-free due on race condition at dvb_net
- !1444 ring-buffer: Fix deadloop issue on reading trace_pipe
- !1469  netfilter: nf_tables: prevent OOB access in nft_byteorder_eval
- !1472  ipv6/addrconf: fix a potential refcount underflow for idev
- pmu: remove uncore code for Zhaoxin Platform
- ipv6/addrconf: fix a potential refcount underflow for idev
- netfilter: nf_tables: prevent OOB access in nft_byteorder_eval
- ftrace: Fix possible warning on checking all pages used in ftrace_process_locs()
- ring-buffer: Fix deadloop issue on reading trace_pipe

* Tue Jul 18 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2307.4.0.0210
- !1435 fix CVE-2023-3117
- netfilter: nf_tables: unbind non-anonymous set if rule construction fails
- netfilter: nf_tables: add NFT_TRANS_PREPARE_ERROR to deal with bound set/chain
- netfilter: nf_tables: incorrect error path handling with NFT_MSG_NEWRULE
- !1400 [openEuler-1.0-LTS] block: Try to handle busy underlying device on discard
- !1416  Fix generic/299 fail
- ext4: Add debug message to notify user space is out of free
- Revert "ext4: Stop trying writing pages if no free blocks generated"
- !1404  bpf: cpumap: Fix memory leak in cpu_map_update_elem
- bpf: cpumap: Fix memory leak in cpu_map_update_elem
- block: Try to handle busy underlying device on discard
- !1377 [sync] PR-1376:  jbd2: Check 'jh->b_transaction' before remove it from checkpoint
- !1374  etmem: fix the div 0 problem in swapcache reclaim process
- !177 net:bonding:support balance-alb interface with vlan to bridge
- jbd2: Check 'jh->b_transaction' before remove it from checkpoint
- etmem: fix the div 0 problem in swapcache reclaim process
- bonding: fix reference count leak in balance-alb mode
- net:bonding:support balance-alb interface with vlan to bridge

* Wed Jul 12 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2307.3.0.0209
- !1361 fix CVE-2023-1295
- io_uring: get rid of intermediate IORING_OP_CLOSE stage
- fs: provide locked helper variant of close_fd_get_file()
- file: Rename __close_fd_get_file close_fd_get_file
- Remove DECnet support from kernel
- net/netlink: fix NETLINK_LIST_MEMBERSHIPS length report
- net: tcp: fix kabi breakage in struct sock
- tcp: deny tcp_disconnect() when threads are waiting
- ping6: Fix send to link-local addresses with VRF.
- net: sched: fix possible refcount leak in tc_chain_tmplt_add()
- rfs: annotate lockless accesses to RFS sock flow table
- rfs: annotate lockless accesses to sk->sk_rxhash
- xfrm: Check if_id in inbound policy/secpath match
- udp6: Fix race condition in udp6_sendmsg & connect
- tcp: Return user_mss for TCP_MAXSEG in CLOSE/LISTEN state if user_mss set
- af_packet: do not use READ_ONCE() in packet_bind()
- af_packet: Fix data-races of pkt_sk(sk)->num.
- ipv{4,6}/raw: fix output xfrm lookup wrt protocol
- ipv6: Fix out-of-bounds access in ipv6_find_tlv()
- net: fix skb leak in __skb_tstamp_tx()
- udplite: Fix NULL pointer dereference in __sk_mem_raise_allocated().
- vlan: fix a potential uninit-value in vlan_dev_hard_start_xmit()
- af_key: Reject optional tunnel/BEET mode templates in outbound policies
- net: Catch invalid index in XPS mapping
- af_unix: Fix data races around sk->sk_shutdown.
- af_unix: Fix a data race of sk->sk_receive_queue->qlen.
- net: datagram: fix data-races in datagram_poll()
- tcp: factor out __tcp_close() helper
- net: annotate sk->sk_err write from do_recvmmsg()
- netlink: annotate accesses to nlk->cb_running
- quota: simplify drop_dquot_ref()
- quota: fix dqput() to follow the guarantees dquot_srcu should provide
- quota: add new helper dquot_active()
- quota: rename dquot_active() to inode_quota_active()
- quota: factor out dquot_write_dquot()
- quota: add dqi_dirty_list description to comment of Dquot List Management
- quota: avoid increasing DQST_LOOKUPS when iterating over dirty/inuse list
- kernel/extable.c: use address-of operator on section symbols
- arm64/mm: mark private VM_FAULT_X defines as vm_fault_t
- x86/mm: Avoid incomplete Global INVLPG flushes
- sched: Fix KCSAN noinstr violation
- serial: 8250: Reinit port->pm on port specific driver unbind
- ACPICA: ACPICA: check null return of ACPI_ALLOCATE_ZEROED in acpi_db_display_objects
- ACPI: EC: Fix oops when removing custom query handlers
- lib: cpu_rmap: Fix potential use-after-free in irq_cpu_rmap_release()
- lib: cpu_rmap: Avoid use after free on rmap->obj array entries
- ext4: improve error recovery code paths in __ext4_remount()
- scsi: core: Improve scsi_vpd_inquiry() checks
- PCI: pciehp: Fix AB-BA deadlock between reset_lock and device_lock
- loop: loop_set_status_from_info() check before assignment
- loop: Check for overflow while configuring loop
- Revert "loop: Check for overflow while configuring loop"
- block: don't set GD_NEED_PART_SCAN if scan partition failed
- block: return -EBUSY when there are open partitions in blkdev_reread_part
- blk-wbt: make enable_state more accurate
- block: Limit number of items taken from the I/O scheduler in one go
- crypto: cryptd - Protect per-CPU resource by disabling BH.
- random: fix data race on crng_node_pool
- x86/kprobes: Fix the error judgment for debug exceptions
- ext4: turning quotas off if mount failed after enable quotas
- ext4: forbid commit inconsistent quota data when errors=remount-ro
- quota: fixup *_write_file_info() to return proper error code
- ipmi_si: fix a memleak in try_smi_init()
- net: add vlan_get_protocol_and_depth() helper
- net: tap: check vlan with eth_type_vlan() method
- !1317  ext4: Stop trying writing pages if no free blocks generated
- !1323  jbd2: fix several checkpoint
- jbd2: fix checkpoint cleanup performance regression
- jbd2: remove __journal_try_to_free_buffer()
- jbd2: fix a race when checking checkpoint buffer busy
- jbd2: Fix wrongly judgement for buffer head removing while doing checkpoint
- jbd2: remove journal_clean_one_cp_list()
- nbd: fix null-ptr-dereference while accessing 'nbd->config'
- nbd: factor out a helper to get nbd_config without holding 'config_lock'
- nbd: fold nbd config initialization into nbd_alloc_config()
- ext4: Stop trying writing pages if no free blocks generated
- ipvlan:Fix out-of-bounds caused by unclear skb->cb

* Fri Jun 30 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2306.7.0.0208
- sched: Fix null pointer derefrence for sd->span
- scsi: hisi_sas: Fix Null point exception after call debugfs_remove_recursive()
- scsi: hisi_sas: Fix normally completed I/O analysed as failed
- drm/msm/dpu: Add check for pstates
- usb: gadget: udc: renesas_usb3: Fix use after free bug in renesas_usb3_remove due to race condition

* Tue Jun 27 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2306.5.0.0207
- HID: intel_ish-hid: Add check for ishtp_dma_tx_map
- media: saa7134: fix use after free bug in saa7134_finidev due to race condition
- config: enable CONFIG_QOS_SCHED_SMART_GRID by default
- mm: oom: move memcg_print_bad_task() out of mem_cgroup_scan_tasks()
- media: dm1105: Fix use after free bug in dm1105_remove due to race condition
- sched: Fix memory leak for smart grid
- sched: Delete redundant updates to p->prefer_cpus
- nbd: fix incomplete validation of ioctl arg
- nbd: validate the block size in nbd_set_size
- relayfs: fix out-of-bounds access in relay_file_read
- kernel/relay.c: fix read_pos error when multiple readers
- net/sched: flower: fix possible OOB write in fl_set_geneve_opt()

* Tue Jun 20 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2306.4.0.0206
- sched: Adjust few parameters range for smart grid
- sched: clear credit count in error branch
- sched: Fix memory leak on error branch
- sched: fix dereference NULL pointers
- sched: Fix timer storm for smart grid
- memstick: r592: Fix UAF bug in r592_remove due to race condition
- fbcon: Check font dimension limits
- sched/rt: Fix possible warn when push_rt_task
- !1152 pci: workaround multiple functions can be assigned to only one VM
- pci: workaround multiple functions can be assigned to only one VM
- sched: Fix negative count for jump label
- sched: Fix possible deadlock in tg_set_dynamic_affinity_mode
- sched: fix WARN found by deadlock detect
- sched: fix smart grid usage count
- sched: Add static key to reduce noise
- net: nsh: Use correct mac_offset to unwind gso skb in nsh_gso_segment()
- !1134 【openEuler-1.0-LTS】cpufreq:conservative: Fix load in fast_dbs_update()
- firewire: fix potential uaf in outbound_phy_packet_callback()
- cpufreq: conservative: fix load in fast_dbs_update()

* Tue Jun 13 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2306.3.0.0205
- arm64: Add AMPERE1 to the Spectre-BHB affected list
- sctp: Call inet6_destroy_sock() via sk->sk_destruct().
- net: Remove WARN_ON_ONCE(sk->sk_forward_alloc) from sk_stream_kill_queues().
- dccp/tcp: Avoid negative sk_forward_alloc by ipv6_pinfo.pktoptions.
- media: dvb-core: Fix kernel WARNING for blocking operation in wait_event*()
- sched: smart grid: init sched_grid_qos structure on QOS purpose
- sched: Introduce smart grid scheduling strategy for cfs
- ipmi: fix SSIF not responding under certain cond.
- ipmi_ssif: Rename idle state and check
- mm/page_alloc: fix potential deadlock on zonelist_update_seq seqlock
- printk: declare printk_deferred_{enter,safe}() in include/linux/printk.h
- serial: 8250: Fix serial8250_tx_empty() race with DMA Tx
- tty: Prevent writing chars during tcsetattr TCSADRAIN/FLUSH
- af_packet: Don't send zero-byte data in packet_sendmsg_spkt().
- nohz: Add TICK_DEP_BIT_RCU
- perf/core: Fix hardlockup failure caused by perf throttle
- of: Fix modalias string generation
- tcp/udp: Fix memleaks of sk and zerocopy skbs with TX timestamp.
- ipv4: Fix potential uninit variable access bug in __ip_make_skb()
- crypto: drbg - Only fail when jent is unavailable in FIPS mode
- crypto: drbg - make drbg_prepare_hrng() handle jent instantiation errors
- net/packet: convert po->auxdata to an atomic flag
- net/packet: convert po->origdev to an atomic flag
- ring-buffer: Sync IRQ works before buffer destruction
- dccp: Call inet6_destroy_sock() via sk->sk_destruct().
- inet6: Remove inet6_destroy_sock() in sk->sk_prot->destroy().
- tcp/udp: Call inet6_destroy_sock() in IPv6 sk->sk_destruct().
- udp: Call inet6_destroy_sock() in setsockopt(IPV6_ADDRFORM).
- lib/cmdline: fix get_option() for strings starting with hyphen
- of: overlay: fix for_each_child.cocci warnings
- kprobes: Fix to handle forcibly unoptimized kprobes on freeing_list
- fs: hfsplus: fix UAF issue in hfsplus_put_super
- block: Fix the partition start may overflow in add_partition()
- block: refactor blkpg_ioctl
- nbd: get config_lock before sock_shutdown
- ipv6: sr: fix out-of-bounds read when setting HMAC data.
- dm: add disk before alloc dax
- dm thin: Fix ABBA deadlock by resetting dm_bufio_client

* Tue Jun 06 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2306.1.0.0204
- !932 [sync] PR-922:  jbd2: fix checkpoint inconsistent
- jbd2: remove t_checkpoint_io_list
- jbd2: recheck chechpointing non-dirty buffer
- irqchip/gic-v3-its: Balance initial LPI affinity across CPUs
- irqchip/gic-v3-its: Track LPI distribution on a per CPU basis
- power: supply: bq24190: Fix use after free bug in bq24190_remove due to race condition
- net: sched: fix NULL pointer dereference in mq_attach

* Wed May 31 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2305.4.0.0203
- !841 【openEuler-1.0-LTS】cpufreq: conservative: Add a switch to enable fast mode
- x86/pm: Fix false positive kmemleak report in msr_build_context()
- drm: Lock pointer access in drm_master_release()
- drm: Fix use-after-free read in drm_getunique()
- cpufreq: conservative: Add a switch to enable fast mode
- of: overlay: kmemleak in dup_and_fixup_symbol_prop()
- iommu/dma: Fix MSI reservation allocation
- lib/stackdepot.c: fix global out-of-bounds in stack_slabs
- rcu: Use *_ONCE() to protect lockless ->expmask accesses
- iommu: Don't print warning when IOMMU driver only supports unmanaged domains
- ext4: avoid a potential slab-out-of-bounds in ext4_group_desc_csum

* Wed May 24 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2305.3.0.0202
- netfilter: nf_tables: deactivate anonymous set from preparation phase
- x86/msr-index: make SPEC_CTRL_IBRS assembler-portable
- xfs: verify buffer contents when we skip log replay
- !586 [openEuelr-1.0-LTS] kvm: arm64: fix some pvsched bugs
- kvm: arm64: fix some pvsched bugs

* Sat May 13 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2305.2.0.0201
- net: sctp: update stream->incnt after successful allocation of stream_in
- !741 [openEuler-1.0-LTS] openeuler_defconfig: Add configuration items for zhaoxin
- !752 arm64/mpam: modify mpam irq register error log
- arm64/mpam: modify mpam irq register error log
- !437 [openEuler-1.0-LTS] USB: HCD: Fix URB giveback issue in tasklet function
- openeuler_defconfig: Add configuration items for zhaoxin
- bluetooth: Perform careful capability checks in hci_sock_ioctl()
- netrom: Fix use-after-free caused by accept on already connected socket
- !689 Fix compile error in allyesconfigs
- !441 [openEuler-1.0-LTS] Add support for Zhaoxin SM3 and SM4 instruction
- !438 [openEuler-1.0-LTS] Add Zhaoxin I2C driver
- i2c: Add Zhaoxin I2C driver
- !432 [openEuler-1.0-LTS] Add Zhaoxin ACE driver
- mm: memcontrol: switch to rcu protection in drain_all_stock()
- !429 [openEuler-1.0.-LTS] ACPI, x86: Improve Zhaoxin processors support for NONSTOP TSC
- !428 [openEuelr-1.0-LTS] x86/acpi/cstate: Optimize ARB_DISABLE on Centaur CPUs
- !687 [HUST CSE] fix a use-after-free bug in uncore_pci_remove()
- scsi/hifc: Fix compile error in allyesconfigs
- net/hinic: Fix compile error in allyesconfigs
- x86/perf: fix use-after-free bug in uncore_pci_remove()
- crypto: Driver for Zhaoxin GMI SM4 Block Cipher Algorithm
- crypto: Driver for Zhaoxin GMI SM3 Secure Hash algorithm
- !433 [openEuler-1.0-LTS] Add support of turbo boost control interface for Zhaoxin CPUs
- !431 [openEuler-1.0-LTS] Add Zhaoxin rng driver
- crypto: Add Zhaoxin ACE driver
- cpufreq: ACPI: Add Zhaoxin/Centaur turbo boost control interface support
- hwrng: Add Zhaoxin rng driver
- USB: HCD: Fix URB giveback issue in tasklet function
- ACPI, x86: Improve Zhaoxin processors support for NONSTOP TSC
- x86/acpi/cstate: Optimize ARB_DISABLE on Centaur CPUs

* Tue May 09 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2305.1.0.0200
- ipv6: Fix an uninit variable access bug in __ip6_make_skb()
- cgroup/cpuset: Wake up cpuset_attach_wq tasks in cpuset_cancel_attach()
- verify_pefile: relax wrapper length check
- udp6: fix potential access to stale information
- mm/swap: fix swap_info_struct race between swapoff and get_swap_pages()
- ftrace: Mark get_lock_parent_ip() __always_inline
- perf/core: Fix the same task check in perf_event_set_output
- net: don't let netpoll invoke NAPI if in xmit context
- icmp: guard against too small mtu
- sched_getaffinity: don't assume 'cpumask_size()' is fully initialized
- dm stats: check for and propagate alloc_percpu failure
- dm thin: fix deadlock when swapping to thin device
- genirq: introduce handle_fasteoi_edge_irq for phytium
- genirq: introduce handle_fasteoi_edge_irq flow handler
- Revert "genirq: Remove irqd_irq_disabled in __irq_move_irq"
- Revert "config: enbale irq pending config for openeuler"
- Revert "genirq: introduce CONFIG_GENERIC_PENDING_IRQ_FIX_KABI"
- Revert "irqchip/gic-v3-its: introduce CONFIG_GENERIC_PENDING_IRQ"
- scsi: dpt_i2o: Remove obsolete driver
- md: extend disks_mutex coverage
- md: use msleep() in md_notify_reboot()
- md: fix double free of mddev->private in autorun_array()
- block/badblocks: fix badblocks loss when badblocks combine
- block/badblocks: fix the bug of reverse order
- block: Only set bb->changed when badblocks changes
- md: fix sysfs duplicate file while adding rdev
- md: replace invalid function flush_rdev_wq() with flush_workqueue()
- bonding: Fix memory leak when changing bond type to Ethernet
- dm ioctl: fix nested locking in table_clear() to remove deadlock concern
- timers/nohz: Last resort update jiffies on nohz_full IRQ entry
- bonding: restore bond's IFF_SLAVE flag if a non-eth dev enslave fails
- bonding: restore IFF_MASTER/SLAVE flags on bond enslave ether type change
- net: qcom/emac: Fix use after free bug in emac_remove due to race condition
- ovl: get_acl: Fix null pointer dereference at realinode in rcu-walk mode
- net: sched: sch_qfq: prevent slab-out-of-bounds in qfq_activate_agg
- ext4: only update i_reserved_data_blocks on successful block allocation
- mm: mem_reliable: Use zone_page_state to count free reliable pages
- writeback, cgroup: fix null-ptr-deref write in bdi_split_work_to_wbs
- sctp: leave the err path free in sctp_stream_init to sctp_stream_free
- RDMA/core: Refactor rdma_bind_addr
- Revert "RDMA/cma: Simplify rdma_resolve_addr() error flow"
- fix kabi broken due to import new inode operation get_inode_acl
- ovl: enable RCU'd ->get_acl()
- vfs: add rcu argument to ->get_acl() callback

* Wed Apr 26 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2304.5.0.0199
- RDMA/hns: Add check for user-configured max_inline_data value
- power: supply: da9150: Fix use after free bug in da9150_charger_remove due to race condition
- !430 [openEuler-1.0-LTS] ata: sata_zhaoxin: Update Zhaoxin Serial ATA product name
- i2c: xgene-slimpro: Fix out-of-bounds bug in xgene_slimpro_i2c_xfer()
- audit: fix a memleak caused by auditing load module
- !595 [openEuler-1.0-LTS] iommu/arm-smmu-v3: Fix UAF when handle evt during iommu group removing
- tcp: restrict net.ipv4.tcp_app_win
- x86/speculation: Allow enabling STIBP with legacy IBRS
- iommu/arm-smmu-v3: Fix UAF when handle evt during iommu group removing
- ata: sata_zhaoxin: Update Zhaoxin Serial ATA product name

* Wed Apr 19 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2304.4.0.0198
- KVM: nVMX: add missing consistency checks for CR0 and CR4
- drm/vmwgfx: Validate the box size for the snooped cursor
- net/sched: Retire tcindex classifier
- Documentation/hw-vuln: Fix rST warning
- Documentation/hw-vuln: Add documentation for Cross-Thread Return Predictions
- KVM: x86: Mitigate the cross-thread return address predictions bug
- x86/speculation: Identify processors vulnerable to SMT RSB predictions
- cpu/SMT: create and export cpu_smt_possible()
- nfc: st-nci: Fix use after free bug in ndlc_remove due to race condition
- Bluetooth: btsdio: fix use after free bug in btsdio_remove due to race condition

* Tue Apr 11 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2304.3.0.0197
- hwmon: (xgene) Fix use after free bug in xgene_hwmon_remove due to race condition
- xirc2ps_cs: Fix use after free bug in xirc2ps_detach
- 9p/xen : Fix use after free bug in xen_9pfs_front_remove due to race condition
- !566 linux-4.19.y bugfixes backport
- bpf: add missing header file include
- uaccess: Add speculation barrier to copy_from_user()
- random: always mix cycle counter in add_latent_entropy()
- x86/mm: Fix use of uninitialized buffer in sme_enable()
- ext4: fail ext4_iget if special inode unallocated
- ext4: zero i_disksize when initializing the bootloader inode
- irqdomain: Drop bogus fwspec-mapping error handling
- irqdomain: Fix disassociation race
- irqdomain: Fix association race
- x86/kprobes: Fix arch_check_optimized_kprobe check within optimized_kprobe range
- x86/kprobes: Fix __recover_optprobed_insn check optimizing logic
- x86/bugs: Reset speculation control settings on init
- timers: Prevent union confusion from unexpected restart_syscall()
- crypto: rsa-pkcs1pad - Use akcipher_request_complete
- crypto: seqiv - Handle EBUSY correctly
- ACPI: battery: Fix missing NUL-termination with large strings
- ACPICA: nsrepair: handle cases without a return value correctly
- genirq: Fix the return type of kstat_cpu_irqs_sum()
- ACPI: NFIT: fix a potential deadlock during NFIT teardown
- alarmtimer: Prevent starvation by small intervals and SIG_IGN
- ring-buffer: Fix race while reader and writer are on the same page
- cgroup: Add missing cpus_read_lock() to cgroup_attach_task_all()
- cgroup: Fix threadgroup_rwsem <-> cpus_read_lock() deadlock
- cgroup/cpuset: Change cpuset_rwsem and hotplug lock order
- Revert "cgroup/cpuset: Change cpuset_rwsem and hotplug lock order"
- Revert "cgroup: Fix threadgroup_rwsem <-> cpus_read_lock() deadlock"
- Revert "cgroup: Add missing cpus_read_lock() to cgroup_attach_task_all()"
- block: fix wrong mode for blkdev_put() from disk_scan_partitions()
- block: fix scan partition for exclusively open device again
- block: fix kabi broken in ioctl.c
- block: merge disk_scan_partitions and blkdev_reread_part
- block: cleanup partition scanning in register_disk
- block: Revert "block: check 'bd_super' before rescanning partition"
- md: fix kabi broken in struct mddev
- md: use interruptible apis in idle/frozen_sync_thread
- md: wake up 'resync_wait' at last in md_reap_sync_thread()
- md: refactor idle/frozen_sync_thread()
- md: add a mutex to synchronize idle and frozen in action_store()
- md: refactor action_store() for 'idle' and 'frozen'
- mm: mem_reliable: Initialize reliable_nr_page when mm_init()
- md: fix soft lockup in status_resync
- md: don't update recovery_cp when curr_resync is ACTIVE
- md: Ensure resync is reported after it starts
- md: Use enum for overloaded magic numbers used by mddev->curr_resync
- loop: Add parm check in loop_control_ioctl
- block/wbt: enable wbt after switching cfq to other schedulers
- Fix double fget() in vhost_net_set_backend()
- sched/fair: Sanitize vruntime of entity being migrated
- sched/fair: sanitize vruntime of entity being placed
- Revert "sched: Reinit task's vruntime if a task sleep over 200 days"
- btrfs: fix race between quota disable and quota assign ioctls

* Tue Apr 04 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2304.1.0.0196
- ext4: Fix i_disksize exceeding i_size problem in paritally written case
- ext4: ext4_put_super: Remove redundant checking for 'sbi->s_journal_bdev'
- ext4: Fix reusing stale buffer heads from last failed mounting
- kvm: initialize all of the kvm_debugregs structure before sending it to userspace
- net: virtio_net_hdr_to_skb: count transport header in UFO
- net: be more gentle about silly gso requests coming from user
- ext4: fix race between writepages and remount

* Fri Mar 31 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2303.6.0.0195
- ALSA: pcm: Move rwsem lock inside snd_ctl_elem_read to prevent UAF
- ftrace: Fix invalid address access in lookup_rec() when index is 0
- ftrace: Fix NULL pointer dereference in is_ftrace_trampoline when ftrace is dead
- scsi: scsi_dh_alua: fix memleak for 'qdata' in alua_activate()
- RDMA/core: Don't infoleak GRH fields
- !480 mm  bugfixes backport
- cgroup: Add missing cpus_read_lock() to cgroup_attach_task_all()
- cgroup: Fix threadgroup_rwsem <-> cpus_read_lock() deadlock
- cgroup/cpuset: Change cpuset_rwsem and hotplug lock order
- mm: memcontrol: fix cannot alloc the maximum memcg ID

* Wed Mar 29 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2303.5.0.0194
- net/sched: tcindex: search key must be 16 bits
- net/sched: tcindex: update imperfect hash filters respecting rcu
- rcu: Upgrade rcu_swap_protected() to rcu_replace_pointer()
- x86/speculation: Add RSB VM Exit protections
- x86/bugs: Warn when "ibrs" mitigation is selected on Enhanced IBRS parts
- x86/speculation: Use DECLARE_PER_CPU for x86_spec_ctrl_current
- x86/speculation: Disable RRSBA behavior
- x86/bugs: Add Cannon lake to RETBleed affected CPU list
- x86/cpu/amd: Enumerate BTC_NO
- x86/common: Stamp out the stepping madness
- x86/speculation: Fill RSB on vmexit for IBRS
- KVM: VMX: Fix IBRS handling after vmexit
- KVM: VMX: Prevent guest RSB poisoning attacks with eIBRS
- x86/speculation: Remove x86_spec_ctrl_mask
- x86/speculation: Use cached host SPEC_CTRL value for guest entry/exit
- x86/speculation: Fix SPEC_CTRL write on SMT state change
- x86/speculation: Fix firmware entry SPEC_CTRL handling
- x86/speculation: Fix RSB filling with CONFIG_RETPOLINE=n
- x86/speculation: Change FILL_RETURN_BUFFER to work with objtool
- intel_idle: Disable IBRS during long idle
- x86/bugs: Report Intel retbleed vulnerability
- x86/bugs: Split spectre_v2_select_mitigation() and spectre_v2_user_select_mitigation()
- x86/speculation: Add spectre_v2=ibrs option to support Kernel IBRS
- x86/bugs: Optimize SPEC_CTRL MSR writes
- x86/entry: Add kernel IBRS implementation
- x86/entry: Remove skip_r11rcx
- x86/bugs: Keep a per-CPU IA32_SPEC_CTRL value
- x86/bugs: Add AMD retbleed= boot parameter
- x86/bugs: Report AMD retbleed vulnerability
- x86/cpufeatures: Move RETPOLINE flags to word 11
- x86/cpu: Add a steppings field to struct x86_cpu_id
- x86/cpu: Add consistent CPU match macros
- x86/devicetable: Move x86 specific macro out of generic code
- x86/cpufeature: Fix various quality problems in the <asm/cpu_device_hd.h> header
- x86/cpufeature: Add facility to check for min microcode revisions
- Revert "x86/cpu: Add a steppings field to struct x86_cpu_id"
- Revert "x86/speculation: Add RSB VM Exit protections"
- x86/nospec: Fix i386 RSB stuffing
- ext4: make sure fs error flag setted before clear journal error
- ext4: commit super block if fs record error when journal record without error
- hugetlb: fix hugepages_setup when deal with pernode
- hugetlb: fix wrong use of nr_online_nodes
- tty: fix out-of-bounds access in tty_driver_lookup_tty()
- arm64: errata: Remove AES hwcap for COMPAT tasks
- kernel: Initialize cpumask before parsing
- genirq: Disable interrupts for force threaded handlers
- softirq: Don't try waking ksoftirqd before it has been spawned
- scsi: hisi_sas: Clear interrupt status when exiting channel int0 for v3 hw
- scsi: hisi_sas: Handle NCQ error when IPTT is valid
- scsi: hisi_sas: Grab sas_dev lock when traversing the members of sas_dev.list
- act_mirred: use the backlog for nested calls to mirred ingress
- net/sched: act_mirred: refactor the handle of xmit
- net: sched: don't expose action qstats to skb_tc_reinsert()
- net: sched: protect against stack overflow in TC act_mirred
- net: sched: refactor reinsert action
- net: tls: fix possible race condition between do_tls_getsockopt_conf() and do_tls_setsockopt_conf()
- wifi: brcmfmac: slab-out-of-bounds read in brcmf_get_assoc_ies()
- ext4: fix another off-by-one fsmap error on 1k block filesystems

* Tue Mar 21 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2303.4.0.0193
- tipc: add an extra conn_get in tipc_conn_alloc
- tipc: set con sock in tipc_conn_alloc
- mm/oom_kill.c: fix oom_cpuset_eligible() comment
- oom: decouple mems_allowed from oom_unkillable_task
- mm, oom: remove redundant task_in_mem_cgroup() check
- mm, oom: refactor dump_tasks for memcg OOMs
- block: Fix wrong offset in bio_truncate()
- fs: move guard_bio_eod() after bio_set_op_attrs
- block: add bio_truncate to fix guard_bio_eod
- mm/mempolicy.c: fix out of bounds write in mpol_parse_str()
- cifs: Fix use-after-free in rdata->read_into_pages()
- media: dvb-usb: az6027: fix null-ptr-deref in az6027_i2c_xfer()

* Tue Mar 14 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2303.3.0.0192
- scsi: cancel the inflight async device probe when remove scsi_target
- scsi: fix use-after-free problem in scsi_remove_target
- HID: asus: use spinlock to safely schedule workers
- HID: asus: use spinlock to protect concurrent accesses
- HID: asus: Remove check for same LED brightness on set
- blk-wbt: don't enable throttling if default elevator is bfq
- block: Fix kabi broken by "block: split .sysfs_lock into two locks"
- block: fix comment and add lockdep assert
- block: don't release queue's sysfs lock during switching elevator
- block: fix race between switching elevator and removing queues
- block: split .sysfs_lock into two locks
- crypto: rsa-pkcs1pad - restore signature length check
- fs/proc: task_mmu.c: don't read mapcount for migration entry
- migrate: hugetlb: check for hugetlb shared PMD in node migration
- mm: hugetlb: proc: check for hugetlb shared PMD in /proc/PID/smaps
- ipv6: Fix tcp socket connection with DSCP.
- ipv6: Fix datagram socket connection with DSCP.
- aio: fix mremap after fork null-deref
- bpf: Always return target ifindex in bpf_fib_lookup
- serial: 8250_dma: Fix DMA Rx rearm race
- serial: 8250_dma: Fix DMA Rx completion race
- x86/i8259: Mark legacy PIC interrupts with IRQ_LEVEL
- ipv4: prevent potential spectre v1 gadget in ip_metrics_convert()
- netlink: annotate data races around sk_state
- netlink: annotate data races around dst_portid and dst_group
- netlink: annotate data races around nlk->portid
- netlink: remove hash::nelems check in netlink_insert
- net: fix UaF in netns ops registration error path
- netfilter: conntrack: do not renew entry stuck in tcp SYN_SENT state
- binder: Gracefully handle BINDER_TYPE_FDA objects with num_fds=0
- binder: Address corner cases in deferred copy and fixup
- binder: fix pointer cast warning
- binder: defer copies of pre-patched txn data
- binder: read pre-translated fds from sender buffer
- binder: avoid potential data leakage when copying txn
- binder: fix handling of error during copy
- binder: use cred instead of task for getsecid
- binder: don't detect sender/target during buffer cleanup
- binder: make sure fd closes complete
- binder: Remove bogus warning on failed same-process transaction
- binder: fix incorrect calculation for num_valid
- binder: Prevent repeated use of ->mmap() via NULL mapping
- binder: Don't modify VMA bounds in ->mmap handler
- binder: Set end of SG buffer area properly.
- binder: return errors from buffer copy functions
- binder: check for overflow when alloc for security context
- binder: fix BUG_ON found by selinux-testsuite
- binder: fix handling of misaligned binder object
- binder: use userspace pointer as base of buffer space
- binder: remove user_buffer_offset
- binder: remove kernel vm_area for buffer space
- binder: avoid kernel vm_area for buffer fixups
- binder: add function to copy binder object from buffer
- binder: add functions to copy to/from binder buffers
- binder: create userspace-to-binder-buffer copy function
- binder: fix use-after-free due to ksys_close() during fdget()
- binder: fix kerneldoc header for struct binder_buffer
- binder: create node flag to request sender's security context
- binder: Add BINDER_GET_NODE_INFO_FOR_REF ioctl.
- binder: use standard functions to allocate fds
- block: fix kabi change since add bd_write_openers and bd_part_write_openers
- block: add info when opening an exclusive opened block device for write
- block: add info when opening a write opend block device exclusively
- Revert "block: add info when opening an exclusive opened block device for write"
- Revert "block: add info when opening a write opend block device exclusively"
- ext4: fix WARNING in mb_find_extent
- sctp: fail if no bound addresses can be used for a given scope

* Wed Mar 08 2023 Zhang Changzhong <zhangchangzhong@huawei.com> - 4.19.90-2303.1.0.0191
- HID: check empty report_list in hid_validate_values()
- dhugetlb: use mutex lock in update_reserve_pages()
- ntfs: fix out-of-bounds read in ntfs_attr_find()
- ntfs: fix use-after-free in ntfs_ucsncmp()
- media: rc: Fix use-after-free bugs caused by ene_tx_irqsim()
- phy: tegra: xusb: Fix return value of tegra_xusb_find_port_node function
- netfilter: nf_tables: fix null deref due to zeroed list head
- tcp: Fix listen() regression in 5.15.88.
- tap: tap_open(): correctly initialize socket uid
- tun: tun_chr_open(): correctly initialize socket uid
- net: add sock_init_data_uid()
- rds: rds_rm_zerocopy_callback() use list_first_entry()

* Tue Feb 28 2023 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2302.5.0.0190
- !423 genirq bugfix for arm64
- genirq: Remove irqd_irq_disabled in __irq_move_irq
- !422 iscsi bugfixes backport
- scsi: iscsi_tcp: Fix UAF during login when accessing the shost ipaddress
- scsi: iscsi_tcp: Fix UAF during logout when accessing the shost ipaddress
- !420 backport CVEs and bugfixes
- net: mpls: fix stale pointer if allocation fails during device rename
- nbd: fix assignment error for first_minor in nbd_dev_add
- selinux: further adjust init order for cred_* hooks
- selinux: further adjust init order for file_alloc_security hook
- !415 mainline bugfix backport
- selinux: reorder hooks to make runtime disable less broken
- evm: Fix a small race in init_desc()
- evm: Check also if *tfm is an error pointer in init_desc()
- iommu: Properly export iommu_group_get_for_dev()
- of: resolver: Add of_node_put() before return and break
- of: unittest: Add of_node_put() before return
- drivers/iommu: Allow IOMMU bus ops to be unregistered
- drivers/iommu: Export core IOMMU API symbols to permit modular drivers
- component: do not dereference opaque pointer in debugfs
- ipmi: use %*ph to print small buffer
- crypto: algif_skcipher - Use chunksize instead of blocksize
- crypto: algif_skcipher - EBUSY on aio should be an error
- crypto: rsa-pkcs1pad - fix buffer overread in pkcs1pad_verify_complete()
- dhugetlb: isolate hwpoison hugepage when release
- mm/sharepool: Fix null-pointer-deference in sp_free_area

* Tue Feb 21 2023 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2302.4.0.0189
- !213  net: bonding: Inherit MPLS features from slave devices
- x86/unwind: Fix check_paravirt() calls orc_find() before declaration
- dhugetlb: set hpool to NULL for cont-bit hugepage
- arm64/ascend: Delete CONFIG_ASCEND_AUTO_TUNING_HUGEPAGE in hulk_defconfig
- arm64/ascend: Delete unused feature auto-tuning hugepage
- mm/memcg_memfs_info: fix potential oom_lock recursion deadlock
- net: bridge: mcast: add and enforce query interval minimum
- net: bridge: mcast: add and enforce startup query interval minimum
- !396 anolis: bond: broadcast ARP or ND messages to all slaves
- anolis: bond: broadcast ARP or ND messages to all slaves
- net: bonding: Inherit MPLS features from slave devices

* Tue Feb 14 2023 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2302.3.0.0188
- block, bfq: switch 'bfqg->ref' to use atomic refcount apis
- x86/bugs: Flush IBP in ib_prctl_set()
- media: vivid: fix compose size exceed boundary
- cifs: do not include page data when checking signature
- SUNRPC: Don't leak netobj memory when gss_read_proxy_verf() fails
- net: stream: purge sk_error_queue in sk_stream_kill_queues()
- net: stream: don't purge sk_error_queue in sk_stream_kill_queues()
- ext4: fix deadlock due to mbcache entry corruption
- mbcache: automatically delete entries from cache on freeing
- mm/khugepaged: invoke MMU notifiers in shmem/file collapse paths
- mm/khugepaged: fix GUP-fast interaction by sending IPI
- mm: gup: fix the fast GUP race against THP collapse
- prlimit: do_prlimit needs to have a speculation check
- arm64: cmpxchg_double*: hazard against entire exchange variable
- net/ulp: prevent ULP without clone op from entering the LISTEN status
- driver core: Fix bus_type.match() error handling in __driver_attach()
- md: fix a crash in mempool_free
- bpf: pull before calling skb_postpull_rcsum()
- SUNRPC: ensure the matching upcall is in-flight upon downcall
- ovl: Use ovl mounter's fsuid and fsgid in ovl_link()
- pnode: terminate at peers of source
- cifs: Fix uninitialized memory read for smb311 posix symlink create
- device_cgroup: Roll back to original exceptions after copy failure
- PCI/sysfs: Fix double free in error path
- PCI: Fix pci_device_is_present() for VFs by checking PF
- ipmi: fix use after free in _ipmi_destroy_user()
- ima: Fix a potential NULL pointer access in ima_restore_measurement_list
- ipmi: fix long wait in unload when IPMI disconnect
- binfmt: Fix error return code in load_elf_fdpic_binary()
- chardev: fix error handling in cdev_device_add()
- mrp: introduce active flags to prevent UAF when applicant uninit
- bpf: make sure skb->len != 0 when redirecting to a tunneling device
- ipmi: fix memleak when unload ipmi driver
- ACPICA: Fix error code path in acpi_ds_call_control_method()
- skbuff: Account for tail adjustment during pull operations
- serial: pl011: Do not clear RX FIFO & RX interrupt in unthrottle.
- serial: amba-pl011: avoid SBSA UART accessing DMACR register
- class: fix possible memory leak in __class_register()
- crypto: tcrypt - Fix multibuffer skcipher speed test mem leak
- blktrace: Fix output non-blktrace event when blk_classic option enabled
- SUNRPC: Fix missing release socket in rpc_sockname()
- bonding: uninitialized variable in bond_miimon_inspect()
- pinctrl: pinconf-generic: add missing of_node_put()
- ima: Fix misuse of dereference of pointer in template_desc_init_fields()
- ACPICA: Fix use-after-free in acpi_ut_copy_ipackage_to_ipackage()
- md/raid1: stop mdx_raid1 thread when raid1 array run failed
- blk-mq: fix possible memleak when register 'hctx' failed
- perf: Fix possible memleak in pmu_dev_alloc()
- cpuidle: dt: Return the correct numbers of parsed idle states
- pstore: Avoid kcore oops by vmap()ing with VM_IOREMAP
- pstore/ram: Fix error return code in ramoops_probe()
- perf: arm_dsu: Fix hotplug callback leak in dsu_pmu_init()
- sched/rt: Optimize checking group RT scheduler constraints
- md: protect md_unregister_thread from reentrancy
- hugetlbfs: fix off-by-one error in hugetlb_vmdelete_list()
- lib/list_debug.c: Detect uninitialized lists
- crypto: tcrypt - avoid signed overflow in byte count
- mm: sharepool: fix hugepage_rsvd count increase error
- config: enbale irq pending config for openeuler
- genirq: introduce CONFIG_GENERIC_PENDING_IRQ_FIX_KABI
- irqchip/gic-v3-its: introduce CONFIG_GENERIC_PENDING_IRQ
- md: fix uaf in md_wakeup_thread
- genirq: add printk safe in irq context
- jbd2: Fix data missing when reusing bh which is ready to be checkpointed
- x86/unwind: Fix orc entry for paravirt {save,restore}_fl
- cifs: sanitize multiple delimiters in prepath
- drm/i915/gvt: fix double free bug in split_2MB_gtt_entry

* Tue Feb 07 2023 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2302.1.0.0187
- ring-buffer: Fix race between reset page and reading page
- block: don't allow a disk link holder to itself
- ext4: fix use-after-free in ext4_orphan_cleanup
- ext4: lost matching-pair of trace in ext4_truncate
- ipv6: raw: Deduct extension header length in rawv6_push_pending_frames
- mm/swapfile: add cond_resched() in get_swap_pages()
- hugetlbfs: don't delete error page from pagecache
- mm: hwpoison: refactor refcount check handling
- dhugetlb: set DYNAMIC_HUGETLB to y for hulk_defconfig
- dhugetlb: use enable_dhugetlb to disable huge_memory
- dhugetlb: skip dissolve hugepage belonging to dynamic hugetlb
- dhugetlb: only support 1G/2M hugepage and ARM64_4K_PAGES
- dhugetlb: isolate dynamic hugetlb code
- dhugetlb: backport dynamic hugetlb feature
- !344 mm: fix false-positive OVERCOMMIT_GUESS failures
- cfq: fix memory leak for cfqq
- mm: fix false-positive OVERCOMMIT_GUESS failures

* Tue Jan 31 2023 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2301.6.0.0186
- bus: hisi_lpc: Fixup IO ports addresses to avoid use-after-free in host removal
- of/fdt: Don't calculate initrd size from DT if start > end
- lib/cmdline: avoid page fault in next_arg
- genirq: Introduce warn log when irq be reentrant
- net: sched: disallow noqueue for qdisc classes
- net: sched: atm: dont intepret cls results when asked to drop
- block: check 'bd_super' before rescanning partition
- net: sched: cbq: dont intepret cls results when asked to drop
- swapfile: fix soft lockup in scan_swap_map_slots
- Huawei BMA: Fix iBMA driver bug

* Wed Jan 18 2023 Zheng Zengkai <zhengzengkai@huawei.com> - 4.19.90-2301.5.0.0185
- USB: Fix kABI for usb_device->reset_in_progress
- rndis_wlan: Prevent buffer overflow in rndis_query_oid
- mm: fix unexpected changes to {failslab|fail_page_alloc}.attr
- ima: Directly assign the ima_default_policy pointer to ima_rules
- driver core: Don't probe devices after bus_type.match() probe deferral
- KEYS: trusted: Fix migratable=1 failing
- certs: Fix blacklist flag type confusion
- crypto: ecdh - avoid unaligned accesses in ecdh_set_secret()
- ipc/sem: Fix dangling sem_array access in semtimedop race
- ipv6: avoid use-after-free in ip6_fragment()
- nvme initialize core quirks before calling nvme_init_subsystem
- memcg: fix possible use-after-free in memcg_write_event_control()
- x86/ioremap: Fix page aligned size calculation in __ioremap_caller()
- nvme: restrict management ioctls to admin
- arm64: errata: Fix KVM Spectre-v2 mitigation selection for Cortex-A57/A72
- arm64: Fix panic() when Spectre-v2 causes Spectre-BHB to re-allocate KVM vectors
- packet: do not set TP_STATUS_CSUM_VALID on CHECKSUM_COMPLETE
- net: tun: Fix use-after-free in tun_detach()
- of: property: decrement node refcount in of_fwnode_get_reference_args()
- af_key: Fix send_acquire race with pfkey_register
- audit: fix undefined behavior in bit shift for AUDIT_BIT
- USB: core: Fix RST error in hub.c
- USB: core: Prevent nested device-reset calls
- ima: Do not print policy rule with inactive LSM labels
- lsm: Resolve KABI changes on lsm_notifier
- ima: Evaluate error in init_ima()
- ima: ima/lsm policy rule loading logic bug fixes
- ima: Handle -ESTALE returned by ima_filter_rule_match()
- ima: use the lsm policy update notifier
- LSM: switch to blocking policy update notifiers
- mm/hwpoison: do not lock page again when me_huge_page() successfully recovers

* Wed Jan 11 2023 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2301.3.0.0184
- arm64: Kconfig: default unset ARCH_LLC_128_LINE_SIZE
- mm/sharepool: clean up ABI breakage
- timekeeping: Avoiding false sharing in field access of tk_core
- mm/hwpoison: put page in already hwpoisoned case with MF_COUNT_INCREASED
- mm/memory-failure.c: fix race with changing page more robustly
- mm,memory_failure: always pin the page in madvise_inject_error
- kobject: Fix slab-out-of-bounds in fill_kobj_path()
- tracing: Fix infinite loop in tracing_read_pipe on overflowed print_trace_line
- i2c: ismt: Fix an out-of-bounds bug in ismt_access()
- misc: sgi-gru: fix use-after-free error in gru_set_context_option, gru_fault and gru_handle_user_call_os
- mm/sharepool: Charge Buddy hugepage to memcg

* Tue Dec 27 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2212.4.0.0183
- dm thin: Use last transaction's pmd->root when commit failed
- drm: mali-dp: potential dereference of null pointer
- power: supply: wm8350-power: Add missing free in free_charger_irq
- sched: Reinit task's vruntime if a task sleep over 200 days
- media: dvb-core: Fix UAF due to refcount races at releasing
- drm/amdkfd: Check for null pointer after calling kmemdup
- !325 Support enabling dirty log gradually in small chunks
- KVM: arm64: Support enabling dirty log gradually in small chunks
- KVM: x86: enable dirty log gradually in small chunks
- KVM: Introduce KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2
- KVM: Fix kvm_clear_dirty_log_protect off-by-(minus-)one
- KVM: Fix the bitmap range to copy during clear dirty
- kvm_main: fix some comments
- KVM: fix KVM_CLEAR_DIRTY_LOG for memory slots of unaligned size
- Revert "KVM: Eliminate extra function calls in kvm_get_dirty_log_protect()"
- KVM: validate userspace input in kvm_clear_dirty_log_protect()
- kvm: introduce manual dirty log reprotect
- kvm: rename last argument to kvm_get_dirty_log_protect
- kvm: make KVM_CAP_ENABLE_CAP_VM architecture agnostic

* Tue Dec 20 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2212.3.0.0182
- Bluetooth: L2CAP: fix use-after-free in l2cap_conn_del()
- Bluetooth: L2CAP: Fix build errors in some archs
- Bluetooth: L2CAP: Fix l2cap_global_chan_by_psm regression
- Bluetooth: L2CAP: Fix use-after-free caused by l2cap_chan_put
- hv_netvsc: Add check for kvmalloc_array
- xen/netback: don't call kfree_skb() with interrupts disabled
- xen/netback: fix build warning
- xen/netback: Ensure protocol headers don't fall in the non-linear area
- !273 [openEuler-1.0-LTS] Fix mouse enumeration issue after wakeup from s4
- arm64: fix a concurrency issue in emulation_proc_handler()
- dm thin: Fix ABBA deadlock between shrink_slab and dm_pool_abort_metadata
- sched/qos: Don't unthrottle cfs_rq when cfs_rq is throttled by qos
- media: mceusb: Use new usb_control_msg_*() routines
- media: mceusb: fix control-message timeouts
- USB: add usb_control_msg_send() and usb_control_msg_recv()
- Fix mouse enumeration issue after wakeup from s4

* Tue Dec 13 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2212.2.0.0181
- mm/sharepool: Fix a double free problem caused by init_local_group
- bpf, test_run: Fix alignment problem in bpf_prog_test_run_skb()
- macvlan: enforce a consistent minimal mtu
- net: macvlan: fix memory leaks of macvlan_common_newlink
- ipv6: addrlabel: fix infoleak when sending struct ifaddrlblmsg to network
- net: gso: fix panic on frag_list with mixed head alloc types
- tcp/udp: Make early_demux back namespacified.
- ipv6: fix WARNING in ip6_route_net_exit_late()
- net, neigh: Fix null-ptr-deref in neigh_table_clear()
- tcp: fix indefinite deferral of RTO with SACK reneging
- net: fix UAF issue in nfqnl_nf_hook_drop() when ops_init() failed
- serial: 8250: Flush DMA Rx on RLSI
- serial: 8250: Fall back to non-DMA Rx if IIR_RDI occurs
- capabilities: fix potential memleak on error path from vfs_getxattr_alloc()
- security: commoncap: fix -Wstringop-overread warning
- ring_buffer: Do not deactivate non-existant pages
- ftrace: Fix null pointer dereference in ftrace_add_mod()
- ftrace: Optimize the allocation for mcount entries
- kprobe: reverse kp->flags when arm_kprobe failed
- mm: fs: initialize fsdata passed to write_begin/write_end interface
- nfs4: Fix kmemleak when allocate slot failed
- kernfs: fix use-after-free in __kernfs_remove
- mm,hugetlb: take hugetlb_lock before decrementing h->resv_huge_pages
- mm: /proc/pid/smaps_rollup: fix no vma's null-deref
- signal handling: don't use BUG_ON() for debugging
- ida: don't use BUG_ON() for debugging

* Tue Dec 06 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2212.1.0.0180
- !272 [openEuler-1.0-LTS] Add MWAIT Cx support for Zhaoxin CPUs.
- Bluetooth: L2CAP: Fix u8 overflow
- l2tp: Don't sleep and disable BH under writer-side sk_callback_lock
- l2tp: Serialize access to sk_user_data with sk_callback_lock
- !288 Add support for ConnectX6 Lx and ConnectX6Dx with openEuler inbox driver
- net/mlx5: Update the list of the PCI supported devices
- net/mlx5: Update the list of the PCI supported devices
- drivers: net: slip: fix NPD bug in sl_tx_timeout()
- staging: rtl8712: fix use after free bugs
- Add MWAIT Cx support for Zhaoxin CPUs.

* Tue Nov 29 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2211.6.0.0179
- x86/tsc: use topology_max_packages() in tsc watchdog check
- scsi: hisi_sas: Set iptt aborted flag when receiving an abnormal CQ
- ext4: fix bug in extents parsing when eh_entries == 0 and eh_depth > 0

* Tue Nov 22 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2211.5.0.0178
- svm: Delete unused ioctl command
- Revert "posix-cpu-timers: Make timespec to nsec conversion safe"
- block: limit request dispatch loop duration
- Bluetooth: L2CAP: Fix accepting connection request for invalid SPSM
- Bluetooth: L2CAP: Fix attempting to access uninitialized memory
- block: check flags of claimed slave bdev to fix uaf for bd_holder_dir

* Tue Nov 15 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2211.4.0.0177
- block: fix use after free for bd_holder_dir
- Revert "block: Fix UAF in bd_link_disk_holder()"
- init/main.c: return 1 from handled __setup() functions
- x86/pm: Save the MSR validity status at context setup
- x86/speculation: Restore speculation related MSRs during S3 resume
- x86/cpu: Load microcode during restore_processor_state()
- genirq: Synchronize interrupt thread startup
- nvme: Fix IOC_PR_CLEAR and IOC_PR_RELEASE ioctls for nvme devices
- once: add DO_ONCE_SLOW() for sleepable contexts
- inet: fully convert sk->sk_rx_dst to RCU rules
- ext4: continue to expand file system when the target size doesn't reach
- nvme: copy firmware_rev on each init
- net: If sock is dead don't access sock's sk_wq in sk_stream_wait_memory
- can: bcm: check the result of can_send() in bcm_can_tx()
- xfrm: Update ipcomp_scratches with NULL when freed
- tcp: annotate data-race around tcp_md5sig_pool_populated
- tcp: fix tcp_cwnd_validate() to not forget is_cwnd_limited
- ext4: fix null-ptr-deref in ext4_write_info
- Revert "fs: check FMODE_LSEEK to control internal pipe splicing"
- ima: Free the entire rule if it fails to parse
- ima: Free the entire rule when deleting a list of rules
- ima: Have the LSM free its audit rule
- mm/migrate_device.c: flush TLB while holding PTL
- mm: prevent page_frag_alloc() from corrupting the memory
- mm/page_alloc: fix race condition between build_all_zonelists and page allocation
- net: team: Unsync device addresses on ndo_stop
- mm/slub: fix to return errno if kmalloc() fails
- of: fdt: fix off-by-one error in unflatten_dt_nodes()

* Tue Nov 08 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2211.2.0.0176
- net: tun: fix bugs for oversize packet when napi frags enabled
- tcp: fix a signed-integer-overflow bug in tcp_add_backlog()
- tcp: prohibit TCP_REPAIR_OPTIONS if data was already sent
- ext4: fix bad checksum after online resize
- blktrace: remove unnessary stop block trace in 'blk_trace_shutdown'
- blktrace: fix possible memleak in '__blk_trace_remove'
- blktrace: introduce 'blk_trace_{start,stop}' helper
- kabi: net: fix kabi broken in sk_buff
- io_uring/af_unix: defer registered files gc to io_uring release
- nbd: refactor size updates
- nbd: move the task_recv check into nbd_size_update
- nbd: remove the call to set_blocksize
- wifi: Fix potential buffer overflow in 'brcmf_fweh_event_worker'
- fs: fix UAF/GPF bug in nilfs_mdt_destroy
- dm: Fix UAF in run_timer_softirq()
- Bluetooth: sco: Fix lock_sock() blockage by memcpy_from_msg()
- ext4: record error information when insert extent failed in 'ext4_split_extent_at'
- livepatch/core: Fix livepatch/state leak on error path
- !130 [openEuler-1.0-LTS] update pmu for Zhaoxin CPUs
- update pmu for Zhaoxin CPUs

* Wed Nov 02 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2211.1.0.0175
- uacce: add the reference counter protection
- nilfs2: fix NULL pointer dereference at nilfs_bmap_lookup_at_level()
- usb: mon: make mmapped memory read only
- !185 [openEuler-1.0-LTS] Add support sata lpm for Zhaoxin CPUs
- ext4: fix bug_on in __es_tree_search caused by bad boot loader inode
- ext4: add EXT4_IGET_BAD flag to prevent unexpected bad inode
- ext4: add helper to check quota inums
- ext4: fix bug_on in __es_tree_search caused by bad quota inode
- atm: idt77252: fix use-after-free bugs caused by tst_timer
- ext4: ext4_read_bh_lock() should submit IO if the buffer isn't uptodate
- !94 [openEuler-1.0-LTS] rtc: Fix set RTC time delay 500ms on some Zhaoxin SOCs
- !88 [openEuler-1.0-LTS] XHCI:Fix some device identify fail when enable xHCI runtime suspend
- !92 [openEuler-1.0-LTS] x86/tsc: Make cur->adjusted values in package#1 to be the same
- !93 [openEuler-1.0-LTS] Driver for Zhaoxin CPU core temperature monitoring
- !89 [openEuler-1.0-LTS] EHCI: Clear wakeup signal locked in S0  state when device plug in
- scsi: stex: Properly zero out the passthrough command structure
- !192 x86/apic/vector: Fix ordering in vector assignment
- nilfs2: fix leak of nilfs_root in case of writer thread creation failure
- vsock: Fix memory leak in vsock_connect()
- x86/apic/vector: Fix ordering in vector assignment
- Add support for PxSCT.LPM set based on actual LPM circumstances
- Add support for disabling PhyRdy Change Interrupt based on actual LPM capability
- Driver for Zhaoxin CPU core temperature monitoring
- rtc: Fix set RTC time delay 500ms on some Zhaoxin SOCs
- x86/tsc: Make cur->adjusted values in package#1 to be the same
- EHCI: Clear wakeup signal locked in S0 state when device plug in
- XHCI:Fix some device identify fail when enable xHCI runtime suspend

* Thu Oct 27 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2210.5.0.0174
- sch_sfb: Also store skb len before calling child enqueue
- sch_sfb: Don't assume the skb is still around after enqueueing to child
- ipv6: Fix data races around sk->sk_prot.
- ipv6: annotate some data-races around sk->sk_prot
- ipv6: provide and use ipv6 specific version for {recv, send}msg
- inet: factor out inet_send_prepare()
- nilfs2: fix use-after-free bug of struct nilfs_root

* Tue Oct 25 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2210.4.0.0173
- nfp: fix use-after-free in area_cache_get()
- mISDN: fix use-after-free bugs in l1oip timer handlers
- tcp: Fix data races around icsk->icsk_af_ops.
- Bluetooth: L2CAP: Fix use-after-free caused by l2cap_reassemble_sdu
- !134 scsi: megaraid_sas: Add support for MegaRAID Aero controllers
- !138 vfio-pci: Mask cap zero
- bnx2x: fix potential memory leak in bnx2x_tpa_stop()
- r8152: Rate limit overflow messages
- scsi: megaraid_sas: Add support for MegaRAID Aero controllers
- vfio-pci: Mask cap zero
- tcp/udp: Fix memory leak in ipv6_renew_options().
- net: mvpp2: fix mvpp2 debugfs leak
- !159 PCI: Add ACS quirk for Broadcom NICs
- !137 net: bonding: Add support for IPV6 ns/na to balance-alb/balance-tlb mode
- kcm: avoid potential race in kcm_tx_work
- net: bonding: Add support for IPV6 ns/na to balance-alb/balance-tlb mode
- !139 nvme: Assign subsys instance from first ctrl
- fbdev: smscufx: Fix use-after-free in ufx_ops_open()
- nvme: fix controller instance leak
- nvme: Assign subsys instance from first ctrl
- PCI: Add ACS quirk for Broadcom BCM5750x NICs
- PCI: Add ACS quirk for Broadcom BCM57414 NIC

* Tue Oct 18 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2210.3.0.0172
- binder: fix UAF of ref->proc caused by race condition
- arm64: fix oops in concurrently setting insn_emulation sysctls
- mm/hotplug: silence a lockdep splat with printk()
- init/Kconfig: Add SMP to the dependencies of QOS_SCHED
- mm/rmap: Fix kabi broken in anon_vma
- mm/rmap: Fix anon_vma->degree ambiguity leading to double-reuse
- HID: roccat: Fix use-after-free in roccat_read()
- ext4: fix dir corruption when ext4_dx_add_entry() fails
- quota: Add more checking after reading from quota file
- quota: Replace all block number checking with helper function
- quota: Check next/prev free block number after reading from quota file
- Revert "quota: Check next/prev free block number after reading from quota file"
- Revert "quota: Replace all block number checking with helper function"
- Revert "quota: Add more checking after reading from quota file"
- tracefs: Only clobber mode/uid/gid on remount if asked
- netfilter: ebtables: fix memory leak when blob is malformed
- netfilter: ebtables: reject blobs that don't provide all entry points
- mm: Fix TLB flush for not-first PFNMAP mappings in unmap_region()
- SUNRPC: use _bh spinlocking on ->transport_lock
- tcp: fix early ETIMEDOUT after spurious non-SACK RTO
- netfilter: br_netfilter: Drop dst references before setting.
- debugfs: add debugfs_lookup_and_remove()
- tcp: annotate data-race around challenge_timestamp
- Revert "mm: kmemleak: take a full lowmem check in kmemleak_*_phys()"
- net: neigh: don't call kfree_skb() under spin_lock_irqsave()
- neigh: fix possible DoS due to net iface start/stop loop
- mm/hugetlb: fix hugetlb not supporting softdirty tracking
- asm-generic: sections: refactor memory_intersects
- loop: Check for overflow while configuring loop
- net: Fix a data-race around sysctl_somaxconn.
- net: Fix a data-race around netdev_budget_usecs.
- net: Fix a data-race around netdev_budget.
- net: Fix a data-race around sysctl_net_busy_read.
- net: Fix a data-race around sysctl_net_busy_poll.
- net: Fix a data-race around sysctl_tstamp_allow_data.
- ratelimit: Fix data-races in ___ratelimit().
- net: Fix data-races around netdev_tstamp_prequeue.
- net: Fix data-races around weight_p and dev_weight_[rt]x_bias.
- net: ipvtap - add __init/__exit annotations to module init/exit funcs
- bonding: 802.3ad: fix no transmission of LACPDUs
- xfrm: fix refcount leak in __xfrm_policy_check()
- audit: fix potential double free on error path from fsnotify_add_inode_mark
- dm: return early from dm_pr_call() if DM device is suspended
- NFSv4: Fix races in the legacy idmapper upcall

* Tue Oct 11 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2210.1.0.0171
- netfilter: nf_conntrack_irc: Fix forged IP logic
- ext4: fix check for block being out of directory size
- ext4: check if directory block is within i_size
- block: Fix UAF in bd_link_disk_holder()
- ALSA: pcm: oss: Fix race at SNDCTL_DSP_SYNC
- block: add a new config to control dispatching bios asynchronously
- block: fix kabi broken in request_queue
- md: enable dispatching bio asynchronously for raid10 by default
- arm64/topology: getting preferred sibling's cpumask supported by platform
- block: support to dispatch bio asynchronously
- block: add new fields in request_queue
- md/raid10: convert resync_lock to use seqlock
- md/raid10: prevent unnecessary calls to wake_up() in fast path
- !122 【kernel-openEuler-1.0-LTS】kernel：fix some issues with 4.19 kernel on openEuler 22.03 system
- mm: sharepool: fix potential AA deadlock
- mm: sharepool: check size=0 in mg_sp_make_share_k2u()
- mm: sharepool: delete redundant check in __sp_remap_get_pfn
- Revert "cifs: fix double free race when mount fails in cifs_get_root()"
- scsi: hisi_sas: Release resource directly in hisi_sas_abort_task() when NCQ error
- scsi: hisi_sas: Enable force phy when SATA disk directly connected
- scsi: hisi_sas: Modify v3 HW ATA completion process when SATA disk is in error status
- sched: Fix invalid free for tsk->se.dyn_affi_stats
- scsi: target: tcmu: Fix warning: 'page' may be used uninitialized
- scsi: target: tcmu: Fix crash on ARM during cmd completion
- scsi: target: tcmu: Optimize use of flush_dcache_page
- scsi: target: tcmu: Fix size in calls to tcmu_flush_dcache_range
- signal: fix deadlock caused by calling printk() under sighand->siglock
- mm: fix missing handler for __GFP_NOWARN
- perf bench futex-wake: Restore thread count default to online CPU count
- selftests/bpf: Enlarge select() timeout for test_maps
- xfs: preserve default grace interval during quotacheck
- i40e: Fix kernel crash during module removal
- i40e: Fix use-after-free in i40e_client_subtask()
- EDAC: skx_common: downgrade message importance on missing PCI device
- x86/entry/64: Don't compile ignore_sysret if 32-bit emulation is enabled
- x86: Fix early boot crash on gcc-10, third try
- objtool: Don't fail on missing symbol table

* Tue Sep 27 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2209.6.0.0170
- KVM: x86/pmu: Update AMD PMC sample period to fix guest NMI-watchdog
- KVM: x86: Adjust counter sample period after a wrmsr
- KVM: x86: Fix perfctr WRMSR for running counters
- perf/core: Provide a kernel-internal interface to recalibrate event period
- media: em28xx: initialize refcount before kref_get
- mm: avoid potential deadlock tirgged by writing slab-attr-file
- ext4: fix use-after-free in ext4_ext_shift_extents
- quota: Add more checking after reading from quota file
- quota: Replace all block number checking with helper function
- quota: Check next/prev free block number after reading from quota file
- efi: capsule-loader: Fix use-after-free in efi_capsule_write
- ipvlan: Fix out-of-bound bugs caused by unset skb->mac_header
- mm/sharepool: Fix UAF reported by KASAN
- blk-mq: avoid extending delays of active hctx from blk_mq_delay_run_hw_queues
- mm: mem_reliable: Start fallback if no suitable zone found
- net: hns3: update hns3 version to 22.9.2
- net: hns3: fix error resume keep alive when remove hclgevf
- net: hns3: update hns3 version to 22.9.1
- net: hns3: fix keep alive can not resume problem when system busy

* Tue Sep 20 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2209.5.0.0169
- jfs: prevent NULL deref in diFree
- jfs: fix GPF in diFree

* Thu Sep 15 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2209.4.0.0168
- mm: Force TLB flush for PFNMAP mappings before unlink_file_vma()
- video: fbdev: pxa3xx-gcu: Fix integer overflow in pxa3xx_gcu_write

* Wed Sep 14 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2209.3.0.0167
- KVM: x86: do not report a vCPU as preempted outside instruction boundaries
- KVM: arm64: Write arch.mdcr_el2 changes since last vcpu_load on VHE
- netfilter: nf_conntrack_irc: Tighten matching on DCC message
- ext4: avoid resizing to a partial cluster size
- locking/atomic: Make test_and_*_bit() ordered on failure
- geneve: do not use RT_TOS for IPv6 flowlabel
- SUNRPC: Reinitialise the backchannel request buffers before reuse
- NFSv4/pnfs: Fix a use-after-free bug in open
- NFSv4.1: RECLAIM_COMPLETE must handle EACCES
- tcp: fix over estimation in sk_forced_mem_schedule()
- ext4: fix extent status tree race in writeback error recovery path
- ext4: update s_overhead_clusters in the superblock during an on-line resize
- ext4: make sure ext4_append() always allocates new block
- kprobes: Forbid probing on trampoline and BPF code areas
- kfifo: fix kfifo_to_user() return type
- profiling: fix shift too large makes kernel panic
- serial: 8250_dw: Store LSR into lsr_saved_flags in dw8250_tx_wait_empty()
- mm/mmap.c: fix missing call to vm_unacct_memory in mmap_region
- mtd: st_spi_fsm: Add a clk_disable_unprepare() in .probe()'s error path
- mtd: sm_ftl: Fix deadlock caused by cancel_work_sync in sm_release
- can: error: specify the values of data[5..7] of CAN error frames
- fs: check FMODE_LSEEK to control internal pipe splicing
- tcp: make retransmitted SKB fit into the send window
- nohz/full, sched/rt: Fix missed tick-reenabling bug in dequeue_task_rt()
- bus: hisi_lpc: fix missing platform_device_put() in hisi_lpc_acpi_probe()
- x86/pmem: Fix platform-device leak in error path
- selinux: Add boundary check in put_entry()
- ACPI: LPSS: Fix missing check in register_device_clock()
- fs: Add missing umask strip in vfs_tmpfile
- vfs: Check the truncate maximum size in inode_newsize_ok()
- tcp: Fix a data-race around sysctl_tcp_comp_sack_nr.
- tcp: Fix a data-race around sysctl_tcp_comp_sack_delay_ns.
- tcp: Fix a data-race around sysctl_tcp_invalid_ratelimit.
- tcp: Fix a data-race around sysctl_tcp_autocorking.
- tcp: Fix a data-race around sysctl_tcp_min_rtt_wlen.
- tcp: Fix a data-race around sysctl_tcp_min_tso_segs.
- igmp: Fix data-races around sysctl_igmp_qrv.
- net: ping6: Fix memleak in ipv6_renew_options().
- tcp: Fix a data-race around sysctl_tcp_challenge_ack_limit.
- tcp: Fix a data-race around sysctl_tcp_nometrics_save.
- tcp: Fix a data-race around sysctl_tcp_frto.
- tcp: Fix a data-race around sysctl_tcp_adv_win_scale.
- tcp: Fix a data-race around sysctl_tcp_app_win.
- tcp: Fix data-races around sysctl_tcp_dsack.
- mm/mempolicy: fix uninit-value in mpol_rebind_policy()
- tcp: Fix data-races around sysctl_tcp_max_reordering.
- tcp: Fix a data-race around sysctl_tcp_rfc1337.
- tcp: Fix a data-race around sysctl_tcp_stdurg.
- tcp: Fix a data-race around sysctl_tcp_retrans_collapse.
- tcp: Fix data-races around sysctl_tcp_slow_start_after_idle.
- tcp: Fix a data-race around sysctl_tcp_thin_linear_timeouts.
- tcp: Fix data-races around sysctl_tcp_recovery.
- tcp: Fix a data-race around sysctl_tcp_early_retrans.
- tcp: Fix data-races around sysctl_tcp_fastopen.
- tcp: Fix a data-race around sysctl_tcp_tw_reuse.
- tcp: Fix a data-race around sysctl_tcp_notsent_lowat.
- tcp: Fix data-races around some timeout sysctl knobs.
- tcp: Fix data-races around sysctl_tcp_reordering.
- igmp: Fix a data-race around sysctl_igmp_max_memberships.
- igmp: Fix data-races around sysctl_igmp_llm_reports.
- tcp: Fix a data-race around sysctl_tcp_probe_interval.
- tcp: Fix a data-race around sysctl_tcp_probe_threshold.
- tcp: Fix data-races around sysctl_tcp_mtu_probing.
- tcp/dccp: Fix a data-race around sysctl_tcp_fwmark_accept.
- ip: Fix a data-race around sysctl_fwmark_reflect.
- ip: Fix data-races around sysctl_ip_nonlocal_bind.
- ip: Fix data-races around sysctl_ip_fwd_use_pmtu.
- block: fix the problem of io_ticks becoming smaller
- blk-mq: Fix memory leak in blk_mq_init_allocated_queue error handling
- block, bfq: save & resume weight on a queue merge/split
- ACPICA: Disassembler: create buffer fields in ACPI_PARSE_LOAD_PASS1
- acpi/nfit: improve bounds checking for 'func'
- ACPICA: Do not increment operation_region reference counts for field units
- ACPICA: Fix exception code class checks
- ACPI: configfs: add missing check after configfs_register_default_group()
- ACPI: custom_method: fix potential use-after-free issue
- ACPI: custom_method: fix a possible memory leak
- ACPI: APD: Check for NULL pointer after calling devm_ioremap()
- ACPI/IORT: Fix PMCG node single ID mapping handling
- ACPI/IORT: Check node revision for PMCG resources
- kprobes: don't call disarm_kprobe() for disabled kprobes
- x86/unwind/orc: Unwind ftrace trampolines with correct ORC entry
- usb: gadget: function: printer: fix use-after-free in __lock_acquire
- video: fbdev: i740fb: Error out if 'pixclock' equals zero
- lightnvm: disable the subsystem
- configfs: fix a race in configfs_lookup()
- configfs: fold configfs_attach_attr into configfs_lookup
- configfs: make configfs_create() return inode
- configfs: factor dirent removal into helpers
- configfs: simplify the configfs_dirent_is_ready
- configfs: return -ENAMETOOLONG earlier in configfs_lookup

* Mon Sep 05 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2209.1.0.0166
- dm-thin: Resume failed in FAIL mode
- tpm: fix reference counting for struct tpm_chip
- af_key: Do not call xfrm_probe_algs in parallel
- net: usb: ax88179_178a: Fix packet receiving
- net: usb: ax88179_178a: Fix out-of-bounds accesses in RX fixup
- net: usb: ax88179_178a: fix packet alignment padding

* Mon Aug 29 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2208.6.0.0165
- tty: use new tty_insert_flip_string_and_push_buffer() in pty_write()
- tty: extract tty_flip_buffer_commit() from tty_flip_buffer_push()
- tty: drop tty_schedule_flip()
- tty: the rest, stop using tty_schedule_flip()
- tty: drivers/tty/, stop using tty_schedule_flip()
- can: bcm/raw/isotp: use per module netdevice notifier
- CIFS: Fix retry mid list corruption on reconnects
- KVM: arm64: vgic-its: Change default outer cacheability for {PEND, PROP}BASER
- xhci: Fix a logic issue when display Zhaoxin XHCI root hub speed
- dm verity: set DM_TARGET_IMMUTABLE feature flag
- scsi: hisi_sas: Add SATA_DISK_ERR bit handling for v3 hw
- Revert "scsi: hisi_sas: Modify v3 HW I/O processing when SATA_DISK_ERR bit is set and NCQ Error occurs"
- netfilter: nf_tables: do not allow RULE_ID to refer to another chain
- netfilter: nf_tables: do not allow SET_ID to refer to another table

* Mon Aug 22 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2208.5.0.0164
- x86/speculation: Add LFENCE to RSB fill sequence
- x86/speculation: Add RSB VM Exit protections
- Revert "blk-mq: fix null pointer dereference in blk_mq_queue_tag_busy_ite"
- blk-mq: fix null pointer dereference in blk_mq_queue_tag_busy_ite
- arm64: Avoid premature usercopy failure for __arch_copy_to_user_generic_read
- net_sched: cls_route: remove from list when handle is 0

* Mon Aug 15 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2208.4.0.0163
- Revert "x86/unwind/orc: Change REG_SP_INDIRECT"
- Phytium/S2500: kdump: Avoid vmcore saving failure across multi-socket
- PCI: Add config control for phytium ACS quirks
- scsi: libiscsi: Teardown iscsi_cls_conn gracefully
- scsi: libiscsi: Add iscsi_cls_conn to sysfs after initialization
- scsi: iscsi: Add helper functions to manage iscsi_cls_conn
- media: v4l2-mem2mem: Apply DST_QUEUE_OFF_BASE on MMAP buffers across ioctls
- sched: Fix null-ptr-deref in free_fair_sched_group
- RDMA/ib_srp: Fix a deadlock
- mm/slub: add missing TID updates on slab deactivation
- block: fix regression for dm
- blk-mq: handle bio after queue is initialized
- x86: Clear .brk area at early boot
- signal/seccomp: Dump core when there is only one live thread
- x86/unwind/orc: Recheck address range after stack info was updated
- x86/unwind/orc: Silence warnings caused by missing ORC data
- x86/unwind/orc: Change REG_SP_INDIRECT

* Tue Aug 09 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2208.2.0.0162
- netfilter: nf_queue: do not allow packet truncation below transport header offset
- openvswitch: fix OOB access in reserve_sfa_size()
- dm thin: use refcount_t for thin_c reference counting
- exec: Force single empty string when argv is empty
- usb: gadget: rndis: prevent integer overflow in rndis_set_response()
- serial: pl011: UPSTAT_AUTORTS requires .throttle/unthrottle
- serial: 8250: fix return error code in serial8250_request_std_resource()
- ipv4: Fix data-races around sysctl_ip_dynaddr.
- icmp: Fix a data-race around sysctl_icmp_ratemask.
- icmp: Fix a data-race around sysctl_icmp_ratelimit.
- icmp: Fix data-races around sysctl.
- net: Fix data-races around sysctl_mem.
- inetpeer: Fix data-races around sysctl.
- usbnet: fix memory leak in error case
- esp: limit skb_page_frag_refill use to a single page
- net: tun: avoid disabling NAPI twice
- net: bonding: fix use-after-free after 802.3ad slave unbind
- net: bonding: fix possible NULL deref in rlb code
- usbnet: fix memory allocation in helpers
- net: tun: stop NAPI when detaching queues
- net: tun: unlink NAPI from device on destruction
- virtio-net: fix race between ndo_open() and virtio_device_ready()
- SUNRPC: Fix READ_PLUS crasher
- virtio_net: fix xdp_rxq_info bug after suspend/resume
- erspan: do not assume transport header is always set
- net/sched: sch_netem: Fix arithmetic in netem_dump() for 32-bit platforms
- bonding: ARP monitor spams NETDEV_NOTIFY_PEERS notifiers
- ext4: make variable "count" signed
- serial: 8250: Store to lsr_save_flags after lsr read
- irqchip/gic-v3: Fix refcount leak in gic_populate_ppi_partitions
- irqchip/gic/realview: Fix refcount leak in realview_gic_of_init
- ata: libata-core: fix NULL pointer deref in ata_host_alloc_pinfo()
- ipv6/addrconf: fix a null-ptr-deref bug for ip6_ptr
- io_uring: add missing item types for various requests
- net/sched: cls_u32: fix possible leak in u32_init_knode()
- fq_codel: reject silly quantum parameters
- net: sched: sch_teql: fix null-pointer dereference
- rcu: Set a maximum limit for back-to-back callback invocation
- mm: Fix page counter mismatch in shmem_mfill_atomic_pte
- scsi: mpt3sas: Fix unlock imbalance
- io-wq: Switch io_wqe_worker's fs before releasing request
- ath9k: fix use-after-free in ath9k_hif_usb_rx_cb
- Revert "iommu/vt-d: Fix potential memory leak in intel_setup_irq_remapping()"

* Tue Aug 02 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2208.1.0.0161
- fbcon: Prevent that screen size is smaller than font size
- fbcon: Disallow setting font bigger than screen size
- fbmem: Check virtual screen sizes in fb_set_var()
- xfrm: xfrm_policy: fix a possible double xfrm_pols_put() in xfrm_bundle_lookup()
- scsi: core: Fix race between handling STS_RESOURCE and completion
- block: prevent lockdep false positive warning about 'bd_mutex'
- dm verity: allow only one error handling mode
- dm verity: Fix compilation warning
- dm verity: add root hash pkcs#7 signature verification
- jbd2: Fix assertion 'jh->b_frozen_data == NULL' failure when journal aborted
- dm btree spine: show warning if node_check failed in node_prep_for_write()
- dm btree spine: remove paranoid node_check call in node_prep_for_write()
- ext4: Fix race when reusing xattr blocks
- ext4: Unindent codeblock in ext4_xattr_block_set()
- ext4: Remove EA inode entry from mbcache on inode eviction
- mbcache: Add functions to delete entry if unused
- mbcache: Don't reclaim used entries
- perf/core: Fix data race between perf_event_set_output() and perf_mmap_close()

* Mon Jul 25 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2207.4.0.0160
- inotify: show inotify mask flags in proc fdinfo
- io_uring: always grab file table for deferred statx
- bpf: Don't redirect packets with invalid pkt_len
- config: enable CONFIG_QOS_SCHED_DYNAMIC_AFFINITY by default
- sched: Add statistics for scheduler dynamic affinity
- sched: Adjust cpu range in load balance dynamicly
- sched: Adjust wakeup cpu range according CPU util dynamicly
- cpuset: Introduce new interface for scheduler dynamic affinity
- sched: Introduce dynamic affinity for cfs scheduler
- crypto: hisilicon/sec - don't sleep when in softirq
- video: fbdev: sm712fb: Fix crash in smtcfb_write()
- video: fbdev: sm712fb: Fix crash in smtcfb_read()
- scsi: ses: fix slab-out-of-bounds in ses_enclosure_data_process
- block: don't delete queue kobject before its children
- etmem:fix kernel stack overflow in do_swapcache_reclaim
- etmem:fix kasan slab-out-of-bounds in do_swapcache_reclaim
- nbd: don't clear 'NBD_CMD_INFLIGHT' flag if request is not completed
- blk-throttle: fix io hung due to configuration updates
- block: fix NULL pointer dereference in disk_release()
- block, bfq: make bfq_has_work() more accurate
- blk-mq: fix panic during blk_mq_run_work_fn()
- blk-mq: cancel blk-mq dispatch work in both blk_cleanup_queue and disk_release()
- blk-mq: move cancel of hctx->run_work to the front of blk_exit_queue
- ext4: fix race condition between ext4_ioctl_setflags and ext4_fiemap

* Mon Jul 18 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2207.3.0.0159
- block: fix that part scan is disabled in device_add_disk()
- Revert "block: rename bd_invalidated"
- Revert "block: move the NEED_PART_SCAN flag to struct gendisk"
- Revert "block:Fix kabi broken"
- rcu/tree: Mark functions as notrace
- netfilter: nf_tables: stricter validation of element data
- net: rose: fix UAF bugs caused by timer handler
- xen/arm: Fix race in RB-tree based P2M accounting
- vt: drop old FONT ioctls
- dm thin: Fix crash in dm_sm_register_threshold_callback()
- xen/blkfront: force data bouncing when backend is untrusted
- xen/netfront: force data bouncing when backend is untrusted
- xen-netfront: fix potential deadlock in xennet_remove()
- xen/netfront: fix leaking data in shared pages
- xen/blkfront: fix leaking data in shared pages
- xen/blkfront: fix memory allocation flags in blkfront_setup_indirect()
- tmpfs: fix the issue that the mount and remount results are inconsistent.
- tmpfs: fix undefined-behaviour in shmem_reconfigure()
- mm/sharepool: Check sp_is_enabled() before show spa_stat

* Mon Jul 11 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2207.2.0.0158
- x86: Fix return value of __setup handlers
- x86/delay: Fix the wrong asm constraint in delay_loop()
- ACPI: sysfs: Fix BERT error region memory mapping
- tcp: fix tcp_mtup_probe_success vs wrong snd_cwnd
- nbd: fix io hung while disconnecting device
- nbd: fix race between nbd_alloc_config() and module removal
- nbd: call genl_unregister_family() first in nbd_cleanup()
- ip_gre: test csum_start instead of transport header
- net: xfrm: unexport __init-annotated xfrm4_protocol_init()
- SUNRPC: Fix the calculation of xdr->end in xdr_get_next_encode_buffer()
- af_unix: Fix a data-race in unix_dgram_peer_wake_me().
- NFSv4: Don't hold the layoutget locks across multiple RPC calls
- tcp: tcp_rtx_synack() can be called from process context
- serial: 8250_fintek: Check SER_RS485_RTS_* only with RS485
- md: fix an incorrect NULL check in md_reload_sb
- md: fix an incorrect NULL check in does_sb_need_changing
- ext4: avoid cycles in directory h-tree
- ext4: verify dir block before splitting it
- proc: fix dentry/inode overinstantiating under /proc/${pid}/net
- drivers/base/node.c: fix compaction sysfs file leak
- fsnotify: fix wrong lockdep annotations
- PCI: Avoid pci_dev_lock() AB/BA deadlock with sriov_numvfs_store()
- fat: add ratelimit to fat*_ent_bread()
- nvme-pci: fix a NULL pointer dereference in nvme_alloc_admin_tags
- bpf: Enlarge offset check value to INT_MAX in bpf_skb_{load,store}_bytes
- dm stats: add cond_resched when looping over entries
- zsmalloc: fix races between asynchronous zspage free and page migration
- netfilter: conntrack: re-fetch conntrack after insertion
- assoc_array: Fix BUG_ON during garbage collect
- net: af_key: check encryption module availability consistency
- x86/pci/xen: Disable PCI/MSI[-X] masking for XEN_HVM guests
- net: bridge: Clear offload_fwd_mark when passing frame up bridge interface.
- ARM: 9197/1: spectre-bhb: fix loop8 sequence for Thumb2
- ARM: 9196/1: spectre-bhb: enable for Cortex-A15
- block:Fix kabi broken
- block: Fix warning in bd_link_disk_holder()
- block: move the NEED_PART_SCAN flag to struct gendisk
- block: rename bd_invalidated
- scsi: hisi_sas: Modify v3 HW I/O processing when SATA_DISK_ERR bit is set and NCQ Error occurs
- scsi: hisi_sas: enable use_clustering
- scsi: hisi_sas: Change DMA setup lock timeout to 2.5s
- x86/speculation/mmio: Print SMT warning
- KVM: x86/speculation: Disable Fill buffer clear within guests
- x86/speculation/mmio: Reuse SRBDS mitigation for SBDS
- x86/speculation/srbds: Update SRBDS mitigation selection
- x86/speculation/mmio: Add sysfs reporting for Processor MMIO Stale Data
- x86/speculation/mmio: Enable CPU Fill buffer clearing on idle
- x86/bugs: Group MDS, TAA & Processor MMIO Stale Data mitigations
- x86/speculation/mmio: Add mitigation for Processor MMIO Stale Data
- x86/speculation: Add a common function for MD_CLEAR mitigation update
- x86/speculation/mmio: Enumerate Processor MMIO Stale Data bug
- Documentation: Add documentation for Processor MMIO Stale Data
- x86/cpu: Add another Alder Lake CPU to the Intel family
- x86/cpu: Add Lakefield, Alder Lake and Rocket Lake models to the to Intel CPU family
- x86/cpu: Add Jasper Lake to Intel family
- cpu/speculation: Add prototype for cpu_show_srbds()
- x86/cpu: Add Elkhart Lake to Intel family
- block: open accurate iostat account by default
- block: use "precise_iostat" to switch accurate iostat account
- block/diskstats: more accurate approximation of io_ticks for slow disks
- fs-writeback: writeback_sb_inodes：Recalculate 'wrote' according skipped pages

* Tue Jul 05 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2207.1.0.0157
- ext4: correct the misjudgment in ext4_iget_extra_inode
- ext4: correct max_inline_xattr_value_size computing
- ext4: fix use-after-free in ext4_xattr_set_entry
- ext4: add EXT4_INODE_HAS_XATTR_SPACE macro in xattr.h
- tracepoint: Add tracepoint_probe_register_may_exist() for BPF tracing
- swiotlb: skip swiotlb_bounce when orig_addr is zero
- KVM: x86: Forbid VMM to set SYNIC/STIMER MSRs when SynIC wasn't activated
- mm/sharepool: Fix using uninitialized sp_flag
- mm/sharepool: Add a task_struct parameter for sp_get_local_group()
- mm/sharepool: Don't check the DVPP address space range before merging
- mm/sharepool: Configure the DVPP range for process
- mm/sharepool: Introduce SPG_NON_DVPP flag for sp_group_add_task
- mm/sharepool: Update sp_mapping structure
- mm/sharepool: Clear the initialization of sp-associated structure for a process
- mm/sharepool: Unify the memory allocation process
- mm/sharepool: Use vm_private_data to store the spa
- mm/sharepool: Share pool statistics adaption
- mm/sharepool: Release the sp addr based on the id
- mm/sharepool: Add an interface to obtain an id
- mm/sharepool: Address space management for sp_group
- mm/sharepool: Create global normal and dvpp mapping
- mm/sharepool: Delete single-group mode
- io_uring: io_close: Set owner as current->files if req->work.files uninitialized

* Mon Jun 27 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2206.4.0.0156
- mm/memcontrol: fix wrong vmstats for dying memcg
- ext4: recover csum seed of tmp_inode after migrating to extents
- xfs: show the proper user quota options
- drivers core: node: Use a more typical macro definition style for ACCESS_ATTR
- drivers core: Use sysfs_emit for shared_cpu_map_show and shared_cpu_list_show
- mm: and drivers core: Convert hugetlb_report_node_meminfo to sysfs_emit
- drivers core: Miscellaneous changes for sysfs_emit
- drivers core: Remove strcat uses around sysfs_emit and neaten
- drivers core: Use sysfs_emit and sysfs_emit_at for show(device *...) functions

* Mon Jun 20 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2206.3.0.0155
- arm64: fix out-of-range error when adapting for ARM64_SPECTRE_BHB
- xfs: replace -EIO with -EFSCORRUPTED for corrupt metadata
- xfs: namecheck directory entry names before listing them
- xfs: namecheck attribute names before listing them
- xfs: check attribute leaf block structure
- xfs: check attribute name validity
- xfs: check directory name validity
- xfs: scrub should flag dir/attr offsets that aren't mappable with xfs_dablk_t
- xfs: abort xattr scrub if fatal signals are pending
- tcp: increase source port perturb table to 2^16
- tcp: change source port randomizarion at connect() time
- arm64: fix extra cpucaps setup problem
- Revert "sched: Fix sched_fork() access an invalid sched_task_group"
- Revert "sched: Fix yet more sched_fork() races"
- powerpc/32: Fix overread/overwrite of thread_struct via ptrace
- sctp: use call_rcu to free endpoint
- ext4: convert from atomic_t to refcount_t on ext4_io_end->count
- ext4: correct the judgment of BUG in ext4_mb_normalize_request
- ext4: fix bug_on ext4_mb_use_inode_pa
- HID: holtek: fix mouse probing
- HID: check for valid USB device for many HID drivers
- HID: wacom: fix problems when device is not a valid USB device
- HID: add USB_HID dependancy on some USB HID drivers
- HID: add USB_HID dependancy to hid-chicony
- HID: add USB_HID dependancy to hid-prodikeys
- HID: add hid_is_usb() function to make it simpler for USB detection
- netfilter: nf_tables: disallow non-stateful expression in sets earlier
- NFSv4: fix open failure with O_ACCMODE flag
- Revert "NFSv4: Handle the special Linux file open access mode"

* Mon Jun 13 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2206.2.0.0154
- x86: Pin task-stack in __get_wchan()
- x86: Fix __get_wchan() for !STACKTRACE
- x86/unwind/orc: Fix premature unwind stoppage due to IRET frames
- x86/unwind: Prevent false warnings for non-current tasks
- ALSA: pcm: Fix potential AB/BA lock with buffer_mutex and mmap_lock
- ALSA: pcm: Fix races among concurrent prealloc proc writes
- ALSA: pcm: Fix races among concurrent prepare and hw_params/hw_free calls
- ALSA: pcm: Fix races among concurrent read/write and buffer changes
- ALSA: pcm: Fix races among concurrent hw_params and hw_free calls
- NFC: netlink: fix sleep in atomic bug when firmware download timeout
- nfc: replace improper check device_is_registered() in netlink related functions
- ext4: fix super block checksum incorrect after mount
- block: remove the bd_openers checks in blk_drop_partitions
- block: fix busy device checking in blk_drop_partitions again
- block: fix busy device checking in blk_drop_partitions
- ext4: add reserved GDT blocks check

* Mon Jun 06 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2206.1.0.0153
- ping: fix address binding wrt vrf
- tcp: resalt the secret every 10 seconds
- netlink: do not reset transport header in netlink_recvmsg()
- ipv4: drop dst in multicast routing path
- net: Fix features skip in for_each_netdev_feature()
- VFS: Fix memory leak caused by concurrently mounting fs with subtype
- mm: userfaultfd: fix missing cache flush in mcopy_atomic_pte() and __mcopy_atomic()
- mm: hugetlb: fix missing cache flush in copy_huge_page_from_user()
- dm: interlock pending dm_io and dm_wait_for_bios_completion
- dm: fix mempool NULL pointer race when completing IO
- tcp: make sure treq->af_specific is initialized
- net: igmp: respect RCU rules in ip_mc_source() and ip_mc_msfilter()
- x86: __memcpy_flushcache: fix wrong alignment if size > 2^32
- tcp: fix potential xmit stalls caused by TCP_NOTSENT_LOWAT
- ip_gre: Make o_seqno start from 0 in native mode
- tcp: md5: incorrect tcp_header_len for incoming connections
- mtd: rawnand: Fix return value check of wait_for_completion_timeout
- mtd: rawnand: fix ecc parameters for mt7622
- hex2bin: fix access beyond string end
- serial: 8250: Correct the clock for EndRun PTP/1588 PCIe device
- serial: 8250: Also set sticky MCR bits in console restoration
- ext4: force overhead calculation if the s_overhead_cluster makes no sense
- ext4: fix overhead calculation to account for the reserved gdt blocks
- ext4: limit length to bitmap_maxbytes - blocksize in punch_hole
- arm_pmu: Validate single/group leader events
- netlink: reset network and mac headers in netlink_dump()
- net/packet: fix packet_sock xmit return value checking
- mm: page_alloc: fix building error on -Werror=array-compare
- etherdevice: Adjust ether_addr* prototypes to silence -Wstringop-overead
- smp: Fix offline cpu check in flush_smp_call_function_queue()
- ipv6: fix panic when forwarding a pkt with no in6 dev
- mm: kmemleak: take a full lowmem check in kmemleak_*_phys()
- mm, page_alloc: fix build_zonerefs_node()
- cifs: potential buffer overflow in handling symlinks
- veth: Ensure eth header is in skb's linear part
- mm/sparsemem: fix 'mem_section' will never be NULL gcc 12 warning
- mm: don't skip swap entry even if zap_details specified
- irqchip/gic-v3: Fix GICR_CTLR.RWP polling
- mm/mempolicy: fix mpol_new leak in shared_policy_replace
- mmmremap.c: avoid pointless invalidate_range_start/end on mremap(old_size=0)
- mm: fix race between MADV_FREE reclaim and blkdev direct IO read
- NFS: swap-out must always use STABLE writes.
- NFS: swap IO handling is slightly different for O_DIRECT IO
- SUNRPC/call_alloc: async tasks mustn't block waiting for memory
- NFSv4: Protect the state recovery thread against direct reclaim
- macvtap: advertise link netns via netlink
- dm ioctl: prevent potential spectre v1 gadget
- ipv4: Invalidate neighbour for broadcast address upon address addition
- mm/memcontrol: return 1 from cgroup.memory __setup() handler
- ACPI: CPPC: Avoid out of bounds access when parsing _CPC data
- ext4: don't BUG if someone dirty pages without asking ext4 first
- PM: core: keep irq flags in device_pm_check_callbacks()
- ACPI/APEI: Limit printable size of BERT table data
- ACPICA: Avoid walking the ACPI Namespace if it is not there
- netfilter: nf_conntrack_tcp: preserve liberal flag in tcp options
- NFS: remove unneeded check in decode_devicenotify_args()
- serial: 8250: Fix race condition in RTS-after-send handling
- serial: 8250_mid: Balance reference count for PCI DMA device
- tcp: ensure PMTU updates are processed during fastopen
- af_netlink: Fix shift out of bounds in group mask calculation
- mtd: rawnand: atmel: fix refcount issue in atmel_nand_controller_init
- mtd: onenand: Check for error irq
- printk: fix return value of printk.devkmsg __setup handler
- perf/core: Fix address filter parser for multiple filters
- ACPI: APEI: fix return value of __setup handlers
- crypto: authenc - Fix sleep in atomic context in decrypt_tail
- PCI: pciehp: Clear cmd_busy bit in polling mode
- ACPI: properties: Consistently return -ENOENT if there are no more references
- mm,hwpoison: unmap poisoned page before invalidation
- scsi: libsas: Fix sas_ata_qc_issue() handling of NCQ NON DATA commands
- mempolicy: mbind_range() set_policy() after vma_merge()
- mm: invalidate hwpoison page cache page in fault path
- mm/pages_alloc.c: don't create ZONE_MOVABLE beyond the end of a node
- NFSD: prevent integer overflow on 32 bit systems
- SUNRPC: avoid race between mod_timer() and del_timer_sync()
- xfrm: fix tunnel model fragmentation behavior
- sched/fair: Fix enqueue_task_fair() warning some more
- sched/fair: Fix enqueue_task_fair warning
- floppy: disable FDRAWCMD by default
- perf: Fix sys_perf_event_open() race against self
- KVM: x86/mmu: fix NULL pointer dereference on guest INVPCID

* Tue May 31 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2205.6.0.0152
- net: hns3: update hns3 version to 22.5.1
- net: hns3: fix vf link setting failed when no vf driver loaded
- arm64: Add memmap reserve range check to avoid conflict
- ext4: fix bug_on in ext4_writepages
- ext4: fix warning in ext4_handle_inode_extension
- ext4: fix use-after-free in ext4_rename_dir_prepare
- uce: coredump scenario support kernel recovery
- NULL pointer dereference on rmmod iptable_mangle.

* Tue May 24 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2205.5.0.0151
- sched/qos: Add qos_tg_{throttle,unthrottle}_{up,down}
- sched: Throttle offline task at tracehook_notify_resume()
- sched: enable CONFIG_QOS_SCHED on arm64
- sched/qos: Remove dependency CONFIG_x86
- net/sched: cls_u32: fix netns refcount changes in u32_change()
- mm: hwpoison: enable memory error handling on 1GB hugepage optionaly
- mm: fix gup_pud_range
- nfc: nfcmrvl: main: reorder destructive operations in nfcmrvl_nci_unregister_dev to avoid bugs
- ext4: fix warning when submitting superblock in ext4_commit_super()
- ext4: fix bug_on in __es_tree_search
- secure_seq: use the 64 bits of the siphash for port offset calculation
- floppy: use a statically allocated error counter
- mmc: block: fix read single on recovery logic
- SUNRPC: Ensure that the gssproxy client can start in a connected state
- Revert "SUNRPC: attempt AF_LOCAL connect on setup"
- ax25: Fix UAF bugs in ax25 timers
- ptrace: Check PTRACE_O_SUSPEND_SECCOMP permission on PTRACE_SEIZE
- drm/vgem: Close use-after-free race in vgem_gem_create
- mm/memory.c: update the first page in clear_gigantic_page_chunk

* Tue May 17 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2205.4.0.0150
- scsi: hisi_sas: Change hisi_sas_control_phy() phyup timeout
- scsi: hisi_sas: Fix SAS disk sense info print incorrectly sometimes
- scsi: hisi_sas: Don't fail IT nexus reset for Open Reject timeout
- mm/share_pool: Support read-only memory allocation
- mm: clear_freelist_page: Provide timeout mechanism for worker runtime
- io_uring: fix race between timeout flush and removal
- ax25: fix UAF bug in ax25_send_control()
- ax25: Fix refcount leaks caused by ax25_cb_del()
- ax25: fix UAF bugs of net_device caused by rebinding operation
- ax25: fix reference count leaks of ax25_dev
- ax25: add refcount in ax25_dev to avoid UAF bugs
- ext4: fix bug_on in start_this_handle during umount filesystem
- ext4: unregister sysfs path before destroying jbd2 journal
- ext4: fix use-after-free in ext4_search_dir
- mm: Update reliable flag in memory allocaion for reliable task only in task context
- mm: refactor the reclaim thread of page cache from per-cpu to per-node

* Tue May 10 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2205.3.0.0149
- ixgbevf: add disable link state
- ixgbe: add improvement for MDD response functionality
- ixgbe: add the ability for the PF to disable VF link state
- io_uring: fix false WARN_ONCE
- mm/sharepool: Fix sharepool node id invalid when using sp_alloc
- sharepool: fix hisi oom deadlock
- share_pool: Fix ABBA deadlock
- net: ipv6: fix skb_over_panic in __ip6_append_data
- net: handle ARPHRD_PIMREG in dev_is_mac_header_xmit()
- net/packet: fix slab-out-of-bounds access in packet_recvmsg()
- mm: fix dereference a null pointer in migrate[_huge]_page_move_mapping()
- cpuset: Fix unsafe lock order between cpuset lock and cpuslock
- tcp: make tcp_read_sock() more robust
- xfrm: Fix xfrm migrate issues when address family changes
- Revert "xfrm: state and policy should fail if XFRMA_IF_ID 0"
- ext4: add check to prevent attempting to resize an fs with sparse_super2
- net-sysfs: add check for netdevice being present to speed_show
- memfd: fix F_SEAL_WRITE after shmem huge page allocated
- PCI: pciehp: Fix infinite loop in IRQ handler upon power fault
- netfilter: nf_queue: fix possible use-after-free
- netfilter: nf_queue: don't assume sk is full socket
- xfrm: enforce validity of offload input flags
- xfrm: fix the if_id check in changelink
- netfilter: fix use-after-free in __nf_register_net_hook()
- xfrm: fix MTU regression
- cifs: fix double free race when mount fails in cifs_get_root()
- mtd: rawnand: brcmnand: Fixed incorrect sub-page ECC status
- x86/asm: Move native_write_cr0/4() out of line
- x86/asm: Pin sensitive CR0 bits
- x86/asm: Pin sensitive CR4 bits
- mm: Add more debug info if oom occurs
- mm: Fix reliable task used problem shown in meminfo
- mm: Show correct reliable pagecache size

* Fri May 06 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2205.1.0.0148
- hamradio: improve the incomplete fix to avoid NPD
- hamradio: defer ax25 kfree after unregister_netdev
- can: mcba_usb: mcba_usb_start_xmit(): fix double dev_kfree_skb in error path
- llc: only change llc->dev when bind() succeeds
- netdevice: add the case if dev is NULL
- llc: fix netdevice reference leaks in llc_ui_bind()
- ARM: fix Thumb2 regression with Spectre BHB
- ARM: Spectre-BHB: provide empty stub for non-config
- ARM: fix build warning in proc-v7-bugs.c
- ARM: Do not use NOCROSSREFS directive with ld.lld
- ARM: fix co-processor register typo
- ARM: fix build error when BPF_SYSCALL is disabled
- ARM: include unprivileged BPF status in Spectre V2 reporting
- ARM: Spectre-BHB workaround
- ARM: use LOADADDR() to get load address of sections
- ARM: early traps initialisation
- ARM: report Spectre v2 status through sysfs
- can: usb_8dev: usb_8dev_start_xmit(): fix double dev_kfree_skb() in error path

* Tue Apr 26 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2204.4.0.0147
- Revert "perf: Paper over the hw.target problems"
- ax25: Fix NULL pointer dereferences in ax25 timers
- ax25: fix NPD bug in ax25_disconnect
- ax25: Fix NULL pointer dereference in ax25_kill_by_device
- ax25: improve the incomplete fix to avoid UAF and NPD bugs
- ax25: NPD bug when detaching AX25 device
- objtool: Fix stack offset tracking for indirect CFAs
- x86/entry/64: Fix unwind hints in kernel exit path
- af_key: add __GFP_ZERO flag for compose_sadb_supported in function pfkey_register
- arm64: Use the clearbhb instruction in mitigations
- arm64: add ID_AA64ISAR2_EL1 sys register
- KVM: arm64: Allow SMCCC_ARCH_WORKAROUND_3 to be discovered and migrated
- arm64: Mitigate spectre style branch history side channels
- KVM: arm64: Add templates for BHB mitigation sequences
- arm64: proton-pack: Report Spectre-BHB vulnerabilities as part of Spectre-v2
- arm64: Add percpu vectors for EL1
- arm64: entry: Add macro for reading symbol addresses from the trampoline
- arm64: entry: Add vectors that have the bhb mitigation sequences
- arm64: entry: Add non-kpti __bp_harden_el1_vectors for mitigations
- arm64: entry: Allow the trampoline text to occupy multiple pages
- arm64: entry: Make the kpti trampoline's kpti sequence optional
- arm64: entry: Move trampoline macros out of ifdef'd section
- arm64: entry: Don't assume tramp_vectors is the start of the vectors
- arm64: entry: Allow tramp_alias to access symbols after the 4K boundary
- arm64: entry: Move the trampoline data page before the text page
- arm64: entry: Free up another register on kpti's tramp_exit path
- arm64: entry: Make the trampoline cleanup optional
- arm64: entry.S: Add ventry overflow sanity checks
- x86/speculation: Warn about eIBRS + LFENCE + Unprivileged eBPF + SMT
- x86/speculation: Warn about Spectre v2 LFENCE mitigation
- x86/speculation: Update link to AMD speculation whitepaper
- x86/speculation: Use generic retpoline by default on AMD
- x86/speculation: Include unprivileged eBPF status in Spectre v2 mitigation reporting
- Documentation/hw-vuln: Update spectre doc
- x86/speculation: Add eIBRS + Retpoline options
- x86/speculation: Rename RETPOLINE_AMD to RETPOLINE_LFENCE
- x86,bugs: Unconditionally allow spectre_v2=retpoline,amd
- x86/speculation: Merge one test in spectre_v2_user_select_mitigation()
- mm/memory.c: fix clear_gigantic_page_chunk

* Tue Apr 19 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2204.3.0.0146
- ext4: fix fs corruption when tring to remove a non-empty directory with IO error
- Revert "ext4: fix file system corrupted when rmdir non empty directory with IO error"
- sched: Fix yet more sched_fork() races
- sched/fair: Fix wrong cpu selecting from isolated domain
- netfilter: nf_tables: initialize registers in nft_do_chain()
- nbd: fix possible overflow on 'first_minor' in nbd_dev_add()
- net: sched: adapt Qdisc kabi
- net_sched: fix a crash in tc_new_tfilter()
- net: sched: use Qdisc rcu API instead of relying on rtnl lock
- net: sched: add helper function to take reference to Qdisc
- net: sched: extend Qdisc with rcu
- net: core: netlink: add helper refcount dec and lock function
- xen/netfront: react properly to failing gnttab_end_foreign_access_ref()
- xen/gnttab: fix gnttab_end_foreign_access() without page specified
- xen/pvcalls: use alloc/free_pages_exact()
- xen/9p: use alloc/free_pages_exact()
- xen: remove gnttab_query_foreign_access()
- xen/gntalloc: don't use gnttab_query_foreign_access()
- xen/scsifront: don't use gnttab_query_foreign_access() for mapped status
- xen/netfront: don't use gnttab_query_foreign_access() for mapped status
- xen/blkfront: don't use gnttab_query_foreign_access() for mapped status
- xen/grant-table: add gnttab_try_end_foreign_access()
- xen/xenbus: don't let xenbus_grant_ring() remove grants in error case
- xen/xenbus: Fix granting of vmalloc'd memory
- binder: fix test regression due to sender_euid change
- binder: use cred instead of task for selinux checks
- binder: use euid from cred instead of using task
- svm: Change svm to modules
- svm: Delete unused svm_get_unmapped_area ops
- ascend: mm: Add MAP_ALIGN flag to map aligned va
- svm: Delete unused function sysrq_sched_debug_show_export
- svm: Delete get meminfo interface in svm ioctl
- svm: Export symbols for svm module
- can: ems_usb: ems_usb_start_xmit(): fix double dev_kfree_skb() in error path
- mm: Add space after ReliableFileCache
- mm: Drop reliable_reserve_size
- mm: page_counter: mitigate consequences of a page_counter underflow
- drivers: hamradio: 6pack: fix UAF bug caused by mod_timer()
- hamradio: remove needs_free_netdev to avoid UAF
- hamradio: defer 6pack kfree after unregister_netdev
- ovl: fix uninitialized pointer read in ovl_lookup_real_one()
- ovl: fix IOCB_DIRECT if underlying fs doesn't support direct IO
- ovl: fix lseek overflow on 32bit
- ovl: sync dirty data when remounting to ro mode

* Tue Apr 12 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2204.2.0.0145
- Revert "module, async: async_synchronize_full() on module init iff async is used"
- tty: n_gsm: fix encoding of control signal octet bit DV
- fget: clarify and improve __fget_files() implementation
- memblock: use kfree() to release kmalloced memblock regions
- tty: n_gsm: fix proper link termination after failed open
- gso: do not skip outer ip header in case of ipip and net_failover
- net: __pskb_pull_tail() & pskb_carve_frag_list() drop_monitor friends
- cgroup/cpuset: Fix a race between cpuset_attach() and cpu hotplug
- tracing: Fix tp_printk option related with tp_printk_stop_on_boot
- dmaengine: sh: rcar-dmac: Check for error num after setting mask
- net: sched: limit TC_ACT_REPEAT loops
- mtd: rawnand: qcom: Fix clock sequencing in qcom_nandc_probe()
- NFS: Do not report writeback errors in nfs_getattr()
- NFS: LOOKUP_DIRECTORY is also ok with symlinks
- bonding: fix data-races around agg_select_timer
- drop_monitor: fix data-race in dropmon_net_event / trace_napi_poll_hit
- ping: fix the dif and sdif check in ping_lookup
- taskstats: Cleanup the use of task->exit_code
- xfrm: Don't accidentally set RTO_ONLINK in decode_session4()
- nvme: fix a possible use-after-free in controller reset during load
- quota: make dquot_quota_sync return errors from ->sync_fs
- vfs: make freeze_super abort when sync_filesystem returns error
- serial: parisc: GSC: fix build when IOSAPIC is not set
- perf: Fix list corruption in perf_cgroup_switch()
- seccomp: Invalidate seccomp mode to catch death failures
- n_tty: wake up poll(POLLRDNORM) on receiving data
- veth: fix races around rq->rx_notify_masked
- net: fix a memleak when uncloning an skb dst and its metadata
- net: do not keep the dst cache when uncloning an skb dst and its metadata
- ipmr,ip6mr: acquire RTNL before calling ip[6]mr_free_table() on failure path
- bonding: pair enable_port with slave_arr_updates
- bpf: Add kconfig knob for disabling unpriv bpf by default
- scsi: target: iscsi: Make sure the np under each tpg is unique
- NFSv4 expose nfs_parse_server_name function
- NFSv4 remove zero number of fs_locations entries error check
- NFSv4.1: Fix uninitialised variable in devicenotify
- nfs: nfs4clinet: check the return value of kstrdup()
- NFSv4 only print the label when its queried
- NFS: Fix initialisation of nfs_client cl_flags field
- ima: Allow template selection with ima_template[_fmt]= after ima_hash=
- ima: Remove ima_policy file before directory
- integrity: check the return value of audit_log_start()
- ext4: fix error handling in ext4_restore_inline_data()
- iommu/amd: Fix loop timeout issue in iommu_ga_log_enable()
- iommu/vt-d: Fix potential memory leak in intel_setup_irq_remapping()
- block: bio-integrity: Advance seed correctly for larger interval sizes
- af_packet: fix data-race in packet_setsockopt / packet_setsockopt
- rtnetlink: make sure to refresh master_dev/m_ops in __rtnl_newlink()
- ipv4: tcp: send zero IPID in SYNACK messages
- ipv4: raw: lock the socket in raw_bind()
- phylib: fix potential use-after-free
- NFS: Ensure the server has an up to date ctime before renaming
- NFS: Ensure the server has an up to date ctime before hardlinking
- ipv6: annotate accesses to fn->fn_sernum
- ipv4: avoid using shared IP generator for connected sockets
- ping: fix the sk_bound_dev_if match in ping_lookup
- ipv6_tunnel: Rate limit warning messages
- tty: n_gsm: fix SW flow control encoding/handling
- serial: stm32: fix software flow control transfer
- serial: 8250: of: Fix mapped region size when using reg-offset property
- netfilter: nft_payload: do not update layer 4 checksum when mangling fragments
- PM: wakeup: simplify the output logic of pm_show_wakelocks()
- tty: fix crash in release_tty if tty->port is not set
- tty: don't crash in tty_init_dev when missing tty_port
- printk: Convert a use of sprintf to snprintf in console_unlock

* Thu Apr 07 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2204.1.0.0144
- serial: 8250: Fix max baud limit in generic 8250 port
- sched/fair: Add qos_throttle_list node in struct cfs_rq
- Reinstate some of "swiotlb: rework "fix info leak with DMA_FROM_DEVICE""
- Revert "swiotlb: rework "fix info leak with DMA_FROM_DEVICE""
- USB: gadget: validate endpoint index for xilinx udc
- sr9700: sanity check for packet length
- ima: Fix return value of ima_write_policy()
- ima: Don't modify file descriptor mode on the fly
- ima: Set file->f_mode instead of file->f_flags in ima_calc_file_hash()
- ima: Remove __init annotation from ima_pcrread()
- ima: Call ima_calc_boot_aggregate() in ima_eventdigest_init()
- evm: Check size of security.evm before using it
- ima: Don't ignore errors from crypto_shash_update()
- mm: Fallback to non-mirrored region below low watermark
- mm: Disable watermark check if reliable fallback is disabled
- mm: Do limit checking after memory allocation for memory reliable

* Tue Mar 29 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2203.5.0.0143
- livepatch/arm64: Fix incorrect endian conversion when long jump
- arm64/mpam: realign step entry when traversing rmid_transform
- dt-bindings: mpam: refactor device tree node structure
- arm64/mpam: refactor device tree structure to support multiple devices
- arm64/mpam: fix __mpam_device_create() section mismatch error
- block-map: add __GFP_ZERO flag for alloc_page in function bio_copy_kern
- hugetlb: Add huge page alloced limit
- swiotlb: rework "fix info leak with DMA_FROM_DEVICE"
- swiotlb: fix info leak with DMA_FROM_DEVICE
- esp: Fix possible buffer overflow in ESP transformation
- sock: remove one redundant SKB_FRAG_PAGE_ORDER macro
- io_uring: fix UAF in get_files_struct()
- xfs: fix an undefined behaviour in _da3_path_shift
- xfs: Fix possible null-pointer dereferences in xchk_da_btree_block_check_sibling()
- xfs: fix use after free in buf log item unlock assert
- ACPI/IORT: Do not blindly trust DMA masks from firmware

* Tue Mar 22 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2203.4.0.0142
- kabi: fix kabi broken in struct fuse_in
- fuse: fix pipe buffer lifetime for direct_io
- blk-throtl: fix race in io dispatching
- ext4: Fix symlink file size not match to file content
- livepatch/core: Check klp_func before 'klp_init_object_loaded'
- irqchip/gic-phytium-2500: Fix issue that interrupts are concentrated in one cpu
- blk-mq: add exception handling when srcu->sda alloc failed
- audit: improve audit queue handling when "audit=1" on cmdline
- Revert "audit: bugfix for infinite loop when flush the hold queue"
- veth: Do not record rx queue hint in veth_xmit

* Tue Mar 15 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2203.3.0.0141
- crypto: pcrypt - Fix user-after-free on module unload
- lib/iov_iter: initialize "flags" in new pipe_buffer
- mm: Count reliable shmem used based on NR_SHMEM
- mm: fix zoneref mapping problem in memory reliable
- mm: disable memory reliable when kdump is in progress
- mm: introduce "clear_freelist" kernel parameter
- mm: fix unable to use reliable memory in page cache
- nfc: st21nfca: Fix potential buffer overflows in EVT_TRANSACTION
- select: Fix indefinitely sleeping task in poll_schedule_timeout()
- mtd: nand: bbt: Fix corner case in bad block table handling
- netns: add schedule point in ops_exit_list()
- af_unix: annote lockless accesses to unix_tot_inflight & gc_in_progress
- crypto: stm32/crc32 - Fix kernel BUG triggered in probe()
- ext4: don't use the orphan list when migrating an inode
- ext4: set csum seed in tmp inode while migrating to extents
- ext4: make sure quota gets properly shutdown on error
- ext4: make sure to reset inode lockdep class when quota enabling fails
- cputime, cpuacct: Include guest time in user time in cpuacct.stat
- serial: Fix incorrect rs485 polarity on uart open
- scsi: sr: Don't use GFP_DMA
- dm space map common: add bounds check to sm_ll_lookup_bitmap()
- dm btree: add a defensive bounds check to insert_at()
- ACPICA: Executer: Fix the REFCLASS_REFOF case in acpi_ex_opcode_1A_0T_1R()
- ACPICA: Utilities: Avoid deleting the same object twice in a row
- jffs2: GC deadlock reading a page that is used in jffs2_write_begin()
- bpf: Do not WARN in bpf_warn_invalid_xdp_action()
- net: bonding: debug: avoid printing debug logs when bond is not notifying peers
- net-sysfs: update the queue counts in the unregistration path
- dmaengine: pxa/mmp: stop referencing config->slave_id
- scsi: ufs: Fix race conditions related to driver data
- iommu/io-pgtable-arm: Fix table descriptor paddr formatting
- ext4: avoid trim error on fs with small groups
- net: mcs7830: handle usb read errors properly
- tpm: add request_locality before write TPM_INT_ENABLE
- netfilter: ipt_CLUSTERIP: fix refcount leak in clusterip_tg_check()
- xfrm: state and policy should fail if XFRMA_IF_ID 0
- xfrm: interface with if_id 0 should return error
- crypto: stm32/cryp - fix double pm exit
- xfrm: fix a small bug in xfrm_sa_len()
- sched/rt: Try to restart rt period timer when rt runtime exceeded
- serial: amba-pl011: do not request memory region twice
- tty: serial: uartlite: allow 64 bit address
- netfilter: bridge: add support for pppoe filtering
- crypto: qce - fix uaf on qce_ahash_register_one
- shmem: fix a race between shmem_unused_huge_shrink and shmem_evict_inode
- can: bcm: switch timer to HRTIMER_MODE_SOFT and remove hrtimer_tasklet
- ip6_vti: initialize __ip6_tnl_parm struct in vti6_siocdevprivate
- scsi: libiscsi: Fix UAF in iscsi_conn_get_param()/iscsi_conn_teardown()
- ipv6: Do cleanup if attribute validation fails in multipath route
- ipv6: Continue processing multipath route even if gateway attribute is invalid
- ipv6: Check attribute length for RTA_GATEWAY when deleting multipath route
- ipv6: Check attribute length for RTA_GATEWAY in multipath route
- tracing: Tag trace_percpu_buffer as a percpu pointer
- tracing: Fix check for trace_percpu_buffer validity in get_trace_buf()
- net: fix use-after-free in tw_timer_handler
- udp: using datalen to cap ipv6 udp max gso segments
- selinux: initialize proto variable in selinux_ip_postroute_compat()
- x86/pkey: Fix undefined behaviour with PKRU_WD_BIT
- ipmi: fix initialization when workqueue allocation fails
- ipmi: bail out if init_srcu_struct fails
- bonding: fix ad_actor_system option setting to default
- ipmi: Fix UAF when uninstall ipmi_si and ipmi_msghandler module
- net: skip virtio_net_hdr_set_proto if protocol already set
- net: hns3: update hns3 version to 22.2.1
- net: hns3: fix RMW issue for VLAN filter switch
- net: hns3: fix pf vlan filter out of work after self test
- arm64: acpi: fix UBSAN warning
- sched: Fix sleeping in atomic context at cpu_qos_write()
- io_uring: don't re-setup vecs/iter in io_resumit_prep() is already there
- io_uring: don't double complete failed reissue request
- io_uring: remove redundant initialization of variable ret
- block: don't ignore REQ_NOWAIT for direct IO
- io_uring: re-issue block requests that failed because of resources
- dm multipath: fix missing blk_account_io_done() in error path
- block: account inflight from blk_account_io_start() if 'precise_iostat' is set
- block: add a switch for precise iostat accounting
- blk-throttle: Set BIO_THROTTLED when bio has been throttled
- bfq: fix use-after-free in bfq_dispatch_request
- hugetlbfs: fix a truncation issue in hugepages parameter

* Tue Mar 08 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2203.2.0.0140
- mm: Fix return val in khugepaged_scan_pmd()
- mm: do some clean up of accounting ReliableTaskUsed
- mm: fix statistic of ReliableTaskUsed
- mm: fix missing reclaim of low-reliable page cache
- mm: fix statistic of ReliableFileCache in /proc/meminfo
- mm: Add more gfp flag check in prepare_before_alloc()
- efi: Stub mirrored_kernelcore if CONFIG_HAVE_MEMBLOCK_NODE_MAP is not enabled
- mm: Memory reliable features can only be disabled via proc interface
- mm: Fix reliable_debug in proc not consistent with boot parameter problem
- f2fs: fix to do sanity check on inode type during garbage collection
- mm: Check page status in page_reliable()
- mm: Show ReliableTaskUsed in /proc/meminfo
- mm: Refactor code in reliable_report_meminfo()
- mm: Show correct reliable_user_used if PAGE_SIZE is not 4K
- proc: Fix reliable display err in /proc/pid/status
- Revert "mm: add page cache fallback statistic"
- mm: fix page cache use reliable memory when reliable_debug=P
- mm: add support for limiting the usage of reliable memory in pagecache
- mm: add "ReliableFileCache" item in /proc/meminfo
- mm: Introduce shmem mirrored memory limit for memory reliable
- mm: Introduce watermark check for memory reliable
- mm: Count mirrored pages in buddy system
- mm: Export mem_reliable_status() for checking memory reliable status
- mm: Make MEMORY_RELIABLE depends on HAVE_MEMBLOCK_NODE_MAP
- efi: Disable mirror feature if kernelcore is not spcified
- mm: Introduce proc interface to control memory reliable features
- mm: Demote warning message in vmemmap_verify() to debug level
- mm: Ratelimited mirrored memory related warning messages

* Tue Mar 01 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2203.1.0.0139
- usb: gadget: rndis: check size of RNDIS_MSG_SET command
- USB: gadget: validate interface OS descriptor requests
- mm/hwpoison: clear MF_COUNT_INCREASED before retrying get_any_page()
- udf: Restore i_lenAlloc when inode expansion fails
- udf: Fix NULL ptr deref when converting from inline format
- ext4: fix underflow in ext4_max_bitmap_size()
- bpf: Verifer, adjust_scalar_min_max_vals to always call update_reg_bounds()
- livepatch/x86: Fix incorrect use of 'strncpy'
- tipc: improve size validations for received domain records
- yam: fix a memory leak in yam_siocdevprivate()
- ipmi_si: Phytium S2500 missing timeout counter reset in intf_mem_inw
- mm,hwpoison: Fix use-after-free in memory_failure()
- dm-mpath: fix UAF in multipath_message()
- usb: gadget: clear related members when goto fail
- usb: gadget: don't release an existing dev->buf
- dm: make sure dm_table is binded before queue request
- cgroup-v1: Require capabilities to set release_agent
- NFSv4: nfs_atomic_open() can race when looking up a non-regular file
- NFSv4: Handle case where the lookup of a directory fails
- configfs: fix a race in configfs_{,un}register_subsystem()

* Tue Feb 22 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2202.4.0.0138
- tipc: improve size validations for received domain records
- yam: fix a memory leak in yam_siocdevprivate()
- ipmi_si: Phytium S2500 missing timeout counter reset in intf_mem_inw
- mm,hwpoison: Fix use-after-free in memory_failure()
- dm-mpath: fix UAF in multipath_message()
- usb: gadget: clear related members when goto fail
- usb: gadget: don't release an existing dev->buf
- dm: make sure dm_table is binded before queue request
- cgroup-v1: Require capabilities to set release_agent
- NFSv4: nfs_atomic_open() can race when looking up a non-regular file
- NFSv4: Handle case where the lookup of a directory fails
- configfs: fix a race in configfs_{,un}register_subsystem()
- fs/filesystems.c: downgrade user-reachable WARN_ONCE() to pr_warn_once()
- drm/i915: Flush TLBs before releasing backing store
- moxart: fix potential use-after-free on remove path
- memstick: rtsx_usb_ms: fix UAF

* Tue Feb 15 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2202.3.0.0137
- fs/filesystems.c: downgrade user-reachable WARN_ONCE() to pr_warn_once()
- drm/i915: Flush TLBs before releasing backing store
- moxart: fix potential use-after-free on remove path
- memstick: rtsx_usb_ms: fix UAF
- ext4: fix file system corrupted when rmdir non empty directory with IO error
- bpf, doc: Remove references to warning message when using bpf_trace_printk()
- bpf: Remove inline from bpf_do_trace_printk
- bpf: Use dedicated bpf_trace_printk event instead of trace_printk()
- net: cipso: fix warnings in netlbl_cipsov4_add_std
- xsk: Use struct_size() helper
- mm/page_alloc: fix counting of free pages after take off from buddy
- mm,hwpoison: drop unneeded pcplist draining
- mm,hwpoison: take free pages off the buddy freelists
- mm,hwpoison: drain pcplists before bailing out for non-buddy zero-refcount page
- mm,hwpoison: Try to narrow window race for free pages
- mm,hwpoison: introduce MF_MSG_UNSPLIT_THP
- mm,hwpoison: return 0 if the page is already poisoned in soft-offline
- mm,hwpoison: refactor soft_offline_huge_page and __soft_offline_page
- mm,hwpoison: rework soft offline for in-use pages
- mm,hwpoison: rework soft offline for free pages
- mm,hwpoison: unify THP handling for hard and soft offline
- mm,hwpoison: kill put_hwpoison_page
- mm,hwpoison: refactor madvise_inject_error
- mm,hwpoison-inject: don't pin for hwpoison_filter
- mm, hwpoison: remove recalculating hpage
- mm,hwpoison: cleanup unused PageHuge() check
- scsi: Revert "target: iscsi: Wait for all commands to finish before freeing a session"
- uce: get_user scenario support kernel recovery
- uce: copy_from_user scenario support kernel recovery
- mm: Modify sharepool sp_mmap() page_offset
- support multiple node for getting phys interface
- share_pool: Accept device_id in k2u flags
- share_pool: Clear the usage of node_id and device_id
- share_pool: Make multi-device support extendable
- share_pool: Fix flags conflict
- config: enable MEMORY_RELIABLE by default
- mm: add sysctl to clear free list pages
- workqueue: Provide queue_work_node to queue work near a given NUMA node
- mm:vmscan: add the missing check of page_cache_over_limit
- sysctl: add proc interface to set page cache limit
- mm/vmscan: dont do shrink_slab in reclaim page cache
- mm/vmscan: dont reclaim anon page when shrink page cache
- filemap: dont shrink_page_cache in add_to_page_cache
- mm/vmscan: fix unexpected shrinking page cache with vm_cache_reclaim_enable disable
- mm/vmscan: fix frequent call of shrink_page_cache_work
- proc/meminfo: add "FileCache" item in /proc/meminfo
- mm: add page cache fallback statistic
- mm: add cmdline for the reliable memory usage of page cache
- mm: make page cache use reliable memory by default
- shmem: Show reliable shmem info
- shmem: Introduce shmem reliable
- mm: Introduce fallback mechanism for memory reliable
- mm: Add reliable memory use limit for user tasks
- mm: thp: Add memory reliable support for hugepaged collapse
- proc: Count reliable memory usage of reliable tasks
- mm: Add reliable_nr_page for accounting reliable memory
- mm: Introduce reliable flag for user task
- meminfo: Show reliable memory info
- mm: Introduce memory reliable
- efi: Find mirrored memory ranges for arm64
- efi: Make efi_find_mirror() public
- arm64: efi: Add fake memory support
- efi: Make efi_print_memmap() public
- mm/memory_hotplug: allow to specify a default online_type
- mm/memory_hotplug: convert memhp_auto_online to store an online_type
- hv_balloon: don't check for memhp_auto_online manually
- drivers/base/memory: store mapping between MMOP_* and string in an array
- drivers/base/memory: map MMOP_OFFLINE to 0
- drivers/base/memory: rename MMOP_ONLINE_KEEP to MMOP_ONLINE
- drivers/base/memory.c: Use DEVICE_ATTR_RO and friends
- mm/memory_hotplug: drop "online" parameter from add_memory_resource()

* Tue Feb 08 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2202.1.0.0136
- config: enable CONFIG_MEMCG_MEMFS_INFO by default
- mm/memcg_memfs_info: show files that having pages charged in mem_cgroup
- ext4: fix e2fsprogs checksum failure for mounted filesystem
- drm/vmwgfx: Fix stale file descriptors on failed usercopy
- perf vendor events amd: Fix broken L2 Cache Hits from L2 HWPF metric
- perf vendor events amd: Add recommended events
- perf vendor events amd: Add L2 Prefetch events for zen1
- perf/amd/uncore: Fix sysfs type mismatch
- perf/x86/amd: Don't touch the AMD64_EVENTSEL_HOSTONLY bit inside the guest
- tools/power turbostat: Support AMD Family 19h
- perf/x86/amd/ibs: Support 27-bit extended Op/cycle counter
- perf vendor events amd: Enable Family 19h users by matching Zen2 events
- perf vendor events amd: Update Zen1 events to V2
- perf vendor events amd: Add Zen2 events
- perf vendor events amd: Restrict model detection for zen1 based processors
- perf vendor events amd: Remove redundant '['
- perf vendor events intel: Add Tremontx event file v1.02
- perf vendor events intel: Add Icelake V1.00 event file
- perf vendor events amd: Add L3 cache events for Family 17h
- perf vendor events intel: Add uncore_upi JSON support
- perf vendor events amd: perf PMU events for AMD Family 17h
- perf/amd/uncore: Allow F19h user coreid, threadmask, and sliceid specification
- perf/amd/uncore: Allow F17h user threadmask and slicemask specification
- perf/amd/uncore: Prepare to scale for more attributes that vary per family
- perf/x86/amd/ibs: Don't include randomized bits in get_ibs_op_count()
- perf/amd/uncore: Set all slices and threads to restore perf stat -a behaviour
- perf/x86/amd/ibs: Fix raw sample data accumulation
- arch/x86/amd/ibs: Fix re-arming IBS Fetch
- perf/amd/uncore: Add support for Family 19h L3 PMU
- perf/amd/uncore: Make L3 thread mask code more readable
- perf/amd/uncore: Prepare L3 thread mask code for Family 19h
- EDAC/amd64: Handle three rank interleaving mode
- EDAC/amd64: Add family ops for Family 19h Models 00h-0Fh
- EDAC/amd64: Save max number of controllers to family type
- EDAC/amd64: Gather hardware information early
- EDAC/amd64: Make struct amd64_family_type global
- EDAC/amd64: Set grain per DIMM
- EDAC/amd64: Support asymmetric dual-rank DIMMs
- EDAC/amd64: Cache secondary Chip Select registers
- EDAC/amd64: Add PCI device IDs for family 17h, model 70h
- EDAC/amd64: Find Chip Select memory size using Address Mask
- EDAC/amd64: Adjust printed chip select sizes when interleaved
- EDAC/amd64: Recognize x16 symbol size
- EDAC/amd64: Set maximum channel layer size depending on family
- EDAC/amd64: Support more than two Unified Memory Controllers
- EDAC/amd64: Add Family 17h Model 30h PCI IDs
- EDAC/amd64: Initialize DIMM info for systems with more than two channels
- EDAC/amd64: Support more than two controllers for chip selects handling
- EDAC/amd64: Use a macro for iterating over Unified Memory Controllers
- x86/mce: Fix use of uninitialized MCE message string
- x86/MCE/AMD, EDAC/mce_amd: Add new Load Store unit McaType
- x86/MCE/AMD, EDAC/mce_amd: Add new error descriptions for some SMCA bank types
- x86/MCE/AMD, EDAC/mce_amd: Add new McaTypes for CS, PSP, and SMU units
- x86/MCE/AMD, EDAC/mce_amd: Add new MP5, NBIO, and PCIE SMCA bank types
- EDAC/mce_amd: Always load on SMCA systems
- x86/cpu/amd: Call init_amd_zn() om Family 19h processors too
- x86/amd_nb: Add Family 19h PCI IDs
- x86/amd_nb: Add PCI device IDs for family 17h, model 70h
- x86/amd_nb: Add PCI device IDs for family 17h, model 30h
- hwmon/k10temp, x86/amd_nb: Consolidate shared device IDs
- EDAC/amd64: Drop some family checks for newer systems
- x86/microcode/AMD: Increase microcode PATCH_MAX_SIZE
- KVM: mmu: Fix SPTE encoding of MMIO generation upper half
- build_bug.h: add wrapper for _Static_assert
- KVM: x86: fix overlap between SPTE_MMIO_MASK and generation
- KVM: x86: assign two bits to track SPTE kinds
- KVM: Move the memslot update in-progress flag to bit 63
- KVM: Remove the hack to trigger memslot generation wraparound
- KVM: x86: clflushopt should be treated as a no-op by emulation
- KVM: SVM: Clear the CR4 register on reset
- KVM: SVM: Replace hard-coded value with #define
- KVM: x86/mmu: Set mmio_value to '0' if reserved #PF can't be generated
- KVM: x86/mmu: Apply max PA check for MMIO sptes to 32-bit KVM
- KVM: x86: only do L1TF workaround on affected processors
- kvm: x86: Fix L1TF mitigation for shadow MMU
- KVM: x86/mmu: Consolidate "is MMIO SPTE" code
- KVM: SVM: Override default MMIO mask if memory encryption is enabled
- KVM: x86/mmu: Add explicit access mask for MMIO SPTEs
- kvm: x86: Fix reserved bits related calculation errors caused by MKTME
- KVM: x86: Rename access permissions cache member in struct kvm_vcpu_arch
- kvm: x86: Move kvm_set_mmio_spte_mask() from x86.c to mmu.c
- kvm/svm: PKU not currently supported
- kvm: x86: Expose RDPID in KVM_GET_SUPPORTED_CPUID
- KVM: x86: Refactor the MMIO SPTE generation handling
- KVM: Explicitly define the "memslot update in-progress" bit
- KVM: x86: Use a u64 when passing the MMIO gen around
- KVM: x86: expose MOVDIR64B CPU feature into VM.
- KVM: x86: expose MOVDIRI CPU feature into VM.
- KVM: x86: Add requisite includes to hyperv.h
- KVM: x86: Add requisite includes to kvm_cache_regs.h
- KVM: nVMX: Allocate and configure VM{READ,WRITE} bitmaps iff enable_shadow_vmcs
- x86/cpufeatures: Enumerate MOVDIR64B instruction
- x86/cpufeatures: Enumerate MOVDIRI instruction
- x86/pkeys: Don't check if PKRU is zero before writing it
- x86/fpu: Only write PKRU if it is different from current
- x86/pkeys: Provide *pkru() helpers
- sysctl: returns -EINVAL when a negative value is passed to proc_doulongvec_minmax
- arm64: move jump_label_init() before parse_early_param()
- tcp: fix memleak when tcp internal pacing is used
- scsi: scsi_debug: Sanity check block descriptor length in resp_mode_select()
- ovl: fix warning in ovl_create_real()
- fuse: annotate lock in fuse_reverse_inval_entry()
- PCI/MSI: Clear PCI_MSIX_FLAGS_MASKALL on error
- sit: do not call ipip6_dev_free() from sit_init_net()
- net/packet: rx_owner_map depends on pg_vec
- x86/sme: Explicitly map new EFI memmap table as encrypted
- dm btree remove: fix use after free in rebalance_children()
- net: netlink: af_netlink: Prevent empty skb by adding a check on len.
- irqchip/irq-gic-v3-its.c: Force synchronisation when issuing INVALL
- net, neigh: clear whole pneigh_entry at alloc time
- aio: fix use-after-free due to missing POLLFREE handling
- aio: keep poll requests on waitqueue until completed
- signalfd: use wake_up_pollfree()
- wait: add wake_up_pollfree()
- tracefs: Have new files inherit the ownership of their parent
- mm: bdi: initialize bdi_min_ratio when bdi is unregistered
- udp: using datalen to cap max gso segments
- bpf: Fix the off-by-two error in range markings
- ipmi: msghandler: Make symbol 'remove_work_wq' static
- serial: core: fix transmit-buffer reset and memleak
- serial: pl011: Add ACPI SBSA UART match id
- net: annotate data-races on txq->xmit_lock_owner
- ipmi: Move remove_work to dedicated workqueue
- vrf: Reset IPCB/IP6CB when processing outbound pkts in vrf dev xmit
- scsi: iscsi: Unblock session then wake up error handler
- shm: extend forced shm destroy to support objects from several IPC nses
- fuse: release pipe buf after last use
- tracing: Check pid filtering when creating events
- ipv6: fix typos in __ip6_finish_output()
- proc/vmcore: fix clearing user buffer by properly using clear_user()
- tracing: Fix pid filtering when triggers are attached
- fuse: fix page stealing
- ipmi_si: Phytium S2500 workaround for MMIO-based IPMI
- etmem: Add a scan flag to support specified page swap-out
- etmem: add swapcache reclaim to etmem
- etmem: add original kernel swap enabled options

* Tue Jan 25 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2201.4.0.0135
- net: bridge: clear bridge's private skb space on xmit
- audit: bugfix for infinite loop when flush the hold queue
- blk-throttle: enable hierarchical throttle in cgroup v1
- xfs: map unwritten blocks in XFS_IOC_{ALLOC,FREE}SP just like fallocate

* Tue Jan 18 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2201.3.0.0134
- ip_gre: validate csum_start only on pull
- hugetlbfs: fix issue of preallocation of gigantic pages can't work
- hugetlbfs: extend the definition of hugepages parameter to support node allocation
- mm: remove sharepool sp_unshare_uva current->mm NULL check
- share pool: use rwsem to protect sp group exit
- Add new module parameters:time out
- virtio-blk: validate num_queues during probe
- virtio-blk: Use blk_validate_block_size() to validate block size
- block: Add a helper to validate the block size
- Revert "virtio-blk: Add validation for block size in config space"
- scsi: virtio_scsi: Rescan the entire target on transport reset when LUN is 0
- Revert "svm: Add support to get svm mpam configuration"
- Revert "svm: Add support to set svm mpam configuration"
- Revert "svm: Add svm_set_user_mpam_en to enable/disable mpam for smmu"
- cgroup: Use open-time cgroup namespace for process migration perm checks
- cgroup: Allocate cgroup_file_ctx for kernfs_open_file->priv
- cgroup: Use open-time credentials for process migraton perm checks
- NFC: add necessary privilege flags in netlink layer
- NFC: add NCI_UNREG flag to eliminate the race
- NFC: reorder the logic in nfc_{un,}register_device
- NFC: reorganize the functions in nci_request
- ext4: Fix BUG_ON in ext4_bread when write quota data
- PM: hibernate: use correct mode for swsusp_close()
- Revert "watchdog: Fix check_preemption_disabled() error"

* Tue Jan 11 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2201.2.0.0133
- arm64/mpam: fix mpam dts init arm_mpam_of_device_ids error
- arm64/mpam: fix mpam probe error for wrong init order

* Tue Jan 04 2022 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2201.1.0.0132
- mm: export collect_procs()
- net: hns: update hns version to 21.12.1
- net: hns: fix bug when two ports opened promisc mode both
- net: hns3: update hns3 version to 21.12.4
- net: hns3: fix the concurrency between functions reading debugfs
- f2fs: fix to do sanity check on last xattr entry in __f2fs_setxattr()
- mwifiex: Fix skb_over_panic in mwifiex_usb_recv()
- tee: handle lookup of shm with reference count 0
- tee: don't assign shm id for private shms
- tee: remove linked list of struct tee_shm
- ext4: fix an use-after-free issue about data=journal writeback mode
- ext4: Fix null-ptr-deref in '__ext4_journal_ensure_credits'
- scsi: ufs: Correct the LUN used in eh_device_reset_handler() callback
- netdevsim: Zero-initialize memory for new map's value in function nsim_bpf_map_alloc
- lib/strncpy_from_user.c: Mask out bytes after NUL terminator.
- bpf: Add probe_read_{user, kernel} and probe_read_{user, kernel}_str helpers
- bpf: Make use of probe_user_write in probe write helper
- uaccess: Add strict non-pagefault kernel-space read function
- bpf: fix script for generating man page on BPF helpers
- bpf: Backport __BPF_FUNC_MAPPER and annotation from mainline
- bpf: Fix up register-based shifts in interpreter to silence KUBSAN
- xen/netback: don't queue unlimited number of packages
- xen/netback: fix rx queue stall detection
- xen/console: harden hvc_xen against event channel storms
- xen/netfront: harden netfront against event channel storms
- xen/blkfront: harden blkfront against event channel storms
- xen/netfront: don't trust the backend response data blindly
- xen/netfront: disentangle tx_skb_freelist
- xen/netfront: don't read data from request on the ring page
- xen/netfront: read response from backend only once
- xen/blkfront: don't trust the backend response data blindly
- xen/blkfront: don't take local copy of a request from the ring page
- xen/blkfront: read response from backend only once
- xen: sync include/xen/interface/io/ring.h with Xen's newest version
- xen/netback: avoid race in xenvif_rx_ring_slots_available()
- netfilter: fix regression in looped (broad|multi)cast's MAC handling
- perf/core: Avoid put_page() when GUP fails
- perf/core: Disable page faults when getting phys address
- mm: kmemleak: slob: respect SLAB_NOLEAKTRACE flag
- ipc: WARN if trying to remove ipc object which is absent
- tun: fix bonding active backup with arp monitoring
- perf/x86/intel/uncore: Fix IIO event constraints for Skylake Server
- perf/x86/intel/uncore: Fix filter_tid mask for CHA events on Skylake Server
- sched/core: Mitigate race cpus_share_cache()/update_top_cache_domain()
- tty: tty_buffer: Fix the softlockup issue in flush_to_ldisc
- PCI/MSI: Deal with devices lying about their MSI mask capability
- PCI/MSI: Destroy sysfs before freeing entries
- ext4: fix lazy initialization next schedule time computation in more granular unit
- x86/cpu: Fix migration safety with X86_BUG_NULL_SEL
- mm, oom: do not trigger out_of_memory from the #PF
- mm, oom: pagefault_out_of_memory: don't force global OOM for dying tasks
- llc: fix out-of-bound array index in llc_sk_dev_hash()
- zram: off by one in read_block_state()
- mm/zsmalloc.c: close race window between zs_pool_dec_isolated() and zs_unregister_migration()
- dmaengine: dmaengine_desc_callback_valid(): Check for `callback_result`
- netfilter: nfnetlink_queue: fix OOB when mac header was cleared
- NFS: Fix deadlocks in nfs_scan_commit_list()
- apparmor: fix error check
- serial: 8250_dw: Drop wrong use of ACPI_PTR()
- crypto: pcrypt - Delay write to padata->info
- tcp: don't free a FIN sk_buff in tcp_remove_empty_skb()
- cgroup: Make rebind_subsystems() disable v2 controllers all at once
- task_stack: Fix end_of_stack() for architectures with upwards-growing stack
- gre/sit: Don't generate link-local addr if addr_gen_mode is IN6_ADDR_GEN_MODE_NONE
- smackfs: Fix use-after-free in netlbl_catmap_walk()
- signal: Remove the bogus sigkill_pending in ptrace_stop
- bpf: Prevent increasing bpf_jit_limit above max
- x86/sme: Use #define USE_EARLY_PGTABLE_L5 in mem_encrypt_identity.c
- tpm: Check for integer overflow in tpm2_map_response_body()
- scsi: core: Put LLD module refcnt after SCSI device is released
- net: Prevent infinite while loop in skb_tx_hash()

* Thu Dec 30 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2112.8.0.0131
- mm/page_alloc: Use cmdline to disable "place pages to tail"
- bpf: Remove MTU check in __bpf_skb_max_len
- sctp: account stream padding length for reconf chunk

* Tue Dec 28 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2112.6.0.0130
- watchdog: Fix check_preemption_disabled() error
- btrfs: unlock newly allocated extent buffer after error
- net/hinic: Fix call trace when the rx_buff module parameter is grater than 2
- dt-bindings: mpam: add document for arm64 mpam
- arm64/mpam: add device tree support for mpam initialization
- arm64/mpam: remove __init macro to support driver probe
- arm64/mpam: rmid: refine allocation and release process
- arm64/mpam: resctrl: add tips when rmid modification failed
- arm64/mpam: Fix mpam corrupt when cpu online
- cpufreq: schedutil: Destroy mutex before kobject_put() frees the memory
- kprobes: Fix optimize_kprobe()/unoptimize_kprobe() cancellation logic
- kprobes: Set unoptimized flag after unoptimizing code

* Wed Dec 22 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2112.5.0.0129
- config: enable CONFIG_RAMAXEL_SPRAID by default
- scsi:spraid: support Ramaxel's spraid driver
- USB: gadget: bRequestType is a bitfield, not a enum
- phonet: refcount leak in pep_sock_accep
- USB: gadget: detect too-big endpoint 0 requests

* Tue Dec 21 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2112.4.0.0128
- block, bfq: don't move oom_bfqq
- blk-mq: fix abnormal free in single queue process
- scsi: hisi_sas: Add support for sata disk I/O errors report to libsas
- KVM: arm64: Allow vcpus running without HCR_EL2.FB
- KVM: arm64: Set kvm_vcpu::pre_pcpu properly
- KVM: arm64: Ensure I-cache isolation between vcpus of a same VM
- arm64/tlbi: mark tlbi ipi as EXPERIMENTAL
- arm64/tlb: restore no IPi code
- arm64/configs: enable TLBI_IPI
- arm64/tlbi: split disable_tlbflush_is to control flush
- arm64/tlb: add CONFIG_ARM64_TLBI_IPI
- arm64: tlb: Add boot parameter to disable TLB flush within the same inner shareable domain
- arm64: mm: Restore mm_cpumask (revert commit 38d96287504a ("arm64: mm: kill mm_cpumask usage"))
- audit: ensure userspace is penalized the same as the kernel when under pressure
- audit: improve robustness of the audit queue handling
- block/wbt: fix negative inflight counter when remove scsi device
- nbd: Fix use-after-free in blk_mq_free_rqs
- block, bfq: fix use after free in bfq_bfqq_expire
- block, bfq: fix queue removal from weights tree
- block, bfq: fix decrement of num_active_groups
- block, bfq: fix asymmetric scenarios detection
- block, bfq: improve asymmetric scenarios detection
- fget: check that the fd still exists after getting a ref to it
- config: Enable CONFIG_EXT4_PARALLEL_DIO_READ as default
- ext4: update direct I/O read lock pattern for IOCB_NOWAIT
- Revert "Revert "ext4: remove EXT4_STATE_DIOREAD_LOCK flag""
- Revert "Revert "ext4: Allow parallel DIO reads""
- net: hns3: update hns3 version to 21.12.3
- net: hns3: fix the VLAN of a vf cannot be added problem
- net: hns3: fix pfc packet number incorrect after querying pfc parameters
- net: hns3: fix VF RSS failed problem after PF enable multi-TCs
- usb: gadget: configfs: Fix use-after-free issue with udc_name
- hugetlbfs: flush TLBs correctly after huge_pmd_unshare
- mm: share_pool: adjust sp_alloc behavior when coredump
- mm: share_pool: adjust sp_make_share_k2u behavior when coredump
- Revert "timekeeping: Fix ktime_add overflow in tk_set_wall_to_mono"
- Revert "timekeeping: Avoid undefined behaviour in 'ktime_get_with_offset()'"
- Revert "posix-cpu-timers: Avoid undefined behaviour in timespec64_to_ns()"
- time: Normalize timespec64 before timespec64_compare()
- iommu/arm-smmu-v3: remove unnecessary mpam enable procedure
- fix kabi effect by change in md_rdev
- Revert "dm space maps: don't reset space map allocation cursor when committing"
- nvme-fabrics: fix kabi broken by "reject I/O to offline device"
- nvme: fix NULL derefence in nvme_ctrl_fast_io_fail_tmo_show/store
- nvme: export fast_io_fail_tmo to sysfs
- nvme-fabrics: reject I/O to offline device
- nvme: add a Identify Namespace Identification Descriptor list quirk
- nvme: fix identify error status silent ignore
- nvme: fix possible hang when ns scanning fails during error recovery
- nvme: refactor nvme_identify_ns_descs error handling
- nvme: Namepace identification descriptor list is optional
- nvmet: use new ana_log_size instead the old one
- nvme-multipath: fix double initialization of ANA state
- nvme-core: use list_add_tail_rcu instead of list_add_tail for nvme_init_ns_head
- nvme: make nvme_report_ns_ids propagate error back
- nvme-multipath: avoid crash on invalid subsystem cntlid enumeration
- nvme-multipath: split bios with the ns_head bio_set before submitting
- nvme: add proper discard setup for the multipath device
- fix kabi change
- md: Fix undefined behaviour in is_mddev_idle
- xfs: fix up non-directory creation in SGID directories
- xfs: remove the kuid/kgid conversion wrappers
- xfs: remove the icdinode di_uid/di_gid members
- xfs: ensure that the inode uid/gid match values match the icdinode ones
- configfs: fix a use-after-free in __configfs_open_file
- share_pool: don't trace the invalid spa address
- share_pool: Remove the redundant warning message

* Mon Dec 13 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2112.3.0.0127
- ixgbe: fix large MTU request from VF
- block, bfq: move bfqq to root_group if parent group is offlined
- io_uring: use bottom half safe lock for fixed file data
- io_uring: fix soft lockup when call __io_remove_buffers
- block: Fix fsync always failed if once failed
- blk-mq: use the new flag to quiesce/unquiesce queue in block layer
- blk-mq: add a new queue flag to quiesce/unquiesce queue
- blk-mq: factor out some helps to quiesce/unquiesce queue
- blk: Fix lock inversion between ioc lock and bfqd lock
- bfq: Remove merged request already in bfq_requests_merged()
- md: fix a warning caused by a race between concurrent md_ioctl()s
- net: hns3: update hns3 version to 21.12.2
- net: hns3: fix race condition in debugfs
- kabi: fix kabi broken in struct sock
- tracing: Have all levels of checks prevent recursion
- netfilter: Kconfig: use 'default y' instead of 'm' for bool config option
- mm, slub: fix mismatch between reconstructed freelist depth and cnt
- vfs: check fd has read access in kernel_read_file_from_fd()
- dma-debug: fix sg checks in debug_dma_map_sg()
- acpi/arm64: fix next_platform_timer() section mismatch error
- x86/resctrl: Free the ctrlval arrays when domain_setup_mon_state() fails
- sched: Always inline is_percpu_thread()
- perf/x86: Reset destroy callback on event init failure
- net: prevent user from passing illegal stab size
- netfilter: ip6_tables: zero-initialize fragment offset
- rtnetlink: fix if_nlmsg_stats_size() under estimation
- netlink: annotate data races around nlk->bound
- net: bridge: use nla_total_size_64bit() in br_get_linkxstats_size()
- net_sched: fix NULL deref in fifo_set_limit()
- phy: mdio: fix memory leak
- bpf, arm: Fix register clobbering in div/mod implementation
- scsi: sd: Free scsi_disk device via put_device()
- cred: allow get_cred() and put_cred() to be given NULL.
- net: udp: annotate data race around udp_sk(sk)->corkflag
- elf: don't use MAP_FIXED_NOREPLACE for elf interpreter mappings
- af_unix: fix races in sk_peer_pid and sk_peer_cred accesses
- cpufreq: schedutil: Use kobject release() method to free sugov_tunables
- tty: Fix out-of-bound vmalloc access in imageblit
- tcp: address problems caused by EDT misshaps
- arm64: Mark __stack_chk_guard as __ro_after_init
- md: fix a lock order reversal in md_alloc
- irqchip/gic-v3-its: Fix potential VPE leak on error
- scsi: iscsi: Adjust iface sysfs attr detection
- serial: mvebu-uart: fix driver's tx_empty callback
- cifs: fix incorrect check for null pointer in header_assemble

* Tue Dec 07 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2112.1.0.0126
- arm64: Fix conflict for capability when cpu hotplug
- mm: memcontrol: fix cpuhotplug statistics flushing
- mm, memcg: fix error return value of mem_cgroup_css_alloc()
- mm/memcontrol: fix a data race in scan count
- GPIO : support ascend_gpio_dwapb_enable switch
- ext4: always panic when errors=panic is specified
- config: disable CONFIG_NGBE by default in hulk_defconfig
- x86/config: Enable netswift Giga NIC driver for x86
- net: ngbe: Add Netswift Giga NIC driver
- ras: report cpu logical index to userspace in arm event
- arm64: Avoid premature usercopy failure
- hugetlb: before freeing hugetlb page set dtor to appropriate value

* Tue Nov 30 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2111.7.0.0125
- defconfig: update the defconfigs to support 9P
- sched: Introduce handle priority reversion mechanism
- sched: unthrottle qos cfs rq when free a task group
- sched: Avoid sched entity null pointer panic
- sched: Clear idle_stamp when unthrottle offline tasks
- sched: Fix offline task can't be killed in a timely
- sched: Optimizing qos scheduler performance
- sched: Fix throttle offline task trigger panic
- sched: Remove residual checkings for qos scheduler
- sched: Change cgroup task scheduler policy
- sched: Unthrottle the throttled cfs rq when offline rq
- sched: Enable qos scheduler config
- sched: Throttle qos cfs_rq when current cpu is running online task
- sched: Introduce qos scheduler for co-location
- io_uring: return back safer resurrect
- cpufreq: Fix get_cpu_device() failed in add_cpu_dev_symlink()
- ACPI: CPPC: Fix cppc_cpufreq_init failed in CPU Hotplug situation
- lib/clear_user: ensure loop in __arch_clear_user cache-aligned v2

* Wed Nov 24 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2111.6.0.0124
- drm/ioctl: Ditch DRM_UNLOCKED except for the legacy vblank ioctl
- config: Enable some configs for test
- share_pool: add mm address check when access the process's sp_group file

* Tue Nov 23 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2111.5.0.0123
- rq-qos: fix missed wake-ups in rq_qos_throttle try two
- atlantic: Fix OOB read and write in hw_atl_utils_fw_rpc_wait
- drivers : remove drivers/mtd/hisilicon/sfc
- drivers : remove drivers/soc/hisilicon/sysctl
- drivers : remove drivers/soc/hisilicon/lbc
- ipv4: fix uninitialized warnings in fnhe_remove_oldest()
- crypto: public_key: fix overflow during implicit conversion
- net: bridge: fix stale eth hdr pointer in br_dev_xmit
- x86/entry: Make entry_64_compat.S objtool clean

* Tue Nov 16 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2111.4.0.0122
- io_uring: fix ltout double free on completion race
- iommu: smmuv2: fix compile error when CONFIG_ARCH_PHYTIUM is off
- crypto: hisilicon delete invlaid api and config
- crypto: hisilicon - add CRYPTO_TFM_REQ_MAY_BACKLOG flag judge in sec_process()
- tcp: adjust rto_base in retransmits_timed_out()
- tcp: create a helper to model exponential backoff
- tcp: always set retrans_stamp on recovery
- profiling: fix shift-out-of-bounds bugs
- prctl: allow to setup brk for et_dyn executables
- dmaengine: acpi: Avoid comparison GSI with Linux vIRQ
- tracing/kprobe: Fix kprobe_on_func_entry() modification
- rcu: Fix missed wakeup of exp_wq waiters
- netfilter: socket: icmp6: fix use-after-scope
- PCI: Sync __pci_register_driver() stub for CONFIG_PCI=n
- PCI: Fix pci_dev_str_match_path() alloc while atomic bug
- block, bfq: honor already-setup queue merges
- mm/memory_hotplug: use "unsigned long" for PFN in zone_for_pfn_range()
- tcp: fix tp->undo_retrans accounting in tcp_sacktag_one()
- net/af_unix: fix a data-race in unix_dgram_poll
- events: Reuse value read using READ_ONCE instead of re-reading it
- x86/mm: Fix kern_addr_valid() to cope with existing but not present entries
- arm64/sve: Use correct size when reinitialising SVE state
- mm/hugetlb: initialize hugetlb_usage in mm_init
- scsi: BusLogic: Fix missing pr_cont() use
- ovl: fix BUG_ON() in may_delete() when called from ovl_cleanup()
- cifs: fix wrong release in sess_alloc_buffer() failed path
- bonding: 3ad: fix the concurrency between __bond_release_one() and bond_3ad_state_machine_handler()
- PCI: Use pci_update_current_state() in pci_enable_device_flags()
- userfaultfd: prevent concurrent API initialization
- PCI: Return ~0 data on pciconfig_read() CAP_SYS_ADMIN failure
- block: bfq: fix bfq_set_next_ioprio_data()
- arm64: head: avoid over-mapping in map_memory
- bpf: Fix pointer arithmetic mask tightening under state pruning
- bpf: verifier: Allocate idmap scratch in verifier env
- selftests/bpf: fix tests due to const spill/fill
- selftests/bpf: Test variable offset stack access
- bpf: Sanity check max value for var_off stack access
- bpf: Reject indirect var_off stack access in unpriv mode
- bpf: Reject indirect var_off stack access in raw mode
- bpf: Support variable offset stack access from helpers
- bpf: correct slot_type marking logic to allow more stack slot sharing
- PCI/MSI: Skip masking MSI-X on Xen PV
- tty: Fix data race between tiocsti() and flush_to_ldisc()
- net: sched: Fix qdisc_rate_table refcount leak when get tcf_block failed
- tty: serial: fsl_lpuart: fix the wrong mapbase value
- CIFS: Fix a potencially linear read overflow
- PCI: PM: Enable PME if it can be signaled from D3cold
- PCI: PM: Avoid forcing PCI_D0 for wakeup reasons inconsistently
- tcp: seq_file: Avoid skipping sk during tcp_seek_last_pos
- fcntl: fix potential deadlock for &fasync_struct.fa_lock
- hrtimer: Avoid double reprogramming in __hrtimer_start_range_ns()
- sched/deadline: Fix missing clock update in migrate_task_rq_dl()
- sched/deadline: Fix reset_on_fork reporting of DL tasks
- locking/mutex: Fix HANDOFF condition
- ipv4/icmp: l3mdev: Perform icmp error route lookup on source device routing table (v2)
- perf/x86/intel/pt: Fix mask of num_address_ranges
- Revert "EMMC: ascend customized emmc host"
- Revert "EMMC: add hisi_mmc_core"
- Revert "EMMC: adaption for ascend customized emmc card"
- Revert "EMMC: adaption for ascend customized sd card"
- Revert "EMMC: adaption for ascend customized host layer"
- Revert "EMMC: hisi extensions for dw mmc host controller"
- Revert "EMMC: add dts bindings documents"
- Revert "EMMC: open CONFIG_ASCEND_HISI_MMC"
- Revert "EMMC: fix ascend hisi emmc probe failed problem according to mmc_host struct"
- iommu: support phytium ft2000plus and S2500 iommu function
- arm64: Errata: fix kabi changed by cpu_errata and enable idc
- blk-mq: don't free tags if the tag_set is used by other device in queue initialztion
- nbd: add a flush_workqueue in nbd_start_device
- svm: Fix ts problem, which need the len to check out memory
- sctp: add vtag check in sctp_sf_ootb
- sctp: add vtag check in sctp_sf_do_8_5_1_E_sa
- sctp: add vtag check in sctp_sf_violation
- sctp: fix the processing for COOKIE_ECHO chunk
- sctp: fix the processing for INIT_ACK chunk
- sctp: fix the processing for INIT chunk
- sctp: use init_tag from inithdr for ABORT chunk
- openeuler_defconfig: Build HISI PMU drivers as modules.
- arm64: perf: Expose some new events via sysfs
- arm64: perf: Hook up new events
- arm64: perf: Correct the event index in sysfs
- arm64: perf: Add support for Armv8.1 PMCEID register format
- perf/smmuv3: Don't trample existing events with global filter
- drivers/perf: hisi: Add missing include of linux/module.h
- drivers/perf: Prevent forced unbinding of PMU drivers
- drivers/perf: Fix kernel panic when rmmod PMU modules during perf sampling
- drivers/perf: hisi: Fix wrong value for all counters enable
- pmu/smmuv3: Clear IRQ affinity hint on device removal
- drivers/perf: hisi: Permit modular builds of HiSilicon uncore drivers
- drivers/perf: hisi: Fix typo in events attribute array
- drivers/perf: hisi: Simplify hisi_read_sccl_and_ccl_id and its comment
- drivers/perf: hisi: update the sccl_id/ccl_id for certain HiSilicon platform
- perf/smmuv3: Validate groups for global filtering
- perf/smmuv3: Validate group size
- drivers/perf: arm_spe: Don't error on high-order pages for aux buf
- drm/hisilicon: Features to support reading resolutions from EDID
- drm/hisilicon: Support i2c driver algorithms for bit-shift adapters
- compiler.h: fix barrier_data() on clang

* Tue Nov 09 2021 Laibin Qiu <qiulaibin@huawei.com> - 4.19.90-2111.3.0.0121
- bonding: Fix a use-after-free problem when bond_sysfs_slave_add() failed
- ANDROID: staging: ion: move buffer kmap from begin/end_cpu_access()
- ath9k: Postpone key cache entry deletion for TXQ frames reference it
- ath: Modify ath_key_delete() to not need full key entry
- ath: Export ath_hw_keysetmac()
- ath9k: Clear key cache explicitly on disabling hardware
- ath: Use safer key clearing with key cache entries
- ext4: if zeroout fails fall back to splitting the extent node
- dccp: don't duplicate ccid when cloning dccp sock
- selftests/bpf: add demo for file read pattern detection
- libbpf: Support detecting writable tracepoint program
- ext4: add trace for the read and release of regular file
- xfs: add trace for read and release of regular file
- fs: add helper fs_file_read_do_trace()
- vfs: add bare tracepoints for vfs read and release
- bpf: Support writable context for bare tracepoint
- trace: bpf: Allow bpf to attach to bare tracepoints
- tracepoints: Add helper to test if tracepoint is enabled in a header
- Revert "xfs: add writable tracepoint for xfs file buffer read"
- Revert "selftests/bpf: add test_xfs_file.c and test_set_xfs_file.c"
- Partially revert "xfs: let writable tracepoint enable to clear flag of f_mode"
- Revert "selftests/bpf: test_xfs_file support to clear FMODE_RANDOM"
- Revert "selftests/bpf: add test_spec_readahead_xfs_file to support specail async readahead"
- EMMC: fix ascend hisi emmc probe failed problem according to mmc_host struct
- Bluetooth: cmtp: fix file refcount when cmtp_attach_device fails
- scsi: hisi_sas: print status and error when sata io abnormally completed
- Revert "scsi: hisi_sas: use threaded irq to process CQ interrupts"
- Revert "scsi: hisi_sas: replace spin_lock_irqsave/spin_unlock_restore with spin_lock/spin_unlock"
- net: hns3: update hns3 version to 21.10.5
- net: hns3: remove an unnecessary 'goto' in hclge_init_ae_dev()
- net: hns3: fix ret not initialized problem in hclge_get_dfx_reg()
- net: hns3: refix kernel crash when unload VF while it is being reset
- net: hns3: ignore reset event before initialization process is done
- net: hns3: fix vf reset workqueue cannot exit
- net: hns3: reset DWRR of unused tc to zero
- net: hns3: fix a return value error in hclge_get_reset_status()
- net: hns3: fix the timing issue of VF clearing interrupt sources
- net: hns3: disable mac in flr process
- net: hns3: add trace event in hclge_gen_resp_to_vf()
- net: hns3: remove an unnecessary check in hclge_set_umv_space()
- net: hns3: remove unnecessary parameter 'is_alloc' in hclge_set_umv_space()
- net: hns3: remove the rss_size limitation by vector num
- net: hns3: bd_num from fireware should not be zero
- net: hns3: fix the exception when query imp info
- net: hns3: fix local variable "desc" not initialized problem
- net: hns3: limit bd numbers when getting dfx regs.
- s390/bpf: Fix optimizing out zero-extensions
- s390/bpf: Fix 64-bit subtraction of the -0x80000000 constant
- nbd: add sanity check for first_minor
- perf: hisi: Fix compile error if defined MODULE
- nfc: nci: fix the UAF of rf_conn_info object
- ipv6: make exception cache less predictible
- ipv6: use siphash in rt6_exception_hash()
- ipv4: make exception cache less predictible
- ipv4: use siphash instead of Jenkins in fnhe_hashfun()
- README: README optimize
- PM: hibernate: Get block device exclusively in swsusp_check()
- isdn: cpai: check ctr->cnr to avoid array index out of bound
- blk-cgroup: synchronize blkg creation against policy deactivation
- iommu/arm-smmu-v3: Add suspend and resume support
- nbd: Fix use-after-free in pid_show
- scsi: scsi_debug: Fix out-of-bound read in resp_report_tgtpgs()
- scsi: scsi_debug: Fix out-of-bound read in resp_readcap16()
- scsi: hisi_sas: unsupported DIX between OS and HBA only for SATA device
- scsi: hisi_sas: queue debugfs dump work before FLR
- mm/mempolicy: fix a race between offset_il_node and mpol_rebind_task
- jbd2: avoid transaction reuse after reformatting
- jbd2: clean up checksum verification in do_one_pass()
- ext4: check magic even the extent block bh is verified
- ext4: avoid recheck extent for EXT4_EX_FORCE_CACHE
- ext4: prevent partial update of the extent blocks
- ext4: check for inconsistent extents between index and leaf block
- ext4: check for out-of-order index extents in ext4_valid_extent_entries()
- quota: correct error number in free_dqentry()
- quota: check block number when reading the block in quota file
- nbd: fix uaf in nbd_handle_reply()
- nbd: partition nbd_read_stat() into nbd_read_reply() and nbd_handle_reply()
- nbd: clean up return value checking of sock_xmit()
- nbd: don't start request if nbd_queue_rq() failed
- nbd: check sock index in nbd_read_stat()
- nbd: make sure request completion won't concurrent
- nbd: don't handle response without a corresponding request message
- config: enable CONFIG_ASCEND_CLEAN_CDM by default
- numa/cdm: Introduce a bootarg to specify the target nodes to move to
- numa/cdm: Introduce a hbm_per_part variable
- numa: Restrict the usage of cdm_node_to_ddr_node()
- numa: Move the management structures for cdm nodes to ddr
- perf: hisi: Add support for HiSilicon SoC L3T PMU driver
- perf: hisi: Add support for HiSilicon SoC LPDDRC PMU driver
- Documentation: Add documentation for Hisilicon SoC PMU DTS binding
- perf: hisi: Add support for HiSilicon SoC PMU driver dt probe
- watchdog/corelockup: Depends on the hardlockup detection switch
- watchdog/corelockup: Add interface to control the detection sensitivity.
- watchdog/corelockup: Optimized core lockup detection judgment rules
- config/arm64: Enable corelockup detector for hulk defconfig
- corelockup: Add detector enable support by cmdline
- corelockup: Disable wfi/wfe mode for pmu based nmi
- corelockup: Add support of cpu core hang check
- driver/svm: used tgid when get phys
- share pool:Solving the 4G DVPP Address coexist
- share_pool: Default enable enable_share_k2u_spg
- share_pool: Export __vmalloc_node()
- share pool: Add export __get_vm_area map_vm_area for ascend driver
- share_pool: add sp_group_del_task api
- share_pool: Extract sp_check_caller_permission
- share_pool: Clear VM_SHAREPOOL when drop sp area
- share_pool: Don't allow concurrent sp_free or sp_unshare_uva calls
- share_pool: Add compatible interface for multi-group mode
- share_pool: Rename function is_k2task to sp_check_k2task
- share_pool: Add sp_k2u trace
- share_pool: Extract sp_k2u_prepare and sp_k2u_finish
- share_pool: Add sp_alloc trace
- share_pool: Show process prot in an sp_group
- share_pool: Add proc node to show process overview info
- share_pool: Apply proc_sp_group_state to multi-group-mode
- share_pool: Put the pointer of sp_proc_stat in sp_group_master
- share_pool: Free spg_node when group adding failed
- share_pool: Extract is_process_in_group
- share_pool: Apply sp_config_dvpp_range to to multi-group-mode
- share_pool: Apply sp_make_share_k2u() to multi-group-mode
- share_pool: Apply sp_group_id_by_pid() to multi-group-mode
- share_pool: Extract function get_task
- share_pool: Clean outdated DVPP pass through macros
- share_pool: Redesign sp_alloc pass through
- share_pool: Extract sp_free_get_spa
- share_pool: Extract sp_alloc_finish
- share_pool: Extract sp_alloc_mmap_populate
- share_pool: Extract sp_fallocate
- share_pool: Extract sp_alloc_prepare
- share_pool: Using pr_fmt in printing
- share_pool: Add access control for sp_unshare_uva
- ascend: share pool: Only memory of current process is allowed to u2k/k2u
- ascend: share pool: Remove unnecessary params of sp_unshare
- share_pool: k2u hugepage READONLY prot bug fix
- ascend: share pool: Add parameter prot in sp_group_add_task
- share_pool: Introduce struct sp_spg_stat
- share_pool: Introduce struct spg_proc_stat
- share_pool: Initialize sp_group_master when call k2u_task
- share_pool: Rename sp_stat_idr to sp_proc_stat_idr
- share_pool: Rename sp_spg_stat to sp_overall_stat
- share_pool: Add group max process num limitation
- share_pool: Add system max group num limitation
- ascend/config: enable share pool feature
- kabi: fix kabi broken in struct mm_struct
- ascend: sharepool: support multi-group mode
- sharepool: Fix ASLR broken
- share_pool: Adjust the position of do_mmap checker
- share_pool: share_pool: Don't allow non-sp mmap in sp address range
- share_pool: Free newly generated id only when necessary
- share_pool: Show sp vmflags in /proc/$pid/smaps
- share_pool: Free newly generated id when failed
- share_pool: Fix missing semaphore operation in error branch
- share_pool: Use pr_debug to print addresses
- share_pool: Add compact switch for vmalloc_huge* funcs
- share_pool: Don't do direct reclaim or compact for vmalloc_huge* funcs
- share_pool: Eliminate compiler warning for atomic64_t in arm32
- share_pool: Fix memleak of concurrent sp_free and sp_group_add_task
- share_pool: Set initial value to variable node_id
- ascend/share pool: bugfix, sp exit is not atomic
- share_pool: Alloc shared memory on a specified memory node
- share_pool: Alloc sp memory on a specified memory node
- share_pool: Fix concurrency problem when a process adding sp_group is killed
- share_pool: Fix address checker
- share_pool: Optimize compact procedure
- shmem/ascend: charge pages to the memcg of current task
- share_pool: Update kernel-doc comments
- share_pool: Fix warning symbol was not declared
- share_pool: Fix warning missing braces around initializer
- share_pool: Waiting for the migration to complete
- share_pool: Add parameter checking
- share_pool: Fix struct sp_proc_stat memleak
- share_pool: Show k2u_to_task processes in proc_stat interface
- ascend: sharepool: calculate the correct offset of the address which is customized
- share_pool: Print info when thread is being killed
- share pool: Clean sp_mutex for sp_add_group_task
- share_pool: Rename buff_vzalloc_user and buff_vzalloc_hugepage_user
- share_pool: Support showing pid of applier process in spa_stat
- share_pool: Fix coredump hungtask
- share_pool: change printk_ratelimit to pr_level_ratelimited
- share_pool: Turn the negative statistics into zeros
- share_pool: Put relevant functions together
- share_pool: Remove redundant sysctl_share_pool_hugepage_enable
- ascend: sharepool: fix compile warning when the sharepool is turned off
- share_pool: move sysctl interface of share pool from kern_table to vm table
- share_pool: Introduce refcount for struct sp_proc_stat
- share_pool: Increase refcount of sp_group when call __sp_find_spg
- share_pool: Update the comments after removing sp_mutex
- share_pool: Rename __sp_group_drop_locked to sp_group_drop
- share_pool: Introduce an rw semaphore sp_group_sem and remove sp_mutex
- share_pool: Introduce an rw semaphore for per process stat idr
- share_pool: Use type atomic64_t for process stat
- share_pool: Add comments for fine grained locking design
- share_pool: Remove residual macro ESPGMMEXIT
- share_pool: Fix use-after-free of spa in rb_spa_stat_show
- share_pool: Fix the bug of not down_write mm->mmap_sem
- ascend: sharepool: don't enable the vmalloc to use hugepage default
- share_pool: add sysctl_share_pool_map_lock_enable to control the mapped region to be locked
- mm/vmalloc: fix pud_page compile error on arm32
- mm, share_pool: Print share pool info of a process when oom
- ascend: share pool: optimize the big lock for memory processing
- share_pool: Fix memleak if fail in sp_make_share_u2k()
- share_pool: Free sp group id only when it is auto generated
- share_pool: Add interrupt context checker
- share_pool: Use PMD_SIZE alignment in hugepage allocation functions
- share_pool: Remove redundant null pointer check
- mm: Fix compilation error of mm_update_next_owner()
- share_pool: Fix compilation error of do_mm_populate()
- sharepool: Fix null pointer dereference on adding exiting task
- share_pool: Check tsk->mm before use it
- share_pool: Fix a potential bug branch
- x86/mm/ioremap: Fix HUGE_VMAP interface redefinition
- share_pool: Calculate sp_alloc() size for a task
- share_pool: Calculate k2u size for a task
- share_pool: Refactor sp_make_share_k2u()
- share_pool: Fix error message printing
- share_pool: Calculate non-sharepool memory usage for a task
- share_pool: Calculate sp_alloc() size for a sp_group
- share_pool: Do cleanups for statistical functions
- mm/vmalloc: Fix a double free in __vmalloc_node_range
- share_pool: Add and export buff_vzalloc_user()
- ascend: share_pool: don't share the k2u to spg by default
- ascend: share_pool: make the function share_k2u_to_spg work
- share pool: Try to compact when memory is insufficient
- share_pool: Fix null pointer of mm in concurrency scenes
- share pool: Roll back when sp mmap failed
- share_pool: Set errno when fail in sp_free()
- share_pool: Release spg id when fail in sp_group_add_task()
- share_pool: Remove memleak debug printing
- ascend: share_pool: enable svm to use share pool memory
- share_pool: Fix series of bugs
- ascend: share_pool: Use remap_pfn_range to share kva to uva
- ascend: share_pool: Use sharepool_no_page to alloc hugepage
- share_pool: Add dvpp size statistics
- share_pool: Fix rbtree searching bugs
- share_pool: Don't use input param pid in sp_unshare_uva()
- share pool: Solve processing errors of some abnormal branches
- share_pool: Fix spa memleak in dvpp channel destroy procedure
- share_pool: Add sp_area cache
- ascend: share_pool: support debug mode and refactor some functions
- ascend: share_pool: support share pool features for ascend platform
- ascend: share_pool: support fork() and exit() to handle the mm
- ascend: share_pool: add support proc_sharepool_init and is_vm_huge_special
- ascend: share_pool: add /proc/sys/kernel/share_pool_hugepage_enable and ac_mode
- ascend: share_pool: add /proc/<pid>/sp_group
- ascend: memory: introduce do_mm_populate and hugetlb_insert_hugepage
- ascend: mm_struct: introduce new parameter for share pool features
- ascend: vmalloc: export new function for share pool
- ascend: mm: add an owner for mm_struct
- mm/vmalloc: Hugepage vmalloc mappings
- mm/vmalloc: add vmap_range_noflush variant
- mm: Move vmap_range from mm/ioremap.c to mm/vmalloc.c
- arm64: inline huge vmap supported functions
- mm: HUGE_VMAP arch support cleanup
- mm/ioremap: rename ioremap_*_range to vmap_*_range
- mm/vmalloc: rename vmap_*_range vmap_pages_*_range
- mm: apply_to_pte_range warn and fail if a large pte is encountered
- mm/vmalloc: fix vmalloc_to_page for huge vmap mappings
- mm: move lib/ioremap.c to mm/
- mm/ioremap: probe platform for p4d huge map support
- mm: remove map_vm_range
- mm: don't return the number of pages from map_kernel_range{, _noflush}
- mm: rename vmap_page_range to map_kernel_range
- mm: remove vmap_page_range_noflush and vunmap_page_range
- mm: pass addr as unsigned long to vb_free
- mm: only allow page table mappings for built-in zsmalloc
- mm: unexport unmap_kernel_range_noflush
- mm: remove __get_vm_area
- arm64: mm: add p?d_leaf() definitions
- mm: add generic p?d_leaf() macros
- mm/memory.c: add apply_to_existing_page_range() helper
- mm/vmalloc: Add empty <asm/vmalloc.h> headers and use them from <linux/vmalloc.h>
- lib/ioremap: ensure break-before-make is used for huge p4d mappings
- lib/ioremap: ensure phys_addr actually corresponds to a physical address
- ioremap: rework pXd_free_pYd_page() API
- mm: add do_vm_mmap
- config: update hulk_defconfig
- configs: remove euleros_defconfig
- iommu/amd: Fix incorrect PASID decoding from event log
- mm: compaction: avoid 100% CPU usage during compaction when a task is killed
- iommu/vt-d: Unlink device if failed to add to group
- iommu/arm-smmu: Prevent forced unbinding of Arm SMMU drivers
- EMMC: open CONFIG_ASCEND_HISI_MMC
- EMMC: add dts bindings documents
- EMMC: hisi extensions for dw mmc host controller
- EMMC: adaption for ascend customized host layer
- EMMC: adaption for ascend customized sd card
- EMMC: adaption for ascend customized emmc card
- EMMC: add hisi_mmc_core
- EMMC: ascend customized emmc host

* Wed Oct 27 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2110.8.0.0120
- blk-mq: complete req in softirq context in case of single queue
- ovl: fix leaked dentry
- ovl: fix incorrect extent info in metacopy case
- ovl: warn about orphan metacopy
- ovl: fix lookup of indexed hardlinks with metacopy
- ovl: fix redirect traversal on metacopy dentries
- ovl: initialize OVL_UPPERDATA in ovl_lookup()
- ovl: use only uppermetacopy state in ovl_lookup()
- ovl: simplify setting of origin for index lookup
- net: hns3: update hns3 version to 21.10.1
- net: hns3: fix buffer length not enough problem in debugfs
- net: hns3: use ae_dev->ops->reset_event to do reset.
- media: firewire: firedtv-avc: fix a buffer overflow in avc_ca_pmt()
- GPIO : support ascend gpio driver
- mpam: update monitor rmid and group configuration
- mpam: Add support for group rmid modify
- mpam: enable rdt_mon_capable for mbw monitor
- svm: Add svm_set_user_mpam_en to enable/disable mpam for smmu
- svm: Add support to set svm mpam configuration
- svm: Add support to get svm mpam configuration
- iommu/arm-smmu-v3: Add support to enable/disable SMMU user_mpam_en
- iommu/arm-smmu-v3: Add support to get SMMU mpam configuration
- iommu/arm-smmu-v3: Add support to configure mpam in STE/CD context
- nvme-rdma: destroy cm id before destroy qp to avoid use after free
- arm64: Errata: fix kabi changed by cpu_errata
- config: disable CONFIG_HISILICON_ERRATUM_1980005 by default
- cache: Workaround HiSilicon Taishan DC CVAU
- kabi: fix kabi broken in struct device
- virtio_pci: Support surprise removal of virtio pci device
- ip_gre: add validation for csum_start
- netfilter: nft_exthdr: fix endianness of tcp option cast
- tracing / histogram: Fix NULL pointer dereference on strcmp() on NULL event name
- scsi: core: Avoid printing an error if target_alloc() returns -ENXIO
- scsi: scsi_dh_rdac: Avoid crash during rdac_bus_attach()
- x86/fpu: Make init_fpstate correct with optimized XSAVE
- iommu/vt-d: Fix agaw for a supported 48 bit guest address width
- PCI/MSI: Enforce MSI[X] entry updates to be visible
- PCI/MSI: Enforce that MSI-X table entry is masked for update
- PCI/MSI: Mask all unused MSI-X entries
- PCI/MSI: Protect msi_desc::masked for multi-MSI
- PCI/MSI: Use msi_mask_irq() in pci_msi_shutdown()
- PCI/MSI: Correct misleading comments
- PCI/MSI: Do not set invalid bits in MSI mask
- PCI/MSI: Enable and mask MSI-X early
- genirq/msi: Ensure deactivation on teardown
- x86/ioapic: Force affinity setup before startup
- x86/msi: Force affinity setup before startup
- genirq: Provide IRQCHIP_AFFINITY_PRE_STARTUP
- tcp_bbr: fix u32 wrap bug in round logic if bbr_init() called after 2B packets
- net: bridge: fix memleak in br_add_if()
- net: igmp: fix data-race in igmp_ifc_timer_expire()
- ACPI: NFIT: Fix support for virtual SPA ranges
- ovl: prevent private clone if bind mount is not allowed
- tracing: Reject string operand in the histogram expression
- reiserfs: add check for root_inode in reiserfs_fill_super
- serial: 8250: Mask out floating 16/32-bit bus bits
- ext4: fix potential htree corruption when growing large_dir directories
- pipe: increase minimum default pipe size to 2 pages
- tracing/histogram: Rename "cpu" to "common_cpu"
- tracing / histogram: Give calculation hist_fields a size
- blk-iolatency: error out if blk_get_queue() failed in iolatency_set_limit()
- net: Fix zero-copy head len calculation.
- netfilter: nft_nat: allow to specify layer 4 protocol NAT only
- netfilter: conntrack: adjust stop timestamp to real expiry value
- virtio_net: Do not pull payload in skb->head
- virtio_net: Add XDP meta data support
- net: check untrusted gso_size at kernel entry
- sctp: move 198 addresses from unusable to private scope
- net: annotate data race around sk_ll_usec
- net/802/garp: fix memleak in garp_request_join()
- net/802/mrp: fix memleak in mrp_request_join()
- af_unix: fix garbage collect vs MSG_PEEK
- efi: Change down_interruptible() in virt_efi_reset_system() to down_trylock()
- svm: Use vma->vm_pgoff for the nid
- Ascend/hugetlb:support alloc normal and buddy hugepage
- Ascend/memcg: Use CONFIG_ASCEND_FEATURES for customized interfaces
- Ascend/cdm:alloc hugepage from the specified CDM node
- ascend/svm: Support pinned memory size greater than 2GB
- mm: ascend: Fix compilation error of mem_cgroup_from_css()
- fuse: truncate pagecache on atomic_o_trunc
- ext4: drop unnecessary journal handle in delalloc write
- ext4: factor out write end code of inline file
- ext4: correct the error path of ext4_write_inline_data_end()
- ext4: check and update i_disksize properly

* Thu Oct 21 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2110.7.0.0119
- sched/topology: Fix sched_domain_topology_level alloc in sched_init_numa()
- uacce: misc fixes
- mm/page_alloc: place pages to tail in __free_pages_core()
- mm/page_alloc: move pages to tail in move_to_free_list()
- mm/page_alloc: place pages to tail in __putback_isolated_page()
- mm/page_alloc: convert "report" flag of __free_one_page() to a proper flag
- mm: add function __putback_isolated_page
- mm/page_alloc.c: memory hotplug: free pages as higher order
- raid1: ensure write behind bio has less than BIO_MAX_VECS sectors
- blk-wbt: fix IO hang due to negative inflight counter
- Export sysboml for bbox to use.
- ovl: use a private non-persistent ino pool
- ovl: simplify i_ino initialization
- ovl: factor out helper ovl_get_root()
- ovl: fix out of date comment and unreachable code

* Tue Oct 19 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2110.6.0.0118
- Revert "cache: Workaround HiSilicon Taishan DC CVAU"
- Revert "config: disable CONFIG_HISILICON_ERRATUM_1980005 by default"

* Tue Oct 19 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2110.5.0.0117
- soc: aspeed: lpc-ctrl: Fix boundary check for mmap
- mmap: userswap: fix some format issues
- mmap: userswap: fix memory leak in do_mmap
- arm64/mpam: fix the problem that the ret variable is not initialized
- NFS: Fix a race in __nfs_list_for_each_server()
- NFSv4: Clean up nfs_client_return_marked_delegations()
- NFS: Add a helper nfs_client_for_each_server()
- blktrace: Fix uaf in blk_trace access after removing by sysfs
- io_uring: don't take uring_lock during iowq cancel
- io_uring: hold uring_lock while completing failed polled io in io_wq_submit_work()
- block: fix UAF from race of ioc_release_fn() and __ioc_clear_queue()
- Driver/SMMUV3: Bugfix for the softlockup when the driver processes events
- net_sched: remove need_resched() from qdisc_run()
- ath10k: Fix TKIP Michael MIC verification for PCIe
- ath10k: drop fragments with multicast DA for PCIe
- ath10k: add CCMP PN replay protection for fragmented frames for PCIe
- ath10k: add struct for high latency PN replay protection
- config: disable CONFIG_HISILICON_ERRATUM_1980005 by default
- cache: Workaround HiSilicon Taishan DC CVAU
- kabi: Fix "Intel: perf/core: Add attr_groups_update into struct pmu"
- x86: Fix kabi broken for struct cpuinfo_x86
- kabi: Fix "perf/x86/intel: Support per-thread RDPMC TopDown metrics"
- PCI: kabi: fix kabi broken for struct pci_dev
- kabi: Fix "PCI: Decode PCIe 32 GT/s link speed"
- openeuler_defconfig: Adjust some configs for Intel icelake support
- hulk_defconfig: Adjust some configs for Intel icelake support
- perf/x86/intel/uncore: Fix M2M event umask for Ice Lake server
- node: fix device cleanups in error handling code
- device-dax/core: Fix memory leak when rmmod dax.ko
- ntb: intel: Fix memleak in intel_ntb_pci_probe
- perf/x86/intel/uncore: Fix the scale of the IMC free-running events
- intel_idle: Ignore _CST if control cannot be taken from the platform
- intel_idle: Fix max_cstate for processor models without C-state tables
- perf/x86/intel/uncore: Reduce the number of CBOX counters
- powercap: RAPL: remove unused local MSR define
- PCI/ERR: Update error status after reset_link()
- PCI/ERR: Combine pci_channel_io_frozen cases
- intel_th: msu: Fix the unexpected state warning
- intel_th: msu: Fix window switching without windows
- intel_th: Fix freeing IRQs
- PCI: Do not use bus number zero from EA capability
- perf/x86/intel/uncore: Fix missing marker for snr_uncore_imc_freerunning_events
- intel_th: msu: Fix possible memory leak in mode_store()
- intel_th: msu: Fix overflow in shift of an unsigned int
- intel_th: msu: Fix missing allocation failure check on a kstrndup
- intel_th: msu: Fix an uninitialized mutex
- intel_th: gth: Fix the window switching sequence
- tools/power/x86/intel-speed-select: Fix a read overflow in isst_set_tdp_level_msr()
- intel_rapl: need linux/cpuhotplug.h for enum cpuhp_state
- device-dax: fix memory and resource leak if hotplug fails
- MAINTAINERS: Add entry for EDAC-I10NM
- MAINTAINERS: Update entry for EDAC-SKYLAKE
- tools x86 uapi asm: Sync the pt_regs.h copy with the kernel sources
- docs: fix numaperf.rst and add it to the doc tree
- acpi/hmat: fix an uninitialized memory_target
- acpi/hmat: Update acpi_hmat_type enum with ACPI_HMAT_TYPE_PROXIMITY
- acpi/hmat: fix memory leaks in hmat_init()
- drivers/dax: Allow to include DEV_DAX_PMEM as builtin
- doc: trace: fix reference to cpuidle documentation file
- openeuler_defconfig: Enable some Icelake support configs
- hulk_defconfig: Enable some Icelake support configs
- tools/power turbostat: Fix Haswell Core systems
- tools/power turbostat: Support Ice Lake server
- tools/power turbostat: consolidate duplicate model numbers
- tools/power turbostat: reduce debug output
- intel_th: msu-sink: An example msu buffer "sink"
- intel_th: msu: Introduce buffer interface
- intel_th: msu: Start read iterator from a non-empty window
- intel_th: msu: Split sgt array and pointer in multiwindow mode
- intel_th: msu: Support multipage blocks
- intel_th: msu: Remove set but not used variable 'last'
- intel_th: msu: Fix unused variable warning on arm64 platform
- intel_th: msu: Add current window tracking
- intel_th: msu: Add a sysfs attribute to trigger window switch
- intel_th: msu: Correct the block wrap detection
- intel_th: Add switch triggering support
- intel_th: gth: Factor out trace start/stop
- intel_th: msu: Factor out pipeline draining
- intel_th: msu: Switch over to scatterlist
- intel_th: msu: Replace open-coded list_{first,last,next}_entry variants
- intel_th: Only report useful IRQs to subdevices
- intel_th: msu: Start handling IRQs
- intel_th: pci: Use MSI interrupt signalling
- intel_th: Communicate IRQ via resource
- intel_th: Add "rtit" source device
- intel_th: Skip subdevices if their MMIO is missing
- intel_th: Rework resource passing between glue layers and core
- intel_th: pti: Use sysfs_match_string() helper
- intel_th: Only create useful device nodes
- intel_th: Mark expected switch fall-throughs
- perf/x86/amd: Fix sampling Large Increment per Cycle events
- Intel: hardirq/nmi: Allow nested nmi_enter()
- Intel: platform/x86: ISST: Increase timeout
- Intel: ICX: platform/x86: ISST: Fix wrong unregister type
- Intel: ICX: platform/x86: ISST: Allow additional core-power mailbox commands
- Intel: EDAC/i10nm: Update driver to support different bus number config register offsets
- Intel: EDAC, {skx,i10nm}: Make some configurations CPU model specific
- Intel: intel_idle: Customize IceLake server support
- Intel: x86/uaccess: Move copy_user_handle_tail() into asm
- Intel: x86/insn-eval: Add support for 64-bit kernel mode
- Intel: x86/extable: Introduce _ASM_EXTABLE_UA for uaccess fixups
- x86/traps: Stop using ist_enter/exit() in do_int3()
- Intel: EDAC, skx: Retrieve and print retry_rd_err_log registers
- Intel: EDAC, skx_common: Refactor so that we initialize "dev" in result of adxl decode.
- Intel: perf/x86: Fix n_metric for cancelled txn
- Intel: perf/x86/intel: Check perf metrics feature for each CPU
- Intel: perf/x86/intel: Support per-thread RDPMC TopDown metrics
- Intel: perf/x86/intel: Support TopDown metrics on Ice Lake
- Intel: perf/x86: Add a macro for RDPMC offset of fixed counters
- Intel: perf/x86/intel: Generic support for hardware TopDown metrics
- Intel: perf/core: Add a new PERF_EV_CAP_SIBLING event capability
- Intel: perf/x86/intel: Use switch in intel_pmu_disable/enable_event
- Intel: perf/x86/intel: Fix the name of perf METRICS
- Intel: perf/x86/intel: Move BTS index to 47
- Intel: perf/x86/intel: Introduce the fourth fixed counter
- Intel: perf/x86/intel: Name the global status bit in NMI handler
- Intel: perf/x86: Use event_base_rdpmc for the RDPMC userspace support
- Intel: perf/x86: Keep LBR records unchanged in host context for guest usage
- Intel: perf/x86: Add constraint to create guest LBR event without hw counter
- Intel: perf/x86/lbr: Add interface to get LBR information
- perf/x86/core: Refactor hw->idx checks and cleanup
- Intel: perf/x86: Fix variable types for LBR registers
- perf/x86/amd: Add support for Large Increment per Cycle Events
- Intel: perf/x86/amd: Constrain Large Increment per Cycle events
- Intel: perf/x86/intel: Fix SLOTS PEBS event constraint
- Intel: perf/x86: Use update attribute groups for default attributes
- intel: perf/x86/intel: Use update attributes for skylake format
- Intel: perf/x86: Use update attribute groups for extra format
- Intel: perf/x86: Use update attribute groups for caps
- Intel: perf/x86: Add is_visible attribute_group callback for base events
- Intel: perf/x86: Use the new pmu::update_attrs attribute group
- Intel: perf/x86: Get rid of x86_pmu::event_attrs
- Intel: perf/core: Add attr_groups_update into struct pmu
- Intel: sysfs: Add sysfs_update_groups function
- perf/x86/intel: Export mem events only if there's PEBS support
- Intel: perf/x86/intel: Factor out common code of PMI handler
- PCI: pciehp: Add DMI table for in-band presence detection disabled
- Intel:PCI: pciehp: Wait for PDS if in-band presence is disabled
- Intel:PCI: pciehp: Disable in-band presence detect when possible
- Intel:PCI/AER: Fix the broken interrupt injection
- genirq: Provide interrupt injection mechanism
- Intel:PCI/DPC: Add "pcie_ports=dpc-native" to allow DPC without AER control
- Intel:PCI/AER: Fix kernel-doc warnings
- Intel:PCI/AER: Use for_each_set_bit() to simplify code
- Intel:PCI/AER: Save AER Capability for suspend/resume
- Intel:PCI: Get rid of dev->has_secondary_link flag
- Intel:PCI: Make pcie_downstream_port() available outside of access.c
- Intel:PCI: Assign bus numbers present in EA capability for bridges
- Intel:PCI/AER: Log messages with pci_dev, not pcie_device
- Intel:PCI/DPC: Log messages with pci_dev, not pcie_device
- Intel:PCI: Replace dev_printk(KERN_DEBUG) with dev_info(), etc
- Intel:PCI: Replace printk(KERN_INFO) with pr_info(), etc
- Intel:PCI: Use dev_printk() when possible
- Intel:PCI/portdrv: Support PCIe services on subtractive decode bridges
- Intel:PCI/portdrv: Use conventional Device ID table formatting
- Intel:PCI/ASPM: Save LTR Capability for suspend/resume
- Intel:PCI: Enable SERR# forwarding for all bridges
- Intel:PCI/AER: Use match_string() helper to simplify the code
- Intel:PCI/AER: Queue one GHES event, not several uninitialized ones
- Intel:PCI/AER: Abstract AER interrupt handling
- Intel:PCI/AER: Reuse existing pcie_port_find_device() interface
- Intel:PCI/AER: Use managed resource allocations
- Intel:PCI/AER: Use threaded IRQ for bottom half
- Intel:PCI/AER: Use kfifo_in_spinlocked() to insert locked elements
- Intel:PCI/AER: Remove unused aer_error_resume()
- Intel:PCI/ERR: Remove duplicated include from err.c
- Intel:PCI: Make link active reporting detection generic
- PCI: Unify device inaccessible
- Intel:PCI/ERR: Always report current recovery status for udev
- PCI/ERR: Simplify broadcast callouts
- PCI/ERR: Handle fatal error recovery
- Intel:PCI/DPC: Save and restore config state
- PCI: portdrv: Restore PCI config state on slot reset
- PCI: Simplify disconnected marking
- Intel: ntb: intel: add hw workaround for NTB BAR alignment
- Intel: ntb: intel: fix static declaration
- Intel: ntb: intel: Add Icelake (gen4) support for Intel NTB
- Intel: NTB: add new parameter to peer_db_addr() db_bit and db_data
- Intel: perf/x86/intel: Fix invalid Bit 13 for Icelake MSR_OFFCORE_RSP_x register
- Intel: perf/x86/intel/uncore: Add Ice Lake server uncore support
- Intel: perf/x86/intel/uncore: Add box_offsets for free-running counters
- Intel: perf/x86/intel/uncore: Factor out __snr_uncore_mmio_init_box
- Intel: perf/x86/intel/uncore: Add IMC uncore support for Snow Ridge
- Intel: perf/x86/intel/uncore: Clean up client IMC
- Intel: perf/x86/intel/uncore: Support MMIO type uncore blocks
- Intel: perf/x86/intel/uncore: Factor out box ref/unref functions
- Intel: perf/x86/intel/uncore: Add uncore support for Snow Ridge server
- Intel: perf/x86/intel: Add more Icelake CPUIDs
- Intel: Documentation: admin-guide: PM: Add intel_idle document
- Intel: ACPI: processor: Make ACPI_PROCESSOR_CSTATE depend on ACPI_PROCESSOR
- Intel: intel_idle: Use ACPI _CST on server systems
- Intel: intel_idle: Add module parameter to prevent ACPI _CST from being used
- Intel: intel_idle: Allow ACPI _CST to be used for selected known processors
- Intel: cpuidle: Allow idle states to be disabled by default
- Intel: Documentation: admin-guide: PM: Add cpuidle document
- Intel: cpuidle: use BIT() for idle state flags and remove CPUIDLE_DRIVER_FLAGS_MASK
- Intel: intel_idle: Use ACPI _CST for processor models without C-state tables
- Intel: intel_idle: Refactor intel_idle_cpuidle_driver_init()
- Intel: ACPI: processor: Export acpi_processor_evaluate_cst()
- Intel: ACPI: processor: Clean up acpi_processor_evaluate_cst()
- Intel: ACPI: processor: Introduce acpi_processor_evaluate_cst()
- Intel: ACPI: processor: Export function to claim _CST control
- Intel: tools/power/x86: A tool to validate Intel Speed Select commands
- Intel: platform/x86: ISST: Restore state on resume
- Intel: platform/x86: ISST: Add Intel Speed Select PUNIT MSR interface
- Intel: platform/x86: ISST: Add Intel Speed Select mailbox interface via MSRs
- Intel: platform/x86: ISST: Add Intel Speed Select mailbox interface via PCI
- Intel: platform/x86: ISST: Add Intel Speed Select mmio interface
- Intel: platform/x86: ISST: Add IOCTL to Translate Linux logical CPU to PUNIT CPU number
- Intel: platform/x86: ISST: Store per CPU information
- Intel: platform/x86: ISST: Add common API to register and handle ioctls
- Intel: platform/x86: ISST: Update ioctl-number.txt for Intel Speed Select interface
- Intel: EDAC, skx, i10nm: Fix source ID register offset
- Intel: EDAC, i10nm: Check ECC enabling status per channel
- Intel: EDAC, i10nm: Add Intel additional Ice-Lake support
- Intel: EDAC, skx, i10nm: Make skx_common.c a pure library
- Intel: EDAC, skx_common: Add code to recognise new compound error code
- Intel: EDAC, i10nm: Add a driver for Intel 10nm server processors
- EDAC, skx_edac: Delete duplicated code
- Intel: EDAC, skx_common: Separate common code out from skx_edac
- Intel: powercap/intel_rapl: add support for ICX-D
- Intel: powercap/intel_rapl: add support for ICX
- Intel: powercap/intel_rapl: add support for IceLake desktop
- Intel: intel_rapl: Fix module autoloading issue
- Intel: intel_rapl: support two power limits for every RAPL domain
- Intel: intel_rapl: support 64 bit register
- intel_rapl: abstract RAPL common code
- Intel: intel_rapl: cleanup hardcoded MSR access
- Intel: intel_rapl: cleanup some functions
- Intel: intel_rapl: abstract register access operations
- Intel: intel_rapl: abstract register address
- Intel: intel_rapl: introduce struct rapl_if_private
- Intel: intel_rapl: introduce intel_rapl.h
- Intel: intel_rapl: remove hardcoded register index
- Intel: intel_rapl: use reg instead of msr
- Intel: powercap/intel_rapl: Update RAPL domain name and debug messages
- Intel: powercap/intel_rapl: Support multi-die/package
- Intel: powercap/intel_rapl: Simplify rapl_find_package()
- Intel: x86/topology: Define topology_logical_die_id()
- Intel: x86/topology: Define topology_die_id()
- Intel: cpu/topology: Export die_id
- Intel: x86/topology: Create topology_max_die_per_package()
- Intel: x86/topology: Add CPUID.1F multi-die/package support
- Intel: topology: Simplify cputopology.txt formatting and wording
- Intel: perf/x86/regs: Use PERF_REG_EXTENDED_MASK
- Intel: perf/x86: Remove pmu->pebs_no_xmm_regs
- Intel: perf/x86: Clean up PEBS_XMM_REGS
- Intel: perf/x86/regs: Check reserved bits
- Intel: perf/x86: Disable extended registers for non-supported PMUs
- Intel: perf/core: Add PERF_PMU_CAP_NO_EXCLUDE for exclusion incapable PMUs
- Intel: perf/core: Add function to test for event exclusion flags
- Intel: perf/x86/intel/pt: Remove software double buffering PMU capability
- Intel: perf/ring_buffer: Fix AUX software double buffering
- Intel: perf regs x86: Add X86 specific arch__intr_reg_mask()
- Intel: perf parse-regs: Add generic support for arch__intr/user_reg_mask()
- Intel: perf parse-regs: Split parse_regs
- Intel: perf parse-regs: Improve error output when faced with unknown register name
- Intel: perf record: Fix suggestion to get list of registers usable with --user-regs and --intr-regs
- Intel: perf tools x86: Add support for recording and printing XMM registers
- Intel: perf/x86/intel/uncore: Add Intel Icelake uncore support
- Intel: perf/x86/lbr: Avoid reading the LBRs when adaptive PEBS handles them
- Intel: perf/x86/intel: Support adaptive PEBS v4
- Intel: perf/x86/intel/ds: Extract code of event update in short period
- Intel: perf/x86/intel: Extract memory code PEBS parser for reuse
- Intel: perf/x86: Support outputting XMM registers
- Intel: doc/mm: New documentation for memory performance
- Intel: acpi/hmat: Register memory side cache attributes
- Intel: acpi/hmat: Register performance attributes
- Intel: acpi/hmat: Register processor domain to its memory
- Intel: node: Add memory-side caching attributes
- Intel: node: Add heterogenous memory access attributes
- node: Link memory nodes to their compute nodes
- Intel: acpi/hmat: Parse and report heterogeneous memory
- Intel: acpi: Add HMAT to generic parsing tables
- irqchip: phytium-2500: Fix compilation issues
- Intel: acpi: Create subtable parsing infrastructure
- Intel: ACPICA: ACPI 6.3: HMAT updates
- Intel: device-dax: "Hotplug" persistent memory for use like normal RAM
- mm/resource: Let walk_system_ram_range() search child resources
- Intel: mm/memory-hotplug: Allow memory resources to be children
- Intel: mm/resource: Move HMM pr_debug() deeper into resource code
- Intel: device-dax: Add a 'modalias' attribute to DAX 'bus' devices
- Intel: device-dax: Add a 'target_node' attribute
- Intel: device-dax: Auto-bind device after successful new_id
- Intel: acpi/nfit, device-dax: Identify differentiated memory with a unique numa-node
- Intel: device-dax: Add /sys/class/dax backwards compatibility
- Intel: device-dax: Add support for a dax override driver
- Intel: device-dax: Move resource pinning+mapping into the common driver
- Intel: device-dax: Introduce bus + driver model
- Intel: device-dax: Start defining a dax bus model
- Intel: device-dax: Remove multi-resource infrastructure
- Intel: device-dax: Kill dax_region base
- Intel: device-dax: Kill dax_region ida
- Intel: dmaengine: ioatdma: support latency tolerance report (LTR) for v3.4
- Intel: dmaengine: ioatdma: add descriptor pre-fetch support for v3.4
- Intel: dmaengine: ioatdma: disable DCA enabling on IOATDMA v3.4
- Intel: dmaengine: ioatdma: Add Snow Ridge ioatdma device id
- perf/x86/intel: Add Tremont core PMU support
- perf/x86/intel: Add Icelake support
- perf/x86: Support constraint ranges
- PCI/PME: Fix kernel-doc of pcie_pme_resume() and pcie_pme_remove()
- PCI: Add PCIE_LNKCAP2_SLS2SPEED() macro
- PCI: Use pci_speed_string() for all PCI/PCI-X/PCIe strings
- PCI: Add pci_speed_string()
- PCI: Add 32 GT/s decoding in some macros
- PCI: Decode PCIe 32 GT/s link speed
- PCI/AER: Log which device prevents error recovery
- PCI/AER: Initialize aer_fifo
- PCI/AER: Use kfifo for tracking events instead of reimplementing it
- PCI/AER: Remove error source from AER struct aer_rpc
- Intel: PCI: Add support for Immediate Readiness
- ia64: ensure proper NUMA distance and possible map initialization
- sched/topology: Make sched_init_numa() use a set for the deduplicating sort
- block: don't call rq_qos_ops->done_bio if the bio isn't tracked
- block: fix blk-iolatency accounting underflow
- ovl: fix missing negative dentry check in ovl_rename()
- ext4: flush s_error_work before journal destroy in ext4_fill_super
- Revert "ext4: fix panic when mount failed with parallel flush_stashed_error_work"
- ext4: refresh the ext4_ext_path struct after dropping i_data_sem.
- ext4: ensure enough credits in ext4_ext_shift_path_extents
- ext4: use true,false for bool variable

* Tue Oct 12 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2110.3.0.0116
- net: 6pack: fix slab-out-of-bounds in decode_data

* Mon Oct 11 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2110.2.0.0115
- bpf: Fix integer overflow in prealloc_elems_and_freelist()

* Fri Oct 08 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2110.1.0.0114
- timerqueue: fix kabi for struct timerqueue_head
- lib/timerqueue: Rely on rbtree semantics for next timer
- ACPI / APEI: Notify all ras err to driver
- ACPI / APEI: Add a notifier chain for unknown (vendor) CPER records
- blk-mq-sched: Fix blk_mq_sched_alloc_tags() error handling
- jbd2: protect jh by grab a ref in jbd2_journal_forget
- jbd2: Don't call __bforget() unnecessarily
- jbd2: Drop unnecessary branch from jbd2_journal_forget()
- ipc: replace costly bailout check in sysvipc_find_ipc()
- sched/topology: fix the issue groups don't span domain->span for NUMA diameter > 2
- sched/topology: Warn when NUMA diameter > 2
- USB: ehci: fix an interrupt calltrace error
- net: hns3: update hns3 version to 21.9.4
- net: hns3: expand buffer len for fd tcam of debugfs
- net: hns3: fix hns3 debugfs queue info print coverage bugs
- net: hns3: fix memory override when bd_num is bigger than port info size
- scsi: hisi_sas: Optimize the code flow of setting sense data when ssp I/O abnormally completed

* Wed Sep 29 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2109.8.0.0113
- Bluetooth: fix use-after-free error in lock_sock_nested()
- bpf, mips: Validate conditional branch offsets
- scsi: qla2xxx: Fix crash in qla2xxx_mqueuecommand()
- crypto: ccp - fix resource leaks in ccp_run_aes_gcm_cmd()
- bpf: Fix truncation handling for mod32 dst reg wrt zero
- bpf: Fix 32 bit src register truncation on div/mod
- bpf: Do not use ax register in interpreter on div/mod
- Revert "bpf: allocate 0x06 to new eBPF instruction class JMP32"
- Revert "bpf: refactor verifier min/max code for condition jump"
- Revert "bpf: verifier support JMP32"
- Revert "bpf: disassembler support JMP32"
- Revert "tools: bpftool: teach cfg code about JMP32"
- Revert "bpf: interpreter support for JMP32"
- Revert "bpf: JIT blinds support JMP32"
- Revert "x86_64: bpf: implement jitting of JMP32"
- Revert "arm64: bpf: implement jitting of JMP32"
- Revert "bpf: Fix 32 bit src register truncation on div/mod"
- Revert "bpf: Fix truncation handling for mod32 dst reg wrt zero"
- block: fix wrong define name
- block: fix compile error when CONFIG_BLK_DEV_THROTTLING disable
- pid: fix imbalanced calling of cgroup_threadgroup_change_begin/end()
- pid: fix return value when copy_process() failed
- block: fix NULL pointer in blkcg_drain_queue()
- block: clean up ABI breakage
- block: mark queue init done at the end of blk_register_queue
- block: fix race between adding/removing rq qos and normal IO
- scsi: hisi_sas: set sense data when the sas disk's I/O abnormally completed
- kyber: initialize 'async_depth' in kyber_queue_data_alloc()
- kyber: introduce kyber_depth_updated()
- blk-mq: handle all throttled io in blk_cleanup_queue()

* Wed Sep 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2109.7.0.0112
- memcg: enable accounting for ldt_struct objects
- memcg: enable accounting for posix_timers_cache slab
- memcg: enable accounting for signals
- memcg: enable accounting for new namesapces and struct nsproxy
- memcg: enable accounting for fasync_cache
- memcg: enable accounting for mnt_cache entries
- memcg: enable accounting for pids in nested pid namespaces
- KVM: do not allow mapping valid but non-reference-counted pages
- nvme: remove the call to nvme_update_disk_info in nvme_ns_remove
- block: flush the integrity workqueue in blk_integrity_unregister
- block: check if a profile is actually registered in blk_integrity_unregister
- blk-mq: fix kabi broken in blk_mq_tags
- blk-mq: fix is_flush_rq
- blk-mq: fix kernel panic during iterating over flush request
- block: factor out a new helper from blk_rq_init()
- blk-mq: don't grab rq's refcount in blk_mq_check_expired()
- blk-mq: clearing flush request reference in tags->rqs[]
- blk-mq: clear stale request in tags->rq[] before freeing one request pool
- blk-mq: grab rq->refcount before calling ->fn in blk_mq_tagset_busy_iter
- Revert "blk-mq: use static_rqs instead of rqs to iterate tags"
- Revert "blk-mq: use blk_mq_queue_tag_inflight_iter() in debugfs"
- Revert "nbd: use blk_mq_queue_tag_inflight_iter()"
- blk-cgroup: fix UAF by grabbing blkcg lock before destroying blkg pd
- tasks: Fix kabi broken for struct task_struct
- tasks, sched/core: RCUify the assignment of rq->curr
- tasks, sched/core: With a grace period after finish_task_switch(), remove unnecessary code
- tasks, sched/core: Ensure tasks are available for a grace period after leaving the runqueue
- tasks: Add a count of task RCU users
- Revert "sched/membarrier: fix NULL poiner in membarrier_global_expedited"
- ext4: update last_pos for the case ext4_htree_fill_tree return fail
- blk-throttle: fix UAF by deleteing timer in blk_throtl_exit()
- nvme-rdma: don't update queue count when failing to set io queues
- scsi: hisi_sas: replace spin_lock_irqsave/spin_unlock_restore with spin_lock/spin_unlock
- scsi: hisi_sas: use threaded irq to process CQ interrupts

* Wed Sep 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2109.6.0.0111
- ext4: fix race writing to an inline_data file while its xattrs are changing
- uce: pagecache reading scenario add shmem support
- Revert "uce: pagecache reading scenario add shmem support"
- memcg: enable accounting of ipc resources
- uce: pagecache reading scenario add shmem support
- misc/uacce: fixup out-of-bounds array write
- crypto/sec: add aead support for user-side

* Mon Sep 13 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2109.5.0.0110
- nvme-pci: Use u32 for nvme_dev.q_depth and nvme_queue.q_depth
- nvme-pci: use unsigned for io queue depth
- net: hns3: update hns3 version to 21.9.2
- net: hns3: the pointer is cast to another pointer in a different type, which is incompatible.
- net: hns3: cleanup for some print type miss match and blank lines
- net: hns3: remove tc enable checking
- net: hns3: Constify static structs
- net: hns3: fix kernel crash when unload VF while it is being reset
- net: hns3: fix memory override when bd_num is bigger than the ring size
- net: hns3: pad the short tunnel frame before sending to hardware
- net: hns3: check the return of skb_checksum_help()
- net: hns3: add 'QoS' support for port based VLAN configuration
- net: hns3: remove unused parameter from hclge_set_vf_vlan_common()
- net: hns3: disable port VLAN filter when support function level VLAN filter control
- net: hns3: remove redundant param mbx_event_pending
- net: hns3: remove the useless debugfs file node cmd
- net: hns3: fix get wrong pfc_en when query PFC configuration
- net: hns3: fix mixed flag HCLGE_FLAG_MQPRIO_ENABLE and HCLGE_FLAG_DCB_ENABLE
- net: hns3: add support for tc mqprio offload
- net: hns3: add debugfs support for vlan configuration
- net: hns3: add support for VF modify VLAN filter state
- net: hns3: add query basic info support for VF
- net: hns3: add support for modify VLAN filter state
- Revert: net: hns3: adds support for extended VLAN mode and 'QOS' in vlan 802.1Q protocol.
- net: hns3: change the method of getting cmd index in debugfs
- net: hns3: refactor dump mac tbl of debugfs
- net: hns3: add support for dumping MAC umv counter in debugfs
- net: hns3: refactor dump serv info of debugfs
- net: hns3: refactor dump mac tnl status of debugfs
- net: hns3: refactor dump qs shaper of debugfs
- net: hns3: refactor dump qos buf cfg of debugfs
- net: hns3: split out hclge_dbg_dump_qos_buf_cfg()
- net: hns3: refactor dump qos pri map of debugfs
- net: hns3: refactor dump qos pause cfg of debugfs
- net: hns3: refactor dump tc of debugfs
- net: hns3: refactor dump tm of debugfs
- net: hns3: refactor dump tm map of debugfs
- net: hns3: refactor dump fd tcam of debugfs
- net: hns3: refactor queue info of debugfs
- net: hns3: refactor queue map of debugfs
- net: hns3: refactor dump reg dcb info of debugfs
- net: hns3: refactor dump reg of debugfs
- net: hns3: Constify static structs
- net: hns3: refactor dump ncl config of debugfs
- net: hns3: refactor dump m7 info of debugfs
- net: hns3: refactor dump reset info of debugfs
- net: hns3: refactor dump intr of debugfs
- net: hns3: refactor dump loopback of debugfs
- net: hns3: refactor dump mng tbl of debugfs
- net: hns3: refactor dump mac list of debugfs
- net: hns3: refactor dump bd info of debugfs
- net: hns3: refactor the debugfs process
- net: hns3: add debugfs support for tm priority and qset info
- net: hns3: add interfaces to query information of tm priority/qset
- net: hns3: change the value of the SEPARATOR_VALUE macro in hclgevf_main.c
- net: hns3: fix for vxlan gpe tx checksum bug
- net: hns3: Fix for geneve tx checksum bug
- net: hns3: refine the struct hane3_tc_info
- net: hns3: VF not request link status when PF support push link status feature
- net: hns3: remove a duplicate pf reset counting
- net: hns3: remediate a potential overflow risk of bd_num_list
- net: hns3: fix query vlan mask value error for flow director
- net: hns3: fix error mask definition of flow director
- net: hns3: cleanup for endian issue for VF RSS
- net: hns3: fix incorrect handling of sctp6 rss tuple
- net: hns3: refine function hclge_set_vf_vlan_cfg()
- net: hns3: dump tqp enable status in debugfs
- hisilicon/hns3: convert comma to semicolon
- net: hns3: remove a misused pragma packed
- net: hns3: add debugfs of dumping pf interrupt resources
- net: hns3: Supply missing hclge_dcb.h include file
- net: hns3: print out speed info when parsing speed fails
- net: hns3: add a missing mutex destroy in hclge_init_ad_dev()
- net: hns3: add a print for initializing CMDQ when reset pending
- net: hns3: replace snprintf with scnprintf in hns3_update_strings
- net: hns3: change affinity_mask to numa node range
- net: hns3: change hclge/hclgevf workqueue to WQ_UNBOUND mode
- tcp_comp: Del compressed_data and remaining_data from tcp_comp_context_rx
- tcp_comp: Add dpkt to save decompressed skb
- tcp_comp: Fix ZSTD_decompressStream failed
- mm: downgrade the print level in do_shrink_slab
- uio: introduce UIO_MEM_IOVA
- mm/mempolicy.c: fix checking unmapped holes for mbind
- mm/mempolicy.c: check range first in queue_pages_test_walk
- net: qrtr: fix another OOB Read in qrtr_endpoint_post
- net: qrtr: fix OOB Read in qrtr_endpoint_post
- mm, slab, slub: stop taking cpu hotplug lock
- mm, slab, slub: stop taking memory hotplug lock
- mm, slub: stop freeing kmem_cache_node structures on node offline
- kernel/hung_task.c: introduce sysctl to print all traces when a hung task is detected
- vt_kdsetmode: extend console locking

* Mon Sep 06 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2109.2.0.0109
- cpuidle: menu: Avoid computations when result will be discarded
- virtio_blk: fix handling single range discard request
- virtio_blk: add discard and write zeroes support
- iommu/arm-smmu-v3: add bit field SFM into GERROR_ERR_MASK
- page_alloc: consider highatomic reserve in watermark fast
- mm/filemap.c: fix a data race in filemap_fault()
- scsi/hifc: Fix memory leakage bug
- RDMA/hns: Fix wrong timer context buffer page size
- RDMA/hns: Bugfix for posting multiple srq work request
- RDMA/hns: Fix 0-length sge calculation error
- RDMA/hns: Fix configuration of ack_req_freq in QPC
- RDMA/hns: Add check for the validity of sl configuration
- RDMA/hns: Fix bug during CMDQ initialization
- RDMA/hns: Fixed wrong judgments in the goto branch
- RDMA/hns: Bugfix for checking whether the srq is full when post wr
- RDMA/hns: Fix wrong parameters when initial mtt of srq->idx_que
- RDMA/hns: Force rewrite inline flag of WQE
- RDMA/hns: Fix missing assignment of max_inline_data
- RDMA/hns: Avoid enabling RQ inline on UD
- RDMA/hns: Support to query firmware version
- RDMA/hns: Force srq_limit to 0 when creating SRQ
- RDMA/hns: Add interception for resizing SRQs
- RDMA/hns: Fix an cmd queue issue when resetting

* Wed Sep 01 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2109.1.0.0108
- iommu: smmuv2: Using the SMMU_BYPASS_DEV to bypass SMMU for some SoCs
- iommu: dev_bypass: cleanup dev bypass code
- arm64: phytium: using MIDR_PHYTIUM_FT2000PLUS instead of ARM_CPU_IMP_PHYTIUM
- arm64: Add MIDR encoding for PHYTIUM CPUs
- arm64: Add MIDR encoding for HiSilicon Taishan CPUs
- sched: Fix sched_fork() access an invalid sched_task_group
- KVM: nSVM: avoid picking up unsupported bits from L2 in int_ctl (CVE-2021-3653)
- KVM: nSVM: always intercept VMLOAD/VMSAVE when nested (CVE-2021-3656)
- Bluetooth: switch to lock_sock in SCO
- Bluetooth: avoid circular locks in sco_sock_connect
- Bluetooth: schedule SCO timeouts with delayed_work
- Bluetooth: defer cleanup of resources in hci_unregister_dev()

* Mon Aug 30 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2108.9.0.0107
- tcp_comp: Fix comp_read_size return value
- virtio-blk: Add validation for block size in config space
- blk-mq: fix divide by zero crash in tg_may_dispatch()
- mm, vmscan: guarantee drop_slab_node() termination
- jump_label: skip resource release if jump label is not relocated
- ext4: prevent getting empty inode buffer
- ext4: move ext4_fill_raw_inode() related functions before __ext4_get_inode_loc()
- ext4: factor out ext4_fill_raw_inode()
- ext4: make the updating inode data procedure atomic
- KVM: X86: MMU: Use the correct inherited permissions to get shadow page
- x86/config: Enable CONFIG_USERSWAP for openeuler_defconfig
- ext4: fix panic when mount failed with parallel flush_stashed_error_work
- device core: Consolidate locking and unlocking of parent and device
- Revert "ext4: flush s_error_work before journal destroy in ext4_fill_super"
- ext2: Strengthen xattr block checks
- ext2: Merge loops in ext2_xattr_set()
- ext2: introduce helper for xattr entry validation
- mm: rmap: explicitly reset vma->anon_vma in unlink_anon_vmas()

* Tue Aug 24 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2108.8.0.0106
- bpf: Fix leakage due to insufficient speculative store bypass mitigation
- bpf: Introduce BPF nospec instruction for mitigating Spectre v4
- bpf: track spill/fill of constants
- bpf/verifier: per-register parent pointers
- blk-mq: clear active_queues before clearing BLK_MQ_F_TAG_QUEUE_SHARED

* Mon Aug 23 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2108.7.0.0105
- scsi: hisi_sas: Flush workqueue in hisi_sas_v3_remove()
- nvme: force complete cancelled requests
- blk-mq: blk-mq: provide forced completion method
- ext4: flush s_error_work before journal destroy in ext4_fill_super
- Revert "net: make get_net_ns return error if NET_NS is disabled"
- kthread: Fix PF_KTHREAD vs to_kthread() race
- sched/debug: Fix 'sched_debug_lock' undeclared error
- Remove MODULE_ALIAS() calls that take undefined macro
- scripts/dtc: Remove redundant YYLOC global declaration
- x86/boot/compressed: Don't declare __force_order in kaslr_64.c
- usb: hso: fix error handling code of hso_create_net_device
- hso: fix bailout in error case of probe


* Tue Aug 17 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2108.5.0.0104
- spec: fixed the mistake for dates in kernel.spec

* Tue Aug 17 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2108.5.0.0103
- iscsi: Fix KABI change for 'Fix conn use after free during resets'
- iscsi: alloc iscsi_cls_session with iscsi_cls_session_warpper
- iscsi: introduce iscsi_cls_session_warapper and helper
- scsi: iscsi: Fix conn use after free during resets
- scsi: sr: Return correct event when media event code is 3
- net: xilinx_emaclite: Do not print real IOMEM pointer
- sctp: move the active_key update after sh_keys is added
- usb: max-3421: Prevent corruption of freed memory
- net: ll_temac: Fix bug causing buffer descriptor overrun
- tcp_comp: Avoiding the null pointer problem of ctx in comp_stream_read
- nbd: add the check to prevent overflow in __nbd_ioctl()
- ext4: fix potential uninitialized access to retval in kmmpd
- blk-mq: fix kabi broken by "blk-mq: fix hang caused by freeze/unfreeze sequence"
- blk-mq: fix hang caused by freeze/unfreeze sequence
- config: Enable CONFIG_UCE_KERNEL_RECOVERY by default
- EDAC/ghes: Remove intermediate buffer pvt->detail_location
- USB: fix some clerical mistakes
- uce: pagecache reading scenario support kernel recovery
- uce: cow scenario support kernel recovery
- selinux: fix NULL dereference in policydb_destroy()
- livepatch/x86: Ignore return code of save_stack_trace_tsk_reliable()
- mm,hwpoison: return -EHWPOISON to denote that the page has already been poisoned
- mm/memory-failure: use a mutex to avoid memory_failure() races
- arm64: mm: account for hotplug memory when randomizing the linear region


* Fri Aug 13 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2108.4.0.0102
- test modules directory existed when ls

* Tue Aug 10 2021 Gou Hao <gouhao@uniontech.com> -4.19.90-2108.4.0.0101
- fix rpmbuild error with patches

* Tue Aug 10 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2108.4.0.0100
- openeuler_defconfig: Enable ARCH_PHYTIUM and ARM_GIC_PHYTIUM_2500
- config: Enable Phytium FT-2500 support configs for hulk_defconfig
- irqchip: phytium-2500: Add interrupt controller driver
- mm/vmscan: setup drop_caches_loop_limit in cmdline
- mm/memcg: optimize memory.numa_stat like memory.stat
- livepatch: Fix crash when access the global variable in hook
- timer: Use hlist_unhashed_lockless() in timer_pending()
- list: Add hlist_unhashed_lockless()
- config: Enable CONFIG_GPIO_HISI by default
- gpio: gpio-hisi: Add HiSilicon GPIO support
- config: Enable CONFIG_I2C_HISI by default
- i2c: add support for HiSilicon I2C controller
- i2c: core: add api to provide frequency mode strings
- i2c: core: add managed function for adding i2c adapters
- blk: reuse lookup_sem to serialize partition operations
- Revert "block: take bd_mutex around delete_partitions in del_gendisk"
- Revert "block: avoid creating invalid symlink file for patitions"
- Revert "block: call bdput() to avoid memleak"
- sctp: fix return value check in __sctp_rcv_asconf_lookup
- workqueue: fix UAF in pwq_unbound_release_workfn()
- exit: Move preemption fixup up, move blocking operations down
- Input: joydev - prevent use of not validated data in JSIOCSBTNMAP ioctl
- Input: joydev - prevent potential read overflow in ioctl
- srcu: Take early exit on memory-allocation failure
- Revert "modpost: add read_text_file() and get_line() helpers"
- Revert "modpost: use read_text_file() and get_line() for reading text files"
- Revert "modpost: remove use of non-standard strsep() in HOSTCC code"
- Revert "modpost: explain why we can't use strsep"
- cpuidle: fix return type err in haltpoll_switch_governor
- mm/slab: add naive detection of double free
- mm/mempool: fix a data race in mempool_free()
- mm/list_lru: fix a data race in list_lru_count_one
- mm/cma.c: fix NULL pointer dereference when cma could not be activated
- iommu/amd: Prevent NULL pointer dereference

* Mon Aug 02 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2108.1.0.0099
- bcache: always record start time of a sample
- bcache: do not collect data insert info created by write_moving
- tcp_comp: open configs for tcp compression
- tcp_comp: implement recvmsg for tcp compression
- tcp_comp: implement sendmsg for tcp compression
- tcp_comp: add stub proto ops for tcp compression socket
- tcp_comp: allow ignore local tcp connections
- tcp_comp: only enable compression for give server ports
- tcp_comp: add sysctl for enable/disable compression
- tcp_comp: add init and cleanup hook for compression
- tcp_comp: add tcp comp option to SYN and SYN-ACK
- tcp_comp: add Kconfig for tcp payload compression
- tracing: Fix bug in rb_per_cpu_empty() that might cause deadloop.
- proc: Avoid mixing integer types in mem_rw()
- net: sched: cls_api: Fix the the wrong parameter
- sctp: update active_key for asoc when old key is being replaced
- nvme-pci: don't WARN_ON in nvme_reset_work if ctrl.state is not RESETTING
- net/sched: act_skbmod: Skip non-Ethernet packets
- net/tcp_fastopen: fix data races around tfo_active_disable_stamp
- scsi: target: Fix protect handling in WRITE SAME(32)
- scsi: iscsi: Fix iface sysfs attr detection
- nvme-pci: do not call nvme_dev_remove_admin from nvme_remove
- ipv6: fix 'disable_policy' for fwd packets
- net: ip_tunnel: fix mtu calculation for ETHER tunnel devices
- udp: annotate data races around unix_sk(sk)->gso_size
- ipv6: tcp: drop silly ICMPv6 packet too big messages
- tcp: annotate data races around tp->mtu_info
- dma-buf/sync_file: Don't leak fences on merge failure
- net: validate lwtstate->data before returning from skb_tunnel_info()
- net: send SYNACK packet with accepted fwmark
- net: bridge: sync fdb to new unicast-filtering ports
- netfilter: ctnetlink: suspicious RCU usage in ctnetlink_dump_helpinfo
- dm writecache: fix writing beyond end of underlying device when shrinking
- dm writecache: return the exact table values that were set
- dm multipath: use updated MPATHF_QUEUE_IO on mapping for bio-based mpath
- dm writecache: fix data corruption when reloading the target
- dm verity fec: fix hash block number in verity_fec_decode
- sched/fair: Fix CFS bandwidth hrtimer expiry type
- scsi: libfc: Fix array index out of bound exception
- scsi: scsi_dh_alua: Fix signedness bug in alua_rtpg()
- net: bridge: multicast: fix PIM hello router port marking race
- NFSv4/pNFS: Don't call _nfs4_pnfs_v3_ds_connect multiple times
- virtio_net: move tx vq operation under tx queue lock
- x86/fpu: Limit xstate copy size in xstateregs_set()
- nfs: fix acl memory leak of posix_acl_create()
- NFSv4: Initialise connection to the server in nfs4_alloc_client()
- PCI/sysfs: Fix dsm_label_utf16s_to_utf8s() buffer overrun
- virtio_console: Assure used length from device is limited
- virtio_net: Fix error handling in virtnet_restore()
- virtio-blk: Fix memory leak among suspend/resume procedure
- NFS: nfs_find_open_context() may only select open files
- lib/decompress_unlz4.c: correctly handle zero-padding around initrds.
- i2c: core: Disable client irq on reboot/shutdown
- scsi: qedi: Fix null ref during abort handling
- scsi: iscsi: Fix shost->max_id use
- scsi: iscsi: Add iscsi_cls_conn refcount helpers
- scsi: scsi_dh_alua: Check for negative result value
- tracing: Do not reference char * as a string in histograms
- scsi: core: Fix bad pointer dereference when ehandler kthread is invalid
- seq_buf: Fix overflow in seq_buf_putmem_hex()
- ipmi/watchdog: Stop watchdog timer when the current action is 'none'
- net: ip: avoid OOM kills with large UDP sends over loopback
- vsock: notify server to shutdown when client has pending signal
- xfrm: Fix error reporting in xfrm_state_construct.
- virtio_net: Remove BUG() to avoid machine dead
- dm space maps: don't reset space map allocation cursor when committing
- ipv6: use prandom_u32() for ID generation
- mm/huge_memory.c: don't discard hugepage if other processes are mapping it
- vfio/pci: Handle concurrent vma faults
- vfio-pci: Use io_remap_pfn_range() for PCI IO memory
- writeback: fix obtain a reference to a freeing memcg css
- ipv6: fix out-of-bound access in ip6_parse_tlv()
- bpf: Do not change gso_size during bpf_skb_change_proto()
- ipv6: exthdrs: do not blindly use init_net
- net/ipv4: swap flow ports when validating source
- vxlan: add missing rcu_read_lock() in neigh_reduce()
- pkt_sched: sch_qfq: fix qfq_change_class() error path
- netfilter: nft_tproxy: restrict support to TCP and UDP transport protocols
- netfilter: nft_osf: check for TCP packet before further processing
- netfilter: nft_exthdr: check for IPv6 packet before further processing
- netlabel: Fix memory leak in netlbl_mgmt_add_common
- ACPI: sysfs: Fix a buffer overrun problem with description_show()
- evm: fix writing <securityfs>/evm overflow
- lib: vsprintf: Fix handling of number field widths in vsscanf
- ACPI: processor idle: Fix up C-state latency if not ordered
- fuse: check connected before queueing on fpq->io
- evm: Refuse EVM_ALLOW_METADATA_WRITES only if an HMAC key is loaded
- evm: Execute evm_inode_init_security() only when an HMAC key is loaded
- seq_buf: Make trace_seq_putmem_hex() support data longer than 8
- ext4: use ext4_grp_locked_error in mb_find_extent
- ext4: fix avefreec in find_group_orlov
- ext4: remove check for zero nr_to_scan in ext4_es_scan()
- ext4: correct the cache_nr in tracepoint ext4_es_shrink_exit
- ext4: return error code when ext4_fill_flex_info() fails
- ext4: fix kernel infoleak via ext4_extent_header
- iov_iter_fault_in_readable() should do nothing in xarray case
- scsi: core: Retry I/O for Notify (Enable Spinup) Required error
- kthread: prevent deadlock when kthread_mod_delayed_work() races with kthread_cancel_delayed_work_sync()
- kthread_worker: split code for canceling the delayed work timer
- scsi: sr: Return appropriate error code when disk is ejected
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
- mm/rmap: use page_not_mapped in try_to_unmap()
- mm/rmap: remove unneeded semicolon in page_not_mapped()
- mm: add VM_WARN_ON_ONCE_PAGE() macro
- sctp: add param size validation for SCTP_PARAM_SET_PRIMARY
- sctp: validate chunk size in __rcv_asconf_lookup
- stop_machine: Avoid potential race behaviour
- KVM: PPC: Book3S: Fix H_RTAS rets buffer overflow
- can: raw: fix raw_rcv panic for sock UAF
- mm/page_isolation: do not isolate the max order page
- mm/zswap: fix passing zero to 'PTR_ERR' warning
- mm/page_alloc: speed up the iteration of max_order
- mm: hugetlb: fix type of delta parameter and related local variables in gather_surplus_pages()
- mm/vmalloc.c:__vmalloc_area_node(): avoid 32-bit overflow
- sctp: add size validation when walking chunks
- sctp: validate from_addr_param return
- jbd2: fix kabi broken in struct journal_s
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
- mm: vmscan: use a new flag to indicate shrinker is registered
- Revert "jbd2: remove the out label in __jbd2_journal_remove_checkpoint()"
- Revert "jbd2: ensure abort the journal if detect IO error when writing original buffer back"
- Revert "jbd2: fix kabi broken in struct journal_s"
- Revert "jbd2: don't abort the journal when freeing buffers"
- mm/vmscan: add drop_caches_loop_limit to break loop in drop_slab_node
- mm/vmscan: fix infinite loop in drop_slab_node
- userswap: add a kernel parameter to enable userswap
- userfaultfd: fix BUG_ON() in userfaultfd_release()
- kprobes: Warn if the kprobe is reregistered
- Revert "kretprobe: check re-registration of the same kretprobe earlier"

* Tue Jul 27 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2107.5.0.0098
- mm: vmalloc: prevent use after free in _vm_unmap_aliases
- PCI/sysfs: Take reference on device to be removed
- seq_file: disallow extremely large seq buffer allocations
- ARM: footbridge: remove personal server platform
- mm: slab: fix kmem_cache_create failed when sysfs node not destroyed
- ARM: ensure the signal page contains defined contents
- nvme-pci: use atomic bitops to mark a queue enabled
- nvme: check the PRINFO bit before deciding the host buffer length
- nvme: fix compat address handling in several ioctls
- nvme-core: make implicit seed truncation explicit
- nvme-core: don't use NVME_NSID_ALL for command effects and supported log
- nvme-pci: fix NULL req in completion handler
- nvme-pci: cancel nvme device request before disabling
- nvme: copy MTFA field from identify controller
- nvme-pci: Unblock reset_work on IO failure
- nvme-pci: Don't disable on timeout in reset state
- nvme-pci: Fix controller freeze wait disabling
- block: error out if blk_get_queue() failed in blk_init_rl()

* Tue Jul 20 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2107.4.0.0097
- Revert "smp: Fix smp_call_function_single_async prototype"
- Revert "vt: Fix character height handling with VT_RESIZEX"
- block: only call sched requeue_request() for scheduled requests
- KVM: arm: replace WARN_ON with pr_warn for UNKNOWN type
- net/packet: annotate accesses to po->ifindex
- net/packet: annotate accesses to po->bind
- inet: annotate date races around sk->sk_txhash
- ping: Check return value of function 'ping_queue_rcv_skb'
- net: ethtool: clear heap allocations for ethtool function
- x86/fpu: Reset state for all signal restore failures
- inet: use bigger hash table for IP ID generation
- net: bridge: fix vlan tunnel dst refcnt when egressing
- net: bridge: fix vlan tunnel dst null pointer dereference
- tracing: Do no increment trace_clock_global() by one
- tracing: Do not stop recording comms if the trace file is being read
- tracing: Do not stop recording cmdlines when tracing is off
- icmp: don't send out ICMP messages with a source address of 0.0.0.0
- net/af_unix: fix a data-race in unix_dgram_sendmsg / unix_release_sock
- net: ipv4: fix memory leak in ip_mc_add1_src
- net: make get_net_ns return error if NET_NS is disabled
- net: add documentation to socket.c
- sch_cake: Fix out of bounds when parsing TCP options and header
- netfilter: synproxy: Fix out of bounds when parsing TCP options
- rtnetlink: Fix regression in bridge VLAN configuration
- udp: fix race between close() and udp_abort()
- net: ipv4: fix memory leak in netlbl_cipsov4_add_std
- fib: Return the correct errno code
- net: Return the correct errno code
- rtnetlink: Fix missing error code in rtnl_bridge_notify()
- net: ipconfig: Don't override command-line hostnames or domains
- nvme-loop: check for NVME_LOOP_Q_LIVE in nvme_loop_destroy_admin_queue()
- nvme-loop: clear NVME_LOOP_Q_LIVE when nvme_loop_configure_admin_queue() fails
- nvme-loop: reset queue count to 1 in nvme_loop_destroy_io_queues()
- scsi: target: core: Fix warning on realtime kernels
- proc: only require mm_struct for writing
- tracing: Correct the length check which causes memory corruption
- ftrace: Do not blindly read the ip address in ftrace_bug()
- scsi: core: Only put parent device if host state differs from SHOST_CREATED
- scsi: core: Put .shost_dev in failure path if host state changes to RUNNING
- scsi: core: Fix error handling of scsi_host_alloc()
- NFSv4: nfs4_proc_set_acl needs to restore NFS_CAP_UIDGID_NOMAP on error.
- NFS: Fix use-after-free in nfs4_init_client()
- NFS: Fix a potential NULL dereference in nfs_get_client()
- sched/fair: Make sure to update tg contrib for blocked load
- perf: Fix data race between pin_count increment/decrement
- cgroup1: don't allow '
- wq: handle VM suspension in stall detection
- cgroup: disable controllers at parse time
- net: mdiobus: get rid of a BUG_ON()
- netlink: disable IRQs for netlink_lock_table()
- bonding: init notify_work earlier to avoid uninitialized use
- proc: Track /proc/$pid/attr/ opener mm_struct
- ACPI: EC: Look for ECDT EC after calling acpi_load_tables()
- ACPI: probe ECDT before loading AML tables regardless of module-level code flag
- mm, hugetlb: fix simple resv_huge_pages underflow on UFFDIO_COPY
- x86/apic: Mark _all_ legacy interrupts when IO/APIC is missing
- pid: take a reference when initializing `cad_pid`
- netfilter: nfnetlink_cthelper: hit EBUSY on updates if size mismatches
- ipvs: ignore IP_VS_SVC_F_HASHED flag when adding service
- vfio/platform: fix module_put call in error flow
- vfio/pci: zap_vma_ptes() needs MMU
- vfio/pci: Fix error return code in vfio_ecap_init()
- efi: cper: fix snprintf() use in cper_dimm_err_location()
- efi: Allow EFI_MEMORY_XP and EFI_MEMORY_RO both to be cleared
- lib/clear_user: ensure loop in __arch_clear_user cache-aligned
- scsi: core: Treat device offline as a failure
- Revert "scsi: check the whole result for reading write protect flag"
- ext4: fix WARN_ON_ONCE(!buffer_uptodate) after an error writing the superblock
- arm64/config: Set CONFIG_TXGBE=m by default
- make bch_btree_check() to be multiple threads
- Make compile successful when CONFIG_BCACHE is not set.
- Move only dirty data when gc runnning, in order to reducing write amplification.
- Add traffic policy for low cache available.
- igmp: Add ip_mc_list lock in ip_check_mc_rcu
- memcg: fix unsuitable null check after alloc memory
- cpuidle: fix a build error when compiling haltpoll into module
- config: enable KASAN and UBSAN by default
- KVM: x86: expose AVX512_BF16 feature to guest
- KVM: cpuid: remove has_leaf_count from struct kvm_cpuid_param
- KVM: cpuid: rename do_cpuid_1_ent
- KVM: cpuid: set struct kvm_cpuid_entry2 flags in do_cpuid_1_ent
- KVM: cpuid: extract do_cpuid_7_mask and support multiple subleafs
- KVM: cpuid: do_cpuid_ent works on a whole CPUID function
- ext4: fix possible UAF when remounting r/o a mmp-protected file system
- locks: Fix UBSAN undefined behaviour in flock64_to_posix_lock
- iomap: Mark read blocks uptodate in write_begin
- iomap: Clear page error before beginning a write
- iomap: move the zeroing case out of iomap_read_page_sync
- nbd: handle device refs for DESTROY_ON_DISCONNECT properly
- cifs: Fix leak when handling lease break for cached root fid
- mm/memcontrol.c: fix kasan slab-out-of-bounds in mem_cgroup_css_alloc
- module: limit enabling module.sig_enforce
- selftests/bpf: add test_spec_readahead_xfs_file to support specail async readahead
- mm: support special async readahead
- selftests/bpf: test_xfs_file support to clear FMODE_RANDOM
- xfs: let writable tracepoint enable to clear flag of f_mode
- jbd2: fix kabi broken in struct journal_s
- btrfs: allow btrfs_truncate_block() to fallback to nocow for data space reservation
- NFSv4.1: fix kabi for struct rpc_xprt
- usb: gadget: rndis: Fix info leak of rndis
- once: Fix panic when module unload
- SUNRPC: Should wake up the privileged task firstly.
- SUNRPC: Fix the batch tasks count wraparound.
- bpf: Fix leakage under speculation on mispredicted branches
- bpf: Do not mark insn as seen under speculative path verification
- bpf: Inherit expanded/patched seen count from old aux data
- bpf: Update selftests to reflect new error states
- bpf, test_verifier: switch bpf_get_stack's 0 s> r8 test
- bpf: Test_verifier, bpf_get_stack return value add <0
- bpf: extend is_branch_taken to registers
- selftests/bpf: add selftest part of "bpf: improve verifier branch analysis"
- selftests/bpf: Test narrow loads with off > 0 in test_verifier
- bpf, selftests: Fix up some test_verifier cases for unprivileged
- bpf: fix up selftests after backports were fixed
- nvme-rdma: avoid request double completion for concurrent nvme_rdma_timeout
- binfmt: Move install_exec_creds after setup_new_exec to match binfmt_elf
- ext4: fix memory leak in ext4_fill_super
- RDMA/hns: Add support for addressing when hopnum is 0
- RDMA/hns: Optimize hns buffer allocation flow
- RDMA/hns: Check if depth of qp is 0 before configure
- RDMA/hns: Optimize qp param setup flow
- RDMA/hns: Optimize qp buffer allocation flow
- RDMA/hns: Optimize qp destroy flow
- RDMA/hns: Remove asynchronic QP destroy
- RDMA/hns: Bugfix for posting a wqe with sge
- RDMA/hns: Delete unnecessary variable max_post
- RDMA/hns: optimize the duplicated code for qpc setting flow
- RDMA/hns: Prevent undefined behavior in hns_roce_set_user_sq_size()
- RDMA/umem: Add rdma_umem_for_each_dma_block()
- RDMA/verbs: Add a DMA iterator to return aligned contiguous memory blocks
- can: bcm: delay release of struct bcm_op after synchronize_rcu()
- etmem_scan: fix memleak in vm_idle_read
- x86/uprobes: Do not use prefixes.nbytes when looping over prefixes.bytes
- Revert "arm64: capabilities: Merge entries for ARM64_WORKAROUND_CLEAN_CACHE"
- Revert "arm64: capabilities: Merge duplicate Cavium erratum entries"
- Revert "arm64: capabilities: Merge duplicate entries for Qualcomm erratum 1003"
- net: hns3: update hns3 version to 1.9.40.24
- net: hns3: remove redundant assignment to rx_index
- net: hns3: Fix potential null pointer defererence of null ae_dev
- net: hns3: not reset TQP in the DOWN while VF resetting
- net: hns3: remove redundant enum type HNAE3_RESTORE_CLIENT
- net: hns3: add stats logging when skb padding fails
- net: hns3: add tx send size handling for tso skb
- net: hns3: add handling for xmit skb with recursive fraglist
- net: hns3: use napi_consume_skb() when cleaning tx desc
- net: hns3: use writel() to optimize the barrier operation
- net: hns3: optimize the rx clean process
- net: hns3: optimize the tx clean process
- net: hns3: batch tx doorbell operation
- net: hns3: batch the page reference count updates
- net: hns3: streaming dma buffer sync between cpu and device
- net: hns3: rename buffer-related functions
- net: hns3: pointer type of buffer should be void
- net: hns3: remove unnecessary devm_kfree
- net: hns3: add suspend and resume pm_ops
- Revert "net: hns3: add suspend/resume function for hns3 driver"
- net: hns3: change flr_prepare/flr_done function names
- net: hns3: change hclge_reset_done function name
- net: hns3: configure promisc mode for VF asynchronously
- kabi: add kabi list for x86_64
- kabi: update kabi list for arm64
- hugetlbfs: hugetlb_fault_mutex_hash() cleanup
- ipv6: record frag_max_size in atomic fragments in input path
- scsi: libsas: Use _safe() loop in sas_resume_port()
- SMB3: incorrect file id in requests compounded with open
- NFSv4: Fix v4.0/v4.1 SEEK_DATA return -ENOTSUPP when set NFS_V4_2 config
- NFS: Don't corrupt the value of pg_bytes_written in nfs_do_recoalesce()
- NFS: fix an incorrect limit in filelayout_decode_layout()
- dm snapshot: properly fix a crash when an origin has no snapshots
- proc: Check /proc/$pid/attr/ writes against file opener
- iommu/vt-d: Fix sysfs leak in alloc_iommu()
- NFSv4: Fix a NULL pointer dereference in pnfs_mark_matching_lsegs_return()
- cifs: set server->cipher_type to AES-128-CCM for SMB3.0
- tty: vt: always invoke vc->vc_sw->con_resize callback
- vt: Fix character height handling with VT_RESIZEX
- vgacon: Record video mode changes with VT_RESIZEX
- Revert "niu: fix missing checks of niu_pci_eeprom_read"
- Revert "qlcnic: Avoid potential NULL pointer dereference"
- Revert "rtlwifi: fix a potential NULL pointer dereference"
- Revert "media: rcar_drif: fix a memory disclosure"
- Revert "gdrom: fix a memory leak bug"
- Revert "scsi: ufs: fix a missing check of devm_reset_control_get"
- Revert "video: imsttfb: fix potential NULL pointer dereferences"
- Revert "hwmon: (lm80) fix a missing check of bus read in lm80 probe"
- Revert "leds: lp5523: fix a missing check of return value of lp55xx_read"
- Revert "net: stmicro: fix a missing check of clk_prepare"
- Revert "video: hgafb: fix potential NULL pointer dereference"
- dm snapshot: fix crash with transient storage and zero chunk size
- Revert "serial: mvebu-uart: Fix to avoid a potential NULL pointer dereference"
- Revert "rapidio: fix a NULL pointer dereference when create_workqueue() fails"
- Revert "ALSA: sb8: add a check for request_region"
- cifs: fix memory leak in smb2_copychunk_range
- locking/mutex: clear MUTEX_FLAGS if wait_list is empty due to signal
- nvmet: seset ns->file when open fails
- ptrace: make ptrace() fail if the tracee changed its pid unexpectedly
- firmware: arm_scpi: Prevent the ternary sign expansion bug
- ipv6: remove extra dev_hold() for fallback tunnels
- ip6_tunnel: sit: proper dev_{hold|put} in ndo_[un]init methods
- sit: proper dev_{hold|put} in ndo_[un]init methods
- ip6_gre: proper dev_{hold|put} in ndo_[un]init methods
- block: reexpand iov_iter after read/write
- scsi: target: tcmu: Return from tcmu_handle_completions() if cmd_id not found
- ACPI / hotplug / PCI: Fix reference count leak in enable_slot()
- nvme: do not try to reconfigure APST when the controller is not live
- netfilter: conntrack: Make global sysctls readonly in non-init netns
- kobject_uevent: remove warning in init_uevent_argv()
- blk-mq: Swap two calls in blk_mq_exit_queue()
- userfaultfd: release page in error path to avoid BUG_ON
- netfilter: nftables: avoid overflows in nft_hash_buckets()
- kernel: kexec_file: fix error return code of kexec_calculate_store_digests()
- sched/fair: Fix unfairness caused by missing load decay
- netfilter: nfnetlink_osf: Fix a missing skb_header_pointer() NULL check
- net: fix nla_strcmp to handle more then one trailing null character
- ksm: fix potential missing rmap_item for stable_node
- mm/hugeltb: handle the error case in hugetlb_fix_reserve_counts()
- khugepaged: fix wrong result value for trace_mm_collapse_huge_page_isolate()
- netfilter: xt_SECMARK: add new revision to fix structure layout
- sctp: fix a SCTP_MIB_CURRESTAB leak in sctp_sf_do_dupcook_b
- sctp: do asoc update earlier in sctp_sf_do_dupcook_a
- NFSv4.2 fix handling of sr_eof in SEEK's reply
- pNFS/flexfiles: fix incorrect size check in decode_nfs_fh()
- NFS: Deal correctly with attribute generation counter overflow
- NFSv4.2: Always flush out writes in nfs42_proc_fallocate()
- PCI: Release OF node in pci_scan_device()'s error path
- ethtool: ioctl: Fix out-of-bounds warning in store_link_ksettings_for_user()
- sctp: Fix out-of-bounds warning in sctp_process_asconf_param()
- cuse: prevent clone
- ip6_vti: proper dev_{hold|put} in ndo_[un]init methods
- tpm: fix error return code in tpm2_get_cc_attrs_tbl()
- sctp: delay auto_asconf init until binding the first addr
- Revert "net/sctp: fix race condition in sctp_destroy_sock"
- smp: Fix smp_call_function_single_async prototype
- net: Only allow init netns to set default tcp cong to a restricted algo
- mm/memory-failure: unnecessary amount of unmapping
- mm/sparse: add the missing sparse_buffer_fini() in error branch
- drivers/block/null_blk/main: Fix a double free in null_init.
- sched/debug: Fix cgroup_path[] serialization
- x86/events/amd/iommu: Fix sysfs type mismatch
- vfio/mdev: Do not allow a mdev_type to have a NULL parent pointer
- ata: libahci_platform: fix IRQ check
- x86/kprobes: Fix to check non boostable prefixes correctly
- ACPI: CPPC: Replace cppc_attr with kobj_attribute
- irqchip/gic-v3: Fix OF_BAD_ADDR error handling
- x86/microcode: Check for offline CPUs before requesting new microcode
- ovl: fix missing revert_creds() on error path
- x86/cpu: Initialize MSR_TSC_AUX if RDTSCP *or* RDPID is supported
- md: Fix missing unused status line of /proc/mdstat
- md: md_open returns -EBUSY when entering racing area
- md: factor out a mddev_find_locked helper from mddev_find
- md: split mddev_find
- md-cluster: fix use-after-free issue when removing rdev
- md/bitmap: wait for external bitmap writes to complete during tear down
- dm rq: fix double free of blk_mq_tag_set in dev remove after table load fails
- dm space map common: fix division bug in sm_ll_find_free_block()
- dm persistent data: packed struct should have an aligned() attribute too
- tracing: Restructure trace_clock_global() to never block
- tracing: Map all PIDs to command lines
- tty: fix memory leak in vc_deallocate
- ext4: fix error code in ext4_commit_super
- posix-timers: Preserve return value in clock_adjtime32()
- Revert 337f13046ff0 ("futex: Allow FUTEX_CLOCK_REALTIME with FUTEX_WAIT op")
- dm raid: fix inconclusive reshape layout on fast raid4/5/6 table reload sequences
- md/raid1: properly indicate failure when ending a failed write request
- NFSv4: Don't discard segments marked for return in _pnfs_return_layout()
- NFS: Don't discard pNFS layout segments that are marked for return
- ACPI: GTDT: Don't corrupt interrupt mappings on watchdow probe failure
- arm64/vdso: Discard .note.gnu.property sections in vDSO
- perf/arm_pmu_platform: Fix error handling
- genirq/matrix: Prevent allocation counter corruption
- crypto: api - check for ERR pointers in crypto_destroy_tfm()
- cifs: Return correct error code from smb2_get_enc_key
- ftrace: Handle commands when closing set_ftrace_filter file
- ACPI/IORT: Fix 'Number of IDs' handling in iort_id_map()
- ext4: do not use extent after put_bh
- modpost: explain why we can't use strsep
- modpost: remove use of non-standard strsep() in HOSTCC code
- modpost: use read_text_file() and get_line() for reading text files
- modpost: add read_text_file() and get_line() helpers
- arm64: capabilities: Merge duplicate entries for Qualcomm erratum 1003
- arm64: capabilities: Merge duplicate Cavium erratum entries
- arm64: capabilities: Merge entries for ARM64_WORKAROUND_CLEAN_CACHE
- net: phy: ensure phylib state machine is stopped after calling phy_stop
- net: linkwatch: add check for netdevice being present to linkwatch_do_dev
- net: phy: call state machine synchronously in phy_stop
- of: fix kmemleak crash caused by imbalance in early memory reservation
- random: fix soft lockup when trying to read from an uninitialized blocking pool
- random: only read from /dev/random after its pool has received 128 bits
- block: check queue's limits.discard_granularity in __blkdev_issue_discard()
- block: loop: set discard granularity and alignment for block device backed loop
- posix-cpu-timers: Stop disabling timers on mt-exec
- kprobes: Fix compiler warning for !CONFIG_KPROBES_ON_FTRACE
- perf top: Fix stdio interface input handling with glibc 2.28+
- iommu/vt-d: Fix mm reference leak
- iommu/dma: Fix for dereferencing before null checking
- srcu: Apply *_ONCE() to ->srcu_last_gp_end
- arm64: Kconfig: select HAVE_FUTEX_CMPXCHG
- kill kernfs_pin_sb()
- mm, thp: fix defrag setting if newline is not used
- nfsd: Clone should commit src file metadata too
- nfsd: Ensure CLONE persists data and metadata changes to the target file
- x86/sysfb: Fix check for bad VRAM size
- x86/timer: Force PIT initialization when !X86_FEATURE_ARAT
- x86/timer: Don't skip PIT setup when APIC is disabled or in legacy mode
- x86/timer: Skip PIT initialization on modern chipsets
- x86/apic: Rename 'lapic_timer_frequency' to 'lapic_timer_period'
- iommu/vt-d: Handle PCI bridge RMRR device scopes in intel_iommu_get_resv_regions
- iommu/vt-d: Handle RMRR with PCI bridge device scopes
- iommu/vt-d: Introduce is_downstream_to_pci_bridge helper
- crypto: x86 - remove SHA multibuffer routines and mcryptd
- iommu/vt-d: Duplicate iommu_resv_region objects per device list
- memcg: fix kabi broken when memory cgroup enhance
- mm: memcontrol: fix NULL-ptr deref in percpu stats flush
- mm: memcg: get number of pages on the LRU list in memcgroup base on lru_zone_size
- mm: memcontrol: fix percpu vmstats and vmevents flush
- mm, memcg: partially revert "mm/memcontrol.c: keep local VM counters in sync with the hierarchical ones"
- mm/memcontrol.c: keep local VM counters in sync with the hierarchical ones
- mm: memcontrol: flush percpu vmevents before releasing memcg
- mm: memcontrol: flush percpu vmstats before releasing memcg
- mm/memcontrol: fix wrong statistics in memory.stat
- mm: memcontrol: don't batch updates of local VM stats and events
- mm: memcontrol: fix NUMA round-robin reclaim at intermediate level
- mm: memcontrol: fix recursive statistics correctness & scalabilty
- mm: memcontrol: move stat/event counting functions out-of-line
- mm: memcontrol: make cgroup stats and events query API explicitly local
- mm: memcontrol: quarantine the mem_cgroup_[node_]nr_lru_pages() API
- mm, memcg: rename ambiguously named memory.stat counters and functions
- mm/memcontrol.c: fix memory.stat item ordering
- mm: memcontrol: expose THP events on a per-memcg basis
- mm: memcontrol: track LRU counts in the vmstats array
- mm: memcontrol: push down mem_cgroup_nr_lru_pages()
- mm: memcontrol: push down mem_cgroup_node_nr_lru_pages()
- mm: workingset: don't drop refault information prematurely
- mm: memcontrol: replace zone summing with lruvec_page_state()
- mm: memcontrol: replace node summing with memcg_page_state()
- mm, oom: add oom victim's memcg to the oom context information
- mm/oom_kill.c: fix uninitialized oc->constraint
- mm, oom: reorganize the oom report in dump_header
- memcg: update the child's qos_level synchronously in memcg_qos_write()
- memcg: Add static key for memcg priority
- memcg: fix kabi broken when enable CONFIG_MEMCG_QOS
- memcg: enable CONFIG_MEMCG_QOS by default
- memcg: support priority for oom
- scsi: core: Fix failure handling of scsi_add_host_with_dma()
- fuse: fix the ->direct_IO() treatment of iov_iter
- bdev: Do not return EBUSY if bdev discard races with write
- block: mark flush request as IDLE when it is really finished
- blk-mq: mark flush request as IDLE in flush_end_io()
- vhost_net: avoid tx queue stuck when sendmsg fails
- iommu/vt-d: Add support for ACPI device use physical, node as pci device to establish identity mapping
- io_uring: NULL files dereference by SQPOLL
- vgacon: remove software scrollback support
- block: dio: ensure the memory order between bi_private and bi_css
- ext4: fix memory leak in ext4_fill_super
- RDMA/ucma: Rework ucma_migrate_id() to avoid races with destroy
- RDMA/ucma: Add missing locking around rdma_leave_multicast()
- RDMA/ucma: Fix locking for ctx->events_reported
- RDMA/ucma: Put a lock around every call to the rdma_cm layer
- mm/memory-failure: make sure wait for page writeback in memory_failure
- can: bcm: fix infoleak in struct bcm_msg_head
- blk-wbt: make sure throttle is enabled properly
- blk-wbt: introduce a new disable state to prevent false positive by rwb_enabled()
- ext4: stop return ENOSPC from ext4_issue_zeroout
- dm btree remove: assign new_root only when removal succeeds
- block: call bdput() to avoid memleak
- scsi: remove unused kobj map for sd devie to avoid memleak
- tools build: Check if gettid() is available before providing helper
- tools build feature: Check if eventfd() is available
- tools build feature: Check if get_current_dir_name() is available
- perf tools: Use %define api.pure full instead of %pure-parser
- bpf: move new add member to the end of the struct bpf_prog_aux

* Thu Jul 08 2021 Senlin Xia <xiasenlin1@huawei.com> - 4.19.90-2106.3.0.0096
- add buildrequire: perl-devel for with_perf

* Thu Jun 17 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2106.3.0.0095
- cpuidle: fix container_of err in cpuidle_device and cpuidle_driver

* Wed Jun 16 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2106.2.0.0094
- sched/membarrier: fix NULL poiner in membarrier_global_expedited
- writeback: don't warn on an unregistered BDI in __mark_inode_dirty

* Tue Jun 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2106.1.0.0093
- fs/buffer.c: add checking buffer head stat before clear
- Bluetooth: SMP: Fail if remote and local public keys are identical
- Bluetooth: use correct lock to prevent UAF of hdev object
- Bluetooth: fix the erroneous flush_work() order
- iomap: Make sure iomap_end is called after iomap_begin
- x86/kvm: Add "nopvspin" parameter to disable PV spinlocks
- scsi: libsas: add lun number check in .slave_alloc callback
- nfc: fix NULL ptr dereference in llcp_sock_getname() after failed connect
- USB:ehci:fix Kunpeng920 ehci hardware problem
- nvme: don't warn on block content change effects
- block: recalculate segment count for multi-segment discards correctly
- nbd: Fix NULL pointer in flush_workqueue
- Bluetooth: Fix slab-out-of-bounds read in hci_extended_inquiry_result_evt()
- HID: make arrays usage and value to be the same
- ath10k: Validate first subframe of A-MSDU before processing the list
- mac80211: extend protection against mixed key and fragment cache attacks
- mac80211: do not accept/forward invalid EAPOL frames
- mac80211: prevent attacks on TKIP/WEP as well
- mac80211: check defrag PN against current frame
- mac80211: add fragment cache to sta_info
- mac80211: drop A-MSDUs on old ciphers
- cfg80211: mitigate A-MSDU aggregation attacks
- mac80211: properly handle A-MSDUs that start with an RFC 1042 header
- mac80211: prevent mixed key and fragment cache attacks
- mac80211: assure all fragments are encrypted
- mac80211: mark station unauthorized before key removal
- block: avoid creating invalid symlink file for patitions
- block: take bd_mutex around delete_partitions in del_gendisk
- NFSv4: Fix second deadlock in nfs4_evict_inode()
- NFSv4: Fix deadlock between nfs4_evict_inode() and nfs4_opendata_get_inode()
- NFSv4.1: fix handling of backchannel binding in BIND_CONN_TO_SESSION
- NFS: Don't gratuitously clear the inode cache when lookup failed
- NFS: Don't revalidate the directory permissions on a lookup failure
- NFS: nfs_delegation_find_inode_server must first reference the superblock
- nfs4: strengthen error check to avoid unexpected result
- NFS: Fix interrupted slots by sending a solo SEQUENCE operation
- NFS: Ensure we time out if a delegreturn does not complete
- NFSv4.0: nfs4_do_fsinfo() should not do implicit lease renewals
- NFS: Use kmemdup_nul() in nfs_readdir_make_qstr()
- NFSv3: FIx bug when using chacl and chmod to change acl
- NFSv4.x: Handle bad/dead sessions correctly in nfs41_sequence_process()
- NFSv4.1: Only reap expired delegations
- NFSv4.1: Fix open stateid recovery
- NFSv4.1: Don't process the sequence op more than once.
- NFS: Ensure NFS writeback allocations don't recurse back into NFS.
- nfs_remount(): don't leak, don't ignore LSM options quietly
- UACCE backport from mainline
- crypto: hisilicon-Cap block size at 2^31
- crypto: hisilicon-hpre add req check when callback
- crypto: hisilicon- count send_ref when sending bd
- crypto: hisilicon-enhancement of qm DFX
- crypto: hisilicon-memory management optimization
- net: hns3: update hns3 version to 1.9.38.12
- net: hns3: add match_id to check mailbox response from PF to VF
- net: hns3: fix possible mismatches resp of mailbox
- net: hns3: fix the logic for clearing resp_msg
- net: hns3: fix queue id check error when configure flow director rule by ethtool
- net: hns3: add check for HNS3_NIC_STATE_INITED before net open
- net: hns3: add waiting time before cmdq memory is released
- net: hns3: disable firmware compatible features when uninstall PF
- net: hns3: fix change RSS 'hfunc' ineffective issue
- net: hns3: fix inconsistent vf id print
- net: hns3: remove redundant variable initialization
- net: hns3: replace the tab before the left brace with one space
- net: hns3: fix hns3_cae_pfc_storm.h missing header guard problem
- net: hns3: modify an error type configuration
- net: hns3: put off calling register_netdev() until client initialize complete
- net: hns3: replace disable_irq by IRQ_NOAUTOEN flag
- net: hns3: update rss indirection table after setup tc
- net: hns3: don't change tc mqprio configuration when client is unregistered
- net: hns3: remove redundant client_setup_tc handle
- arm64/mpam: Fix use-after-free in mkdir_resctrl_prepare()

* Sat Jun 05 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2105.9.0.0092
- selftests/bpf: add test_xfs_file.c and test_set_xfs_file.c
- bpf: add bpf_probe_read_str into bpf_helpers.h
- xfs: add writable tracepoint for xfs file buffer read
- readahead: introduce FMODE_WILLNEED to read first 2MB of file

* Fri Jun 04 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2105.8.0.0091
- tools: libbpf: fix compiler error
- bpf: fix kabi for struct bpf_prog_aux and struct bpf_raw_event_map
- tools: bpftool: add raw_tracepoint_writable prog type to header
- tools: sync bpf.h
- bpf: add writable context for raw tracepoints
- x86/tsc: Respect tsc command line paraemeter for clocksource_tsc_early

* Tue Jun 01 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2105.6.0.0090
- cpuidle: fix kabi broken in cpuidle_device and cpuidle_driver
- config: set default value of haltpoll
- ARM: cpuidle: Add support for cpuidle-haltpoll driver for ARM
- arm64: Add some definitions of kvm_para*
- cpuidle-haltpoll: Use arch_cpu_idle() to replace default_idle()
- arm64: Optimize ttwu IPI
- config: enable CONFIG_CPU_IDLE_GOV_HALTPOLL and CONFIG_HALTPOLL_CPUIDLE default
- KVM: polling: add architecture backend to disable polling
- cpuidle-haltpoll: Fix small typo
- cpuidle: haltpoll: allow force loading on hosts without the REALTIME hint
- cpuidle-haltpoll: Enable kvm guest polling when dedicated physical CPUs are available
- cpuidle-haltpoll: do not set an owner to allow modunload
- cpuidle-haltpoll: return -ENODEV on modinit failure
- cpuidle-haltpoll: vcpu hotplug support
- cpuidle-haltpoll: set haltpoll as preferred governor
- cpuidle: allow governor switch on cpuidle_register_driver()
- cpuidle: governor: Add new governors to cpuidle_governors again
- cpuidle: Add cpuidle.governor= command line parameter
- cpuidle-haltpoll: disable host side polling when kvm virtualized
- kvm: x86: add host poll control msrs
- cpuidle: add haltpoll governor
- governors: unify last_state_idx
- cpuidle: use first valid target residency as poll time
- cpuidle: header file stubs must be "static inline"
- cpuidle: add poll_limit_ns to cpuidle_device structure
- add cpuidle-haltpoll driver
- cpuidle: poll_state: Fix default time limit
- cpuidle: poll_state: Disregard disable idle states
- cpuidle: poll_state: Revise loop termination condition
- cpuidle: menu: Do not update last_state_idx in menu_select()
- bpf: No need to simulate speculative domain for immediates
- bpf: Fix mask direction swap upon off reg sign change
- bpf: Wrap aux data inside bpf_sanitize_info container

* Tue Jun 01 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2105.5.0.0089
- ata: ahci: Disable SXS for Hisilicon Kunpeng920
- fuse: don't ignore errors from fuse_writepages_fill()
- NFS: finish_automount() requires us to hold 2 refs to the mount record
- NFS: If nfs_mountpoint_expiry_timeout < 0, do not expire submounts
- NFS: remove unused check for negative dentry
- NFSv3: use nfs_add_or_obtain() to create and reference inodes
- NFS: Refactor nfs_instantiate() for dentry referencing callers
- sysfs: Remove address alignment constraint in sysfs_emit{_at}
- Revert "mm, sl[aou]b: guarantee natural alignment for kmalloc(power-of-two)"
- Revert "mm, sl[ou]b: improve memory accounting"
- Revert "mm: memcontrol: fix slub memory accounting"
- io_uring: truncate lengths larger than MAX_RW_COUNT on provide buffers
- arm/ras: Report ARM processor information to userspace
- fuse: update attr_version counter on fuse_notify_inval_inode()
- alinux: random: speed up the initialization of module
- net: mac802154: Fix general protection fault
- cipso,calipso: resolve a number of problems with the DOI refcounts
- Bluetooth: verify AMP hci_chan before amp_destroy
- net/nfc: fix use-after-free llcp_sock_bind/connect
- x86: Select HARDIRQS_SW_RESEND on x86
- x86/apic/vector: Force interupt handler invocation to irq context

* Wed May 26 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2105.4.0.0088
- tools arch x86: Sync asm/cpufeatures.h with the with the kernel
- cpufreq: intel_pstate: Also use CPPC nominal_perf for base_frequency
- ACPI / CPPC: Fix guaranteed performance handling
- perf vendor events: Add JSON metrics for Cascadelake server
- perf vendor events: Add stepping in CPUID string for x86
- cpufreq: intel_pstate: Fix compilation for !CONFIG_ACPI
- cpufreq: intel_pstate: Add base_frequency attribute
- ACPI / CPPC: Add support for guaranteed performance
- EDAC, skx: Fix randconfig builds in a better way
- EDAC, skx: Fix randconfig builds
- EDAC, skx_edac: Add address translation for non-volatile DIMMs
- ACPI/ADXL: Add address translation interface using an ACPI DSM
- x86/mce: Add macros for the corrected error count bit field
- x86/mce: Use BIT_ULL(x) for bit mask definitions
- x86/cpufeatures: Enumerate the new AVX512 BFLOAT16 instructions
- tools/testing/selftests/exec: fix link error
- NFSv4.1: Don't rebind to the same source port when reconnecting to the server
- genirq: Sanitize state handling in check_irq_resend()
- genirq: Add return value to check_irq_resend()
- irqchip/gic-v2, v3: Prevent SW resends entirely
- irqchip/git-v3-its: Implement irq_retrigger callback for device-triggered LPIs
- irqchip/gic-v2, v3: Implement irq_chip->irq_retrigger()
- genirq: Walk the irq_data hierarchy when resending an interrupt
- genirq: Add protection against unsafe usage of generic_handle_irq()

* Mon May 24 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2105.3.0.0087
- jbd2: don't abort the journal when freeing buffers
- jbd2: ensure abort the journal if detect IO error when writing original buffer back
- jbd2: remove the out label in __jbd2_journal_remove_checkpoint()
- x86/unwind/orc: Remove boot-time ORC unwind tables sorting
- scripts/sorttable: Implement build-time ORC unwind table sorting
- scripts/sorttable: Rename 'sortextable' to 'sorttable'
- scripts/sortextable: Refactor the do_func() function
- scripts/sortextable: Remove dead code
- scripts/sortextable: Clean up the code to meet the kernel coding style better
- scripts/sortextable: Rewrite error/success handling
- treewide: Replace GPLv2 boilerplate/reference with SPDX - rule 378
- ext4: Fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed
- Revert "ext4: Fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed"
- nfs4.0: Refetch lease_time after clientid update
- nfs4: Rename nfs41_setup_state_renewal
- nfs4: Make nfs4_proc_get_lease_time available for nfs4.0
- nfs: Fix copy-and-paste error in debug message
- ext4: cleanup in-core orphan list if ext4_truncate() failed to get a transaction handle
- bluetooth: eliminate the potential race condition when removing the HCI controller
- mm: enhance variables check and sync for pin mem
- perf jit: Fix inaccurate DWARF line table
- perf jvmti: Remove redundant jitdump line table entries
- perf jvmti: Fix demangling Java symbols
- perf tests: Add test for the java demangler
- perf jvmti: Do not report error when missing debug information
- perf jvmti: Fix jitdump for methods without debug info
- bpf: Fix leakage of uninitialized bpf stack under speculation
- bpf: Fix masking negation logic upon negative dst register
- bcache: add readahead cache policy options via sysfs interface
- mm/page_alloc: fix managed_pages of zone is incorrect and out of bounds
- freezer: Add unsafe version of freezable_schedule_timeout_interruptible() for NFS
- NFS: Allow signal interruption of NFS4ERR_DELAYed operations
- SUNRPC: Make "no retrans timeout" soft tasks behave like softconn for timeouts
- SUNRPC: Don't let RPC_SOFTCONN tasks time out if the transport is connected
- ext4: fix check to prevent false positive report of incorrect used inodes
- livepatch/x86_64: Fix the deadlock when insmoding livepatch kernel module
- tools/testing/selftests: add self-test for verifying load alignment
- fs/binfmt_elf: use PT_LOAD p_align values for suitable start address
- ext4: introduce ext4_sb_bread_unmovable() to replace sb_bread_unmovable()
- ext4: use ext4_sb_bread() instead of sb_bread()
- ext4: introduce ext4_sb_breadahead_unmovable() to replace sb_breadahead_unmovable()
- ext4: use ext4_buffer_uptodate() in __ext4_get_inode_loc()
- ext4: use common helpers in all places reading metadata buffers
- ext4: introduce new metadata buffer read helpers
- ext4: treat buffers contining write errors as valid in ext4_sb_bread()
- bpf: Fix truncation handling for mod32 dst reg wrt zero
- bpf: Fix 32 bit src register truncation on div/mod
- arm64: bpf: implement jitting of JMP32
- x86_64: bpf: implement jitting of JMP32
- bpf: JIT blinds support JMP32
- bpf: interpreter support for JMP32
- tools: bpftool: teach cfg code about JMP32
- bpf: disassembler support JMP32
- bpf: verifier support JMP32
- bpf: refactor verifier min/max code for condition jump
- bpf: allocate 0x06 to new eBPF instruction class JMP32

* Wed May 12 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2105.2.0.0086
- ovl: allow upperdir inside lowerdir
- ACPI: x86: Call acpi_boot_table_init() after acpi_table_upgrade()
- ACPI: tables: x86: Reserve memory occupied by ACPI tables
- x86/crash: Fix crash_setup_memmap_entries() out-of-bounds access
- locking/qrwlock: Fix ordering in queued_write_lock_slowpath()
- net: ip6_tunnel: Unregister catch-all devices
- netfilter: nft_limit: avoid possible divide error in nft_limit_init
- netfilter: conntrack: do not print icmpv6 as unknown via /proc
- scsi: libsas: Reset num_scatter if libata marks qc as NODATA
- arm64: alternatives: Move length validation in alternative_{insn, endif}
- arm64: fix inline asm in load_unaligned_zeropad()
- readdir: make sure to verify directory entry for legacy interfaces too
- neighbour: Disregard DEAD dst in neigh_update
- driver core: Fix locking bug in deferred_probe_timeout_work_func()
- netfilter: x_tables: fix compat match/target pad out-of-bound write
- workqueue: Move the position of debug_work_activate() in __queue_work()
- xfrm: interface: fix ipv4 pmtu check to honor ip header df
- net-ipv6: bugfix - raw & sctp - switch to ipv6_can_nonlocal_bind()
- net: ensure mac header is set in virtio_net_hdr_to_skb()
- fs: direct-io: fix missing sdio->boundary
- net: ipv6: check for validity before dereferencing cfg->fc_nlinfo.nlh
- cifs: Silently ignore unknown oplock break handle
- cifs: revalidate mapping when we open files for SMB1 POSIX
- scsi: target: pscsi: Clean up after failure in pscsi_map_sg()
- mm: fix race by making init_zero_pfn() early_initcall
- tracing: Fix stack trace event size
- PM: runtime: Fix ordering in pm_runtime_get_suppliers()
- PM: runtime: Fix race getting/putting suppliers at probe
- ext4: do not iput inode under running transaction in ext4_rename()
- locking/ww_mutex: Simplify use_ww_ctx & ww_ctx handling
- thermal/core: Add NULL pointer check before using cooling device stats
- scsi: st: Fix a use after free in st_open()
- vhost: Fix vhost_vq_reset()
- rpc: fix NULL dereference on kmalloc failure
- ext4: fix bh ref count on error paths
- ipv6: weaken the v4mapped source check
- tcp: relookup sock for RST+ACK packets handled by obsolete req sock
- nfs: we don't support removing system.nfs4_acl
- NFSv4.2: fix return value of _nfs4_get_security_label()
- nfs: fix PNFS_FLEXFILE_LAYOUT Kconfig default
- pNFS/NFSv4: Try to return invalid layout in pnfs_layout_process()
- pNFS/NFSv4: Fix a layout segment leak in pnfs_layout_process()
- NFSv4.2: condition READDIR's mask for security label based on LSM state
- NFSv4.2: support EXCHGID4_FLAG_SUPP_FENCE_OPS 4.2 EXCHANGE_ID flag
- NFS: fix nfs_path in case of a rename retry
- NFSv4.1 handle ERR_DELAY error reclaiming locking state on delegation recall
- NFS: Don't return layout segments that are in use
- NFS: Don't move layouts to plh_return_segs list while in use
- SUNRPC reverting d03727b248d0 ("NFSv4 fix CLOSE not waiting for direct IO compeletion")
- NFSv4 fix CLOSE not waiting for direct IO compeletion
- NFSv4.1 fix rpc_call_done assignment for BIND_CONN_TO_SESSION
- nfs: Fix potential posix_acl refcnt leak in nfs3_set_acl
- NFSv4/pnfs: Return valid stateids in nfs_layout_find_inode_by_stateid()
- NFSv4.1 make cachethis=no for writes
- NFS/pnfs: Fix pnfs_generic_prepare_to_resend_writes()
- NFS/pnfs: Bulk destroy of layouts needs to be safe w.r.t. umount
- cgroup/files: support boot parameter to control if disable files cgroup
- efi: Fix a race and a buffer overflow while reading efivars via sysfs
- RDMA/hns: Allocate one more recv SGE for HIP08
- mm: memcontrol: fix slub memory accounting
- mm, sl[ou]b: improve memory accounting
- mm: fix numa stats for thp migration
- mm/vmscan: count layzfree pages and fix nr_isolated_* mismatch
- SUNRPC: Close a race with transport setup and module put
- sunrpc: Change the place of endtime in struct krb5_ctx
- bpf: Tighten speculative pointer arithmetic mask
- bpf: Move sanitize_val_alu out of op switch
- bpf: Refactor and streamline bounds check into helper
- bpf: Improve verifier error messages for users
- bpf: Rework ptr_limit into alu_limit and add common error path
- bpf: Ensure off_reg has no mixed signed bounds for all types
- bpf: Move off_reg into sanitize_ptr_alu
- bpf: Add sanity check for upper ptr_limit
- bpf: Simplify alu_limit masking for pointer arithmetic

* Tue May 11 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.26.0.0085
- add kabi list for aarch64 and x86_64

* Sat May 08 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.26.0.0084
- pid: fix pid recover method kabi change
- config: enable kernel hotupgrade features by default
- kexec: Add quick kexec support for kernel
- arm64: smp: Add support for cpu park
- pid: add pid reserve method for checkpoint and restore
- mm: add pin memory method for checkpoint add restore
- Revert "sched: Introduce qos scheduler for co-location"
- Revert "sched: Throttle qos cfs_rq when current cpu is running online task"
- Revert "sched: Enable qos scheduler config"
- Revert "memcg: support priority for oom"
- Revert "memcg: enable CONFIG_MEMCG_QOS by default"
- Revert "memcg: fix kabi broken when enable CONFIG_MEMCG_QOS"
- f2fs: fix to avoid out-of-bounds memory access
- ext4: Reduce ext4 timestamp warnings
- livepatch: Restoring code segment permissions after stop_machine completed
- livepatch: Delete redundant variable 'flag'
- memcg: fix kabi broken when enable CONFIG_MEMCG_QOS
- memcg: enable CONFIG_MEMCG_QOS by default
- memcg: support priority for oom
- sched: Enable qos scheduler config
- sched: Throttle qos cfs_rq when current cpu is running online task
- sched: Introduce qos scheduler for co-location
- ipv6: route: convert comma to semicolon
- ipv6/route: Add a missing check on proc_dointvec
- netfilter: xtables: avoid BUG_ON
- SUNRPC: Test whether the task is queued before grabbing the queue spinlocks
- SUNRPC: If there is no reply expected, bail early from call_decode
- SUNRPC: Fix backchannel latency metrics
- sunrpc: convert to time64_t for expiry
- sunrpc: Fix potential leaks in sunrpc_cache_unhash()
- SUNRPC: Skip zero-refcount transports
- SUNRPC: Fix buffer handling of GSS MIC without slack
- SUNRPC: Don't allow compiler optimisation of svc_xprt_release_slot()
- SUNRPC/nfs: Fix return value for nfs4_callback_compound()
- net/sunrpc: return 0 on attempt to write to "transports"
- net/sunrpc: Fix return value for sysctl sunrpc.transports
- sunrpc: raise kernel RPC channel buffer size
- sunrpc: add missing newline when printing parameter 'pool_mode' by sysfs
- xprtrdma: Fix trace point use-after-free race
- SUNRPC: Fix backchannel RPC soft lockups
- SUNRPC/cache: Fix unsafe traverse caused double-free in cache_purge
- nfsd: export upcalls must not return ESTALE when mountd is down
- sunrpc/cache: handle missing listeners better.
- xprtrdma: Fix handling of RDMA_ERROR replies
- xprtrdma: Expose transport header errors
- sunrpc: destroy rpc_inode_cachep after unregister_filesystem
- xprtrdma: fix incorrect header size calculations
- nvme: fix ns removal hang when failing to revalidate due to a transient error
- kernel/cputime: do not update cputime when cpu offline
- perf/x86: Always store regs->ip in perf_callchain_kernel()
- perf/x86: Make perf callchains work without CONFIG_FRAME_POINTER
- irqchip/gic-v3: Do not enable irqs when handling spurious interrups
- config: enable CONFIG_HW_RANDOM_HISI_V2 by default
- hwrng: add data_mode to support rand data with post process
- hwrng: add HiSilicon TRNG driver

* Sun Apr 25 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.21.0.0083
- bcache: Rewrite patch to delay to invalidate cache data
- nfc: Avoid endless loops caused by repeated llcp_sock_connect()
- nfc: fix memory leak in llcp_sock_connect()
- nfc: fix refcount leak in llcp_sock_connect()
- nfc: fix refcount leak in llcp_sock_bind()

* Thu Apr 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.19.0.0082
- KVM: arm64: Support the vCPU preemption check
- KVM: arm64: Add interface to support vCPU preempted check
- KVM: arm64: Support pvsched preempted via shared structure
- KVM: arm64: Implement PV_SCHED_FEATURES call
- KVM: arm64: Document PV-sched interface
- KVM: Check preempted_in_kernel for involuntary preemption
- KVM: Boost vCPUs that are delivering interrupts
- arm64/spinlock: fix a -Wunused-function warning
- locking/osq: Use optimized spinning loop for arm64
- arm/arm64: Make use of the SMCCC 1.1 wrapper
- arm/arm64: Provide a wrapper for SMCCC 1.1 calls
- KVM: Implement kvm_put_guest()
- KVM: arm/arm64: Factor out hypercall handling from PSCI code

* Thu Apr 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.18.0.0081
- bcache: Add a sample of userspace prefetch client
- bcache: Delay to invalidate cache data in writearound write
- bcache: inflight prefetch requests block overlapped normal requests
- bcache: provide a switch to bypass all IO requests
- bcache: add a framework to perform prefetch

* Thu Apr 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.17.0.0080
- net/hinic: Fix null pointer dereference in hinic_physical_port_id
- kvm: debugfs: Export x86 kvm exits to vcpu_stat
- ext4: fix time overflow
- ext4: drop legacy pre-1970 encoding workaround
- fuse: fix live lock in fuse_iget()
- fuse: fix bad inode
- net/sctp: fix race condition in sctp_destroy_sock
- config: set config hip08 prefetch default value
- ext4: do not set SB_ACTIVE in ext4_orphan_cleanup()
- RDMA/hns: add eq and cq time cfg compatibility support.
- nvme: fix incorrect behavior when BLKROSET is called by the user
- nvme-fc: fix error loop in create_hw_io_queues
- nvme-fc: Fix wrong return value in __nvme_fc_init_request()
- nvme-multipath: fix deadlock between ana_work and scan_work
- nvme: fix deadlock caused by ANA update wrong locking
- nvme-multipath: Fix memory leak with ana_log_buf
- nvme-fc: fix module unloads while lports still pending
- ipmi: remve duplicate code in __ipmi_bmc_register()
- ipmi_si_intf: Fix race in timer shutdown handling
- ipmi_ssif: fix unexpected driver unregister warning
- ipmi_si: fix unexpected driver unregister warning
- ipmi:ssif: Only unregister the platform driver if it was registered
- ipmi: Make ipmi_interfaces_srcu variable static
- ipmi: Fix return value when a message is truncated
- ipmi: Free the address list on module cleanup
- net: hns3: clear VF down state bit before request link status
- config: disable config ARM64_BOOTPARAM_HOTPLUG_CPU0 by default
- config: disable CONFIG_SATA_ZHAOXIN by default

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.16.0.0079
- config/arm64: fix kabi by disable CONFIG_NVME_MULTIPATH

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.15.0.0078
- config/x86: enable SHRINK_PAGECACHE
- arm64: Add config switch and kernel parameter for CPU0 hotplug

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.14.0.0077
- arm64: errata: enable HISILICON_ERRATUM_HIP08_RU_PREFETCH
- arm64: errata: fix kabi changed for cpu_errata
- arm64: errata: add option to disable cache readunique prefetch on 1620

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.13.0.0076
- firewire: nosy: Fix a use-after-free bug in nosy_ioctl()

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.12.0.0075
- iommu/arm-smmu-v3: Reduce contention during command-queue insertion
- iommu/arm-smmu-v3: Operate directly on low-level queue where possible
- iommu/arm-smmu-v3: Move low-level queue fields out of arm_smmu_queue
- iommu/arm-smmu-v3: Drop unused 'q' argument from Q_OVF macro
- iommu/arm-smmu-v3: Separate s/w and h/w views of prod and cons indexes
- iommu/io-pgtable: Rename iommu_gather_ops to iommu_flush_ops
- iommu/io-pgtable-arm: Remove redundant call to io_pgtable_tlb_sync()
- iommu/arm-smmu-v3: Increase maximum size of queues
- iommu/io-pgtable: Replace IO_PGTABLE_QUIRK_NO_DMA with specific flag
- iommu: Allow io-pgtable to be used outside of drivers/iommu/
- iommu: Fix flush_tlb_all typo
- iommu: Change tlb_range_add to iotlb_range_add and tlb_sync to iotlb_sync

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.11.0.0074
- io_uring: order refnode recycling
- io_uring: get an active ref_node from files_data
- io_uring: fix racy req->flags modification
- io_uring: defer file table grabbing request cleanup for locked requests
- io_uring: batch put_task_struct()
- tasks: add put_task_struct_many()
- io_uring: fix missing io_queue_linked_timeout()
- io_uring: deduplicate io_grab_files() calls
- io_uring: don't do opcode prep twice
- io_uring: don't open-code recv kbuf managment
- io_uring: extract io_put_kbuf() helper
- io_uring: simplify file ref tracking in submission state
- io_uring: move BUFFER_SELECT check into *recv[msg]
- io_uring: free selected-bufs if error'ed
- io_uring: don't forget cflags in io_recv()
- io_uring: remove extra checks in send/recv
- io_uring: indent left {send,recv}[msg]()
- io-wq: update hash bits
- io_uring: get rid of atomic FAA for cq_timeouts
- io_uring: consolidate *_check_overflow accounting
- io_uring: de-unionise io_kiocb
- io_uring: follow **iovec idiom in io_import_iovec
- io_uring: mark ->work uninitialised after cleanup
- io_uring/io-wq: move RLIMIT_FSIZE to io-wq
- io_uring: alloc ->io in io_req_defer_prep()
- io_uring: inline io_req_work_grab_env()
- io_uring: fix racy IOPOLL completions
- io_uring: always let io_iopoll_complete() complete polled io
- io_uring: don't recurse on tsk->sighand->siglock with signalfd
- io_uring: don't use poll handler if file can't be nonblocking read/written
- io_uring: fix linked deferred ->files cancellation
- io_uring: fix cancel of deferred reqs with ->files
- io_uring: flush timeouts that should already have expired
- io_uring: find and cancel head link async work on files exit
- io_uring: always plug for any number of IOs
- io_uring: fix recursive completion locking on oveflow flush
- io_uring: enable lookup of links holding inflight files
- io_uring: place cflags into completion data
- io_uring: remove sequence from io_kiocb
- io_uring: use non-intrusive list for defer
- io_uring: remove init for unused list
- io_uring: add req->timeout.list
- io_uring: use completion list for CQ overflow
- io_uring: use inflight_entry list for iopoll'ing
- io_uring: rename ctx->poll into ctx->iopoll
- io_uring: share completion list w/ per-op space
- io_uring: get rid of __req_need_defer()
- io_uring: only call kfree() for a non-zero pointer
- io_uring: fix a use after free in io_async_task_func()
- io_uring: remove nr_events arg from iopoll_check()
- io_uring: don't delay iopoll'ed req completion
- io_uring: fix lost cqe->flags
- io_uring: keep queue_sqe()'s fail path separately
- io_uring: fix mis-refcounting linked timeouts
- io_uring: use new io_req_task_work_add() helper throughout
- io_uring: abstract out task work running
- io_uring: do grab_env() just before punting
- io_uring: factor out grab_env() from defer_prep()
- io_uring: do init work in grab_env()
- io_uring: don't pass def into io_req_work_grab_env
- io_uring: fix function args for !CONFIG_NET
- io_uring: set @poll->file after @poll init
- io_uring: remove REQ_F_MUST_PUNT
- io_uring: remove setting REQ_F_MUST_PUNT in rw
- io_uring: optimise io_req_find_next() fast check
- io_uring: kill REQ_F_TIMEOUT_NOSEQ
- io_uring: kill REQ_F_TIMEOUT
- io_uring: replace find_next() out param with ret
- io_uring: fix missing io_grab_files()
- io_uring: don't mark link's head for_async
- io_uring: fix feeding io-wq with uninit reqs
- io_uring: fix punting req w/o grabbed env
- io_uring: fix req->work corruption
- io_uring: simplify io_async_task_func()
- io_uring: fix NULL mm in io_poll_task_func()
- io_uring: use task_work for links if possible
- io_uring: do task_work_run() during iopoll
- io_uring: clean up req->result setting by rw
- io_uring: cosmetic changes for batch free
- io_uring: batch-free linked requests as well
- io_uring: dismantle req early and remove need_iter
- io_uring: remove inflight batching in free_many()
- io_uring: fix refs underflow in io_iopoll_queue()
- io_uring: enable READ/WRITE to use deferred completions
- io_uring: pass in completion state to appropriate issue side handlers
- io_uring: pass down completion state on the issue side
- io_uring: add 'io_comp_state' to struct io_submit_state
- io_uring: provide generic io_req_complete() helper
- io_uring: add missing REQ_F_COMP_LOCKED for nested requests
- io_uring: clean up io_kill_linked_timeout() locking
- io_uring: deduplicate freeing linked timeouts
- io_uring: kill REQ_F_LINK_NEXT
- io_uring: fix stalled deferred requests
- io_uring: add IORING_OP_OPENAT2 for compatablity
- arm64: fix kabi with io_uring interface
- x86: fix kabi with io_uring interface
- io_uring: fix provide_buffers sign extension
- io_uring: ignore double poll add on the same waitqueue head
- io_uring: fix SQPOLL IORING_OP_CLOSE cancelation state
- io_uring: make ctx cancel on exit targeted to actual ctx
- io_uring: fix error path cleanup in io_sqe_files_register()
- io_uring: ensure open/openat2 name is cleaned on cancelation
- io_uring: sanitize double poll handling
- io_uring: fail poll arm on queue proc failure
- io_uring: allow non-fixed files with SQPOLL
- io_uring: ensure consistent view of original task ->mm from SQPOLL
- io_uring: stash ctx task reference for SQPOLL
- io_uring: don't miscount pinned memory
- io_uring: don't burn CPU for iopoll on exit
- io_uring: fix imbalanced sqo_mm accounting
- io_uring: return locked and pinned page accounting
- io_uring: fix missing ->mm on exit
- io_uring: fix NULL-mm for linked reqs
- io_uring: account locked memory before potential error case
- io_uring: don't touch 'ctx' after installing file descriptor
- io_uring: remove dead 'ctx' argument and move forward declaration
- io_uring: fix recvmsg setup with compat buf-select
- io_uring: fix shift-out-of-bounds when round up cq size
- io_uring: round-up cq size before comparing with rounded sq size
- io_uring: use type appropriate io_kiocb handler for double poll
- io_uring: fix double poll mask init
- io_uring: Fix sizeof() mismatch
- io_uring: keep a pointer ref_node in file_data
- io_uring: refactor *files_register()'s error paths
- io_uring: clean file_data access in files_register
- io-wq: fix use-after-free in io_wq_worker_running
- io_uring: fix potential ABBA deadlock in ->show_fdinfo()
- io_uring: always delete double poll wait entry on match
- io-wq: fix hang after cancelling pending hashed work
- io_uring: fix racy overflow count reporting
- io_uring: partially inline io_iopoll_getevents()
- io_uring: briefly loose locks while reaping events
- io_uring: fix stopping iopoll'ing too early
- io_uring: fix potential use after free on fallback request free
- io_uring: set table->files[i] to NULL when io_sqe_file_register failed
- io_uring: fix removing the wrong file in __io_sqe_files_update()
- io_uring: fix IOPOLL -EAGAIN retries
- io_uring: clear req->result on IOPOLL re-issue
- io_uring: hold 'ctx' reference around task_work queue + execute
- io_uring: use TWA_SIGNAL for task_work uncondtionally
- io_uring: Fix NULL pointer dereference in loop_rw_iter()
- io_uring: clear IORING_SQ_NEED_WAKEUP after executing task works
- io_uring: add a helper for async rw iovec prep
- io_uring: simplify io_req_map_rw()
- io_uring: extract io_sendmsg_copy_hdr()
- io_uring: use more specific type in rcv/snd msg cp
- io_uring: rename sr->msg into umsg
- io_uring: fix sq array offset calculation
- io_uring: fix lockup in io_fail_links()
- io_uring: fix ->work corruption with poll_add
- io_uring: missed req_init_async() for IOSQE_ASYNC
- io_uring: always allow drain/link/hardlink/async sqe flags
- io_uring: ensure double poll additions work with both request types
- io_uring: fix recvmsg memory leak with buffer selection
- io_uring: fix not initialised work->flags
- io_uring: fix missing msg_name assignment
- io_uring: account user memory freed when exit has been queued
- io_uring: fix memleak in io_sqe_files_register()
- io_uring: fix memleak in __io_sqe_files_update()
- io_uring: export cq overflow status to userspace
- io_uring: fix regression with always ignoring signals in io_cqring_wait()
- io_uring: use signal based task_work running
- task_work: teach task_work_add() to do signal_wake_up()
- io_uring: fix current->mm NULL dereference on exit
- io_uring: fix hanging iopoll in case of -EAGAIN
- io_uring: fix io_sq_thread no schedule when busy
- io-wq: return next work from ->do_work() directly
- io-wq: compact io-wq flags numbers
- io_uring: separate reporting of ring pages from registered pages
- io_uring: report pinned memory usage
- io_uring: rename ctx->account_mem field
- io_uring: add wrappers for memory accounting
- io_uring: use EPOLLEXCLUSIVE flag to aoid thundering herd type behavior
- io_uring: change the poll type to be 32-bits
- io_uring: fix possible race condition against REQ_F_NEED_CLEANUP
- io_uring: reap poll completions while waiting for refs to drop on exit
- io_uring: acquire 'mm' for task_work for SQPOLL
- io_uring: add memory barrier to synchronize io_kiocb's result and iopoll_completed
- io_uring: don't fail links for EAGAIN error in IOPOLL mode
- io_uring: cancel by ->task not pid
- io_uring: lazy get task
- io_uring: batch cancel in io_uring_cancel_files()
- io_uring: cancel all task's requests on exit
- io-wq: add an option to cancel all matched reqs
- io-wq: reorder cancellation pending -> running
- io_uring: fix lazy work init
- io_uring: fix io_kiocb.flags modification race in IOPOLL mode
- io_uring: check file O_NONBLOCK state for accept
- io_uring: avoid unnecessary io_wq_work copy for fast poll feature
- io_uring: avoid whole io_wq_work copy for requests completed inline
- io_uring: allow O_NONBLOCK async retry
- io_wq: add per-wq work handler instead of per work
- io_uring: don't arm a timeout through work.func
- io_uring: remove custom ->func handlers
- io_uring: don't derive close state from ->func
- io_uring: use kvfree() in io_sqe_buffer_register()
- io_uring: validate the full range of provided buffers for access
- io_uring: re-set iov base/len for buffer select retry
- io_uring: move send/recv IOPOLL check into prep
- io_uring: fix {SQ,IO}POLL with unsupported opcodes
- io_uring: disallow close of ring itself
- io_uring: fix overflowed reqs cancellation
- io_uring: off timeouts based only on completions
- io_uring: move timeouts flushing to a helper
- statx: hide interfaces no longer used by io_uring
- io_uring: call statx directly
- statx: allow system call to be invoked from io_uring
- io_uring: add io_statx structure
- io_uring: get rid of manual punting in io_close
- io_uring: separate DRAIN flushing into a cold path
- io_uring: don't re-read sqe->off in timeout_prep()
- io_uring: simplify io_timeout locking
- io_uring: fix flush req->refs underflow
- io_uring: don't submit sqes when ctx->refs is dying
- io_uring: async task poll trigger cleanup
- io_uring: add tee(2) support
- splice: export do_tee()
- io_uring: don't repeat valid flag list
- io_uring: rename io_file_put()
- io_uring: remove req->needs_fixed_files
- io_uring: cleanup io_poll_remove_one() logic
- io_uring: file registration list and lock optimization
- io_uring: add IORING_CQ_EVENTFD_DISABLED to the CQ ring flags
- io_uring: add 'cq_flags' field for the CQ ring
- io_uring: allow POLL_ADD with double poll_wait() users
- io_uring: batch reap of dead file registrations
- io_uring: name sq thread and ref completions
- io_uring: remove duplicate semicolon at the end of line
- io_uring: remove obsolete 'state' parameter
- io_uring: remove 'fd is io_uring' from close path
- io_uring: reset -EBUSY error when io sq thread is waken up
- io_uring: don't add non-IO requests to iopoll pending list
- io_uring: don't use kiocb.private to store buf_index
- io_uring: cancel work if task_work_add() fails
- io_uring: remove dead check in io_splice()
- io_uring: fix FORCE_ASYNC req preparation
- io_uring: don't prepare DRAIN reqs twice
- io_uring: initialize ctx->sqo_wait earlier
- io_uring: polled fixed file must go through free iteration
- io_uring: fix zero len do_splice()
- io_uring: don't use 'fd' for openat/openat2/statx
- splice: move f_mode checks to do_{splice,tee}()
- io_uring: handle -EFAULT properly in io_uring_setup()
- io_uring: fix mismatched finish_wait() calls in io_uring_cancel_files()
- io_uring: punt splice async because of inode mutex
- io_uring: check non-sync defer_list carefully
- io_uring: fix extra put in sync_file_range()
- io_uring: use cond_resched() in io_ring_ctx_wait_and_kill()
- io_uring: use proper references for fallback_req locking
- io_uring: only force async punt if poll based retry can't handle it
- io_uring: enable poll retry for any file with ->read_iter / ->write_iter
- io_uring: statx must grab the file table for valid fd
- io_uring: only restore req->work for req that needs do completion
- io_uring: don't count rqs failed after current one
- io_uring: kill already cached timeout.seq_offset
- io_uring: fix cached_sq_head in io_timeout()
- io_uring: only post events in io_poll_remove_all() if we completed some
- io_uring: io_async_task_func() should check and honor cancelation
- io_uring: check for need to re-wait in polled async handling
- io_uring: correct O_NONBLOCK check for splice punt
- io_uring: restore req->work when canceling poll request
- io_uring: move all request init code in one place
- io_uring: keep all sqe->flags in req->flags
- io_uring: early submission req fail code
- io_uring: track mm through current->mm
- io_uring: remove obsolete @mm_fault
- io_uring: punt final io_ring_ctx wait-and-free to workqueue
- io_uring: fix fs cleanup on cqe overflow
- io_uring: don't read user-shared sqe flags twice
- io_uring: remove req init from io_get_req()
- io_uring: alloc req only after getting sqe
- io_uring: simplify io_get_sqring
- io_uring: do not always copy iovec in io_req_map_rw()
- io_uring: ensure openat sets O_LARGEFILE if needed
- io_uring: initialize fixed_file_data lock
- io_uring: remove redundant variable pointer nxt and io_wq_assign_next call
- io_uring: fix ctx refcounting in io_submit_sqes()
- io_uring: process requests completed with -EAGAIN on poll list
- io_uring: remove bogus RLIMIT_NOFILE check in file registration
- io_uring: use io-wq manager as backup task if task is exiting
- io_uring: grab task reference for poll requests
- io_uring: retry poll if we got woken with non-matching mask
- io_uring: add missing finish_wait() in io_sq_thread()
- io_uring: refactor file register/unregister/update handling
- io_uring: cleanup io_alloc_async_ctx()
- io_uring: fix missing 'return' in comment
- io-wq: handle hashed writes in chains
- io-uring: drop 'free_pfile' in struct io_file_put
- io-uring: drop completion when removing file
- io_uring: Fix ->data corruption on re-enqueue
- io-wq: close cancel gap for hashed linked work
- io_uring: make spdxcheck.py happy
- io_uring: honor original task RLIMIT_FSIZE
- io-wq: hash dependent work
- io-wq: split hashing and enqueueing
- io-wq: don't resched if there is no work
- io-wq: remove duplicated cancel code
- io_uring: fix truncated async read/readv and write/writev retry
- io_uring: dual license io_uring.h uapi header
- io_uring: io_uring_enter(2) don't poll while SETUP_IOPOLL|SETUP_SQPOLL enabled
- io_uring: Fix unused function warnings
- io_uring: add end-of-bits marker and build time verify it
- io_uring: provide means of removing buffers
- io_uring: add IOSQE_BUFFER_SELECT support for IORING_OP_RECVMSG
- net: abstract out normal and compat msghdr import
- io_uring: add IOSQE_BUFFER_SELECT support for IORING_OP_READV
- io_uring: support buffer selection for OP_READ and OP_RECV
- io_uring: add IORING_OP_PROVIDE_BUFFERS
- io_uring: buffer registration infrastructure
- io_uring/io-wq: forward submission ref to async
- io-wq: optimise out *next_work() double lock
- io-wq: optimise locking in io_worker_handle_work()
- io-wq: shuffle io_worker_handle_work() code
- io_uring: get next work with submission ref drop
- io_uring: remove @nxt from handlers
- io_uring: make submission ref putting consistent
- io_uring: clean up io_close
- io_uring: Ensure mask is initialized in io_arm_poll_handler
- io_uring: remove io_prep_next_work()
- io_uring: remove extra nxt check after punt
- io_uring: use poll driven retry for files that support it
- io_uring: mark requests that we can do poll async in io_op_defs
- io_uring: add per-task callback handler
- io_uring: store io_kiocb in wait->private
- task_work_run: don't take ->pi_lock unconditionally
- io-wq: use BIT for ulong hash
- io_uring: remove IO_WQ_WORK_CB
- io-wq: remove unused IO_WQ_WORK_HAS_MM
- io_uring: extract kmsg copy helper
- io_uring: clean io_poll_complete
- io_uring: add splice(2) support
- io_uring: add interface for getting files
- splice: make do_splice public
- io_uring: remove req->in_async
- io_uring: don't do full *prep_worker() from io-wq
- io_uring: don't call work.func from sync ctx
- io_uring: io_accept() should hold on to submit reference on retry
- io_uring: consider any io_read/write -EAGAIN as final
- io_uring: make sure accept honor rlimit nofile
- io_uring: make sure openat/openat2 honor rlimit nofile
- io_uring: NULL-deref for IOSQE_{ASYNC,DRAIN}
- io_uring: ensure RCU callback ordering with rcu_barrier()
- io_uring: fix lockup with timeouts
- io_uring: free fixed_file_data after RCU grace period
- io-wq: remove io_wq_flush and IO_WQ_WORK_INTERNAL
- io-wq: fix IO_WQ_WORK_NO_CANCEL cancellation
- io_uring: fix 32-bit compatability with sendmsg/recvmsg
- io_uring: define and set show_fdinfo only if procfs is enabled
- io_uring: drop file set ref put/get on switch
- io_uring: import_single_range() returns 0/-ERROR
- io_uring: pick up link work on submit reference drop
- io-wq: ensure work->task_pid is cleared on init
- io-wq: remove spin-for-work optimization
- io_uring: fix poll_list race for SETUP_IOPOLL|SETUP_SQPOLL
- io_uring: fix personality idr leak
- io_uring: handle multiple personalities in link chains
- io_uring: fix __io_iopoll_check deadlock in io_sq_thread
- io_uring: prevent sq_thread from spinning when it should stop
- io_uring: fix use-after-free by io_cleanup_req()
- io_uring: remove unnecessary NULL checks
- io_uring: add missing io_req_cancelled()
- io_uring: prune request from overflow list on flush
- io-wq: don't call kXalloc_node() with non-online node
- io_uring: retain sockaddr_storage across send/recvmsg async punt
- io_uring: cancel pending async work if task exits
- io-wq: add io_wq_cancel_pid() to cancel based on a specific pid
- io-wq: make io_wqe_cancel_work() take a match handler
- io_uring: fix openat/statx's filename leak
- io_uring: fix double prep iovec leak
- io_uring: fix async close() with f_op->flush()
- io_uring: allow AT_FDCWD for non-file openat/openat2/statx
- io_uring: grab ->fs as part of async preparation
- io-wq: add support for inheriting ->fs
- io_uring: retry raw bdev writes if we hit -EOPNOTSUPP
- io_uring: add cleanup for openat()/statx()
- io_uring: fix iovec leaks
- io_uring: remove unused struct io_async_open
- io_uring: flush overflowed CQ events in the io_uring_poll()
- io_uring: statx/openat/openat2 don't support fixed files
- io_uring: fix deferred req iovec leak
- io_uring: fix 1-bit bitfields to be unsigned
- io_uring: get rid of delayed mm check
- io_uring: cleanup fixed file data table references
- io_uring: spin for sq thread to idle on shutdown
- io_uring: put the flag changing code in the same spot
- io_uring: iterate req cache backwards
- io_uring: punt even fadvise() WILLNEED to async context
- io_uring: fix sporadic double CQE entry for close
- io_uring: remove extra ->file check
- io_uring: don't map read/write iovec potentially twice
- io_uring: use the proper helpers for io_send/recv
- io_uring: prevent potential eventfd recursion on poll
- io_uring: add BUILD_BUG_ON() to assert the layout of struct io_uring_sqe
- io_uring: add ->show_fdinfo() for the io_uring file descriptor
- io_uring: add support for epoll_ctl(2)
- eventpoll: support non-blocking do_epoll_ctl() calls
- eventpoll: abstract out epoll_ctl() handler
- io_uring: fix linked command file table usage
- io_uring: support using a registered personality for commands
- io_uring: allow registering credentials
- io_uring: add io-wq workqueue sharing
- io-wq: allow grabbing existing io-wq
- io_uring/io-wq: don't use static creds/mm assignments
- io-wq: make the io_wq ref counted
- io_uring: fix refcounting with batched allocations at OOM
- io_uring: add comment for drain_next
- io_uring: don't attempt to copy iovec for READ/WRITE
- io_uring: honor IOSQE_ASYNC for linked reqs
- io_uring: prep req when do IOSQE_ASYNC
- io_uring: use labeled array init in io_op_defs
- io_uring: optimise sqe-to-req flags translation
- io_uring: remove REQ_F_IO_DRAINED
- io_uring: file switch work needs to get flushed on exit
- io_uring: hide uring_fd in ctx
- io_uring: remove extra check in __io_commit_cqring
- io_uring: optimise use of ctx->drain_next
- io_uring: add support for probing opcodes
- io_uring: account fixed file references correctly in batch
- io_uring: add opcode to issue trace event
- io_uring: remove 'fname' from io_open structure
- io_uring: enable option to only trigger eventfd for async completions
- io_uring: change io_ring_ctx bool fields into bit fields
- io_uring: file set registration should use interruptible waits
- io_uring: Remove unnecessary null check
- io_uring: add support for send(2) and recv(2)
- io_uring: remove extra io_wq_current_is_worker()
- io_uring: optimise commit_sqring() for common case
- io_uring: optimise head checks in io_get_sqring()
- io_uring: clamp to_submit in io_submit_sqes()
- io_uring: add support for IORING_SETUP_CLAMP
- io_uring: extend batch freeing to cover more cases
- io_uring: wrap multi-req freeing in struct req_batch
- io_uring: batch getting pcpu references
- pcpu_ref: add percpu_ref_tryget_many()
- io_uring: add IORING_OP_MADVISE
- mm: make do_madvise() available internally
- io_uring: add IORING_OP_FADVISE
- io_uring: allow use of offset == -1 to mean file position
- io_uring: add non-vectored read/write commands
- io_uring: improve poll completion performance
- io_uring: split overflow state into SQ and CQ side
- io_uring: add lookup table for various opcode needs
- io_uring: remove two unnecessary function declarations
- io_uring: move *queue_link_head() from common path
- io_uring: rename prev to head
- io_uring: add IOSQE_ASYNC
- io-wq: support concurrent non-blocking work
- io_uring: add support for IORING_OP_STATX
- fs: make two stat prep helpers available
- io_uring: avoid ring quiesce for fixed file set unregister and update
- io_uring: add support for IORING_OP_CLOSE
- io-wq: add support for uncancellable work
- percpu-refcount: Introduce percpu_ref_resurrect()
- percpu_ref: introduce PERCPU_REF_ALLOW_REINIT flag
- fs: make filename_lookup available externally
- fs: introduce __close_fd_get_file to support IORING_OP_CLOSE for io_uring
- io_uring: add support for IORING_OP_OPENAT
- fs: make build_open_flags() available internally
- io_uring: add support for fallocate()
- io_uring: don't cancel all work on process exit
- Revert "io_uring: only allow submit from owning task"
- io_uring: fix compat for IORING_REGISTER_FILES_UPDATE
- io_uring: only allow submit from owning task
- io_uring: ensure workqueue offload grabs ring mutex for poll list
- io_uring: clear req->result always before issuing a read/write request
- io_uring: be consistent in assigning next work from handler
- io-wq: cancel work if we fail getting a mm reference
- io_uring: don't setup async context for read/write fixed
- io_uring: remove punt of short reads to async context
- io-wq: add cond_resched() to worker thread
- io-wq: remove unused busy list from io_sqe
- io_uring: pass in 'sqe' to the prep handlers
- io_uring: standardize the prep methods
- io_uring: read 'count' for IORING_OP_TIMEOUT in prep handler
- io_uring: move all prep state for IORING_OP_{SEND,RECV}_MGS to prep handler
- io_uring: move all prep state for IORING_OP_CONNECT to prep handler
- io_uring: add and use struct io_rw for read/writes
- io_uring: use u64_to_user_ptr() consistently
- io_uring: io_wq_submit_work() should not touch req->rw
- io_uring: don't wait when under-submitting
- io_uring: warn about unhandled opcode
- io_uring: read opcode and user_data from SQE exactly once
- io_uring: make IORING_OP_TIMEOUT_REMOVE deferrable
- io_uring: make IORING_OP_CANCEL_ASYNC deferrable
- io_uring: make IORING_POLL_ADD and IORING_POLL_REMOVE deferrable
- io_uring: make HARDLINK imply LINK
- io_uring: any deferred command must have stable sqe data
- io_uring: remove 'sqe' parameter to the OP helpers that take it
- io_uring: fix pre-prepped issue with force_nonblock == true
- io-wq: re-add io_wq_current_is_worker()
- io_uring: fix sporadic -EFAULT from IORING_OP_RECVMSG
- io_uring: fix stale comment and a few typos
- io_uring: ensure we return -EINVAL on unknown opcode
- io_uring: add sockets to list of files that support non-blocking issue
- io_uring: only hash regular files for async work execution
- io_uring: run next sqe inline if possible
- io_uring: don't dynamically allocate poll data
- io_uring: deferred send/recvmsg should assign iov
- io_uring: sqthread should grab ctx->uring_lock for submissions
- io-wq: briefly spin for new work after finishing work
- io-wq: remove worker->wait waitqueue
- io_uring: allow unbreakable links
- io_uring: fix a typo in a comment
- io_uring: hook all linked requests via link_list
- io_uring: fix error handling in io_queue_link_head
- io_uring: use hash table for poll command lookups
- io-wq: clear node->next on list deletion
- io_uring: ensure deferred timeouts copy necessary data
- io_uring: allow IO_SQE_* flags on IORING_OP_TIMEOUT
- io_uring: handle connect -EINPROGRESS like -EAGAIN
- io_uring: remove io_wq_current_is_worker
- io_uring: remove parameter ctx of io_submit_state_start
- io_uring: mark us with IORING_FEAT_SUBMIT_STABLE
- io_uring: ensure async punted connect requests copy data
- io_uring: ensure async punted sendmsg/recvmsg requests copy data
- net: disallow ancillary data for __sys_{send,recv}msg_file()
- net: separate out the msghdr copy from ___sys_{send,recv}msg()
- io_uring: ensure async punted read/write requests copy iovec
- io_uring: add general async offload context
- io_uring: transform send/recvmsg() -ERESTARTSYS to -EINTR
- io_uring: use current task creds instead of allocating a new one
- io_uring: fix missing kmap() declaration on powerpc
- io_uring: add mapping support for NOMMU archs
- io_uring: make poll->wait dynamically allocated
- io-wq: shrink io_wq_work a bit
- io-wq: fix handling of NUMA node IDs
- io_uring: use kzalloc instead of kcalloc for single-element allocations
- io_uring: cleanup io_import_fixed()
- io_uring: inline struct sqe_submit
- io_uring: store timeout's sqe->off in proper place
- io_uring: remove superfluous check for sqe->off in io_accept()
- io_uring: async workers should inherit the user creds
- io-wq: have io_wq_create() take a 'data' argument
- io_uring: fix dead-hung for non-iter fixed rw
- io_uring: add support for IORING_OP_CONNECT
- net: add __sys_connect_file() helper
- io_uring: only return -EBUSY for submit on non-flushed backlog
- io_uring: only !null ptr to io_issue_sqe()
- io_uring: simplify io_req_link_next()
- io_uring: pass only !null to io_req_find_next()
- io_uring: remove io_free_req_find_next()
- io_uring: add likely/unlikely in io_get_sqring()
- io_uring: rename __io_submit_sqe()
- io_uring: improve trace_io_uring_defer() trace point
- io_uring: drain next sqe instead of shadowing
- io_uring: close lookup gap for dependent next work
- io_uring: allow finding next link independent of req reference count
- io_uring: io_allocate_scq_urings() should return a sane state
- io_uring: Always REQ_F_FREE_SQE for allocated sqe
- io_uring: io_fail_links() should only consider first linked timeout
- io_uring: Fix leaking linked timeouts
- io_uring: remove redundant check
- io_uring: break links for failed defer
- io-wq: remove extra space characters
- io-wq: wait for io_wq_create() to setup necessary workers
- io_uring: request cancellations should break links
- io_uring: correct poll cancel and linked timeout expiration completion
- io_uring: remove dead REQ_F_SEQ_PREV flag
- io_uring: fix sequencing issues with linked timeouts
- io_uring: make req->timeout be dynamically allocated
- io_uring: make io_double_put_req() use normal completion path
- io_uring: cleanup return values from the queueing functions
- io_uring: io_async_cancel() should pass in 'nxt' request pointer
- io_uring: make POLL_ADD/POLL_REMOVE scale better
- io-wq: remove now redundant struct io_wq_nulls_list
- io_uring: Fix getting file for non-fd opcodes
- io_uring: introduce req_need_defer()
- io_uring: clean up io_uring_cancel_files()
- io-wq: ensure free/busy list browsing see all items
- io_uring: ensure registered buffer import returns the IO length
- io-wq: ensure we have a stable view of ->cur_work for cancellations
- io_wq: add get/put_work handlers to io_wq_create()
- io_uring: Fix getting file for timeout
- io_uring: check for validity of ->rings in teardown
- io_uring: fix potential deadlock in io_poll_wake()
- io_uring: use correct "is IO worker" helper
- io_uring: make timeout sequence == 0 mean no sequence
- io_uring: fix -ENOENT issue with linked timer with short timeout
- io_uring: don't do flush cancel under inflight_lock
- io_uring: flag SQPOLL busy condition to userspace
- io_uring: make ASYNC_CANCEL work with poll and timeout
- io_uring: provide fallback request for OOM situations
- io_uring: convert accept4() -ERESTARTSYS into -EINTR
- io_uring: fix error clear of ->file_table in io_sqe_files_register()
- io_uring: separate the io_free_req and io_free_req_find_next interface
- io_uring: keep io_put_req only responsible for release and put req
- io_uring: remove passed in 'ctx' function parameter ctx if possible
- io_uring: reduce/pack size of io_ring_ctx
- io_uring: properly mark async work as bounded vs unbounded
- io-wq: add support for bounded vs unbunded work
- io-wq: io_wqe_run_queue() doesn't need to use list_empty_careful()
- io_uring: add support for backlogged CQ ring
- io_uring: pass in io_kiocb to fill/add CQ handlers
- io_uring: make io_cqring_events() take 'ctx' as argument
- io_uring: add support for linked SQE timeouts
- io_uring: abstract out io_async_cancel_one() helper
- io_uring: use inlined struct sqe_submit
- io_uring: Use submit info inlined into req
- io_uring: allocate io_kiocb upfront
- io_uring: io_queue_link*() right after submit
- io_uring: Merge io_submit_sqes and io_ring_submit
- io_uring: kill dead REQ_F_LINK_DONE flag
- io_uring: fixup a few spots where link failure isn't flagged
- io_uring: enable optimized link handling for IORING_OP_POLL_ADD
- io-wq: use proper nesting IRQ disabling spinlocks for cancel
- io_uring: add completion trace event
- io-wq: use kfree_rcu() to simplify the code
- io_uring: set -EINTR directly when a signal wakes up in io_cqring_wait
- io_uring: support for generic async request cancel
- io_uring: ensure we clear io_kiocb->result before each issue
- io_uring: io_wq_create() returns an error pointer, not NULL
- io_uring: fix race with canceling timeouts
- io_uring: support for larger fixed file sets
- io_uring: protect fixed file indexing with array_index_nospec()
- io_uring: add support for IORING_OP_ACCEPT
- net: add __sys_accept4_file() helper
- io_uring: io_uring: add support for async work inheriting files
- io_uring: replace workqueue usage with io-wq
- io-wq: small threadpool implementation for io_uring
- sched/core, workqueues: Distangle worker accounting from rq lock
- sched: Remove stale PF_MUTEX_TESTER bit
- io_uring: Fix mm_fault with READ/WRITE_FIXED
- io_uring: remove index from sqe_submit
- io_uring: add set of tracing events
- io_uring: add support for canceling timeout requests
- io_uring: add support for absolute timeouts
- io_uring: replace s->needs_lock with s->in_async
- io_uring: allow application controlled CQ ring size
- io_uring: add support for IORING_REGISTER_FILES_UPDATE
- io_uring: allow sparse fixed file sets
- io_uring: run dependent links inline if possible
- io_uring: don't touch ctx in setup after ring fd install
- io_uring: Fix leaked shadow_req
- io_uring: fix bad inflight accounting for SETUP_IOPOLL|SETUP_SQTHREAD
- io_uring: used cached copies of sq->dropped and cq->overflow
- io_uring: Fix race for sqes with userspace
- io_uring: Fix broken links with offloading
- io_uring: Fix corrupted user_data
- io_uring: correct timeout req sequence when inserting a new entry
- io_uring : correct timeout req sequence when waiting timeout
- io_uring: revert "io_uring: optimize submit_and_wait API"
- io_uring: fix logic error in io_timeout
- io_uring: fix up O_NONBLOCK handling for sockets
- io_uring: consider the overflow of sequence for timeout req
- io_uring: fix sequence logic for timeout requests
- io_uring: only flush workqueues on fileset removal
- io_uring: remove wait loop spurious wakeups
- io_uring: fix reversed nonblock flag for link submission
- io_uring: use __kernel_timespec in timeout ABI
- io_uring: make CQ ring wakeups be more efficient
- io_uring: compare cached_cq_tail with cq.head in_io_uring_poll
- io_uring: correctly handle non ->{read,write}_iter() file_operations
- io_uring: IORING_OP_TIMEOUT support
- io_uring: use cond_resched() in sqthread
- io_uring: fix potential crash issue due to io_get_req failure
- io_uring: ensure poll commands clear ->sqe
- io_uring: fix use-after-free of shadow_req
- io_uring: use kmemdup instead of kmalloc and memcpy
- io_uring: increase IORING_MAX_ENTRIES to 32K
- io_uring: make sqpoll wakeup possible with getevents
- io_uring: extend async work merging
- io_uring: limit parallelism of buffered writes
- io_uring: add io_queue_async_work() helper
- io_uring: optimize submit_and_wait API
- io_uring: add support for link with drain
- io_uring: fix wrong sequence setting logic
- io_uring: expose single mmap capability
- io_uring: allocate the two rings together
- io_uring: add need_resched() check in inner poll loop
- io_uring: don't enter poll loop if we have CQEs pending
- io_uring: fix potential hang with polled IO
- io_uring: fix an issue when IOSQE_IO_LINK is inserted into defer list
- io_uring: fix manual setup of iov_iter for fixed buffers
- io_uring: fix KASAN use after free in io_sq_wq_submit_work
- io_uring: ensure ->list is initialized for poll commands
- io_uring: track io length in async_list based on bytes
- io_uring: don't use iov_iter_advance() for fixed buffers
- io_uring: add a memory barrier before atomic_read
- io_uring: fix counter inc/dec mismatch in async_list
- io_uring: fix the sequence comparison in io_sequence_defer
- io_uring: fix io_sq_thread_stop running in front of io_sq_thread
- io_uring: add support for recvmsg()
- io_uring: add support for sendmsg()
- io_uring: add support for sqe links
- io_uring: punt short reads to async context
- uio: make import_iovec()/compat_import_iovec() return bytes on success
- io_uring: ensure req->file is cleared on allocation
- io_uring: fix memory leak of UNIX domain socket inode
- io_uring: Fix __io_uring_register() false success
- tools/io_uring: sync with liburing
- tools/io_uring: fix Makefile for pthread library link
- select: shift restore_saved_sigmask_unless() into poll_select_copy_remaining()
- select: change do_poll() to return -ERESTARTNOHAND rather than -EINTR
- signal: simplify set_user_sigmask/restore_user_sigmask
- signal: remove the wrong signal_pending() check in restore_user_sigmask()
- io_uring: use wait_event_interruptible for cq_wait conditional wait
- io_uring: adjust smp_rmb inside io_cqring_events
- io_uring: fix infinite wait in khread_park() on io_finish_async()
- io_uring: remove 'ev_flags' argument
- io_uring: fix failure to verify SQ_AFF cpu
- io_uring: fix race condition reading SQE data
- io_uring: use cpu_online() to check p->sq_thread_cpu instead of cpu_possible()
- io_uring: fix shadowed variable ret return code being not checked
- req->error only used for iopoll
- io_uring: add support for eventfd notifications
- io_uring: add support for IORING_OP_SYNC_FILE_RANGE
- io_uring: add support for marking commands as draining
- fs: add sync_file_range() helper
- io_uring: avoid page allocation warnings
- io_uring: drop req submit reference always in async punt
- io_uring: free allocated io_memory once
- io_uring: fix SQPOLL cpu validation
- io_uring: have submission side sqe errors post a cqe
- io_uring: remove unnecessary barrier after unsetting IORING_SQ_NEED_WAKEUP
- io_uring: remove unnecessary barrier after incrementing dropped counter
- io_uring: remove unnecessary barrier before reading SQ tail
- io_uring: remove unnecessary barrier after updating SQ head
- io_uring: remove unnecessary barrier before reading cq head
- io_uring: remove unnecessary barrier before wq_has_sleeper
- io_uring: fix notes on barriers
- io_uring: fix handling SQEs requesting NOWAIT
- io_uring: remove 'state' argument from io_{read,write} path
- io_uring: fix poll full SQ detection
- io_uring: fix race condition when sq threads goes sleeping
- io_uring: fix race condition reading SQ entries
- io_uring: fail io_uring_register(2) on a dying io_uring instance
- io_uring: fix CQ overflow condition
- io_uring: fix possible deadlock between io_uring_{enter,register}
- io_uring: drop io_file_put() 'file' argument
- io_uring: only test SQPOLL cpu after we've verified it
- io_uring: park SQPOLL thread if it's percpu
- io_uring: restrict IORING_SETUP_SQPOLL to root
- io_uring: fix double free in case of fileset regitration failure
- io_uring: offload write to async worker in case of -EAGAIN
- io_uring: fix big-endian compat signal mask handling
- io_uring: retry bulk slab allocs as single allocs
- io_uring: fix poll races
- io_uring: fix fget/fput handling
- io_uring: add prepped flag
- io_uring: make io_read/write return an integer
- io_uring: use regular request ref counts
- tools/io_uring: remove IOCQE_FLAG_CACHEHIT
- io_uring: add a few test tools
- io_uring: allow workqueue item to handle multiple buffered requests
- io_uring: add support for IORING_OP_POLL
- io_uring: add io_kiocb ref count
- io_uring: add submission polling
- io_uring: add file set registration
- net: split out functions related to registering inflight socket files
- io_uring: add support for pre-mapped user IO buffers
- io_uring: batch io_kiocb allocation
- io_uring: use fget/fput_many() for file references
- fs: add fget_many() and fput_many()
- io_uring: support for IO polling
- io_uring: add fsync support
- Add io_uring IO interface
- io_pgetevents: use __kernel_timespec
- pselect6: use __kernel_timespec
- ppoll: use __kernel_timespec
- signal: Add restore_user_sigmask()
- signal: Add set_user_sigmask()
- block: Initialize BIO I/O priority early
- block: prevent merging of requests with different priorities
- aio: Fix fallback I/O priority value
- block: Introduce get_current_ioprio()
- aio: Comment use of IOCB_FLAG_IOPRIO aio flag
- fs: fix kabi change since add iopoll
- fs: add an iopoll method to struct file_operations
- signal: Allow cifs and drbd to receive their terminating signals
- cifs: fix rmmod regression in cifs.ko caused by force_sig changes
- signal/cifs: Fix cifs_put_tcp_session to call send_sig instead of force_sig

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.10.0.0073
- bpf, x86: Validate computation of branch displacements for x86-32
- bpf, x86: Validate computation of branch displacements for x86-64

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.9.0.0072
- mm/vmalloc.c: fix percpu free VM area search criteria
- mm/vmalloc.c: avoid bogus -Wmaybe-uninitialized warning
- mm/vmap: add DEBUG_AUGMENT_LOWEST_MATCH_CHECK macro
- mm/vmap: add DEBUG_AUGMENT_PROPAGATE_CHECK macro
- mm/vmalloc.c: keep track of free blocks for vmap allocation

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.8.0.0071
- config: Enable CONFIG_USERSWAP
- userswap: support userswap via userfaultfd
- userswap: add a new flag 'MAP_REPLACE' for mmap()
- mm, mempolicy: fix up gup usage in lookup_node
- mm/mempolicy: Allow lookup_node() to handle fatal signal
- mm/gup: Let __get_user_pages_locked() return -EINTR for fatal signal
- mm/gup: fix fixup_user_fault() on multiple retries
- mm/gup: allow VM_FAULT_RETRY for multiple times
- mm: allow VM_FAULT_RETRY for multiple times

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.7.0.0070
- sched/fair: fix kabi broken due to adding fields in rq and sched_domain_shared
- sched/fair: fix try_steal compile error
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

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.6.0.0069
- sched/fair: fix kabi broken due to adding idle_h_nr_running in cfs_rq
- sched/fair: Make sched-idle CPU selection consistent throughout
- sched/fair: Optimize select_idle_cpu
- sched/fair: Fall back to sched-idle CPU if idle CPU isn't found
- sched/fair: Start tracking SCHED_IDLE tasks count in cfs_rq
- sched/core: Create task_has_idle_policy() helper

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.5.0.0068
- ext4: add reclaim checks to xattr code
- locking/mutex: Fix non debug version of mutex_lock_io_nested()
- dm verity: add root hash pkcs#7 signature verification
- Revert "netfilter: x_tables: Update remaining dereference to RCU"
- netfilter: x_tables: Use correct memory barriers.
- Revert "netfilter: x_tables: Switch synchronization to RCU"
- arm64: kdump: update ppos when reading elfcorehdr
- netfilter: ctnetlink: fix dump of the expect mask attribute
- dm ioctl: fix out of bounds array access when no devices
- block: Suppress uevent for hidden device when removed
- NFS: Correct size calculation for create reply length
- cifs: Fix preauth hash corruption
- ext4: do not try to set xattr into ea_inode if value is empty
- kernel, fs: Introduce and use set_restart_fn() and arch_set_restart_data()
- nvme-rdma: fix possible hang when failing to set io queues
- sunrpc: fix refcount leak for rpc auth modules
- include/linux/sched/mm.h: use rcu_dereference in in_vfork()
- hrtimer: Update softirq_expires_next correctly after __hrtimer_get_next_event()
- scsi: target: core: Prevent underflow for service actions
- scsi: target: core: Add cmd length set before cmd complete
- PCI: Fix pci_register_io_range() memory leak
- Revert "mm, slub: consider rest of partial list if acquire_slab() fails"
- cifs: return proper error code in statfs(2)
- tcp: add sanity tests to TCP_QUEUE_SEQ
- tcp: annotate tp->write_seq lockless reads
- tcp: annotate tp->copied_seq lockless reads
- netfilter: x_tables: gpf inside xt_find_revision()
- net: Fix gro aggregation for udp encaps with zero csum
- dm table: fix zoned iterate_devices based device capability checks
- dm table: fix DAX iterate_devices based device capability checks
- dm table: fix iterate_devices based device capability checks
- dm bufio: subtract the number of initial sectors in dm_bufio_get_device_size
- swap: fix swapfile read/write offset
- mm/hugetlb.c: fix unnecessary address expansion of pmd sharing
- net: fix up truesize of cloned skb in skb_prepare_for_shift()
- xfs: Fix assert failure in xfs_setattr_size()
- arm64 module: set plt* section addresses to 0x0
- hugetlb: fix update_and_free_page contig page struct assumption
- net: icmp: pass zeroed opts from icmp{,v6}_ndo_send before sending
- ipv6: silence compilation warning for non-IPV6 builds
- ipv6: icmp6: avoid indirect call for icmpv6_send()
- xfrm: interface: use icmp_ndo_send helper
- sunvnet: use icmp_ndo_send helper
- gtp: use icmp_ndo_send helper
- icmp: allow icmpv6_ndo_send to work with CONFIG_IPV6=n
- icmp: introduce helper for nat'd source address in network device context
- dm: fix deadlock when swapping to encrypted device
- printk: fix deadlock when kernel panic
- module: Ignore _GLOBAL_OFFSET_TABLE_ when warning for undefined symbols
- hugetlb: fix copy_huge_page_from_user contig page struct assumption
- x86: fix seq_file iteration for pat/memtype.c
- ACPI: property: Fix fwnode string properties matching
- blk-settings: align max_sectors on "logical_block_size" boundary
- mm/rmap: fix potential pte_unmap on an not mapped pte
- arm64: Add missing ISB after invalidating TLB in __primary_switch
- mm/hugetlb: fix potential double free in hugetlb_register_node() error path
- mm/memory.c: fix potential pte_unmap_unlock pte error
- ocfs2: fix a use after free on error
- tracepoint: Do not fail unregistering a probe due to memory failure
- isofs: release buffer head before return
- tcp: fix SO_RCVLOWAT related hangs under mem pressure
- random: fix the RNDRESEEDCRNG ioctl
- bfq: Avoid false bfq queue merging
- locking/static_key: Fix false positive warnings on concurrent dec/inc
- jump_label/lockdep: Assert we hold the hotplug lock for _cpuslocked() operations
- KVM: fix memory leak in kvm_io_bus_unregister_dev()
- net: qrtr: fix a kernel-infoleak in qrtr_recvmsg()
- xen-blkback: don't leak persistent grants from xen_blkbk_map()
- KVM: SVM: Periodically schedule when unregistering regions on destroy
- gianfar: fix jumbo packets+napi+rx overrun crash
- usbip: fix stub_dev usbip_sockfd_store() races leading to gpf
- media: v4l: ioctl: Fix memory leak in video_usercopy
- block: only update parent bi_status when bio fail
- RDMA/hns: fix timer, gid_type, scc cfg
- block: respect queue limit of max discard segment
- block: Use non _rcu version of list functions for tag_set_list

* Thu Apr 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.4.0.0067
- ext4: fix potential error in ext4_do_update_inode
- mm, sl[aou]b: guarantee natural alignment for kmalloc(power-of-two)
- mm,hwpoison: return -EBUSY when migration fails
- config: Enable files cgroup on x86
- ext4: Fix unreport netlink message to userspace when fs abort
- ext4: don't leak old mountpoint samples
- scsi: libiscsi: convert change of struct iscsi_conn to fix KABI
- scsi: libiscsi: Reset max/exp cmdsn during recovery
- scsi: iscsi_tcp: Fix shost can_queue initialization
- scsi: libiscsi: Add helper to calculate max SCSI cmds per session
- scsi: libiscsi: Fix iSCSI host workq destruction
- scsi: libiscsi: Fix iscsi_task use after free()
- scsi: libiscsi: Drop taskqueuelock
- scsi: libiscsi: Fix iscsi_prep_scsi_cmd_pdu() error handling
- scsi: libiscsi: Fix error count for active session
- ext4: fix timer use-after-free on failed mount
- loop: fix I/O error on fsync() in detached loop devices
- md/bitmap: fix memory leak of temporary bitmap
- md: get sysfs entry after redundancy attr group create
- md: fix deadlock causing by sysfs_notify
- md: fix the checking of wrong work queue
- md: flush md_rdev_misc_wq for HOT_ADD_DISK case
- md: don't flush workqueue unconditionally in md_open
- md: add new workqueue for delete rdev

* Tue Apr 13 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.3.0.0066
- nvme-fabrics: fix kabi broken due to adding fields in struct nvme_ctrl

* Thu Apr 01 2021 Jiachen Fan <fanjiachen3@huawei.com> - 4.19.90-2104.2.0.0065
- Add the option of "with_perf"
- Output jvmti plug-in as part of perf building

* Wed Apr 07 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.2.0.0064
- x86/Kconfig: Drop vendor dependency for X86_UMIP
- x86/Kconfig: Rename UMIP config parameter
- iommu/vt-d:Add support for detecting ACPI device in RMRR
- USB:Fix kernel NULL pointer when unbind UHCI form vfio-pci
- x86/apic: Mask IOAPIC entries when disabling the local APIC
- xhci: fix issue with resume from system Sx state
- xhci: Adjust the UHCI Controllers bit value
- ALSA: hda: Add support of Zhaoxin NB HDAC codec
- ALSA: hda: Add support of Zhaoxin NB HDAC
- ALSA: hda: Add support of Zhaoxin SB HDAC
- xhci: Show Zhaoxin XHCI root hub speed correctly
- xhci: fix issue of cross page boundary in TRB prefetch
- PCI: Add ACS quirk for Zhaoxin Root/Downstream Ports
- PCI: Add ACS quirk for Zhaoxin multi-function devices
- xhci: Add Zhaoxin xHCI LPM U1/U2 feature support
- ata: sata_zhaoxin: Add support for Zhaoxin Serial ATA
- PCI: Add Zhaoxin Vendor ID
- x86/perf: Add hardware performance events support for Zhaoxin CPU.
- crypto: x86/crc32c-intel - Don't match some Zhaoxin CPUs
- x86/speculation/swapgs: Exclude Zhaoxin CPUs from SWAPGS vulnerability
- x86/speculation/spectre_v2: Exclude Zhaoxin CPUs from SPECTRE_V2
- x86/mce: Add Zhaoxin LMCE support
- x86/mce: Add Zhaoxin CMCI support
- x86/mce: Add Zhaoxin MCE support
- x86/acpi/cstate: Add Zhaoxin processors support for cache flush policy in C3
- x86/power: Optimize C3 entry on Centaur CPUs
- ACPI, x86: Add Zhaoxin processors support for NONSTOP TSC
- x86/cpu: Add detect extended topology for Zhaoxin CPUs
- x86/cpufeatures: Add Zhaoxin feature bits
- x86/cpu/centaur: Add Centaur family >=7 CPUs initialization support
- x86/cpu/centaur: Replace two-condition switch-case with an if statement
- x86/cpu: Remove redundant cpu_detect_cache_sizes() call
- x86/cpu: Create Zhaoxin processors architecture support file
- xhci: apply XHCI_PME_STUCK_QUIRK to Intel Comet Lake platforms
- xhci: Fix memory leak when caching protocol extended capability PSI tables - take 2
- xhci: fix runtime pm enabling for quirky Intel hosts
- xhci: Force Maximum Packet size for Full-speed bulk devices to valid range.

* Thu Apr 01 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2104.1.0.0063
- configs: add config BMA to config files
- Huawei BMA: Adding Huawei BMA driver: host_kbox_drv
- Huawei BMA: Adding Huawei BMA driver: cdev_veth_drv
- Huawei BMA: Adding Huawei BMA driver: host_veth_drv
- Huawei BMA: Adding Huawei BMA driver: host_cdev_drv
- Huawei BMA: Adding Huawei BMA driver: host_edma_drv
- scsi: ses: Fix crash caused by kfree an invalid pointer
- net: hns3: PF add support for pushing link status to VFs
- net: hns: update hns version to 21.2.1
- net: hns: Remove unused macro AE_NAME_PORT_ID_IDX
- net: hns: use IRQ_NOAUTOEN to avoid irq is enabled due to request_irq
- net: hns: Replace zero-length array with flexible-array member
- hisilicon/hns: convert comma to semicolon
- net: hns: make arrays static, makes object smaller
- net: hns: Move static keyword to the front of declaration
- net: hns: use eth_broadcast_addr() to assign broadcast address
- net: hns: use true,false for bool variables
- net: hns: fix wrong display of "Advertised link modes"
- net: hns: fix ping failed when setting "autoneg off speed 100 duplex half"
- net: hns: fix variable used when DEBUG is defined
- net: hns: fix non-promiscuous mode does not take effect problem
- net: hns: remove redundant variable initialization
- treewide: Replace GPLv2 boilerplate/reference with SPDX - rule 152
- net/hinic: update hinic version to 2.3.2.18
- net/hinic: Add support for hinic PMD on VF
- net/hinic: Add XDP support for pass and drop actions
- net/hinic: permit configuration of rx-vlan-filter with ethtool
- locks: fix a memory leak bug in __break_lease()

* Mon Mar 29 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2103.4.0.0062
- mm/vmscan: fix uncleaned mem_cgroup_uncharge
- staging: rtl8188eu: prevent ->ssid overflow in rtw_wx_set_scan()
- PCI: rpadlpar: Fix potential drc_name corruption in store functions
- perf/x86/intel: Fix a crash caused by zero PEBS status
- btrfs: fix race when cloning extent buffer during rewind of an old root
- bpf: Fix off-by-one for area size in creating mask to left
- bpf: Prohibit alu ops for pointer types not defining ptr_limit
- net/x25: prevent a couple of overflows
- drm/ttm/nouveau: don't call tt destroy callback on alloc failure.
- cgroup: Fix kabi broken by files_cgroup introduced
- arm64/mpam: fix a possible deadlock in mpam_enable
- config: arm64: build TCM driver to modules by default
- staging: TCM: add GMJS(Nationz Tech) TCM driver.
- config: enable config TXGBE by default
- x86/config: Set CONFIG_TXGBE=m by default
- net: txgbe: Add support for Netswift 10G NIC

* Mon Mar 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2103.3.0.0061
- arm64/mpam: fix a memleak in add_schema
- scsi: check the whole result for reading write protect flag
- ext4: Fix bug on in ext4_es_cache_extent as ext4_split_extent_at failed
- md: add checkings before flush md_misc_wq
- dm: use noio when sending kobject event
- ext4: fix potential htree index checksum corruption
- quota: Fix memory leak when handling corrupted quota file
- quota: Sanity-check quota file headers on load
- block, bfq: invoke flush_idle_tree after reparent_active_queues in pd_offline
- block, bfq: make reparent_leaf_entity actually work only on leaf entities
- block, bfq: turn put_queue into release_process_ref in __bfq_bic_change_cgroup
- block, bfq: move forward the getting of an extra ref in bfq_bfqq_move
- block, bfq: get extra ref to prevent a queue from being freed during a group move
- perf/ftrace: Fix use-after-free in __ftrace_ops_list_func()
- fs/xfs: fix time overflow
- ext4: remove set but not used variable 'es' in ext4_jbd2.c
- ext4: remove set but not used variable 'es'
- ext4: don't try to processed freed blocks until mballoc is initialized
- ext4: drop ext4_handle_dirty_super()
- ext4: use sbi instead of EXT4_SB(sb) in ext4_update_super()
- ext4: save error info to sb through journal if available
- ext4: protect superblock modifications with a buffer lock
- ext4: drop sync argument of ext4_commit_super()
- ext4: combine ext4_handle_error() and save_error_info()
- ext4: defer saving error info from atomic context
- ext4: simplify ext4 error translation
- ext4: move functions in super.c
- ext4: make ext4_abort() use __ext4_error()
- ext4: standardize error message in ext4_protect_reserved_inode()
- ext4: save all error info in save_error_info() and drop ext4_set_errno()
- ext4: save the error code which triggered an ext4_error() in the superblock
- ext4: remove redundant sb checksum recomputation
- Revert "ext4: Protect superblock modifications with a buffer lock"

* Mon Mar 15 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2103.2.0.0060
- xen-netback: respect gnttab_map_refs()'s return value
- Xen/gnttab: handle p2m update errors on a per-slot basis
- sysfs: fix kabi broken when add sysfs_emit and sysfs_emit_at
- scsi: iscsi: Verify lengths on passthrough PDUs
- scsi: iscsi: Ensure sysfs attributes are limited to PAGE_SIZE
- sysfs: Add sysfs_emit and sysfs_emit_at to format sysfs output
- scsi: iscsi: Restrict sessions and handles to admin capabilities
- ovl: do not fail because of O_NOATIME
- ovl: check permission to open real file
- ovl: call secutiry hook in ovl_real_ioctl()
- ovl: verify permissions in ovl_path_open()
- ovl: switch to mounter creds in readdir
- ovl: pass correct flags for opening real directory
- mm/swapfile.c: fix potential memory leak in sys_swapon
- hibernate: Allow uswsusp to write to swap
- mm/swapfile.c: move inode_lock out of claim_swapfile
- mm/swapfile.c: fix a comment in sys_swapon()
- vfs: don't allow writes to swap files
- mm: set S_SWAPFILE on blockdev swap devices
- block_dump: remove block_dump feature when dirting inode
- virtio-blk: modernize sysfs attribute creation
- nvme: register ns_id attributes as default sysfs groups
- ext4: Fix not report exception message when mount with errors=continue
- xen-blkback: fix error handling in xen_blkbk_map()
- xen-scsiback: don't "handle" error by BUG()
- xen-netback: don't "handle" error by BUG()
- xen-blkback: don't "handle" error by BUG()
- xen/arm: don't ignore return errors from set_phys_to_machine
- Xen/gntdev: correct error checking in gntdev_map_grant_pages()
- Xen/gntdev: correct dev_bus_addr handling in gntdev_map_grant_pages()
- Xen/x86: also check kernel mapping in set_foreign_p2m_mapping()
- Xen/x86: don't bail early from clear_foreign_p2m_mapping()

* Thu Mar 11 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2103.1.0.0059
- brcmfmac: Loading the correct firmware for brcm43456
- config: Enable the config option of the etmem feature
- etmem: add etmem-swap feature
- etmem: add etmem-scan feature
- moduleparam: Save information about built-in modules in separate file
- ovl: expand warning in ovl_d_real()
- net: watchdog: hold device global xmit lock during tx disable
- bfq-iosched: Revert "bfq: Fix computation of shallow depth"
- ovl: skip getxattr of security labels
- cap: fix conversions on getxattr
- ovl: perform vfs_getxattr() with mounter creds
- tracing: Check length before giving out the filter buffer
- tracing: Do not count ftrace events in top level enable output
- blk-mq: don't hold q->sysfs_lock in blk_mq_map_swqueue
- block: don't hold q->sysfs_lock in elevator_init_mq
- SUNRPC: Handle 0 length opaque XDR object data properly
- SUNRPC: Move simple_get_bytes and simple_get_netobj into private header
- fgraph: Initialize tracing_graph_pause at task creation
- tracing/kprobe: Fix to support kretprobe events on unloaded modules
- md: Set prev_flush_start and flush_bio in an atomic way
- mm: thp: fix MADV_REMOVE deadlock on shmem THP
- mm: hugetlb: remove VM_BUG_ON_PAGE from page_huge_active
- mm: hugetlb: fix a race between isolating and freeing page
- mm: hugetlb: fix a race between freeing and dissolving the page
- mm: hugetlbfs: fix cannot migrate the fallocated HugeTLB page
- smb3: Fix out-of-bounds bug in SMB2_negotiate()
- cifs: report error instead of invalid when revalidating a dentry fails
- genirq/msi: Activate Multi-MSI early when MSI_FLAG_ACTIVATE_EARLY is set
- kretprobe: Avoid re-registration of the same kretprobe earlier
- ovl: fix dentry leak in ovl_get_redirect
- memblock: do not start bottom-up allocations with kernel_end
- workqueue: Restrict affinity change to rescuer
- kthread: Extract KTHREAD_IS_PER_CPU
- sysctl: handle overflow in proc_get_long
- fs: fix lazytime expiration handling in __writeback_single_inode()
- writeback: Drop I_DIRTY_TIME_EXPIRE
- dm integrity: conditionally disable "recalculate" feature
- tracing: Fix race in trace_open and buffer resize call
- Revert "mm/slub: fix a memory leak in sysfs_slab_add()"
- net/rds: restrict iovecs length for RDS_CMSG_RDMA_ARGS
- net: fix iteration for sctp transport seq_files
- netfilter: conntrack: skip identical origin tuple in same zone only
- netfilter: flowtable: fix tcp and udp header checksum update
- netfilter: xt_recent: Fix attempt to update deleted entry
- af_key: relax availability checks for skb size calculation
- net: ip_tunnel: fix mtu calculation
- net_sched: gen_estimator: support large ewma log
- tcp: fix TLP timer not set when CA_STATE changes from DISORDER to OPEN
- net/mlx5: Fix memory leak on flow table creation error flow
- xfrm: fix disable_xfrm sysctl when used on xfrm interfaces
- xfrm: Fix oops in xfrm_replay_advance_bmp
- netfilter: nft_dynset: add timeout extension to template
- net: sit: unregister_netdevice on newlink's error path
- esp: avoid unneeded kmap_atomic call
- udp: Prevent reuseport_select_sock from reading uninitialized socks
- vrf: Fix fast path output packet handling with async Netfilter rules
- livepatch/core: Fix jump_label_apply_nops called multi times
- gpu: hibmc: Fix stuck when switch GUI to text.
- gpu: hibmc: Use drm get pci dev api.
- gpu: hibmc: Fix erratic display during startup stage.
- net: hns3: update hns3 version to 1.9.38.11
- net: hns3: fix 'ret' may be used uninitialized problem
- net: hns3: update hns3 version to 1.9.38.10
- net: hns3: adds support for setting pf max tx rate via sysfs
- ext4: find old entry again if failed to rename whiteout
- config: disable config TMPFS_INODE64 by default
- tmpfs: restore functionality of nr_inodes=0
- tmpfs: support 64-bit inums per-sb
- tmpfs: per-superblock i_ino support
- Revert "scsi: sg: fix memory leak in sg_build_indirect"
- scsi: fix kabi for scsi_device
- scsi: core: Only re-run queue in scsi_end_request() if device queue is busy
- scsi: core: Run queue in case of I/O resource contention failure
- Revert "scsi: sd: block: Fix read-only flag residuals when partition table change"
- scsi: sd: block: Fix kabi change by 'scsi: sd: block: Fix regressions in read-only block device handling'
- scsi: sd: block: Fix read-only flag residuals when partition table change
- scsi: sd: block: Fix regressions in read-only block device handling
- proc/mounts: Fix kabi broken
- proc/mounts: add cursor
- list: introduce list_for_each_continue()

* Wed Feb 24 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2102.3.0.0058
- arm64/mpam: Fix compile warning
- arm64/mpam: Sort domains when cpu online
- arm64/mpam: resctrl: Refresh cpu mask for handling cpuhp
- arm64/mpam: resctrl: Allow setting register MPAMCFG_MBW_MIN to 0
- arm64/mpam: resctrl: Use resctrl_group_init_alloc() for default group
- arm64/mpam: resctrl: Add proper error handling to resctrl_mount()
- arm64/mpam: Supplement additional useful ctrl features for mount options
- ACPI/MPAM: Use acpi_map_pxm_to_node() to get node id for memory node
- arm64/mpam: Set per-cpu's closid to none zero for cdp
- arm64/mpam: Simplify mpamid cdp mapping process
- arm64/mpam: Filter schema control type with ctrl features
- arm64/mpam: resctrl: Add rmid file in resctrl sysfs
- arm64/mpam: Split header files into suitable location
- arm64/mpam: resctrl: Export resource's properties to info directory
- arm64/mpam: Add resctrl_ctrl_feature structure to manage ctrl features
- arm64/mpam: Add wait queue for monitor alloc and free
- arm64/mpam: Remap reqpartid,pmg to rmid and intpartid to closid
- arm64/mpam: Separate internal and downstream priority event
- arm64/mpam: Enabling registering and logging error interrupts
- arm64/mpam: Fix MPAM_ESR intPARTID_range error
- arm64/mpam: Integrate monitor data for Memory Bandwidth if cdp enabled
- arm64/mpam: Add hook-events id for ctrl features
- arm64/mpam: Re-plan intpartid narrowing process
- arm64/mpam: Restore extend ctrls' max width for checking schemata input
- arm64/mpam: Squash default priority from mpam device to class
- arm64/mpam: Store intpri and dspri for mpam device reset
- arm64/mpam: resctrl: Support priority and hardlimit(Memory bandwidth) configuration
- arm64/mpam: resctrl: Support cpus' monitoring for mon group
- arm64/mpam: resctrl: collect child mon group's monitor data
- arm64/mpam: Using software-defined id for rdtgroup instead of 32-bit integer
- arm64/mpam: Implement intpartid narrowing process
- arm64/mpam: resctrl: Remove unnecessary CONFIG_ARM64
- arm64/mpam: resctrl: Remove ctrlmon sysfile
- arm64/mpam: Clean up header files and rearrange declarations
- arm64/mpam: resctrl: Support cdp on monitoring data
- arm64/mpam: Support cdp on allocating monitors
- arm64/mpam: resctrl: Move ctrlmon sysfile write/read function to mpam_ctrlmon.c
- arm64/mpam: resctrl: Update closid alloc and free process with bitmap
- arm64/mpam: resctrl: Update resources reset process
- arm64/mpam: Support cdp in mpam_sched_in()
- arm64/mpam: resctrl: Write and read schemata by schema_list
- arm64/mpam: resctrl: Use resctrl_group_init_alloc() to init schema list
- arm64/mpam: resctrl: Add helpers for init and destroy schemata list
- arm64/mpam: resctrl: Supplement cdpl2,cdpl3 for mount options
- arm64/mpam: resctrl: Append schemata CDP definitions
- arm64/mpam: resctrl: Rebuild configuration and monitoring pipeline
- arm64/mpam: Probe partid,pmg and feature capabilities' ranges from classes
- arm64/mpam: Add helper for getting MSCs' configuration
- arm64/mpam: Migrate old MSCs' discovery process to new branch
- drivers: base: cacheinfo: Add helper to search cacheinfo by of_node
- arm64/mpam: Implement helpers for handling configuration and monitoring
- arm64/mpam: resctrl: Handle cpuhp and resctrl_dom allocation
- arm64/mpam: resctrl: Re-synchronise resctrl's view of online CPUs
- arm64/mpam: Init resctrl resources' info from resctrl_res selected
- arm64/mpam: Pick MPAM resources and events for resctrl_res exported
- arm64/mpam: Allocate mpam component configuration arrays
- arm64/mpam: Summarize feature support during mpam_enable()
- arm64/mpam: Reset controls when CPUs come online
- arm64/mpam: Add helper for getting mpam sysprops
- arm64/mpam: Probe the features resctrl supports
- arm64/mpam: Supplement MPAM MSC register layout definitions
- arm64/mpam: Probe supported partid/pmg ranges from devices
- cacheinfo: Provide a helper to find a cacheinfo leaf
- arm64/mpam: Add mpam driver discovery phase and kbuild boiler plate
- arm64/mpam: Preparing for MPAM refactoring


* Mon Feb 22 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2102.2.0.0057
- powerpc: fix a compiling error for 'access_ok'
- mmap: fix a compiling error for 'MAP_CHECKNODE'
- futex: sched: fix UAF when free futex_exit_mutex in free_task()
- futex: sched: fix kabi broken in task_struct
- futex: Prevent exit livelock
- futex: Provide distinct return value when owner is exiting
- futex: Add mutex around futex exit
- futex: Provide state handling for exec() as well
- futex: Sanitize exit state handling
- futex: Mark the begin of futex exit explicitly
- futex: Set task::futex_state to DEAD right after handling futex exit
- futex: Split futex_mm_release() for exit/exec
- exit/exec: Seperate mm_release()
- futex: Replace PF_EXITPIDONE with a state
- futex: Move futex exit handling into futex code
- net: Disable NETIF_F_HW_TLS_RX when RXCSUM is disabled
- ipv6: set multicast flag on the multicast route
- net_sched: reject silly cell_log in qdisc_get_rtab()
- net_sched: avoid shift-out-of-bounds in tcindex_set_parms()
- ipv6: create multicast route with RTPROT_KERNEL
- udp: mask TOS bits in udp_v4_early_demux()
- kasan: fix incorrect arguments passing in kasan_add_zero_shadow
- kasan: fix unaligned address is unhandled in kasan_remove_zero_shadow
- skbuff: back tiny skbs with kmalloc() in __netdev_alloc_skb() too
- netfilter: rpfilter: mask ecn bits before fib lookup
- driver core: Extend device_is_dependent()
- dm integrity: fix a crash if "recalculate" used without "internal_hash"
- dm: avoid filesystem lookup in dm_get_dev_t()
- ACPI: scan: Make acpi_bus_get_device() clear return pointer on error
- net: ipv6: Validate GSO SKB before finish IPv6 processing
- net: skbuff: disambiguate argument and member for skb_list_walk_safe helper
- net: introduce skb_list_walk_safe for skb segment walking
- tipc: fix NULL deref in tipc_link_xmit()
- net: avoid 32 x truesize under-estimation for tiny skbs
- dm integrity: fix flush with external metadata device
- netfilter: nf_nat: Fix memleak in nf_nat_init
- netfilter: conntrack: fix reading nf_conntrack_buckets
- net: sunrpc: interpret the return value of kstrtou32 correctly
- mm, slub: consider rest of partial list if acquire_slab() fails
- ext4: fix superblock checksum failure when setting password salt
- NFS: nfs_igrab_and_active must first reference the superblock
- NFS/pNFS: Fix a leak of the layout 'plh_outstanding' counter
- pNFS: Mark layout for return if return-on-close was not sent
- NFS4: Fix use-after-free in trace_event_raw_event_nfs4_set_lock
- dump_common_audit_data(): fix racy accesses to ->d_name
- bfq: Fix computation of shallow depth
- dm integrity: fix the maximum number of arguments
- dm snapshot: flush merged data before committing metadata
- mm/hugetlb: fix potential missing huge page size info
- ACPI: scan: Harden acpi_device_add() against device ID overflows
- block: fix use-after-free in disk_part_iter_next
- vhost_net: fix ubuf refcount incorrectly when sendmsg fails
- virtio_net: Fix recursive call to cpus_read_lock()
- proc: fix lookup in /proc/net subdirectories after setns(2)
- proc: change ->nlink under proc_subdir_lock
- lib/genalloc: fix the overflow when size is too big
- scsi: scsi_transport_spi: Set RQF_PM for domain validation commands
- workqueue: Kick a worker based on the actual activation of delayed works
- dm verity: skip verity work if I/O error when system is shutting down
- module: delay kobject uevent until after module init call
- NFSv4: Fix a pNFS layout related use-after-free race when freeing the inode
- quota: Don't overflow quota file offsets
- module: set MODULE_STATE_GOING state when a module fails to load
- fcntl: Fix potential deadlock in send_sig{io, urg}()
- null_blk: Fix zone size initialization
- ext4: don't remount read-only with errors=continue on reboot
- vfio/pci: Move dummy_resources_list init in vfio_pci_probe()
- arm64: module/ftrace: intialize PLT at load time
- arm64: module: rework special section handling
- net: drop bogus skb with CHECKSUM_PARTIAL and offset beyond end of trimmed packet
- net/mlx5e: Fix two double free cases
- net/mlx5e: Fix memleak in mlx5e_create_l2_table_groups
- net: ipv6: fib: flush exceptions when purging route
- net: fix pmtu check in nopmtudisc mode
- net: ip: always refragment ip defragmented packets
- net: vlan: avoid leaks on register_vlan_dev() failures
- netfilter: xt_RATEEST: reject non-null terminated string from userspace
- netfilter: ipset: fix shift-out-of-bounds in htable_bits()
- netfilter: x_tables: Update remaining dereference to RCU
- net-sysfs: take the rtnl lock when accessing xps_rxqs_map and num_tc
- net-sysfs: take the rtnl lock when storing xps_rxqs
- net: sched: prevent invalid Scell_log shift count
- erspan: fix version 1 check in gre_parse_header()
- net: hns: fix return value check in __lb_other_process()
- ipv4: Ignore ECN bits for fib lookups in fib_compute_spec_dst()
- net-sysfs: take the rtnl lock when accessing xps_cpus_map and num_tc
- net-sysfs: take the rtnl lock when storing xps_cpus
- i40e: Fix Error I40E_AQ_RC_EINVAL when removing VFs
- lwt: Disable BH too in run_lwt_bpf()
- net/mlx5: Properly convey driver version to firmware
- vxlan: Copy needed_tailroom from lowerdev
- vxlan: Add needed_headroom for lower device
- ixgbe: avoid premature Rx buffer reuse
- xsk: Fix xsk_poll()'s return type
- net/mlx4_en: Handle TX error CQE
- net/mlx4_en: Avoid scheduling restart task if it is already running
- net/mlx5: Fix wrong address reclaim when command interface is down
- i40e: Fix removing driver while bare-metal VFs pass traffic
- net/tls: Protect from calling tls_dev_del for TLS RX twice
- net/tls: missing received data after fast remote close
- clocksource/drivers/arch_timer: Fix vdso_fix compile error for arm32
- scsi/hifc:Fix the bug that the system may be oops during unintall hifc module.
- KVM: Enable PUD huge mappings only on 1620
- fs: fix files.usage bug when move tasks
- scsi: do quiesce for enclosure driver
- ext4: fix bug for rename with RENAME_WHITEOUT
- mm: fix kabi broken
- mm: memcontrol: add struct mem_cgroup_extension
- mm: thp: don't need care deferred split queue in memcg charge move path
- mm: vmscan: protect shrinker idr replace with CONFIG_MEMCG
- mm: thp: make deferred split shrinker memcg aware
- mm: shrinker: make shrinker not depend on memcg kmem
- mm: move mem_cgroup_uncharge out of __page_cache_release()
- mm: thp: extract split_queue_* into a struct
- bonding: add documentation for peer_notif_delay
- bonding: fix value exported by Netlink for peer_notif_delay
- bonding: add an option to specify a delay between peer notifications
- arm64/ascend: mm: Fix hugetlb check node error
- fix virtio_gpu use-after-free while creating dumb
- ext4: add ext3 report error to userspace by netlink
- arm64/ascend: mm: Fix arm32 compile warnings
- Kconfig: disable KTASK by default
- netpoll: accept NULL np argument in netpoll_send_skb()
- netpoll: netpoll_send_skb() returns transmit status
- netpoll: move netpoll_send_skb() out of line
- netpoll: remove dev argument from netpoll_send_skb_on_dev()
- efi/arm: Revert "Defer persistent reservations until after paging_init()"
- arm64, mm, efi: Account for GICv3 LPI tables in static memblock reserve table
- block: better deal with the delayed not supported case in blk_cloned_rq_check_limits
- block: Return blk_status_t instead of errno codes
- ASoC: msm8916-wcd-digital: Select REGMAP_MMIO to fix build error
- irqchip/gic-v3: Fix compiling error on ARM32 with GICv3
- PCI: Fix pci_slot_release() NULL pointer dereference
- md/cluster: fix deadlock when node is doing resync job
- md/cluster: block reshape with remote resync job
- ext4: fix deadlock with fs freezing and EA inodes
- ext4: fix a memory leak of ext4_free_data
- ACPI: PNP: compare the string length in the matching_id()
- Revert "ACPI / resources: Use AE_CTRL_TERMINATE to terminate resources walks"
- nfs_common: need lock during iterate through the list
- clocksource/drivers/arm_arch_timer: Correct fault programming of CNTKCTL_EL1.EVNTI
- NFS: switch nfsiod to be an UNBOUND workqueue.
- lockd: don't use interval-based rebinding over TCP
- SUNRPC: xprt_load_transport() needs to support the netid "rdma6"
- PCI: iproc: Fix out-of-bound array accesses
- PCI: Fix overflow in command-line resource alignment requests
- PCI: Bounds-check command-line resource alignment requests
- genirq/irqdomain: Don't try to free an interrupt that has no mapping
- spi: fix resource leak for drivers without .remove callback
- scsi: core: Fix VPD LUN ID designator priorities
- selinux: fix inode_doinit_with_dentry() LABEL_INVALID error handling
- sched: Reenable interrupts in do_sched_yield()
- sched/deadline: Fix sched_dl_global_validate()
- selinux: fix error initialization in inode_doinit_with_dentry()
- serial_core: Check for port state when tty is in error state
- arm64: syscall: exit userspace before unmasking exceptions
- netfilter: x_tables: Switch synchronization to RCU
- block: factor out requeue handling from dispatch code
- arm64: Change .weak to SYM_FUNC_START_WEAK_PI for arch/arm64/lib/mem*.S
- arm64: lse: Fix LSE atomics with LLVM
- arm64: lse: fix LSE atomics with LLVM's integrated assembler
- net: bridge: vlan: fix error return code in __vlan_add()
- tcp: fix cwnd-limited bug for TSO deferral where we send nothing
- tcp: select sane initial rcvq_space.space for big MSS
- netfilter: nf_tables: avoid false-postive lockdep splat
- tracing: Fix userstacktrace option for instances
- mm/swapfile: do not sleep with a spin lock held
- mm: list_lru: set shrinker map bit when child nr_items is not zero
- cifs: fix potential use-after-free in cifs_echo_request()
- ftrace: Fix updating FTRACE_FL_TRAMP
- net: ip6_gre: set dev->hard_header_len when using header_ops
- ipv4: Fix tos mask in inet_rtm_getroute()
- netfilter: bridge: reset skb->pkt_type after NF_INET_POST_ROUTING traversal
- bonding: wait for sysfs kobject destruction before freeing struct slave
- tcp: Set INET_ECN_xmit configuration in tcp_reinit_congestion_control
- sock: set sk_err to ee_errno on dequeue from errq
- ipv6: addrlabel: fix possible memory leak in ip6addrlbl_net_init
- efivarfs: revert "fix memory leak in efivarfs_create()"
- scsi: libiscsi: Fix NOP race condition
- nvme: free sq/cq dbbuf pointers when dbbuf set fails
- proc: don't allow async path resolution of /proc/self components
- arm64: pgtable: Ensure dirty bit is preserved across pte_wrprotect()
- arm64: pgtable: Fix pte_accessible()
- scsi: libiscsi: fix task hung when iscsid deamon exited
- mmap: fix a compiling error for 'MAP_PA32BIT'
- hifc: remove unnecessary __init specifier
- armv7 fix compile error
- cputime: fix undefined reference to get_idle_time when CONFIG_PROC_FS disabled
- memcg/ascend: enable kmem cgroup by default for ascend
- memcg/ascend: Check sysctl oom config for memcg oom
- bdi: fix compiler error in bdi_get_dev_name()
- arm64: fix compile error when CONFIG_HOTPLUG_CPU is disabled
- scsi: target: iscsi: Fix cmd abort fabric stop race
- scsi: target: fix hang when multiple threads try to destroy the same iscsi session
- scsi: target: remove boilerplate code
- ext4: Protect superblock modifications with a buffer lock
- arm64: arch_timer: only do cntvct workaround on VDSO path on D05
- libata: transport: Use scnprintf() for avoiding potential buffer overflow
- Document: In the binding document, add enable-init-all-GICR field description.
- irqchip/irq-gic-v3: Add workaround bindings in device tree to init ts core GICR.
- asm-generic/io.h: Fix !CONFIG_GENERIC_IOMAP pci_iounmap() implementation
- hugetlbfs: Add dependency with ascend memory features
- net/mlx5: Disable QoS when min_rates on all VFs are zero
- sctp: change to hold/put transport for proto_unreach_timer
- net: Have netpoll bring-up DSA management interface
- mlxsw: core: Use variable timeout for EMAD retries
- ah6: fix error return code in ah6_input()
- tipc: fix memory leak in tipc_topsrv_start()
- sctp: Fix COMM_LOST/CANT_STR_ASSOC err reporting on big-endian platforms
- libceph: clear con->out_msg on Policy::stateful_server faults
- mlxsw: core: Fix use-after-free in mlxsw_emad_trans_finish()
- tipc: fix memory leak caused by tipc_buf_append()
- mlxsw: core: Fix memory leak on module removal
- irqchip/gic-v3-its: Unconditionally save/restore the ITS state on suspend.
- sbsa_gwdt: Add WDIOF_PRETIMEOUT flag to watchdog_info at defination
- NMI: Enable arm-pmu interrupt as NMI in Acensed.
- arm64/ascend: mm: Add MAP_CHECKNODE flag to check node hugetlb
- config: enable CONFIG_NVME_MULTIPATH by default
- mm/userfaultfd: do not access vma->vm_mm after calling handle_userfault()
- ext4: fix bogus warning in ext4_update_dx_flag()
- efivarfs: fix memory leak in efivarfs_create()
- libfs: fix error cast of negative value in simple_attr_write()
- xfs: revert "xfs: fix rmap key and record comparison functions"
- fail_function: Remove a redundant mutex unlock
- xfs: strengthen rmap record flags checking
- xfs: fix the minrecs logic when dealing with inode root child blocks
- ip_tunnels: Set tunnel option flag when tunnel metadata is present
- perf lock: Don't free "lock_seq_stat" if read_count isn't zero
- vfs: remove lockdep bogosity in __sb_start_write
- arm64: psci: Avoid printing in cpu_psci_cpu_die()
- tcp: only postpone PROBE_RTT if RTT is < current min_rtt estimate
- page_frag: Recover from memory pressure
- net: bridge: add missing counters to ndo_get_stats64 callback
- inet_diag: Fix error path to cancel the meseage in inet_req_diag_fill()
- devlink: Add missing genlmsg_cancel() in devlink_nl_sb_port_pool_fill()
- Convert trailing spaces and periods in path components
- net: sch_generic: fix the missing new qdisc assignment bug
- reboot: fix overflow parsing reboot cpu number
- Revert "kernel/reboot.c: convert simple_strtoul to kstrtoint"
- perf scripting python: Avoid declaring function pointers with a visibility attribute
- random32: make prandom_u32() output unpredictable
- net: Update window_clamp if SOCK_RCVBUF is set
- IPv6: Set SIT tunnel hard_header_len to zero
- don't dump the threads that had been already exiting when zapped.
- selinux: Fix error return code in sel_ib_pkey_sid_slow()
- ocfs2: initialize ip_next_orphan
- futex: Don't enable IRQs unconditionally in put_pi_state()
- uio: Fix use-after-free in uio_unregister_device()
- ext4: unlock xattr_sem properly in ext4_inline_data_truncate()
- ext4: correctly report "not supported" for {usr, grp}jquota when !CONFIG_QUOTA
- perf: Fix get_recursion_context()
- xfs: fix a missing unlock on error in xfs_fs_map_blocks
- xfs: fix brainos in the refcount scrubber's rmap fragment processor
- xfs: fix rmap key and record comparison functions
- xfs: set the unwritten bit in rmap lookup flags in xchk_bmap_get_rmapextents
- xfs: fix flags argument to rmap lookup when converting shared file rmaps
- nbd: fix a block_device refcount leak in nbd_release
- tick/common: Touch watchdog in tick_unfreeze() on all CPUs
- netfilter: use actual socket sk rather than skb sk when routing harder
- tpm: efi: Don't create binary_bios_measurements file for an empty log
- xfs: fix scrub flagging rtinherit even if there is no rt device
- xfs: flush new eof page on truncate to avoid post-eof corruption
- perf tools: Add missing swap for ino_generation
- netfilter: ipset: Update byte and packet counters regardless of whether they match
- xfs: set xefi_discard when creating a deferred agfl free log intent item
- net: xfrm: fix a race condition during allocing spi
- time: Prevent undefined behaviour in timespec64_to_ns()
- fork: fix copy_process(CLONE_PARENT) race with the exiting ->real_parent
- scsi: core: Don't start concurrent async scan on same host
- blk-cgroup: Pre-allocate tree node on blkg_conf_prep
- blk-cgroup: Fix memleak on error path
- futex: Handle transient "ownerless" rtmutex state correctly
- tracing: Fix out of bounds write in get_trace_buf
- ftrace: Handle tracing when switching between context
- ftrace: Fix recursion check for NMI test
- ring-buffer: Fix recursion protection transitions between interrupt context
- kthread_worker: prevent queuing delayed work from timer_fn when it is being canceled
- mm: mempolicy: fix potential pte_unmap_unlock pte error
- Fonts: Replace discarded const qualifier
- ptrace: fix task_join_group_stop() for the case when current is traced
- device property: Don't clear secondary pointer for shared primary firmware node
- device property: Keep secondary firmware node secondary by type
- ext4: fix invalid inode checksum
- ext4: fix error handling code in add_new_gdb
- ext4: fix leaking sysfs kobject after failed mount
- ring-buffer: Return 0 on success from ring_buffer_resize()
- perf python scripting: Fix printable strings in python3 scripts
- sgl_alloc_order: fix memory leak
- nbd: make the config put is called before the notifying the waiter
- cifs: handle -EINTR in cifs_setattr
- ext4: Detect already used quota file early
- ACPI: Add out of bounds and numa_off protections to pxm_to_node()
- xfs: don't free rt blocks when we're doing a REMAP bunmapi call
- arm64/mm: return cpu_all_mask when node is NUMA_NO_NODE
- uio: free uio id after uio file node is freed
- arm64: topology: Stop using MPIDR for topology information
- xfs: fix realtime bitmap/summary file truncation when growing rt volume
- mm: fix exec activate_mm vs TLB shootdown and lazy tlb switching race
- futex: Fix incorrect should_fail_futex() handling
- serial: pl011: Fix lockdep splat when handling magic-sysrq interrupt
- fuse: fix page dereference after free
- tcp: Prevent low rmem stalls with SO_RCVLOWAT.
- netem: fix zero division in tabledist
- efivarfs: Replace invalid slashes with exclamation marks in dentries.
- arm64: Run ARCH_WORKAROUND_1 enabling code on all CPUs
- config: set default value of CONFIG_TEST_FREE_PAGES
- mm/page_alloc.c: fix freeing non-compound pages
- mm, hwpoison: double-check page count in __get_any_page()
- mm: fix a race during THP splitting
- mm: fix check_move_unevictable_pages() on THP
- mlock: fix unevictable_pgs event counts on THP
- mm: swap: memcg: fix memcg stats for huge pages
- mm: swap: fix vmstats for huge pages
- mm: move nr_deactivate accounting to shrink_active_list()
- blk-throttle: don't check whether or not lower limit is valid if CONFIG_BLK_DEV_THROTTLING_LOW is off
- blk-cgroup: prevent rcu_sched detected stalls warnings in blkg_destroy_all()


* Tue Feb 09 2021 Cheng Jian <cj.chengjian@huawei.com> - 4.19.90-2102.1.0.0056
- nbd: freeze the queue while we're adding connections
- nbd: Fix memory leak in nbd_add_socket
- futex: Handle faults correctly for PI futexes
- futex: Simplify fixup_pi_state_owner()
- futex: Use pi_state_update_owner() in put_pi_state()
- rtmutex: Remove unused argument from rt_mutex_proxy_unlock()
- futex: Provide and use pi_state_update_owner()
- futex: Replace pointless printk in fixup_owner()
- futex: Ensure the correct return value from futex_lock_pi()
- inet: do not call sublist_rcv on empty list
- netfilter: add and use nf_hook_slow_list()
- netfilter: clear skb->next in NF_HOOK_LIST()
- scsi: target: Fix XCOPY NAA identifier lookup
- nfsd4: readdirplus shouldn't return parent of export
- HID: core: Correctly handle ReportSize being zero

* Mon Jan 11 2021 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2101.1.0.0055
- net: hns3: update hns3 version to 1.9.38.9
- net: hns3: optimize the process of queue reset
- net: hns3: fix loopback test of serdes and phy is failed if duplex is half
- net: hns3: format the output of the MAC address
- net: hns3: rename hns-customer to hns3_extension
- net: hns3: fix RoCE calling the wrong function problem
- net: hns3: Clear the CMDQ registers before unmapping BAR region
- net: hns3: fix for loopback failure when vlan filter is enable
- net: hns3: replace snprintf with scnprintf in hns3_dbg_cmd_read
- net: hns3: delete unused codes
- net: hns3: fix missing help info in debugfs
- net: hns3: add trace event support for PF/VF mailbox
- net: hns3: fix loopback failed when phy has no .set_loopback interface
- net: hns3: clear hardware resource when loading driver
- net: hns3: fix incorrect print value of vf_id and vport_id
- net: hns3: fix bug when initialize the RSS tuples for SCTP6
- net: hns3: solve the problem of array uninitialized
- net: hns3: clean up for some coding style.
- net: hns3: adds a kernel message when restart autoneg.
- net: hns3: modify a print message
- net: hns3: provide .get_cmdq_stat interface for the client
- net: hns3: add a hardware error detect type
- net: hns3: implement .process_hw_error for hns3 client
- net: hns3: modify location of one print information
- net/hinic: update hinic version to 2.3.2.17
- net/hinic: Modify the printing level of some logs
- net/hinic: Fix oops when memory is insufficient
- net/hinic: Set default features when probe netdev
- RDMA/hns: fix eth extended SGE err
- scsi: hisi_sas: Delete down() when handle Block-IO
- nvme-fabrics: reject I/O to offline device
- PCI: Add pci reset quirk for Huawei Intelligent NIC virtual function
- nvme: fix nvme_stop_queues cost long time error
- scsi: hisi_sas: fix logic bug when alloc device with MAX device num == 1
- scsi: hisi_sas: mask corresponding RAS interrupts for hilink DFX exception
- scsi: hisi_sas: Directly trigger SCSI error handling for completion errors
- scsi: hisi_sas: use wait_for_completion_timeout() when clearing ITCT
- scsi: hisi_sas: Fix the conflict between device gone and host reset
- scsi: hisi_sas: Update all the registers after suspend and resume
- scsi: hisi_sas: Make slot buf minimum allocation of PAGE_SIZE
- scsi: hisi_sas: Reduce HISI_SAS_SGE_PAGE_CNT in size
- scsi: flip the default on use_clustering
- RDMA/hns: Disable UD on HIP08
- powerpc/rtas: Restrict RTAS requests from userspace
- mwifiex: Fix possible buffer overflows in mwifiex_cmd_802_11_ad_hoc_start
- xenbus/xenbus_backend: Disallow pending watch messages
- xen/xenbus: Count pending messages for each watch
- xen/xenbus/xen_bus_type: Support will_handle watch callback
- xen/xenbus: Add 'will_handle' callback support in xenbus_watch_path()
- xen/xenbus: Allow watches discard events before queueing
- xen-blkback: set ring->xenblkd to NULL after kthread_stop()
- HID: core: Sanitize event code and type when mapping input
- cfg80211: add missing policy for NL80211_ATTR_STATUS_CODE
- speakup: Reject setting the speakup line discipline outside of speakup
- tty: Fix ->session locking
- tty: Fix ->pgrp locking in tiocspgrp()
- ALSA: rawmidi: Fix racy buffer resize under concurrent accesses
- jfs: Fix array index bounds check in dbAdjTree

* Tue Dec 22 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.5.0.0054
- Revert "mm/memory_hotplug: refrain from adding memory into an impossible node"

* Mon Dec 21 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.4.0.0053
- defconfig: update the defconfigs to support NVDIMM

* Thu Dec 17 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.3.0.0052
- scsi/hifc: fix the issue that the system is suspended during the pres
- mm: thp: make the THP mapcount atomic against __split_huge_pmd_locked()
- romfs: fix uninitialized memory leak in romfs_dev_read()

* Tue Dec 15 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.2.0.0051
- scsi: libiscsi: Fix cmds hung when sd_shutdown

* Thu Dec 10 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2012.1.0.0050
- fanotify: fix merging marks masks with FAN_ONDIR
- scsi/hifc: fix the issue of npiv cannot be deleted

* Sat Nov 28 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2011.6.0.0049
- refcount_t: Add ACQUIRE ordering on success for dec(sub)_and_test() variants
- x86/asm: 'Simplify' GEN_*_RMWcc() macros
- Revert "refcount_t: Add ACQUIRE ordering on success for dec(sub)_and_test() variants"
- refcount_t: Add ACQUIRE ordering on success for dec(sub)_and_test() variants
- powerpc/64s: flush L1D after user accesses
- powerpc/uaccess: Evaluate macro arguments once, before user access is allowed
- powerpc: Fix __clear_user() with KUAP enabled
- powerpc: Implement user_access_begin and friends
- powerpc: Add a framework for user access tracking
- powerpc/64s: flush L1D on kernel entry
- powerpc/64s: move some exception handlers out of line

* Mon Nov 23 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2011.4.0.0048
- Bluetooth: fix kernel oops in store_pending_adv_report
- vt: Disable KD_FONT_OP_COPY
- fbcon: Fix global-out-of-bounds read in fbcon_get_font()
- Fonts: Support FONT_EXTRA_WORDS macros for built-in fonts
- fbdev, newport_con: Move FONT_EXTRA_WORDS macros into linux/font.h
- speakup: Do not let the line discipline be used several times
- mm/page_idle.c: skip offline pages
- mm/memory_hotplug: refrain from adding memory into an impossible node
- khugepaged: drain LRU add pagevec after swapin
- khugepaged: drain all LRU caches before scanning pages
- khugepaged: do not stop collapse if less than half PTEs are referenced
- powercap: restrict energy meter to root access
- Input: sunkbd - avoid use-after-free in teardown paths
- nbd: don't update block size after device is started

* Wed Nov 18 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2011.3.0.0047
- tools: perf: Fix build error in v4.19.y
- nvme-fabrics: modify default value to reconnect forever
- nvme-rdma: add module param to turn off inline data dynamically
- nvme-rdma: fix crash casue by destroy id while resolving addr
- nvme-rdma: avoid race between time out and tear down
- nvme-core: introduce sync io queues
- nvme-rdma: avoid repeated request completion
- nvme-rdma: fix crash due to incorrect cqe
- nvme-multipath: fix crash in nvme_mpath_clear_ctrl_paths
- nvme: fix controller removal race with scan work
- nvme-multipath: fix bogus request queue reference put
- nvme-multipath: fix deadlock due to head->lock
- nvme: don't protect ns mutation with ns->head->lock
- nvme: clear any SGL flags in passthru commands
- nvme: disable streams when get stream params failed
- nvme: revalidate after verifying identifiers
- nvme: release namespace head reference on error
- nvme: unlink head after removing last namespace
- nvme: Make nvme_uninit_ctrl symmetric to nvme_init_ctrl
- nvme: Fix ctrl use-after-free during sysfs deletion
- nvme-rdma: fix crash when connect rejected
- nvme-rdma: fix timeout handler
- nvme: Fix parsing of ANA log page
- nvme: release ida resources
- nvme: Add compat_ioctl handler for NVME_IOCTL_SUBMIT_IO
- nvme: introduce "Command Aborted By host" status code
- nvme: enable aen regardless of the presence of I/O queues
- nvme: make nvme_identify_ns propagate errors back
- nvme: pass status to nvme_error_status
- nvme: don't abort completed request in nvme_cancel_request
- nvme: put ns_head ref if namespace fails allocation
- nvme: implement Enhanced Command Retry
- nvme: wait until all completed request's complete fn is called
- blk-mq: introduce blk_mq_tagset_wait_completed_request()
- blk-mq: introduce blk_mq_request_completed()
- nvme-rdma: fix a segmentation fault during module unload
- mlx5: remove support for ib_get_vector_affinity
- nvme-rdma: fix possible use-after-free in connect timeout
- nvme-rdma: fix possible use-after-free in connect error flow
- nvme-rdma: use dynamic dma mapping per command
- nvme-rdma: remove redundant reference between ib_device and tagset
- scsi/hifc: add hifc driver compile config module
- scsi/hifc: add hifc driver FC service module
- scsi/hifc: add hifc driver scsi module
- scsi/hifc: add hifc driver io module
- scsi/hifc: add hifc driver port resource module
- scsi/hifc: add hifc driver port manager module
- scsi/hifc: add hifc driver chip resource module
- perf/core: Fix a memory leak in perf_event_parse_addr_filter()
- mm/rmap: fixup copying of soft dirty and uffd ptes
- mm: madvise: fix vma user-after-free
- svcrdma: fix bounce buffers for unaligned offsets and multiple pages
- net/mlx5: Don't call timecounter cyc2time directly from 1PPS flow
- net/tls: sendfile fails with ktls offload
- tipc: fix the skb_unshare() in tipc_buf_append()
- mlx4: handle non-napi callers to napi_poll
- net/mlx5e: Fix VLAN create flow
- net/mlx5e: Fix VLAN cleanup flow
- openvswitch: handle DNAT tuple collision
- xfrmi: drop ignore_df check before updating pmtu
- net: openvswitch: use div_u64() for 64-by-32 divisions
- e1000: Do not perform reset in reset_task if we are already down
- tipc: fix memory leak in service subscripting
- net: openvswitch: use u64 for meter bucket
- svcrdma: Fix leak of transport addresses
- net: sch_generic: aviod concurrent reset and enqueue op for lockless qdisc
- cpufreq: CPPC: put ACPI table after using it
- cpufreq : CPPC: Break out if HiSilicon CPPC workaround is matched
- tty/amba-pl011: Call acpi_put_table() to fix memory leak
- irqchip/gicv3: Call acpi_put_table() to fix memory leak
- partitions/efi: Fix partition name parsing in GUID partition entry
- tty: make FONTX ioctl use the tty pointer they were actually passed
- vt: keyboard, extend func_buf_lock to readers
- vt: keyboard, simplify vt_kdgkbsent
- binder: fix UAF when releasing todo list
- bpf: Fix clobbering of r2 in bpf_gen_ld_abs
- bpf: Remove recursion prevention from rcu free callback
- ipvs: Fix uninit-value in do_ip_vs_set_ctl()
- xfs: make sure the rt allocator doesn't run off the end
- ip_gre: set dev->hard_header_len and dev->needed_headroom properly
- crypto: ccp - fix error handling
- netfilter: nf_fwd_netdev: clear timestamp in forwarding path
- netfilter: conntrack: connection timeout after re-register
- vfio iommu type1: Fix memory leak in vfio_iommu_type1_pin_pages
- vfio/pci: Clear token on bypass registration failure
- ext4: limit entries returned when counting fsmap records
- watchdog: Use put_device on error
- watchdog: Fix memleak in watchdog_cdev_register
- watchdog: initialize device before misc_register
- ramfs: fix nommu mmap with gaps in the page cache
- lib/crc32.c: fix trivial typo in preprocessor condition
- xfs: fix high key handling in the rt allocator's query_range function
- xfs: limit entries returned when counting fsmap records
- mm, oom_adj: don't loop through tasks in __set_oom_adj when not necessary
- mm/memcg: fix device private memcg accounting
- netfilter: nf_log: missing vlan offload tag and proto
- ipvs: clear skb->tstamp in forwarding path
- cifs: Return the error from crypt_message when enc/dec key not found.
- cifs: remove bogus debug code
- icmp: randomize the global rate limiter
- tcp: fix to update snd_wl1 in bulk receiver fast path
- net/sched: act_tunnel_key: fix OOB write in case of IPv6 ERSPAN tunnels
- net/ipv4: always honour route mtu during forwarding
- net: fix pos incrementment in ipv6_route_seq_next
- ipv4: Restore flowi4_oif update before call to xfrm_lookup_route
- mm: khugepaged: recalculate min_free_kbytes after memory hotplug as expected by khugepaged
- perf: Fix task_function_call() error handling
- bonding: set dev->needed_headroom in bond_setup_by_slave()
- xfrm: Use correct address family in xfrm_state_find
- xfrm: clone whole liftime_cur structure in xfrm_do_migrate
- xfrm: clone XFRMA_SEC_CTX in xfrm_do_migrate
- xfrm: clone XFRMA_REPLAY_ESN_VAL in xfrm_do_migrate
- xfrm: clone XFRMA_SET_MARK in xfrm_do_migrate
- sctp: fix sctp_auth_init_hmacs() error path
- cifs: Fix incomplete memory allocation on setxattr path
- mm/khugepaged: fix filemap page_to_pgoff(page) != offset
- nvme-core: put ctrl ref when module ref get fail
- usermodehelper: reset umask to default before executing user process
- netfilter: ctnetlink: add a range check for l3/l4 protonum
- ep_create_wakeup_source(): dentry name can change under you...
- epoll: EPOLL_CTL_ADD: close the race in decision to take fast path
- epoll: replace ->visited/visited_list with generation count
- epoll: do not insert into poll queues until all sanity checks are done
- mm: don't rely on system state to detect hot-plug operations
- mm: replace memmap_context by meminit_context
- random32: Restore __latent_entropy attribute on net_rand_state
- nfs: Fix security label length not being reset
- nvme-core: get/put ctrl and transport module in nvme_dev_open/release()
- ftrace: Move RCU is watching check after recursion check
- mm, THP, swap: fix allocating cluster for swapfile by mistake
- kprobes: Fix to check probe enabled before disarm_kprobe_ftrace()
- tracing: fix double free
- bpf: Fix a rcu warning for bpffs map pretty-print
- lockdep: fix order in trace_hardirqs_off_caller()
- nvme: explicitly update mpath disk capacity on revalidation
- perf parse-events: Use strcmp() to compare the PMU name
- vfio/pci: fix racy on error and request eventfd ctx
- nvme: fix possible deadlock when I/O is blocked
- cifs: Fix double add page to memcg when cifs_readpages
- vfio/pci: Clear error and request eventfd ctx after releasing
- perf kcore_copy: Fix module map when there are no modules loaded
- perf metricgroup: Free metric_events on error
- perf util: Fix memory leak of prefix_if_not_in
- perf stat: Fix duration_time value for higher intervals
- perf evsel: Fix 2 memory leaks
- vfio/pci: fix memory leaks of eventfd ctx
- printk: handle blank console arguments passed in.
- arm64/cpufeature: Drop TraceFilt feature exposure from ID_DFR0 register
- fuse: don't check refcount after stealing page
- perf mem2node: Avoid double free related to realloc
- bdev: Reduce time holding bd_mutex in sync in blkdev_close()
- mm/mmap.c: initialize align_offset explicitly for vm_unmapped_area
- mm/vmscan.c: fix data races using kswapd_classzone_idx
- mm/filemap.c: clear page error before actual read
- mm/kmemleak.c: use address-of operator on section symbols
- NFS: Fix races nfs_page_group_destroy() vs nfs_destroy_unlinked_subrequests()
- PCI: pciehp: Fix MSI interrupt race
- SUNRPC: Fix a potential buffer overflow in 'svc_print_xprts()'
- nvme-multipath: do not reset on unknown status
- perf cpumap: Fix snprintf overflow check
- serial: 8250: 8250_omap: Terminate DMA before pushing data on RX timeout
- serial: 8250_omap: Fix sleeping function called from invalid context during probe
- serial: 8250_port: Don't service RX FIFO if throttled
- perf parse-events: Fix 3 use after frees found with clang ASAN
- xfs: mark dir corrupt when lookup-by-hash fails
- xfs: don't ever return a stale pointer from __xfs_dir3_free_read
- mm: avoid data corruption on CoW fault into PFN-mapped VMA
- perf jevents: Fix leak of mapfile memory
- random: fix data races at timer_rand_state
- selinux: sel_avc_get_stat_idx should increase position index
- audit: CONFIG_CHANGE don't log internal bookkeeping as an event
- skbuff: fix a data race in skb_queue_len()
- mm/swapfile.c: swap_next should increase position index
- tracing: Set kernel_stack's caller size properly
- ACPI: EC: Reference count query handlers under lock
- sctp: move trace_sctp_probe_path into sctp_outq_sack
- ipv6_route_seq_next should increase position index
- rt_cpu_seq_next should increase position index
- neigh_stat_seq_next() should increase position index
- xfs: fix log reservation overflows when allocating large rt extents
- kernel/sys.c: avoid copying possible padding bytes in copy_to_user
- xfs: fix attr leaf header freemap.size underflow
- fix dget_parent() fastpath race
- net: silence data-races on sk_backlog.tail
- mm: fix double page fault on arm64 if PTE_AF is cleared
- sdei_watchdog: avoid possible false hardlockup
- xen/pciback: use lateeoi irq binding
- xen/pvcallsback: use lateeoi irq binding
- xen/scsiback: use lateeoi irq binding
- xen/netback: use lateeoi irq binding
- xen/blkback: use lateeoi irq binding
- xen/events: fix race in evtchn_fifo_unmask()
- xen/events: add a proper barrier to 2-level uevent unmasking
- arm64: fix abi change caused by ILP32

* Fri Oct 30 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2010.2.0.0046
- rtc: cmos: Revert "rtc: Fix the AltCentury value on AMD/Hygon platform"
- NTB: Fix static check warning in perf_clear_test
- NTB: ntb_perf: Fix address err in perf_copy_chunk
- NTB: Fix an error in get link status
- rtc: Fix the AltCentury value on AMD/Hygon platform
- tools/power turbostat: Add support for Hygon Fam 18h (Dhyana) RAPL
- tools/power turbostat: Fix caller parameter of get_tdp_amd()
- tools/power turbostat: Also read package power on AMD F17h (Zen)
- tools/power turbostat: Add support for AMD Fam 17h (Zen) RAPL
- NTB: Add Hygon Device ID
- x86/amd_nb: Make hygon_nb_misc_ids static
- i2c-piix4: Add Hygon Dhyana SMBus support
- x86/CPU/hygon: Fix phys_proc_id calculation logic for multi-die processors
- hwmon: (k10temp) Add Hygon Dhyana support
- tools/cpupower: Add Hygon Dhyana support
- EDAC, amd64: Add Hygon Dhyana support
- cpufreq: Add Hygon Dhyana support
- ACPI: Add Hygon Dhyana support
- x86/xen: Add Hygon Dhyana support to Xen
- x86/kvm: Add Hygon Dhyana support to KVM
- x86/mce: Add Hygon Dhyana support to the MCA infrastructure
- x86/bugs: Add Hygon Dhyana to the respective mitigation machinery
- x86/apic: Add Hygon Dhyana support
- x86/pci, x86/amd_nb: Add Hygon Dhyana support to PCI and northbridge
- x86/amd_nb: Check vendor in AMD-only functions
- x86/alternative: Init ideal_nops for Hygon Dhyana
- x86/events: Add Hygon Dhyana support to PMU infrastructure
- x86/smpboot: Do not use BSP INIT delay and MWAIT to idle on Dhyana
- x86/cpu/mtrr: Support TOP_MEM2 and get MTRR number
- x86/cpu: Get cache info and setup cache cpumap for Hygon Dhyana
- x86/cpu: Create Hygon Dhyana architecture support file
- kvm: debugfs: aarch64 export cpu time related items to debugfs
- kvm: debugfs: export remaining aarch64 kvm exit reasons to debugfs
- kvm: debugfs: Export vcpu stat via debugfs
- kvm: fix compile error when including linux/kvm.h
- kvm: arm64: add KVM_CAP_ARM_CPU_FEATURE extension
- kvm: arm64: make ID registers configurable
- kvm: arm64: emulate the ID registers
- arm64: add a helper function to traverse arm64_ftr_regs
- xen/events: defer eoi in case of excessive number of events
- xen/events: use a common cpu hotplug hook for event channels
- xen/events: switch user event channels to lateeoi model
- xen/events: add a new "late EOI" evtchn framework
- xen/events: avoid removing an event channel while handling it
- net/hinic: update hinic version to 2.3.2.16
- net/hinic: Allowed to send commands when only hot activation of ucode
- net/hinic: Fix ethtool loopback test failure
- net/hinic: VF is not allowed to configure global resources
- net/hinic: Allow to remove administratively set MAC on VFs
- net/hinic: Fix the driver does not report an error when setting MAC fails
- Bluetooth: MGMT: Fix not checking if BT_HS is enabled
- Bluetooth: Disable High Speed by default
- Bluetooth: L2CAP: Fix calling sk_filter on non-socket based channel
- Bluetooth: A2MP: Fix not initializing all members
- perf/core: Fix race in the perf_mmap_close() function
- geneve: add transport ports in route lookup for geneve
- ext4: only set last error block when check system zone failed
- xfs: Fix tail rounding in xfs_alloc_file_space()
- KEYS: reaching the keys quotas correctly
- serial: 8250: Avoid error message on reprobe
- mm: memcg: fix memcg reclaim soft lockup
- mm/thp: fix __split_huge_pmd_locked() for migration PMD
- kprobes: fix kill kprobe which has been marked as gone
- percpu: fix first chunk size calculation for populated bitmap
- spi: Fix memory leak on splited transfers
- nvme-rdma: cancel async events before freeing event struct
- nvme-fc: cancel async events before freeing event struct
- NFS: Zero-stateid SETATTR should first return delegation
- scsi: target: iscsi: Fix hang in iscsit_access_np() when getting tpg->np_login_sem
- scsi: target: iscsi: Fix data digest calculation
- xfs: initialize the shortform attr header padding entry
- block: ensure bdi->io_pages is always initialized
- dm writecache: handle DAX to partitions on persistent memory correctly
- libata: implement ATA_HORKAGE_MAX_TRIM_128M and apply to Sandisks
- uaccess: Add non-pagefault user-space write function
- uaccess: Add non-pagefault user-space read functions
- xfs: don't update mtime on COW faults
- include/linux/log2.h: add missing () around n in roundup_pow_of_two()
- perf jevents: Fix suspicious code in fixregex()
- xfs: fix xfs_bmap_validate_extent_raw when checking attr fork of rt files
- fix regression in "epoll: Keep a reference on files added to the check list"
- perf tools: Correct SNOOPX field offset
- cpuidle: Fixup IRQ state
- tpm: Unify the mismatching TPM space buffer sizes
- device property: Fix the secondary firmware node handling in set_primary_fwnode()
- PM: sleep: core: Fix the handling of pending runtime resume requests
- writeback: Fix sync livelock due to b_dirty_time processing
- writeback: Avoid skipping inode writeback
- writeback: Protect inode->i_io_list with inode->i_lock
- serial: 8250: change lock order in serial8250_do_startup()
- serial: 8250_exar: Fix number of ports for Commtech PCIe cards
- serial: pl011: Don't leak amba_ports entry on driver register error
- serial: pl011: Fix oops on -EPROBE_DEFER
- vt_ioctl: change VT_RESIZEX ioctl to check for error return from vc_resize()
- vt: defer kfree() of vc_screenbuf in vc_do_resize()
- blk-mq: order adding requests to hctx->dispatch and checking SCHED_RESTART
- fs: prevent BUG_ON in submit_bh_wbc()
- ext4: handle option set by mount flags correctly
- ext4: handle read only external journal device
- ext4: don't BUG on inconsistent journal feature
- jbd2: make sure jh have b_transaction set in refile/unfile_buffer
- scsi: fcoe: Memory leak fix in fcoe_sysfs_fcf_del()
- scsi: iscsi: Do not put host in iscsi_set_flashnode_param()
- locking/lockdep: Fix overflow in presentation of average lock-time
- PCI: Fix pci_create_slot() reference count leak
- xfs: Don't allow logging of XFS_ISTALE inodes
- iommu/iova: Don't BUG on invalid PFNs
- mm/hugetlb: fix calculation of adjust_range_if_pmd_sharing_possible
- do_epoll_ctl(): clean the failure exits up a bit
- epoll: Keep a reference on files added to the check list
- efi: add missed destroy_workqueue when efisubsys_init fails
- RDMA/bnxt_re: Do not add user qps to flushlist
- vfio/type1: Add proper error unwind for vfio_iommu_replay()
- fs/signalfd.c: fix inconsistent return codes for signalfd4
- xfs: Fix UBSAN null-ptr-deref in xfs_sysfs_init
- virtio_ring: Avoid loop when vq is broken in virtqueue_poll
- xfs: fix inode quota reservation checks
- scsi: target: tcmu: Fix crash in tcmu_flush_dcache_range on ARM
- spi: Prevent adding devices below an unregistering controller
- jbd2: add the missing unlock_buffer() in the error path of jbd2_write_superblock()
- ext4: fix checking of directory entry validity for inline directories
- mm, page_alloc: fix core hung in free_pcppages_bulk()
- mm: include CMA pages in lowmem_reserve at boot
- kernel/relay.c: fix memleak on destroy relay channel
- khugepaged: adjust VM_BUG_ON_MM() in __khugepaged_enter()
- khugepaged: khugepaged_test_exit() check mmget_still_valid()
- perf probe: Fix memory leakage when the probe point is not found
- xfs: fix duplicate verification from xfs_qm_dqflush()
- xfs: reset buffer write failure state on successful completion
- xfs: fix partially uninitialized structure in xfs_reflink_remap_extent
- xfs: clear PF_MEMALLOC before exiting xfsaild thread
- xfs: acquire superblock freeze protection on eofblocks scans
- xfs: Fix deadlock between AGI and AGF with RENAME_WHITEOUT
- macvlan: validate setting of multiple remote source MAC addresses
- blk-mq: insert flush request to the front of dispatch queue
- blk-mq: Rerun dispatching in the case of budget contention
- blk-mq: Add blk_mq_delay_run_hw_queues() API call
- blk-mq: In blk_mq_dispatch_rq_list() "no budget" is a reason to kick
- blk-mq: Put driver tag in blk_mq_dispatch_rq_list() when no budget
- blk-mq: insert passthrough request into hctx->dispatch directly
- arm64/ascend: Fix register_persistent_clock definition
- net: add __must_check to skb_put_padto()
- netfilter: nf_tables: incorrect enum nft_list_attributes definition
- tcp_bbr: adapt cwnd based on ack aggregation estimation
- tcp_bbr: refactor bbr_target_cwnd() for general inflight provisioning
- ipv4: Update exception handling for multipath routes via same device
- tipc: use skb_unshare() instead in tipc_buf_append()
- tipc: fix shutdown() of connection oriented socket
- tipc: Fix memory leak in tipc_group_create_member()
- ipv6: avoid lockdep issue in fib6_del()
- ip: fix tos reflection in ack and reset packets
- af_key: pfkey_dump needs parameter validation
- SUNRPC: stop printk reading past end of string
- net: handle the return value of pskb_carve_frag_list() correctly
- net/mlx5e: Don't support phys switch id if not in switchdev mode
- net: disable netpoll on fresh napis
- tipc: fix shutdown() of connectionless socket
- sctp: not disable bh in the whole sctp_get_port_local()
- net: ethernet: mlx4: Fix memory allocation in mlx4_buddy_init()
- netfilter: nfnetlink: nfnetlink_unicast() reports EAGAIN instead of ENOBUFS
- netfilter: nf_tables: fix destination register zeroing
- netfilter: nf_tables: add NFTA_SET_USERDATA if not null
- scsi: fcoe: Fix I/O path allocation
- ipvlan: fix device features
- tipc: fix uninit skb->data in tipc_nl_compat_dumpit()
- net: Fix potential wrong skb->protocol in skb_vlan_untag()
- gre6: Fix reception with IP6_TNL_F_RCV_DSCP_COPY
- bonding: fix active-backup failover for current ARP slave
- bonding: fix a potential double-unregister
- bonding: show saner speed for broadcast mode
- i40e: Fix crash during removing i40e driver
- i40e: Set RX_ONLY mode for unicast promiscuous on VLAN
- svcrdma: Fix another Receive buffer leak
- net/compat: Add missing sock updates for SCM_RIGHTS
- net: initialize fastreuse on inet_inherit_port
- net: refactor bind_bucket fastreuse into helper
- net/tls: Fix kmap usage
- net: Set fput_needed iff FDPUT_FPUT is set
- af_packet: TPACKET_V3: fix fill status rwlock imbalance
- ipvs: allow connection reuse for unconfirmed conntrack
- xfrm: Fix crash when the hold queue is used.
- net sched: fix reporting the first-time use timestamp
- IB/mlx5: Replace tunnel mpls capability bits for tunnel_offloads
- fib: add missing attribute validation for tun_id
- net/mlx5: Fix mlx5_ifc_query_lag_out_bits
- mpls: fix warning with multi-label encap
- hdlc_ppp: add range checks in ppp_cp_parse_cr()
- spi/ascend: Add spi-cpld to device tree compatibility list
- net: hns3: update hns3 version to 1.9.38.8
- net: hns3: modify the sensitive words
- block: allow for_each_bvec to support zero len bvec
- HID: hid-input: clear unmapped usages
- net/nfc/rawsock.c: add CAP_NET_RAW check.
- arm64/ascend: Implement the read_persistend_clock64 for aarch64
- ext4: clear buffer verified flag if read metadata from disk
- ext4: Fix bdev write error check failed when mount fs with ro
- loop: Report EOPNOTSUPP properly

* Wed Sep 23 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2009.3.0.0045
- acpi/arm64: check the returned logical CPU number of 'acpi_map_cpuid()'
- staging: most: net: fix buffer overflow
- block: Do not discard buffers under a mounted filesystem
- block: refactor bd_start_claiming
- fs: Don't invalidate page buffers in block_write_full_page()
- ilp32: fix compile problem when ARM64_ILP32 and UBSAN are both enabled
- locking/percpu-rwsem: use this_cpu_{inc|dec}() for read_count
- scsi: libsas: Set data_dir as DMA_NONE if libata marks qc as NODATA
- Btrfs: fix selftests failure due to uninitialized i_mode in test inodes
- btrfs: inode: Verify inode mode to avoid NULL pointer dereference
- drm/ttm: fix incrementing the page pointer for huge pages
- drm/ttm: fix start page for huge page check in ttm_put_pages()
- media: uvcvideo: Avoid cyclic entity chains due to malformed USB descriptors
- fbcon: remove now unusued 'softback_lines' cursor() argument
- fbcon: remove soft scrollback code
- mm/hugetlb: fix a race between hugetlb sysctl handlers
- nfs: Fix getxattr kernel panic and memory overflow
- net/packet: fix overflow in tpacket_rcv
- net/packet: make tp_drops atomic
- ext4: fix potential negative array index in do_split()
- rbd: require global CAP_SYS_ADMIN for mapping and unmapping
- xfs: fix boundary test in xfs_attr_shortform_verify
- xfs: use the latest extent at writeback delalloc conversion time
- xfs: validate writeback mapping using data fork seq counter
- xfs: create delalloc bmapi wrapper for full extent allocation
- xfs: refactor AGI unlinked bucket updates
- xfs: add xfs_verify_agino_or_null helper
- xfs: clean up iunlink functions
- arm64/ascend: enable ascend features for Ascend910 platform
- arm64/ascend: Add auto tuning hugepage module
- arm64/ascend: Enable CONFIG_ASCEND_AUTO_TUNING_HUGEPAGE for hulk_defconfig
- arm64/ascend: Notifier will return a freed val to indecate print logs
- arm64/ascend: Add hugepage flags change interface
- arm64/ascend: Add set hugepage number helper function
- arm64/ascend: Add mmap hook when alloc hugepage
- arm64/ascend: Add new CONFIG for auto-tuning hugepage
- dm thin metadata: Fix use-after-free in dm_bm_set_read_only
- dm thin metadata: Avoid returning cmd->bm wild pointer on error
- dm cache metadata: Avoid returning cmd->bm wild pointer on error
- watchdog: Enable CONFIG_ASCEND_WATCHDOG_SYSFS_CONFIGURE in hulk_defconfig
- watchdog: Add interface to config timeout and pretimeout in sysfs
- mm/swapfile: fix and annotate various data races
- serial: 8250: fix null-ptr-deref in serial8250_start_tx()
- timekeeping: Prevent 32bit truncation in scale64_check_overflow()
- lib : kobject: fix refcount imblance on kobject_rename
- genirq/debugfs: Add missing sanity checks to interrupt injection
- ovl: fix WARN_ON nlink drop to zero
- ovl: fix some xino configurations
- ovl: fix corner case of non-constant st_dev; st_ino
- ovl: fix corner case of conflicting lower layer uuid
- ovl: generalize the lower_fs[] array
- ovl: simplify ovl_same_sb() helper
- ovl: generalize the lower_layers[] array
- ovl: fix lookup failure on multi lower squashfs
- fat: don't allow to mount if the FAT length == 0
- serial: amba-pl011: Make sure we initialize the port.lock spinlock
- perf top: Fix wrong hottest instruction highlighted
- xfs: prohibit fs freezing when using empty transactions
- xfs: Use scnprintf() for avoiding potential buffer overflow
- xfs: use bitops interface for buf log item AIL flag check
- xfs: fix some memory leaks in log recovery
- xfs: convert EIO to EFSCORRUPTED when log contents are invalid
- xfs: fix inode fork extent count overflow
- nvme: fix memory leak caused by incorrect subsystem free
- nvme: fix possible deadlock when nvme_update_formats fails
- dm verity: don't prefetch hash blocks for already-verified data
- arm64: kprobes: Recover pstate.D in single-step exception handler
- nbd: fix possible page fault for nbd disk
- nbd: rename the runtime flags as NBD_RT_ prefixed
- jbd2: flush_descriptor(): Do not decrease buffer head's ref count
- Revert "dm crypt: use WQ_HIGHPRI for the IO and crypt workqueues"
- ACPICA: Win OSL: Replace get_tick_count with get_tick_count64
- ext4: avoid fetching btime in ext4_getattr() unless requested
- mm: pagewalk: fix termination condition in walk_pte_range()
- mm/huge_memory.c: use head to check huge zero page
- mm/page-writeback.c: improve arithmetic divisions
- mm/page-writeback.c: use div64_ul() for u64-by-unsigned-long divide
- PCI: PM/ACPI: Refresh all stale power state data in pci_pm_complete()
- ACPI: PM: Fix regression in acpi_device_set_power()
- ACPI: PM: Allow transitions to D0 to occur in special cases
- ACPI: PM: Avoid evaluating _PS3 on transitions from D3hot to D3cold
- iommu/arm-smmu: Mark expected switch fall-through
- efi/memreserve: Register reservations as 'reserved' in /proc/iomem
- compat_ioctl: handle SIOCOUTQNSD
- mm: slub: fix conversion of freelist_corrupted()
- khugepaged: retract_page_tables() remember to test exit
- kprobes: Fix NULL pointer dereference at kprobe_ftrace_handler
- ftrace: Setup correct FTRACE_FL_REGS flags for module
- mm/page_counter.c: fix protection usage propagation
- driver core: Avoid binding drivers to dead devices
- genirq/affinity: Make affinity setting if activated opt-in
- mm/mmap.c: Add cond_resched() for exit_mmap() CPU stalls
- sched: correct SD_flags returned by tl->sd_flags()
- sched/fair: Fix NOHZ next idle balance
- xattr: break delegations in {set, remove}xattr
- firmware: Fix a reference count leak.
- ext4: fix direct I/O read error
- arm64: csum: Fix handling of bad packets
- arm64/alternatives: move length validation inside the subsection
- bpf: Fix map leak in HASH_OF_MAPS map
- dm integrity: fix integrity recalculation that is improperly skipped
- io-mapping: indicate mapping failure
- vt: Reject zero-sized screen buffer size.
- fuse: fix weird page warning
- printk: queue wake_up_klogd irq_work only if per-CPU areas are ready
- genirq/affinity: Handle affinity setting on inactive interrupts correctly
- sched/fair: handle case of task_h_load() returning 0
- sched: Fix unreliable rseq cpu_id for new tasks
- timer: Fix wheel index calculation on last level
- timer: Prevent base->clk from moving backward
- uio_pdrv_genirq: fix use without device tree and no interrupt
- fuse: Fix parameter for FS_IOC_{GET, SET}FLAGS
- ovl: fix unneeded call to ovl_change_flags()
- ovl: relax WARN_ON() when decoding lower directory file handle
- ovl: inode reference leak in ovl_is_inuse true case.
- arm64/alternatives: don't patch up internal branches
- arm64/alternatives: use subsections for replacement sequences
- block: release bip in a right way in error path
- cifs: update ctime and mtime during truncate
- dm zoned: assign max_io_len correctly
- virtio-blk: free vblk-vqs in error path of virtblk_probe()
- mm/slub: fix stack overruns with SLUB_STATS
- mm/slub.c: fix corrupted freechain in deactivate_slab()
- mm: fix swap cache node allocation mask
- dm writecache: add cond_resched to loop in persistent_memory_claim()
- dm writecache: correct uncommitted_block when discarding uncommitted entry
- ring-buffer: Zero out time extend if it is nested and not absolute
- mm/slab: use memzero_explicit() in kzfree()
- sched/core: Fix PI boosting between RT and DEADLINE tasks
- sched/deadline: Initialize ->dl_boosted
- efi/esrt: Fix reference count leak in esre_create_sysfs_entry.
- loop: replace kill_bdev with invalidate_bdev
- fanotify: fix ignore mask logic for events on child and on dir
- md: add feature flag MD_FEATURE_RAID0_LAYOUT
- kretprobe: Prevent triggering kretprobe from within kprobe_flush_task
- ext4: avoid race conditions when remounting with options that change dax
- ext4: fix partial cluster initialization when splitting extent
- selinux: fix double free
- arm64: hw_breakpoint: Don't invoke overflow handler on uaccess watchpoints
- lib/zlib: remove outdated and incorrect pre-increment optimization
- vfio/mdev: Fix reference count leak in add_mdev_supported_type
- PCI: dwc: Fix inner MSI IRQ domain registration
- dm zoned: return NULL if dmz_get_zone_for_reclaim() fails to find a zone
- ipmi: use vzalloc instead of kmalloc for user creation
- PCI: Fix pci_register_host_bridge() device_register() error handling
- drivers: base: Fix NULL pointer exception in __platform_driver_probe() if a driver developer is foolish
- scsi: sr: Fix sr_probe() missing deallocate of device minor
- vfio/pci: fix memory leaks in alloc_perm_bits()
- PCI: Allow pci_resize_resource() for devices on root bus
- ipmi: fix sleep-in-atomic in free_user at cleanup SRCU user->release_barrier
- Revert "ipmi: fix sleep-in-atomic in free_user at cleanup SRCU user->release_barrier"
- kernel/cpu_pm: Fix uninitted local in cpu_pm
- ext4: fix race between ext4_sync_parent() and rename()
- ext4: fix EXT_MAX_EXTENT/INDEX to check for zeroed eh_max
- mm: initialize deferred pages with interrupts enabled
- cpuidle: Fix three reference count leaks
- spi: dw: Return any value retrieved from the dma_transfer callback
- PCI: Don't disable decoding when mmio_always_on is set
- sched/core: Fix illegal RCU from offline CPUs
- audit: fix a net reference leak in audit_list_rules_send()
- audit: fix a net reference leak in audit_send_reply()
- spi: dw: Fix Rx-only DMA transfers
- spi: dw: Enable interrupts in accordance with DMA xfer mode
- arm64: insn: Fix two bugs in encoding 32-bit logical immediates
- spi: dw: Zero DMA Tx and Rx configurations on stack
- perf: Add cond_resched() to task_function_call()
- mm/slub: fix a memory leak in sysfs_slab_add()
- proc: Use new_inode not new_inode_pseudo
- ovl: initialize error in ovl_copy_xattr
- spi: Fix controller unregister order
- spi: No need to assign dummy value in spi_unregister_controller()
- spi: dw: Fix controller unregister order
- ACPI: CPPC: Fix reference count leak in acpi_cppc_processor_probe()
- ACPI: sysfs: Fix reference count leak in acpi_sysfs_add_hotplug_profile()
- efi/efivars: Add missing kobject_put() in sysfs entry creation error path
- aio: fix async fsync creds
- mm: add kvfree_sensitive() for freeing sensitive data objects
- sched/fair: Don't NUMA balance for kthreads
- lib: Reduce user_access_begin() boundaries in strncpy_from_user() and strnlen_user()
- tun: correct header offsets in napi frags mode
- spi: dw: use "smp_mb()" to avoid sending spi data error
- Revert "cgroup: Add memory barriers to plug cgroup_rstat_updated() race window"
- iommu: Fix reference count leak in iommu_group_alloc.
- mm: remove VM_BUG_ON(PageSlab()) from page_mapcount()
- exec: Always set cap_ambient in cap_bprm_set_creds
- padata: purge get_cpu and reorder_via_wq from padata_do_serial
- padata: initialize pd->cpu with effective cpumask
- padata: Replace delayed timer with immediate workqueue in padata_reorder
- fix multiplication overflow in copy_fdtable()
- exec: Move would_dump into flush_old_exec
- cifs: fix leaked reference on requeued write
- arm64: fix the flush_icache_range arguments in machine_kexec
- NFSv4: Fix fscache cookie aux_data to ensure change_attr is included
- nfs: fscache: use timespec64 in inode auxdata
- NFS: Fix fscache super_cookie index_key from changing after umount
- ipc/util.c: sysvipc_find_ipc() incorrectly updates position index
- net: phy: fix aneg restart in phy_ethtool_set_eee
- virtio-blk: handle block_device_operations callbacks after hot unplug
- shmem: fix possible deadlocks on shmlock_user_lock
- ipc/mqueue.c: change __do_notify() to bypass check_kill_permission()
- coredump: fix crash when umh is disabled
- mm/page_alloc: fix watchdog soft lockups during set_zone_contiguous()
- arm64: hugetlb: avoid potential NULL dereference
- cifs: protect updating server->dstaddr with a spinlock
- vfio: avoid possible overflow in vfio_iommu_type1_pin_pages
- propagate_one(): mnt_set_mountpoint() needs mount_lock
- ext4: check for non-zero journal inum in ext4_calculate_overhead
- ext4: convert BUG_ON's to WARN_ON's in mballoc.c
- ext4: increase wait time needed before reuse of deleted inode numbers
- ext4: use matching invalidatepage in ext4_writepage
- mm: shmem: disable interrupt when acquiring info->lock in userfaultfd_copy path
- perf/core: fix parent pid/tid in task exit events
- vt: don't hardcode the mem allocation upper bound
- audit: check the length of userspace generated audit records
- tpm/tpm_tis: Free IRQ if probing fails
- mm/ksm: fix NULL pointer dereference when KSM zero page is enabled
- mm/hugetlb: fix a addressing exception caused by huge_pte_offset
- vmalloc: fix remap_vmalloc_range() bounds checks
- KEYS: Avoid false positive ENOMEM error on key read
- loop: Better discard support for block devices
- ipc/util.c: sysvipc_find_ipc() should increase position index
- scsi: iscsi: Report unbind session event when the target has been removed
- watchdog: reset last_hw_keepalive time at start
- ext4: fix extent_status fragmentation for plain files
- bpf: fix buggy r0 retval refinement for tracing helpers
- NFS: Fix memory leaks in nfs_pageio_stop_mirroring()
- percpu_counter: fix a data race at vm_committed_as
- cifs: Allocate encryption header through kmalloc
- ext4: do not commit super on read-only bdev
- NFS: direct.c: Fix memory leak of dreq when nfs_get_lock_context fails
- irqchip/mbigen: Free msi_desc on device teardown
- ext4: use non-movable memory for superblock readahead
- mm/vmalloc.c: move 'area->pages' after if statement
- ext4: do not zeroout extents beyond i_disksize
- tracing: Fix the race between registering 'snapshot' event trigger and triggering 'snapshot' operation
- keys: Fix proc_keys_next to increase position index
- ext4: fix incorrect inodes per group in error message
- ext4: fix incorrect group count in ext4_fill_super error message
- ovl: fix value of i_ino for lower hardlink corner case
- dm zoned: remove duplicate nr_rnd_zones increase in dmz_init_zone()
- ipmi: fix hung processes in __get_guid()
- libata: Return correct status in sata_pmp_eh_recover_pm() when ATA_DFLAG_DETACH is set
- kmod: make request_module() return an error when autoloading is disabled
- NFS: Fix a page leak in nfs_destroy_unlinked_subrequests()
- dm verity fec: fix memory leak in verity_fec_dtr
- dm writecache: add cond_resched to avoid CPU hangs
- mm: Use fixed constant in page_frag_alloc instead of size + 1
- tpm: tpm2_bios_measurements_next should increase position index
- tpm: tpm1_bios_measurements_next should increase position index
- tpm: Don't make log failures fatal
- PCI/ASPM: Clear the correct bits when enabling L1 substates
- md: check arrays is suspended in mddev_detach before call quiesce operations
- irqchip/gic-v4: Provide irq_retrigger to avoid circular locking dependency
- block: Fix use-after-free issue accessing struct io_cq
- genirq/irqdomain: Check pointer in irq_domain_alloc_irqs_hierarchy()
- libata: Remove extra scsi_host_put() in ata_scsi_add_hosts()
- sched: Avoid scale real weight down to zero
- block: keep bdi->io_pages in sync with max_sectors_kb for stacked devices
- firmware: arm_sdei: fix double-lock on hibernate with shared events
- arm64: Fix size of __early_cpu_boot_status
- random: always use batched entropy for get_random_u{32, 64}
- padata: always acquire cpu_hotplug_lock before pinst->lock
- bpf: Explicitly memset some bpf info structures declared on the stack
- bpf: Explicitly memset the bpf_attr structure
- libfs: fix infoleak in simple_attr_read()
- bpf/btf: Fix BTF verification of enum members in struct/union
- genirq: Fix reference leaks on irq affinity notifiers
- scsi: sd: Fix optimal I/O size for devices that change reported values
- scsi: ipr: Fix softlockup when rescanning devices in petitboot
- nfs: add minor version to nfs_server_key for fscache
- arm64: smp: fix crash_smp_send_stop() behaviour
- arm64: smp: fix smp_send_stop() behaviour
- mm, slub: prevent kmalloc_node crashes and memory leaks
- mm: slub: be more careful about the double cmpxchg of freelist
- block, bfq: fix overwrite of bfq_group pointer in bfq_find_set_group()
- mm: slub: add missing TID bump in kmem_cache_alloc_bulk()
- driver core: Fix creation of device links with PM-runtime flags
- driver core: Remove device link creation limitation
- driver core: Add device link flag DL_FLAG_AUTOPROBE_CONSUMER
- driver core: Make driver core own stateful device links
- driver core: Fix adding device links to probing suppliers
- driver core: Remove the link if there is no driver with AUTO flag
- jbd2: fix data races at struct journal_head
- signal: avoid double atomic counter increments for user accounting
- cifs_atomic_open(): fix double-put on late allocation failure
- workqueue: don't use wq_select_unbound_cpu() for bound works
- virtio-blk: fix hw_queue stopped on arbitrary error
- dm writecache: verify watermark during resume
- dm: report suspended device during destroy
- dm cache: fix a crash due to incorrect work item cancelling
- mm: fix possible PMD dirty bit lost in set_pmd_migration_entry()
- mm, numa: fix bad pmd by atomically check for pmd_trans_huge when marking page tables prot_numa
- cifs: don't leak -EAGAIN for stat() during reconnect
- audit: always check the netlink payload length in audit_receive_msg()
- audit: fix error handling in audit_data_to_entry()
- ext4: potential crash on allocation error in ext4_alloc_flex_bg_array()
- cifs: Fix mode output in debugging statements
- ipmi:ssif: Handle a possible NULL pointer reference
- irqchip/gic-v3-its: Fix misuse of GENMASK macro
- ata: ahci: Add shutdown to freeze hardware resources of ahci
- bpf, offload: Replace bitwise AND by logical AND in bpf_prog_offload_info_fill
- genirq/proc: Reject invalid affinity masks (again)
- ext4: fix race between writepages and enabling EXT4_EXTENTS_FL
- ext4: rename s_journal_flag_rwsem to s_writepages_rwsem
- ext4: fix mount failure with quota configured as module
- ext4: fix potential race between s_flex_groups online resizing and access
- ext4: fix potential race between s_group_info online resizing and access
- ext4: fix potential race between online resizing and write operations
- ext4: fix a data race in EXT4_I(inode)->i_disksize
- genirq/irqdomain: Make sure all irq domain flags are distinct
- Revert "ipc, sem: remove uneeded sem_undo_list lock usage in exit_sem()"
- jbd2: fix ocfs2 corrupt when clearing block group bits
- vt: vt_ioctl: fix race in VT_RESIZEX
- vt: fix scrollback flushing on background consoles
- NFS: Fix memory leaks
- brd: check and limit max_part par
- irqchip/gic-v3-its: Reference to its_invall_cmd descriptor when building INVALL
- irqchip/gic-v3: Only provision redistributors that are enabled in ACPI
- bpf: map_seq_next should always increase position index
- cifs: fix NULL dereference in match_prepath
- driver core: platform: fix u32 greater or equal to zero comparison
- irqchip/mbigen: Set driver .suppress_bind_attrs to avoid remove problems
- module: avoid setting info->name early in case we can fall back to info->mod->name
- watchdog/softlockup: Enforce that timestamp is valid on boot
- arm64: fix alternatives with LLVM's integrated assembler
- scsi: iscsi: Don't destroy session if there are outstanding connections
- iommu/arm-smmu-v3: Use WRITE_ONCE() when changing validity of an STE
- driver core: platform: Prevent resouce overflow from causing infinite loops
- selinux: ensure we cleanup the internal AVC counters on error in avc_update()
- selinux: ensure we cleanup the internal AVC counters on error in avc_insert()
- jbd2: clear JBD2_ABORT flag before journal_reset to update log tail info when load journal
- uio: fix a sleep-in-atomic-context bug in uio_dmem_genirq_irqcontrol()
- ext4: fix ext4_dax_read/write inode locking sequence for IOCB_NOWAIT
- cpu/hotplug, stop_machine: Fix stop_machine vs hotplug order
- nvme: fix the parameter order for nvme_get_log in nvme_get_fw_slot_info
- arm64: ssbs: Fix context-switch when SSBS is present on all CPUs
- ext4: improve explanation of a mount failure caused by a misconfigured kernel
- ext4: fix checksum errors with indexed dirs
- ext4: don't assume that mmp_nodename/bdevname have NUL
- arm64: nofpsmid: Handle TIF_FOREIGN_FPSTATE flag cleanly
- arm64: cpufeature: Set the FP/SIMD compat HWCAP bits properly
- padata: fix null pointer deref of pd->pinst
- arm64: ptrace: nofpsimd: Fail FP/SIMD regset operations
- arm64: cpufeature: Fix the type of no FP/SIMD capability
- NFSv4: try lease recovery on NFS4ERR_EXPIRED
- NFS: Revalidate the file size on a fatal write error
- nfs: NFS_SWAP should depend on SWAP
- PCI: Don't disable bridge BARs when assigning bus resources
- perf/core: Fix mlock accounting in perf_mmap()
- clocksource: Prevent double add_timer_on() for watchdog_timer
- x86/apic/msi: Plug non-maskable MSI affinity race
- mm/page_alloc.c: fix uninitialized memmaps on a partially populated last section
- mm: return zero_resv_unavail optimization
- mm: zero remaining unavailable struct pages
- ext4: fix deadlock allocating crypto bounce page from mempool
- aio: prevent potential eventfd recursion on poll
- eventfd: track eventfd_signal() recursion depth
- watchdog: fix UAF in reboot notifier handling in watchdog core code
- jbd2_seq_info_next should increase position index
- NFS: Directory page cache pages need to be locked when read
- NFS: Fix memory leaks and corruption in readdir
- padata: Remove broken queue flushing
- dm writecache: fix incorrect flush sequence when doing SSD mode commit
- dm: fix potential for q->make_request_fn NULL pointer
- dm crypt: fix benbi IV constructor crash if used in authenticated mode
- dm space map common: fix to ensure new block isn't already in use
- dm zoned: support zone sizes smaller than 128MiB
- ovl: fix wrong WARN_ON() in ovl_cache_update_ino()
- alarmtimer: Unregister wakeup source when module get fails
- irqdomain: Fix a memory leak in irq_domain_push_irq()
- rcu: Avoid data-race in rcu_gp_fqs_check_wake()
- ipc/msg.c: consolidate all xxxctl_down() functions
- kernel/module: Fix memleak in module_add_modinfo_attrs()
- mm/migrate.c: also overwrite error when it is bigger than zero
- mm/memory_hotplug: shrink zones when offlining memory
- mm/memory_hotplug: fix try_offline_node()
- mm/memunmap: don't access uninitialized memmap in memunmap_pages()
- drivers/base/node.c: simplify unregister_memory_block_under_nodes()
- mm/hotplug: kill is_dev_zone() usage in __remove_pages()
- mm/memory_hotplug: remove "zone" parameter from sparse_remove_one_section
- mm/memory_hotplug: make unregister_memory_block_under_nodes() never fail
- mm/memory_hotplug: remove memory block devices before arch_remove_memory()
- mm/memory_hotplug: create memory block devices after arch_add_memory()
- drivers/base/memory: pass a block_id to init_memory_block()
- mm/memory_hotplug: allow arch_remove_memory() without CONFIG_MEMORY_HOTREMOVE
- s390x/mm: implement arch_remove_memory()
- mm/memory_hotplug: make __remove_pages() and arch_remove_memory() never fail
- powerpc/mm: Fix section mismatch warning
- mm/memory_hotplug: make __remove_section() never fail
- mm/memory_hotplug: make unregister_memory_section() never fail
- mm, memory_hotplug: update a comment in unregister_memory()
- drivers/base/memory.c: clean up relics in function parameters
- mm/memory_hotplug: release memory resource after arch_remove_memory()
- mm, memory_hotplug: add nid parameter to arch_remove_memory
- drivers/base/memory.c: remove an unnecessary check on NR_MEM_SECTIONS
- mm, sparse: pass nid instead of pgdat to sparse_add_one_section()
- mm, sparse: drop pgdat_resize_lock in sparse_add/remove_one_section()
- arm64/mm: add temporary arch_remove_memory() implementation
- s390x/mm: fail when an altmap is used for arch_add_memory()
- mm/memory_hotplug: simplify and fix check_hotplug_memory_range()
- scsi: iscsi: Avoid potential deadlock in iscsi_if_rx func
- sd: Fix REQ_OP_ZONE_REPORT completion handling
- tun: add mutex_unlock() call and napi.skb clearing in tun_get_user()
- bpf: fix BTF limits
- scsi: libfc: fix null pointer dereference on a null lport
- iommu: Use right function to get group for device
- NFSv4/flexfiles: Fix invalid deref in FF_LAYOUT_DEVID_NODE()
- NFS: Add missing encode / decode sequence_maxsz to v4.2 operations
- driver core: Fix PM-runtime for links added during consumer probe
- driver core: Fix possible supplier PM-usage counter imbalance
- net: phy: fixed_phy: Fix fixed_phy not checking GPIO
- driver core: Do not call rpm_put_suppliers() in pm_runtime_drop_link()
- driver core: Fix handling of runtime PM flags in device_link_add()
- driver core: Do not resume suppliers under device_links_write_lock()
- driver core: Avoid careless re-use of existing device links
- driver core: Fix DL_FLAG_AUTOREMOVE_SUPPLIER device link flag handling
- Revert "efi: Fix debugobjects warning on 'efi_rts_work'"
- scsi: core: scsi_trace: Use get_unaligned_be*()
- scsi: sd: enable compat ioctls for sed-opal
- NFSv4.x: Drop the slot if nfs4_delegreturn_prepare waits for layoutreturn
- NFSv2: Fix a typo in encode_sattr()
- scsi: sd: Clear sdkp->protection_type if disk is reformatted without PI
- scsi: enclosure: Fix stale device oops with hot replug
- xprtrdma: Fix completion wait during device removal
- xprtrdma: Fix use-after-free in rpcrdma_post_recvs
- tcp: cache line align MAX_TCP_HEADER
- svcrdma: Fix trace point use-after-free race
- net: stricter validation of untrusted gso packets
- net: bridge: enfore alignment for ethernet address
- net: use correct this_cpu primitive in dev_recursion_level
- net: core: reduce recursion limit value
- ipv4: fill fl4_icmp_{type, code} in ping_v4_sendmsg
- net: Added pointer check for dst->ops->neigh_lookup in dst_neigh_lookup_skb
- vlan: consolidate VLAN parsing code and limit max parsing depth
- svcrdma: Fix page leak in svc_rdma_recv_read_chunk()
- i40e: Memory leak in i40e_config_iwarp_qvlist
- i40e: Fix of memory leak and integer truncation in i40e_virtchnl.c
- i40e: Wrong truncation from u16 to u8
- i40e: add num_vectors checker in iwarp handler
- Revert "vxlan: fix tos value before xmit"
- openvswitch: Prevent kernel-infoleak in ovs_ct_put_key()
- net: gre: recompute gre csum for sctp over gre tunnels
- vxlan: Ensure FDB dump is performed under RCU
- ipv6: fix memory leaks on IPV6_ADDRFORM path
- ipv4: Silence suspicious RCU usage warning
- igb: reinit_locked() should be called with rtnl_lock
- net/mlx5e: fix bpf_prog reference count leaks in mlx5e_alloc_rq
- mlxsw: core: Free EMAD transactions using kfree_rcu()
- mlxsw: core: Increase scope of RCU read-side critical section
- mlx4: disable device on shutdown
- net/mlx5: Verify Hardware supports requested ptp function on a given pin
- rds: Prevent kernel-infoleak in rds_notify_queue_get()
- rtnetlink: Fix memory(net_device) leak when ->newlink fails
- udp: Improve load balancing for SO_REUSEPORT.
- udp: Copy has_conns in reuseport_grow().
- sctp: shrink stream outq when fails to do addstream reconf
- sctp: shrink stream outq only when new outcnt < old outcnt
- tcp: allow at most one TLP probe per flight
- net: udp: Fix wrong clean up for IS_UDPLITE macro
- net-sysfs: add a newline when printing 'tx_timeout' by sysfs
- ip6_gre: fix null-ptr-deref in ip6gre_init_net()
- dev: Defer free of skbs in flush_backlog
- bonding: check return value of register_netdevice() in bond_newlink()
- ipvs: fix the connection sync failed in some cases
- mlxsw: destroy workqueue when trap_register in mlxsw_emad_init
- bonding: check error value of register_netdevice() immediately
- tipc: clean up skb list lock handling on send path
- libceph: don't omit recovery_deletes in target_copy()
- sched: consistently handle layer3 header accesses in the presence of VLANs
- tcp: md5: allow changing MD5 keys in all socket states
- tcp: md5: refine tcp_md5_do_add()/tcp_md5_hash_key() barriers
- tcp: md5: do not send silly options in SYNCOOKIES
- tcp: md5: add missing memory barriers in tcp_md5_do_add()/tcp_md5_hash_key()
- tcp: make sure listeners don't initialize congestion-control state
- tcp: fix SO_RCVLOWAT possible hangs under high mem pressure
- net_sched: fix a memory leak in atm_tc_init()
- llc: make sure applications use ARPHRD_ETHER
- l2tp: remove skb_dst_set() from l2tp_xmit_skb()
- mlxsw: spectrum_router: Remove inappropriate usage of WARN_ON()
- i40e: protect ring accesses with READ- and WRITE_ONCE
- ixgbe: protect ring accesses with READ- and WRITE_ONCE
- SUNRPC: Properly set the @subbuf parameter of xdr_buf_subsegment()
- sunrpc: fixed rollback in rpc_gssd_dummy_populate()
- netfilter: ipset: fix unaligned atomic access
- xfrm: Fix double ESP trailer insertion in IPsec crypto offload.
- net: Do not clear the sock TX queue in sk_set_socket()
- net: Fix the arp error in some cases
- sch_cake: don't call diffserv parsing code when it is not needed
- tcp_cubic: fix spurious HYSTART_DELAY exit upon drop in min RTT
- sch_cake: fix a few style nits
- sch_cake: don't try to reallocate or unshare skb unconditionally
- ip_tunnel: fix use-after-free in ip_tunnel_lookup()
- ip6_gre: fix use-after-free in ip6gre_tunnel_lookup()
- tcp: grow window for OOO packets only for SACK flows
- tcp: don't ignore ECN CWR on pure ACK
- sctp: Don't advertise IPv4 addresses if ipv6only is set on the socket
- net: increment xmit_recursion level in dev_direct_xmit()
- net: place xmit recursion in softnet data
- net: fix memleak in register_netdevice()
- mld: fix memory leak in ipv6_mc_destroy_dev()
- net: sched: export __netdev_watchdog_up()
- net: core: device_rename: Use rwsem instead of a seqcount
- sched/rt, net: Use CONFIG_PREEMPTION.patch
- e1000e: Do not wake up the system via WOL if device wakeup is disabled
- xdp: Fix xsk_generic_xmit errno
- net/filter: Permit reading NET in load_bytes_relative when MAC not set
- net: sunrpc: Fix off-by-one issues in 'rpc_ntop6'
- igb: Report speed and duplex as unknown when device is runtime suspended
- e1000e: Relax condition to trigger reset for ME workaround
- e1000e: Disable TSO for buffer overrun workaround
- ixgbe: fix signed-integer-overflow warning
- macvlan: Skip loopback packets in RX handler
- net/mlx5e: IPoIB, Drop multicast packets that this interface sent
- netfilter: nft_nat: return EOPNOTSUPP if type or flags are not supported
- e1000: Distribute switch variables for initialization
- ixgbe: Fix XDP redirect on archs with PAGE_SIZE above 4K
- vxlan: Avoid infinite loop when suppressing NS messages with invalid options
- bridge: Avoid infinite loop when suppressing NS messages with invalid options
- ipv6: fix IPV6_ADDRFORM operation logic
- l2tp: do not use inet_hash()/inet_unhash()
- l2tp: add sk_family checks to l2tp_validate_socket
- devinet: fix memleak in inetdev_init()
- netfilter: nf_conntrack_pptp: fix compilation warning with W=1 build
- bonding: Fix reference count leak in bond_sysfs_slave_add.
- xsk: Add overflow check for u64 division, stored into u32
- esp6: get the right proto for transport mode in esp6_gso_encap
- netfilter: nf_conntrack_pptp: prevent buffer overflows in debug code
- netfilter: nfnetlink_cthelper: unbreak userspace helper support
- netfilter: ipset: Fix subcounter update skip
- netfilter: nft_reject_bridge: enable reject with bridge vlan
- ip_vti: receive ipip packet by calling ip_tunnel_rcv
- vti4: eliminated some duplicate code.
- xfrm: fix a NULL-ptr deref in xfrm_local_error
- xfrm: fix a warning in xfrm_policy_insert_list
- xfrm interface: fix oops when deleting a x-netns interface
- xfrm: call xfrm_output_gso when inner_protocol is set in xfrm_output
- xfrm: allow to accept packets with ipv6 NEXTHDR_HOP in xfrm_input
- libceph: ignore pool overlay and cache logic on redirects
- mlxsw: spectrum: Fix use-after-free of split/unsplit/type_set in case reload fails
- net/mlx4_core: fix a memory leak bug.
- net/mlx5e: Update netdev txq on completions during closure
- sctp: Start shutdown on association restart if in SHUTDOWN-SENT state and socket is closed
- sctp: Don't add the shutdown timer if its already been added
- net/mlx5: Add command entry handling completion
- net: ipip: fix wrong address family in init error path
- net: inet_csk: Fix so_reuseport bind-address cache in tb->fast*
- __netif_receive_skb_core: pass skb by reference
- netfilter: nft_set_rbtree: Introduce and use nft_rbtree_interval_start()
- tcp: fix SO_RCVLOWAT hangs with fat skbs
- net: tcp: fix rx timestamp behavior for tcp_recvmsg
- net: ipv4: really enforce backoff for redirects
- tcp: fix error recovery in tcp_zerocopy_receive()
- Revert "ipv6: add mtu lock check in __ip6_rt_update_pmtu"
- net: fix a potential recursive NETDEV_FEAT_CHANGE
- drop_monitor: work around gcc-10 stringop-overflow warning
- netfilter: nf_osf: avoid passing pointer to local var
- netfilter: nat: never update the UDP checksum when it's 0
- sctp: Fix bundling of SHUTDOWN with COOKIE-ACK
- net/mlx5: Fix command entry leak in Internal Error State
- net/mlx5: Fix forced completion access non initialized command entry
- tipc: fix partial topology connection closure
- sch_sfq: validate silly quantum values
- sch_choke: avoid potential panic in choke_reset()
- net_sched: sch_skbprio: add message validation to skbprio_change()
- net/mlx4_core: Fix use of ENOSPC around mlx4_counter_alloc()
- fq_codel: fix TCA_FQ_CODEL_DROP_BATCH_SIZE sanity checks
- cgroup, netclassid: remove double cond_resched
- sctp: Fix SHUTDOWN CTSN Ack in the peer restart case
- net/mlx5: Fix failing fw tracer allocation on s390
- svcrdma: Fix leak of svc_rdma_recv_ctxt objects
- mlxsw: Fix some IS_ERR() vs NULL bugs
- vrf: Check skb for XFRM_TRANSFORMED flag
- xfrm: Always set XFRM_TRANSFORMED in xfrm{4, 6}_output_finish
- vrf: Fix IPv6 with qdisc and xfrm
- sched: etf: do not assume all sockets are full blown
- macvlan: fix null dereference in macvlan_device_event()
- ipv6: fix restrict IPV6_ADDRFORM operation
- ipv6: restrict IPV6_ADDRFORM operation
- arm64/ascend: Set mem_sleep_current to PM_SUSPEND_ON for ascend platform
- mm/swap_state: fix a data race in swapin_nr_pages
- arm64: secomp: fix the secure computing mode 1 syscall check for ilp32
- vti4: removed duplicate log message.
- KEYS: Don't write out to userspace while holding key semaphore
- netfilter: nf_tables: report EOPNOTSUPP on unsupported flags/object type
- net: revert default NAPI poll timeout to 2 jiffies
- net: ipv6: do not consider routes via gateways for anycast address check
- net: ipv4: devinet: Fix crash when add/del multicast IP with autojoin
- mlxsw: spectrum_flower: Do not stop at FLOW_ACTION_VLAN_MANGLE
- ipv6: don't auto-add link-local address to lag ports
- net: Fix Tx hash bound checking
- sctp: fix possibly using a bad saddr with a given dst
- sctp: fix refcount bug in sctp_wfree
- net, ip_tunnel: fix interface lookup with no key
- ipv4: fix a RCU-list lock in fib_triestat_seq_show
- vti6: Fix memory leak of skb if input policy check fails
- netfilter: nft_fwd_netdev: validate family and chain type
- netfilter: flowtable: reload ip{v6}h in nf_flow_tuple_ip{v6}
- xfrm: policy: Fix doulbe free in xfrm_policy_timer
- xfrm: add the missing verify_sec_ctx_len check in xfrm_add_acquire
- xfrm: fix uctx len check in verify_sec_ctx_len
- vti[6]: fix packet tx through bpf_redirect() in XinY cases
- xfrm: handle NETDEV_UNREGISTER for xfrm device
- ceph: check POOL_FLAG_FULL/NEARFULL in addition to OSDMAP_FULL/NEARFULL
- vxlan: check return value of gro_cells_init()
- tcp: repair: fix TCP_QUEUE_SEQ implementation
- net: ip_gre: Accept IFLA_INFO_DATA-less configuration
- net: ip_gre: Separate ERSPAN newlink / changelink callbacks
- net_sched: keep alloc_hash updated after hash allocation
- net_sched: cls_route: remove the right filter from hashtable
- net/packet: tpacket_rcv: avoid a producer race condition
- net: cbs: Fix software cbs to consider packet sending time
- mlxsw: spectrum_mr: Fix list iteration in error path
- Revert "ipv6: Fix handling of LLA with VRF and sockets bound to VRF"
- Revert "vrf: mark skb for multicast or link-local as enslaved to VRF"
- ipv4: ensure rcu_read_lock() in cipso_v4_error()
- netfilter: nft_tunnel: add missing attribute validation for tunnels
- netfilter: nft_payload: add missing attribute validation for payload csum flags
- netfilter: cthelper: add missing attribute validation for cthelper
- netfilter: x_tables: xt_mttg_seq_next should increase position index
- netfilter: xt_recent: recent_seq_next should increase position index
- netfilter: synproxy: synproxy_cpu_seq_next should increase position index
- netfilter: nf_conntrack: ct_cpu_seq_next should increase position index
- macvlan: add cond_resched() during multicast processing
- bonding/alb: make sure arp header is pulled before accessing it
- devlink: validate length of region addr/len
- tipc: add missing attribute validation for MTU property
- net/ipv6: remove the old peer route if change it to a new one
- net/ipv6: need update peer route when modify metric
- net: fq: add missing attribute validation for orphan mask
- devlink: validate length of param values
- net/packet: tpacket_rcv: do not increment ring index on drop
- netlink: Use netlink header as base to calculate bad attribute offset
- net/ipv6: use configured metric when add peer route
- ipvlan: don't deref eth hdr before checking it's set
- ipvlan: do not use cond_resched_rcu() in ipvlan_process_multicast()
- ipvlan: do not add hardware address of master to its unicast filter list
- ipvlan: add cond_resched_rcu() while processing muticast backlog
- ipv6/addrconf: call ipv6_mc_up() for non-Ethernet interface
- inet_diag: return classid for all socket types
- gre: fix uninit-value in __iptunnel_pull_header
- cgroup, netclassid: periodically release file_lock on classid updating
- netfilter: nf_flowtable: fix documentation
- netfilter: nft_tunnel: no need to call htons() when dumping ports
- net: netlink: cap max groups which will be considered in netlink_bind()
- net/tls: Fix to avoid gettig invalid tls record
- ipv6: Fix nlmsg_flags when splitting a multipath route
- ipv6: Fix route replacement with dev-only route
- sctp: move the format error check out of __sctp_sf_do_9_1_abort
- net: sched: correct flower port blocking
- net: fib_rules: Correctly set table field when table number exceeds 8 bits
- netfilter: xt_hashlimit: limit the max size of hashtable
- mlxsw: spectrum_dpipe: Add missing error path
- bpf: Return -EBADRQC for invalid map type in __bpf_tx_xdp_map
- mlx5: work around high stack usage with gcc
- netfilter: nft_tunnel: add the missing ERSPAN_VERSION nla_policy
- net/sched: flower: add missing validation of TCA_FLOWER_FLAGS
- net/sched: matchall: add missing validation of TCA_MATCHALL_FLAGS
- core: Don't skip generic XDP program execution for cloned SKBs
- net/mlx5: IPsec, fix memory leak at mlx5_fpga_ipsec_delete_sa_ctx
- net/mlx5: IPsec, Fix esp modify function attribute
- net_sched: fix a resource leak in tcindex_set_parms()
- bonding/alb: properly access headers in bond_alb_xmit()
- sunrpc: expiry_time should be seconds not timeval
- tcp: clear tp->segs_{in|out} in tcp_disconnect()
- tcp: clear tp->data_segs{in|out} in tcp_disconnect()
- tcp: clear tp->delivered in tcp_disconnect()
- tcp: clear tp->total_retrans in tcp_disconnect()
- net_sched: fix an OOB access in cls_tcindex
- l2tp: Allow duplicate session creation with UDP
- cls_rsvp: fix rsvp_policy
- net: Fix skb->csum update in inet_proto_csum_replace16().
- xfrm: interface: do not confirm neighbor when do pmtu update
- xfrm interface: fix packet tx through bpf_redirect()
- vti[6]: fix packet tx through bpf_redirect()
- netfilter: nft_tunnel: ERSPAN_VERSION must not be null
- igb: Fix SGMII SFP module discovery for 100FX/LX.
- ixgbe: Fix calculation of queue with VFs and flow director on interface flap
- ixgbevf: Remove limit of 10 entries for unicast filter list
- net_sched: ematch: reject invalid TCF_EM_SIMPLE
- netfilter: nf_tables: add __nft_chain_type_get()
- netfilter: ipset: use bitmap infrastructure completely
- netfilter: nft_osf: add missing check for DREG attribute
- tcp: do not leave dangling pointers in tp->highest_sack
- tcp_bbr: improve arithmetic division in bbr_update_bw()
- Revert "udp: do rmem bulk free even if the rx sk queue is empty"
- net-sysfs: Fix reference count leak
- net_sched: fix datalen for ematch
- net: rtnetlink: validate IFLA_MTU attribute in rtnl_create_link()
- net, ip_tunnel: fix namespaces move
- net, ip6_tunnel: fix namespaces move
- net: ip6_gre: fix moving ip6gre between namespaces
- ipv6: sr: remove SKB_GSO_IPXIP6 on End.D* actions
- packet: fix data-race in fanout_flow_is_huge()
- net: neigh: use long type to store jiffies delta
- xsk: Fix registration of Rx-only sockets
- net: netem: correct the parent's backlog when corrupted packet was dropped
- net: netem: fix error path for corrupted GSO frames
- act_mirred: Fix mirred_init_module error handling
- ip6erspan: remove the incorrect mtu limit for ip6erspan
- llc: fix sk_buff refcounting in llc_conn_state_process()
- llc: fix another potential sk_buff leak in llc_ui_sendmsg()
- net: sched: cbs: Avoid division by zero when calculating the port rate
- net/rds: Fix 'ib_evt_handler_call' element in 'rds_ib_stat_names'
- xsk: avoid store-tearing when assigning umem
- xsk: avoid store-tearing when assigning queues
- net/sched: cbs: Set default link speed to 10 Mbps in cbs_set_port_rate
- i40e: reduce stack usage in i40e_set_fc
- net/rds: Add a few missing rds_stat_names entries
- net: fix bpf_xdp_adjust_head regression for generic-XDP
- tipc: reduce risk of wakeup queue starvation
- xfrm interface: ifname may be wrong in logs
- xdp: fix possible cq entry leak
- net/tls: fix socket wmem accounting on fallback with netem
- net: netem: fix backlog accounting for corrupted GSO frames
- bpf: fix the check that forwarding is enabled in bpf_ipv6_fib_lookup
- net: core: support XDP generic on stacked devices.
- signal/bpfilter: Fix bpfilter_kernl to use send_sig not force_sig
- net/mlx5: Delete unused FPGA QPN variable
- mlxsw: spectrum: Set minimum shaper on MC TCs
- mlxsw: reg: QEEC: Add minimum shaper fields
- tipc: fix wrong timeout input for tipc_wait_for_cond()
- tipc: update mon's self addr when node addr generated
- mlxsw: spectrum_qdisc: Include MC TCs in Qdisc counters
- mlxsw: spectrum: Wipe xstats.backlog of down ports
- tcp: fix marked lost packets not being retransmitted
- af_unix: add compat_ioctl support
- ethtool: reduce stack usage with clang
- fs: fix kabi broken introduced by fixing CVE-2020-14381
- futex: Unbreak futex hashing
- futex: Fix inode life-time issue
- block/bio-integrity: don't free 'buf' if bio_integrity_add_page() failed
- arm64/ascend: set the correct dvpp mmap area when no MAP_DVPP flags
- ext4: fix error pointer dereference
- ext4: Avoid freeing inodes on dirty list
- writeback: Export inode_io_list_del()
- blktrace: ensure our debugfs dir exists
- blktrace: fix debugfs use after free
- loop: be paranoid on exit and prevent new additions / removals
- Revert "block: rename 'q->debugfs_dir' and 'q->blk_trace->dir' in blk_unregister_queue()"
- ext4: force buffer up-to-date while marking it dirty
- ext4: fix a data race at inode->i_disksize
- ext4: fix a data race at inode->i_blocks
- jbd2: abort journal if free a async write error metadata buffer
- ext4: abort the filesystem if failed to async write metadata buffer
- net: hns3: update hns3 version to 1.9.38.7
- net: hns3: initialize the message content sent to the VF
- net: hns3: check vlan id before using it
- net: hns3: check RSS key index before using
- net: hns3: check cmdq message parameters sent from VF
- config: add certs dir to CONFIG_MODULE_SIG_KEY
- net/hinic: Fix Oops when probing hinic driver

* Mon Sep 14 2020 xinghe <xinghe1@huawei.com> - 4.19.90-2008.6.0.0044
- add perf-tip file fix cannot load perf-tips warning

* Mon Aug 31 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2008.6.0.0043
- arm64/config: enable TIPC module for openEuler
- net: hns3: update hns3 version to 1.9.38.6
- net: hns3: add support for dumping MAC umv counter in debugfs
- net: hns3: fix bug when PF set the duplicate MAC address for VFs
- net/hinic: Check the legality of out_size in nictool
- net/hinic: Fix out-of-bounds access when setting ets
- net/hinic: Rename camelCase used in nictool
- net/hinic: Fix alignment and code style
- net/hinic: Delete unused heartbeat enhancement feature
- net/hinic: Delete the unused chip fault handling process
- net/hinic: Delete unused microcode back pressure feature
- net/hinic: Fix misspelled word and wrong print format
- net/hinic: update hinic version to 2.3.2.15
- net/hinic: Add the maximum value of the module parameter poll_weight
- net/hinic: Add pause/pfc mutual exclusion protection
- net/hinic: Add lock for mgmt channel event_flag
- net/hinic: Fix signed integer overflow
- nfsd: apply umask on fs without ACL support
- arm64/ascend: use ascend_enable_full to enable ascend platform
- sbsa_gwdt: Enable ARM_SBSA_WATCHDOG_PANIC_NOTIFIER in hulk_defconfig
- sbsa_gwdt: Introduce a panic notifier
- memcg/ascend: Support not account pages of cdm for memcg
- dt-bindings: iommu: Add Message Based SPI for hisilicon
- iommu: support message based spi for smmu
- nbd_genl_status: null check for nla_nest_start
- config: Add default value for CONFIG_ASCEND_INIT_ALL_GICR
- irq-gic-v3: Add support to init ts core GICR
- ascend: mm/hugetlb: Enable ASCEND_CHARGE_MIGRAGE_HUGEPAGES for hulk_defconfig
- ascend: mm/hugetlb: Enable charge migrate hugepages
- config: Add default value for CONFIG_SERIAL_ATTACHED_MBIGEN
- serial: amba-pl011: Fix serial port discard interrupt when interrupt signal line of serial port is connected to mbigen.
- iommu: fix a mistake for iommu_unregister_device_fault_handler
- printk: Export a symbol.
- arm64/ascend: Enable ASCEND_IOPF_HIPRI for hulk_defconfig
- arm64/ascend: Enable iopf hipri feature for Ascend Platform
- mm: Check numa node hugepages enough when mmap hugetlb
- arm64/ascend: Enable CONFIG_ASCEND_OOM for hulk_defconfig
- arm64/ascend: Add new enable_oom_killer interface for oom contrl
- svm: add support for allocing memory which is within 4G physical address in svm_mmap
- suspend: export cpu_suspend/cpu_resume/psci_ops
- printk: export log_buf_addr_get/log_buf_len_get
- arm64/ascend: fix memleak when remove svm
- iommu: fix NULL pointer when release iopf queue
- arm64/ascend: Enable ASCEND_DVPP_MMAP for hulk_defconfig
- arm64/ascend: Don't use the DvPP mmap space for svm.
- arm64/ascend: Enable DvPP mmap features for Ascend Platform
- usb: xhci: Add workaround for phytium
- arm64: topology: Support PHYTIUM CPU
- arm64: mm: define NET_IP_ALIGN to 0
- arm64: ilp32: fix kabi change
- config: add CONFIG_ARM64_ILP32 in defconfigs
- arm64: ilp32: fix compile warning cause by 'VA_BITS'
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
- arm64: ilp32: add is_ilp32_compat_{task, thread} and TIF_32BIT_AARCH64
- arm64: introduce is_a32_compat_{task, thread} for AArch32 compat
- arm64: uapi: set __BITS_PER_LONG correctly for ILP32 and LP64
- arm64: rename functions that reference compat term
- arm64: rename COMPAT to AARCH32_EL0
- arm64: ilp32: add documentation on the ILP32 ABI for ARM64
- thread: move thread bits accessors to separated file
- asm-generic: Drop getrlimit and setrlimit syscalls from default list
- 32-bit userspace ABI: introduce ARCH_32BIT_OFF_T config option
- compat ABI: use non-compat openat and open_by_handle_at variants
- ptrace: Add compat PTRACE_{G, S}ETSIGMASK handlers
- arm64: signal: Make parse_user_sigframe() independent of rt_sigframe layout
- scsi: libsas: Check link status in ATA prereset()
- scsi: libsas: Remove postreset from sas_sata_ops

* Wed Aug 19 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2008.3.0.0042
- x86/mm: split vmalloc_sync_all()
- kexec/uefi: copy secure_boot flag in boot params across kexec reboot
- x86/config: enable CONFIG_HINIC by default
- cgroup: add missing skcd->no_refcnt check in cgroup_sk_clone()
- Revert "cgroup: add missing skcd->no_refcnt check in cgroup_sk_clone()"
- cgroup: add missing skcd->no_refcnt check in cgroup_sk_clone()
- ext4: Correctly restore system zone info when remount fails
- ext4: Handle add_system_zone() failure in ext4_setup_system_zone()
- ext4: Fold ext4_data_block_valid_rcu() into the caller
- ext4: Check journal inode extents more carefully
- ext4: Don't allow overlapping system zones
- ext4: Handle error of ext4_setup_system_zone() on remount
- nfs: set invalid blocks after NFSv4 writes
- cgroup1: don't call release_agent when it is ""
- cgroup-v1: cgroup_pidlist_next should update position index
- cgroup: Iterate tasks that did not finish do_exit()
- cgroup: cgroup_procs_next should increase position index
- mm/vmscan.c: don't round up scan size for online memory cgroup
- cgroup: saner refcounting for cgroup_root
- cgroup: Prevent double killing of css when enabling threaded cgroup
- mm: memcg/slab: fix memory leak at non-root kmem_cache destroy
- mm: memcg/slab: synchronize access to kmem_cache dying flag using a spinlock
- mm/memcg: fix refcount error while moving and swapping
- memcg: fix NULL pointer dereference in __mem_cgroup_usage_unregister_event
- mm/memcontrol.c: lost css_put in memcg_expand_shrinker_maps()
- random32: move the pseudo-random 32-bit definitions to prandom.h
- random32: remove net_rand_state from the latent entropy gcc plugin
- random: fix circular include dependency on arm64 after addition of percpu.h
- ARM: percpu.h: fix build error
- random32: update the net random state on interrupt and activity
- vgacon: Fix for missing check in scrollback handling
- memcg: fix memcg_kmem_bypass() for remote memcg charging
- arm64/numa: cdm: Cacheline aligned cdmmask to improve performance
- mm/page_alloc.c: ratelimit allocation failure warnings more aggressively
- iomap: fix sub-page uptodate handling
- net/hinic: Add dfx information
- net/hinic: Add read chip register interface
- net/hinic: Synchronize time to firmware every hour
- net: add {READ|WRITE}_ONCE() annotations on ->rskq_accept_head
- net: avoid possible false sharing in sk_leave_memory_pressure()
- sctp: add chunks to sk_backlog when the newsk sk_socket is not set
- netfilter: ctnetlink: honor IPS_OFFLOAD flag
- fork, memcg: alloc_thread_stack_node needs to set tsk->stack
- net/udp_gso: Allow TX timestamp with UDP GSO
- inet: frags: call inet_frags_fini() after unregister_pernet_subsys()
- netfilter: ebtables: CONFIG_COMPAT: reject trailing data after last rule
- netfilter: nft_flow_offload: add entry to flowtable after confirmation
- perf/core: Fix the address filtering fix
- netfilter: nft_set_hash: bogus element self comparison from deactivation path
- fs/nfs: Fix nfs_parse_devname to not modify it's argument
- ip_tunnel: Fix route fl4 init in ip_md_tunnel_xmit
- net/mlx5: Take lock with IRQs disabled to avoid deadlock
- xfs: Sanity check flags of Q_XQUOTARM call
- cgroup: fix KABI broken by "cgroup: fix cgroup_sk_alloc() for sk_clone_lock()"
- cgroup: fix cgroup_sk_alloc() for sk_clone_lock()
- net: memcg: fix lockdep splat in inet_csk_accept()
- net: memcg: late association of sock to memcg
- cgroup: memcg: net: do not associate sock with unrelated cgroup
- net/hinic: Retry to get ack after VF message timeout
- net/hinic: Fix register_chrdev_region fails for major number 921
- net/hinic: Fix mgmt message timeout during firmware hot upgrade
- net/hinic: Correct return and features from set_features callback
- net/hinic: Hinic only supports csum offloading of vxlan/ipip tunnel packets
- net/hinic: Set net device link down when the chip fault
- net/hinic: Delete unused UFO codes
- net/hinic: Delete the remaining old linux kernel adaptation interface
- net/hinic: Delete the old kernel version adaptation interface in netdev ops
- net/hinic: Delete the old kernel version adaptation interface in ethtool ops
- net/hinic: Delete useless linux adaptation functions
- net/hinic: Delete unused functions and macro definitions in ossl
- netfilter: nat: check the bounds of nf_nat_l3protos and nf_nat_l4protos

* Web Jul 29 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2007.2.0.0041
- mm, vmstat: reduce zone->lock holding time by /proc/pagetypeinfo
- kernel/notifier.c: intercept duplicate registrations to avoid infinite loops
- macvlan: use skb_reset_mac_header() in macvlan_queue_xmit()
- scsi: qedf: remove memset/memcpy to nfunc and use func instead
- ext4: Send ext4_handle_error message after set sb->s_flags
- tcp: refine rule to allow EPOLLOUT generation under mem pressure
- netfilter: nf_tables: fix flowtable list del corruption
- netfilter: nf_tables: store transaction list locally while requesting module
- netfilter: nf_tables: remove WARN and add NLA_STRING upper limits
- netfilter: nft_tunnel: fix null-attribute check
- netfilter: arp_tables: init netns pointer in xt_tgdtor_param struct
- netfilter: fix a use-after-free in mtype_destroy()
- mm/huge_memory.c: thp: fix conflict of above-47bit hint address and PMD alignment
- mm/huge_memory.c: make __thp_get_unmapped_area static
- mm/page-writeback.c: avoid potential division by zero in wb_min_max_ratio()
- mm: memcg/slab: call flush_memcg_workqueue() only if memcg workqueue is valid
- mm/shmem.c: thp, shmem: fix conflict of above-47bit hint address and PMD alignment
- iommu: Remove device link to group on failure
- netfilter: ipset: avoid null deref when IPSET_ATTR_LINENO is present
- netfilter: conntrack: dccp, sctp: handle null timeout argument
- netfilter: arp_tables: init netns pointer in xt_tgchk_param struct
- tty: always relink the port
- tty: link tty and port before configuring it as console
- chardev: Avoid potential use-after-free in 'chrdev_open()'
- net: hns3: update hns3 version to 1.9.38.5
- net: hns3: fix the number of queues
- net: hns3: fixes a promoiscuous mode
- net: hns3: fix driver bug
- net: hns3: fix for VLAN config when reset
- net: hns3: fix bug when calculating the
- net: hns3: fix speed unknown issue in bond
- net: hns3: fix a missing return in hclge_set_vlan_filter()
- net: hns3: update hns3 version to 1.9.38.3
- net: hns3: remove redundant codes entered by mistake
- net/hinic: Fix out-of-bounds when receiving mbox messages
- RDMA/hns: Modify the code based on the review comments
- Revert "zram: convert remaining CLASS_ATTR() to CLASS_ATTR_RO()"
- config: set CONFIG_CAN_DEBUG_DEVICES for arm64 hulk_defconfig
- config: add CONFIG_CAN_J1939 in defconfigs
- can: j1939: fix address claim code example
- can: j1939: j1939_sk_bind(): take priv after lock is held
- can: j1939: warn if resources are still linked on destroy
- can: j1939: j1939_can_recv(): add priv refcounting
- can: j1939: transport: j1939_cancel_active_session(): use hrtimer_try_to_cancel() instead of hrtimer_cancel()
- can: j1939: make sure socket is held as long as session exists
- can: j1939: transport: make sure the aborted session will be deactivated only once
- can: j1939: socket: rework socket locking for j1939_sk_release() and j1939_sk_sendmsg()
- can: j1939: main: j1939_ndev_to_priv(): avoid crash if can_ml_priv is NULL
- can: j1939: move j1939_priv_put() into sk_destruct callback
- can: af_can: export can_sock_destruct()
- can: j1939: transport: j1939_xtp_rx_eoma_one(): Add sanity check for correct total message size
- can: j1939: transport: j1939_session_fresh_new(): make sure EOMA is send with the total message size set
- can: j1939: fix memory leak if filters was set
- can: j1939: fix resource leak of skb on error return paths
- can: add support of SAE J1939 protocol
- can: af_can: use spin_lock_bh() for &net->can.can_rcvlists_lock
- can: af_can: remove NULL-ptr checks from users of can_dev_rcv_lists_find()
- can: make use of preallocated can_ml_priv for per device struct can_dev_rcv_lists
- can: af_can: can_pernet_exit(): no need to iterate over and cleanup registered CAN devices
- can: af_can: can_rx_register(): use max() instead of open coding it
- can: af_can: give variable holding the CAN receiver and the receiver list a sensible name
- can: af_can: rename find_dev_rcv_lists() to can_dev_rcv_lists_find()
- can: af_can: rename find_rcv_list() to can_rcv_list_find()
- can: proc: give variable holding the CAN per device receive lists a sensible name
- can: af_can: give variable holding the CAN per device receive lists a sensible name
- can: proc: give variables holding CAN statistics a sensible name
- can: af_can: give variables holding CAN statistics a sensible name
- can: af_can: can_pernet_init(): Use preferred style kzalloc(sizeof()) usage
- can: extend sockaddr_can to include j1939 members
- can: add socket type for CAN_J1939
- can: introduce CAN_REQUIRED_SIZE macro
- can: introduce CAN midlayer private and allocate it automatically
- net: hns3: update hns3 version to 1.9.38.3
- net: hns3: clean code for security
- net: hns3: modify an incorrect type in
- net: hns3: check queue id range before
- net: hns3: fix error handling for desc filling
- net: hns3: fix for not calculating tx BD send size correctly
- net: hns3: fix for not unmapping tx buffer correctly
- net: hns3: fix desc filling bug when skb is expanded or lineared
- net: hns3: drop the WQ_MEM_RECLAIM flag when allocating wq
- net: hns3: optimize the parameter of hclge_update_port_base_vlan_cfg and ignore the send mailbox failure when VF is unalive
- net: hns3: use netif_tx_disable to stop the transmit queue
- net: hns3: add support of dumping mac reg in debugfs
- net: hns3: fix a fake tx timeout issue
- net: hns3: fix use-after-free when doing self test
- net: hns3: add a log for switching VLAN filter state
- net: hns3: fix problem of missing updating port information
- net: hns3: add vlan list lock to protect vlan list and fix duplicate node in vlan list
- net: hns3: fix bug for port base vlan configuration
- net: hns3: skip periodic service task if reset failed
- net: hns3: check reset pending after FLR prepare
- net: hns3: fix for mishandle of asserting VF reset fail
- net: hns3: fix for missing uninit debugfs when unload driver
- net: hns3: unify format of failed print information for clean up
- net: hns3: modify location of one print information
- net: hns3: fix return value error when query mac link status fail
- net: hns3: remove unnecessary mac enable in app loopback
- net: hns3: remove some useless code
- net: hns3: fix an inappropriate type assignment
- net: hns3: update hns3 version to 1.9.38.2
- net: hns3: fix reset bug
- sdei_watchdog: fix compile error when CONFIG_HARDLOCKUP_DETECTOR is not set
- net/hinic: Add support for 128 qps
- net/hinic: Add support for X86 Arch
- fs/filescontrol: add a switch to enable / disable accounting of open fds
- usb: usbtest: fix missing kfree(dev->buf) in usbtest_disconnect
- vfio/pci: Fix SR-IOV VF handling with MMIO blocking
- signal: Export tracepoint symbol signal_generate
- x86/speculation: PR_SPEC_FORCE_DISABLE enforcement for indirect branches.
- x86/speculation: Avoid force-disabling IBPB based on STIBP and enhanced IBRS.
- x86/speculation: Add support for STIBP always-on preferred mode
- x86/speculation: Change misspelled STIPB to STIBP
- x86/speculation: Prevent rogue cross-process SSBD shutdown
- vfio-pci: Invalidate mmaps and block MMIO access on disabled memory
- vfio-pci: Fault mmaps to enable vma tracking
- vfio/type1: Support faulting PFNMAP vmas
- vfio/type1: Fix VA->PA translation for PFNMAP VMAs in vaddr_get_pfn()
- vfio_pci: Enable memory accesses before calling pci_map_rom
- net/hinic: Fix copying out of bounds when using tools to get statistics
- uacce: fix problem of parameter check
- net: hns3: update hns3 version to 1.9.38.1
- net: hns3: add device name valid check
- ext4, jbd2: ensure panic by fix a race between jbd2 abort and ext4 error handlers
- Revert "ext4, jbd2: switch to use completion variable instead of JBD2_REC_ERR"
- x86/speculation: Add Ivy Bridge to affected list
- x86/speculation: Add SRBDS vulnerability and mitigation documentation
- x86/speculation: Add Special Register Buffer Data Sampling (SRBDS) mitigation
- x86/cpu: Add 'table' argument to cpu_matches()
- x86/cpu: Add a steppings field to struct x86_cpu_id
- ext4: stop overwrite the errcode in ext4_setup_super
- panic/printk: fix zap_lock
- vt: keyboard: avoid signed integer overflow in k_ascii
- ext4: Fix block bitmap corruption when io error
- mm: Fix mremap not considering huge pmd devmap
- net-sysfs: Call dev_hold always in rx_queue_add_kobject
- net-sysfs: Call dev_hold always in netdev_queue_add_kobject
- net-sysfs: fix netdev_queue_add_kobject() breakage
- net-sysfs: Fix reference count leak in rx|netdev_queue_add_kobject
- SUNRPC: Fix xprt->timer use-after-free
- printk/panic: Avoid deadlock in printk()
- block: Fix use-after-free in blkdev_get()
- ata/libata: Fix usage of page address by page_address in ata_scsi_mode_select_xlat function
- media: go7007: fix a miss of snd_card_free
- vt: fix unicode console freeing with a common interface
- vt: don't use kmalloc() for the unicode screen buffer
- scsi: Fix kabi change due to add offline_already member in struct scsi_device
- scsi: core: avoid repetitive logging of device offline messages
- hfs: fix null-ptr-deref in hfs_find_init()
- ext4, jbd2: switch to use completion variable instead of JBD2_REC_ERR
- jbd2: clean __jbd2_journal_abort_hard() and __journal_abort_soft()
- jbd2: make sure ESHUTDOWN to be recorded in the journal superblock
- vt: vt_ioctl: fix use-after-free in vt_in_use()
- vt: vt_ioctl: fix VT_DISALLOCATE freeing in-use virtual console
- vt: vt_ioctl: remove unnecessary console allocation checks
- vt: switch vt_dont_switch to bool
- vt: ioctl, switch VT_IS_IN_USE and VT_BUSY to inlines
- vt: selection, introduce vc_is_sel
- ALSA: proc: Avoid possible leaks of snd_info_entry objects
- net/hinic: update hinic version to 2.3.2.14
- net/hinic: Fix memleak when create_singlethread_workqueue() is failed
- net/hinic: Fix VF driver loading failure during the firmware hot upgrade process
- net/hinic: Fix data inconsistency in the forwarding scenario when DCB is turned on
- net/hinic: Fix reboot -f stuck for a long time
- net/hinic: Add tx timeout dfx information
- net/hinic: Add a lock when registering the driver's global netdevice notifier
- net/hinic: Fix VF has a low probability of network failure on the virtual machine
- net/hinic: Fix the firmware compatibility bug in the MAC reuse scenario
- irqchip/gic-v3-its: Probe ITS page size for all GITS_BASERn registers
- selinux: properly handle multiple messages in selinux_netlink_send()
- media: tw5864: Fix possible NULL pointer dereference in tw5864_handle_frame
- arm64/mpam: Supplement err tips in info/last_cmd_status
- arm64/mpam: Fix unreset resources when mkdir ctrl group or umount resctrl
- MPAM / ACPI: Refactoring MPAM init process and set MPAM ACPI as entrance
- ACPI 6.x: Add definitions for MPAM table
- ACPI / PPTT: cacheinfo: Label caches based on fw_token
- ACPI / PPTT: Filthy hack to find _a_ backwards reference in the PPTT [ROTTEN]
- ACPI / PPTT: Add helper to validate cache nodes from an offset [dead]
- ACPI / processor: Add helper to convert acpi_id to a phys_cpuid
- ext4: report error to userspace by netlink
- pcie_cae add judgement about chip type
- Enable trust mode control for SR-IOV ports
- Added ethtool_ops interface to query optical module information
- Revert "consolemap: Fix a memory leaking bug in drivers/tty/vt/consolemap.c"
- ext4: fix support for inode sizes > 1024 bytes
- ext4: validate the debug_want_extra_isize mount option at parse time
- sunrpc: clean up properly in gss_mech_unregister()
- sunrpc: svcauth_gss_register_pseudoflavor must reject duplicate registrations.
- sunrpc: check that domain table is empty at module unload.
- arm64: smp: Increase secondary CPU boot timeout value
- KVM: arm64: Only flush VM for the first and the last vcpu
- media: remove videobuf-core.c
- ext4: mark block bitmap corrupted when found instead of BUGON
- bcache: fix potential deadlock problem in btree_gc_coalesce
- fs/binfmt_elf.c: allocate initialized memory in fill_thread_core_info()
- USB: gadget: fix illegal array access in binding with UDC

* Wed Jun 03 2020 Xie XiuQi <xiexiuqi@huawei.com> - 4.19.90-2005.2.0.0040
- update req_distinguished_name for x509.genkey

* Fri May 22 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2005.2.0.0039
- signal: fix kabi changes in struct task_struct
- signal: Extend exec_id to 64bits
- livepatch/core: Fix compile error when CONFIG_JUMP_LABEL closed
- net/hinic: Adjust AEQ interrupt retransmission settings
- net/hinic: Number of VF queues cleared during initialization
- net/hinic: Reduce VF EQ queue depth in SDI mode
- net/hinic: Disable the CSUM offload capability of TUNNEL in SDI mode
- net/hinic: VF does not display firmware statistics
- net/hinic: SDI bare metal VF supports dynamic queue
- net/hinic: Support doorbell BAR size of 256K in SDI mode
- net/hinic: Supports variable SDI master host ppf_id
- net/hinic: Optimize SDI interrupt aggregation parameters
- netlabel: cope with NULL catmap
- netprio_cgroup: Fix unlimited memory leak of v2 cgroups
- net: hns3: update hns3 version to 1.9.38.0
- net: hns3: solve the unlock 2 times when rocee init fault
- scsi: sg: add sg_remove_request in sg_write
- KVM: SVM: Fix potential memory leak in svm_cpu_init()
- ptp: free ptp device pin descriptors properly
- spi: spi-dw: Add lock protect dw_spi rx/tx to prevent concurrent calls
- drivers sfc: Fix cross page write error
- drivers sysctl: add read and write interface of pmbus
- net/hinic: Fix TX timeout under ipip tunnel packet
- xsk: Add missing check on user supplied headroom size
- fs/namespace.c: fix mountpoint reference counter race
- USB: core: Fix free-while-in-use bug in the USB S-Glibrary
- block, bfq: fix use-after-free in bfq_idle_slice_timer_body
- mwifiex: Fix possible buffer overflows in mwifiex_cmd_append_vsie_tlv()
- mwifiex: Fix possible buffer overflows in mwifiex_ret_wmm_get_status()
- scsi: mptfusion: Fix double fetch bug in ioctl
- mt76: fix array overflow on receiving too many fragments for a packet
- net: hns3: change the order of reinitializing RoCE and VF during reset
- net: hns3: update hns3 version to 1.9.37.9
- Revert "scsi: fix failing unload of a LLDD module"
- s390/mm: fix page table upgrade vs 2ndary address mode accesses
- pcie_cae support getting chipnums of this system
- net: hns3: remove the unnecessary ccflags

* Wed May 06 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2005.1.0.0038
- perf: Make perf able to build with latest libbfd
- nbd: use blk_mq_queue_tag_inflight_iter()
- blk-mq: use blk_mq_queue_tag_inflight_iter() in debugfs

* Tue Apr 28 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2004.1.0.0037
- net: hns3: update hns3 version to 1.9.37.8
- net: hns3: optimize FD tuple inspect
- net: hns3: fix unsupported config for RSS
- net: hns3: disable auto-negotiation off with 1000M setting in ethtool
- net: hns3: update VF mac list configuration as PF
- net: hns3: modify magic number in hclge_dbg_dump_ncl_config
- net: hns3: do mac configuration instead of rollback when malloc mac node fail
- net: hns3: update the device mac address asynchronously
- net: hns3: add one parameter for function hns3_nic_maybe_stop_tx()
- net: hns3: delete unnecessary logs after kzalloc fails
- net: hns3: fix some coding style found by codereview
- net: hns3: use uniform format "failed to xxx" to print fail message
- net: hns3: add debug information for flow table when failed
- net: hns3: modify hclge_restore_fd_entries()'s return type to void
- net: hns3: splice two "if" logic as one
- net: hns3: clean up some coding style issue
- net: hns3: modify definition location of struct hclge_mac_ethertype_idx_rd_cmd
- net: hns3: modify comment of macro HNAE3_MIN_VECTOR_NUM
- net: hns3: modify one macro into unsigned type
- net: hns3: delete unused macro HCLGEVF_MPF_ENBALE
- net: hns3: modify definition location of struct hclge_vf_vlan_cfg
- net: hns3: remove unnecessary 'ret' variable in hclge_misc_err_recovery()
- net: hns3: remove unnecessary register info in hclge_reset_err_handle()
- net: hns3: misc cleanup for VF reset
- net: hns3: merge mac state HCLGE_MAC_TO_DEL and HCLGE_MAC_DEL_FAIL
- net: hns3: update hns3 version to 1.9.37.7
- scsi: hisi_sas: do not reset the timer to wait for phyup when phy already up
- net: hns3: add suspend/resume function for hns3 driver
- btrfs: tree-checker: Enhance chunk checker to validate chunk profile
- net/hinic: fix the problem that out-of-bounds access
- scsi: sg: fix memory leak in sg_build_indirect
- scsi: sg: add sg_remove_request in sg_common_write
- btrfs: Don't submit any btree write bio if the fs has errors
- btrfs: extent_io: Handle errors better in extent_write_full_page()
- net/hinic: Delete useless header files
- powerpc/powernv/idle: Restore AMR/UAMOR/AMOR after idle
- media: xirlink_cit: add missing descriptor sanity checks
- Input: add safety guards to input_set_keycode()
- f2fs: fix to avoid memory leakage in f2fs_listxattr
- media: stv06xx: add missing descriptor sanity checks
- media: ov519: add missing endpoint sanity checks
- btrfs: tree-checker: Verify inode item
- btrfs: delayed-inode: Kill the BUG_ON() in btrfs_delete_delayed_dir_index()
- net: hns3: update hns3 version to 1.9.37.6
- net: hns3: ignore the send mailbox failure by VF is unalive
- net: hns3: update hns3 version to 1.9.37.5
- net: hns3: fix "tc qdisc del" failed issue
- net: hns3: rename two functions from periodical to periodic
- net: hns3: modify some print messages for cleanup and keep style consistent
- net: hns3: add some blank lines for cleanup
- net: hns3: sync some code from linux mainline
- net: hns3: fix mailbox send to VF failed issue
- net: hns3: disable phy loopback setting in hclge_mac_start_phy
- net: hns3: delete some useless code
- net: hns3: remove the limitation of MAC address duplicate configuration
- net: hns3: delete the unused struct hns3_link_mode_mapping
- net: hns3: rename one parameter in hclge_add_fd_entry_by_arfs()
- net: hns3: modify the location of macro HCLGE_LINK_STATUS_MS definition
- net: hns3: modify some unsuitable parameter type of RSS
- net: hns3: move some definition location
- net: hns3: add judgement for hclgevf_update_port_base_vlan_info()
- net: hns3: check null pointer in function hclge_fd_config_rule()
- net: hns3: optimize deletion of the flow direction table
- net: hns3: fix a ipv6 address copy problem in hclge_fd_get_flow_tuples()
- net: hns3: fix VF bandwidth does not take effect in some case
- net: hns3: synchronize some print relating to reset issue
- net: hns3: delete unnecessary 5s delay judgement in hclgevf_reset_event()
- net: hns3: delete unnecessary reset handling judgement in hclgevf_reset_tqp()
- net: hns3: delete unnecessary judgement in hns3_get_regs()
- net: hns3: delete one variable in hclge_get_sset_count() for optimization
- net: hns3: optimize return process for phy loop back
- net: hns3: fix "mac exist" problem
- net: hns3: add one printing information in hnae3_unregister_client() function
- slcan: Don't transmit uninitialized stack data in padding
- mm: mempolicy: require at least one nodeid for MPOL_PREFERRED
- livepatch/core: fix kabi for klp_rel_state
- livepatch/core: support jump_label
- arm64: entry: SP Alignment Fault doesn't write to FAR_EL1
- arm64: mark (__)cpus_have_const_cap as __always_inline
- arm64/module: revert to unsigned interpretation of ABS16/32 relocations
- arm64/module: deal with ambiguity in PRELxx relocation ranges
- i2c: designware: Add ACPI HID for Hisilicon Hip08-Lite I2C controller
- ACPI / APD: Add clock frequency for Hisilicon Hip08-Lite I2C controller
- qm: fix packet loss for acc
- net/hinic: Solve the problem that 1822 NIC reports 5d0 error
- net: hns3: Rectification of driver code review
- net: hns3: update hns3 version to 1.9.37.4
- net: hns3: additional fix for fraglist handling
- net: hns3: fix for fraglist skb headlen not handling correctly
- net: hns3: update hns3 version to 1.9.37.3
- sec: modify driver to adapt dm-crypt
- qm: reinforce reset failure scene
- zip: fix decompress a empty file
- hpre: dfx for IO operation and delay
- RDMA/hns: optimize mtr management and fix mtr addressing bug
- RDMA/hns: fix bug of accessing null pointer
- sec: Overall optimization of sec code
- qm: optimize the maximum number of VF and delete invalid addr
- qm: optimize set hw_reset flag logic for user
- qm: fixup the problem of wrong judgement of used parameter
- qm: Move all the same logic functions of hisilicon crypto to qm
- drivers : localbus cleancode
- drivers : sysctl cleancode
- drivers : sfc cleancode
- kretprobe: check re-registration of the same kretprobe earlier
- vhost: Check docket sk_family instead of call getname
- btrfs: tree-checker: Add EXTENT_ITEM and METADATA_ITEM check
- block: fix possible memory leak in 'blk_prepare_release_queue'
- Revert "dm-crypt: Add IV generation templates"
- Revert "dm-crypt: modify dm-crypt to rely on IV generation templates"

* Sat Mar 21 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.4.0.0036
- x86/config: enable CONFIG_CFQ_GROUP_IOSCHED
- x86/openeuler_config: disable CONFIG_EFI_VARS

* Fri Mar 20 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.3.0.0035
- btrfs: don't use WARN_ON when ret is -ENOTENT in __btrfs_free_extent()
- cifs: fix panic in smb2_reconnect

* Wed Mar 18 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.2.0.0034
- xfs: avoid f_bfree overflow
- xfs: always init fdblocks in mount
- xfs: devirtualize ->sf_entsize and ->sf_nextentry
- block: fix inaccurate io_ticks
- block: delete part_round_stats and switch to less precise counting
- CIFS: Fix bug which the return value by asynchronous read is error
- net/hinic: Magic number rectification
- net/hinic: slove the problem that VF may be disconnected when vm reboot and receive lots of broadcast packets.
- openeuler/config: disable CONFIG_EFI_VARS
- pagecache: support percpu refcount to imporve performance
- arm64: mm: support setting page attributes for debugging
- staging: android: ashmem: Disallow ashmem memory from being remapped
- mm/resource: Return real error codes from walk failures
- vt: selection, push sel_lock up
- vt: selection, push console lock down
- net: ipv6_stub: use ip6_dst_lookup_flow instead of ip6_dst_lookup
- net: ipv6: add net argument to ip6_dst_lookup_flow

* Mon Mar 16 2020 Luo Chunsheng <luochunsheng@huawei.com> - 4.19.90-2003.1.1.0033
- fix kernel-devel upgrade running scriptlet failed

* Sat Mar 14 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.1.1.0032
- openeuler/config: enable CONFIG_FCOE
- openeuler/config: disable unused debug config
- net: hns3: update the number of version
- net: hns3: add dumping vlan filter config in debugfs
- net: hns3: Increase vlan tag0 when close the port_base_vlan
- net: hns3: adds support for extended VLAN mode and 'QOS' in vlan 802.1Q protocol.

* Thu Mar 12 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.90-2003.1.0.0031
- net/hinic: driver code compliance rectification
- net/hinic: Solve the problem that the network card hangs when receiving the skb which frag_size=0
- net: hns3: adds support for reading module eeprom info
- net: hns3: update hns3 version to 1.9.37.1
- btrfs: tree-checker: Remove comprehensive root owner check
- xfs: add agf freeblocks verify in xfs_agf_verify
- blktrace: fix dereference after null check
- blktrace: Protect q->blk_trace with RCU
- vgacon: Fix a UAF in vgacon_invert_region
- can, slip: Protect tty->disc_data in write_wakeup and close with RCU
- relay: handle alloc_percpu returning NULL in relay_open
- drm/radeon: check the alloc_workqueue return value
- apparmor: Fix use-after-free in aa_audit_rule_init

* Wed Mar 4 2020 Luo Chunsheng <luochunsheng@huawei.com> - 4.19.95-2002.6.0.0030
- delete useless directory

* Tue Mar 3 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.95-2002.6.0.0029
- livepatch/x86: enable livepatch config openeuler
- livepatch/x86: enable livepatch config for hulk
- livepatch/arm64: check active func in consistency stack checking
- livepatch/x86: check active func in consistency stack checking
- livepatch/x86: support livepatch without ftrace
- KVM: nVMX: Check IO instruction VM-exit conditions
- KVM: nVMX: Refactor IO bitmap checks into helper function
- KVM: nVMX: Don't emulate instructions in guest mode
- floppy: check FDC index for errors before assigning it
- ext4: add cond_resched() to __ext4_find_entry()
* Fri Feb 28 2020 Yang Yingliang <yangyingliang@huawei.com> - 4.19.95-2002.5.0.0028
- x86 / config: add openeuler_defconfig
- files_cgroup: Fix soft lockup when refcnt overflow.
- vt: selection, close sel_buffer race
- vt: selection, handle pending signals in paste_selection
- RDMA/hns: Compilation Configuration update
- jbd2: do not clear the BH_Mapped flag when forgetting a metadata buffer
- jbd2: move the clearing of b_modified flag to the journal_unmap_buffer()
- iscsi: use dynamic single thread workqueue to improve performance
- workqueue: implement NUMA affinity for single thread workqueue
- iscsi: add member for NUMA aware order workqueue
- Revert "debugfs: fix kabi for function debugfs_remove_recursive"
- Revert "bdi: fix kabi for struct backing_dev_info"
- Revert "membarrier/kabi: fix kabi for membarrier_state"
- Revert "PCI: fix kabi change in struct pci_bus"
- files_cgroup: fix error pointer when kvm_vm_worker_thread
- bdi: get device name under rcu protect
- x86/kvm: Be careful not to clear KVM_VCPU_FLUSH_TLB bit
- timer_list: avoid other cpu soft lockup when printing timer list
- sysrq: avoid concurrently info printing by 'sysrq-trigger'
- bdi: fix memleak in bdi_register_va()
- iommu/iova: avoid softlockup in fq_flush_timeout
- qm: fix the way judge whether q stop in user space
- net: hns3: clear devil number for hns3_cae
- net: hns3: fix compile error when CONFIG_HNS3_DCB is not set
- qm: fixup compilation dependency
- rde: optimize debug regs clear logic
- sec: change sec_control reg config
- hpre: add likely and unlikey in result judgement
- hpre: optimize key process before free
- net: hns3: fix bug when parameter check
- drivers : sysctl fixup some param dont check the legitimacy
- net: hns3: add protect for parameters and remove unused functions
- qm: remove invalid addr print
- zip: use offset fields in sqe to avoid SG_SPLIT
- qm: fix wrong number of sg elements after dma map
- RDMA/hns:security review update
- RDMA/hns: some robust optimize in rdfx
- RDMA/hns: fix the bug of out-of-bonds-read in post send
- net: hns3: Remove the function of vf check mac address
- net: hns3: update hns3 version to 1.9.35.1
- uacce: Remove uacce mode 1 relatives
- acc: Remove uacce mode 1 logic below hisilicon
- RDMA/hns: Add roce dfx of arm_cnt
- RDMA/hns: avoid potential overflow of
- RDMA/hns: handle device err after device state to UNIT
- net: hns3: change version to 1.9.35.0
- net: hns3: fix missing help info for qs shaper in debugfs
- net: hns3: set VF's default reset_type to HNAE3_NONE_RESET
- net: hns3: fix port base vlan add fail when concurrent with reset
- net: hns3: skip mac speed and duplex modification checking for fibre port support autoneg
- net: hns3: modify timing of reading register in hclge_reset_wait()
- net: hns3: support of dump mac id and loopback status in debugfs
- net: hns3: optimize parameter of hclge_set_phy_loopback() function
- net: hns3: optimize parameter of hclge_phy_link_status_wait() function
- net: hns3: delete unnecessary judgement in hns3_get_stats()
- net: hns3: no need to check return value of debugfs_create functions
- net: hns3: make array spec_opcode static const, makes object smaller
- net: hns: replace space with tab for cleanup
- net: hns3: modify return value in hns3_dbg_cmd_write
- net: hns3: rename variable flag in hnae3_unregister_client()
- net: hns3: move struct hclge_mdio_cfg_cmd declaration
- net: hns3: modify error process of hclge_phy_link_status_wait()
- net: hns3: support query vf ring and vector map relation
- net: hns3: add enabled tc numbers and dwrr weight info in debugfs
- net: hns3: add error process in hclge_mac_link_status_wait() function
- net: hns3: modify code of hclge_mac_phy_link_status_wait() function
- net: hns3: replace goto with return in function hns3_set_ringparam()
- net: hns3: modify print format in hns3_set_ringpa()
- net: hns: replace goto with return in function hclge_set_vf_uc_mac_addr
- net: hns3: modify the irq name of misc vectors
- net: hns3: optimize code of hns3_parse_vlan_tag() function
- net: hns3: optimize local variable of hclge_set_loopback() function
- net: hns3: optimize code of hclge_init_kdump_kernel_config() function
- net: hns: remove unnecessary newline
- net: hns: modify print function used in hclge_init_ae_dev()
- net: hns3: modify the irq name of tqp vectors
- net: hns3: delete blank lines and space for cleanup
- net: hns3: do not schedule the periodical task when reset fail
- net: hns3: modify the location of updating the hardware reset done counter
- net: hns3: refactor the notification scheme of PF reset
- net: hns3: refactor the procedure of VF FLR
- net: hns3: modify hclge_func_reset_sync_vf()'s return type to void
- net: hns3: enlarge HCLGE_RESET_WAIT_CNT
- net: hns3: refactor the precedure of PF FLR
- net: hns3: split hclgevf_reset() into preparing and rebuilding part
- net: hns3: split hclge_reset() into preparing and rebuilding part
- net: hns3: Add "mac table" information query function
- net: hns3: fix bug that PF set VF mac didn't work
- net: hns3: delete some useless repeated printing
- net: hns3: delete some useless function and definication
- net: hns3: sync some code from net-next part1
- net: hns3: refactor the promisc mode setting
- net: hns3: refine mac address configure for VF
- net: hns3: use mutex vport_lock intead of spin lock umv_lock
- net: hns3: opmitize the table entry restore when resetting
- net: hns3: refine mac address configure for PF
- net: fix bug and change version to 1.9.33.0
- net: hns3: cae clear warnings
- drivers : sysctl remove rcu_lock
- RDMA/hns:remove useless header in cmd
- hac: sec: add initial configuration in sec_engine_init
- net: hns3: cae security review
- net: hns3: cae io_param definition updated
- debugfs: fix kabi for function debugfs_remove_recursive
- simple_recursive_removal(): kernel-side rm -rf for ramfs-style filesystems
- debugfs: simplify __debugfs_remove_file()
- block: rename 'q->debugfs_dir' and 'q->blk_trace->dir' in blk_unregister_queue()
- ext4: add cond_resched() to ext4_protect_reserved_inode
- bdi: fix kabi for struct backing_dev_info
- bdi: fix use-after-free for the bdi device
- vfs: fix do_last() regression
- do_last(): fetch directory ->i_mode and ->i_uid before it's too late
- ext4: reserve revoke credits in __ext4_new_inode
- jbd2: make jbd2_handle_buffer_credits() handle reserved handles
- jbd2: Fine tune estimate of necessary descriptor blocks
- jbd2: Provide trace event for handle restarts
- ext4: Reserve revoke credits for freed blocks
- jbd2: Make credit checking more strict
- jbd2: Rename h_buffer_credits to h_total_credits
- jbd2: Reserve space for revoke descriptor blocks
- jbd2: Drop jbd2_space_needed()
- jbd2: remove repeated assignments in __jbd2_log_wait_for_space()
- jbd2: Account descriptor blocks into t_outstanding_credits
- jbd2: Factor out common parts of stopping and restarting a handle
- jbd2: Drop pointless wakeup from jbd2_journal_stop()
- jbd2: Drop pointless check from jbd2_journal_stop()
- jbd2: Reorganize jbd2_journal_stop()
- ocfs2: Use accessor function for h_buffer_credits
- ext4, jbd2: Provide accessor function for handle credits
- ext4: Provide function to handle transaction restarts
- ext4: Avoid unnecessary revokes in ext4_alloc_branch()
- ext4: Use ext4_journal_extend() instead of jbd2_journal_extend()
- ext4: Fix ext4_should_journal_data() for EA inodes
- ext4: Do not iput inode under running transaction
- ext4: Move marking of handle as sync to ext4_add_nondir()
- jbd2: Completely fill journal descriptor blocks
- jbd2: Fixup stale comment in commit code
- libertas: Fix two buffer overflows at parsing bss descriptor
* Fri Feb 7 2020 Xie XiuQi <xiexiuqi@huawei.com> - 4.19.95-2002.1.0.0027
- drm/i915/gen9: Clear residual context state on context switch
- selftest/membarrier: fix build error
- membarrier/kabi: fix kabi for membarrier_state
- membarrier: Fix RCU locking bug caused by faulty merge
- sched/membarrier: Return -ENOMEM to userspace on memory allocation failure
- sched/membarrier: Skip IPIs when mm->mm_users == 1
- selftests, sched/membarrier: Add multi-threaded test
- sched/membarrier: Fix p->mm->membarrier_state racy load
- sched: Clean up active_mm reference counting
- sched/membarrier: Remove redundant check
- drm/i915: Fix use-after-free when destroying GEM context
- PCI: fix kabi change in struct pci_bus
- PCI: add a member in 'struct pci_bus' to record the original 'pci_ops'
- KVM: tools/kvm_stat: Fix kvm_exit filter name
- KVM: arm/arm64: use esr_ec as trace field of kvm_exit tracepoint
- PCI/AER: increments pci bus reference count in aer-inject process
- irqchip/gic-v3-its: its support herbination
- PM / hibernate: introduce system_in_hibernation
- config: enable CONFIG_SMMU_BYPASS_DEV by default
- f2fs: support swap file w/ DIO
- mac80211: Do not send Layer 2 Update frame before authorization
- cfg80211/mac80211: make ieee80211_send_layer2_update a public function
- PCI/AER: Refactor error injection fallbacks
- net/sched: act_mirred: Pull mac prior redir to non mac_header_xmit device
- kernfs: fix potential null pointer dereference
- arm64: fix calling nmi_enter() repeatedly when IPI_CPU_CRASH_STOP
- usb: missing parentheses in USE_NEW_SCHEME
- USB: serial: option: add Telit ME910G1 0x110a composition
- USB: core: fix check for duplicate endpoints
- usb: dwc3: gadget: Fix request complete check
- net: sch_prio: When ungrafting, replace with FIFO
- mlxsw: spectrum_qdisc: Ignore grafting of invisible FIFO
- vlan: vlan_changelink() should propagate errors
- vlan: fix memory leak in vlan_dev_set_egress_priority
- vxlan: fix tos value before xmit
- tcp: fix "old stuff" D-SACK causing SACK to be treated as D-SACK
- sctp: free cmd->obj.chunk for the unprocessed SCTP_CMD_REPLY
- sch_cake: avoid possible divide by zero in cake_enqueue()
- pkt_sched: fq: do not accept silly TCA_FQ_QUANTUM
- net: usb: lan78xx: fix possible skb leak
- net: stmmac: dwmac-sunxi: Allow all RGMII modes
- net: stmmac: dwmac-sun8i: Allow all RGMII modes
- net: dsa: mv88e6xxx: Preserve priority when setting CPU port.
- macvlan: do not assume mac_header is set in macvlan_broadcast()
- gtp: fix bad unlock balance in gtp_encap_enable_socket
- PCI/switchtec: Read all 64 bits of part_event_bitmap
- ARM: dts: imx6ul: use nvmem-cells for cpu speed grading
- cpufreq: imx6q: read OCOTP through nvmem for imx6ul/imx6ull
- powerpc/spinlocks: Include correct header for static key
- powerpc/vcpu: Assume dedicated processors as non-preempt
- hv_netvsc: Fix unwanted rx_table reset
- llc2: Fix return statement of llc_stat_ev_rx_null_dsap_xid_c (and _test_c)
- parisc: Fix compiler warnings in debug_core.c
- block: fix memleak when __blk_rq_map_user_iov() is failed
- s390/dasd: fix memleak in path handling error case
- s390/dasd/cio: Interpret ccw_device_get_mdc return value correctly
- drm/exynos: gsc: add missed component_del
- s390/purgatory: do not build purgatory with kcov, kasan and friends
- net: stmmac: Always arm TX Timer at end of transmission start
- net: stmmac: RX buffer size must be 16 byte aligned
- net: stmmac: xgmac: Clear previous RX buffer size
- net: stmmac: Do not accept invalid MTU values
- fs: avoid softlockups in s_inodes iterators
- perf/x86/intel: Fix PT PMI handling
- kconfig: don't crash on NULL expressions in expr_eq()
- iommu/iova: Init the struct iova to fix the possible memleak
- regulator: rn5t618: fix module aliases
- ASoC: wm8962: fix lambda value
- rfkill: Fix incorrect check to avoid NULL pointer dereference
- parisc: add missing __init annotation
- net: usb: lan78xx: Fix error message format specifier
- cxgb4: Fix kernel panic while accessing sge_info
- bnx2x: Fix logic to get total no. of PFs per engine
- bnx2x: Do not handle requests from VFs after parity
- bpf: Clear skb->tstamp in bpf_redirect when necessary
- btrfs: Fix error messages in qgroup_rescan_init
- powerpc: Ensure that swiotlb buffer is allocated from low memory
- samples: bpf: fix syscall_tp due to unused syscall
- samples: bpf: Replace symbol compare of trace_event
- ARM: dts: am437x-gp/epos-evm: fix panel compatible
- spi: spi-ti-qspi: Fix a bug when accessing non default CS
- bpf, mips: Limit to 33 tail calls
- bnxt_en: Return error if FW returns more data than dump length
- ARM: dts: bcm283x: Fix critical trip point
- ASoC: topology: Check return value for soc_tplg_pcm_create()
- spi: spi-cavium-thunderx: Add missing pci_release_regions()
- ARM: dts: Cygnus: Fix MDIO node address/size cells
- selftests/ftrace: Fix multiple kprobe testcase
- ARM: dts: BCM5301X: Fix MDIO node address/size cells
- netfilter: nf_tables: validate NFT_DATA_VALUE after nft_data_init()
- netfilter: nf_tables: validate NFT_SET_ELEM_INTERVAL_END
- netfilter: nft_set_rbtree: bogus lookup/get on consecutive elements in named sets
- netfilter: uapi: Avoid undefined left-shift in xt_sctp.h
- ARM: vexpress: Set-up shared OPP table instead of individual for each CPU
- ARM: dts: imx6ul: imx6ul-14x14-evk.dtsi: Fix SPI NOR probing
- efi/gop: Fix memory leak in __gop_query32/64()
- efi/gop: Return EFI_SUCCESS if a usable GOP was found
- efi/gop: Return EFI_NOT_FOUND if there are no usable GOPs
- ASoC: Intel: bytcr_rt5640: Update quirk for Teclast X89
- x86/efi: Update e820 with reserved EFI boot services data to fix kexec breakage
- libtraceevent: Fix lib installation with O=
- netfilter: ctnetlink: netns exit must wait for callbacks
- locking/spinlock/debug: Fix various data races
- ASoC: max98090: fix possible race conditions
- regulator: fix use after free issue
- bpf: Fix passing modified ctx to ld/abs/ind instruction
- USB: dummy-hcd: increase max number of devices to 32
- USB: dummy-hcd: use usb_urb_dir_in instead of usb_pipein
- block: fix use-after-free on cached last_lookup partition
- perf/x86/intel/bts: Fix the use of page_private()
- xen/blkback: Avoid unmapping unmapped grant pages
- s390/smp: fix physical to logical CPU map for SMT
- ubifs: ubifs_tnc_start_commit: Fix OOB in layout_in_gaps
- net: add annotations on hh->hh_len lockless accesses
- xfs: periodically yield scrub threads to the scheduler
- ath9k_htc: Discard undersized packets
- ath9k_htc: Modify byte order for an error message
- net: core: limit nested device depth
- rxrpc: Fix possible NULL pointer access in ICMP handling
- KVM: PPC: Book3S HV: use smp_mb() when setting/clearing host_ipi flag
- selftests: rtnetlink: add addresses with fixed life time
- powerpc/pseries/hvconsole: Fix stack overread via udbg
- drm/mst: Fix MST sideband up-reply failure handling
- scsi: qedf: Do not retry ELS request if qedf_alloc_cmd fails
- bdev: Refresh bdev size for disks without partitioning
- bdev: Factor out bdev revalidation into a common helper
- fix compat handling of FICLONERANGE, FIDEDUPERANGE and FS_IOC_FIEMAP
- tty: serial: msm_serial: Fix lockup for sysrq and oops
- arm64: dts: meson: odroid-c2: Disable usb_otg bus to avoid power failed warning
- dt-bindings: clock: renesas: rcar-usb2-clock-sel: Fix typo in example
- regulator: ab8500: Remove AB8505 USB regulator
- media: flexcop-usb: ensure -EIO is returned on error condition
- Bluetooth: Fix memory leak in hci_connect_le_scan
- Bluetooth: delete a stray unlock
- Bluetooth: btusb: fix PM leak in error case of setup
- platform/x86: pmc_atom: Add Siemens CONNECT X300 to critclk_systems DMI table
- xfs: don't check for AG deadlock for realtime files in bunmapi
- ACPI: sysfs: Change ACPI_MASKABLE_GPE_MAX to 0x100
- HID: i2c-hid: Reset ALPS touchpads on resume
- nfsd4: fix up replay_matches_cache()
- PM / devfreq: Check NULL governor in available_governors_show
- drm/msm: include linux/sched/task.h
- ftrace: Avoid potential division by zero in function profiler
- arm64: Revert support for execute-only user mappings
- exit: panic before exit_mm() on global init exit
- ALSA: firewire-motu: Correct a typo in the clock proc string
- ALSA: cs4236: fix error return comparison of an unsigned integer
- apparmor: fix aa_xattrs_match() may sleep while holding a RCU lock
- tracing: Fix endianness bug in histogram trigger
- tracing: Have the histogram compare functions convert to u64 first
- tracing: Avoid memory leak in process_system_preds()
- tracing: Fix lock inversion in trace_event_enable_tgid_record()
- rseq/selftests: Fix: Namespace gettid() for compatibility with glibc 2.30
- riscv: ftrace: correct the condition logic in function graph tracer
- gpiolib: fix up emulated open drain outputs
- libata: Fix retrieving of active qcs
- ata: ahci_brcm: BCM7425 AHCI requires AHCI_HFLAG_DELAY_ENGINE
- ata: ahci_brcm: Add missing clock management during recovery
- ata: ahci_brcm: Allow optional reset controller to be used
- ata: ahci_brcm: Fix AHCI resources management
- ata: libahci_platform: Export again ahci_platform_<en/dis>able_phys()
- compat_ioctl: block: handle BLKREPORTZONE/BLKRESETZONE
- compat_ioctl: block: handle Persistent Reservations
- dmaengine: Fix access to uninitialized dma_slave_caps
- locks: print unsigned ino in /proc/locks
- pstore/ram: Write new dumps to start of recycled zones
- mm: move_pages: return valid node id in status if the page is already on the target node
- memcg: account security cred as well to kmemcg
- mm/zsmalloc.c: fix the migrated zspage statistics.
- media: cec: check 'transmit_in_progress', not 'transmitting'
- media: cec: avoid decrementing transmit_queue_sz if it is 0
- media: cec: CEC 2.0-only bcast messages were ignored
- media: pulse8-cec: fix lost cec_transmit_attempt_done() call
- MIPS: Avoid VDSO ABI breakage due to global register variable
- drm/sun4i: hdmi: Remove duplicate cleanup calls
- ALSA: hda/realtek - Add headset Mic no shutup for ALC283
- ALSA: usb-audio: set the interface format after resume on Dell WD19
- ALSA: usb-audio: fix set_format altsetting sanity check
- ALSA: ice1724: Fix sleep-in-atomic in Infrasonic Quartet support code
- netfilter: nft_tproxy: Fix port selector on Big Endian
- drm: limit to INT_MAX in create_blob ioctl
- taskstats: fix data-race
- xfs: fix mount failure crash on invalid iclog memory access
- ALSA: hda - fixup for the bass speaker on Lenovo Carbon X1 7th gen
- ALSA: hda/realtek - Enable the bass speaker of ASUS UX431FLC
- ALSA: hda/realtek - Add Bass Speaker and fixed dac for bass speaker
- PM / hibernate: memory_bm_find_bit(): Tighten node optimisation
- xen/balloon: fix ballooned page accounting without hotplug enabled
- xen-blkback: prevent premature module unload
- IB/mlx5: Fix steering rule of drop and count
- IB/mlx4: Follow mirror sequence of device add during device removal
- s390/cpum_sf: Avoid SBD overflow condition in irq handler
- s390/cpum_sf: Adjust sampling interval to avoid hitting sample limits
- md: raid1: check rdev before reference in raid1_sync_request func
- afs: Fix creation calls in the dynamic root to fail with EOPNOTSUPP
- net: make socket read/write_iter() honor IOCB_NOWAIT
- usb: gadget: fix wrong endpoint desc
- drm/nouveau: Move the declaration of struct nouveau_conn_atom up a bit
- scsi: iscsi: qla4xxx: fix double free in probe
- scsi: qla2xxx: Ignore PORT UPDATE after N2N PLOGI
- scsi: qla2xxx: Send Notify ACK after N2N PLOGI
- scsi: qla2xxx: Configure local loop for N2N target
- scsi: qla2xxx: Fix PLOGI payload and ELS IOCB dump length
- scsi: qla2xxx: Don't call qlt_async_event twice
- scsi: qla2xxx: Drop superfluous INIT_WORK of del_work
- scsi: lpfc: Fix memory leak on lpfc_bsg_write_ebuf_set func
- rxe: correctly calculate iCRC for unaligned payloads
- RDMA/cma: add missed unregister_pernet_subsys in init failure
- afs: Fix SELinux setting security label on /afs
- afs: Fix afs_find_server lookups for ipv4 peers
- PM / devfreq: Don't fail devfreq_dev_release if not in list
- PM / devfreq: Set scaling_max_freq to max on OPP notifier error
- PM / devfreq: Fix devfreq_notifier_call returning errno
- iio: adc: max9611: Fix too short conversion time delay
- drm/amd/display: Fixed kernel panic when booting with DP-to-HDMI dongle
- drm/amdgpu: add cache flush workaround to gfx8 emit_fence
- drm/amdgpu: add check before enabling/disabling broadcast mode
- nvme-fc: fix double-free scenarios on hw queues
- nvme_fc: add module to ops template to allow module references
- spi: fsl: use platform_get_irq() instead of of_irq_to_resource()
- pinctrl: baytrail: Really serialize all register accesses
- tty/serial: atmel: fix out of range clock divider handling
- spi: fsl: don't map irq during probe
- gtp: avoid zero size hashtable
- gtp: fix an use-after-free in ipv4_pdp_find()
- gtp: fix wrong condition in gtp_genl_dump_pdp()
- tcp: do not send empty skb from tcp_write_xmit()
- tcp/dccp: fix possible race __inet_lookup_established()
- net: marvell: mvpp2: phylink requires the link interrupt
- gtp: do not allow adding duplicate tid and ms_addr pdp context
- net/dst: do not confirm neighbor for vxlan and geneve pmtu update
- sit: do not confirm neighbor when do pmtu update
- vti: do not confirm neighbor when do pmtu update
- tunnel: do not confirm neighbor when do pmtu update
- net/dst: add new function skb_dst_update_pmtu_no_confirm
- gtp: do not confirm neighbor when do pmtu update
- ip6_gre: do not confirm neighbor when do pmtu update
- net: add bool confirm_neigh parameter for dst_ops.update_pmtu
- vhost/vsock: accept only packets with the right dst_cid
- udp: fix integer overflow while computing available space in sk_rcvbuf
- tcp: Fix highest_sack and highest_sack_seq
- ptp: fix the race between the release of ptp_clock and cdev
- net: stmmac: dwmac-meson8b: Fix the RGMII TX delay on Meson8b/8m2 SoCs
- net/mlxfw: Fix out-of-memory error in mfa2 flash burning
- net: ena: fix napi handler misbehavior when the napi budget is zero
- hrtimer: Annotate lockless access to timer->state
- net: icmp: fix data-race in cmp_global_allow()
- net: add a READ_ONCE() in skb_peek_tail()
- inetpeer: fix data-race in inet_putpeer / inet_putpeer
- netfilter: bridge: make sure to pull arp header in br_nf_forward_arp()
- 6pack,mkiss: fix possible deadlock
- netfilter: ebtables: compat: reject all padding in matches/watchers
- bonding: fix active-backup transition after link failure
- ALSA: hda - Downgrade error message for single-cmd fallback
- netfilter: nf_queue: enqueue skbs with NULL dst
- net, sysctl: Fix compiler warning when only cBPF is present
- x86/mce: Fix possibly incorrect severity calculation on AMD
- Revert "powerpc/vcpu: Assume dedicated processors as non-preempt"
- userfaultfd: require CAP_SYS_PTRACE for UFFD_FEATURE_EVENT_FORK
- kernel: sysctl: make drop_caches write-only
- mailbox: imx: Fix Tx doorbell shutdown path
- ocfs2: fix passing zero to 'PTR_ERR' warning
- s390/cpum_sf: Check for SDBT and SDB consistency
- libfdt: define INT32_MAX and UINT32_MAX in libfdt_env.h
- s390/zcrypt: handle new reply code FILTERED_BY_HYPERVISOR
- perf regs: Make perf_reg_name() return "unknown" instead of NULL
- perf script: Fix brstackinsn for AUXTRACE
- cdrom: respect device capabilities during opening action
- powerpc: Don't add -mabi= flags when building with Clang
- scripts/kallsyms: fix definitely-lost memory leak
- apparmor: fix unsigned len comparison with less than zero
- gpio: mpc8xxx: Don't overwrite default irq_set_type callback
- scsi: target: iscsi: Wait for all commands to finish before freeing a session
- scsi: iscsi: Don't send data to unbound connection
- scsi: NCR5380: Add disconnect_mask module parameter
- scsi: scsi_debug: num_tgts must be >= 0
- scsi: ufs: Fix error handing during hibern8 enter
- scsi: pm80xx: Fix for SATA device discovery
- watchdog: Fix the race between the release of watchdog_core_data and cdev
- HID: rmi: Check that the RMI_STARTED bit is set before unregistering the RMI transport device
- HID: Improve Windows Precision Touchpad detection.
- libnvdimm/btt: fix variable 'rc' set but not used
- ARM: 8937/1: spectre-v2: remove Brahma-B53 from hardening
- HID: logitech-hidpp: Silence intermittent get_battery_capacity errors
- HID: quirks: Add quirk for HP MSU1465 PIXART OEM mouse
- bcache: at least try to shrink 1 node in bch_mca_scan()
- clk: pxa: fix one of the pxa RTC clocks
- scsi: atari_scsi: sun3_scsi: Set sg_tablesize to 1 instead of SG_NONE
- powerpc/security: Fix wrong message when RFI Flush is disable
- PCI: rpaphp: Correctly match ibm, my-drc-index to drc-name when using drc-info
- PCI: rpaphp: Annotate and correctly byte swap DRC properties
- PCI: rpaphp: Don't rely on firmware feature to imply drc-info support
- powerpc/pseries/cmm: Implement release() function for sysfs device
- scsi: ufs: fix potential bug which ends in system hang
- PCI: rpaphp: Fix up pointer to first drc-info entry
- scsi: lpfc: fix: Coverity: lpfc_cmpl_els_rsp(): Null pointer dereferences
- fs/quota: handle overflows of sysctl fs.quota.* and report as unsigned long
- irqchip: ingenic: Error out if IRQ domain creation failed
- irqchip/irq-bcm7038-l1: Enable parent IRQ if necessary
- clk: clk-gpio: propagate rate change to parent
- clk: qcom: Allow constant ratio freq tables for rcg
- f2fs: fix to update dir's i_pino during cross_rename
- scsi: lpfc: Fix duplicate unreg_rpi error in port offline flow
- scsi: tracing: Fix handling of TRANSFER LENGTH == 0 for READ(6) and WRITE(6)
- jbd2: Fix statistics for the number of logged blocks
- ext4: iomap that extends beyond EOF should be marked dirty
- powerpc/book3s64/hash: Add cond_resched to avoid soft lockup warning
- powerpc/security/book3s64: Report L1TF status in sysfs
- clocksource/drivers/timer-of: Use unique device name instead of timer
- clocksource/drivers/asm9260: Add a check for of_clk_get
- leds: lm3692x: Handle failure to probe the regulator
- dma-debug: add a schedule point in debug_dma_dump_mappings()
- powerpc/tools: Don't quote $objdump in scripts
- powerpc/pseries: Don't fail hash page table insert for bolted mapping
- powerpc/pseries: Mark accumulate_stolen_time() as notrace
- scsi: hisi_sas: Replace in_softirq() check in hisi_sas_task_exec()
- scsi: csiostor: Don't enable IRQs too early
- scsi: lpfc: Fix SLI3 hba in loop mode not discovering devices
- scsi: target: compare full CHAP_A Algorithm strings
- dmaengine: xilinx_dma: Clear desc_pendingcount in xilinx_dma_reset
- iommu/tegra-smmu: Fix page tables in > 4 GiB memory
- iommu: rockchip: Free domain on .domain_free
- f2fs: fix to update time in lazytime mode
- Input: atmel_mxt_ts - disable IRQ across suspend
- scsi: lpfc: Fix locking on mailbox command completion
- scsi: mpt3sas: Fix clear pending bit in ioctl status
- scsi: lpfc: Fix discovery failures when target device connectivity bounces
- perf probe: Fix to show function entry line as probe-able
- mmc: sdhci: Add a quirk for broken command queuing
- mmc: sdhci: Workaround broken command queuing on Intel GLK
- mmc: sdhci-of-esdhc: fix P2020 errata handling
- mmc: sdhci: Update the tuning failed messages to pr_debug level
- mmc: sdhci-of-esdhc: Revert "mmc: sdhci-of-esdhc: add erratum A-009204 support"
- mmc: sdhci-msm: Correct the offset and value for DDR_CONFIG register
- powerpc/irq: fix stack overflow verification
- powerpc/vcpu: Assume dedicated processors as non-preempt
- x86/MCE/AMD: Allow Reserved types to be overwritten in smca_banks[]
- x86/MCE/AMD: Do not use rdmsr_safe_on_cpu() in smca_configure()
- KVM: arm64: Ensure 'params' is initialised when looking up sys register
- ext4: unlock on error in ext4_expand_extra_isize()
- staging: comedi: gsc_hpdi: check dma_alloc_coherent() return value
- platform/x86: hp-wmi: Make buffer for HPWMI_FEATURE2_QUERY 128 bytes
- intel_th: pci: Add Elkhart Lake SOC support
- intel_th: pci: Add Comet Lake PCH-V support
- USB: EHCI: Do not return -EPIPE when hub is disconnected
- cpufreq: Avoid leaving stale IRQ work items during CPU offline
- usbip: Fix error path of vhci_recv_ret_submit()
- usbip: Fix receive error in vhci-hcd when using scatter-gather
- btrfs: return error pointer from alloc_test_extent_buffer
- s390/ftrace: fix endless recursion in function_graph tracer
- drm/amdgpu: fix uninitialized variable pasid_mapping_needed
- usb: xhci: Fix build warning seen with CONFIG_PM=n
- can: kvaser_usb: kvaser_usb_leaf: Fix some info-leaks to USB devices
- mmc: mediatek: fix CMD_TA to 2 for MT8173 HS200/HS400 mode
- Revert "mmc: sdhci: Fix incorrect switch to HS mode"
- btrfs: don't prematurely free work in scrub_missing_raid56_worker()
- btrfs: don't prematurely free work in reada_start_machine_worker()
- net: phy: initialise phydev speed and duplex sanely
- drm/amdgpu: fix bad DMA from INTERRUPT_CNTL2
- mips: fix build when "48 bits virtual memory" is enabled
- libtraceevent: Fix memory leakage in copy_filter_type
- crypto: vmx - Avoid weird build failures
- mac80211: consider QoS Null frames for STA_NULLFUNC_ACKED
- crypto: sun4i-ss - Fix 64-bit size_t warnings on sun4i-ss-hash.c
- crypto: sun4i-ss - Fix 64-bit size_t warnings
- net: ethernet: ti: ale: clean ale tbl on init and intf restart
- fbtft: Make sure string is NULL terminated
- iwlwifi: check kasprintf() return value
- brcmfmac: remove monitor interface when detaching
- x86/insn: Add some Intel instructions to the opcode map
- ASoC: Intel: bytcr_rt5640: Update quirk for Acer Switch 10 SW5-012 2-in-1
- ASoC: wm5100: add missed pm_runtime_disable
- spi: st-ssc4: add missed pm_runtime_disable
- ASoC: wm2200: add missed operations in remove and probe failure
- btrfs: don't prematurely free work in run_ordered_work()
- btrfs: don't prematurely free work in end_workqueue_fn()
- mmc: tmio: Add MMC_CAP_ERASE to allow erase/discard/trim requests
- crypto: virtio - deal with unsupported input sizes
- tun: fix data-race in gro_normal_list()
- spi: tegra20-slink: add missed clk_unprepare
- ASoC: wm8904: fix regcache handling
- iwlwifi: mvm: fix unaligned read of rx_pkt_status
- bcache: fix deadlock in bcache_allocator
- tracing/kprobe: Check whether the non-suffixed symbol is notrace
- tracing: use kvcalloc for tgid_map array allocation
- x86/crash: Add a forward declaration of struct kimage
- cpufreq: Register drivers only after CPU devices have been registered
- bcache: fix static checker warning in bcache_device_free()
- parport: load lowlevel driver if ports not found
- nvme: Discard workaround for non-conformant devices
- s390/disassembler: don't hide instruction addresses
- ASoC: Intel: kbl_rt5663_rt5514_max98927: Add dmic format constraint
- iio: dac: ad5446: Add support for new AD5600 DAC
- ASoC: rt5677: Mark reg RT5677_PWR_ANLG2 as volatile
- spi: pxa2xx: Add missed security checks
- EDAC/ghes: Fix grain calculation
- media: si470x-i2c: add missed operations in remove
- ice: delay less
- crypto: atmel - Fix authenc support when it is set to m
- soundwire: intel: fix PDI/stream mapping for Bulk
- media: pvrusb2: Fix oops on tear-down when radio support is not present
- fsi: core: Fix small accesses and unaligned offsets via sysfs
- ath10k: fix get invalid tx rate for Mesh metric
- perf probe: Filter out instances except for inlined subroutine and subprogram
- perf probe: Skip end-of-sequence and non statement lines
- perf probe: Fix to show calling lines of inlined functions
- perf probe: Return a better scope DIE if there is no best scope
- perf probe: Skip overlapped location on searching variables
- perf parse: If pmu configuration fails free terms
- xen/gntdev: Use select for DMA_SHARED_BUFFER
- drm/amdgpu: fix potential double drop fence reference
- drm/amdgpu: disallow direct upload save restore list from gfx driver
- perf tools: Splice events onto evlist even on error
- perf probe: Fix to probe a function which has no entry pc
- libsubcmd: Use -O0 with DEBUG=1
- perf probe: Fix to show inlined function callsite without entry_pc
- perf probe: Fix to show ranges of variables in functions without entry_pc
- perf probe: Fix to probe an inline function which has no entry pc
- perf probe: Walk function lines in lexical blocks
- perf jevents: Fix resource leak in process_mapfile() and main()
- perf probe: Fix to list probe event with correct line number
- perf probe: Fix to find range-only function instance
- rtlwifi: fix memory leak in rtl92c_set_fw_rsvdpagepkt()
- ALSA: timer: Limit max amount of slave instances
- spi: img-spfi: fix potential double release
- bnx2x: Fix PF-VF communication over multi-cos queues.
- rfkill: allocate static minor
- nvmem: imx-ocotp: reset error status on probe
- media: v4l2-core: fix touch support in v4l_g_fmt
- ixgbe: protect TX timestamping from API misuse
- pinctrl: amd: fix __iomem annotation in amd_gpio_irq_handler()
- Bluetooth: Fix advertising duplicated flags
- libbpf: Fix error handling in bpf_map__reuse_fd()
- iio: dln2-adc: fix iio_triggered_buffer_postenable() position
- pinctrl: sh-pfc: sh7734: Fix duplicate TCLK1_B
- loop: fix no-unmap write-zeroes request behavior
- libata: Ensure ata_port probe has completed before detach
- s390/mm: add mm_pxd_folded() checks to pxd_free()
- s390/time: ensure get_clock_monotonic() returns monotonic values
- phy: qcom-usb-hs: Fix extcon double register after power cycle
- net: dsa: LAN9303: select REGMAP when LAN9303 enable
- gpu: host1x: Allocate gather copy for host1x
- RDMA/qedr: Fix memory leak in user qp and mr
- ACPI: button: Add DMI quirk for Medion Akoya E2215T
- spi: sprd: adi: Add missing lock protection when rebooting
- drm/tegra: sor: Use correct SOR index on Tegra210
- net: phy: dp83867: enable robust auto-mdix
- i40e: initialize ITRN registers with correct values
- arm64: psci: Reduce the waiting time for cpu_psci_cpu_kill()
- md/bitmap: avoid race window between md_bitmap_resize and bitmap_file_clear_bit
- media: smiapp: Register sensor after enabling runtime PM on the device
- x86/ioapic: Prevent inconsistent state when moving an interrupt
- ipmi: Don't allow device module unload when in use
- rtl8xxxu: fix RTL8723BU connection failure issue after warm reboot
- drm/gma500: fix memory disclosures due to uninitialized bytes
- perf tests: Disable bp_signal testing for arm64
- x86/mce: Lower throttling MCE messages' priority to warning
- bpf/stackmap: Fix deadlock with rq_lock in bpf_get_stack()
- Bluetooth: hci_core: fix init for HCI_USER_CHANNEL
- Bluetooth: Workaround directed advertising bug in Broadcom controllers
- Bluetooth: missed cpu_to_le16 conversion in hci_init4_req
- iio: adc: max1027: Reset the device at probe time
- usb: usbfs: Suppress problematic bind and unbind uevents.
- perf report: Add warning when libunwind not compiled in
- perf test: Report failure for mmap events
- drm/bridge: dw-hdmi: Restore audio when setting a mode
- ath10k: Correct error handling of dma_map_single()
- x86/mm: Use the correct function type for native_set_fixmap()
- extcon: sm5502: Reset registers during initialization
- drm/amd/display: Fix dongle_caps containing stale information.
- syscalls/x86: Use the correct function type in SYSCALL_DEFINE0
- media: ti-vpe: vpe: fix a v4l2-compliance failure about invalid sizeimage
- media: ti-vpe: vpe: ensure buffers are cleaned up properly in abort cases
- media: ti-vpe: vpe: fix a v4l2-compliance failure causing a kernel panic
- media: ti-vpe: vpe: Make sure YUYV is set as default format
- media: ti-vpe: vpe: fix a v4l2-compliance failure about frame sequence number
- media: ti-vpe: vpe: fix a v4l2-compliance warning about invalid pixel format
- media: ti-vpe: vpe: Fix Motion Vector vpdma stride
- media: cx88: Fix some error handling path in 'cx8800_initdev()'
- drm/drm_vblank: Change EINVAL by the correct errno
- block: Fix writeback throttling W=1 compiler warnings
- samples: pktgen: fix proc_cmd command result check logic
- drm/bridge: dw-hdmi: Refuse DDC/CI transfers on the internal I2C controller
- media: cec-funcs.h: add status_req checks
- media: flexcop-usb: fix NULL-ptr deref in flexcop_usb_transfer_init()
- regulator: max8907: Fix the usage of uninitialized variable in max8907_regulator_probe()
- hwrng: omap3-rom - Call clk_disable_unprepare() on exit only if not idled
- usb: renesas_usbhs: add suspend event support in gadget mode
- media: venus: Fix occasionally failures to suspend
- selftests/bpf: Correct path to include msg + path
- pinctrl: devicetree: Avoid taking direct reference to device name string
- ath10k: fix offchannel tx failure when no ath10k_mac_tx_frm_has_freq
- media: venus: core: Fix msm8996 frequency table
- tools/power/cpupower: Fix initializer override in hsw_ext_cstates
- media: ov6650: Fix stored crop rectangle not in sync with hardware
- media: ov6650: Fix stored frame format not in sync with hardware
- media: i2c: ov2659: Fix missing 720p register config
- media: ov6650: Fix crop rectangle alignment not passed back
- media: i2c: ov2659: fix s_stream return value
- media: am437x-vpfe: Setting STD to current value is not an error
- IB/iser: bound protection_sg size by data_sg size
- ath10k: fix backtrace on coredump
- staging: rtl8188eu: fix possible null dereference
- staging: rtl8192u: fix multiple memory leaks on error path
- spi: Add call to spi_slave_abort() function when spidev driver is released
- drm/amdgpu: grab the id mgr lock while accessing passid_mapping
- iio: light: bh1750: Resolve compiler warning and make code more readable
- drm/bridge: analogix-anx78xx: silence -EPROBE_DEFER warnings
- drm/panel: Add missing drm_panel_init() in panel drivers
- drm: mst: Fix query_payload ack reply struct
- ALSA: hda/ca0132 - Fix work handling in delayed HP detection
- ALSA: hda/ca0132 - Avoid endless loop
- ALSA: hda/ca0132 - Keep power on during processing DSP response
- ALSA: pcm: Avoid possible info leaks from PCM stream buffers
- Btrfs: fix removal logic of the tree mod log that leads to use-after-free issues
- btrfs: handle ENOENT in btrfs_uuid_tree_iterate
- btrfs: do not leak reloc root if we fail to read the fs root
- btrfs: skip log replay on orphaned roots
- btrfs: abort transaction after failed inode updates in create_subvol
- btrfs: send: remove WARN_ON for readonly mount
- Btrfs: fix missing data checksums after replaying a log tree
- btrfs: do not call synchronize_srcu() in inode_tree_del
- btrfs: don't double lock the subvol_sem for rename exchange
- selftests: forwarding: Delete IPv6 address at the end
- sctp: fully initialize v4 addr in some functions
- qede: Fix multicast mac configuration
- qede: Disable hardware gro when xdp prog is installed
- net: usb: lan78xx: Fix suspend/resume PHY register access error
- net: qlogic: Fix error paths in ql_alloc_large_buffers()
- net: nfc: nci: fix a possible sleep-in-atomic-context bug in nci_uart_tty_receive()
- net: hisilicon: Fix a BUG trigered by wrong bytes_compl
- net: gemini: Fix memory leak in gmac_setup_txqs
- net: dst: Force 4-byte alignment of dst_metrics
- mod_devicetable: fix PHY module format
- fjes: fix missed check in fjes_acpi_add
- sock: fix potential memory leak in proto_register()
- arm64/sve: Fix missing SVE/FPSIMD endianness conversions
- svm: Delete ifdef CONFIG_ACPI in svm
- svm: Delete svm_unbind_cores() in svm_notifier_release call
- svm: Fix unpin_memory calculate nr_pages error
- vrf: Do not attempt to create IPv6 mcast rule if IPv6 is disabled
- iommu: Add missing new line for dma type
- xhci: fix USB3 device initiated resume race with roothub autosuspend
- drm/radeon: fix r1xx/r2xx register checker for POT textures
- scsi: iscsi: Fix a potential deadlock in the timeout handler
- dm mpath: remove harmful bio-based optimization
- drm: meson: venc: cvbs: fix CVBS mode matching
- dma-buf: Fix memory leak in sync_file_merge()
- vfio/pci: call irq_bypass_unregister_producer() before freeing irq
- ARM: tegra: Fix FLOW_CTLR_HALT register clobbering by tegra_resume()
- ARM: dts: s3c64xx: Fix init order of clock providers
- CIFS: Close open handle after interrupted close
- CIFS: Respect O_SYNC and O_DIRECT flags during reconnect
- cifs: Don't display RDMA transport on reconnect
- cifs: smbd: Return -EINVAL when the number of iovs exceeds SMBDIRECT_MAX_SGE
- cifs: smbd: Add messages on RDMA session destroy and reconnection
- cifs: smbd: Return -EAGAIN when transport is reconnecting
- rpmsg: glink: Free pending deferred work on remove
- rpmsg: glink: Don't send pending rx_done during remove
- rpmsg: glink: Fix rpmsg_register_device err handling
- rpmsg: glink: Put an extra reference during cleanup
- rpmsg: glink: Fix use after free in open_ack TIMEOUT case
- rpmsg: glink: Fix reuse intents memory leak issue
- rpmsg: glink: Set tail pointer to 0 at end of FIFO
- xtensa: fix TLB sanity checker
- PCI: Apply Cavium ACS quirk to ThunderX2 and ThunderX3
- PCI/MSI: Fix incorrect MSI-X masking on resume
- PCI: Fix Intel ACS quirk UPDCR register address
- PCI/PM: Always return devices to D0 when thawing
- mmc: block: Add CMD13 polling for MMC IOCTLS with R1B response
- mmc: block: Make card_busy_detect() a bit more generic
- Revert "arm64: preempt: Fix big-endian when checking preempt count in assembly"
- tcp: Protect accesses to .ts_recent_stamp with {READ, WRITE}_ONCE()
- tcp: tighten acceptance of ACKs not matching a child socket
- tcp: fix rejected syncookies due to stale timestamps
- net/mlx5e: Query global pause state before setting prio2buffer
- tipc: fix ordering of tipc module init and exit routine
- tcp: md5: fix potential overestimation of TCP option space
- openvswitch: support asymmetric conntrack
- net: thunderx: start phy before starting autonegotiation
- net: sched: fix dump qlen for sch_mq/sch_mqprio with NOLOCK subqueues
- net: ethernet: ti: cpsw: fix extra rx interrupt
- net: dsa: fix flow dissection on Tx path
- net: bridge: deny dev_set_mac_address() when unregistering
- mqprio: Fix out-of-bounds access in mqprio_dump
- inet: protect against too small mtu values.
- ext4: check for directory entries too close to block end
- ext4: fix ext4_empty_dir() for directories with holes

* Mon Jan 13 2020 luochunsheng<luochunsheng@huawei.com> - 4.19.90-vhulk1912.2.1.0026
- fix compile error when debugfiles.list is empty

* Mon Jan 13 2020 luochunsheng<luochunsheng@huawei.com> - 4.19.90-vhulk1912.2.1.0025
- update kernel code from https://gitee.com/openeuler/kernel/ 

* Mon Jan 06 2020 zhanghailiang<zhang.zhanghailiang@huawei.com> - 4.19.90-vhulk1912.2.1.0024
- support more than 256 vcpus for VM

* Tue Dec 31 2019 linfeilong<linfeilong@huawei.com> - 4.19.90-vhulk1912.2.1.0023
- delete some unuseful file

* Mon Dec 30 2019 yuxiangyang<yuxiangyang4@huawei.com> - 4.19.90-vhulk1912.2.1.0022
- update Huawei copyright

* Mon Dec 30 2019 caomeng<caomeng5@huawei.com> - 4.19.90-vhulk1912.2.1.0021
- modefied README.md

* Sat Dec 28 2019 caomeng<caomeng5@huawei.com> - 4.19.90-vhulk1912.2.1.0020
- change tag and change config_ktask

* Sat Dec 28 2019 caomeng<caomeng5@huawei.com> - 4.19.90-vhulk1907.1.0.0019
- modefied license

* Wed Dec 25 2019 luochunsheng<luochunsheng@huawei.com> - 4.19.90-vhulk1907.1.0.0018
- update Module.kabi_aarch64
- fix patch kernel-SMMU-V3-support-Virtualization-with-3408iMR-3.patch

* Tue Dec 24 2019 Pan Zhang<zhangpan26@huawei.com> - 4.19.90-vhulk1907.1.0.0017
- fix get_user_pages_fast with evmm issue

* Tue Dec 24 2019 caihongda <caihongda@huawei.com> - 4.19.90-vhulk1907.1.0.0016
- cpu/freq:remove unused patches

* Tue Dec 24 2019 shenkai <shenkai8@huawei.com> - 4.19.90-vhulk1907.1.0.0015
- modify vmap allocation start address

* Tue Dec 24 2019 caomeng<caomeng5@huawei.com> - 4.19.90-vhulk1907.1.0.0014
- fix some problem about rebase hulk

* Mon Dec 23 2019 yuxiangyang<yuxiangyang4@huawei.com> - 4.19.90-vhulk1907.1.0.0013
- fix CONFIG_EULEROS_USE_IDLE_NO_CSTATES compile error
- add a new method of cpu usage

* Mon Dec 23 2019 caomeng <caomeng5@huawei.com> - 4.19.90-vhulk1907.1.0.0012
- change version

* Mon Dec 23 2019 luochunsheng <luochunsheng@huawei.com> - 4.19.36-vhulk1907.1.0.0011
- fix mkgrub-menu-*.sh path
- SMMU supports bypass of configured PCI devices by cmdline smmu.bypassdev

* Mon Dec 23 2019 chenmaodong<chenmaodong@huawei.com> - 4.19.36-vhulk1907.1.0.0010
- drm/radeon: Fix potential buffer overflow in ci_dpm.c

* Mon Dec 23 2019 wuxu<wuxu.wu@huawei.com> - 4.19.36-vhulk1907.1.0.0009
- add security compile noexecstack option for vdso

* Mon Dec 23 2019 caomeng<caomeng5@huawei.com> - 4.19.36-vhulk1907.1.0.0008
- rebase hulk patches

* Fri Dec 20 2019 yeyunfeng<yeyunfeng@huawei.com> - 4.19.36-vhulk1907.1.0.0007
- perf/smmuv3: fix possible sleep in preempt context
- crypto: user - prevent operating on larval algorithms

* Thu Dec 19 2019 luochunsheng <luochunsheng@huawei.com> - 4.19.36-vhulk1907.1.0.0006
- update release to satisfy upgrade

* Wed Nov 27 2019 lihongjiang <lihongjiang6@huawei.com> - 4.19.36-vhulk1907.1.0.h005
- change page size from 4K to 64K

* Thu Nov 21 2019 caomeng <caomeng5@huawei.com> - 4.19.36-vhulk1907.1.0.h004
- fix problem about x86 compile: change signing_key.pem to certs/signing_key.pem
- in file arch/x86/configs/euleros_defconfig

* Mon Nov 4 2019 caomeng <caomeng5@huawei.com> - 4.19.36-vhulk1907.1.0.h003
- Add buildrequires ncurlses-devel

* Fri Oct 25 2019 luochunsheng <luochunsheng@huawei.com> - 4.19.36-vhulk1907.1.0.h002
- Add vmlinx to debuginfo package and add kernel-source package

* Wed Sep 04 2019 openEuler Buildteam <buildteam@openeuler.org> - 4.19.36-vhulk1907.1.0.h001
- Package init
