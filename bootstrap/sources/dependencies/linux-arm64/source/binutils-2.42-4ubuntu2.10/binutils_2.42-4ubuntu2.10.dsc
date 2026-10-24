-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: binutils
Binary: binutils-for-host, binutils-for-build, binutils, libctf-nobfd0, libctf-nobfd0-dbg, libctf0, libctf0-dbg, libgprofng0, libgprofng0-dbg, libsframe1, libsframe1-dbg, libbinutils, libbinutils-dbg, binutils-dev, binutils-multiarch, binutils-multiarch-dbg, binutils-multiarch-dev, binutils-hppa64-linux-gnu, binutils-hppa64-linux-gnu-dbg, binutils-doc, binutils-source, binutils-common, binutils-x86-64-linux-gnu, binutils-x86-64-linux-gnu-dbg, binutils-i686-linux-gnu, binutils-i686-linux-gnu-dbg, binutils-aarch64-linux-gnu, binutils-aarch64-linux-gnu-dbg, binutils-arm-linux-gnueabihf, binutils-arm-linux-gnueabihf-dbg, binutils-arm-linux-gnueabi, binutils-arm-linux-gnueabi-dbg, binutils-powerpc64le-linux-gnu, binutils-powerpc64le-linux-gnu-dbg, binutils-s390x-linux-gnu, binutils-s390x-linux-gnu-dbg, binutils-alpha-linux-gnu, binutils-alpha-linux-gnu-dbg, binutils-arc-linux-gnu, binutils-arc-linux-gnu-dbg, binutils-hppa-linux-gnu, binutils-hppa-linux-gnu-dbg,
 binutils-ia64-linux-gnu, binutils-ia64-linux-gnu-dbg, binutils-loongarch64-linux-gnu, binutils-loongarch64-linux-gnu-dbg, binutils-m68k-linux-gnu, binutils-m68k-linux-gnu-dbg, binutils-powerpc-linux-gnu, binutils-powerpc-linux-gnu-dbg, binutils-powerpc64-linux-gnu, binutils-powerpc64-linux-gnu-dbg, binutils-riscv64-linux-gnu, binutils-riscv64-linux-gnu-dbg, binutils-sh4-linux-gnu, binutils-sh4-linux-gnu-dbg, binutils-sparc64-linux-gnu, binutils-sparc64-linux-gnu-dbg, binutils-x86-64-linux-gnux32, binutils-x86-64-linux-gnux32-dbg, binutils-x86-64-gnu, binutils-x86-64-gnu-dbg, binutils-i686-gnu, binutils-i686-gnu-dbg, binutils-x86-64-kfreebsd-gnu, binutils-x86-64-kfreebsd-gnu-dbg, binutils-i686-kfreebsd-gnu,
 binutils-i686-kfreebsd-gnu-dbg
Architecture: any all
Version: 2.42-4ubuntu2.10
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Uploaders: James Troup <binutils@elmo.tasta.io>
Homepage: https://www.gnu.org/software/binutils/
Standards-Version: 4.6.2
Vcs-Browser: https://salsa.debian.org/toolchain-team/binutils
Vcs-Git: https://salsa.debian.org/toolchain-team/binutils.git
Testsuite: autopkgtest
Testsuite-Triggers: autoconf, bison, build-essential, chrpath, debugedit, dejagnu, dwz, fakeroot, file, flex, gettext, libjansson-dev, libstdc++-dev, lsb-release, pkg-config, procps, python3, quilt, texinfo, xz-utils, zlib1g-dev
Build-Depends: autoconf (>= 2.64), dpkg-dev (>= 1.19.0.5), bison, flex, gettext, texinfo, dejagnu, quilt, chrpath, dwz, debugedit (>= 4.16), python3:any, file, xz-utils, lsb-release, zlib1g-dev, procps, help2man, libjansson-dev, pkg-config, libzstd-dev, g++-aarch64-linux-gnu [amd64 i386 ppc64el s390x x32] <!nocheck>, g++-arm-linux-gnueabi [amd64 arm64 i386 x32] <!nocheck>, g++-arm-linux-gnueabihf [amd64 arm64 i386 ppc64el s390x x32] <!nocheck>, g++-powerpc64le-linux-gnu [amd64 arm64 i386 ppc64 s390x x32] <!nocheck>, g++-s390x-linux-gnu [amd64 arm64 i386 ppc64el x32] <!nocheck>, g++-alpha-linux-gnu [amd64 i386 x32] <!nocheck>, g++-hppa-linux-gnu [amd64 i386 x32] <!nocheck>, g++-m68k-linux-gnu [amd64 i386 x32] <!nocheck>, g++-powerpc-linux-gnu [amd64 i386 ppc64el s390x x32] <!nocheck>, g++-powerpc64-linux-gnu [amd64 i386 s390x x32] <!nocheck>, g++-riscv64-linux-gnu [amd64 arm64 i386 ppc64el s390x x32] <!nocheck>, g++-sh4-linux-gnu [amd64 i386 x32] <!nocheck>, g++-sparc64-linux-gnu [amd64 i386 x32] <!nocheck>, g++-i686-linux-gnu [amd64 arm64 ppc64el s390x x32] <!nocheck>, g++-x86-64-linux-gnu [arm64 i386 ppc64el s390x] <!nocheck>, g++-x86-64-linux-gnux32 [amd64 arm64 i386 ppc64el] <!nocheck>
Build-Conflicts: libelf-dev
Package-List:
 binutils deb devel optional arch=any
 binutils-aarch64-linux-gnu deb devel optional arch=arm64,amd64,i386,x32,ppc64el,s390x
 binutils-aarch64-linux-gnu-dbg deb debug optional arch=arm64,amd64,i386,x32,ppc64el,s390x
 binutils-alpha-linux-gnu deb devel optional arch=alpha,amd64,i386,x32,arm64,ppc64el
 binutils-alpha-linux-gnu-dbg deb debug optional arch=alpha,amd64,i386,x32,arm64,ppc64el
 binutils-arc-linux-gnu deb devel optional arch=arc,amd64,i386,x32,arm64,ppc64el
 binutils-arc-linux-gnu-dbg deb debug optional arch=arc,amd64,i386,x32,arm64,ppc64el
 binutils-arm-linux-gnueabi deb devel optional arch=armel,amd64,i386,x32,arm64,ppc64el
 binutils-arm-linux-gnueabi-dbg deb debug optional arch=armel,amd64,i386,x32,arm64,ppc64el
 binutils-arm-linux-gnueabihf deb devel optional arch=armhf,amd64,i386,x32,arm64,ppc64el,s390x
 binutils-arm-linux-gnueabihf-dbg deb debug optional arch=armhf,amd64,i386,x32,arm64,ppc64el,s390x
 binutils-common deb devel optional arch=any
 binutils-dev deb devel optional arch=any
 binutils-doc deb doc optional arch=all
 binutils-for-build deb devel optional arch=all
 binutils-for-host deb devel optional arch=any
 binutils-hppa-linux-gnu deb devel optional arch=hppa,amd64,i386,x32,arm64,ppc64el
 binutils-hppa-linux-gnu-dbg deb debug optional arch=hppa,amd64,i386,x32,arm64,ppc64el
 binutils-hppa64-linux-gnu deb devel optional arch=amd64,i386,x32,hppa
 binutils-hppa64-linux-gnu-dbg deb debug optional arch=amd64,i386,x32,hppa
 binutils-i686-gnu deb devel optional arch=hurd-i386,amd64,i386,x32
 binutils-i686-gnu-dbg deb debug optional arch=hurd-i386,amd64,i386,x32
 binutils-i686-kfreebsd-gnu deb devel optional arch=kfreebsd-i386,amd64,i386,x32
 binutils-i686-kfreebsd-gnu-dbg deb debug optional arch=kfreebsd-i386,amd64,i386,x32
 binutils-i686-linux-gnu deb devel optional arch=i386,amd64,arm64,ppc64el,x32,s390x
 binutils-i686-linux-gnu-dbg deb debug optional arch=i386,amd64,arm64,ppc64el,x32,s390x
 binutils-ia64-linux-gnu deb devel optional arch=ia64,amd64,i386,x32
 binutils-ia64-linux-gnu-dbg deb debug optional arch=ia64,amd64,i386,x32
 binutils-loongarch64-linux-gnu deb devel optional arch=loong64,amd64,i386,x32,arm64,ppc64el
 binutils-loongarch64-linux-gnu-dbg deb debug optional arch=loong64,amd64,i386,x32,arm64,ppc64el
 binutils-m68k-linux-gnu deb devel optional arch=m68k,amd64,i386,x32,arm64,ppc64el
 binutils-m68k-linux-gnu-dbg deb debug optional arch=m68k,amd64,i386,x32,arm64,ppc64el
 binutils-multiarch deb devel optional arch=any
 binutils-multiarch-dbg deb debug optional arch=any
 binutils-multiarch-dev deb devel optional arch=any
 binutils-powerpc-linux-gnu deb devel optional arch=powerpc,amd64,i386,x32,arm64,ppc64el,s390x
 binutils-powerpc-linux-gnu-dbg deb debug optional arch=powerpc,amd64,i386,x32,arm64,ppc64el,s390x
 binutils-powerpc64-linux-gnu deb devel optional arch=ppc64,amd64,i386,x32,ppc64el,s390x
 binutils-powerpc64-linux-gnu-dbg deb debug optional arch=ppc64,amd64,i386,x32,ppc64el,s390x
 binutils-powerpc64le-linux-gnu deb devel optional arch=ppc64el,amd64,i386,x32,ppc64,arm64,s390x
 binutils-powerpc64le-linux-gnu-dbg deb debug optional arch=ppc64el,amd64,i386,x32,ppc64,arm64,s390x
 binutils-riscv64-linux-gnu deb devel optional arch=riscv64,amd64,i386,x32,arm64,ppc64el,s390x
 binutils-riscv64-linux-gnu-dbg deb debug optional arch=riscv64,amd64,i386,x32,arm64,ppc64el,s390x
 binutils-s390x-linux-gnu deb devel optional arch=s390x,amd64,i386,x32,arm64,ppc64el
 binutils-s390x-linux-gnu-dbg deb debug optional arch=s390x,amd64,i386,x32,arm64,ppc64el
 binutils-sh4-linux-gnu deb devel optional arch=sh4,amd64,i386,x32,arm64,ppc64el
 binutils-sh4-linux-gnu-dbg deb debug optional arch=sh4,amd64,i386,x32,arm64,ppc64el
 binutils-source deb devel optional arch=all
 binutils-sparc64-linux-gnu deb devel optional arch=sparc64,amd64,i386,x32,arm64,ppc64el
 binutils-sparc64-linux-gnu-dbg deb debug optional arch=sparc64,amd64,i386,x32,arm64,ppc64el
 binutils-x86-64-gnu deb devel optional arch=hurd-amd64,amd64,i386,x32
 binutils-x86-64-gnu-dbg deb debug optional arch=hurd-amd64,amd64,i386,x32
 binutils-x86-64-kfreebsd-gnu deb devel optional arch=kfreebsd-amd64,amd64,i386,x32
 binutils-x86-64-kfreebsd-gnu-dbg deb debug optional arch=kfreebsd-amd64,amd64,i386,x32
 binutils-x86-64-linux-gnu deb devel optional arch=amd64,arm64,i386,ppc64el,x32,s390x
 binutils-x86-64-linux-gnu-dbg deb debug optional arch=amd64,arm64,i386,ppc64el,x32,s390x
 binutils-x86-64-linux-gnux32 deb devel optional arch=x32,amd64,arm64,i386,ppc64el
 binutils-x86-64-linux-gnux32-dbg deb debug optional arch=x32,amd64,arm64,i386,ppc64el
 libbinutils deb devel optional arch=any
 libbinutils-dbg deb debug optional arch=any
 libctf-nobfd0 deb devel optional arch=any
 libctf-nobfd0-dbg deb debug optional arch=any
 libctf0 deb devel optional arch=any
 libctf0-dbg deb debug optional arch=any
 libgprofng0 deb devel optional arch=any
 libgprofng0-dbg deb debug optional arch=any
 libsframe1 deb devel optional arch=any
 libsframe1-dbg deb debug optional arch=any
Checksums-Sha1:
 44da41792c60419863d7e13fa1deaf6b24dd69b8 27567160 binutils_2.42.orig.tar.xz
 82f5f0c9e08508c4d9ef0a1eb5ffe3aa716102fd 196552 binutils_2.42-4ubuntu2.10.debian.tar.xz
Checksums-Sha256:
 f6e4d41fd5fc778b06b7891457b3620da5ecea1006c6a4a41ae998109f85a800 27567160 binutils_2.42.orig.tar.xz
 6acc777971890cb1efaeeb33a0a5358651c71067ced69dcfd59da7d0977f7530 196552 binutils_2.42-4ubuntu2.10.debian.tar.xz
Files:
 a075178a9646551379bfb64040487715 27567160 binutils_2.42.orig.tar.xz
 6296328f33a8a62a1effa2e03255aa79 196552 binutils_2.42-4ubuntu2.10.debian.tar.xz
Original-Maintainer: Matthias Klose <doko@debian.org>

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEi0Ab7+QbQ0yQSEMs9jtmipabB8AFAmmKTIYACgkQ9jtmipab
B8ARwg/+MZodkYECKF0BLFtdAHUda2MZGaomVACwDhR+IVplNnrfvfuGRJkvSCvH
4pH5c+hZs9dNJ0COiuhaprODjpFM3xDSETMVtPFaHcykcTpwhcpIgJeIV+Ee7OFv
/tszHDzylaqGYD+Q+w2zjyG843S2Jusl78f23IB34MjrMKVymxiFo92a5k8qHTmM
gACxQIWbRme6/lEJhjp/OA5caLFst8hvkvQyAeXl4qPD1AxnMVn4aU4KV+kFul3R
5hDogdTpBq8pq8t8SCOtUwCGNpY4HKfMf+/UeAkkQwK7lywzFSBqytDbfBrcMBiu
Y0veKF3TxbOvm6vNRGbYsveJRYdpaoWme1uoL3Es058wfy9VYNwDhWW9cUK4ckFC
iD66FPaStOY7M3Au1tsn41+s6VdlowrF1tdAZBZPiyoGSpNTJYnrcqAntDVVMQBm
9gWfjVfYQhuNlOrvurWjtcnWopvhYFjHTxQHEhuQkDsBybBHpNxIZzs0SEXsPPXF
45uzofX1aZjRzsCUbO9Wejgqc/5zCwWxEti4Yx8EHNHHWdoby+dpUQE9Kf+dByGb
DG6El+vsyVH24t7R+vY/GxGXJ/NnV3SpSfpLhf50JFrsVlv8CckZEqjqRL4YOwJ4
tzNlHRxVIPev1WLEqPgvOEohXBAAgZr5GslGXSkDbo/4k/hpAbY=
=yaxd
-----END PGP SIGNATURE-----
