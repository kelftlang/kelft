-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: zlib
Binary: zlib1g, zlib1g-dev, zlib1g-udeb, lib64z1, lib64z1-dev, lib32z1, lib32z1-dev, libn32z1, libn32z1-dev, libx32z1, libx32z1-dev, minizip, libminizip1t64, libminizip-dev
Architecture: any
Version: 1:1.3.dfsg-3.1ubuntu2.2
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Homepage: http://zlib.net/
Standards-Version: 4.6.1
Build-Depends: dpkg-dev (>= 1.22.5), debhelper (>= 13), gcc-multilib [amd64 i386 kfreebsd-amd64 mips mipsel powerpc ppc64 s390 sparc s390x mipsn32 mipsn32el mipsr6 mipsr6el mipsn32r6 mipsn32r6el mips64 mips64el mips64r6 mips64r6el x32] <!nobiarch>, autoconf
Package-List:
 lib32z1 deb libs optional arch=amd64,ppc64,kfreebsd-amd64,s390x profile=!nobiarch
 lib32z1-dev deb libdevel optional arch=amd64,ppc64,kfreebsd-amd64,s390x profile=!nobiarch
 lib64z1 deb libs optional arch=sparc,s390,i386,powerpc,mips,mipsel,mipsn32,mipsn32el,mipsr6,mipsr6el,mipsn32r6,mipsn32r6el,x32 profile=!nobiarch
 lib64z1-dev deb libdevel optional arch=sparc,s390,i386,powerpc,mips,mipsel,mipsn32,mipsn32el,mipsr6,mipsr6el,mipsn32r6,mipsn32r6el,x32 profile=!nobiarch
 libminizip-dev deb libdevel optional arch=any
 libminizip1t64 deb libs optional arch=any
 libn32z1 deb libs optional arch=mips,mipsel profile=!nobiarch
 libn32z1-dev deb libdevel optional arch=mips,mipsel profile=!nobiarch
 libx32z1 deb libs optional arch=amd64,i386
 libx32z1-dev deb libdevel optional arch=amd64,i386
 minizip deb utils optional arch=any
 zlib1g deb libs required arch=any
 zlib1g-dev deb libdevel optional arch=any
 zlib1g-udeb udeb debian-installer optional arch=any
Checksums-Sha1:
 1013da3e3125946039f2c60e291a54a9422b4553 1128572 zlib_1.3.dfsg.orig.tar.xz
 c8550aa3cf99179213175eba139489cc015533a6 61316 zlib_1.3.dfsg-3.1ubuntu2.2.debian.tar.xz
Checksums-Sha256:
 5eea0322c1c21c75cad3b607ac1c43ff5c71e014b8ac4a34300b5e2b80d02e70 1128572 zlib_1.3.dfsg.orig.tar.xz
 de1c2d532ecb7caf99ccb905fb03c37fe0c8117fbdc79d05be4474b71e6398c2 61316 zlib_1.3.dfsg-3.1ubuntu2.2.debian.tar.xz
Files:
 3eee75fc36a344cfe93c8bf1c0473df4 1128572 zlib_1.3.dfsg.orig.tar.xz
 483795d49ab1389da921757074c56919 61316 zlib_1.3.dfsg-3.1ubuntu2.2.debian.tar.xz
Original-Maintainer: Mark Brown <broonie@debian.org>

-----BEGIN PGP SIGNATURE-----

iQHTBAEBCgA9FiEE26yozGlLvY8PLmS9C+du+fOjiEwFAmqNrFYfHGNocmlzYS5v
aWtvbm9tb3VAY2Fub25pY2FsLmNvbQAKCRAL527586OITMwdC/sEQeAwsa5MtSSs
83v4r1RrKQH0mx7yHrDhPdiiCYlfo/7BhbiaYPzdWBrNqN9j7oLpZy8sYPYHyHDA
oTBtoSxjqQpwmfooQLyIra98uyumDN+l40Qqu/LcMa4NcItW6jM3sep2tTp1JmA3
CWwVOyEmKytb+n1c+AijpoFVRn37O5/e51XPjPAzcPVEuswSy2wTKEKmEoKRuohP
U/GXWC/0MTIltCKE3K2WeIosdHM3Njr+dzxApvK0qYZkyUaYBfgw85uV4de3FzvI
j8/71xUm2aHlicI8kiCHjTB2huocgT6MUnY728SXhSMwImvtYZuRXW4A4rEOxs6y
acGHpBzbALsN/jdwNRyHTkZqt6Q+okOQ78/w+ZWMz5SZ3KvzLIaR95pZCNFIXf1+
TRN4uLMX65ifnOgzTk75FQvLacvfY32z+i5wKTblQNx2O92/JdroMlqdgdeeGctZ
mZFFpDAHACn8xfe+OB/7odjO4T7OjAnEwePDpc+R6pSjhfGNCms=
=q8MX
-----END PGP SIGNATURE-----
