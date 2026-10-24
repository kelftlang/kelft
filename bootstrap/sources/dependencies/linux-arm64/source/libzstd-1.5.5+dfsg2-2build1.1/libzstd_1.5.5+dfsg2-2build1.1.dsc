-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: libzstd
Binary: libzstd-dev, libzstd1, zstd, libzstd1-udeb
Architecture: any
Version: 1.5.5+dfsg2-2build1.1
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Uploaders: Peter Pentchev <roam@debian.org>
Homepage: https://github.com/facebook/zstd
Standards-Version: 4.6.2
Vcs-Browser: https://salsa.debian.org/pkg-rpm-team/libzstd
Vcs-Git: https://salsa.debian.org/pkg-rpm-team/libzstd.git
Testsuite: autopkgtest
Testsuite-Triggers: build-essential, cmake, pkgconf, python3, python3-click, python3-typedload
Build-Depends: cmake (>= 3.24~), debhelper (>> 13.3.2~), dh-package-notes, dpkg-build-api (= 1), help2man, liblz4-dev, liblzma-dev, zlib1g-dev, less <!nocheck>, python3 <!nocheck>
Package-List:
 libzstd-dev deb libdevel optional arch=any
 libzstd1 deb libs optional arch=any
 libzstd1-udeb udeb debian-installer optional arch=any profile=!noudeb
 zstd deb utils optional arch=any
Checksums-Sha1:
 b8c804cce277e7ec938cf18b5bbc46e92d552daf 1784164 libzstd_1.5.5+dfsg2.orig.tar.xz
 62af7a080456dd8a7791562dc0aaa40430a77794 21288 libzstd_1.5.5+dfsg2-2build1.1.debian.tar.xz
Checksums-Sha256:
 d7cf3c10d416fd999cb8fcf7685d9268ba7bec8eb78121fc2d0d916fa393d22b 1784164 libzstd_1.5.5+dfsg2.orig.tar.xz
 c1df6d2628b26d085259b8e7ac020eb060e4c1feca98d6103058eda5ded725bc 21288 libzstd_1.5.5+dfsg2-2build1.1.debian.tar.xz
Files:
 757b1b125f12cb78fbf256e79ac6d3e9 1784164 libzstd_1.5.5+dfsg2.orig.tar.xz
 924233f65bf79a9c11435e0eb6777db9 21288 libzstd_1.5.5+dfsg2-2build1.1.debian.tar.xz
Original-Maintainer: RPM packaging team <team+pkg-rpm@tracker.debian.org>
-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEVovyKmYzfL/Jprm3LIPbyOm9DjcFAma1goQACgkQLIPbyOm9
DjeyDw/+L4YHOorTAKo305RI+4LK1y3JTXdLpaX77WxA61UGnrVJc3xDyVG6NK3H
1pM3kEgtrJfrHT8LI5ypDRktaS5pbEknL5GE0i0iqmNR/g2ZgjshLCUyzkaS0x1y
hO/BTYtWJeLljfHeCWrlgF4SEHL1Ds/hivf7vqPcPr/zjcDBQHNdgWROREMQp44K
+TZiFqS5oXFvPHHyvh24hbY4fbuEkNwrFrEZu41gSARLQRR3xcJ2QD1mTEXbI0V6
iC4DsvVprU9OdamJ87fGAkCEHBMxNp5zHej/A3G0R6wlxX+8uIKz7BIgj+Cc72gp
8HzrBDGsh2YF6EIunFl+KZ/K8mr10hOs8jPIcSutbfNAupHZraVOrSmdY/JgH4xz
odZS410UGKSqUXyyaT+KNhLeGNqPRtQD7g3ic0RkIH9WTGlM9/LrWx6JNvEzFR7u
c/aenmbTrYFcjuEdVHjVYVqCr77rXK7ojSS3Vteh9ie+8yeBrnBUoWMEdntDG8QJ
NFlpt7sOKkAt+EBewOzHZ0AzsiZB47nLUepsMrJNoSnaKP1jq/nLnGH4bkuX2txL
1+BCgcCZ/T7tUKt9vmnWfonWp5pk9jlXGpXAyhYygOkty/LwfQ0qTRs5YCJtFeAP
Pl1fVeF9VCYALDJEaxX6KbAmAqEcGVu/McJgSCT1Wl3jAuROVgw=
=5TMO
-----END PGP SIGNATURE-----
