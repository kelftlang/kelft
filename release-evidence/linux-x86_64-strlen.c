/* Copyright (C) 1991-2024 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <stddef.h>
const char __kelft_relink_marker[]="kelft-controlled-glibc-strlen-source";
size_t strlen(const char *text){const char *end=text;while(*end)end++;return (size_t)(end-text);}
extern __typeof(strlen) __strlen __attribute__((alias("strlen")));
extern __typeof(strlen) __GI_strlen __attribute__((alias("strlen"),visibility("hidden")));
