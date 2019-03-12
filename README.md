Copyright (c) 2019 Western Digital Corporation or its affiliates

# <p align="center">hmmap</p>

## I. Introduction

### I.1. Overview

hmmap is a mmap-able char device that provides memory to applications 
leveraging  a pluggable cache and backend infrastructure. hmmap takes control 
during a page fault in the address space provided by hmmap. The decision of 
what pages to cache and evict is made in a pluggable hmmap cache layer. In 
addition, when a page is read to/from the cache then a pluggable backend layer 
handles the IO to/from the cache.

### I.2. Kernel Version

hmmap is currently based on the Linux kernel version 5.0.

### I.3. License

This program is free software; you can redistribute it and/or modify it under 
the terms of the GNU General Public License as published by the Free Software 
Foundation; either version 2 of the License, or (at your option) any later 
version.

This program is distributed in the hope that it will be useful, but 
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more 
details.

You should have received a copy of the GNU General Public License along with 
this program; if not, write to the Free Software Foundation, Inc., 51 Franklin 
Street, Fifth Floor, Boston, MA 02110-1301, USA.

### I.4. Contact and Bug Reports

To report problems please contact:
* Adam Manzanares  (adam.manzanares@wdc.com)
