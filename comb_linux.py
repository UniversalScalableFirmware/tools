#!/usr/bin/env python
## @ comb_linux.py
#
# Generate a combined linux image
#
# Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##
import argparse
from   ctypes import Structure, ARRAY, c_char, c_uint8, c_uint32, sizeof

class LOCATION (Structure):
    _pack_ = 1
    _fields_ = [
        ('off',     c_uint32),
        ('len',     c_uint32),
        ]

class LINUX_HDR (Structure):
    _pack_ = 1
    _fields_ = [
        ('signature', ARRAY(c_char, 4)),
        ('rev',       c_uint8),
        ('length',    c_uint8),
        ('rsvd1',     c_uint8),
        ('rsvd2',     c_uint8),
        ('cmdline',   LOCATION),
        ('kernel',    LOCATION),
        ('initrd',    LOCATION)
        ]

    def __init__(self):
        self.signature        = b'LNXH'
        self.rev              = 1
        self.length           = sizeof(LINUX_HDR)


def get_file_data (file, mode = 'rb'):
    return open(file, mode).read()

def gen_file_from_object (file, object):
    open (file, 'wb').write(object)

def align_val (offset, alignment = 8):
    return (offset + alignment - 1) & ~(alignment - 1)

def gen_padding (offset, alignment = 8):
    return b'\xff' * (align_val(offset, alignment) - offset)

def main():
    ap = argparse.ArgumentParser()

    ap.add_argument('-o',  '--output',  type=str, required=True, help='Provide output file path')
    ap.add_argument('-k',  '--kernel',  type=str, required=True, help='Provide kernel file path')
    ap.add_argument('-i',  '--initrd',  type=str, default='',    help='Provide initrd file path')
    ap.add_argument('-c',  '--cmdline', type=str, default='',    help='Provide kernel command line file path')


    args = ap.parse_args()

    hdr = LINUX_HDR()
    pld = bytearray(hdr)

    if args.cmdline:
        data = get_file_data(args.cmdline)
        pld.extend (gen_padding(len(pld), 0x10))
        hdr.cmdline.off = len(pld)
        hdr.cmdline.len = len(data)
        pld.extend (data)

    if args.kernel:
        data = get_file_data(args.kernel)
        pld.extend (gen_padding(len(pld), 0x1000))
        hdr.kernel.off = len(pld)
        hdr.kernel.len = len(data)
        pld.extend (data)

    if args.initrd:
        data = get_file_data(args.initrd)
        pld.extend (gen_padding(len(pld), 0x1000))
        hdr.initrd.off = len(pld)
        hdr.initrd.len = len(data)
        pld.extend (data)

    pld[:sizeof(hdr)] = bytearray(hdr)
    hdr = LINUX_HDR.from_buffer(pld)
    print ("Combind Image:")
    print ('  CmdLine: Off:%08X Len:%08X' % (hdr.cmdline.off, hdr.cmdline.len))
    print ('  Kernel : Off:%08X Len:%08X' % (hdr.kernel.off,  hdr.kernel.len))
    print ('  InitRd : Off:%08X Len:%08X' % (hdr.initrd.off,  hdr.initrd.len))
    gen_file_from_object (args.output, pld)

if __name__ == '__main__':
    main()

