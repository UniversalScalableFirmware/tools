#!/usr/bin/env python
## @ GenPldHdr.py
# Generate a payload header from a payload binary
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##
import os
import sys
import re
import string
import argparse
import subprocess
import uuid
from   ctypes import *

PUB_KEY_TYPE = {
           # key_type   : key_val
            "RSA"       : 1,
            "ECC"       : 2,
            "DSA"       : 3,
    }

# Signing type schemes  defined should match with cryptolib.h
SIGN_TYPE_SCHEME = {
           # sign_type            : key_val
            "RSA_PKCS1"           : 1,
            "RSA_PSS"             : 2,
            "ECC"                 : 3,
            "DSA"                 : 4,
    }

# Hash values defined should match with cryptolib.h
HASH_TYPE_VALUE = {
            # Hash_string : Hash_Value
            "SHA2_256"    : 1,
            "SHA2_384"    : 2,
            "SHA2_512"    : 3,
            "SM3_256"     : 4,
    }

class PUB_KEY_HDR (Structure):
    _pack_ = 1
    _fields_ = [
        ('Identifier', ARRAY(c_char, 4)),      #signature ('P', 'U', 'B', 'K')
        ('KeySize',    c_uint16),              #Length of Public Key
        ('KeyType',    c_uint8),               #RSA or ECC
        ('Reserved',   ARRAY(c_uint8, 1)),
        ('KeyData',    ARRAY(c_uint8, 0)),   #Pubic key data with KeySize bytes for RSA_KEY() format
        ]

    def __init__(self):
        self.Identifier = b'PUBK'

class SIGNATURE_HDR (Structure):
    _pack_ = 1
    _fields_ = [
        ('Identifier', ARRAY(c_char, 4)),      #signature Identifier('S', 'I', 'G', 'N')
        ('SigSize',    c_uint16),              #Length of signature 2K and 3K in bytes
        ('SigType',    c_uint8),               #PKCSv1.5 or RSA-PSS or ECC
        ('HashAlg',    c_uint8),               #Hash Alg for signingh SHA256, 384
        ('Signature',  ARRAY(c_uint8, 0)),     #Signature length defined by SigSize bytes
        ]

    def __init__(self):
        self.Identifier = b'SIGN'

class c_uint24(Structure):
    """Little-Endian 24-bit Unsigned Integer"""
    _pack_   = 1
    _fields_ = [('Data', (c_uint8 * 3))]

    def __init__(self, val=0):
        self.set_value(val)

    def __str__(self, indent=0):
        return '0x%.6x' % self.value

    def __int__(self):
        return self.get_value()

    def set_value(self, val):
        self.Data[0:3] = value_to_bytes(val, 3)

    def get_value(self):
        return bytes_to_value(self.Data[0:3])

    value = property(get_value, set_value)


class EFI_FIRMWARE_VOLUME_HEADER(Structure):
    _fields_ = [
        ('ZeroVector',           ARRAY(c_uint8, 16)),
        ('FileSystemGuid',       ARRAY(c_uint8, 16)),
        ('FvLength',             c_uint64),
        ('Signature',            ARRAY(c_char, 4)),
        ('Attributes',           c_uint32),
        ('HeaderLength',         c_uint16),
        ('Checksum',             c_uint16),
        ('ExtHeaderOffset',      c_uint16),
        ('Reserved',             c_uint8),
        ('Revision',             c_uint8)
        ]


class EFI_FIRMWARE_VOLUME_EXT_HEADER(Structure):
    _fields_ = [
        ('FvName',               ARRAY(c_uint8, 16)),
        ('ExtHeaderSize',        c_uint32)
        ]


class EFI_FFS_INTEGRITY_CHECK(Structure):
    _fields_ = [
        ('Header',               c_uint8),
        ('File',                 c_uint8)
        ]


class EFI_FFS_FILE_HEADER(Structure):
    _fields_ = [
        ('Name',                 ARRAY(c_uint8, 16)),
        ('IntegrityCheck',       EFI_FFS_INTEGRITY_CHECK),
        ('Type',                 c_uint8),
        ('Attributes',           c_uint8),
        ('Size',                 c_uint24),
        ('State',                c_uint8)
        ]


class EFI_COMMON_SECTION_HEADER(Structure):
    _fields_ = [
        ('Size',                 c_uint24),
        ('Type',                 c_uint8)
        ]


class EFI_IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress',       c_uint32),
        ('Size',                 c_uint32)
        ]


class EFI_TE_IMAGE_HEADER(Structure):
    _fields_ = [
        ('Signature',               ARRAY(c_char, 2)),
        ('Machine',                 c_uint16),
        ('NumberOfSections',        c_uint8),
        ('Subsystem',               c_uint8),
        ('StrippedSize',            c_uint16),
        ('AddressOfEntryPoint',     c_uint32),
        ('BaseOfCode',              c_uint32),
        ('ImageBase',               c_uint64),
        ('DataDirectoryBaseReloc',  EFI_IMAGE_DATA_DIRECTORY),
        ('DataDirectoryDebug',      EFI_IMAGE_DATA_DIRECTORY)
        ]


class EFI_IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic',              c_uint16),
        ('e_cblp',               c_uint16),
        ('e_cp',                 c_uint16),
        ('e_crlc',               c_uint16),
        ('e_cparhdr',            c_uint16),
        ('e_minalloc',           c_uint16),
        ('e_maxalloc',           c_uint16),
        ('e_ss',                 c_uint16),
        ('e_sp',                 c_uint16),
        ('e_csum',               c_uint16),
        ('e_ip',                 c_uint16),
        ('e_cs',                 c_uint16),
        ('e_lfarlc',             c_uint16),
        ('e_ovno',               c_uint16),
        ('e_res',                ARRAY(c_uint16, 4)),
        ('e_oemid',              c_uint16),
        ('e_oeminfo',            c_uint16),
        ('e_res2',               ARRAY(c_uint16, 10)),
        ('e_lfanew',             c_uint16)
        ]

class EFI_IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine',               c_uint16),
        ('NumberOfSections',      c_uint16),
        ('TimeDateStamp',         c_uint32),
        ('PointerToSymbolTable',  c_uint32),
        ('NumberOfSymbols',       c_uint32),
        ('SizeOfOptionalHeader',  c_uint16),
        ('Characteristics',       c_uint16)
        ]

class PE_RELOC_BLOCK_HEADER(Structure):
    _fields_ = [
        ('PageRVA',              c_uint32),
        ('BlockSize',            c_uint32)
        ]

class EFI_IMAGE_OPTIONAL_HEADER32(Structure):
    _fields_ = [
        ('Magic',                         c_uint16),
        ('MajorLinkerVersion',            c_uint8),
        ('MinorLinkerVersion',            c_uint8),
        ('SizeOfCode',                    c_uint32),
        ('SizeOfInitializedData',         c_uint32),
        ('SizeOfUninitializedData',       c_uint32),
        ('AddressOfEntryPoint',           c_uint32),
        ('BaseOfCode',                    c_uint32),
        ('BaseOfData',                    c_uint32),
        ('ImageBase',                     c_uint32),
        ('SectionAlignment',              c_uint32),
        ('FileAlignment',                 c_uint32),
        ('MajorOperatingSystemVersion',   c_uint16),
        ('MinorOperatingSystemVersion',   c_uint16),
        ('MajorImageVersion',             c_uint16),
        ('MinorImageVersion',             c_uint16),
        ('MajorSubsystemVersion',         c_uint16),
        ('MinorSubsystemVersion',         c_uint16),
        ('Win32VersionValue',             c_uint32),
        ('SizeOfImage',                   c_uint32),
        ('SizeOfHeaders',                 c_uint32),
        ('CheckSum'     ,                 c_uint32),
        ('Subsystem',                     c_uint16),
        ('DllCharacteristics',            c_uint16),
        ('SizeOfStackReserve',            c_uint32),
        ('SizeOfStackCommit' ,            c_uint32),
        ('SizeOfHeapReserve',             c_uint32),
        ('SizeOfHeapCommit' ,             c_uint32),
        ('LoaderFlags'     ,              c_uint32),
        ('NumberOfRvaAndSizes',           c_uint32),
        ('DataDirectory',                 ARRAY(EFI_IMAGE_DATA_DIRECTORY, 16))
        ]

class EFI_IMAGE_OPTIONAL_HEADER32_PLUS(Structure):
    _fields_ = [
        ('Magic',                         c_uint16),
        ('MajorLinkerVersion',            c_uint8),
        ('MinorLinkerVersion',            c_uint8),
        ('SizeOfCode',                    c_uint32),
        ('SizeOfInitializedData',         c_uint32),
        ('SizeOfUninitializedData',       c_uint32),
        ('AddressOfEntryPoint',           c_uint32),
        ('BaseOfCode',                    c_uint32),
        ('ImageBase',                     c_uint64),
        ('SectionAlignment',              c_uint32),
        ('FileAlignment',                 c_uint32),
        ('MajorOperatingSystemVersion',   c_uint16),
        ('MinorOperatingSystemVersion',   c_uint16),
        ('MajorImageVersion',             c_uint16),
        ('MinorImageVersion',             c_uint16),
        ('MajorSubsystemVersion',         c_uint16),
        ('MinorSubsystemVersion',         c_uint16),
        ('Win32VersionValue',             c_uint32),
        ('SizeOfImage',                   c_uint32),
        ('SizeOfHeaders',                 c_uint32),
        ('CheckSum'     ,                 c_uint32),
        ('Subsystem',                     c_uint16),
        ('DllCharacteristics',            c_uint16),
        ('SizeOfStackReserve',            c_uint64),
        ('SizeOfStackCommit' ,            c_uint64),
        ('SizeOfHeapReserve',             c_uint64),
        ('SizeOfHeapCommit' ,             c_uint64),
        ('LoaderFlags'     ,              c_uint32),
        ('NumberOfRvaAndSizes',           c_uint32),
        ('DataDirectory',                 ARRAY(EFI_IMAGE_DATA_DIRECTORY, 16))
        ]

class EFI_IMAGE_OPTIONAL_HEADER(Union):
    _fields_ = [
        ('PeOptHdr',             EFI_IMAGE_OPTIONAL_HEADER32),
        ('PePlusOptHdr',         EFI_IMAGE_OPTIONAL_HEADER32_PLUS)
        ]

class EFI_IMAGE_NT_HEADERS32(Structure):
    _fields_ = [
        ('Signature',            c_uint32),
        ('FileHeader',           EFI_IMAGE_FILE_HEADER),
        ('OptionalHeader',       EFI_IMAGE_OPTIONAL_HEADER)
        ]


class EFI_IMAGE_DIRECTORY_ENTRY:
    EXPORT                     = 0
    IMPORT                     = 1
    RESOURCE                   = 2
    EXCEPTION                  = 3
    SECURITY                   = 4
    BASERELOC                  = 5
    DEBUG                      = 6
    COPYRIGHT                  = 7
    GLOBALPTR                  = 8
    TLS                        = 9
    LOAD_CONFIG                = 10

class EFI_FV_FILETYPE:
    ALL                        = 0x00
    RAW                        = 0x01
    FREEFORM                   = 0x02
    SECURITY_CORE              = 0x03
    PEI_CORE                   = 0x04
    DXE_CORE                   = 0x05
    PEIM                       = 0x06
    DRIVER                     = 0x07
    COMBINED_PEIM_DRIVER       = 0x08
    APPLICATION                = 0x09
    SMM                        = 0x0a
    FIRMWARE_VOLUME_IMAGE      = 0x0b
    COMBINED_SMM_DXE           = 0x0c
    SMM_CORE                   = 0x0d
    OEM_MIN                    = 0xc0
    OEM_MAX                    = 0xdf
    DEBUG_MIN                  = 0xe0
    DEBUG_MAX                  = 0xef
    FFS_MIN                    = 0xf0
    FFS_MAX                    = 0xff
    FFS_PAD                    = 0xf0

class EFI_SECTION_TYPE:
    """Enumeration of all valid firmware file section types."""
    ALL                        = 0x00
    COMPRESSION                = 0x01
    GUID_DEFINED               = 0x02
    DISPOSABLE                 = 0x03
    PE32                       = 0x10
    PIC                        = 0x11
    TE                         = 0x12
    DXE_DEPEX                  = 0x13
    VERSION                    = 0x14
    USER_INTERFACE             = 0x15
    COMPATIBILITY16            = 0x16
    FIRMWARE_VOLUME_IMAGE      = 0x17
    FREEFORM_SUBTYPE_GUID      = 0x18
    RAW                        = 0x19
    PEI_DEPEX                  = 0x1b
    SMM_DEPEX                  = 0x1c

def print_bytes (data, indent=0, offset=0, show_ascii = False, brief=False):
    bytes_per_line = 16
    printable = ' ' + string.ascii_letters + string.digits + string.punctuation
    str_fmt = '{:s}{:06x}: {:%ds} {:s}' % (bytes_per_line * 3)
    bytes_per_line
    data_array = bytearray(data)
    dlen = len(data_array)
    for idx in range(0, dlen, bytes_per_line):
        if brief and (idx > bytes_per_line and idx < dlen - bytes_per_line * 2):
            if idx == bytes_per_line * 3:
                print (indent * ' ' + '......')
        else:
            hex_str = ' '.join('%02X' % val for val in data_array[idx:idx + bytes_per_line])
            asc_str = ''.join('%c' % (val if (chr(val) in printable) else '.')
                          for val in data_array[idx:idx + bytes_per_line])
            print (str_fmt.format(indent * ' ', offset + idx, hex_str, ' ' + asc_str if show_ascii else ''))


def align_ptr (offset, alignment = 8):
    return (offset + alignment - 1) & ~(alignment - 1)

def get_padding_size (offset, alignment = 4):
    return align_ptr(offset, alignment) - offset

def value_to_bytes (value, length):
    return value.to_bytes(length, 'little')

def bytes_to_value (byte):
    return int.from_bytes (byte, 'little')

def bytes_to_uuid (byte):
    return uuid.UUID(bytes_le = bytes(byte))

def gen_file_from_object (file, object):
    open (file, 'wb').write(object)

def get_file_data (file, mode = 'rb'):
    return open(file, mode).read()

def output_struct (obj, indent = 0, plen = 0, offset = None):
    if offset is None:
        offset = [0]

    if indent:
        body = ''
    else:
        body = ('  ' * indent + '<%s>:\n') % obj.__class__.__name__

    if plen == 0:
        plen = sizeof(obj)

    max_key_len = 26
    pstr = ('  ' * (indent + 1) + '{0:<%d} = {1}\n') % max_key_len

    for field, ftype in obj._fields_:
        key = field
        val = getattr(obj, key)
        rep = ''

        if not isinstance(val, c_uint24) and isinstance(val, Structure):
            body += pstr.format(key, val.__class__.__name__)
            body += output_struct (val, indent + 1, offset = offset)
            plen -= sizeof(val)
        else:
            if type(val) is bytes:
                rep = "0x%X ('%s')" % (bytes_to_value (bytearray (val)), str (val, 'utf-8'))
            elif type(val) is int:
                rep = '0x%X' % val
            elif isinstance(val, c_uint24):
                rep = '0x%X' % val.get_value()
            elif 'c_ubyte_Array' in str(type(val)):
                if sizeof(val) == 16:
                    rep = str(uuid.UUID(bytes_le = bytes(val))).upper()
                else:
                    res = ['0x%02X'%i for i in bytearray(val)]
                    rep = '[%s]' % (','.join(res))
            else:
                rep = str(val)
            plen      -= sizeof(ftype)
            body      += pstr.format('0x%04X %s' % (offset[0], key), rep)
            offset[0] += sizeof(ftype)
        if plen <= 0:
            break

    return body

class Section:
    def __init__(self, offset, secdata):
        self.SecHdr   = EFI_COMMON_SECTION_HEADER.from_buffer (secdata, 0)
        self.SecData  = secdata[0:int(self.SecHdr.Size)]
        self.Offset   = offset

class FirmwareFile:
    def __init__(self, offset, filedata):
        self.FfsHdr   = EFI_FFS_FILE_HEADER.from_buffer (filedata, 0)
        self.FfsData  = filedata[0:int(self.FfsHdr.Size)]
        self.Offset   = offset
        self.SecList  = []

    def ParseFfs(self):
        ffssize = len(self.FfsData)
        offset  = sizeof(self.FfsHdr)
        if self.FfsHdr.Name != '\xff' * 16:
            while offset < (ffssize - sizeof (EFI_COMMON_SECTION_HEADER)):
                sechdr = EFI_COMMON_SECTION_HEADER.from_buffer (self.FfsData, offset)
                sec = Section (offset, self.FfsData[offset:offset + int(sechdr.Size)])
                self.SecList.append(sec)
                offset += int(sechdr.Size)
                offset  = align_ptr(offset, 4)

class FirmwareVolume:
    def __init__(self, offset, fvdata):
        self.FvHdr    = EFI_FIRMWARE_VOLUME_HEADER.from_buffer (fvdata, 0)
        self.FvData   = fvdata[0 : self.FvHdr.FvLength]
        self.Offset   = offset
        if self.FvHdr.ExtHeaderOffset > 0:
            self.FvExtHdr = EFI_FIRMWARE_VOLUME_EXT_HEADER.from_buffer (self.FvData, self.FvHdr.ExtHeaderOffset)
        else:
            self.FvExtHdr = None
        self.FfsList  = []

    def ParseFv(self):
        fvsize = len(self.FvData)
        if self.FvExtHdr:
            offset = self.FvHdr.ExtHeaderOffset + self.FvExtHdr.ExtHeaderSize
        else:
            offset = self.FvHdr.HeaderLength
        offset = align_ptr(offset)
        while offset < (fvsize - sizeof (EFI_FFS_FILE_HEADER)):
            ffshdr = EFI_FFS_FILE_HEADER.from_buffer (self.FvData, offset)
            if (ffshdr.Name == '\xff' * 16) and (int(ffshdr.Size) == 0xFFFFFF):
                offset = fvsize
            else:
                ffs = FirmwareFile (offset, self.FvData[offset:offset + int(ffshdr.Size)])
                ffs.ParseFfs()
                self.FfsList.append(ffs)
                offset += int(ffshdr.Size)
                offset = align_ptr(offset)

class FirmwareDevice:
    def __init__(self, fd_bin, offset = 0):
        self.FvList  = []
        self.FspList = []
        self.Offset = 0
        self.FdData = bytearray(fd_bin)

    def ParseFd(self):
        offset = 0
        fdsize = len(self.FdData)
        self.FvList  = []
        while offset < (fdsize - sizeof (EFI_FIRMWARE_VOLUME_HEADER)):
            fvh = EFI_FIRMWARE_VOLUME_HEADER.from_buffer (self.FdData, offset)
            if b'_FVH' != fvh.Signature:
                raise Exception("ERROR: Invalid FV header !")
            fv = FirmwareVolume (offset, self.FdData[offset:offset + fvh.FvLength])
            fv.ParseFv ()
            self.FvList.append(fv)
            offset += fv.FvHdr.FvLength


class PeTeImage:
    def __init__(self, offset, data):
        self.Offset    = offset
        tehdr          = EFI_TE_IMAGE_HEADER.from_buffer (data, 0)
        if   tehdr.Signature == b'VZ': # TE image
            self.TeHdr   = tehdr
        elif tehdr.Signature == b'MZ': # PE image
            self.TeHdr   = None
            self.DosHdr  = EFI_IMAGE_DOS_HEADER.from_buffer (data, 0)
            self.PeHdr   = EFI_IMAGE_NT_HEADERS32.from_buffer (data, self.DosHdr.e_lfanew)
            if self.PeHdr.Signature != 0x4550:
                raise Exception("ERROR: Invalid PE32 header !")
            if self.PeHdr.OptionalHeader.PeOptHdr.Magic == 0x10b: # PE32 image
                if self.PeHdr.FileHeader.SizeOfOptionalHeader < EFI_IMAGE_OPTIONAL_HEADER32.DataDirectory.offset:
                    raise Exception("ERROR: Unsupported PE32 image !")
                if self.PeHdr.OptionalHeader.PeOptHdr.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC:
                    raise Exception("ERROR: No relocation information available !")
            elif self.PeHdr.OptionalHeader.PeOptHdr.Magic == 0x20b: # PE32+ image
                if self.PeHdr.FileHeader.SizeOfOptionalHeader < EFI_IMAGE_OPTIONAL_HEADER32_PLUS.DataDirectory.offset:
                    raise Exception("ERROR: Unsupported PE32+ image !")
                if self.PeHdr.OptionalHeader.PePlusOptHdr.NumberOfRvaAndSizes <= EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC:
                    raise Exception("ERROR: No relocation information available !")
            else:
                raise Exception("ERROR: Invalid PE32 optional header !")
        self.Offset    = offset
        self.Data      = data
        self.RelocList = []


    def IsTeImage(self):
        return  self.TeHdr is not None

    def GetEntrypoint (self):
        if self.IsTeImage():
            return self.TeHdr.AddressOfEntryPoint
        else:
            return self.PeHdr.OptionalHeader.PePlusOptHdr.AddressOfEntryPoint

    def GetMachineType(self):
        if self.IsTeImage():
            return self.TeHdr.Machine
        else:
            return self.PeHdr.FileHeader.Machine

    def ParseReloc(self):
        if self.IsTeImage():
            rsize   = self.TeHdr.DataDirectoryBaseReloc.Size
            roffset = sizeof(self.TeHdr) - self.TeHdr.StrippedSize + self.TeHdr.DataDirectoryBaseReloc.VirtualAddress
        else:
            # Assuming PE32 image type (self.PeHdr.OptionalHeader.PeOptHdr.Magic == 0x10b)
            rsize   = self.PeHdr.OptionalHeader.PeOptHdr.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC].Size
            roffset = self.PeHdr.OptionalHeader.PeOptHdr.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC].VirtualAddress
            if self.PeHdr.OptionalHeader.PePlusOptHdr.Magic == 0x20b: # PE32+ image
                rsize   = self.PeHdr.OptionalHeader.PePlusOptHdr.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC].Size
                roffset = self.PeHdr.OptionalHeader.PePlusOptHdr.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY.BASERELOC].VirtualAddress

        alignment = 4
        offset = roffset
        while offset < roffset + rsize:
            offset = align_ptr(offset, 4)
            blkhdr = PE_RELOC_BLOCK_HEADER.from_buffer(self.Data, offset)
            offset += sizeof(blkhdr)
            # Read relocation type,offset pairs
            rlen  = blkhdr.BlockSize - sizeof(PE_RELOC_BLOCK_HEADER)
            rnum  = int (rlen/sizeof(c_uint16))
            rdata = (c_uint16 * rnum).from_buffer(self.Data, offset)
            for each in rdata:
                roff  = each & 0xfff
                rtype = each >> 12
                if rtype == 0: # IMAGE_REL_BASED_ABSOLUTE:
                    continue
                if ((rtype != 3) and (rtype != 10)): # IMAGE_REL_BASED_HIGHLOW and IMAGE_REL_BASED_DIR64
                    raise Exception("ERROR: Unsupported relocation type %d!" % rtype)
                # Calculate the offset of the relocation
                aoff  = blkhdr.PageRVA + roff
                if self.IsTeImage():
                    aoff += sizeof(self.TeHdr) - self.TeHdr.StrippedSize
                self.RelocList.append((rtype, aoff))
            offset += sizeof(rdata)
        return (roffset, rsize)

    def Rebase(self, delta, fdbin):
        count = 0
        if delta == 0:
            return count

        for (rtype, roff) in self.RelocList:
            if rtype == 3: # IMAGE_REL_BASED_HIGHLOW
                offset = roff + self.Offset
                value  = bytes_to_value(fdbin[offset:offset+sizeof(c_uint32)])
                value += delta
                fdbin[offset:offset+sizeof(c_uint32)] = value_to_bytes(value, sizeof(c_uint32))
                count += 1
            elif rtype == 10: # IMAGE_REL_BASED_DIR64
                offset = roff + self.Offset
                value  = bytes_to_value(fdbin[offset:offset+sizeof(c_uint64)])
                value += delta
                fdbin[offset:offset+sizeof(c_uint64)] = value_to_bytes(value, sizeof(c_uint64))
                count += 1
            else:
                raise Exception('ERROR: Unknown relocation type %d !' % rtype)

        if self.IsTeImage():
            offset  = self.Offset + EFI_TE_IMAGE_HEADER.ImageBase.offset
            size    = EFI_TE_IMAGE_HEADER.ImageBase.size
        else:
            offset  = self.Offset + self.DosHdr.e_lfanew
            offset += EFI_IMAGE_NT_HEADERS32.OptionalHeader.offset
            offset += EFI_IMAGE_OPTIONAL_HEADER32.ImageBase.offset
            size    = EFI_IMAGE_OPTIONAL_HEADER32.ImageBase.size

        value  = bytes_to_value(fdbin[offset:offset+size]) + delta
        fdbin[offset:offset+size] = value_to_bytes(value, size)

        return count


class PAYLOAD_COMMON_HEADER (Structure):
    _pack_    = 1
    _fields_  = [
        ( 'Identifier'        , ARRAY(c_char, 4)),
        ( 'HeaderLength'      , c_uint32),
        ( 'HeaderRevision'    , c_uint8),
        ( 'Reserved1'         , ARRAY(c_uint8, 3))
    ]

class PAYLOAD_INFO_HEADER (Structure):
    CAP_PIC   = (1 << 0)
    CAP_RELOC = (1 << 1)
    CAP_AUTH  = (1 << 2)

    _pack_    = 1
    _fields_  = [
        ( 'CommonHeader'      , PAYLOAD_COMMON_HEADER),
        ( 'ProducerId'        , ARRAY(c_char, 8)),
        ( 'ImageId'           , ARRAY(c_char, 8)),
        ( 'Revision'          , c_uint32),
        ( 'Length'            , c_uint32),
        ( 'Svn'               , c_uint32),
        ( 'Reserved2'         , ARRAY(c_uint8, 2)),
        ( 'Machine'           , c_uint16),
        ( 'Capability'        , c_uint32),
        ( 'ImageOffset'       , c_uint32),
        ( 'ImageLength'       , c_uint32),
        ( 'ImageBase'         , c_uint64),
        ( 'ImageAlignment'    , c_uint32),
        ( 'EntryPointOffset'  , c_uint32),
    ]

    def __init__ (self):
        self.CommonHeader.Identifier     = b'PLDH'
        self.CommonHeader.HeaderLength   = sizeof(PAYLOAD_INFO_HEADER)
        self.CommonHeader.HeaderRevision = 1
        self.ProducerId     = b'Intel'
        self.ImageId        = b'UEFI_PLD'


class PAYLOAD_RELOC_HEADER (Structure):
    # Relocation data contains raw reloc block data
    RELOC_FMT_RAW = 0
    # Relocation data contains a offset/length pair to point to reloc block data
    RELOC_FMT_PTR = 1
    _pack_    = 1
    _fields_  = [
        ( 'CommonHeader'      , PAYLOAD_COMMON_HEADER),
        ( 'RelocFmt'          , c_uint8),
        ( 'Reserved'          , ARRAY(c_uint8, 1)),
        ( 'RelocImgStripped'  , c_uint16),
        ( 'RelocImgOffset'    , c_uint32),
    ]

class PAYLOAD_AUTH_HEADER (Structure):
    # Relocation data contains raw reloc block data
    RELOC_FMT_RAW = 0
    # Relocation data contains a offset/length pair to point to reloc block data
    RELOC_FMT_PTR = 1
    _pack_    = 1
    _fields_  = [
        ( 'CommonHeader'      , PAYLOAD_COMMON_HEADER)
    ]

class PAYLOAD_HEADER_HELPER:
    def __init__ (self):
        pass

    @staticmethod
    def locate_sec_image_in_fd (fd_bin):
        fd = FirmwareDevice (fd_bin)
        fd.ParseFd ()

        # Find the 1st SEC file containing a TE/PE section
        found = False
        for idx, fv in enumerate(fd.FvList):
            for ffs in fv.FfsList:
                for sec in ffs.SecList:
                    if sec.SecHdr.Type in [EFI_SECTION_TYPE.TE, EFI_SECTION_TYPE.PE32]:   # TE or PE32
                        if ffs.FfsHdr.Type == EFI_FV_FILETYPE.SECURITY_CORE:
                            offset = fd.Offset + fv.Offset + ffs.Offset + sec.Offset + sizeof(sec.SecHdr)
                            length = len(sec.SecData) - sizeof(sec.SecHdr)
                            found  = True
                            break

        if not found:
            raise Exception ('Could not find SEC file with TE/PE32 section !')

        return (offset, length)


    @staticmethod
    def create_reloc_table (reloc_fmt, reloc_img_off, reloc_data, stripped = 0):
        pld_reloc_hdr = PAYLOAD_RELOC_HEADER ()
        pld_reloc_hdr.CommonHeader.Identifier     = b'PLDR'
        pld_reloc_hdr.CommonHeader.HeaderLength   = sizeof(pld_reloc_hdr) + len(reloc_data)
        pld_reloc_hdr.CommonHeader.HeaderRevision = 1
        pld_reloc_hdr.RelocFmt = reloc_fmt
        pld_reloc_hdr.RelocImgOffset   = reloc_img_off
        pld_reloc_hdr.RelocImgStripped = stripped

        if reloc_fmt ==  PAYLOAD_RELOC_HEADER.RELOC_FMT_PTR:
            if len(reloc_data) != sizeof(PE_RELOC_BLOCK_HEADER):
                raise Exception ('Unexpected relocation data length !')

        return pld_reloc_hdr, bytearray(reloc_data)


    @staticmethod
    def create_auth_table (pri_key, hash_type, sign_scheme, data):

        pld_auth_hdr = PAYLOAD_AUTH_HEADER ()
        pld_auth_hdr.CommonHeader.Identifier     = b'PLDA'
        pld_auth_hdr.CommonHeader.HeaderRevision = 1

        pubkey_bin = single_sign_gen_pub_key (pri_key)
        pubkey = PUB_KEY_HDR()
        pubkey.KeySize  = len(pubkey_bin)
        pubkey.KeyType  = PUB_KEY_TYPE['RSA']

        # Assume public exponent is always 4 bytes
        auth_len = sizeof(PAYLOAD_AUTH_HEADER) + sizeof(SIGNATURE_HDR) + sizeof(PUB_KEY_HDR) + pubkey.KeySize * 2 - 4

        pld_info_hdr = PAYLOAD_INFO_HEADER.from_buffer (data)
        pld_info_hdr.Length = pld_info_hdr.Length + auth_len

        tmp_in  = '$temp1.bin'
        tmp_out = '$temp2.bin'
        fo = open(tmp_in, 'wb')
        fo.write (data)
        fo.close ()
        single_sign_file (pri_key, hash_type, sign_scheme, tmp_in, tmp_out)
        signature  = get_file_data (tmp_out)
        os.remove (tmp_in)
        os.remove (tmp_out)

        sign = SIGNATURE_HDR()
        sign.SigSize = len(signature)
        sign.SigType = SIGN_TYPE_SCHEME[sign_scheme]
        sign.HashAlg = HASH_TYPE_VALUE[hash_type]

        dlen = sizeof(pld_auth_hdr) + sizeof(sign) + len(signature) + sizeof(pubkey) + len(pubkey_bin)
        pld_auth_hdr.CommonHeader.HeaderLength = dlen
        return (pld_auth_hdr, sign, signature, pubkey,  pubkey_bin)



def get_openssl_path ():
    if os.name == 'nt':
        if 'OPENSSL_PATH' not in os.environ:
            os.environ['OPENSSL_PATH'] = "C:\\Openssl\\"
        if 'OPENSSL_CONF' not in os.environ:
            openssl_cfg = "C:\\Openssl\\openssl.cfg"
            if os.path.exists(openssl_cfg):
                os.environ['OPENSSL_CONF'] = openssl_cfg
    openssl = os.path.join(os.environ.get ('OPENSSL_PATH', ''), 'openssl')
    return openssl


def run_process (arg_list, print_cmd = False, capture_out = False):
    sys.stdout.flush()
    if print_cmd:
        print (' '.join(arg_list))

    exc    = None
    result = 0
    output = ''
    try:
        if capture_out:
            output = subprocess.check_output(arg_list).decode()
        else:
            result = subprocess.call (arg_list)
    except Exception as ex:
        result = 1
        exc    = ex

    if result:
        if not print_cmd:
            print ('Error in running process:\n  %s' % ' '.join(arg_list))
        if exc is None:
            sys.exit(1)
        else:
            raise exc

    return output



#
# Extract public key using openssl
#
# in_key        [Input]         Private key or public key in pem format
# pub_key_file  [Input/Output]  Public Key to a file
#
# return        keydata (mod, exp) in bin format
#

def single_sign_gen_pub_key (in_key, pub_key_file = None):

    # Expect key to be in PEM format
    is_prv_key = False
    cmdline = [get_openssl_path(), 'rsa', '-pubout', '-text', '-noout', '-in', '%s' % in_key]
    # Check if it is public key or private key
    text = open(in_key, 'r').read()
    if '-BEGIN RSA PRIVATE KEY-' in text:
        is_prv_key = True
    elif '-BEGIN PUBLIC KEY-' in text:
        cmdline.extend (['-pubin'])
    else:
        raise Exception('Unknown key format "%s" !' % in_key)

    if pub_key_file:
        cmdline.extend (['-out', '%s' % pub_key_file])
        capture = False
    else:
        capture = True

    output = run_process (cmdline, capture_out = capture)
    if not capture:
        output = text = open(pub_key_file, 'r').read()
    data     = output.replace('\r', '')
    data     = data.replace('\n', '')
    data     = data.replace('  ', '')

    # Extract the modulus
    if is_prv_key:
        match = re.search('modulus(.*)publicExponent:\s+(\d+)\s+', data)
    else:
        match = re.search('Modulus(?:.*?):(.*)Exponent:\s+(\d+)\s+', data)
    if not match:
        raise Exception('Public key not found!')
    modulus  = match.group(1).replace(':', '')
    exponent = int(match.group(2))

    mod = bytearray.fromhex(modulus)
    # Remove the '00' from the front if the MSB is 1
    if mod[0] == 0 and (mod[1] & 0x80):
        mod = mod[1:]
    exp = bytearray.fromhex('{:08x}'.format(exponent))

    keydata   = mod + exp

    return keydata


#
# Sign an file using openssl
#
# priv_key   [Input]        Key Id or Path to Private key
# hash_type  [Input]        Signing hash
# sign_scheme[Input]        Sign/padding scheme
# in_file    [Input]        Input file to be signed
# out_file   [Input/Output] Signed data file
#

def single_sign_file (priv_key, hash_type, sign_scheme, in_file, out_file):

    _hash_type_string = {
        "SHA2_256"    : 'sha256',
        "SHA2_384"    : 'sha384',
        "SHA2_512"    : 'sha512',
    }

    _hash_digest_Size = {
        # Hash_string : Hash_Size
        "SHA2_256"    : 32,
        "SHA2_384"    : 48,
        "SHA2_512"    : 64,
        "SM3_256"     : 32,
    }

    _sign_scheme_string = {
        "RSA_PKCS1"    : 'pkcs1',
        "RSA_PSS"      : 'pss',
    }


    # Temporary files to store hash generated
    hash_file_tmp = out_file+'.hash.tmp'
    hash_file     = out_file+'.hash'

    # Generate hash using openssl dgst in hex format
    cmdargs = [get_openssl_path(), 'dgst', '-'+'%s' % _hash_type_string[hash_type], '-out', '%s' % hash_file_tmp, '%s' % in_file]
    run_process (cmdargs)

    # Extract hash form dgst command output and convert to ascii
    with open(hash_file_tmp, 'r') as fin:
        hashdata = fin.read()
    fin.close()
    os.remove (hash_file_tmp)

    try:
        hashdata = hashdata.rsplit('=', 1)[1].strip()
    except:
        raise Exception('Hash Data not found for signing!')

    if len(hashdata) != (_hash_digest_Size[hash_type] * 2):
        raise Exception('Hash Data size do match with for hash type!')

    hashdata_bytes = bytearray.fromhex(hashdata)
    open (hash_file, 'wb').write(hashdata_bytes)

    print ("Key used for Singing %s !!" % priv_key)

    # sign using Openssl pkeyutl
    cmdargs = [get_openssl_path(), 'pkeyutl', '-sign', '-in', '%s' % hash_file, '-inkey', '%s' % priv_key,
               '-out', '%s' % out_file, '-pkeyopt', 'digest:%s' % _hash_type_string[hash_type],
               '-pkeyopt', 'rsa_padding_mode:%s' % _sign_scheme_string[sign_scheme]]

    run_process (cmdargs)
    os.remove (hash_file)

    return


def parse_payload_bin (bin):
    image = []
    offset = 0
    pld_info_hdr = PAYLOAD_INFO_HEADER.from_buffer (bin)
    if pld_info_hdr.CommonHeader.Identifier != b'PLDH':
        print ("Unexpected payload image format !")
        return

    image.append ((offset, pld_info_hdr))
    dlen    = pld_info_hdr.CommonHeader.HeaderLength
    offset += dlen + get_padding_size (dlen)

    if pld_info_hdr.Capability &  PAYLOAD_INFO_HEADER.CAP_RELOC:
        pld_reloc_hdr = PAYLOAD_RELOC_HEADER.from_buffer (bin, offset)
        if pld_reloc_hdr.CommonHeader.Identifier != b'PLDR':
            print ("Unexpected relocation table format !")
            return
        image.append ((offset, pld_reloc_hdr))
        dlen    = pld_reloc_hdr.CommonHeader.HeaderLength
        rel_len = dlen   - sizeof(PAYLOAD_RELOC_HEADER)
        rel_off = offset + sizeof(PAYLOAD_RELOC_HEADER)
        offset += dlen + get_padding_size (dlen)
        image.append ((offset, bin[rel_off:rel_off + rel_len]))


    offset  = pld_info_hdr.ImageOffset
    pld_len = pld_info_hdr.ImageLength
    image.append ((offset, bin[offset:offset + pld_len]))
    offset += pld_len

    if pld_info_hdr.Capability &  PAYLOAD_INFO_HEADER.CAP_AUTH:
        pld_auth_hdr = PAYLOAD_AUTH_HEADER.from_buffer (bin, offset)
        if pld_auth_hdr.CommonHeader.Identifier != b'PLDA':
            print ("Unexpected authentication table format !")
            return
        image.append ((offset, pld_auth_hdr))
        offset += sizeof(PAYLOAD_AUTH_HEADER)
        signature_hdr = SIGNATURE_HDR.from_buffer (bin, offset)
        if signature_hdr.Identifier != b'SIGN':
            print ("Unexpected signature format !")
            return
        image.append ((offset, signature_hdr))
        offset += sizeof(signature_hdr)
        dlen = signature_hdr.SigSize
        image.append ((offset, bin[offset:offset+dlen]))
        offset += dlen
        pubkey_hdr = PUB_KEY_HDR.from_buffer (bin, offset)
        if pubkey_hdr.Identifier != b'PUBK':
            print ("Unexpected public key format !")
            return
        image.append ((offset, pubkey_hdr))
        offset += sizeof(pubkey_hdr)
        dlen = pubkey_hdr.KeySize
        image.append ((offset, bin[offset:offset+dlen]))
        offset += dlen + get_padding_size (dlen)

    for offset, each in image:
        if type(each) is bytearray:
            indent = 4
            if 'PAYLOAD_RELOC_HEADER' in last_type:
                print ('    RelocationData:')
                last_type = 'PAYLOAD_RAW_BIN'
            else:
                if 'PAYLOAD_RAW_BIN' in last_type:
                    print ('\nOffset:0x%06x <PAYLOAD_RAW_DATA>:' % (offset))
                elif 'PUB_KEY_HDR' in last_type:
                    print ('  PublicKeyData:')
                    indent += 2
                elif 'SIGNATURE_HDR' in last_type:
                    print ('  SignatureData:')
                    indent += 2
                else:
                    print ('  Binary:')
                last_type = ''
            print_bytes (each, offset = offset, indent = 4, brief = True)
            dlen = len(each)
        else:
            indent = 0
            last_type = str(type(each))
            if 'SIGNATURE_HDR' in last_type or 'PUB_KEY_HDR' in last_type:
                indent += 2

            lines = output_struct(each, offset = [offset]).rstrip()
            print ('\n%sOffset:0x%06x %s' % (' ' * indent, offset, lines))
            dlen = sizeof(each)


    if offset + dlen != pld_info_hdr.Length:
        print ('Payload image length (0x%06X) does not match the length in header (0x%06X) !' % (offset, pld_info_hdr.Length))


def build_payload_fd (fd_bin, pri_key = None, hash_type = 'SHA2_256', sign_scheme = 'RSA_PSS', alignment = 0x1000, align_in_place = False):
    pld_info_hdr = PAYLOAD_INFO_HEADER ()
    pld_info_hdr.ImageLength = len(fd_bin)
    if not (alignment and (not(alignment & (alignment - 1)))):
        raise Exception ('Image alignment needs to be power of 2 !')
    pld_info_hdr.ImageAlignment = alignment

    # Extract relocation info for SEC
    reloc_fmt = PAYLOAD_RELOC_HEADER.RELOC_FMT_RAW
    #reloc_fmt = PAYLOAD_RELOC_HEADER.RELOC_FMT_PTR

    new_fd_bin = bytearray (fd_bin)
    sec_off, sec_len = PAYLOAD_HEADER_HELPER.locate_sec_image_in_fd (new_fd_bin)
    pe_img = new_fd_bin[sec_off:sec_off + sec_len]
    pe_obj = PeTeImage(0, pe_img)
    roff, rlen = pe_obj.ParseReloc()

    if pe_obj.IsTeImage():
        stripped = pe_obj.TeHdr.StrippedSize
    else:
        stripped = 0

    if reloc_fmt == PAYLOAD_RELOC_HEADER.RELOC_FMT_RAW:
        reloc_data = pe_img[roff : roff + rlen]
    else:
        reloc_data = PE_RELOC_BLOCK_HEADER ()
        reloc_data.PageRVA   = sec_off + roff
        reloc_data.BlockSize = rlen

    pld_reloc_hdr, pld_reloc_data = PAYLOAD_HEADER_HELPER.create_reloc_table (reloc_fmt, sec_off, bytearray (reloc_data), stripped)
    pld_reloc_tbl = bytearray(pld_reloc_hdr) + pld_reloc_data

    pld_info_hdr_len = sizeof(pld_info_hdr)
    reloc_tbl_off = pld_info_hdr_len + get_padding_size (pld_info_hdr_len)

    reloc_tbl_len = len(pld_reloc_tbl)
    curr_offset   = reloc_tbl_off + reloc_tbl_len
    pld_img_off   = curr_offset + get_padding_size (curr_offset)
    if align_in_place:
        pld_img_off += get_padding_size (pld_img_off, alignment)

    pld_img_len  = len(fd_bin)
    curr_offset  = pld_img_off + pld_img_len
    pld_auth_off = curr_offset + get_padding_size (curr_offset)

    if reloc_tbl_len > 0:
        pld_info_hdr.Capability |= PAYLOAD_INFO_HEADER.CAP_RELOC

    if pri_key:
        pld_info_hdr.Capability |= PAYLOAD_INFO_HEADER.CAP_AUTH

    pld_info_hdr.Machine = pe_obj.GetMachineType ()
    pld_info_hdr.EntryPointOffset = pe_obj.GetEntrypoint () + sec_off
    pld_info_hdr.ImageOffset = pld_img_off
    pld_info_hdr.Length   = pld_auth_off
    pld_info_hdr.Revision = 0x00010001

    img_info = [
                 ('HEAD', 0,             bytearray(pld_info_hdr)),
                 ('RELO', reloc_tbl_off, pld_reloc_tbl),
                 ('PLDI', pld_img_off,   fd_bin)
               ]

    offset = 0
    pld_bin = bytearray()
    for name, doff, bins in img_info:
        dlen    = len(bins)
        if doff > offset:
            pld_bin.extend (b'\x00' * (doff - offset))
            offset = doff
        offset += dlen
        pld_bin.extend (bins)

    auth_comp = PAYLOAD_HEADER_HELPER.create_auth_table (pri_key, hash_type, sign_scheme, pld_bin)
    auth_bin = bytearray(auth_comp[0]) + bytearray(auth_comp[1]) + auth_comp[2] + bytearray(auth_comp[3]) + auth_comp[4]

    pld_info_hdr = PAYLOAD_INFO_HEADER.from_buffer (pld_bin)
    pld_info_hdr.Length = len(pld_bin) + (get_padding_size (offset) + len(auth_bin))

    padding = b'\x00' * get_padding_size (offset)
    return pld_bin + padding + auth_bin



def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-i',  '--in_image',  type=str,  required=True, help='Payload input image file path')
    parser.add_argument('-t',  '--type',      type=str,  default = 'UEFI', choices=['UEFI'],  help='Payload type')
    parser.add_argument('-o',  '--out_image', type=str,  default =  '', help='Payload output image file path')
    parser.add_argument('-k',  '--key',       type=str,  default =  '', help='Private key for payload signing')
    parser.add_argument('-a',  '--align',     type=str,  default = '1', help='Actual raw payload alignment in image')
    parser.add_argument('-ai', '--align_in_place', action='store_true', help='The raw payload needs to be aligned in place or not')

    # Parse command line arguments
    args = parser.parse_args()

    if args.out_image:
        bins = get_file_data (args.in_image)
        pld_bin = build_payload_fd (bins, pri_key = args.key, alignment = int(args.align, 0), align_in_place = args.align_in_place)
        gen_file_from_object (args.out_image, pld_bin)
        print ("The payload image with length 0x%06X has been created successfully !\n%s" % (len(pld_bin), args.out_image))
    else:
        bin = bytearray(get_file_data(args.in_image))
        parse_payload_bin (bin)

    return 0


if __name__ == '__main__':
    sys.exit(main())
