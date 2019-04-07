#!/usr/bin/python3

import sys
from struct import pack, unpack


"""
 struct DOS_Header 
 {
// short is 2 bytes, long is 4 bytes
     char signature[2] = { 'M', 'Z' };
     short lastsize;
     short nblocks;
     short nreloc;
     short hdrsize;
     short minalloc;
     short maxalloc;
     void *ss; // 2 byte value
     void *sp; // 2 byte value
     short checksum;
     void *ip; // 2 byte value
     void *cs; // 2 byte value
     short relocpos;
     short noverlay;
     short reserved1[4];
     short oem_id;
     short oem_info;
     short reserved2[10];
     long  e_lfanew; // Offset to the 'PE\0\0' signature relative to the beginning of the file
 }

"""

class MSDOS:

    def __init__(self, headerbin):
        self.reserved1 = [0 for i in range(4)]
        self.reserved2 = [0 for i in range(10)]
        (
            self.signature, 
            self.lastsize, 
            self.nblocks, 
            self.nreloc, 
            self.hdrsize, 
            self.minalloc, 
            self.maxalloc, 
            self.ss, 
            self.sp, 
            self.checksum, 
            self.ip, 
            self.cs, 
            self.relocpos, 
            self.noverlay, 
            self.reserved1[0], self.reserved1[1], self.reserved1[2], self.reserved1[3], 
            self.oem_id, 
            self.oem_info, 
            self.reserved2[0], self.reserved2[1], self.reserved2[2], self.reserved2[3], self.reserved2[4], 
            self.reserved2[5], self.reserved2[6], self.reserved2[7], self.reserved2[8], self.reserved2[9], 
            self.pe_offset
        ) = unpack("<2sHHHHHHHHHHHHH4HHH10HL", headerbin)

    def printPEOffset(self):
        print("PE offset : {} / {}".format(hex(self.pe_offset), self.pe_offset))


    def repack(self):
        return pack(
            "<2sHHHHHHHHHHHHH4HHH10HL",
            self.signature, self.lastsize, self.nblocks, 
            self.nreloc, self.hdrsize, self.minalloc, 
            self.maxalloc, self.ss, self.sp, self.checksum, 
            self.ip, self.cs, self.relocpos, self.noverlay, 
            self.reserved1[0], self.reserved1[1], self.reserved1[2], self.reserved1[3], self.oem_id, self.oem_info, 
            self.reserved2[0], self.reserved2[1], self.reserved2[2], self.reserved2[3], self.reserved2[4], 
            self.reserved2[5], self.reserved2[6], self.reserved2[7], self.reserved2[8], self.reserved2[9], 
            self.pe_offset
        )

"""


 struct COFFHeader
 {
    char signature[4]           // contains PE\0\0
    short Machine;              // type of machines see https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#PE_Header
    short NumberOfSections;
    long TimeDateStamp;
    long PointerToSymbolTable;
    long NumberOfSymbols;
    short SizeOfOptionalHeader;
    short Characteristics;      // tell if the file is an exe or a dll etc...
 }

"""

class PEHeader:

    def __init__(self, headerbin):
        (
            self.signaturePE, self.Machine, self.NumberOfSections, 
            self.TimeDateStamp, self.PointerToSymbolTable, self.NumberOfSymbols, 
            self.SizeOfOptionalHeader, self.Characteristics
        ) = unpack("<4sHHLLLHH", headerbin)

    def getArch(self):
        bits = 0

        if self.Machine == 0x14c:
            bits = 32
        if self.Machine == 0x8664:
            bits = 64
        return bits


    def repack(self):
        return pack(
            "<4sHHLLLHH",
            self.signaturePE, self.Machine, self.NumberOfSections, 
            self.TimeDateStamp, self.PointerToSymbolTable, self.NumberOfSymbols, 
            self.SizeOfOptionalHeader, self.Characteristics
        )

"""

 struct PEOptHeader
 {
/* 64 bit version of the PE Optional Header also known as IMAGE_OPTIONAL_HEADER64
char is 1 byte
short is 2 bytes
long is 4 bytes
long long is 8 bytes
*/
    short signature; //decimal number 267 for 32 bit, 523 for 64 bit, and 263 for a ROM image. 
    char MajorLinkerVersion; 
    char MinorLinkerVersion;
    long SizeOfCode;
    long SizeOfInitializedData;
    long SizeOfUninitializedData;
    long AddressOfEntryPoint;  //The RVA of the code entry point
    long BaseOfCode;
    /*The next 21 fields are an extension to the COFF optional header format*/
    long long ImageBase;
    long SectionAlignment;
    long FileAlignment;
    short MajorOSVersion;
    short MinorOSVersion;
    short MajorImageVersion;
    short MinorImageVersion;
    short MajorSubsystemVersion;
    short MinorSubsystemVersion;
    long Win32VersionValue;
    long SizeOfImage;
    long SizeOfHeaders;
    long Checksum;
    short Subsystem;
    short DLLCharacteristics;
    long long SizeOfStackReserve;
    long long SizeOfStackCommit;
    long long SizeOfHeapReserve;
    long long SizeOfHeapCommit;
    long LoaderFlags;
    long NumberOfRvaAndSizes;
    data_directory DataDirectory[NumberOfRvaAndSizes];     //Can have any number of elements, matching the number in NumberOfRvaAndSizes.
 }                                        //However, it is always 16 in PE files.
"""

# Optional header are not optional


class PEOptHeader:
    def __init__(self, header, arch):
        self.arch = arch
        pattern = ""
        if arch == 32:
            pattern = "<HccLLLLLLLLLLHHHHHHLLLLHHLLLLL"
        else:
            pattern = "<HccLLLLLLLLLLHHHHHHLLLLHHQQQQL"
        (
            self.PEOptsignature, #short
            self.MajorLinkerVersion, #char
            self.MinorLinkerVersion, #char
            self.SizeOfCode, #long
            self.SizeOfInitializedData, #long   
            self.SizeOfUninitializedData,    #long
            self.AddressOfEntryPoint, #long
            self.BaseOfCode, #long
            self.BaseOfData, #long
            self.ImageBase, #long
            self.SectionAlignment, #long   
            self.FileAlignment, #long
            self.MajorOSVersion, #short
            self.MinorOSVersion, #short
            self.MajorImageVersion, #short
            self.MinorImageVersion, #short
            self.MajorSubsystemVersion, #short 
            self.MinorSubsystemVersion, #short
            self.Win32VersionValue, #long
            self.SizeOfImage, #long
            self.SizeOfHeaders, #long
            self.Checksum, #long
            self.Subsystem, #short
            self.DLLCharacteristics, #short   
            self.SizeOfStackReserve, #long -> long long if 64b
            self.SizeOfStackCommit, #long -> long long if 64b
            self.SizeOfHeapReserve, #long -> long long if 64b
            self.SizeOfHeapCommit, #long -> long long if 64b
            self.LoaderFlags, #long
            self.NumberOfRvaAndSizes #long   
            #data_directory DataDirectory[NumberOfRvaAndSizes]
        ) = unpack(pattern, header[0:96])
        self.data_directory = [{"virtualAddress": 0, "size": 0} for i in range(self.NumberOfRvaAndSizes)]

        for i in range(self.NumberOfRvaAndSizes):
            (
                self.data_directory[i]["virtualAddress"], 
                self.data_directory[i]["size"] 
            ) = unpack("<LL", header[96 + 8*i:96 + 8*(i+1)])


    def repack(self):
        pattern = ""
        if self.arch == 32:
            pattern = "<HccLLLLLLLLLLHHHHHHLLLLHHLLLLL"
        else:
            pattern = "<HccLLLLLLLLLLHHHHHHLLLLHHQQQQL"
        output = pack(
            pattern,
            self.PEOptsignature, self.MajorLinkerVersion, self.MinorLinkerVersion,
            self.SizeOfCode, self.SizeOfInitializedData, self.SizeOfUninitializedData,
            self.AddressOfEntryPoint, self.BaseOfCode, self.BaseOfData, self.ImageBase, 
            self.SectionAlignment, self.FileAlignment, self.MajorOSVersion, self.MinorOSVersion,
            self.MajorImageVersion, self.MinorImageVersion, self.MajorSubsystemVersion,
            self.MinorSubsystemVersion, self.Win32VersionValue, self.SizeOfImage,
            self.SizeOfHeaders, self.Checksum, self.Subsystem, self.DLLCharacteristics,
            self.SizeOfStackReserve, self.SizeOfStackCommit, self.SizeOfHeapReserve, 
            self.SizeOfHeapCommit, self.LoaderFlags, self.NumberOfRvaAndSizes 
        )
        for i in range(self.NumberOfRvaAndSizes):
            output += pack("<LL", self.data_directory[i]["virtualAddress"], self.data_directory[i]["size"])
        return output

"""
    struct IMAGE_SECTION_HEADER 
 {
// short is 2 bytes
// long is 4 bytes
  char  Name[IMAGE_SIZEOF_SHORT_NAME]; // IMAGE_SIZEOF_SHORT_NAME is 8 bytes
  union {
    long PhysicalAddress;
    long VirtualSize;
  } Misc;
  long  VirtualAddress;
  long  SizeOfRawData;
  long  PointerToRawData;
  long  PointerToRelocations;
  long  PointerToLinenumbers;
  short NumberOfRelocations;
  short NumberOfLinenumbers;
  long  Characteristics;              // Tell if the section is writable, readable, executable and more
 }
    """

class SectionHeader:
    def __init__(self, header, nbSections):
        self.section = [{
                "name":None, "Misc": None, "VirtualAddress": None,
                "SizeOfRawData": None, "PointerToRawData": None, "PointerToRelocations": None,
                "PointerToLinenumbers": None, "NumberOfRelocations": None, "NumberOfLinenumbers": None,
                "Characteristics": None,
                } for i in range(nbSections)]
        self.index = {}

        for i in range(nbSections):
            (
                self.section[i]["name"],                 # 8char
                self.section[i]["Misc"],                 # long
                self.section[i]["VirtualAddress"],       # long
                self.section[i]["SizeOfRawData"],        # long
                self.section[i]["PointerToRawData"],     # long
                self.section[i]["PointerToRelocations"], # long
                self.section[i]["PointerToLinenumbers"], # long
                self.section[i]["NumberOfRelocations"],  # short
                self.section[i]["NumberOfLinenumbers"],  # short
                self.section[i]["Characteristics"],      # long
            ) = unpack("<8sLLLLLLHHL", header[40*i:40*(i+1)])
            self.index[self.section[i]["name"]] = i


    def getSectionRights(self, i):
        secChara = self.section[i]["Characteristics"] & 0xF0000000
        rights = ""
        if secChara & 0x40000000 == 0x40000000:
            rights += "r"
        if secChara & 0x80000000 == 0x80000000:
            rights += "w"
        if secChara & 0x20000000 == 0x20000000:
            rights += "x"
        return rights

    def sectionsInfo(self):
        i = 0
        for sec in self.section:
            print("{} : {} - {}".format(sec["name"], hex(sec["VirtualAddress"]), self.getSectionRights(i)))
            i+=1


    def addRight(self, section, right):
        if right == "r":
            self.section[self.index[section]]["Characteristics"] |= 0x40000000
        if right == "w":
            self.section[self.index[section]]["Characteristics"] |= 0x80000000
        if right == "x":
            self.section[self.index[section]]["Characteristics"] |= 0x20000000


    def repack(self):
        output = b''
        for i in range(len(self.section)):
            output += pack(
                "<8sLLLLLLHHL", 
                self.section[i]["name"], self.section[i]["Misc"], self.section[i]["VirtualAddress"],       # long
                self.section[i]["SizeOfRawData"], self.section[i]["PointerToRawData"], 
                self.section[i]["PointerToRelocations"],  self.section[i]["PointerToLinenumbers"], # long
                self.section[i]["NumberOfRelocations"], self.section[i]["NumberOfLinenumbers"],  # short
                self.section[i]["Characteristics"],      # long
            )
        return output


def main(argv):
    with open(argv[1], "rb") as f:
        binary = f.read()

    msdos = MSDOS(binary[:64])
    msdos.printPEOffset()

    pe = PEHeader(binary[msdos.pe_offset:msdos.pe_offset + 24])
    if pe.getArch() != 0:
        print("{}bits".format(pe.getArch()))
    else:
        return 1
    print("Size of optional header : {}".format(pe.SizeOfOptionalHeader))
    
    offsetPEOpt = msdos.pe_offset + 24

    opt = PEOptHeader(binary[offsetPEOpt:offsetPEOpt + pe.SizeOfOptionalHeader], pe.getArch())
    
    offsetSectionTable = offsetPEOpt + pe.SizeOfOptionalHeader

    sections = SectionHeader(binary[offsetSectionTable:offsetSectionTable + 40 * pe.NumberOfSections], pe.NumberOfSections)

    sections.sectionsInfo()

    # sections.addRight(b'.text\0\0\0', 'w')

    # bin2 = binary[0:offsetSectionTable] + sections.repack() + binary[offsetSectionTable+40*pe.NumberOfSections:]

    # with open("{}2".format(argv[1]), "wb") as f:
    #     f.write(bin2)

if __name__=="__main__":
    if len(sys.argv) != 2:
        print("usage: {} <filename>".format(sys.argv[0]))
        exit(1)
    exit(main(sys.argv))