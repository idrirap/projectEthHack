#!/usr/bin/python3

import secrets
import sys
import subprocess
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


    def addSection(self):
        self.NumberOfSections += 1

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
        self.OEP = self.AddressOfEntryPoint 


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

    def getOEP(self):
        return self.OEP


    def setEP(self, newEP):
        self.AddressOfEntryPoint = newEP

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

    def sectionsInfo(self, full):
        i = 0
        if full : 
            print("\033[32mName, \033[33mmisc, \033[34mvirtualAddr, \033[35msizeRaw, \033[36mptrRaw, \033[39mptrReloc, ptrLine, nbReloc, nbLine, meta")
        for sec in self.section:
            if not full : 
                print("{} : {} -> {} - {}".format(
                    sec["name"], hex(sec["PointerToRawData"]), hex(sec["SizeOfRawData"]) , self.getSectionRights(i))
                )
            else:
                print("\033[32m{}, \033[33m{}, \033[34m{}, \033[35m{}, \033[36m{}, \033[39m{}, {}, {}, {}, {}".format(
                    self.section[i]["name"],                      # 8char
                    hex(self.section[i]["Misc"]),                 # long
                    hex(self.section[i]["VirtualAddress"]),       # long
                    hex(self.section[i]["SizeOfRawData"]),        # long
                    hex(self.section[i]["PointerToRawData"]),     # long
                    hex(self.section[i]["PointerToRelocations"]), # long
                    hex(self.section[i]["PointerToLinenumbers"]), # long
                    hex(self.section[i]["NumberOfRelocations"]),  # short
                    hex(self.section[i]["NumberOfLinenumbers"]),  # short
                    hex(self.section[i]["Characteristics"]),      # long
                ))
            i+=1


    def addSection(self, name, misc, size, meta):
        prevSize = self.section[-1]["SizeOfRawData"]
        newSec = {
            "name": name,
            "Misc": misc,
            "VirtualAddress": self.section[-1]["VirtualAddress"] + prevSize,
            "SizeOfRawData": size,
            "PointerToRawData": self.section[-1]["PointerToRawData"] + prevSize,
            "PointerToRelocations": 0,
            "PointerToLinenumbers": 0,
            "NumberOfRelocations": 0,
            "NumberOfLinenumbers": 0,
            "Characteristics": meta
        }
        self.section.append(newSec)
        self.index[self.section[-1]["name"]] = len(self.section) - 1
        # offseting everything
        """
        for i in self.section:
            if i["name"] != name:
                i["VirtualAddress"] += 40
                i["PointerToRawData"] += 40
        """

    def addRight(self, sectionName, right):
        if right == "r":
            self.section[self.index[sectionName]]["Characteristics"] |= 0x40000000
        if right == "w":
            self.section[self.index[sectionName]]["Characteristics"] |= 0x80000000
        if right == "x":
            self.section[self.index[sectionName]]["Characteristics"] |= 0x20000000


    def getStartAddr(self, sectionName):
        return self.section[self.index[sectionName]]["PointerToRawData"]

    def getVirtStart(self, sectionName):
        return self.section[self.index[sectionName]]["VirtualAddress"]

    def getEndAddr(self, sectionName):
        return self.section[self.index[sectionName]]["PointerToRawData"] + self.section[self.index[sectionName]]["SizeOfRawData"]

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


def generateKey():
    random = secrets.token_bytes(4)
    while(int.from_bytes(random, 'big') & 0x000000FF == 0):
        random = secrets.token_bytes(4)
    return random


def hashing(data):
    output = 0
    for i in range(int(len(data)/4)):
        output ^= int.from_bytes(data[4*i:4*(i+1)], 'big')
    return output

def xorDat(data, key):
    data = bytearray(data)
    for i in range(len(data)):
        data[i] ^= key[i % 4]
    return data


def createUnpacker(ADDRESS_CODE_START, TOTAL_CODE_SIZE, PARTIAL_KEY, CORRECT_HASH, Arch=0): # TODO Arch 32/64
    print(hex(TOTAL_CODE_SIZE))
    key = int.from_bytes(PARTIAL_KEY, 'little') & 0xFFFFFF00
    #little indianing
    hs = format(CORRECT_HASH, '08x')
    final_string = "0x" + hs[8:10] + hs[6:8] + hs[4:6] + hs[2:4] + hs[:2]
    subprocess.run(["cp", "unpacker.asm", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/ADDRESS_CODE_START/{hex(ADDRESS_CODE_START + 0x400000)}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/TOTAL_CODE_SIZE/{hex(TOTAL_CODE_SIZE)}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/PARTIAL_KEY/{hex(key)}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/CORRECT_HASH/{final_string}/g", "tmpUnpack.asm"])
    subprocess.run(["nasm", "tmpUnpack.asm"])
    subprocess.run(["rm", "tmpUnpack.asm"])
    with open("tmpUnpack", "rb") as f:
        output = f.read()
    subprocess.run(["rm", "tmpUnpack"])
    return output




def main(argv):
    with open(argv[1], "rb") as f:
        binary = f.read()

    #######################################################
    #                       PARSING                       #
    #######################################################

    # Parse MSDOS header
    msdos = MSDOS(binary[:64])
    msdos.printPEOffset()

    # Find address of PEHeader
    pe = PEHeader(binary[msdos.pe_offset:msdos.pe_offset + 24])
    if pe.getArch() != 0:
        print("{}bits".format(pe.getArch()))
    else:
        return 1

    if pe.getArch() == 64:
        print("64bits not working for now")
        exit(2)
    print("Size of optional header : {}".format(pe.SizeOfOptionalHeader))
    
    offsetPEOpt = msdos.pe_offset + 24

    # Parse optional header
    opt = PEOptHeader(binary[offsetPEOpt:offsetPEOpt + pe.SizeOfOptionalHeader], pe.getArch())
    
    offsetSectionTable = offsetPEOpt + pe.SizeOfOptionalHeader
    # Parse sections header
    sections = SectionHeader(binary[offsetSectionTable:offsetSectionTable + 40 * pe.NumberOfSections], pe.NumberOfSections)

    endSectionHeader = offsetSectionTable + 40 * pe.NumberOfSections

    ############ PRINT BEFORE ##############
    sections.sectionsInfo(True)

    #######################################################
    #            EXTRACTING IMPORTANT DATA                #
    #######################################################

    # Get original entry point
    entry = opt.getOEP()
    print("OEP : {}".format(hex(entry)))
    
    # Get starting and finishing address of .text section
    text = sections.getStartAddr(b'.text\0\0\0')
    textEnd = sections.getEndAddr(b'.text\0\0\0')

    #be sure packedSize is multiple of 4
    packedSize = textEnd - opt.getOEP()
    while(packedSize % 4 != 0):
        packedSize -= 1

    print(hex(packedSize))

    #######################################################
    #                   GENERATING STUFF                  #
    #######################################################
    
    #########################.text#########################
    # Set .text writeable
    sections.addRight(b'.text\0\0\0', 'w')

    key = generateKey()
    print(f"key : {key}")

    packedText = xorDat(binary[entry:entry + packedSize], key)
    goodHash = hashing(binary[entry:entry + packedSize])
    
    unpacker = createUnpacker(entry, packedSize, key, goodHash)
    print(f"entry : {hex(entry)} size : {hex(textEnd - entry)} end : {hex(textEnd)}")

    #######################################################
    #           CREATING NEW SECTION AND LOAD             #
    #######################################################

    ########################.unpack########################
    # Create new pack section
    sections.addSection(b'.unpack\0', len(unpacker), 0x1000, 0x60000020)
    pe.addSection()
    # Get starting and finishing address of .unpack and .text section
    upckStart = sections.getStartAddr(b'.unpack\0')
    upckEnd = sections.getEndAddr(b'.unpack\0')
    text = sections.getStartAddr(b'.text\0\0\0')
    textEnd = sections.getEndAddr(b'.text\0\0\0')

    # Change entry point
    opt.setEP(sections.getVirtStart(b'.unpack\0'))

    ############ PRINT BEFORE ##############
    sections.sectionsInfo(True)

    #######################################################
    #                     PACKING BACK                    #
    #######################################################

    packedBin = (
        # Headers
        binary[0:msdos.pe_offset] + pe.repack() + opt.repack() + sections.repack() + 
        binary[endSectionHeader+40:text] + # endSectionHeader + 40 (.packed added)

        # Sections
        binary[text:opt.getOEP()] + packedText + 
        binary[opt.getOEP() + packedSize:upckStart] + unpacker + b'\x00'*(0x1000-len(unpacker)) +
        binary[upckStart:]
    )

    with open("{}.packed.exe".format(argv[1]), "wb") as f:
        f.write(packedBin)

if __name__=="__main__": # TODO : Add CLI
    if len(sys.argv) != 2:
        print("usage: {} <filename>".format(sys.argv[0]))
        exit(1)
    exit(main(sys.argv))