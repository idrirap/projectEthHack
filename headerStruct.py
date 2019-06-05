#!/usr/bin/python3

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


    def printAll(self):
        print(
            f'signature : {self.signature}\n' + 
            f'lastsize : {self.lastsize}\n' + 
            f'nblocks : {self.nblocks}\n' + 
            f'nreloc : {self.nreloc}\n' + 
            f'hdrsize : {self.hdrsize}\n' + 
            f'minalloc : {self.minalloc}\n' + 
            f'maxalloc : {self.maxalloc}\n' + 
            f'ss : {self.ss}\n' + 
            f'sp : {self.sp}\n' + 
            f'checksum : {self.checksum}\n' + 
            f'ip : {self.ip}\n' + 
            f'cs : {self.cs}\n' + 
            f'relocpos : {self.relocpos}\n' + 
            f'noverlay : {self.noverlay}\n' + 
            f'reserved1 : {self.reserved1}\n' +
            f'oem_id : {self.oem_id}\n' + 
            f'oem_info : {self.oem_info}\n' + 
            f'reserved2 : {self.reserved2}\n' +
            f'pe_offset : {self.pe_offset}\n' 
        )


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


    def printAll(self):
        print(
            f"signaturePE : {self.signaturePE}\n" +
            f"Machine : {self.Machine}\n" +
            f"NumberOfSections : {self.NumberOfSections}\n" + 
            f"TimeDateStamp : {self.TimeDateStamp}\n" +
            f"PointerToSymbolTable : {self.PointerToSymbolTable}\n" + 
            f"NumberOfSymbols : {self.NumberOfSymbols}\n" +
            f"SizeOfOptionalHeader : {self.SizeOfOptionalHeader}\n" +
            f"Characteristics : {self.Characteristics}\n"
        )
        print(f"Arch : {self.getArch()} bits")


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
            size = 96
        else:
            pattern = "<HccLLLLLLLLLLHHHHHHLLLLHHQQQQL"
            size = 96 + 16
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
        ) = unpack(pattern, header[0:size])
        self.data_directory = [{"virtualAddress": 0, "size": 0} for i in range(self.NumberOfRvaAndSizes)]
        for i in range(self.NumberOfRvaAndSizes):
            (
                self.data_directory[i]["virtualAddress"], 
                self.data_directory[i]["size"] 
            ) = unpack("<LL", header[96 + 8*i:96 + 8*(i+1)])
        self.OEP = self.AddressOfEntryPoint 


    def printAll(self, sections, fileSize, sectionOffset):
        output =f'MinorLinkerVersion : {self.MinorLinkerVersion} \n'
        if self.SizeOfCode != sections.getSizeOf("code"):
            output += f'\033[31mSizeOfCode : {hex(self.SizeOfCode)} != {hex(sections.getSizeOf("code"))} (real)\033[39m\n'
        else:
            output += f'\033[32mSizeOfCode : {hex(self.SizeOfCode)}\033[39m\n'
        if self.SizeOfInitializedData != sections.getSizeOf("initialized"):
            output += f'\033[31mSizeOfInitializedData : {hex(self.SizeOfInitializedData)} != {hex(sections.getSizeOf("initialized"))} (real)\033[39m\n'
        else:
            output += f'\033[32mSizeOfInitializedData : {hex(self.SizeOfInitializedData)}\033[39m\n'
        if self.SizeOfUninitializedData != sections.getSizeOf("uninitialized"):
            output += f'\033[31mSizeOfUninitializedData : {hex(self.SizeOfUninitializedData)} != {hex(sections.getSizeOf("uninitialized"))} (real)\033[39m\n'
        else:
            output += f'\033[32mSizeOfUninitializedData : {hex(self.SizeOfUninitializedData)}\033[39m\n'
        output += (
            f'\033[33mAddressOfEntryPoint : {hex(self.AddressOfEntryPoint)}\033[39m \n' +
            f'BaseOfCode : {hex(self.BaseOfCode)} \n' +
            f'BaseOfData : {hex(self.BaseOfData)} \n' +
            f'ImageBase : {hex(self.ImageBase)}'
        )
        if self.ImageBase == 0x00400000:
            output += ' = Image is an application \n'
        else:
            output += ' = Image not an application???\n'
        output += (
            f'\033[33mSectionAlignment : {hex(self.SectionAlignment)}\033[39m \n' +
            f'FileAlignment : {hex(self.FileAlignment)} \n' +
            f'MajorImageVersion : {hex(self.MajorImageVersion)} \n' +
            f'MinorImageVersion : {hex(self.MinorImageVersion)} \n' +
            f'MajorSubsystemVersion : {hex(self.MajorSubsystemVersion)} \n' +
            f'MinorSubsystemVersion : {hex(self.MinorSubsystemVersion)} \n' +
            f'Win32VersionValue : {hex(self.Win32VersionValue)} \n'
        )
        if self.SizeOfImage != fileSize:
            output += f'\033[31mSizeOfImage : {hex(self.SizeOfImage)} != {hex(fileSize)} (real)\033[39m\n'
        else:
            output +=f'\033[32mSizeOfImage : {hex(self.SizeOfImage)}\033[39m\n'
        headersSize = sectionOffset + 40 * len(sections.section)
        if self.SizeOfHeaders < headersSize:
            output += f'\033[31mSizeOfHeaders : {hex(self.SizeOfHeaders)} < {hex(headersSize)} (real) Data might be overight\033[39m\n'
        else:
            output += f'\033[32mSizeOfHeaders : {hex(self.SizeOfHeaders)}\033[39m\n'
        output += (
            f'Checksum : {hex(self.Checksum)} \n' +
            f'Subsystem : {hex(self.Subsystem)} \n' +
            f'DLLCharacteristics : {hex(self.DLLCharacteristics)} \n' +
            f'SizeOfStackReserve : {hex(self.SizeOfStackReserve)} \n' +
            f'SizeOfStackCommit : {hex(self.SizeOfStackCommit)} \n' +
            f'SizeOfHeapReserve : {hex(self.SizeOfHeapReserve)} \n' +
            f'SizeOfHeapCommit : {hex(self.SizeOfHeapCommit)} \n' +
            f'LoaderFlags : {hex(self.LoaderFlags)} \n' 
        )
        print(output)


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

    def addCode(self, size):
        self.SizeOfCode += size
        self.SizeOfImage += size

    def setSectionsSize(self, size):
        self.SizeOfImage = self.SizeOfHeaders + size

    def setEP(self, newEP):
        self.AddressOfEntryPoint = newEP

    def rmChecksum(self):
        self.Checksum = 0

    def getFileSize(self):
        return self.SizeOfImage

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


    def isExisting(self, sectName):
        for sect in self.section:
            if sect["name"] == sectName:
                return True
        return False


    def getStartSize(self):
        output = []
        for i in self.section:
            output.append([i["PointerToRawData"],i["SizeOfRawData"]])
        return output

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


    def getSizeOf(self, contains):
        mask = 0
        if contains == "code":
            mask = 0x00000020
        if contains == "initialized":
            mask = 0x00000040
        if contains == "uninitialized":
            mask = 0x00000080
        if mask == 0:
            print("Incorrect mask")
            exit(5)
        total = 0
        for sec in self.section:
            if sec["Characteristics"] & mask != 0:
                total += sec["SizeOfRawData"]
        return total


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
                print("\033[32m{}, \033[33m{}, \033[34m{}, \033[35m{}, \033[36m{}, \033[39m{}, {}, {}, {}, {}->{}".format(
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
                    self.getSectionRights(i),
                ))
            i+=1


    def addSection(self, name, misc, size, meta, ptrRaw=0):
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
        if ptrRaw != 0:
            newSec["PointerToRawData"] = ptrRaw
        self.section.append(newSec)
        self.index[self.section[-1]["name"]] = len(self.section) - 1
        # offseting everything
        """
        for i in self.section:
            if i["name"] != name:
                i["VirtualAddress"] += 40
                i["PointerToRawData"] += 40
        """

    def setAllWriteable(self):
        for sect in self.section:
            sect["Characteristics"] |= 0x80000000

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

    def getSectionEnd(self):
        return self.getEndAddr(self.section[-1]["name"])

    def getSectionStart(self):
        return self.getStartAddr(self.section[0]["name"])

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

    def getSectionsTotalSize(self):
        total = 0
        for i in self.section:
            total += i["SizeOfRawData"]
        return total

    def printBox(self):
        col = 5
        last = 0
        for sect in self.section:
            print(f"\033[3{col}m0x{format(sect['PointerToRawData'], '08x')} ################")
            print(f" "*11 + f" {'{:^16}'.format(sect['name'].decode('utf-8'))} ")
            print(f"0x{format(sect['PointerToRawData'] + sect['SizeOfRawData'] - 1, '08x')} ################")
            last = sect['PointerToRawData'] + sect['SizeOfRawData']
            col = (col + 1) % 7
            while col <= 1:
                col += 1
        return last
            