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


 struct COFFHeader
 {
    short Machine;
    short NumberOfSections;
    long TimeDateStamp;
    long PointerToSymbolTable;
    long NumberOfSymbols;
    short SizeOfOptionalHeader;
    short Characteristics;
 }

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


def main(argv):
    with open(argv[1], "rb") as f:

        binary = f.read()
        #print(binary)

    reserved1 = [0 for i in range(4)]
    reserved2 = [0 for i in range(10)]
    (
        signature, 
        lastsize, 
        nblocks, 
        nreloc, 
        hdrsize, 
        minalloc, 
        maxalloc, 
        ss, 
        sp, 
        checksum, 
        ip, 
        cs, 
        relocpos, 
        noverlay, 
        reserved1[0], reserved1[1], reserved1[2], reserved1[3], 
        oem_id, 
        oem_info, 
        reserved2[0], reserved2[1], reserved2[2], reserved2[3], reserved2[4], reserved2[5], reserved2[6], reserved2[7], 
        reserved2[8], reserved2[9], 
        e_lfanew        # offset to the PE
    ) = unpack("<2sHHHHHHHHHHHHH4HHH10HL", binary[:64])

    

    print("Offset PE : {}\n".format(e_lfanew))

    (
        signaturePE, Machine, NumberOfSections, TimeDateStamp, PointerToSymbolTable, NumberOfSymbols, 
        SizeOfOptionalHeader, Characteristics
    ) = unpack("<4sHHLLLHH", binary[e_lfanew:e_lfanew+24])
    print(unpack("<4sHHLLLHH", binary[e_lfanew:e_lfanew+24]))

    if Machine == 0x14c:
        print("32bits")
    if Machine == 0x8664:
        print("64bits")

    print("Size of optional header : {}".format(SizeOfOptionalHeader))
    
    offsetPEOpt = e_lfanew + 24

    (
    PEOptsignature, #short
    MajorLinkerVersion, #char
    MinorLinkerVersion, #char
    SizeOfCode, #long
    SizeOfInitializedData, #long   
    SizeOfUninitializedData,    #long
    AddressOfEntryPoint, #long
    BaseOfCode, #long
    BaseOfData, #long
    ImageBase, #long
    SectionAlignment, #long   
    FileAlignment, #long
    MajorOSVersion, #short
    MinorOSVersion, #short
    MajorImageVersion, #short
    MinorImageVersion, #short
    MajorSubsystemVersion, #short 
    MinorSubsystemVersion, #short
    Win32VersionValue, #long
    SizeOfImage, #long
    SizeOfHeaders, #long
    Checksum, #long
    Subsystem, #short
    DLLCharacteristics, #short   
    SizeOfStackReserve, #long -> long long if 64b
    SizeOfStackCommit, #long -> long long if 64b
    SizeOfHeapReserve, #long -> long long if 64b
    SizeOfHeapCommit, #long -> long long if 64b
    LoaderFlags, #long
    NumberOfRvaAndSizes #long   
    #data_directory DataDirectory[NumberOfRvaAndSizes]
    ) = unpack("<HccLLLLLLLLLLHHHHHHLLLLHHLLLLL", binary[offsetPEOpt:offsetPEOpt + 96])
    #print(unpack("<HccLLLLLLLLLHHHHHHLLLLHHLLLLLL", binary[offsetPEOpt:offsetPEOpt + 96]))


    offsetDD = offsetPEOpt + 96

    data_directory = [{"virtualAddress": 0, "size": 0} for i in range(NumberOfRvaAndSizes)]

    for i in range(NumberOfRvaAndSizes):
        (
            data_directory[i]["virtualAddress"], 
            data_directory[i]["size"] 
        ) = unpack("<LL", binary[offsetDD+8*i:offsetDD+8*(i+1)])
        #print("{}, {}".format(format(data_directory[i]["virtualAddress"], "#09x"), data_directory[i]["size"]))

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
  long  Characteristics;
 }
    """
    Section = [{
                "name":None, "Misc": None, "VirtualAddress": None,
                "SizeOfRawData": None, "PointerToRawData": None, "PointerToRelocations": None,
                "PointerToLinenumbers": None, "NumberOfRelocations": None, "NumberOfLinenumbers": None,
                "Characteristics": None,
                } for i in range(NumberOfSections)]

    offsetSectionLoader = offsetPEOpt+SizeOfOptionalHeader

    for i in range(NumberOfSections):
        (
            Section[i]["name"],                 # 8char
            Section[i]["Misc"],                 # long
            Section[i]["VirtualAddress"],       # long
            Section[i]["SizeOfRawData"],        # long
            Section[i]["PointerToRawData"],     # long
            Section[i]["PointerToRelocations"], # long
            Section[i]["PointerToLinenumbers"], # long
            Section[i]["NumberOfRelocations"],  # short
            Section[i]["NumberOfLinenumbers"],  # short
            Section[i]["Characteristics"],      # long
        ) = unpack("<8sLLLLLLHHL", binary[offsetSectionLoader+40*i:offsetSectionLoader+40*(i+1)])
        print("{} {}".format(
            Section[i]["name"], hex(Section[i]["VirtualAddress"]),
            )
        )

if __name__=="__main__":
    if len(sys.argv) != 2:
        print("usage: {} <filename>".format(argv[0]))
        exit(1)
    main(sys.argv)