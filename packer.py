#!/usr/bin/python3

import secrets
import sys
import subprocess
import argparse

import headerStruct

def generateKey(arch):
    # init values
    wordlength = 4
    mask = 0x000000FF
    if arch == 64:
        wordlength = 8
        mask = 0x00000000000000FF
    # kind of do while
    # generate random key until the two last digit != 00
    random = secrets.token_bytes(wordlength)
    while(int.from_bytes(random, 'big') & mask == 0):
        random = secrets.token_bytes(wordlength)
    return random


def hashing(data, arch): # TODO implement a real hashing function
    # init values
    wordlength = 4
    if arch == 64:
        wordlength = 8
    output = 0
    # xor each word with each other to create a kind of hash
    for i in range(int(len(data)/wordlength)):
        output ^= int.from_bytes(data[wordlength*i:wordlength*(i+1)], 'big')
    return output

def xorDat(data, key):
    data = bytearray(data)
    for i in range(len(data)):
        data[i] ^= key[i % len(key)]
    return data


def createUnpacker(ADDRESS_OEP, ADDRESS_CODE_START, TOTAL_CODE_SIZE, PARTIAL_KEY, CORRECT_HASH, arch): # TODO Arch 32/64
    if arch == 32:
        mask = 0xFFFFFF00
        hexFormat = '08x'
        file = "unpacker32.asm"
        runtimeOffset = 0x400000
    elif arch == 64:
        mask = 0xFFFFFFFFFFFFFF00
        hexFormat = '016x'
        file = "unpacker64.asm"
        runtimeOffset = 0x400000 # TODO : check this value
    else:
        exit(5)

    # remove two last bytes
    key = int.from_bytes(PARTIAL_KEY, 'little') & mask
    # little indianing
    hs = format(CORRECT_HASH, hexFormat)
    # if [:] out of bound, it returns ''
    final_string = "0x" + hs[14:16] + hs[12:14] + hs[10:12] + hs[8:10] + hs[6:8] + hs[4:6] + hs[2:4] + hs[:2]
    subprocess.run(["cp", file, "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/ADDRESS_CODE_START/{hex(ADDRESS_CODE_START + runtimeOffset)}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/TOTAL_CODE_SIZE/{hex(TOTAL_CODE_SIZE)}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/PARTIAL_KEY/{hex(key)}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/CORRECT_HASH/{final_string}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/ADDRESS_OEP/{hex(ADDRESS_OEP + runtimeOffset)}/g", "tmpUnpack.asm"])
    subprocess.run(["nasm", "tmpUnpack.asm"])
    subprocess.run(["rm", "tmpUnpack.asm"])
    with open("tmpUnpack", "rb") as f:
        output = f.read()
    subprocess.run(["rm", "tmpUnpack"])
    return output


    
    #######################################################
    #                       PARSING                       #
    #######################################################
def parsing(filename):
    with open(filename, "rb") as f:
        binary = f.read()

    # Offsets of header dict
    offsets = {"begin":0}

    # Parse MSDOS header
    msdos = headerStruct.MSDOS(binary[:64])

    # Get fist part of offsets
    offsets["pe"] = msdos.pe_offset
    offsets["PEOpt"] = offsets["pe"] + 24
    
    # Parse PE header
    pe = headerStruct.PEHeader(binary[offsets["pe"]:offsets["PEOpt"]])

    # Get second part of offsets
    offsets["section"] = offsets["PEOpt"] + pe.SizeOfOptionalHeader
    offsets["EndSection"] = offsets["section"] + 40 * pe.NumberOfSections

    if pe.getArch() == 0:
        print("Not 32 nor 64 bits")
        exit(1)

    # Parse optional header
    opt = headerStruct.PEOptHeader(binary[offsets["PEOpt"]:offsets["section"]], pe.getArch())
    
    # Parse sections header
    sections = headerStruct.SectionHeader(binary[offsets["section"]:offsets["EndSection"]], pe.NumberOfSections)

    return binary, offsets, msdos, pe, opt, sections


    #######################################################
    #                      INFO PRINT                     #
    #######################################################
def giveInfo(binary, offsets, msdos, pe, opt, sections):
    print(f"################# MS DOS ################\nStarts at : {hex(offsets['begin'])}")
    msdos.printAll()
    print(f"################### PE ##################\nStarts at : {hex(offsets['pe'])}")
    pe.printAll()
    print(f"############ OPTIONAL HEADERS ###########\nStarts at : {hex(offsets['PEOpt'])}")
    opt.printAll(sections, len(binary), offsets["section"])
    print(f"################ SECTIONS ###############\nStarts at : {hex(offsets['section'])}")
    sections.sectionsInfo(True)
    nbleft = (opt.SizeOfHeaders - (offsets['section'] + pe.NumberOfSections * 40)) / 40
    if nbleft >= 1:
        print(f"\n\033[32mCan add {nbleft} sections\033[39m")
    else:
        print(f"\n\033[31mCan't add any section. Size left = {nbleft} sections\033[39m")

    print("\n#########################################\n")
    print(f"\033[36m0x{format(offsets['begin'], '08x')} ################")
    print(" "*11 + "     MS DOS     ")
    print(f"0x{format(offsets['pe'] - 1, '08x')} ################")
    print(f"\033[32m0x{format(offsets['pe'], '08x')} ################")
    print(" "*11 + "       PE      ")
    print(f"0x{format(offsets['PEOpt'] - 1, '08x')} ################")
    print(f"\033[33m0x{format(offsets['PEOpt'], '08x')} ################")
    print(" "*11 + "    OPT HEAD    ")
    print(f"0x{format(offsets['section'] - 1, '08x')} ################")
    print(f"\033[34m0x{format(offsets['section'], '08x')} ################")
    print(" "*11 + "    SECTIONS    ")
    print(f"0x{format(opt.SizeOfHeaders - 1, '08x')} ################")
    print(f"\033[39m###########################")
    endOfLastSection = sections.printBox()
    if len(binary) > endOfLastSection:
        print(f"\033[31m0x{format(endOfLastSection, '08x')} ################")
        print(" "*11 + "     UNKNOWN    ")
        print(f"0x{format(len(binary) - 1, '08x')} ################")


def testSectionName(sectionName, default, sections, exists):
    if sectionName == None:
        sectionName = default
    if len(sectionName) > 8:
        verboseLog(1, f"Section name {sectionName} too long")
        exit(6)
    sectionName = bytes(sectionName, 'utf-8') + b'\x00' * (8 - len(sectionName))
    if sections.isExisting(sectionName) != exists:
        verboseLog(1, "Conflict with existing sections")
        exit(7)
    return sectionName
        

def addNewSection(newSect, size, pe, opt, sections):
    sections.addSection(newSect, size, 0x1000, 0x60000020)
    pe.addSection()
    opt.addCode(0x1000)
    opt.rmChecksum()


def packingBack(offsets, pe, opt, sections, packedSect, unpacker, binary, unpackingSect, sectionToPack, packedSize):
    upckStart = sections.getStartAddr(unpackingSect)
    upckEnd = sections.getEndAddr(unpackingSect)

    beginPack = sections.getStartAddr(sectionToPack)
    EndPack = sections.getEndAddr(sectionToPack)

    packedBin = (
        # Headers
        binary[0:offsets["pe"]] + pe.repack() + opt.repack() + sections.repack() + 
        binary[offsets["EndSection"]:beginPack] + 

        # packed Sections
        packedSect + binary[beginPack + packedSize:EndPack] + 

        # other section if existing
        binary[EndPack:upckStart] +
        unpacker + b'\x00'*(0x1000-len(unpacker)) +
        # after last section if other existing data
        binary[upckStart:]
    )
    return packedBin


def verboseLog(ok, message):
    if ok == 0:
        code = "[  \033[32mOK\033[39m  ]"
    if ok == 1:
        code = "[ \033[31mFAIL\033[39m ]"
    if ok == 2:
        code = "[ \033[33mINFO\033[39m ]"
    if verbose:
        print(f"{code} {message}")


def main(args):
    (
        binary, offsets, msdos, pe, opt, sections
    ) = parsing(args.filename)

    if args.info:
        giveInfo(binary, offsets, msdos, pe, opt, sections)
        return 0

    verboseLog(0, "Binary parsed")

    #######################################################
    #                    SETUP VARIABLES                  #
    #######################################################

    sectionToPack = testSectionName(args.section, '.text', sections, True)
    unpackingSect = testSectionName(args.new, '.unpack', sections, False)
    # Get original entry point
    entry = opt.getOEP()
    
    # Get starting and finishing address of the section to pack
    beginPack = sections.getStartAddr(sectionToPack)
    EndPack = sections.getEndAddr(sectionToPack)

    # be sure packedSize is multiple of 4 (or 8) and secure the hash
    wordlength = 4
    if pe.getArch() == 64:
        wordlength = 8
    packedSize = EndPack - beginPack
    while(
        packedSize % wordlength != 0 or 
        packedSize % wordlength == 0 and (packedSize/wordlength)%2==0
    ):
        packedSize -= 1

    verboseLog(2, f"Packed size : {hex(packedSize)}")

    sections.addRight(sectionToPack, 'w')

    key = generateKey(pe.getArch())
    verboseLog(0, f"Key generated with success : {key}")

    packedSect = xorDat(binary[beginPack:beginPack + packedSize], key)
    goodHash = hashing(binary[beginPack:beginPack + packedSize], pe.getArch())
    verboseLog(0, f"Hash generated with success : {hex(goodHash)}")
    
    unpacker = createUnpacker(entry, beginPack, packedSize, key, goodHash, pe.getArch())
    verboseLog(0, "Unpacker created with success")

    #######################################################
    #           CREATING NEW SECTION CHANGE EP            #
    #######################################################

    if sections.getLowerAddr() > opt.SizeOfHeaders:
        verboseLog(2, "Size of header inferior to their real size... fixing")
        opt.SizeOfHeaders = sections.getLowerAddr()
        verboseLog(0, "Size of header fixed")

    nbleft = (opt.SizeOfHeaders - (offsets['section'] + pe.NumberOfSections * 40)) / 40
    if nbleft >= 1:
        verboseLog(0, f"Can add {nbleft} sections")
    else:
        verboseLog(1, f"Can't add any section. Size left = {nbleft} sections")

    # Create new pack section
    addNewSection(unpackingSect, len(unpacker), pe, opt, sections)
    offsets["EndSection"] += 40

    verboseLog(0, f"New section {unpackingSect} added")

    # Change entry point
    opt.setEP(sections.getVirtStart(unpackingSect))

    verboseLog(0, "Entry point changed")

    #######################################################
    #                     PACKING BACK                    #
    #######################################################
    packedBin = packingBack(
        offsets, pe, opt, sections, packedSect, unpacker, 
        binary, unpackingSect, sectionToPack, packedSize
    )
    
    verboseLog(0, "Binary packed")

    with open("{}.packed.exe".format(args.filename), "wb") as f:
        f.write(packedBin)

    verboseLog(0, f"{args.filename}.packed.exe created")


verbose = False


if __name__=="__main__":
    
    parser = argparse.ArgumentParser(description='Pimp my section')
    parser.add_argument(
        'filename', metavar='filename', type=str,
        help='Name of the executable to tweak'
    )
    parser.add_argument(
        '-i', '--info', action='store_true',
        help='Give general informations about the file', default=False
    )
    parser.add_argument(
        '-s', '--section', type=str,
        help='Section to pack'
    )
    parser.add_argument(
        '-n', '--new', type=str,
        help='Name of the new unpacking section'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Activate verbosity in the program', default=False
    )
    args = parser.parse_args()
    verbose = args.verbose
    exit(main(args))
