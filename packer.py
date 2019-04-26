#!/usr/bin/python3

import secrets
import sys
import subprocess
import argparse

import headerStruct

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


def createUnpacker(ADDRESS_OEP, ADDRESS_CODE_START, TOTAL_CODE_SIZE, PARTIAL_KEY, CORRECT_HASH, Arch=0): # TODO Arch 32/64
    key = int.from_bytes(PARTIAL_KEY, 'little') & 0xFFFFFF00
    #little indianing
    hs = format(CORRECT_HASH, '08x')
    final_string = "0x" + hs[8:10] + hs[6:8] + hs[4:6] + hs[2:4] + hs[:2]
    subprocess.run(["cp", "unpacker.asm", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/ADDRESS_CODE_START/{hex(ADDRESS_CODE_START + 0x400000)}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/TOTAL_CODE_SIZE/{hex(TOTAL_CODE_SIZE)}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/PARTIAL_KEY/{hex(key)}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/CORRECT_HASH/{final_string}/g", "tmpUnpack.asm"])
    subprocess.run(["sed", "-i", "-e", f"s/ADDRESS_OEP/{hex(ADDRESS_OEP + 0x400000)}/g", "tmpUnpack.asm"])
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
        print("Not 32 or 64 bits")
        exit(1)

    if pe.getArch() == 64:
        print("64bits not working for now")
        exit(2)
    
    # Parse optional header
    opt = headerStruct.PEOptHeader(binary[offsets["PEOpt"]:offsets["section"]], pe.getArch())
    
    # Parse sections header
    sections = headerStruct.SectionHeader(binary[offsets["section"]:offsets["EndSection"]], pe.NumberOfSections)

    return binary, offsets, msdos, pe, opt, sections


def giveInfo(binary, offsets, msdos, pe, opt, sections):
    print(f"################# MS DOS ################\nStarts at : {hex(offsets['begin'])}")
    msdos.printAll()
    print(f"################### PE ##################\nStarts at : {hex(offsets['pe'])}")
    pe.printAll()
    print(f"############ OPTIONAL HEADERS ###########\nStarts at : {hex(offsets['PEOpt'])}")
    opt.printAll(sections, len(binary), offsets["section"])
    print(f"################ SECTIONS ###############\nStarts at : {hex(offsets['section'])}")
    sections.sectionsInfo(True)


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

    #be sure packedSize is multiple of 4 and secure the hash
    packedSize = EndPack - beginPack
    while(packedSize % 4 != 0 or packedSize % 4 == 0 and (packedSize/4)%2==0):
        packedSize -= 1

    verboseLog(2, f"Packed size : {hex(packedSize)}")

    sections.addRight(sectionToPack, 'w')

    key = generateKey()
    verboseLog(0, f"Key generated with success : {key}")

    packedSect = xorDat(binary[beginPack:beginPack + packedSize], key)
    goodHash = hashing(binary[beginPack:beginPack + packedSize])
    verboseLog(0, f"Hash generated with success : {hex(goodHash)}")
    
    unpacker = createUnpacker(entry, beginPack, packedSize, key, goodHash)
    verboseLog(0, "Unpacker created with success")

    #######################################################
    #           CREATING NEW SECTION CHANGE EP            #
    #######################################################

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
