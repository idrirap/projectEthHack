# Project Ethical Hacking
School project made for the course of ethical hacking at FH Joanneum.
This script written in python3 is made to pack 32 and 64 bits windows PE Executables on x86 architecture.

## Features
- Pack windows binary
- Visualise the headers and the file format
- Fix errors in the binary header

## Dependencies
All python library are part of the Python Standard Library.
In order to compile the unpacker, you need to install the NASM compiler.
```sh
$ sudo apt install nasm
```

## Documentation
### Parsing
The header of a PE executable is divided in four parts.
All of them are parsed in the program. Here are the differents sections and the most important parts of each.
The parsing is executed using the unpack library. The structure of each section with the type of each value is described in comments in the headerStruct file.

#### MS DOS
The msdos header. Useless, present only for legacy purposes. It is divided in two parts, some metadata and a short program telling you "this application cannot be run in dos mode".
Since the size of this small programm can vary, the first byte of the next section is indicated in the long **e_lfanew**.

#### The COFF File Header
Starts just after the "PE\0\0" signature, called PEHeader in my code.
The most important parts of this header are the 2nd value, the **machine** value, it gives you the information about the kind of machine this binary is supposed to run on. This is while parsing this variable that the program is able to tell if this is a 32_x86 or a 64_x86 application. If this is any other architecture, the execution is stopped.
Then the 3rd value, the **numberOfSections**. This is useful in order to parse the section header later.
And the 7th value, the **SizeOfOptionalHeader** value. It gives you the size of the next header. However, the size is always the same. The only difference is that in 64 bits this header is 16 bytes bigger than in 32 bits.

#### The Optional Header
*Not optional.*
This is the biggest header of the PE. It contains all of the metadata about the global size of the binary, the sections sizes, the virtual sizes etc...
The most important part are the **AddressOfEntryPoint**, it gives you the address where the program is going to place the instruction pointer.
Then the **FileAlignment**, it gives you a value on which every section has to align in the file. For example 0x100, so every section's length has to be a multiple of 0x100. If the real size of the section is inferior, it has to be padded. The value used for the padding is not important. Most of the time it is padded with zero. But I have seen malware padded with the string "DEADBEEF". This is not a good idea when you try to avoid static analysis. The **SectionAlignment** is almost the same value, but for the sections when loaded in memory.
Finaly, the **SizeOfHeaders**, it gives you the size of all the headers. It is aligned to the section alignment, so most of the time this value is padded with zero. This is this padding space which is used to add new headers for new sections.

#### The Sections Table
Contains all the informations about the sections.
Each section is 40 bytes long. This header is the most important when you want to make a packer. The five first values and the last one are very important.
- Name : the name of the section in ascii. With a length of 8 characters. Padded with 0x00 if the size is shorter.
- VirtualSize : the size of the section when loaded in memory.
- VirtualAddress : the address of the section when loaded in memory.
- SizeOfRawData : the size of the section in the binary file.
- PointerToRawData : the address of the section in the file.
- Characteristics : A 32 bits value where each bit is a characteristic of the section. For example the first bit define if this section is writeable and the 2nd if this is readable.

### Packing and unpacking
The encription of the selected section is made with a basic xor encryption. The length of the key is variable between the differents architectures. The key is 32 bits long in x86_32 and 64 in x86_64. To check if the decryption has been made correctly during the unpacking, a hash is calculated on the entire file. The hash function consist in xoring every part of 32/64 bits on each other. The final variable is considered as a hash.
The key is not stored entirely in the file, the last byte is missing. The unpacker has to bruteforce the key to decrypt the packed section correctly. To check if the section has been unpacked well, the unpacker compare the hash of the file with another a new hash that it has to calculate.

### Unpacker
There are two unpacker, one in 32 and one in 64 bits. The instructions are a bit differents since the key is 64 bits long in 64. They are coded in assembly with the intel syntax.
The unpacker is compiled and injected as a new section in the binary. The **AddressOfEntryPoint** has to be redirected to the begining of the unpacking section. At the end of the execution of the unpacking section, the instruction pointer has to be redirected to the original entry point. Since it is impossible to manipulate directly the instruction pointer like this : 
```asm
mov eip, ADDRESS_ORIGINAL_ENTRY_POINT ; compilation error
```
I had to bypass this using these instruction, to simuate a return to the previous function :
```asm
push ADDRESS_ORIGINAL_ENTRY_POINT
ret
```
Another problem occure when you try to add absolute variable as an adresse. Because the address of original entry point is supposed to be dynamicaly translated to a virtual address when the program is starting. So I had to figure out that I had to add 0x400000 to this address to get the right value in 32 bits and 0x140000000 in 64.

### Commands
```
usage: packer.py [-h] [-i] [-s SECTION] [-n NEW] [-v] filename

Packer for windows 32/64 binary

positional arguments:
  filename              Name of the executable to tweak

optional arguments:
  -h, --help            show this help message and exit
  -i, --info            Give general informations about the file
  -s SECTION, --section SECTION
                        Section to pack
  -n NEW, --new NEW     Name of the new unpacking section
  -v, --verbose         Activate verbosity in the program
```
The given arguments for -s and -n must have a length between 1 and 8. If this condition is not met, the input in the -s section will be replaced by .text and the -n by .unpack

### Examples
#### Default behavior
```sh
$ ./packer ./binary.exe
```
The script is going to look for the section .text and pack it. It is going to create a new section with the unpacker called .unpack
#### Pack a precise section and chose the unpacking section's name
```sh
$ ./packer -s .data -n .pdata ./binary.exe
```
The script is going to look for the section .data and pack it. It is going to create a new section with the unpacker called .pdata
#### Get headers informations
```sh
$ ./packer -i ./binary.exe
```
The script is going to print all the metadatas stored in the headers.

## Future possible improvement
- Change the hash function for a real hashing function, more reliable like sha256.
- Implement the calcul of checksum for the entire binary, instead of replacing it by 0.
- More complexe unpacker

## See more
https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format