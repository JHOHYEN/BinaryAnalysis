##################################################################
# This is a code that can simply analyze an EXE file (PE file).  #
#                                                                #
# It shows the section size, starting address, and section       # 
# characteristics that exist within the Exe file.                #
#                                                                #
# Additionally, a disassembler function has been added to        #
# show the contents of the EXE file.                             #
#                                                                #
# This function uses the capstone function.                      #
# https://www.capstone-engine.org/lang_python.html               #
#                                                                #
#                                                                #
# [sections_info] information                                    #
# Section Header = Headers of each section exist, and the        #
# sections contain information necessary when metadata is stored #
# and loaded into memory.                                        #
#                                                                #
# 1. VirtualSize : The size of the section in memory.            #
# 2. VirtualAddress : Starting address (RVA) of a section        #
#                    in memory.                                  #
# 3. SizeOfRawData : The size of the section in the file.        #
# 4. PointerToRawData : Offset of the section in the file.       #
# 5. Characteristics : Section attributes, Bit OR calculation.   #
#                                                                #
##################################################################

import pefile
from pefile import BoundImportRefData
import os
from capstone import *

def read_file_exe(path):
    file_list = os.listdir(path)
    read_exe = [file for file in file_list if file.endswith(".exe")]
    return read_exe

def f_name(file):
    pe = pefile.PE(file)
    function_name, dll_data = [], []
    #print(pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    pe.parse_data_directories()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_data.append(entry.dll)
        for imp in entry.imports:
            function_name.append("0x%x:\t%s" %(imp.address , imp.name)+'\n')

    return function_name, dll_data

def read_text_info(file):
    data = []
    pe = pefile.PE(file)
    result_data = []
    #for section in pe.sections:
        #print (section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData)
    for section in pe.sections:
        if '.text' in str(section.Name):
            entry = section.PointerToRawData
            end = section.SizeOfRawData + entry
            #print(entry, end)
            raw_data = pe.__data__[entry:end]

    return raw_data, entry, end

def hex_to_assmble(hex_code, addr, end):
    result = []
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(hex_code, addr):
        result.append("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)+"\n")

    return result

def sections_header_info(file):
    pe = pefile.PE(file)
    sections_header = []
    sections_header.append(["Name".ljust(20),"VirtualSize".ljust(20), "Virtual Address".ljust(20), 
                            "SizeOfRawData".ljust(20),"PointerToRawData".ljust(20), "Characteristics".ljust(20)])
    for section in pe.sections :
        sections_header.append([section.Name.decode('utf8').ljust(20), hex(section.Misc_VirtualSize).ljust(20), hex(section.VirtualAddress).ljust(20), 
            hex(section.SizeOfRawData).ljust(20), hex(section.PointerToRawData).ljust(20), hex(section.Characteristics)])
    return sections_header

def write_txt(file_name, text_data, sp, ep, sections_header):
    with open("./" + str(file_name)+"hexcode_disassmble.txt", mode='w', encoding="UTF-8", errors="ignore") as f:
        f.write(str(file_name)+"\n")
        f.write("Strat Point = "+ str(sp) + " End Point" + str(ep))
        f.write("\n[sections_info] information\n")
        f.write("Section Header = Headers of each section exist, and the sections contain information necessary when metadata is stored and loaded into memory. \n")
        f.write("1. VirtualSize : The size of the section in memory.\n")
        f.write("2. VirtualAddress : Starting address (RVA) of a section in memory.\n")
        f.write("3. SizeOfRawData : The size of the section in the file.\n")
        f.write("4. PointerToRawData : Offset of the section in the file.\n")
        f.write("5. Characteristics : Section attributes, Bit OR calculation.\n\n")
        #"(0x2000000 = excutable, 0x4000000 = readable, 0x8000000 = writeable, 0x0000020 = contains code, 0x0000040 = contains initialized data)"
        for data in sections_header:
            f.write(data[0].ljust(20) + str(data[1]).ljust(20) + data[2].ljust(20) + data[3].ljust(20) + data[4].ljust(20) + data[5].ljust(20) + "\n")
        f.write("\n\n[Text_disassemble] information\n")
        for i in text_data:
            f.write(i)

if __name__ == "__main__":
    path = "./" # write exe file directory (write path)
    exe_data = read_file_exe(path)
    for i in exe_data:
        print(i+" Analysis of the PEfile")
        file = path +'/' + i
        text_code, dll_name = f_name(file)
        hex_data, addr, end = read_text_info(file)
        sections_header = sections_header_info(file)
        text_code = hex_to_assmble(hex_data, addr, end)
        write_txt(i, text_code, addr, end, sections_header)

