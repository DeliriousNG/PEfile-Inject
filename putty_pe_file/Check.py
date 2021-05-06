import pefile
# Loading an executable
pe = pefile.PE(".//putty.exe")
# Parsing every section from Sections Header
print("Sections Info: \n")
print("*" * 50)
for section in pe.sections:
    print(section.Name.decode().rstrip('\x00') + "\n|\n|---- Vitual Size : " + hex(section.Misc_VirtualSize) + "\n|\n|---- VirutalAddress : " + hex(section.VirtualAddress) + "\n|\n|---- SizeOfRawData : " + hex(section.SizeOfRawData) + "\n|\n|---- PointerToRawData : " + hex(section.PointerToRawData) + "\n|\n|---- Characterisitcs : " + hex(section.Characteristics)+'\n')    
print("*" * 50)
number_section = pe.FILE_HEADER.NumberOfSections
last_section = number_section - 1
raw_section = pe.sections[last_section].PointerToRawData
print ("Hey:" + hex(raw_section))