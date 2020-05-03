/*****************************************************************************
* *******************************           *******************************  *
*                                htdissect.c                                 *
* *******************************           *******************************  *
*                                                                            *
* This program was made jus for fun on a (quarantine) weeked, as an exercise *
* while I was reading a tutorial on x86 programming.                         *
* Don't take anything seriously here. I didn't. (sec., quality, beauty, etc) *
* My intention is to buind a program to display the content of binary files, *
* initially Windows PE (.exe, .dll, .sys...), but a more modular support for *
* newer format dissectors (a la wireshark) will be welcome in the future.    *
*                                                                            *
* Of course a disassembler will be welcome in the (near) future, too.        *
* For a long-term wishlist:                                                  *
*  - GUI (Portable, if possible)                                             *
*  - Make the whole thing as portable as possible                            *
*  - This program should (one day) become a library, serving as the back-end *
*    for GUI and Text/Console/Command Line versions                          *
*  - Ability to edit displayed data and save changes to input file           *
*                                                                            *
*  Short term improvements are better kept as in-place "TODO:" comments.     *
*                                                                            *
*                                                2020.04.19 Henrique Troyack *
*****************************************************************************/

/*****************************************************************************
*                                                                            *
* REFERENCES:                                                                *
*  - PE Format - Win32 apps | Microsoft Docs                                 *
*    - https://docs.microsoft.com/en-us/windows/win32/debug/pe-format        *
*                                                                            *
*  - Peering Inside the PE: A Tour of the Win32 Portable Executable File     *
*                           Format                                           *
*    Matt Pietrek                                                            *
*    March 1994                                                              *
*    - https://docs.microsoft.com/en-us/previous-versions/                   *
*      ms809762(v%3dmsdn.10)                                                 *
*    - http://bytepointer.com/resources/pietrek_peering_inside_pe.htm        *
*                                                                            *
*  - Updated PEDUMP (by Matt Pietrek)                                        *
*    - http://www.wheaty.net/                                                *
*    - http://www.wheaty.net/downloads.htm                                   *
*                                                                            *
*  - Inside Windows                                                          *
*    An In-Depth Look into the Win32 Portable Executable File Format         *
*    Matt Pietrek                                                            *
*    From the February 2002 issue of MSDN Magazine                           *
*    - https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/ *
*      inside-windows-win32-portable-executable-file-format-in-detail        *
*                                                                            *
*                                                                            *
* SEE ALSO:                                                                  *
*   - Jeremy Gordon "The Go tools for Windows + Assembler"                   *
*     - http://www.godevtool.com/                                            *
*     - http://www.godevtool.com/GoasmHelp/newprog.htm                       *
*                                                                            *
*****************************************************************************/

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

#define TIMESTAMP_STR_SIZE 26

// believe-me there was a reason to avoid '\t' or n-space tabs (iWantToBelieve)
#define TAB_CHAR " "

// IMAGE_FILE_AGGRESIVE_WS_TRIM    0x0010  // Aggressively trim working set
#if (!defined IMAGE_FILE_AGGRESSIVE_WS_TRIM)
  #if defined IMAGE_FILE_AGGRESIVE_WS_TRIM
    #define IMAGE_FILE_AGGRESSIVE_WS_TRIM IMAGE_FILE_AGGRESIVE_WS_TRIM
  #endif
#endif

void GetBytes(void *Dst, size_t BytesCount, FILE *File, long int ReadPos = -1L)
{
  if (ReadPos != -1L) {
    if (fseek(File, ReadPos, SEEK_SET) != 0) {
      fprintf(stderr, "ERROR trying to read %u bytes from position %u\n",
        BytesCount, ReadPos);
      exit(1);
    }
  }
  size_t pos = ftell(File);
  size_t read = fread(Dst, BytesCount, 1, File);
  // TODO: Maybe show file size, current position and intended read size
  // TODO: Maybe print an hexdump of whole file?
  if (read != 1)
  {
    fprintf(stderr, "READ ERROR trying to read %u bytes from position %u\n",
      BytesCount, pos);
    exit(1);
  }
}

const char* ImageFileHeaderMachineName(WORD Machine)
{
  switch (Machine)
  {
  case IMAGE_FILE_MACHINE_UNKNOWN:
    return "IMAGE_FILE_MACHINE_UNKNOWN (The contents of this field are"
      " assumed to be applicable to any machine type)";
  case IMAGE_FILE_MACHINE_AM33:
    return "IMAGE_FILE_MACHINE_AM33 (Matsushita AM33)";
  case IMAGE_FILE_MACHINE_AMD64: return "IMAGE_FILE_MACHINE_AMD64 (x64)";
  case IMAGE_FILE_MACHINE_ARM:
    return "IMAGE_FILE_MACHINE_ARM (ARM little endian)";
  // TODO: SHOULD BE 0xaa64 Not found. Try a newer SDK
  /* case IMAGE_FILE_MACHINE_ARM64:
       return "IMAGE_FILE_MACHINE_ARM64 (ARM64 little endian)"; */
  case IMAGE_FILE_MACHINE_ARMNT:
    return "IMAGE_FILE_MACHINE_ARMNT (ARM Thumb-2 little endian)";
  case IMAGE_FILE_MACHINE_EBC: return "IMAGE_FILE_MACHINE_EBC (EFI byte code)";
  case IMAGE_FILE_MACHINE_I386:
    return "IMAGE_FILE_MACHINE_I386 (Intel 386 or later processors and "
      "compatible processors)";
  case IMAGE_FILE_MACHINE_IA64:
    return "IMAGE_FILE_MACHINE_IA64 (Intel Itanium processor family)";
  case IMAGE_FILE_MACHINE_M32R:
    return "IMAGE_FILE_MACHINE_M32R (Mitsubishi M32R little endian)";
  case IMAGE_FILE_MACHINE_MIPS16:
    return "IMAGE_FILE_MACHINE_MIPS16 (MIPS16)";
  case IMAGE_FILE_MACHINE_MIPSFPU:
    return "IMAGE_FILE_MACHINE_MIPSFPU (MIPS with FPU)";
  case IMAGE_FILE_MACHINE_MIPSFPU16:
    return "IMAGE_FILE_MACHINE_MIPSFPU16 (MIPS16 with FPU)";
  case IMAGE_FILE_MACHINE_POWERPC:
    return "IMAGE_FILE_MACHINE_POWERPC (Power PC little endian)";
  case IMAGE_FILE_MACHINE_POWERPCFP:
    return "IMAGE_FILE_MACHINE_POWERPCFP (Power PC with floating point "
      "support)";
  case IMAGE_FILE_MACHINE_R4000:
    return "IMAGE_FILE_MACHINE_R4000 (MIPS little endian)";
    // TODO: SHOULD BE 0x5032 Not found. Try a newer SDK
    // case IMAGE_FILE_MACHINE_RISCV32:
    //   return "IMAGE_FILE_MACHINE_RISCV32 (RISC-V 32-bit address space)";
    // TODO: SHOULD BE 0x5064 Not found. Try a newer SDK
    // case IMAGE_FILE_MACHINE_RISCV64:
    //   return "IMAGE_FILE_MACHINE_RISCV64 (RISC-V 64-bit address space)";
    // TODO: SHOULD BE 0x5128 Not found. Try a newer SDK
    // case IMAGE_FILE_MACHINE_RISCV128:
    //   return "IMAGE_FILE_MACHINE_RISCV128 (RISC-V 128-bit address space)";
  case IMAGE_FILE_MACHINE_SH3: return "IMAGE_FILE_MACHINE_SH3 (Hitachi SH3)";
  case IMAGE_FILE_MACHINE_SH3DSP:
    return "IMAGE_FILE_MACHINE_SH3DSP (Hitachi SH3 DSP)";
  case IMAGE_FILE_MACHINE_SH4: return "IMAGE_FILE_MACHINE_SH4 (Hitachi SH4)";
  case IMAGE_FILE_MACHINE_SH5: return "IMAGE_FILE_MACHINE_SH5 (Hitachi SH5)";
  case IMAGE_FILE_MACHINE_THUMB: return "IMAGE_FILE_MACHINE_THUMB (Thumb)";
  case IMAGE_FILE_MACHINE_WCEMIPSV2:
    return "IMAGE_FILE_MACHINE_WCEMIPSV2 (MIPS little-endian WCE v2)";
  default: return "INVALID OR UNKNOWN MACHINE TYPE";
  }
}

void HexDump(void *Buffer, size_t Count, size_t *AbsolutePos = 0)
{
  unsigned char *Bytes = (unsigned char*)Buffer;
  size_t Offset = 0;
  if (AbsolutePos) {
    Offset = *AbsolutePos;
  }
  size_t Skip = Offset % 16;
  size_t LineOffset = Offset - (Offset%16);
  if (AbsolutePos) {
    *AbsolutePos += Count;
  }

  printf("  offset   | ");
  for (int i = 0; i < 16; i++)
    printf("%02x ", i);
  printf("|\n");

  // TODO: support dump from midfile where addr is not multiple of 16
  // TODO: test dumps of more than 16 bytes
  // TODO: test dumps of less than 16 bytes
  while (Count) {
    printf("  %08X | ", LineOffset);

    // TODO: Padding before and padding after
    for (unsigned i = 0; i < 16; i++) {
      if (i < Skip || i >= (Count + Skip))
        printf("   ");
      else
        printf("%02X ", Bytes[i-Skip]);
    }
    printf("| ");

    for (unsigned i = 0; i < 16; i++) {
      if (i < Skip || i >= (Count + Skip)) {
        putchar(' ');
      }
      else {
        uint8_t c = Bytes[i - Skip];
        printf("%c", isprint(c) ? c : '.');
      }
    }
    putchar('\n');

    size_t Done = (16 - Skip);
    Bytes += Done;
    Count -= (Count > Done) ? Done : Count;
    Skip = 0;
    LineOffset += 16;
  }
  putchar('\n');
}

struct PossibleImageFileHeaderCharacteristics {
  WORD CharacteristicsBit;
  const char *CharacteristicsDesc;
};

void PrintImageFileHeaderCharacteristics(WORD Characteristics)
{
  //int AppenSeparator = 0;
  static const unsigned KnownValues = 15;
  PossibleImageFileHeaderCharacteristics KnownCharacteristics[KnownValues] = {
    {IMAGE_FILE_RELOCS_STRIPPED, "IMAGE_FILE_RELOCS_STRIPPED"},
    {IMAGE_FILE_EXECUTABLE_IMAGE, "IMAGE_FILE_EXECUTABLE_IMAGE"},
    {IMAGE_FILE_LINE_NUMS_STRIPPED, "IMAGE_FILE_LINE_NUMS_STRIPPED"},
    {IMAGE_FILE_LOCAL_SYMS_STRIPPED, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"},
    {IMAGE_FILE_AGGRESSIVE_WS_TRIM, "IMAGE_FILE_AGGRESSIVE_WS_TRIM"},
    {IMAGE_FILE_LARGE_ADDRESS_AWARE, "IMAGE_FILE_LARGE_ADDRESS_AWARE"},
    {IMAGE_FILE_BYTES_REVERSED_LO, "IMAGE_FILE_BYTES_REVERSED_LO"},
    {IMAGE_FILE_32BIT_MACHINE, "IMAGE_FILE_32BIT_MACHINE"},
    {IMAGE_FILE_DEBUG_STRIPPED, "IMAGE_FILE_DEBUG_STRIPPED"},
    {IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"},
    {IMAGE_FILE_NET_RUN_FROM_SWAP, "IMAGE_FILE_NET_RUN_FROM_SWAP"},
    {IMAGE_FILE_SYSTEM, "IMAGE_FILE_SYSTEM"},
    {IMAGE_FILE_DLL, "IMAGE_FILE_DLL"},
    {IMAGE_FILE_UP_SYSTEM_ONLY, "IMAGE_FILE_UP_SYSTEM_ONLY"},
    {IMAGE_FILE_BYTES_REVERSED_HI, "IMAGE_FILE_BYTES_REVERSED_HI"}
  };

  for (unsigned i = 0; i < KnownValues; i++) {
    if (Characteristics & KnownCharacteristics[i].CharacteristicsBit)
    {
      /* printf("%s%s", (AppenSeparator) ? " | " : "",
           AllPossibleCharacteristics[i].CharacteristicsDesc); */
      //AppenSeparator = 1;
      printf("" TAB_CHAR "" TAB_CHAR "%s\n",
        KnownCharacteristics[i].CharacteristicsDesc);
    }
  }
}

struct PossibleImageFileSectionCharacteristics {
  DWORD CharacteristicsBit;
  const char *CharacteristicsDesc;
};

void PrintImageFileSectionCharacteristics(DWORD Characteristics)
{
  //int AppenSeparator = 0;
  static const unsigned KnownValues = 41;
  PossibleImageFileSectionCharacteristics KnownCharacteristics[KnownValues] = {
    {0x00000000, "IMAGE_SCN_TYPE_REG Reserved for future use."},
    {0x00000001, "IMAGE_SCN_TYPE_DSECT Reserved for future use."},
    {0x00000002, "IMAGE_SCN_TYPE_NOLOAD Reserved for future use."},
    {0x00000004, "IMAGE_SCN_TYPE_GROUP Reserved for future use."},
    {IMAGE_SCN_TYPE_NO_PAD, "IMAGE_SCN_TYPE_NO_PAD"},
    {0x00000010, "IMAGE_SCN_TYPE_COPY Reserved for future use."},
    {IMAGE_SCN_CNT_CODE, "IMAGE_SCN_CNT_CODE"},
    {IMAGE_SCN_CNT_INITIALIZED_DATA, "IMAGE_SCN_CNT_INITIALIZED_DATA"},
    {IMAGE_SCN_CNT_UNINITIALIZED_DATA, "IMAGE_SCN_CNT_UNINITIALIZED_DATA"},
    {IMAGE_SCN_LNK_OTHER, "IMAGE_SCN_LNK_OTHER"},
    {IMAGE_SCN_LNK_INFO, "IMAGE_SCN_LNK_INFO"},
    {0x00000400, "IMAGE_SCN_TYPE_OVER Reserved for future use."},
    {IMAGE_SCN_LNK_REMOVE, "IMAGE_SCN_LNK_REMOVE"},
    {IMAGE_SCN_LNK_COMDAT, "IMAGE_SCN_LNK_COMDAT"},
    {IMAGE_SCN_GPREL, "IMAGE_SCN_GPREL"},
    {IMAGE_SCN_MEM_PURGEABLE,
      "IMAGE_SCN_MEM_PURGEABLE Reserved for future use."},
    {IMAGE_SCN_MEM_16BIT, "IMAGE_SCN_MEM_16BIT Reserved for future use."},
    {IMAGE_SCN_MEM_LOCKED, "IMAGE_SCN_MEM_LOCKED Reserved for future use."},
    {IMAGE_SCN_MEM_PRELOAD, "IMAGE_SCN_MEM_PRELOAD Reserved for future use."},
    {IMAGE_SCN_ALIGN_1BYTES, "IMAGE_SCN_ALIGN_1BYTES"},
    {IMAGE_SCN_ALIGN_2BYTES, "IMAGE_SCN_ALIGN_2BYTES"},
    {IMAGE_SCN_ALIGN_4BYTES, "IMAGE_SCN_ALIGN_4BYTES"},
    {IMAGE_SCN_ALIGN_8BYTES, "IMAGE_SCN_ALIGN_8BYTES"},
    {IMAGE_SCN_ALIGN_16BYTES, "IMAGE_SCN_ALIGN_16BYTES"},
    {IMAGE_SCN_ALIGN_32BYTES, "IMAGE_SCN_ALIGN_32BYTES"},
    {IMAGE_SCN_ALIGN_64BYTES, "IMAGE_SCN_ALIGN_64BYTES"},
    {IMAGE_SCN_ALIGN_128BYTES, "IMAGE_SCN_ALIGN_128BYTES"},
    {IMAGE_SCN_ALIGN_256BYTES, "IMAGE_SCN_ALIGN_256BYTES"},
    {IMAGE_SCN_ALIGN_512BYTES, "IMAGE_SCN_ALIGN_512BYTES"},
    {IMAGE_SCN_ALIGN_1024BYTES, "IMAGE_SCN_ALIGN_1024BYTES"},
    {IMAGE_SCN_ALIGN_2048BYTES, "IMAGE_SCN_ALIGN_2048BYTES"},
    {IMAGE_SCN_ALIGN_4096BYTES, "IMAGE_SCN_ALIGN_4096BYTES"},
    {IMAGE_SCN_ALIGN_8192BYTES, "IMAGE_SCN_ALIGN_8192BYTES"},
    {IMAGE_SCN_LNK_NRELOC_OVFL, "IMAGE_SCN_LNK_NRELOC_OVFL"},
    {IMAGE_SCN_MEM_DISCARDABLE, "IMAGE_SCN_MEM_DISCARDABLE"},
    {IMAGE_SCN_MEM_NOT_CACHED, "IMAGE_SCN_MEM_NOT_CACHED"},
    {IMAGE_SCN_MEM_NOT_PAGED, "IMAGE_SCN_MEM_NOT_PAGED"},
    {IMAGE_SCN_MEM_SHARED, "IMAGE_SCN_MEM_SHARED"},
    {IMAGE_SCN_MEM_EXECUTE, "IMAGE_SCN_MEM_EXECUTE"},
    {IMAGE_SCN_MEM_READ, "IMAGE_SCN_MEM_READ"},
    {IMAGE_SCN_MEM_WRITE, "IMAGE_SCN_MEM_WRITE"}
  };

  for (unsigned i = 0; i < KnownValues; i++) {
    if (Characteristics & KnownCharacteristics[i].CharacteristicsBit)
    {
      /* printf("%s%s", (AppenSeparator) ? " | " : "",
           AllPossibleCharacteristics[i].CharacteristicsDesc); */
      //AppenSeparator = 1;
      printf("" TAB_CHAR "" TAB_CHAR "%s\n",
        KnownCharacteristics[i].CharacteristicsDesc);
    }
  }

}

void DumpImageFileHeader(PIMAGE_FILE_HEADER pImageFileHeader,
  size_t *AbsolutePos)
{
  printf("" TAB_CHAR "Machine: %d (0x%04X)\n" TAB_CHAR "" TAB_CHAR "%s\n",
    pImageFileHeader->Machine, pImageFileHeader->Machine,
    ImageFileHeaderMachineName(pImageFileHeader->Machine));
  HexDump(&pImageFileHeader->Machine, 2, AbsolutePos);

  printf("" TAB_CHAR "NumberOfSections: %d (0x%04X)\n",
    pImageFileHeader->NumberOfSections,
    pImageFileHeader->NumberOfSections);
  HexDump(&pImageFileHeader->NumberOfSections, 2, AbsolutePos);

  time_t ltime = pImageFileHeader->TimeDateStamp;
  char buf[TIMESTAMP_STR_SIZE];
  _ctime64_s(buf, TIMESTAMP_STR_SIZE, &ltime);
  printf("" TAB_CHAR "TimeDateStamp: %d (0x%08X) %s",
    pImageFileHeader->TimeDateStamp, pImageFileHeader->TimeDateStamp, buf);
  HexDump(&pImageFileHeader->TimeDateStamp, 4, AbsolutePos);

  printf("" TAB_CHAR "PointerToSymbolTable: (0x%08X)\n",
    pImageFileHeader->PointerToSymbolTable);
  HexDump(&pImageFileHeader->PointerToSymbolTable, 4, AbsolutePos);

  printf("" TAB_CHAR "NumberOfSymbols: %d (0x%08X)\n",
    pImageFileHeader->NumberOfSymbols, pImageFileHeader->NumberOfSymbols);
  HexDump(&pImageFileHeader->NumberOfSymbols, 4, AbsolutePos);

  printf("" TAB_CHAR "SizeOfOptionalHeader: %d (0x%04X)\n",
    pImageFileHeader->SizeOfOptionalHeader,
    pImageFileHeader->SizeOfOptionalHeader);
  HexDump(&pImageFileHeader->SizeOfOptionalHeader, 2, AbsolutePos);

  printf("" TAB_CHAR "Characteristics: %d (0x%04X):\n",
    pImageFileHeader->Characteristics, pImageFileHeader->Characteristics);
  PrintImageFileHeaderCharacteristics(pImageFileHeader->Characteristics);
  putchar('\n');
  HexDump(&pImageFileHeader->Characteristics, 2, AbsolutePos);
}

void DumpImageSectionHeader(PIMAGE_SECTION_HEADER pImageSectionHeader,
  size_t *AbsolutePos)
{
  /* TODO: HANDLE "For longer names, this field contains a slash (/) that is
                   followed by an ASCII representation of a decimal number
                   that is an offset into the string table." */
  printf("" TAB_CHAR "Name: (0x%016X) \"%.8s\"\n",
    *((uint32_t*)pImageSectionHeader->Name), pImageSectionHeader->Name);
  HexDump(pImageSectionHeader->Name, 8, AbsolutePos);

  printf("" TAB_CHAR "VirtualSize: %d (0x%08X)\n",
    pImageSectionHeader->Misc.VirtualSize,
    pImageSectionHeader->Misc.VirtualSize);
  HexDump(&pImageSectionHeader->Misc.VirtualSize, 4, AbsolutePos);

  printf("" TAB_CHAR "VirtualAddress: %d (0x%08X)\n",
    pImageSectionHeader->VirtualAddress, pImageSectionHeader->VirtualAddress);
  HexDump(&pImageSectionHeader->VirtualAddress, 4, AbsolutePos);

  printf("" TAB_CHAR "SizeOfRawData: %d (0x%08X)\n",
    pImageSectionHeader->SizeOfRawData, pImageSectionHeader->SizeOfRawData);
  HexDump(&pImageSectionHeader->SizeOfRawData, 4, AbsolutePos);

  printf("" TAB_CHAR "PointerToRawData: %d (0x%08X)\n",
    pImageSectionHeader->PointerToRawData,
    pImageSectionHeader->PointerToRawData);
  HexDump(&pImageSectionHeader->PointerToRawData, 4, AbsolutePos);

  printf("" TAB_CHAR "PointerToRelocations: %d (0x%08X)\n",
    pImageSectionHeader->PointerToRelocations,
    pImageSectionHeader->PointerToRelocations);
  HexDump(&pImageSectionHeader->PointerToRelocations, 4, AbsolutePos);

  printf("" TAB_CHAR "PointerToLinenumbers: %d (0x%08X)\n",
    pImageSectionHeader->PointerToLinenumbers,
    pImageSectionHeader->PointerToLinenumbers);
  HexDump(&pImageSectionHeader->PointerToLinenumbers, 4, AbsolutePos);

  printf("" TAB_CHAR "NumberOfRelocations: %d (0x%04X)\n",
    pImageSectionHeader->NumberOfRelocations,
    pImageSectionHeader->NumberOfRelocations);
  HexDump(&pImageSectionHeader->NumberOfRelocations, 2, AbsolutePos);

  printf("" TAB_CHAR "NumberOfLinenumbers: %d (0x%04X)\n",
    pImageSectionHeader->NumberOfLinenumbers,
    pImageSectionHeader->NumberOfLinenumbers);
  HexDump(&pImageSectionHeader->NumberOfLinenumbers, 2, AbsolutePos);

  printf("" TAB_CHAR "Characteristics: %d (0x%08X):\n",
    pImageSectionHeader->Characteristics,
    pImageSectionHeader->Characteristics);
  PrintImageFileSectionCharacteristics(pImageSectionHeader->Characteristics);
  putchar('\n');
  HexDump(&pImageSectionHeader->Characteristics, 4, AbsolutePos);
}

void DumpImageSectionRawData(FILE* ObjFile, DWORD SizeOfRawData,
  DWORD PointerToRawData)
{
  void* RawData = malloc(SizeOfRawData);
  if (!RawData) {
    fprintf(stderr,
      "FAILED TO ALLOC %d BYTES to read SectionRawData from offset 0x%08X\n",
      SizeOfRawData, PointerToRawData);
    exit(1);
  }

  size_t PreviousFilePosition = ftell(ObjFile);
  GetBytes(RawData, SizeOfRawData, ObjFile, PointerToRawData);
  if (fseek(ObjFile, PreviousFilePosition, SEEK_SET) != 0) {
    fprintf(stderr,
      "ERROR restoring file stream position indicator "
      "after reading section raw data\n");
    exit(1);
  }

  printf("" TAB_CHAR "Section Raw Data %d (0x%08X) byte%s long:\n",
    SizeOfRawData, SizeOfRawData, (SizeOfRawData != 1) ? "s" : "");
  size_t SectionRawDataFilePosition = PointerToRawData;
  HexDump(RawData, SizeOfRawData, &SectionRawDataFilePosition);
  free(RawData);
}

void DumpObj(FILE* ObjFile)
{
  // TODO: display hexdump w/ correct position. this may be an COFF or PE
  IMAGE_FILE_HEADER ImageFileHeader = { 0 };
  printf("Reading IMAGE_FILE_HEADER\n");
  GetBytes(&ImageFileHeader, IMAGE_SIZEOF_FILE_HEADER, ObjFile);
  size_t AbsolutePos = 0;

  DumpImageFileHeader(&ImageFileHeader, &AbsolutePos);

  /* TODO: Dump optional header(s), if any (Make sure to use the size
                                            of the optional header) */

  for (int i = 0; i < ImageFileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER ImageSectionHeader = {0};
    printf("Reading IMAGE_SECTION_HEADER\n");
    GetBytes(&ImageSectionHeader, IMAGE_SIZEOF_SECTION_HEADER, ObjFile);
    DumpImageSectionHeader(&ImageSectionHeader, &AbsolutePos);

    /* Grouped Sections (Object Only) The "$"? character (dollar sign) has
       a special interpretation in section names in object files. ... */

    DumpImageSectionRawData(ObjFile, ImageSectionHeader.SizeOfRawData,
      ImageSectionHeader.PointerToRawData);
  }
}

int IsDOSImg(FILE* File) {
  // TODO: check for IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE...
  return 0;
}

void DumpNTImg(FILE* File) {
  // TODO: Dump IMAGE_DOS_HEADER, IMAGE_NT_HEADERS...
}

int main(int argc, char *argv[])
{
  /* TODO: Make it C? replace default args w/ macros?, etc */
  if (argc != 2) {
    fprintf(stderr, "USAGE: %s file", argv[0]);
    return 1;
  }

  // TODO: use memory mapped files
  FILE* InFile = fopen(argv[1], "rb");
  if (!InFile) {
    fprintf(stderr, "Unable to open file '%s'\n", argv[1]);
    return 1;
  }

  /* TODO: identify file type (obj, res, exe...) based on headers and
             filename extension and dump accordingly */
  if (IsDOSImg(InFile)) {
    DumpNTImg(InFile);
  }
  else {
    DumpObj(InFile);
  }

  fclose(InFile);

  return 0;
}
