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
#include <stdarg.h>
#include <time.h>
#include <stdint.h>
#include "dasm.h"

#define TIMESTAMP_STR_SIZE 26

// believe-me there was a reason to avoid '\t' or n-space tabs (iWantToBelieve)
#define TAB_CHAR " "

// IMAGE_FILE_AGGRESIVE_WS_TRIM    0x0010  // Aggressively trim working set
#if (!defined IMAGE_FILE_AGGRESSIVE_WS_TRIM)
  #if defined IMAGE_FILE_AGGRESIVE_WS_TRIM
    #define IMAGE_FILE_AGGRESSIVE_WS_TRIM IMAGE_FILE_AGGRESIVE_WS_TRIM
  #endif
#endif

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

#define FGR FOREGROUND_RED
#define FGG FOREGROUND_GREEN
#define FGB FOREGROUND_BLUE
#define FGW (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)
#define BGR BACKGROUND_RED
#define BGG BACKGROUND_GREEN
#define BGB BACKGROUND_BLUE
#define BGW (BACKGROUND_RED|BACKGROUND_GREEN|BACKGROUND_BLUE)
#define FGI FOREGROUND_INTENSITY
#define BGI BACKGROUND_INTENSITY
// #define CTITLE (FGB|FGI)
#define CTITLE (FGR|FGG)
#define CSUBTITLE (FGR|FGG|FGI)
#define CVALUE (FGB|FGI)
#define CHEXTITLE (FGG|FGB)
#define CHEXOFFSET CHEXTITLE
#define CHEXBYTE FGG
#define CTXT CHEXBYTE
#define CERROR (FGR|FGI)
#define CHEXINST (FGR|FGB)

int ceprintf(WORD wAttributes, const char* format, ...) {
  CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
  static HANDLE hStdErr = NULL;
  if (!hStdErr) {
    hStdErr = GetStdHandle(STD_ERROR_HANDLE);
  }
  GetConsoleScreenBufferInfo(hStdErr, &csbiInfo);
  SetConsoleTextAttribute(hStdErr, wAttributes);
  int status = 0;
  va_list args;
  va_start(args, format);
  status = vfprintf(stderr, format, args);
  va_end(args);
  SetConsoleTextAttribute(hStdErr, csbiInfo.wAttributes);
  return status;
}

int cprintf(WORD wAttributes, const char* format, ...) {
  static CONSOLE_SCREEN_BUFFER_INFO csbiInfo;
  static HANDLE hStdout = NULL;
  if (!hStdout) {
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
  }
  GetConsoleScreenBufferInfo(hStdout, &csbiInfo);
  SetConsoleTextAttribute(hStdout, wAttributes);
  int status = 0;
  va_list args;
  va_start(args, format);
  status = vprintf(format, args);
  va_end(args);
  SetConsoleTextAttribute(hStdout, csbiInfo.wAttributes);
  return status;
}

void GetBytes(void* Dst, size_t BytesCount, FILE* File, long ReadPos = -1L)
{
  if (ReadPos != -1L) {
    if (fseek(File, ReadPos, SEEK_SET) != 0) {
      ceprintf(CERROR, "ERROR trying to read %zu bytes from position %ld\n",
        BytesCount, ReadPos);
      // TODO: return a proper error code and handle there, instead of exit()
      exit(1);
    }
  }
  long pos = ftell(File);
  size_t read = fread(Dst, BytesCount, 1, File);
  // TODO: Maybe show file size, current position and intended read size
  // TODO: Maybe print an hexdump of whole file?
  if (read != 1)
  {
    ceprintf(CERROR, "READ ERROR trying to read %zu bytes from position %u\n",
      BytesCount, pos);
    // TODO: return a proper error code and handle there, instead of exit()
    exit(1);
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
    cprintf(CHEXTITLE, "%02X ", i);
  printf("|\n");

  // TODO: support dump from midfile where addr is not multiple of 16
  // TODO: test dumps of more than 16 bytes
  // TODO: test dumps of less than 16 bytes
  while (Count) {
    cprintf(CHEXOFFSET, "  %08zX ", LineOffset);
    printf("| ");

    // TODO: Padding before and padding after
    for (unsigned i = 0; i < 16; i++) {
      if (i < Skip || i >= (Count + Skip))
        printf("   ");
      else
        cprintf(CHEXBYTE, "%02X ", Bytes[i-Skip]);
    }
    printf("| ");

    for (unsigned i = 0; i < 16; i++) {
      if (i < Skip || i >= (Count + Skip)) {
        putchar(' ');
      }
      else {
        uint8_t c = Bytes[i - Skip];
        cprintf(CTXT, "%c", isprint(c) ? c : '.');
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
      printf(TAB_CHAR "" TAB_CHAR "%s\n",
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
      printf(TAB_CHAR "" TAB_CHAR "%s\n",
        KnownCharacteristics[i].CharacteristicsDesc);
    }
  }

}

#define PRINT_OPT_DEC     0x01
#define PRINT_OPT_HEX     0x02
#define PRINT_OPT_HEXDUMP 0x04

#define PrintWord(Prefix, Title, Word, PrintOptions, AbsolutePos) \
 PrintWordS(Prefix, Title, NULL, Word, PrintOptions, AbsolutePos)
void PrintWordS(const char* Prefix, const char* Title, const char* Suffix,
  uint16_t Word, uint8_t PrintOptions, size_t* AbsolutePos) {
  cprintf(CVALUE, "%s%s: ", Prefix, Title);

  if (PrintOptions & PRINT_OPT_DEC)
    printf("%d ", Word);

  if (PrintOptions & PRINT_OPT_HEX)
    printf("(0x%04X) ", Word);

  if (Suffix)
    printf(Suffix);

  putchar('\n');

  if (PrintOptions & PRINT_OPT_HEXDUMP)
    HexDump(&Word, 2, AbsolutePos);
}

#define PrintDword(Prefix, Title, Word, PrintOptions, AbsolutePos) \
  PrintDwordS(Prefix, Title, NULL, Word, PrintOptions, AbsolutePos)
void PrintDwordS(const char* Prefix, const char* Title, const char *Suffix, uint32_t Dword,
  uint8_t PrintOptions, size_t* AbsolutePos) {
  cprintf(CVALUE, "%s%s: ", Prefix, Title);

  if (PrintOptions & PRINT_OPT_DEC)
    printf("%d ", Dword);

  if (PrintOptions & PRINT_OPT_HEX)
    printf("(0x%08X) ", Dword);

  if (Suffix)
    printf(Suffix);
  else
    putchar('\n');

  if (PrintOptions & PRINT_OPT_HEXDUMP)
    HexDump(&Dword, 4, AbsolutePos);
}

void DumpImageDosHeader(IMAGE_DOS_HEADER *ImageDosHeader,
  size_t* AbsolutePos) {
  PrintWord(TAB_CHAR, "Magic number (e_magic)", ImageDosHeader->e_magic,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Bytes on last page of file (e_cblp)",
    ImageDosHeader->e_cblp, PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP,
    AbsolutePos);

  PrintWord(TAB_CHAR, "Pages in file (e_cp)", ImageDosHeader->e_cp,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Relocations (e_crlc)", ImageDosHeader->e_crlc,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Size of header in paragraphs (e_cparhdr)",
    ImageDosHeader->e_cparhdr,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Minimum extra paragraphs needed (e_minalloc)",
    ImageDosHeader->e_minalloc,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Maximum extra paragraphs needed (e_maxalloc)",
    ImageDosHeader->e_maxalloc,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Initial (relative) SS value (e_ss)",
    ImageDosHeader->e_ss,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Initial SP value (e_sp)", ImageDosHeader->e_sp,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Checksum (e_csum)", ImageDosHeader->e_csum,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Initial IP value (e_ip)", ImageDosHeader->e_ip,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Initial (relative) CS value (e_cs)",
    ImageDosHeader->e_cs,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "File address of relocation table (e_lfarlc)",
    ImageDosHeader->e_lfarlc,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "Overlay number (e_ovno)", ImageDosHeader->e_ovno,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  for (int i = 0; i < 4; i++) {
    printf(TAB_CHAR "Reserved words (e_res[%d]): %d (0x%04X)\n", i,
      ImageDosHeader->e_res[i], ImageDosHeader->e_res[i]);
    HexDump(&ImageDosHeader->e_res[i], 2, AbsolutePos);
  }

  PrintWord(TAB_CHAR, "OEM identifier (for e_oeminfo) (e_oemid)",
    ImageDosHeader->e_oemid,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintWord(TAB_CHAR, "OEM information; e_oemid specific (e_oeminfo)",
    ImageDosHeader->e_oeminfo,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  for (int i = 0; i < 10; i++) {
    printf(TAB_CHAR "Reserved words (e_res2[%d]): %d (0x%04X)\n", i,
      ImageDosHeader->e_res2[i], ImageDosHeader->e_res2[i]);
    HexDump(&ImageDosHeader->e_res2[i], 2, AbsolutePos);
  }

  PrintDword(TAB_CHAR, "File address of new exe header (e_lfanew)",
    ImageDosHeader->e_lfanew,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);
}

void DumpImageFileHeader(PIMAGE_FILE_HEADER pImageFileHeader,
  size_t *AbsolutePos)
{
  cprintf(CVALUE, "Machine: ");
  printf(TAB_CHAR "%d (0x%04X)\n" TAB_CHAR "" TAB_CHAR "%s\n",
    pImageFileHeader->Machine, pImageFileHeader->Machine,
    ImageFileHeaderMachineName(pImageFileHeader->Machine));
  HexDump(&pImageFileHeader->Machine, 2, AbsolutePos);

  PrintWord(TAB_CHAR, "NumberOfSections", pImageFileHeader->NumberOfSections,
    PRINT_OPT_DEC | PRINT_OPT_HEX | PRINT_OPT_HEXDUMP, AbsolutePos);

  time_t ltime = pImageFileHeader->TimeDateStamp;
  char TimeDateStampStr[TIMESTAMP_STR_SIZE];
  _ctime64_s(TimeDateStampStr, TIMESTAMP_STR_SIZE, &ltime);
  PrintDwordS(TAB_CHAR, "TimeDateStamp", TimeDateStampStr, pImageFileHeader->TimeDateStamp,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintDword(TAB_CHAR, "PointerToSymbolTable", pImageFileHeader->PointerToSymbolTable,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  PrintDword(TAB_CHAR, "NumberOfSymbols", pImageFileHeader->NumberOfSymbols,
    PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, AbsolutePos);

  // TODO: replace by PrintWord
  printf(TAB_CHAR "SizeOfOptionalHeader: %d (0x%04X)\n",
    pImageFileHeader->SizeOfOptionalHeader,
    pImageFileHeader->SizeOfOptionalHeader);
  HexDump(&pImageFileHeader->SizeOfOptionalHeader, 2, AbsolutePos);

  printf(TAB_CHAR "Characteristics: %d (0x%04X):\n",
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
  printf(TAB_CHAR "Name: (0x%016X) \"%.8s\"\n",
    *((uint32_t*)pImageSectionHeader->Name), pImageSectionHeader->Name);
  HexDump(pImageSectionHeader->Name, 8, AbsolutePos);

  printf(TAB_CHAR "VirtualSize: %d (0x%08X)\n",
    pImageSectionHeader->Misc.VirtualSize,
    pImageSectionHeader->Misc.VirtualSize);
  HexDump(&pImageSectionHeader->Misc.VirtualSize, 4, AbsolutePos);

  printf(TAB_CHAR "VirtualAddress: %d (0x%08X)\n",
    pImageSectionHeader->VirtualAddress, pImageSectionHeader->VirtualAddress);
  HexDump(&pImageSectionHeader->VirtualAddress, 4, AbsolutePos);

  printf(TAB_CHAR "SizeOfRawData: %d (0x%08X)\n",
    pImageSectionHeader->SizeOfRawData, pImageSectionHeader->SizeOfRawData);
  HexDump(&pImageSectionHeader->SizeOfRawData, 4, AbsolutePos);

  printf(TAB_CHAR "PointerToRawData: %d (0x%08X)\n",
    pImageSectionHeader->PointerToRawData,
    pImageSectionHeader->PointerToRawData);
  HexDump(&pImageSectionHeader->PointerToRawData, 4, AbsolutePos);

  printf(TAB_CHAR "PointerToRelocations: %d (0x%08X)\n",
    pImageSectionHeader->PointerToRelocations,
    pImageSectionHeader->PointerToRelocations);
  HexDump(&pImageSectionHeader->PointerToRelocations, 4, AbsolutePos);

  printf(TAB_CHAR "PointerToLinenumbers: %d (0x%08X)\n",
    pImageSectionHeader->PointerToLinenumbers,
    pImageSectionHeader->PointerToLinenumbers);
  HexDump(&pImageSectionHeader->PointerToLinenumbers, 4, AbsolutePos);

  printf(TAB_CHAR "NumberOfRelocations: %d (0x%04X)\n",
    pImageSectionHeader->NumberOfRelocations,
    pImageSectionHeader->NumberOfRelocations);
  HexDump(&pImageSectionHeader->NumberOfRelocations, 2, AbsolutePos);

  printf(TAB_CHAR "NumberOfLinenumbers: %d (0x%04X)\n",
    pImageSectionHeader->NumberOfLinenumbers,
    pImageSectionHeader->NumberOfLinenumbers);
  HexDump(&pImageSectionHeader->NumberOfLinenumbers, 2, AbsolutePos);

  printf(TAB_CHAR "Characteristics: %d (0x%08X):\n",
    pImageSectionHeader->Characteristics,
    pImageSectionHeader->Characteristics);
  PrintImageFileSectionCharacteristics(pImageSectionHeader->Characteristics);
  putchar('\n');
  HexDump(&pImageSectionHeader->Characteristics, 4, AbsolutePos);
}

void DumpDisassembly(uint8_t* CodeBytes, size_t CodeSize,
  size_t StartAddress) {
  // TODO: Disassemble x86-64/x64
  // TODO: Check to avoid reading past buffer
  size_t InitialCodeBytes = (size_t)CodeBytes;
  size_t InstructionSize = 0;

  INSTRUCTION Instruction;
  while (DASM_INVALID_INSTRUCTION != (InstructionSize = dasm(CodeBytes, CodeSize, &Instruction))) {
    CodeSize -= InstructionSize;
    CodeBytes += InstructionSize;
    cprintf(CHEXOFFSET, "%p: ", StartAddress+(CodeBytes- InitialCodeBytes)-InstructionSize);
    for (uint8_t *bytes = CodeBytes- InstructionSize; bytes < CodeBytes; bytes++)
      cprintf(CHEXBYTE, "%02X ", *bytes);
    for (int i = 6 - InstructionSize; i > 0; i--)
      printf("   ");
    cprintf(CHEXINST, "%s\n", Instruction.Name);
  }
}

void DumpImageSectionRawData(FILE* ObjFile,
  IMAGE_SECTION_HEADER * ImageSectionHeader)
{
  void* RawData = malloc(ImageSectionHeader->SizeOfRawData);
  if (!RawData) {
    ceprintf(CERROR,
      "FAILED TO ALLOC %d BYTES to read SectionRawData from offset 0x%08X\n",
      ImageSectionHeader->SizeOfRawData, ImageSectionHeader->PointerToRawData);
    // TODO: return a proper error code and handle there, instead of exit()
    exit(1);
  }

  long PreviousFilePosition = ftell(ObjFile);
  GetBytes(RawData, ImageSectionHeader->SizeOfRawData, ObjFile,
    ImageSectionHeader->PointerToRawData);
  if (fseek(ObjFile, PreviousFilePosition, SEEK_SET) != 0) {
    ceprintf(CERROR,
      "ERROR restoring file stream position indicator "
      "after reading section raw data\n");
    // TODO: return a proper error code and handle there, instead of exit()
    exit(1);
  }

  printf(TAB_CHAR "Section Raw Data %d (0x%08X) byte%s long:\n",
    ImageSectionHeader->SizeOfRawData, ImageSectionHeader->SizeOfRawData,
    (ImageSectionHeader->SizeOfRawData != 1) ? "s" : "");
  size_t SectionRawDataFilePosition = ImageSectionHeader->PointerToRawData;
  HexDump(RawData, ImageSectionHeader->SizeOfRawData,
    &SectionRawDataFilePosition);

  if (ImageSectionHeader->Characteristics | IMAGE_SCN_CNT_CODE &&
    ImageSectionHeader->Characteristics | IMAGE_SCN_MEM_EXECUTE) {
    DumpDisassembly((uint8_t*)RawData, ImageSectionHeader->SizeOfRawData,
      ImageSectionHeader->PointerToRawData);
  }


  free(RawData);
}

int DumpNTImg(FILE* File) {
    // TODO: Dump IMAGE_DOS_HEADER, IMAGE_NT_HEADERS...
    IMAGE_DOS_HEADER ImageDOSHeader = { 0 };
    size_t AbsolutePos = 0;
    cprintf(CTITLE, "Reading IMAGE_DOS_HEADER\n");
    GetBytes(&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), File);

    if (ImageDOSHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        ceprintf(CERROR, TAB_CHAR "ERROR: IMAGE_DOS_SIGNATURE not found!\n");
        return ERROR_BAD_FORMAT;
    }

    DumpImageDosHeader(&ImageDOSHeader, &AbsolutePos);

    // TODO: Disassemble and dump DOS Stub
    // size_t DosStbuSize = ImageDosHeader.e_lfanew - AbsolutePos;
    // printf(TAB_CHAR "MS-DOS Stub code %d (0x%08X) bytes:\n", DosStbuSize,
    //   DosStbuSize);
    // void* DosStub = malloc(DosStbuSize);
    // GetBytes(DosStub, DosStbuSize, File);
    // HexDump(DosStub, DosStbuSize, &AbsolutePos);

    IMAGE_NT_HEADERS ImageNTHeaders = { 0 };
    cprintf(CTITLE, "Reading IMAGE_NT_HEADERS\n");
    GetBytes(&ImageNTHeaders, sizeof(IMAGE_NT_HEADERS), File,
      ImageDOSHeader.e_lfanew);
    AbsolutePos = ImageDOSHeader.e_lfanew;

    PrintDword(TAB_CHAR, "Signature", ImageNTHeaders.Signature,
      PRINT_OPT_DEC|PRINT_OPT_HEX|PRINT_OPT_HEXDUMP, &AbsolutePos);

    if (ImageNTHeaders.Signature != IMAGE_NT_SIGNATURE) {
      ceprintf(CERROR, TAB_CHAR "ERROR: IMAGE_NT_SIGNATURE not found!\n");
      return ERROR_BAD_FORMAT;
    }

    // TODO: refactor to share code with DumpObj()
    cprintf(CSUBTITLE, TAB_CHAR "Reading IMAGE_FILE_HEADER\n");
    // TODO: AbsolutePos -= 2; to account for DWORD Signature;
    DumpImageFileHeader(&ImageNTHeaders.FileHeader, &AbsolutePos);

    // TODO: Dump IMAGE_OPTIONAL_HEADER

    return 0;
}

void DumpObj(FILE* ObjFile)
{
  IMAGE_FILE_HEADER ImageFileHeader = { 0 };
  cprintf(CTITLE, "Reading IMAGE_FILE_HEADER\n");
  GetBytes(&ImageFileHeader, IMAGE_SIZEOF_FILE_HEADER, ObjFile);
  size_t AbsolutePos = 0;

  DumpImageFileHeader(&ImageFileHeader, &AbsolutePos);

  /* TODO: Dump optional header(s), if any (Make sure to use the size
                                            of the optional header) */

  for (int i = 0; i < ImageFileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER ImageSectionHeader = {0};
    cprintf(CTITLE, "Reading IMAGE_SECTION_HEADER\n");
    GetBytes(&ImageSectionHeader, IMAGE_SIZEOF_SECTION_HEADER, ObjFile);
    DumpImageSectionHeader(&ImageSectionHeader, &AbsolutePos);

    /* Grouped Sections (Object Only) The "$"? character (dollar sign) has
       a special interpretation in section names in object files. ... */

    DumpImageSectionRawData(ObjFile, &ImageSectionHeader);
  }
}

int main(int argc, char *argv[])
{
  /* TODO: Make it C? replace default args w/ macros?, etc */
  if (argc != 2) {
    ceprintf(CERROR, "USAGE: %s file", argv[0]);
    return 1;
  }

  // TODO: use memory mapped files
  // TODO: maybe read all file at once and close it then work in memory?
  FILE* InFile = fopen(argv[1], "rb");
  if (!InFile) {
    ceprintf(CERROR, "Unable to open file '%s'\n", argv[1]);
    return 1;
  }

  /* TODO: identify file type (obj, res, exe...) based on headers and
             filename extension and dump accordingly */
  if (ERROR_BAD_FORMAT == DumpNTImg(InFile)) {
    fseek(InFile, 0, SEEK_SET);
    DumpObj(InFile);
  }

  fclose(InFile);

  return 0;
}
