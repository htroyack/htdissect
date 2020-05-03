#include <stdio.h>
#include <stdint.h>

/*******************************************************************************
*                                                                              *
* byte   F  E  D  C  B  A  9  8  7  6  5  4  3  2  1  0  (1<<n)                *
*      =================================================                       *
*      |P0|P1|P2|P3|O0|O1|Mo|SI|D0|D1|D2|D3|I0|I1|I2|I3|                       *
*      =================================================                       *
*        |           |     |  |  |           |                                 *
*        |           |     |  |  |           +-- Immediate (optional)          *
*        |           |     |  |  +-- Displacement (optional)                   *
*        |           |     |  +-- SIB  (optional)                              *
*        |           |     +-- ModR/M (optional)                               *
*        |           +-- Opcode                                                *
*        +-- Prefixes (optional)                                               *
*                                                                              *
*******************************************************************************/
typedef struct _INSTRUCTION {
  struct prefix {
    uint8_t p0;
    uint8_t p1;
    uint8_t p2;
    uint8_t p3;
  };

  struct opcode {
    uint8_t o0;
    uint8_t o1;
  };

  struct modr_m {
    uint8_t modr_m;
  };

  struct sib {
    uint8_t sib;
  };

  struct displacement {
    union {
      uint8_t db; // displacement byte: 1 byte displacement
      union {     // 4 byte displacement
        uint32_t dd; // displacement dword: 4 byte displacement
        struct {
          uint8_t dd0;
          uint8_t dd1;
          uint8_t dd2;
          uint8_t dd3;
        };
      };
    };
  };

  struct immediate {
    union {
      uint8_t ib; // immediate byte: 1 byte immediate
      union {     // 4 byte immediate
        uint32_t id; // immediate dword: 4 byte immediate
        struct {
          uint8_t i0;
          uint8_t i1;
          uint8_t i2;
          uint8_t i3;
        };
      };
    };
  };
} INSTRUCTION;

// Group 1 — Lock and repeat prefixes:
#define PREFIX_LOCK          0xF0
#define PREFIX_REPNE_REPNZ   0xF2
#define PREFIX_REP_REPE_REPZ 0xF3
// Group 2 — Segment override prefixes:
#define PREFIX_CS_SEGMENT_OVERRIDE 0X2E
#define PREFIX_SS_SEGMENT_OVERRIDE 0X36
#define PREFIX_DS_SEGMENT_OVERRIDE 0X3E
#define PREFIX_ES_SEGMENT_OVERRIDE 0X26
#define PREFIX_FS_SEGMENT_OVERRIDE 0X64
#define PREFIX_GS_SEGMENT_OVERRIDE 0X65
// Branch hints:
#define PREFIX_JCC_BRANCH_NOT_TAKEN PREFIX_CS_SEGMENT_OVERRIDE
#define PREFIX_JCC_BRANCH_TAKEN     PREFIX_DS_SEGMENT_OVERRIDE
// Group 3
#define PREFIX_OPERAND_SIZE_OVERRIDE 0x66
// Group 4
#define PREFIX_ADDRESS_SIZE_OVERRIDE 0x67

int IsPrefix(const uint8_t* byte) {
  switch (*byte)
  {
  // Group 1 — Lock and repeat prefixes:
  case PREFIX_LOCK:
  case PREFIX_REPNE_REPNZ:
  case PREFIX_REP_REPE_REPZ:
  // Group 2 — Segment override prefixes:
  case PREFIX_CS_SEGMENT_OVERRIDE: // Branch hints: PREFIX_BRANCH_NOT_TAKEN
  case PREFIX_SS_SEGMENT_OVERRIDE:
  case PREFIX_DS_SEGMENT_OVERRIDE: // Branch hints: PREFIX_BRANCH_TAKEN
  case PREFIX_ES_SEGMENT_OVERRIDE:
  case PREFIX_FS_SEGMENT_OVERRIDE:
  case PREFIX_GS_SEGMENT_OVERRIDE:
  // Group 3
  case PREFIX_OPERAND_SIZE_OVERRIDE:
  // Group 4
  case PREFIX_ADDRESS_SIZE_OVERRIDE:
    return *byte;
  }

  return 0;
}

#define PREFIX0 0x8000 // 1 << F
#define PREFIX1 0xC000 // 1 << E + ... 0x8000 + 0x4000
#define PREFIX2 0xE000 // 1 << D + ... 0x8000 + 0x4000 + 0x2000
#define PREFIX3 0xF000 // 1 << C + ... 0x8000 + 0x4000 + 0x2000 + 0x1000

uint16_t test_prefix (const uint8_t* byte, INSTRUCTION* i) {
  if (!IsPrefix(byte))
    return 0;
  i->p0 = *byte++;

  if (!IsPrefix(byte))
    return PREFIX0;
  i->p1 = *byte++;

  if (!IsPrefix(byte))
    return PREFIX1;
  i->p2 = *byte++;

  if (!IsPrefix(byte))
    return PREFIX2;
  i->p3 = *byte++;

  return PREFIX3;
}

uint16_t dasm(const uint8_t *code, INSTRUCTION *Instruction) {
  // TODO: addand respect a maxlen
  // TODO: inform number of decoded bytes on return?
  //       (its a count of bits in InstructionFields)
  uint16_t InstructionFields = 0;
  InstructionFields |= test_prefix(code, Instruction);

  return InstructionFields;
}

typedef struct _OPCODE {
  uint8_t Opcode;
  const char* Instruction;
} OPCODE;

// Vide: "Intel® 64 and IA - 32 Architectures Software Developer Manuals"
// "Intel® 64 and IA-32 Architectures Software Developer’s Manual"
// "Volume 2 (2A, 2B, 2C & 2D) : Instruction Set Reference, A - Z"
// "APPENDIX A: OPCODE MAP"
// "A.3 ONE, TWO, AND THREE-BYTE OPCODE MAPS"
// "Table A-2. One-byte Opcode Map: (00H — F7H)"
OPCODE opcodes[0x100] = {
  { 0x00, "ADD"},      // ADD
  { 0x01, "ADD"},      // ADD
  { 0x02, "ADD"},      // ADD
  { 0x03, "ADD"},      // ADD
  { 0x04, "ADD"},      // ADD
  { 0x05, "ADD"},      // ADD
  { 0x06, "PUSH ES"},
  { 0x07, "POP ES"},
  { 0x08, "OR"},       // OR
  { 0x09, "OR"},       // OR
  { 0x0A, "OR"},       // OR
  { 0x0B, "OR"},       // OR
  { 0x0C, "OR"},       // OR
  { 0x0D, "OR"},       // OR
  { 0x0E, "PUSH CS"},
  { 0x0F, NULL},       // 2-byte escape
  { 0x10, "ADC"},      // ADC
  { 0x11, "ADC"},      // ADC
  { 0x12, "ADC"},      // ADC
  { 0x13, "ADC"},      // ADC
  { 0x14, "ADC AL"},   // ADC
  { 0x15, "ADC"},      // ADC
  { 0x16, "PUSH SS"},
  { 0x17, "POP SS"},
  { 0x18, "SBB"},      // SBB
  { 0x19, "SBB"},      // SBB
  { 0x1A, "SBB"},      // SBB
  { 0x1B, "SBB"},      // SBB
  { 0x1C, "SBB"},      // SBB
  { 0x1D, "SBB"},      // SBB
  { 0x1E, "PUSH DS"},
  { 0x1F, "POP DS"},
  { 0x20, "AND"},      // AND
  { 0x21, "AND"},      // AND
  { 0x22, "AND"},      // AND
  { 0x23, "AND"},      // AND
  { 0x24, "AND AL"},   // AND
  { 0x25, "AND AX"},   // AND
  { 0x26, NULL},       // Instruction Prefixes Group 2 [SEG=ES (Prefix)]
  { 0x27, "DAA"},
  { 0x28, "SUB"},      // SUB
  { 0x29, "SUB"},      // SUB
  { 0x2A, "SUB"},      // SUB
  { 0x2B, "SUB"},      // SUB
  { 0x2C, "SUB AL"},   // SUB
  { 0x2D, "SUB"},      // SUB
  { 0x2E, NULL},       // Instruction Prefixes Group 2 [SEG=CS (Prefix)]
  { 0x2F, "DAS"},
  { 0x30, "XOR"},      // XOR
  { 0x31, "XOR"},      // XOR
  { 0x32, "XOR"},      // XOR
  { 0x33, "XOR"},      // XOR
  { 0x34, "XOR AL"},   // XOR
  { 0x35, "XOR"},      // XOR
  { 0x36, NULL},       // Instruction Prefixes Group 2 [SEG=SS (Prefix)]
  { 0x37, "AAA"},
  { 0x38, "CMP"},      // CMP
  { 0x39, "CMP"},      // CMP
  { 0x3A, "CMP"},      // CMP
  { 0x3B, "CMP"},      // CMP
  { 0x3C, "CMP AL"},   // CMP
  { 0x3D, "CMP"},      // CMP
  { 0x3E, NULL},       // Instruction Prefixes Group 2 [SEG=DS (Prefix)]
  { 0x3F, "AAS"},
  { 0x40, "INC EAX"},  // INC
  { 0x41, "INC ECX"},  // INC
  { 0x42, "INC EDX"},  // INC
  { 0x43, "INC EBX"},  // INC
  { 0x44, "INC ESP"},  // INC
  { 0x45, "INC EBP"},  // INC
  { 0x46, "INC ESI"},  // INC
  { 0x47, "INC EDI"},  // INC
  { 0x48, "DEC EAX"},  // DEC
  { 0x49, "DEC ECX"},  // DEC
  { 0x4A, "DEC EDX"},  // DEC
  { 0x4B, "DEC EBX"},  // DEC
  { 0x4C, "DEC ESP"},  // DEC
  { 0x4D, "DEC EBP"},  // DEC
  { 0x4E, "DEC ESI"},  // DEC
  { 0x4F, "DEC EDI"},  // DEC
  { 0x50, "PUSH EAX"}, // PUSH
  { 0x51, "PUSH ECX"}, // PUSH
  { 0x52, "PUSH EDX"}, // PUSH
  { 0x53, "PUSH EBX"}, // PUSH
  { 0x54, "PUSH ESP"}, // PUSH
  { 0x55, "PUSH EBP"}, // PUSH
  { 0x56, "PUSH ESI"}, // PUSH
  { 0x57, "PUSH EDI"}, // PUSH
  { 0x58, "POP EAX"},  // POP
  { 0x59, "POP ECX"},  // POP
  { 0x5A, "POP EDX"},  // POP
  { 0x5B, "POP EBX"},  // POP
  { 0x5C, "POP ESP"},  // POP
  { 0x5D, "POP EBP"},  // POP
  { 0x5E, "POP ESI"},  // POP
  { 0x5F, "POP EDI"},  // POP
  { 0x60, "PUSHAD"},   // TODO: PUSHA or PUSHAD?
  { 0x61, "POPAD"},    // TODO: POPA or POPAD?
  { 0x62, "BOUND"},
  { 0x63, "ARPL"},
  { 0x64, NULL},       // Instruction Prefixes Group 2 [SEG=FS (Prefix)]
  { 0x65, NULL},       // Instruction Prefixes Group 2 [SEG=GS (Prefix)]
  { 0x66, NULL},       // Instruction Prefixes Group 3 [Operand Size (Prefix)]
  { 0x67, NULL},       // Instruction Prefixes Group 4 [Address Size (Prefix)]
  { 0x68, "PUSH"},
  { 0x69, "IMUL"},
  { 0x6A, "PUSH"},
  { 0x6B, "IMUL"},
  { 0x6C, "INS"},      // TODO: INS OR INSB?
  { 0x6D, "INS"},      // TODO: INS or INSW or INSD?
  { 0x6E, "OUTS"},     // TODO: OUTS or OUTSB?
  { 0x6F, "OUTS"},     // TODO: OUTS or OUTSW or OUTSD?
  { 0x70, "JO"},
  { 0x71, "JNO"},
  { 0x72, "JB"},       // TODO: JB or JC or JNAE
  { 0x73, "JNB"},      // TODO: JAE or JNB or JNC
  { 0x74, "JZ"},       // TODO: JE or JZ?
  { 0x75, "JNZ"},      // TODO: JNE or JNZ?
  { 0x76, "JBE"},      // TODO: JBE or JNA?
  { 0x77, "JNBE"},     // TODO: JNBE or JA?
  { 0x78, "JS"},
  { 0x79, "JNS"},
  { 0x7A, "JP"},       // TODO: JP or JPE?
  { 0x7B, "JNP"},      // TODO: JNP or JPO?
  { 0x7C, "JL"},       // TODO: JL or JNGE?
  { 0x7D, "JNL"},      // TODO: JGE or JNL?
  { 0x7E, "JLE"},      // TODO: JLE or JNG?
  { 0x7F, "JNLE"},     // TODO: JG or JNLE?
  { 0x80, "???"},      // TODO: WTF? [Immediate Grp 1 1A] VIDE Section A.4 ?????
  { 0x81, "???"},      // TODO: WTF? [Immediate Grp 1 1A]                  ?????
  { 0x82, "???"},      // TODO: WTF? [Immediate Grp 1 1A]                  ?????
  { 0x83, "???"},      // TODO: WTF? [Immediate Grp 1 1A]                  ?????
  { 0x84, "TEST"},
  { 0x85, "TEST"},
  { 0x86, "XCHG"},
  { 0x87, "XCHG"},
  { 0x88, "MOV"},      // MOV
  { 0x89, "MOV"},      // MOV
  { 0x8A, "MOV"},      // MOV
  { 0x8B, "MOV"},      // MOV
  { 0x8C, "MOV"},
  { 0x8D, "LEA"},
  { 0x8E, "MOV"},
  { 0x8F, "POP"},
  { 0x90, "NOP"},      // XCHG TODO: XCHG EAX, EAX
  { 0x91, "XCHG ECX"}, // XCHG TODO: XCHG EAX, ECX
  { 0x92, "XCHG EDX"}, // XCHG TODO: XCHG EAX, EDX
  { 0x93, "XCHG EBX"}, // XCHG TODO: XCHG EAX, EBX
  { 0x94, "XCHG ESP"}, // XCHG TODO: XCHG EAX, ESP
  { 0x95, "XCHG EBP"}, // XCHG TODO: XCHG EAX, EBP
  { 0x96, "XCHG ESI"}, // XCHG TODO: XCHG EAX, ESI
  { 0x97, "XCHG EDI"}, // XCHG TODO: XCHG EAX, EDI
  { 0x98, "CWDE"},
  { 0x99, "CDQ"},
  { 0x9A, "CALL"},
  { 0x9B, "WAIT"},
  { 0x9C, "PUSHFD"},
  { 0x9D, "POPFD"},
  { 0x9E, "SAHF"},
  { 0x9F, "LAHF"},
  { 0xA0, "MOV"},      // MOV
  { 0xA1, "MOV"},      // MOV
  { 0xA2, "MOV"},      // MOV
  { 0xA3, "MOV"},      // MOV
  { 0xA4, "MOVS"},
  { 0xA5, "MOVS"},
  { 0xA6, "CMPS"},     // TODO: CMPS or CMPSB?
  { 0xA7, "CMPS"},     // TODO: CMPS or CMPSW CMPSD?
  { 0xA8, "TEST"},     // TEST
  { 0xA9, "TEST"},     // TEST
  { 0xAA, "STOS"},     // TODO: STOS or STOSB?
  { 0xAB, "STOS"},     // TODO: STOS or STOSW or STOSD
  { 0xAC, "LODS"},     // LODS TODO: LODS or LODSB?
  { 0xAD, "LODS"},     // LODS TODO: LODS or LODSW or LODSD?
  { 0xAE, "SCAS"},     // SCAS TODO: SCAS or SCASB?
  { 0xAF, "SCAS"},     // SCAS TODO: SCAS or SCASW or SCASD?
  { 0xB0, "MOV AL"},   // MOV
  { 0xB1, "MOV CL"},   // MOV
  { 0xB2, "MOV DL"},   // MOV
  { 0xB3, "MOV BL"},   // MOV
  { 0xB4, "MOV AH"},   // MOV
  { 0xB5, "MOV CH"},   // MOV
  { 0xB6, "MOV DH"},   // MOV
  { 0xB7, "MOV BH"},   // MOV
  { 0xB8, "MOV EAX"},  // MOV
  { 0xB9, "MOV ECX"},  // MOV
  { 0xBA, "MOV EDX"},  // MOV
  { 0xBB, "MOV EBX"},  // MOV
  { 0xBC, "MOV ESP"},  // MOV
  { 0xBD, "MOV EBP"},  // MOV
  { 0xBE, "MOV ESI"},  // MOV
  { 0xBF, "MOV EDI"},  // MOV
  { 0xC0, "???"},      // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  { 0xC1, "???"},      // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  { 0xC2, "RET"},
  { 0xC3, "RET"},
  { 0xC4, "LES"},
  { 0xC5, "LDS"},
  { 0xC6, "???"},      // TODO: WTF? [Grp 11 1A] VIDE Section A.4 ?????
  { 0xC7, "???"},      // TODO: WTF? [Grp 11 1A] VIDE Section A.4 ?????
  { 0xC8, "ENTER"},
  { 0xC9, "LEAVE"},
  { 0xCA, "RET"},
  { 0xCB, "RET"},
  { 0xCC, "INT 3"},
  { 0xCD, "INT"},
  { 0xCE, "INTO"},
  { 0xCF, "IRETD"},
  { 0xD0, "???"},      // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  { 0xD1, "???"},      // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  { 0xD2, "???"},      // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  { 0xD3, "???"},      // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  { 0xD4, "AAM"},
  { 0xD5, "AAD"},
  { 0xD6, "SETALC"},   // TODO: UNDOCUMENTED. A.k.a. "SALC" said to set AL to CF
  { 0xD7, "XLAT"},     // TODO: XLAT or XLATB?
  { 0xD8, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  { 0xD9, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  { 0xDA, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  { 0xDB, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  { 0xDC, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  { 0xDD, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  { 0xDE, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  { 0xDF, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  { 0xE0, "LOOPNE"},
  { 0xE1, "LOOPE"},
  { 0xE2, "LOOP"},
  { 0xE3, "JECXZ"},
  { 0xE4, "IN AL"},
  { 0xE5, "IN EAX"},
  { 0xE6, "OUT"},
  { 0xE7, "OUT"},
  { 0xE8, "CALL"},
  { 0xE9, "JMP"},
  { 0xEA, "JMP"},
  { 0xEB, "JMP"},
  { 0xEC, "IN AL,DX"},
  { 0xED, "IN EAX,DX"},
  { 0xEE, "OUT DX, AL"},
  { 0xEF, "OUT DX, EAX"},
  { 0xF0, NULL},       // Instruction Prefixes Group 1 [LOCK (Prefix)]
  { 0xF1, "ICEBP"},    // TODO: UNDOCUMENTED. A.k.a. "INT1"
  { 0xF2, NULL},   // Instruction Prefixes Group 1 [REPNE XACQUIRE (Prefix)]
  { 0xF3, NULL},   // Instruction Prefixes Group 1 [REP/REPE XRELEASE (Prefix)]
  { 0xF4, "HLT"},
  { 0xF5, "CMC"},
  { 0xF6, "???"},  // TODO: WTF? [Unary Grp 3 1A] VIDE Section A.4 ?????
  { 0xF7, "???"},  // TODO: WTF? [Unary Grp 3 1A] VIDE Section A.4 ?????
  { 0xF8, "CLC"},
  { 0xF9, "STC"},
  { 0xFA, "CLI"},
  { 0xFB, "STI"},
  { 0xFC, "CLD"},
  { 0xFD, "STD"},
  { 0xFE, "???"}, // TODO: WTF? [INC/DEC Grp 4 1A] VIDE Section A.4 ?????
  { 0xFF, "???"}  // TODO: WTF? [INC/DEC Grp 5 1A] VIDE Section A.4 ?????
};

int main()
{
  uint8_t code[] = { 0xF2, 0xF2, 0xF2, 0xAE };

  INSTRUCTION Instruction = { 0 };
  uint16_t InstructionFields = 0;
  InstructionFields = dasm(code, &Instruction);

  if (InstructionFields & PREFIX0) {
    printf("Prefix: %02X", Instruction.p0);
    if (InstructionFields & PREFIX1) {
      printf(" %02X", Instruction.p1);
      if (InstructionFields & PREFIX2) {
        printf(" %02X", Instruction.p2);
        if (InstructionFields & PREFIX3) {
          printf(" %02X", Instruction.p3);
        }
      }
    }
    putchar('\n');
  }

  return 0;
}