#include <stdio.h>
#include "dasm.h"

// Vide: "Intel® 64 and IA - 32 Architectures Software Developer Manuals"
// "Intel® 64 and IA-32 Architectures Software Developer’s Manual"
// "Volume 2 (2A, 2B, 2C & 2D) : Instruction Set Reference, A - Z"
// "APPENDIX A: OPCODE MAP"
// "A.3 ONE, TWO, AND THREE-BYTE OPCODE MAPS"
// "Table A-2. One-byte Opcode Map: (00H — F7H)"
OPCODE OpCodes[0x100] = {
  {0x00, "ADD"},      // ADD
  {0x01, "ADD"},      // ADD
  {0x02, "ADD"},      // ADD
  {0x03, "ADD"},      // ADD
  {0x04, "ADD"},      // ADD
  {0x05, "ADD"},      // ADD
  {0x06, "PUSH ES"},
  {0x07, "POP ES"},
  {0x08, "OR"},       // OR
  {0x09, "OR"},       // OR
  {0x0A, "OR"},       // OR
  {0x0B, "OR"},       // OR
  {0x0C, "OR"},       // OR
  {0x0D, "OR"},       // OR
  {0x0E, "PUSH CS"},
  {0x0F, NULL},       // 2-byte escape
  {0x10, "ADC"},      // ADC
  {0x11, "ADC"},      // ADC
  {0x12, "ADC"},      // ADC
  {0x13, "ADC"},      // ADC
  {0x14, "ADC AL"},   // ADC
  {0x15, "ADC"},      // ADC
  {0x16, "PUSH SS"},
  {0x17, "POP SS"},
  {0x18, "SBB"},      // SBB
  {0x19, "SBB"},      // SBB
  {0x1A, "SBB"},      // SBB
  {0x1B, "SBB"},      // SBB
  {0x1C, "SBB"},      // SBB
  {0x1D, "SBB"},      // SBB
  {0x1E, "PUSH DS"},
  {0x1F, "POP DS"},
  {0x20, "AND"},      // AND
  {0x21, "AND"},      // AND
  {0x22, "AND"},      // AND
  {0x23, "AND"},      // AND
  {0x24, "AND AL"},   // AND
  {0x25, "AND AX"},   // AND
  {0x26, NULL},       // Instruction Prefixes Group 2 [SEG=ES (Prefix)]
  {0x27, "DAA"},
  {0x28, "SUB"},      // SUB
  {0x29, "SUB"},      // SUB
  {0x2A, "SUB"},      // SUB
  {0x2B, "SUB"},      // SUB
  {0x2C, "SUB AL"},   // SUB
  {0x2D, "SUB"},      // SUB
  {0x2E, NULL},       // Instruction Prefixes Group 2 [SEG=CS (Prefix)]
  {0x2F, "DAS"},
  {0x30, "XOR"},      // XOR
  {0x31, "XOR"},      // XOR
  {0x32, "XOR"},      // XOR
  {0x33, "XOR"},      // XOR
  {0x34, "XOR AL"},   // XOR
  {0x35, "XOR"},      // XOR
  {0x36, NULL},       // Instruction Prefixes Group 2 [SEG=SS (Prefix)]
  {0x37, "AAA"},
  {0x38, "CMP"},      // CMP
  {0x39, "CMP"},      // CMP
  {0x3A, "CMP"},      // CMP
  {0x3B, "CMP"},      // CMP
  {0x3C, "CMP AL"},   // CMP
  {0x3D, "CMP"},      // CMP
  {0x3E, NULL},       // Instruction Prefixes Group 2 [SEG=DS (Prefix)]
  {0x3F, "AAS"},
  {0x40, "INC EAX"},  // INC *********************************************
  {0x41, "INC ECX"},  // INC * TODO: The instruction is invalid or not   *
  {0x42, "INC EDX"},  // INC * encodable in 64-bit mode. 40 through 4F   *
  {0x43, "INC EBX"},  // INC * (single-byte INC and DEC) are REX prefix  *
  {0x44, "INC ESP"},  // INC * combinations when in 64 - bit mode        *
  {0x45, "INC EBP"},  // INC * (use FE / FF Grp 4 and 5 for INC and DEC) *
  {0x46, "INC ESI"},  // INC *********************************************
  {0x47, "INC EDI"},  // INC
  {0x48, "DEC EAX"},  // DEC
  {0x49, "DEC ECX"},  // DEC
  {0x4A, "DEC EDX"},  // DEC
  {0x4B, "DEC EBX"},  // DEC
  {0x4C, "DEC ESP"},  // DEC
  {0x4D, "DEC EBP"},  // DEC
  {0x4E, "DEC ESI"},  // DEC
  {0x4F, "DEC EDI"},  // DEC
  {0x50, "PUSH EAX"}, // PUSH
  {0x51, "PUSH ECX"}, // PUSH
  {0x52, "PUSH EDX"}, // PUSH
  {0x53, "PUSH EBX"}, // PUSH
  {0x54, "PUSH ESP"}, // PUSH
  {0x55, "PUSH EBP"}, // PUSH
  {0x56, "PUSH ESI"}, // PUSH
  {0x57, "PUSH EDI"}, // PUSH
  {0x58, "POP EAX"},  // POP
  {0x59, "POP ECX"},  // POP
  {0x5A, "POP EDX"},  // POP
  {0x5B, "POP EBX"},  // POP
  {0x5C, "POP ESP"},  // POP
  {0x5D, "POP EBP"},  // POP
  {0x5E, "POP ESI"},  // POP
  {0x5F, "POP EDI"},  // POP
  {0x60, "PUSHAD"},   // TODO: PUSHA or PUSHAD?
  {0x61, "POPAD"},    // TODO: POPA or POPAD?
  {0x62, "BOUND"},
  {0x63, "ARPL"},
  {0x64, NULL},       // Instruction Prefixes Group 2 [SEG=FS (Prefix)]
  {0x65, NULL},       // Instruction Prefixes Group 2 [SEG=GS (Prefix)]
  {0x66, NULL},       // Instruction Prefixes Group 3 [Operand Size (Prefix)]
  {0x67, NULL},       // Instruction Prefixes Group 4 [Address Size (Prefix)]
  {0x68, "PUSH", DASM_REQ_IMM32},
  {0x69, "IMUL"},
  {0x6A, "PUSH", DASM_REQ_IMM8},
  {0x6B, "IMUL"},
  {0x6C, "INS"},      // TODO: INS OR INSB?
  {0x6D, "INS"},      // TODO: INS or INSW or INSD?
  {0x6E, "OUTS"},     // TODO: OUTS or OUTSB?
  {0x6F, "OUTS"},     // TODO: OUTS or OUTSW or OUTSD?
  {0x70, "JO"},
  {0x71, "JNO"},
  {0x72, "JB"},       // TODO: JB or JC or JNAE
  {0x73, "JNB"},      // TODO: JAE or JNB or JNC
  {0x74, "JZ"},       // TODO: JE or JZ?
  {0x75, "JNZ"},      // TODO: JNE or JNZ?
  {0x76, "JBE"},      // TODO: JBE or JNA?
  {0x77, "JNBE"},     // TODO: JNBE or JA?
  {0x78, "JS"},
  {0x79, "JNS"},
  {0x7A, "JP"},       // TODO: JP or JPE?
  {0x7B, "JNP"},      // TODO: JNP or JPO?
  {0x7C, "JL"},       // TODO: JL or JNGE?
  {0x7D, "JNL"},      // TODO: JGE or JNL?
  {0x7E, "JLE"},      // TODO: JLE or JNG?
  {0x7F, "JNLE"},     // TODO: JG or JNLE?
  {0x80, NULL},       // TODO: WTF? [Immediate Grp 1 1A] VIDE Section A.4 ?????
  {0x81, NULL},       // TODO: WTF? [Immediate Grp 1 1A]                  ?????
  {0x82, NULL},       // TODO: WTF? [Immediate Grp 1 1A]                  ?????
  {0x83, NULL},       // TODO: WTF? [Immediate Grp 1 1A]                  ?????
  {0x84, "TEST"},
  {0x85, "TEST"},
  {0x86, "XCHG"},
  {0x87, "XCHG"},
  {0x88, "MOV"},      // MOV
  {0x89, "MOV", DASM_REQ_MODRM},      // MOV
  {0x8A, "MOV"},      // MOV
  {0x8B, "MOV"},      // MOV
  {0x8C, "MOV"},
  {0x8D, "LEA"},
  {0x8E, "MOV"},
  {0x8F, "POP"},
  {0x90, "NOP"},      // XCHG TODO: XCHG EAX, EAX
  {0x91, "XCHG ECX"}, // XCHG TODO: XCHG EAX, ECX
  {0x92, "XCHG EDX"}, // XCHG TODO: XCHG EAX, EDX
  {0x93, "XCHG EBX"}, // XCHG TODO: XCHG EAX, EBX
  {0x94, "XCHG ESP"}, // XCHG TODO: XCHG EAX, ESP
  {0x95, "XCHG EBP"}, // XCHG TODO: XCHG EAX, EBP
  {0x96, "XCHG ESI"}, // XCHG TODO: XCHG EAX, ESI
  {0x97, "XCHG EDI"}, // XCHG TODO: XCHG EAX, EDI
  {0x98, "CWDE"},
  {0x99, "CDQ"},
  {0x9A, "CALL"},
  {0x9B, "WAIT"},
  {0x9C, "PUSHFD"},
  {0x9D, "POPFD"},
  {0x9E, "SAHF"},
  {0x9F, "LAHF"},
  {0xA0, "MOV"},      // MOV
  {0xA1, "MOV"},      // MOV
  {0xA2, "MOV"},      // MOV
  {0xA3, "MOV"},      // MOV
  {0xA4, "MOVS"},
  {0xA5, "MOVS"},
  {0xA6, "CMPS"},     // TODO: CMPS or CMPSB?
  {0xA7, "CMPS"},     // TODO: CMPS or CMPSW CMPSD?
  {0xA8, "TEST"},     // TEST
  {0xA9, "TEST"},     // TEST
  {0xAA, "STOS"},     // TODO: STOS or STOSB?
  {0xAB, "STOS"},     // TODO: STOS or STOSW or STOSD
  {0xAC, "LODS"},     // LODS TODO: LODS or LODSB?
  {0xAD, "LODS"},     // LODS TODO: LODS or LODSW or LODSD?
  {0xAE, "SCAS"},     // SCAS TODO: SCAS or SCASB?
  {0xAF, "SCAS"},     // SCAS TODO: SCAS or SCASW or SCASD?
  {0xB0, "MOV AL"},   // MOV
  {0xB1, "MOV CL"},   // MOV
  {0xB2, "MOV DL"},   // MOV
  {0xB3, "MOV BL"},   // MOV
  {0xB4, "MOV AH"},   // MOV
  {0xB5, "MOV CH"},   // MOV
  {0xB6, "MOV DH"},   // MOV
  {0xB7, "MOV BH"},   // MOV
  {0xB8, "MOV EAX,", DASM_REQ_IMM32},  // MOV
  {0xB9, "MOV ECX,", DASM_REQ_IMM32},  // MOV
  {0xBA, "MOV EDX,", DASM_REQ_IMM32},  // MOV
  {0xBB, "MOV EBX,", DASM_REQ_IMM32},  // MOV
  {0xBC, "MOV ESP,", DASM_REQ_IMM32},  // MOV
  {0xBD, "MOV EBP,", DASM_REQ_IMM32},  // MOV
  {0xBE, "MOV ESI,", DASM_REQ_IMM32},  // MOV
  {0xBF, "MOV EDI,", DASM_REQ_IMM32},  // MOV
  {0xC0, NULL},       // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  {0xC1, NULL},       // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  {0xC2, "RET"},
  {0xC3, "RET"},
  {0xC4, "LES"},
  {0xC5, "LDS"},
  {0xC6, NULL},       // TODO: WTF? [Grp 11 1A] VIDE Section A.4 ?????
  {0xC7, NULL},       // TODO: WTF? [Grp 11 1A] VIDE Section A.4 ?????
  {0xC8, "ENTER"},
  {0xC9, "LEAVE"},
  {0xCA, "RET"},
  {0xCB, "RET"},
  {0xCC, "INT 3"},
  {0xCD, "INT"},
  {0xCE, "INTO"},
  {0xCF, "IRETD"},
  {0xD0, NULL},       // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  {0xD1, NULL},       // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  {0xD2, NULL},       // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  {0xD3, NULL},       // TODO: WTF? [Shift Grp 2 1A] VIDE Section A.4 ?????
  {0xD4, "AAM"},
  {0xD5, "AAD"},
  {0xD6, "SETALC"},   // TODO: UNDOCUMENTED. A.k.a. "SALC" said to set AL to CF
  {0xD7, "XLAT"},     // TODO: XLAT or XLATB?
  {0xD8, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  {0xD9, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  {0xDA, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  {0xDB, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  {0xDC, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  {0xDD, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  {0xDE, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  {0xDF, "???"},      // TODO: ESC (Escape to coprocessor instruction set)
  {0xE0, "LOOPNE"},
  {0xE1, "LOOPE"},
  {0xE2, "LOOP", DASM_REQ_CB},
  {0xE3, "JECXZ", DASM_REQ_CB},
  {0xE4, "IN AL"},
  {0xE5, "IN EAX"},
  {0xE6, "OUT"},
  {0xE7, "OUT"},
  {0xE8, "CALL", DASM_REQ_CD},
  {0xE9, "JMP"},
  {0xEA, "JMP"},
  {0xEB, "JMP"},
  {0xEC, "IN AL,DX"},
  {0xED, "IN EAX,DX"},
  {0xEE, "OUT DX,AL"},
  {0xEF, "OUT DX,EAX"},
  {0xF0, NULL},       // Instruction Prefixes Group 1 [LOCK (Prefix)]
  {0xF1, "ICEBP"},    // TODO: UNDOCUMENTED. A.k.a. "INT1"
  {0xF2, NULL},   // Instruction Prefixes Group 1 [REPNE XACQUIRE (Prefix)]
  {0xF3, NULL},   // Instruction Prefixes Group 1 [REP/REPE XRELEASE (Prefix)]
  {0xF4, "HLT"},
  {0xF5, "CMC"},
  {0xF6, NULL, DASM_MODRM_EXT, 3}, //TODO: [Unary Grp 3 1A] Section A.4
  {0xF7, NULL, DASM_MODRM_EXT, 3}, //TODO: [Unary Grp 3 1A] Section A.4
  {0xF8, "CLC"},
  {0xF9, "STC"},
  {0xFA, "CLI"},
  {0xFB, "STI"},
  {0xFC, "CLD"},
  {0xFD, "STD"},
  {0xFE, "???"}, // TODO: WTF? [INC/DEC Grp 4 1A] VIDE Section A.4 ?????
  {0xFF, "???"}  // TODO: WTF? [INC/DEC Grp 5 1A] VIDE Section A.4 ?????
};

OpcodeExt ExtGroup3[8] = {
  {0, "TEST"},     {1, NULL},   {2, "NOT"}, {3, "NEG"},
  {4, "MUL EAX,"}, {5, "IMUL"}, {6, "DIV"}, {7, "IDIV"},
};

const char* ModrRMRegOperand[8] = {
  "EAX", "ECX", "EDX", "EBX",
  "ESP", "EBP", "ESI", "EDI"
};

int IsPrefix(const uint8_t byte) {
  switch (byte)
  {
  // Group 1 — Lock and repeat prefixes:
  case DASM_PREFIX_LOCK:
  case DASM_PREFIX_REPNE_REPNZ:
  case DASM_PREFIX_REP_REPE_REPZ:
  // Group 2 — Segment override prefixes:
  case DASM_PREFIX_CS_SEGMENT_OVERRIDE: // Branch hints: PREFIX_BRANCH_NOT_TAKEN
  case DASM_PREFIX_SS_SEGMENT_OVERRIDE:
  case DASM_PREFIX_DS_SEGMENT_OVERRIDE: // Branch hints: PREFIX_BRANCH_TAKEN
  case DASM_PREFIX_ES_SEGMENT_OVERRIDE:
  case DASM_PREFIX_FS_SEGMENT_OVERRIDE:
  case DASM_PREFIX_GS_SEGMENT_OVERRIDE:
  // Group 3
  case DASM_PREFIX_OPERAND_SIZE_OVERRIDE:
  // Group 4
  case DASM_PREFIX_ADDRESS_SIZE_OVERRIDE:
    return byte;
  default:
    return 0;
  }
}

uint8_t ReadLegacyPrefixes(const uint8_t* CodeBytes, size_t CodeSize,
  INSTRUCTION* Instruction) {
  Instruction->PrefixBytes = 0;

  for (unsigned i = 0; i < CodeSize && i < DASM_MAX_PREFIXES; i++) {
    if (!IsPrefix(CodeBytes[i]))
      break;

    Instruction->Prefix[i] = CodeBytes[i];
    ++Instruction->PrefixBytes;
  }
  Instruction->Size = Instruction->PrefixBytes;

  return Instruction->PrefixBytes;
}

uint8_t ReadREXPrefix(const uint8_t* CodeBytes, size_t CodeSize,
  INSTRUCTION* Instruction) {
  // TODO: Handle REX Prefix
  Instruction = Instruction;
  CodeSize = CodeSize;
  CodeBytes = CodeBytes;
  return 0;
}

uint8_t ReadOpcode(const uint8_t* CodeBytes, size_t CodeSize,
  INSTRUCTION* Instruction) {
  if (!CodeSize)
    return Instruction->Size = DASM_INVALID_INSTRUCTION;

  // TODO: Handle multi-byte instructions
  Instruction->Opcode[0] = *CodeBytes;
  Instruction->Properties |= OpCodes[*CodeBytes].Properties;
  Instruction->OpcodeExtGrp = OpCodes[*CodeBytes].OpcodeExtGrp;
  Instruction->Size += 1;

  return 1;
}

uint8_t ReadModRM(const uint8_t* CodeBytes, size_t CodeSize,
  INSTRUCTION* Instruction) {
  if (!(Instruction->Properties & DASM_REQ_MODRM)) {
    return 0;
  }

  if (!CodeSize)
    return Instruction->Size = DASM_INVALID_INSTRUCTION;

  Instruction->ModRM.ModRM = *CodeBytes;
  Instruction->ModRM.Mod = MODRM_MOD(Instruction->ModRM.ModRM);
  Instruction->ModRM.RegOPCode = MODRM_REG_OPCODE(Instruction->ModRM.ModRM);
  Instruction->ModRM.RM = MODRM_RM(Instruction->ModRM.ModRM);

  Instruction->FieldsPresent |= DASM_REQ_MODRM;
  Instruction->Size += 1;

  return 1;
}

uint8_t ReadSIB(const uint8_t* CodeBytes, size_t CodeSize,
  INSTRUCTION* Instruction) {
  Instruction = Instruction;
  CodeSize = CodeSize;
  CodeBytes = CodeBytes;
  return 0;
}

uint8_t ReadDisplacement(const uint8_t* CodeBytes, size_t CodeSize,
  INSTRUCTION* Instruction) {
  Instruction = Instruction;
  CodeSize = CodeSize;
  CodeBytes = CodeBytes;
  return 0;
}

uint8_t ReadImmediate(const uint8_t* CodeBytes, size_t CodeSize,
  INSTRUCTION* Instruction) {
  /* cb, cw, cd that appears on Opcode columns of instruction tables are used
  as rel8, rel16 and rel32 on Instruction column for jump and loop instructions
  as target operands, giving relative offsets. I'll fetch them as Immediate */
  switch (Instruction->Properties & DASM_REQ_IMMEDIATE) {
  case DASM_REQ_IMM8:
    if (CodeSize < 1) return Instruction->Size = DASM_INVALID_INSTRUCTION;
    Instruction->Immediate = *CodeBytes;
    Instruction->Size += 1;
    return 1;
    break;
  case DASM_REQ_IMM32:
    if (CodeSize < 4) return Instruction->Size = DASM_INVALID_INSTRUCTION;
    Instruction->Immediate = *(uint32_t*)CodeBytes;
    // Instruction->Immediate[0] = *CodeBytes++;
    // Instruction->Immediate[1] = *CodeBytes++;
    // Instruction->Immediate[2] = *CodeBytes++;
    // Instruction->Immediate[3] = *CodeBytes++;
    Instruction->Size += 4;
    return 4;
  default:
    return 0;
  }
}

uint8_t DecodeInstructionText(INSTRUCTION* Instruction, uint8_t* StartAddr) {
  Instruction->Name = OpCodes[Instruction->Opcode[0]].Instruction;

  if (Instruction->OpcodeExtGrp) {
    OpcodeExt* OpcodeExtGroup = NULL;
    if (Instruction->OpcodeExtGrp == 3)
      OpcodeExtGroup = ExtGroup3;

    if (OpcodeExtGroup) {
      uint8_t RegOPCode = Instruction->ModRM.RegOPCode;
      Instruction->Name = OpcodeExtGroup[RegOPCode].Instruction;
      if (!Instruction->Name)
        return Instruction->Size = DASM_INVALID_INSTRUCTION;
    }
  }

  if (Instruction->Properties & DASM_REQ_MODRM) {
    const char *ModRMReg = ModrRMRegOperand[Instruction->ModRM.RegOPCode];
    const char *ModRMRM = NULL;
    switch (Instruction->ModRM.Mod)
    {
    case 3:
      ModRMRM = ModrRMRegOperand[Instruction->ModRM.RM];
      break;
    }
    // Here we use only ModR/M.RM, since ModRM/RegOpcode is used as extension
    if (DASM_MODRM_EXT == (Instruction->Properties & DASM_MODRM_EXT))
      snprintf(Instruction->DecodedText, DASM_MAX_INST_TXT, "%s %s",
        Instruction->Name, ModRMRM);
    else
      snprintf(Instruction->DecodedText, DASM_MAX_INST_TXT, "%s %s, %s",
        Instruction->Name,
        ModRMRM, ModRMReg);
  }
  else if (Instruction->Properties & DASM_REQ_CODE_OFFSET) {
    // TODO: consider rel16, rel32, rel64
    // jump or loop to rel8
    uint8_t* Target = (StartAddr + Instruction->Size) +
      (int8_t)Instruction->Immediate;
    snprintf(Instruction->DecodedText, DASM_MAX_INST_TXT, "%s %p",
      Instruction->Name,
      Target);
  }
  else if (Instruction->Properties & DASM_REQ_IMMEDIATE) {
    /* TODO: Consider printing signed/unsigned properly (as decimal?)
             "The opcode determines if the operand is a signed value." */
    snprintf(Instruction->DecodedText, DASM_MAX_INST_TXT, "%s %02X",
      Instruction->Name,
      Instruction->Immediate);
  }
  else {
    snprintf(Instruction->DecodedText, DASM_MAX_INST_TXT, "%s",
      Instruction->Name);
  }

  return 0;
}

// TODO: consider 16, 32 and 64 modes
/* Returns the number of instruction bytes or DASM_INVALID_INSTRUCTION. */
uint8_t dasm(const uint8_t* CodeBytes, size_t CodeSize,
  INSTRUCTION* Instruction, uint8_t* StartAddr) {
  if (!CodeSize)
    return Instruction->Size = DASM_INVALID_INSTRUCTION;

  ReadLegacyPrefixes(CodeBytes, CodeSize, Instruction);

  if (Instruction->Size != DASM_INVALID_INSTRUCTION)
    ReadREXPrefix(CodeBytes + Instruction->Size,
      CodeSize - Instruction->Size, Instruction);

  if (Instruction->Size != DASM_INVALID_INSTRUCTION)
    ReadOpcode(CodeBytes + Instruction->Size,
      CodeSize - Instruction->Size, Instruction);

  if (Instruction->Size != DASM_INVALID_INSTRUCTION)
    ReadModRM(CodeBytes + Instruction->Size,
      CodeSize - Instruction->Size, Instruction);

  if (Instruction->Size != DASM_INVALID_INSTRUCTION)
    ReadSIB(CodeBytes + Instruction->Size,
      CodeSize - Instruction->Size, Instruction);

  if (Instruction->Size != DASM_INVALID_INSTRUCTION)
    ReadDisplacement(CodeBytes + Instruction->Size,
      CodeSize - Instruction->Size, Instruction);

  if (Instruction->Size != DASM_INVALID_INSTRUCTION)
    ReadImmediate(CodeBytes + Instruction->Size,
      CodeSize - Instruction->Size, Instruction);

  if (DASM_INVALID_INSTRUCTION == DecodeInstructionText(Instruction, StartAddr))
    return DASM_INVALID_INSTRUCTION;

  return Instruction->Size;
}
