#pragma once

#include <stdint.h>

#define DASM_INVALID_INSTRUCTION 0xFF
#define DASM_MAX_PREFIXES           4
#define DAS_MAX_DISPLACEMENT_BYTES  4
#define DASM_MAX_INST_TXT          64
#define DASM_MAX_OPCODE_BYTES       2
// Required Instruction fields
#define DASM_REQ_MODRM           0x01
#define DASM_REQ_SIB             0x02
#define DASM_REQ_1_DISPLACEMENT  0x04
#define DASM_REQ_2_DISPLACEMENT  0x08
#define DASM_REQ_4_DISPLACEMENT  0x10
// 1 immediate byte required (imm8/ib)
#define DASM_REQ_IMM8            0x20
// 2 immediate bytes required (imm16/iw)
#define DASM_REQ_IMM16           0x40
// 4 immediate bytes required (imm32/id)
#define DASM_REQ_IMM32           (DASM_REQ_IMM8|DASM_REQ_IMM16)
#define DASM_REQ_IMMEDIATE       (DASM_REQ_IMM8|DASM_REQ_IMM16)
// Requires ModR/M; Reg fields provides opcode ext
#define DASM_MODRM_EXT           (0x80|DASM_REQ_MODRM)

// 3.1.1.1 Opcode Column in the Instruction Summary Table
/*cb, cw, cd, cp, co, ct — A 1-byte (cb), 2-byte (cw), 4-byte (cd), 6-byte (cp),
 8-byte (co) or 10-byte (ct) value following the opcode. This value is used to
 specify a code offset and possibly a new value for the code segment register.*/
/* TODO: cb, cw, cd... appear following the opcode;
   while ib, iw, id... follows the opcode, ModR/M bytes or
   scale-indexing bytes */
#define DASM_REQ_CODE_OFFSET 0x100
#define DASM_REQ_CB (0x100|DASM_REQ_IMM8)
#define DASM_REQ_CW (0x100|DASM_REQ_IMM16)
#define DASM_REQ_CD (0x100|DASM_REQ_IMM32)

// Prefix Group 1 — Lock and repeat prefixes:
#define DASM_PREFIX_LOCK          0xF0
#define DASM_PREFIX_REPNE_REPNZ   0xF2
#define DASM_PREFIX_REP_REPE_REPZ 0xF3
// Prefix Group 2 — Segment override prefixes:
#define DASM_PREFIX_CS_SEGMENT_OVERRIDE 0X2E
#define DASM_PREFIX_SS_SEGMENT_OVERRIDE 0X36
#define DASM_PREFIX_DS_SEGMENT_OVERRIDE 0X3E
#define DASM_PREFIX_ES_SEGMENT_OVERRIDE 0X26
#define DASM_PREFIX_FS_SEGMENT_OVERRIDE 0X64
#define DASM_PREFIX_GS_SEGMENT_OVERRIDE 0X65
// Branch hints:
#define DASM_PREFIX_JCC_BRANCH_NOT_TAKEN PREFIX_CS_SEGMENT_OVERRIDE
#define DASM_PREFIX_JCC_BRANCH_TAKEN     PREFIX_DS_SEGMENT_OVERRIDE
// Prefix Group 3
#define DASM_PREFIX_OPERAND_SIZE_OVERRIDE 0x66
// Prefix Group 4
#define DASM_PREFIX_ADDRESS_SIZE_OVERRIDE 0x67

#define PREFIX0 (uint8_t)0x8000 // 1 << F
#define PREFIX1 (uint8_t)0xC000 // 1 << E + ... 0x8000+0x4000
#define PREFIX2 (uint8_t)0xE000 // 1 << D + ... 0x8000+0x4000+0x2000
#define PREFIX3 (uint8_t)0xF000 // 1 << C + ... 0x8000+0x4000+0x2000+0x1000

#define MODRM_MOD(ModRM)        (((ModRM)>>6)&3)
#define MODRM_REG_OPCODE(ModRM) (((ModRM)>>3)&7)
#define MODRM_RM(ModRM)         ( (ModRM)    &7)

/*******************************************************************************
* References: Figure 2-1. Intel 64 and IA-32 Architectures Instruction Format  *
*             Figure 2-2. Table Interpretation of ModR/M Byte (C8H)            *
*             Figure 2-3. Prefix Ordering in 64-bit Mode                       *
*                                                                              *
*   OPTIONAL               OPTIONAL         OPTIONAL            OPTIONAL       *
*------------------------------------------------------------------------------*
* Instruction  |      |     ModR/M     |      SIB       |            |         *
*  Prefixes    |      |                |Sacle|Index|Base|            |         *
*--------------|Opcode|Mod|RegOPCode|RM|                |Displacement|Immediate*
*Legacy  |REX  |      |   76.543.210   |   76.543.210   |            |         *
*Prefixes|Pref.|      |   Mo.REG.R/M   |   ss.iii.bbb   |            |         *
*------------------------------------------------------------------------------*
*******************************************************************************/
typedef struct _ModRM {
  uint8_t ModRM;     // ModR/M byte
  uint8_t Mod;       // ModR/M Mod bits
  uint8_t RegOPCode; // ModR/M REG bits
  uint8_t RM;        // ModR/M RM bits
} ModRM;

typedef struct _INSTRUCTION {
  uint8_t Prefix[DASM_MAX_PREFIXES];
  uint8_t Opcode[DASM_MAX_OPCODE_BYTES];
  ModRM ModRM;
  uint8_t SIB;
  uint8_t Displacement[DAS_MAX_DISPLACEMENT_BYTES];
  uint32_t Immediate;

  uint16_t Properties;
  uint8_t FieldsPresent;
  uint8_t PrefixBytes;
  uint8_t Size;
  uint8_t OpcodeExtGrp;
  const char* Name;
  char DecodedText[DASM_MAX_INST_TXT];
} INSTRUCTION;

typedef struct _OPCODE {
  uint8_t Opcode;
  const char* Instruction;
  uint16_t Properties;
  uint8_t OpcodeExtGrp;
} OPCODE;

typedef struct {
  uint8_t ModRMRegOpcode;
  const char* Instruction;
} OpcodeExt;

#ifdef __cplusplus
extern "C" {
#endif
  uint8_t dasm(const uint8_t* code, size_t len, INSTRUCTION* Instruction,
    uint8_t* StartAddr);
#ifdef __cplusplus
}
#endif
