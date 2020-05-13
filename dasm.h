#pragma once

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
typedef struct _prefix {
  uint8_t p0;
  uint8_t p1;
  uint8_t p2;
  uint8_t p3;
} prefix;

typedef struct _opcode {
  uint8_t o0;
  uint8_t o1;
} opcode;

typedef union _modr_m {
  uint8_t modr_m;
} modr_m;

typedef struct _sib {
  uint8_t sib;
} sib;

typedef struct _displacement {
  union {
    uint8_t db; // displacement byte: 1 byte displacement
    union {     // 4 byte displacement
      uint32_t dd; // displacement dword: 4 byte displacement
      struct {
        uint8_t dd0;
        uint8_t dd1;
        uint8_t dd2;
        uint8_t dd3;
      } displacementbytes;
    };
  };
} displacement;

typedef struct _immediate {
  union {
    uint8_t ib; // immediate byte: 1 byte immediate
    union {     // 4 byte immediate
      uint32_t id; // immediate dword: 4 byte immediate
      struct{
        uint8_t i0;
        uint8_t i1;
        uint8_t i2;
        uint8_t i3;
      } immediatedword;
    };
  };
} immediate;

typedef struct _INSTRUCTION {
  prefix Prefix;
  opcode Opcode;
  modr_m ModRM;
  sib SIB;
  displacement Displacement;
  uint8_t FieldsNeeded;
  uint8_t FieldsPresent;
  const char *Name;
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

#define PREFIX0 (uint8_t)0x8000 // 1 << F
#define PREFIX1 (uint8_t)0xC000 // 1 << E + ... 0x8000 + 0x4000
#define PREFIX2 (uint8_t)0xE000 // 1 << D + ... 0x8000 + 0x4000 + 0x2000
#define PREFIX3 (uint8_t)0xF000 // 1 << C + ... 0x8000 + 0x4000 + 0x2000 + 0x1000

// 3.1.1.1 Opcode Column in the Instruction Summary Table
/*cb, cw, cd, cp, co, ct — A 1-byte (cb), 2-byte (cw), 4-byte (cd), 6-byte (cp),
 8-byte (co) or 10-byte (ct) value following the opcode. This value is used to
 specify a code offset and possibly a new value for the code segment register.*/
#define CB 0x01
/* /r — Indicates that the ModR/M byte of the instruction contains a register
operand and an r/m operand.*/
#define WANT_SLASH_R 0x02

typedef struct _OPCODE {
  uint8_t Opcode;
  const char* Instruction;
  uint8_t FieldsNeeded;
} OPCODE;

#define DASM_INVALID_INSTRUCTION 0xFF

#ifdef __cplusplus
extern "C" {
#endif
  uint8_t dasm(const uint8_t* code, size_t len, INSTRUCTION* Instruction);
#ifdef __cplusplus
}
#endif
