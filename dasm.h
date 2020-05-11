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

#define PREFIX0 0x8000 // 1 << F
#define PREFIX1 0xC000 // 1 << E + ... 0x8000 + 0x4000
#define PREFIX2 0xE000 // 1 << D + ... 0x8000 + 0x4000 + 0x2000
#define PREFIX3 0xF000 // 1 << C + ... 0x8000 + 0x4000 + 0x2000 + 0x1000

typedef struct _OPCODE {
  uint8_t Opcode;
  const char* Instruction;
} OPCODE;

#ifdef __cplusplus
extern "C" {
#endif
  uint8_t dasm(const uint8_t* code, size_t len, INSTRUCTION* Instruction);
#ifdef __cplusplus
}
#endif
