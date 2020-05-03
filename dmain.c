#include <stdio.h>
#include "dasm.h"

int main()
{
  uint8_t code[] = { 0xF2, 0xF2, 0xF2, 0xAE };

  INSTRUCTION Instruction = { 0 };
  uint8_t InstructionFields = 0;
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
