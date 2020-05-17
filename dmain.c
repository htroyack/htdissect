#include <stdio.h>
#include "dasm.h"

int main()
{
  uint8_t code[] = { 0xF2, 0xF2, 0xF2, 0xAE };

  INSTRUCTION Instruction = { 0 };
  uint8_t InstructionFields = 0;
  InstructionFields = dasm(code, sizeof(code), &Instruction, 0);

  if (InstructionFields & PREFIX0) {
    printf("Prefix: %02X", Instruction.Prefix[0]);
    if (InstructionFields & PREFIX1) {
      printf(" %02X", Instruction.Prefix[1]);
      if (InstructionFields & PREFIX2) {
        printf(" %02X", Instruction.Prefix[2]);
        if (InstructionFields & PREFIX3) {
          printf(" %02X", Instruction.Prefix[3]);
        }
      }
    }
    putchar('\n');
  }

  return 0;
}
