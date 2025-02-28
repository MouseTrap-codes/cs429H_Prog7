#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <regex.h>
#include <stdbool.h>
#include <endian.h>

#define MEM_SIZE 524288 // 512 KB

//// CPU definition
typedef struct cpu {
    uint8_t memory[MEM_SIZE];
    int64_t registers[32];
    uint64_t programCounter;
    int userMode; // 0 = false, 1 = true;
} CPU;

CPU* createCPU() {
    CPU* cpu = malloc(sizeof(CPU));
    if (cpu == NULL) {
        perror("malloc failed!");
        exit(1);
    }
    memset(cpu, 0, sizeof(*cpu));
    return cpu;
}

//// Tinker file header (new format)
typedef struct {
    uint32_t file_type;       // Currently, 0
    uint32_t code_seg_begin;  // Address where code is to be loaded (e.g. 0x2000)
    uint32_t code_seg_size;   // Size of the code segment (in bytes)
    uint32_t data_seg_begin;  // Address where data is to be loaded (e.g. 0x10000)
    uint32_t data_seg_size;   // Size of the data segment (could be 0)
} tinker_file_header;

//// Utility functions
void trim(char *s) {
    char *p = s;
    while (isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

void intToBinaryStr(unsigned int value, int width, char *outStr) {
    for (int i = width - 1; i >= 0; i--) {
        outStr[width - 1 - i] = ((value >> i) & 1) ? '1' : '0';
    }
    outStr[width] = '\0';
}

uint32_t binStrToUint32(const char *binStr) {
    uint32_t value = 0;
    for (int i = 0; i < 32; i++) {
        value <<= 1;
        if (binStr[i] == '1') {
            value |= 1;
        }
    }
    return value;
}

//// Instruction handling routines

// Integer arithmetic
void handleAdd(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    int64_t val1 = cpu->registers[rs];
    int64_t val2 = cpu->registers[rt];
    cpu->registers[rd] = (uint64_t)(val1 + val2);
    cpu->programCounter += 4;
}

void handleAddI(CPU* cpu, uint8_t rd, uint64_t L) {
    cpu->registers[rd] = cpu->registers[rd] + L;
    cpu->programCounter += 4;
}

void handleSub(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    int64_t val1 = cpu->registers[rs];
    int64_t val2 = cpu->registers[rt];
    cpu->registers[rd] = (uint64_t)(val1 - val2);
    cpu->programCounter += 4;
}

void handleSubI(CPU* cpu, uint8_t rd, uint64_t L) {
    cpu->registers[rd] = cpu->registers[rd] - L;
    cpu->programCounter += 4;
}

void handleMul(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    int64_t val1 = cpu->registers[rs];
    int64_t val2 = cpu->registers[rt];
    cpu->registers[rd] = (uint64_t)(val1 * val2);
    cpu->programCounter += 4;
}

void handleDiv(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    int64_t val1 = cpu->registers[rs];
    int64_t val2 = cpu->registers[rt];
    if (val2 == 0) {
        fprintf(stderr, "Simulation error: divide by zero\n");
        exit(1);
    }
    if (val1 == INT64_MIN && val2 == -1) {
        fprintf(stderr, "Signed integer overflow!!!\n");
        return;
    }
    cpu->registers[rd] = (uint64_t)(val1 / val2);
    cpu->programCounter += 4;
}

// Logic instructions
void handleAnd(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    cpu->registers[rd] = cpu->registers[rs] & cpu->registers[rt];
    cpu->programCounter += 4;
}

void handleOr(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    cpu->registers[rd] = cpu->registers[rs] | cpu->registers[rt];
    cpu->programCounter += 4;
}

void handleXor(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    cpu->registers[rd] = cpu->registers[rs] ^ cpu->registers[rt];
    cpu->programCounter += 4;
}

void handleNot(CPU* cpu, uint8_t rd, uint8_t rs) {
    cpu->registers[rd] = ~cpu->registers[rs];
    cpu->programCounter += 4;
}

// Shift instructions
void handleShftR(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    cpu->registers[rd] = cpu->registers[rs] >> cpu->registers[rt];
    cpu->programCounter += 4;
}

void handleShftRI(CPU* cpu, uint8_t rd, uint64_t L) {
    cpu->registers[rd] = cpu->registers[rd] >> L;
    cpu->programCounter += 4;
}

void handleShftL(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    cpu->registers[rd] = cpu->registers[rs] << cpu->registers[rt];
    cpu->programCounter += 4;
}

void handleShftLI(CPU* cpu, uint8_t rd, uint64_t L) {
    cpu->registers[rd] = cpu->registers[rd] << L;
    cpu->programCounter += 4;
}

// Control instructions
void handleBr(CPU* cpu, uint8_t rd) {
    cpu->programCounter = cpu->registers[rd];
}

void handleBrr(CPU* cpu, uint8_t rd) {
    cpu->programCounter += cpu->registers[rd];
}

void handleBrrL(CPU* cpu, int64_t L) {
    cpu->programCounter += (int64_t)L;
}

void handleBrnz(CPU* cpu, uint8_t rd, uint8_t rs) {
    if (cpu->registers[rs] == 0)
        cpu->programCounter += 4;
    else
        cpu->programCounter = cpu->registers[rd];
}

void handleCall(CPU *cpu, uint8_t rd) {
    cpu->programCounter += 4;
    memcpy(cpu->memory + cpu->registers[31] - 8, &(cpu->programCounter), sizeof(cpu->programCounter));
    cpu->programCounter = cpu->registers[rd];
}

void handleReturn(CPU* cpu) {
    memcpy(&(cpu->programCounter), cpu->memory + cpu->registers[31] - 8, sizeof(cpu->programCounter));
}

// Conditional branch (greater than)
void handleBrgt(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    if ((int64_t)cpu->registers[rs] <= (int64_t)cpu->registers[rt])
        cpu->programCounter += 4;
    else
        cpu->programCounter = cpu->registers[rd];
}

// Privileged instructions
void priv(CPU* cpu, int rd, int rs, int rt, uint64_t L) {
    switch (L) {
        case 0x0: // Halt
            exit(0);
        case 0x1: // Trap: switch to supervisor mode
            cpu->userMode = 0;
            cpu->programCounter += 4;
            break;
        case 0x2: // RTE: return to user mode
            cpu->userMode = 1;
            cpu->programCounter += 4;
            break;
        case 0x3: // Input: rd <- Input[rs]
            if (cpu->registers[rs] != 0) {
                printf("unsupported port for input");
                return;
            }
            {
                int64_t input;
                scanf("%lld", &input);
                cpu->registers[rd] = (uint64_t)input;
                cpu->programCounter += 4;
            }
            break;
        case 0x4: // Output: Output[rd] <- rs
            if (cpu->registers[rd] != 1) {
                printf("unsupported port for output");
                return;
            }
            printf("%llu", cpu->registers[rs]);
            cpu->programCounter += 4;
            break;
        default:
            fprintf(stderr, "Simulation error: illegal priv operation\n");
            exit(1);
    }
}

// Data movement instructions

// mov rd, (rs)(L) : load 64-bit value from memory at (register[rs] + L)
void handleMovRdRsL(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, int64_t L) {
    int64_t address = cpu->registers[rs] + L;
    if ((address + 8) > MEM_SIZE || address < 0) {
        fprintf(stderr, "Simulation error: memory access out of bounds\n");
        exit(1);
    }
    cpu->registers[rd] = *(uint64_t*)(cpu->memory + address);
    cpu->programCounter += 4;
}

// mov rd, rs : copy register rs into rd.
void movRdRs(CPU* cpu, uint8_t rd, uint8_t rs) {
    cpu->registers[rd] = cpu->registers[rs];
    cpu->programCounter += 4;
}

// mov rd, L : load the 12-bit immediate L into register rd (without shifting into the upper bits)
void handleMovRdL(CPU* cpu, uint8_t rd, uint16_t L) {
    cpu->registers[rd] = (uint64_t)L;
    cpu->programCounter += 4;
}

// mov (rd)(L), rs : store register rs into memory at (register[rd] + L)
void handleMovRDLRs(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) {
    int64_t address = cpu->registers[rd] + L;
    if ((address + 8) > MEM_SIZE || address < 0) {
        fprintf(stderr, "Simulation error: memory access out of bounds\n");
        exit(1);
    }
    *(uint64_t *)(cpu->memory + address) = cpu->registers[rs];
    cpu->programCounter += 4;
}

// Floating point instructions
void handleAddf(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    double val1 = 0, val2 = 0;
    memcpy(&val1, &(cpu->registers[rs]), sizeof(double));
    memcpy(&val2, &(cpu->registers[rt]), sizeof(double));
    double result = val1 + val2;
    memcpy(&(cpu->registers[rd]), &result, sizeof(double));
    cpu->programCounter += 4;
}

void handleSubf(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    double val1 = 0, val2 = 0;
    memcpy(&val1, &(cpu->registers[rs]), sizeof(double));
    memcpy(&val2, &(cpu->registers[rt]), sizeof(double));
    double result = val1 - val2;
    memcpy(&(cpu->registers[rd]), &result, sizeof(double));
    cpu->programCounter += 4;
}

void handleMulf(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    double val1 = 0, val2 = 0;
    memcpy(&val1, &(cpu->registers[rs]), sizeof(double));
    memcpy(&val2, &(cpu->registers[rt]), sizeof(double));
    double result = val1 * val2;
    memcpy(&(cpu->registers[rd]), &result, sizeof(double));
    cpu->programCounter += 4;
}

void handleDivf(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt) {
    double val1 = 0, val2 = 0;
    memcpy(&val1, &(cpu->registers[rs]), sizeof(double));
    memcpy(&val2, &(cpu->registers[rt]), sizeof(double));
    if (val2 == 0.0) {
        fprintf(stderr, "Simulation error: floating-point divide by zero\n");
        exit(1);
    }
    double result = val1 / val2;
    memcpy(&(cpu->registers[rd]), &result, sizeof(double));
    cpu->programCounter += 4;
}

//// Instruction Handler Wrappers (for uniform function pointer type)
typedef void (*InstructionHandler)(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L);

void wrapperHandleAdd(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleAdd(cpu, rd, rs, rt); }
void wrapperHandleAddI(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleAddI(cpu, rd, L); }
void wrapperHandleSub(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleSub(cpu, rd, rs, rt); }
void wrapperHandleSubI(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleSubI(cpu, rd, L); }
void wrapperHandleMul(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleMul(cpu, rd, rs, rt); }
void wrapperHandleDiv(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleDiv(cpu, rd, rs, rt); }
void wrapperHandleAnd(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleAnd(cpu, rd, rs, rt); }
void wrapperHandleOr(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleOr(cpu, rd, rs, rt); }
void wrapperHandleXor(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleXor(cpu, rd, rs, rt); }
void wrapperHandleNot(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleNot(cpu, rd, rs); }
void wrapperHandleShftR(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleShftR(cpu, rd, rs, rt); }
void wrapperHandleShftRI(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleShftRI(cpu, rd, L); }
void wrapperHandleShftL(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleShftL(cpu, rd, rs, rt); }
void wrapperHandleShftLI(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleShftLI(cpu, rd, L); }
void wrapperHandleBr(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleBr(cpu, rd); }
void wrapperHandleBrr(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleBrr(cpu, rd); }
void wrapperHandleBrrL(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleBrrL(cpu, (int64_t)L); }
void wrapperHandleBrnz(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleBrnz(cpu, rd, rs); }
void wrapperHandleCall(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleCall(cpu, rd); }
void wrapperHandleReturn(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleReturn(cpu); }
void wrapperHandleBrgt(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleBrgt(cpu, rd, rs, rt); }

void wrapperHandleMovRdRsL(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleMovRdRsL(cpu, rd, rs, rt, (int64_t)L); }
void wrapperMovRdRs(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { movRdRs(cpu, rd, rs); }
void wrapperHandleMovRdL(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleMovRdL(cpu, rd, (uint16_t)L); }
void wrapperHandleMovRDLRs(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleMovRDLRs(cpu, rd, rs, L); }

void wrapperHandleAddf(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleAddf(cpu, rd, rs, rt); }
void wrapperHandleSubf(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleSubf(cpu, rd, rs, rt); }
void wrapperHandleMulf(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleMulf(cpu, rd, rs, rt); }
void wrapperHandleDivf(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) { handleDivf(cpu, rd, rs, rt); }

void wrapperHandlePriv(CPU* cpu, uint8_t rd, uint8_t rs, uint8_t rt, uint64_t L) {
    priv(cpu, rd, rs, rt, L);
}

//// Global opcode function pointer array
InstructionHandler opHandlers[256] = {0};

void initOpcodeHandlers() {
    for (int i = 0; i < 256; i++)
        opHandlers[i] = NULL;

    // Logic Instructions (opcodes 0x0-0x3)
    opHandlers[0x0] = wrapperHandleAnd;
    opHandlers[0x1] = wrapperHandleOr;
    opHandlers[0x2] = wrapperHandleXor;
    opHandlers[0x3] = wrapperHandleNot;

    // Shift Instructions (opcodes 0x4-0x7)
    opHandlers[0x4] = wrapperHandleShftR;
    opHandlers[0x5] = wrapperHandleShftRI;
    opHandlers[0x6] = wrapperHandleShftL;
    opHandlers[0x7] = wrapperHandleShftLI;

    // Control Instructions (opcodes 0x8-0xE)
    opHandlers[0x8] = wrapperHandleBr;
    opHandlers[0x9] = wrapperHandleBrr;
    opHandlers[0xA] = wrapperHandleBrrL;  // brr L
    opHandlers[0xB] = wrapperHandleBrnz;
    opHandlers[0xC] = wrapperHandleCall;
    opHandlers[0xD] = wrapperHandleReturn;
    opHandlers[0xE] = wrapperHandleBrgt;

    // Privileged Instructions (opcode 0xF)
    opHandlers[0xF] = wrapperHandlePriv;

    // Data Movement Instructions (opcodes 0x10-0x13)
    opHandlers[0x10] = wrapperHandleMovRdRsL;
    opHandlers[0x11] = wrapperMovRdRs;
    opHandlers[0x12] = wrapperHandleMovRdL;
    opHandlers[0x13] = wrapperHandleMovRDLRs;

    // Floating Point Instructions (opcodes 0x14-0x17)
    opHandlers[0x14] = wrapperHandleAddf;
    opHandlers[0x15] = wrapperHandleSubf;
    opHandlers[0x16] = wrapperHandleMulf;
    opHandlers[0x17] = wrapperHandleDivf;

    // Integer Arithmetic Instructions (opcodes 0x18-0x1D)
    opHandlers[0x18] = wrapperHandleAdd;
    opHandlers[0x19] = wrapperHandleAddI;
    opHandlers[0x1A] = wrapperHandleSub;
    opHandlers[0x1B] = wrapperHandleSubI;
    opHandlers[0x1C] = wrapperHandleMul;
    opHandlers[0x1D] = wrapperHandleDiv;
}

//// Main simulation loop
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program.tko>\n", argv[0]);
        exit(1);
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Invalid tinker filepath\n");
        exit(1);
    }
    
    // Read header from file.
    tinker_file_header header;
    if (fread(&header, sizeof(header), 1, fp) != 1) {
        fprintf(stderr, "Error reading header\n");
        exit(1);
    }
    // Convert header fields from little-endian.
    header.file_type     = le32toh(header.file_type);
    header.code_seg_begin = le32toh(header.code_seg_begin);
    header.code_seg_size  = le32toh(header.code_seg_size);
    header.data_seg_begin = le32toh(header.data_seg_begin);
    header.data_seg_size  = le32toh(header.data_seg_size);
    
    CPU* cpu = createCPU();
    // Initialize stack pointer (r31) to top of memory.
    cpu->registers[31] = MEM_SIZE;
    // Set program counter to code segment beginning.
    cpu->programCounter = header.code_seg_begin;
    
    // Load code segment into memory.
    if (header.code_seg_begin + header.code_seg_size > MEM_SIZE) {
        fprintf(stderr, "Code segment does not fit in memory\n");
        exit(1);
    }
    if (fread(cpu->memory + header.code_seg_begin, 1, header.code_seg_size, fp) != header.code_seg_size) {
        fprintf(stderr, "Error reading code segment\n");
        exit(1);
    }
    // Load data segment into memory.
    if (header.data_seg_size > 0) {
        if (header.data_seg_begin + header.data_seg_size > MEM_SIZE) {
            fprintf(stderr, "Data segment does not fit in memory\n");
            exit(1);
        }
        if (fread(cpu->memory + header.data_seg_begin, 1, header.data_seg_size, fp) != header.data_seg_size) {
            fprintf(stderr, "Error reading data segment\n");
            exit(1);
        }
    }
    fclose(fp);
    
    // Initialize opcode handler array.
    initOpcodeHandlers();
    
    // Simulation loop: run while PC is within the code segment.
    uint64_t codeEnd = header.code_seg_begin + header.code_seg_size;
    while (cpu->programCounter >= header.code_seg_begin && cpu->programCounter < codeEnd) {
        // Fetch 32-bit instruction from memory.
        uint32_t instruction = *(uint32_t*)(cpu->memory + cpu->programCounter);
        instruction = le32toh(instruction);
        
        // Decode fields based on the Tinker Instruction Manual:
        // Bits 31-27: opcode (5 bits)
        // Bits 26-22: rd (5 bits)
        // Bits 21-17: rs (5 bits)
        // Bits 16-12: rt (5 bits)
        // Bits 11-0 : immediate L (12 bits) for instructions that use it.
        uint8_t opcode = (instruction >> 27) & 0x1F;
        //printf("opcode: 0x%x ", opcode);
        uint8_t rd     = (instruction >> 22) & 0x1F;
        //printf("rd: %d ", rd);
        uint8_t rs     = (instruction >> 17) & 0x1F;
        //printf("rs: %d ", rs);
        uint8_t rt     = (instruction >> 12) & 0x1F;
        //printf("rt: %d ", rt);
        uint16_t imm = instruction & 0xFFF;
        //printf("L: %d\n", imm);
        uint64_t L = 0;
        
        // For immediate instructions:
        // For brr L (opcode 0xA) we sign-extend the immediate since it can be negative.
        // For immediate instructions:
        if (opcode == 0xA || opcode == 0x10 || opcode == 0x13) {
            // brr L needs sign extension
            int64_t signedImm = imm;
            if (imm & 0x800) // If bit 11 is set, sign-extend.
                signedImm |= ~0xFFF;
            L = (uint64_t) signedImm;

        } else if (
            // any opcode that uses bits [11:0] as an unsigned immediate
            opcode == 0x19 || // addi
            opcode == 0x1B || // subi
            opcode == 0x12 || // mov rd, L
            opcode == 0xF  || // priv rd, rs, rt, L
            opcode == 0x5  || // shftri
            opcode == 0x7   // shftli
            // opcode == 0x10 || // mov rd, (rs)(L)  <--- Add this
            // opcode == 0x13    // mov (rd)(L), rs  <--- And this
        ) {
            L = imm;
        }
        
        // Dispatch instruction.
        if (opHandlers[opcode]) {
            opHandlers[opcode](cpu, rd, rs, rt, L);
        } else {
            fprintf(stderr, "Unhandled opcode: 0x%X\n", opcode);
            exit(1);
        }
    }
    
    fprintf(stderr, "Simulation error: reached end of code segment\n");
    exit(1);
    return 0;
}
