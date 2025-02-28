#define _GNU_SOURCE
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
#include "uthash.h"

// ===================================================================
//                          Label Map
// ===================================================================
typedef struct {
    char label[50];
    int address; // e.g., 0x1000 -> 4096
    UT_hash_handle hh;
} LabelAddress;

static LabelAddress *labelMap = NULL;

// ===================================================================
//                     Global Error-Handling
// ===================================================================
static FILE *g_fout = NULL;
static char g_outFilename[1024];

// If we detect an error mid-assembly in Pass 2, remove partial file and exit
static void abortAssembly(void) {
    if (g_fout) {
        fclose(g_fout);
        g_fout = NULL;
    }
    if (g_outFilename[0] != '\0') {
        unlink(g_outFilename);
    }
    exit(1);
}

// ===================================================================
//                     Label Validation
// ===================================================================
static int isValidLabelName(const char *label) {
    if (!isalpha((unsigned char)label[0]) && label[0] != '_') {
        return 0;
    }
    for (int i = 1; label[i] != '\0'; i++) {
        if (!isalnum((unsigned char)label[i]) && label[i] != '_') {
            return 0;
        }
    }
    return 1;
}

// ===================================================================
//                Add / Find / Free Label
// ===================================================================
LabelAddress *findLabel(const char *label) {
    LabelAddress *entry = NULL;
    HASH_FIND_STR(labelMap, label, entry);
    return entry;
}

void addLabel(const char *label, int address) {
    if (findLabel(label)) {
        fprintf(stderr, "Error: Duplicate label \"%s\"\n", label);
        exit(1);
    }
    if (!isValidLabelName(label)) {
        fprintf(stderr, "Error: Invalid label name \"%s\"\n", label);
        exit(1);
    }
    LabelAddress *entry = (LabelAddress *)malloc(sizeof(LabelAddress));
    if (!entry) {
        fprintf(stderr, "Error: malloc failed in addLabel.\n");
        exit(1);
    }
    strncpy(entry->label, label, sizeof(entry->label) - 1);
    entry->label[sizeof(entry->label) - 1] = '\0';
    entry->address = address;
    HASH_ADD_STR(labelMap, label, entry);
}

void freeLabelMap() {
    LabelAddress *cur, *tmp;
    HASH_ITER(hh, labelMap, cur, tmp) {
        HASH_DEL(labelMap, cur);
        free(cur);
    }
}

// ===================================================================
//                     Utility Functions
// ===================================================================
void trim(char *s) {
    char *p = s;
    while (isspace((unsigned char)*p)) {
        p++;
    }
    if (p != s) {
        memmove(s, p, strlen(p) + 1);
    }
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

// ===================================================================
//                  Pass 1: Build Label Map & Compute PC & DC
// ===================================================================
void pass1(const char *filename) {
    FILE *fin = fopen(filename, "r");
    if (!fin) {
        perror("pass1 fopen");
        exit(1);
    }
    enum { NONE, CODE, DATA } section = NONE;
    int pc = 0x2000;  // starting address for instructions
    int dc = 0x10000; // starting address for data
    char line[1024];

    while (fgets(line, sizeof(line), fin)) {
        line[strcspn(line, "\n")] = '\0';
        trim(line);
        if (line[0] == '\0' || line[0] == ';')
            continue;
        if (line[0] == '.') {
            if (!strncmp(line, ".code", 5))
                section = CODE;
            else if (!strncmp(line, ".data", 5))
                section = DATA;
            continue;
        }
        if (line[0] == ':') {
            char label[50];
            if (line[0] == ':') {
                char label[50];
                if (sscanf(line + 1, "%49s", label) == 1) {
                    if (section == CODE || section == NONE) {
                        addLabel(label, pc);
                    } else { // section == DATA
                        addLabel(label, dc);
                    }
                }
                continue;
            }
            
            continue;
        }
        if (section == CODE) {
            char temp[16];
            sscanf(line, "%15s", temp);
            if (!strcmp(temp, "ld"))
                pc += 48;  // ld => 12 instructions => 48 bytes
            else if (!strcmp(temp, "push") || !strcmp(temp, "pop"))
                pc += 8;   // push/pop => 2 instructions => 8 bytes
            else
                pc += 4;   // normal instruction => 4 bytes
        } else if (section == DATA) {
            dc += 8; // each data item => 8 bytes
        }
    }
    fclose(fin);
}

// ===================================================================
// Instruction Table for Standard Instructions
// ===================================================================
typedef struct {
    char name[16];
    int  opcode;
    const char *format; 
    UT_hash_handle hh;
} InstructionEntry;

static InstructionEntry *instMap = NULL;

void addInst(const char *name, int opcode, const char *format) {
    InstructionEntry *e = (InstructionEntry *)malloc(sizeof(InstructionEntry));
    if (!e) {
        fprintf(stderr, "malloc error\n");
        exit(1);
    }
    strncpy(e->name, name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    e->opcode = opcode;
    e->format = format;
    HASH_ADD_STR(instMap, name, e);
}

void freeInstMap() {
    InstructionEntry *cur, *tmp;
    HASH_ITER(hh, instMap, cur, tmp) {
        HASH_DEL(instMap, cur);
        free(cur);
    }
}

void populateInstMap() {
    instMap = NULL;
    addInst("add",   0x18, "rd rs rt");
    addInst("addi",  0x19, "rd L");
    addInst("sub",   0x1a, "rd rs rt");
    addInst("subi",  0x1b, "rd L");
    addInst("mul",   0x1c, "rd rs rt");
    addInst("div",   0x1d, "rd rs rt");
    addInst("and",   0x0,  "rd rs rt");
    addInst("or",    0x1,  "rd rs rt");
    addInst("xor",   0x2,  "rd rs rt");
    addInst("not",   0x3,  "rd rs");
    addInst("shftr", 0x4,  "rd rs rt");
    addInst("shftri",0x5,  "rd L");
    addInst("shftl", 0x6,  "rd rs rt");
    addInst("shftli",0x7,  "rd L");
    addInst("br",    0x8,  "rd");
    addInst("brnz",  0xb,  "rd rs");
    addInst("call",  0xc,  "rd"); 
    addInst("return",0xd,  "");
    addInst("brgt",  0xe,  "rd rs rt");
    addInst("priv",  0xf,  "rd rs rt L");
    addInst("addf",  0x14, "rd rs rt");
    addInst("subf",  0x15, "rd rs rt");
    addInst("mulf",  0x16, "rd rs rt");
    addInst("divf",  0x17, "rd rs rt");
}

// ===================================================================
// Assemble "brr", "mov", or standard
// ===================================================================
void assembleBrrOperand(const char *operand, char *binStr) {
    while(isspace((unsigned char)*operand)) operand++;
    int opcode, reg=0, imm=0;
    if(operand[0]=='r'){
        opcode=0x9;
        reg=(int)strtol(operand+1,NULL,0);
    } else{
        opcode=0xa;
        imm=(int)strtol(operand,NULL,0);
    }
    unsigned int inst=(opcode<<27)|(reg<<22)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

void assembleMov(const char *line, char *binStr) {
    char mnemonic[10], token1[64], token2[64];
    if(sscanf(line, "%s %63[^,], %63s", mnemonic, token1, token2)<3){
        strcpy(binStr,"ERROR");
        return;
    }
    trim(token1);
    trim(token2);

    int opcode=0, rd=0, rs=0, rt=0, imm=0;

    if(token1[0]=='('){
        opcode=0x13;
        char *p1=strchr(token1,'r');
        if(!p1){ strcpy(binStr,"ERROR"); return; }
        int rtemp=0;
        sscanf(p1+1,"%d",&rtemp);
        rd=rtemp;
        char *paren2=strstr(token1,")(");
        if(!paren2){
            imm=0;
        } else {
            char offsetBuf[32];
            char *startOffset=paren2+2;
            char *endParen=strrchr(token1,')');
            if(!endParen||endParen<=startOffset){
                strcpy(binStr,"ERROR");
                return;
            }
            size_t length=endParen-startOffset;
            if(length>=sizeof(offsetBuf)){
                strcpy(binStr,"ERROR");
                return;
            }
            strncpy(offsetBuf, startOffset, length);
            offsetBuf[length] = '\0';
            imm=(int)strtol(offsetBuf,NULL,0);
        }
        if(token2[0]!='r'){
            strcpy(binStr,"ERROR");
            return;
        }
        rs=(int)strtol(token2+1,NULL,0);
    }
    else {
        if(token1[0]!='r'){ strcpy(binStr,"ERROR"); return; }
        rd=(int)strtol(token1+1,NULL,0);
        if(token2[0]=='('){
            opcode=0x10;
            char *p1=strchr(token2,'r');
            if(!p1){ strcpy(binStr,"ERROR"); return; }
            int rtemp=0;
            sscanf(p1+1,"%d",&rtemp);
            rs=rtemp;
            char *paren2=strstr(token2,")(");
            if(!paren2){
                imm=0;
            } else {
                char offsetBuf[32];
                char *startOffset=paren2+2;
                char *endParen=strrchr(token2,')');
                if(!endParen||endParen<=startOffset){
                    strcpy(binStr,"ERROR");
                    return;
                }
                size_t length=endParen-startOffset;
                if(length>=sizeof(offsetBuf)){
                    strcpy(binStr,"ERROR");
                    return;
                }
                strncpy(offsetBuf, startOffset, length);
                offsetBuf[length]='\0';
                imm=(int)strtol(offsetBuf,NULL,0);
            }
        }
        else if(token2[0]=='r'){
            opcode=0x11;
            rs=(int)strtol(token2+1,NULL,0);
        }
        else {
            if(token2[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed for mov rD, L\n");
                abortAssembly();
            }
            opcode=0x12;
            imm=(int)strtol(token2,NULL,0);
        }
    }
    unsigned int inst=(opcode<<27)|(rd<<22)|(rs<<17)|(rt<<12)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

void assembleStandard(const char *line, char *binStr) {
    char mnemonic[16], op1[16], op2[16], op3[16], op4[16];
    int num=sscanf(line, "%15s %15s %15s %15s %15s",
                   mnemonic, op1, op2, op3, op4);

    InstructionEntry *e=NULL;
    HASH_FIND_STR(instMap, mnemonic, e);
    if(!e){
        strcpy(binStr,"ERROR");
        return;
    }
    int opcode=e->opcode, rd=0, rs=0, rt=0, imm=0;

    if(!strcmp(e->format,"rd L") && num>=3){
        if(op2[0]=='-'){
            fprintf(stderr,"Error: negative immediate not allowed for %s\n",mnemonic);
            abortAssembly();
        }
    }

    if(!strcmp(e->format,"rd rs rt") && num>=4){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
        rs=(op2[0]=='r')?strtol(op2+1,NULL,0):0;
        rt=(op3[0]=='r')?strtol(op3+1,NULL,0):0;
    }
    else if(!strcmp(e->format,"rd L") && num>=3){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
        imm=(int)strtol(op2,NULL,0);
    }
    else if(!strcmp(e->format,"rd rs") && num>=3){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
        rs=(op2[0]=='r')?strtol(op2+1,NULL,0):0;
    }
    else if(!strcmp(e->format,"rd rs rt L") && num>=5){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
        rs=(op2[0]=='r')?strtol(op2+1,NULL,0):0;
        rt=(op3[0]=='r')?strtol(op3+1,NULL,0):0;
        imm=(int)strtol(op4,NULL,0);
    }
    else if(!strcmp(e->format,"rd") && num>=2){
        rd=(op1[0]=='r')?strtol(op1+1,NULL,0):0;
    } 
    else {
        strcpy(binStr,"ERROR");
        return;
    }

    unsigned int inst=(opcode<<27)|(rd<<22)|(rs<<17)|(rt<<12)|((imm&0xFFF));
    char tmp[33];
    intToBinaryStr(inst,32,tmp);
    strcpy(binStr,tmp);
}

static void assembleReturn(char *binStr)
{
    unsigned int inst = (0xd << 27);  // 0xd0000000 in hex

    char tmp[33];
    intToBinaryStr(inst, 32, tmp);
    strcpy(binStr, tmp);
}

void assembleInstruction(const char *line, char *binStr) {
    char mnemonic[16] = {0};
    sscanf(line, "%15s", mnemonic);
    if (!strcmp(mnemonic, "return")) {
        assembleReturn(binStr);
        return;
    }
    if(!strcmp(mnemonic,"mov")){
        assembleMov(line, binStr);
    }
    else if(!strcmp(mnemonic,"brr")){
        const char *p=line+3;
        while(isspace((unsigned char)*p)) p++;
        assembleBrrOperand(p, binStr);
    }
    else {
        assembleStandard(line, binStr);
    }
}

// ===================================================================
//                      Macro Expansion
// ===================================================================
void parseMacro(const char *line, FILE *outStream) {
    regex_t regex;
    regmatch_t matches[3];
    char op[16];
    if (sscanf(line, "%15s", op) != 1) {
        fprintf(stderr,"Error: invalid macro usage -> %s\n", line);
        abortAssembly();
    }

    if(!strcmp(op,"ld")){
        const char *pattern = "^[[:space:]]*ld[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*(\\S+)";
        if(regcomp(&regex, pattern, REG_EXTENDED)!=0){
            fprintf(stderr,"Error: can't compile regex for ld\n");
            abortAssembly();
        }
        if(regexec(&regex,line,3,matches,0)==0){
            char regBuf[16], immBuf[64];
            int rD;
            int len = matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf, line+matches[1].rm_so, len);
            regBuf[len]='\0';
            rD=(int)strtol(regBuf,NULL,0);
            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(immBuf, line+matches[2].rm_so, len);
            immBuf[len]='\0';
            if(immBuf[0]=='-'){
                fprintf(stderr,"Error: negative immediate not allowed in ld macro\n");
                regfree(&regex);
                abortAssembly();
            }
            uint64_t imm;
            if(!isdigit((unsigned char)immBuf[0])) {
                LabelAddress *entry=findLabel(immBuf);
                if(!entry){
                    fprintf(stderr,"Error: label '%s' not found (ld macro)\n", immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                imm=entry->address;
            } else {
                errno=0;
                char*endptr=NULL;
                uint64_t tmpVal=strtoull(immBuf,&endptr,0);
                if(errno==ERANGE){
                    fprintf(stderr,"Error: ld immediate out of range => %s\n",immBuf);
                    regfree(&regex);
                    abortAssembly();
                }
                imm=tmpVal;
            }
            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
            unsigned long long top12 =(imm>>52)&0xFFF;
            unsigned long long mid12a=(imm>>40)&0xFFF;
            unsigned long long mid12b=(imm>>28)&0xFFF;
            unsigned long long mid12c=(imm>>16)&0xFFF;
            unsigned long long mid4  =(imm>>4)&0xFFF;
            unsigned long long last4 = imm & 0xF;
            fprintf(outStream,"addi r%d %llu\n",rD,top12);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,mid12a);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,mid12b);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,mid12c);
            fprintf(outStream,"shftli r%d 12\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,mid4);
            fprintf(outStream,"shftli r%d 4\n",rD);
            fprintf(outStream,"addi r%d %llu\n",rD,last4);
        } else {
            fprintf(stderr,"Error: invalid 'ld' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"push")){
        const char*pattern="^[[:space:]]*push[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for push\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            fprintf(outStream,"mov (r31)(-8), r%d\n",rD);
            fprintf(outStream,"subi r31 8\n");
        } else {
            fprintf(stderr,"Error: invalid 'push' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"pop")){
        const char *pattern="^[[:space:]]*pop[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for pop\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            fprintf(outStream,"mov r%d, (r31)(0)\n",rD);
            fprintf(outStream,"addi r31 8\n");
        } else {
            fprintf(stderr,"Error: invalid 'pop' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"in")){
        const char*pattern="^[[:space:]]*in[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for in\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf1[16], regBuf2[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1,line+matches[1].rm_so,len);
            regBuf1[len]='\0';
            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2,line+matches[2].rm_so,len);
            regBuf2[len]='\0';
            int rD=(int)strtol(regBuf1,NULL,0);
            int rS=(int)strtol(regBuf2,NULL,0);
            fprintf(outStream,"priv r%d r%d r0 3\n",rD,rS);
        } else {
            fprintf(stderr,"Error: invalid 'in' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"out")){
        const char *pattern="^[[:space:]]*out[[:space:]]+r([0-9]+)[[:space:]]*,[[:space:]]*r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for out\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,3,matches,0)){
            char regBuf1[16], regBuf2[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf1,line+matches[1].rm_so,len);
            regBuf1[len]='\0';
            len=matches[2].rm_eo - matches[2].rm_so;
            strncpy(regBuf2,line+matches[2].rm_so,len);
            regBuf2[len]='\0';
            int rD=(int)strtol(regBuf1,NULL,0);
            int rS=(int)strtol(regBuf2,NULL,0);
            fprintf(outStream,"priv r%d r%d r0 4\n",rD,rS);
        } else {
            fprintf(stderr,"Error: invalid 'out' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"clr")){
        const char *pattern="^[[:space:]]*clr[[:space:]]+r([0-9]+)";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for clr\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,2,matches,0)){
            char regBuf[16];
            int len=matches[1].rm_eo - matches[1].rm_so;
            strncpy(regBuf,line+matches[1].rm_so,len);
            regBuf[len]='\0';
            int rD=(int)strtol(regBuf,NULL,0);
            fprintf(outStream,"xor r%d r%d r%d\n",rD,rD,rD);
        } else {
            fprintf(stderr,"Error: invalid 'clr' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    else if(!strcmp(op,"halt")){
        const char *pattern="^[[:space:]]*halt[[:space:]]*$";
        if(regcomp(&regex,pattern,REG_EXTENDED)!=0){
            fprintf(stderr,"Regex compile error for halt\n");
            abortAssembly();
        }
        if(!regexec(&regex,line,0,NULL,0)){
            fprintf(outStream,"priv r0 r0 r0 0\n");
        } else {
            fprintf(stderr,"Error: invalid 'halt' usage => %s\n",line);
            regfree(&regex);
            abortAssembly();
        }
        regfree(&regex);
    }
    else {
        fprintf(outStream, "%s\n", line);
    }
}

// ===================================================================
//             FinalAssemble: Merge Code & Data and Write Header
// ===================================================================

// Header structure as specified in the assignment
typedef struct {
    uint64_t file_type;       // Currently, 0
    uint64_t code_seg_begin;  // Address where code is to be loaded (0x2000)
    uint64_t code_seg_size;   // Size of the code segment in bytes
    uint64_t data_seg_begin;  // Address where data is to be loaded (0x10000)
    uint64_t data_seg_size;   // Size of the data segment in bytes (could be 0)
} tinker_file_header;

void finalAssemble(const char *infile, const char *outfile) {
    FILE *fin = fopen(infile,"r");
    if(!fin){
        perror("finalAssemble fopen");
        exit(1);
    }

    // Allocate dynamic buffers for code and data segments.
    size_t codeCapacity = 1024, codeCount = 0;
    uint32_t *codeBuffer = malloc(codeCapacity * sizeof(uint32_t));
    if(!codeBuffer){
        perror("malloc codeBuffer");
        fclose(fin);
        exit(1);
    }
    size_t dataCapacity = 1024, dataCount = 0;
    uint64_t *dataBuffer = malloc(dataCapacity * sizeof(uint64_t));
    if(!dataBuffer){
        perror("malloc dataBuffer");
        free(codeBuffer);
        fclose(fin);
        exit(1);
    }

    enum { CODE, DATA } currentSection = CODE;
    char line[1024];
    char assembled[128];

    while(fgets(line, sizeof(line), fin)){
        line[strcspn(line,"\n")]='\0';
        trim(line);
        if(line[0]=='\0' || line[0]==';')
            continue;
        if(strcmp(line,".code") == 0){
            currentSection = CODE;
            continue;
        }
        else if(strcmp(line,".data") == 0){
            currentSection = DATA;
            continue;
        }
        if(line[0]==':'){
            continue;
        }
        // Handle inline labels (e.g. "instr :label")
        char *col = strchr(line,':');
        if(col){
            char lab[50];
            if(sscanf(col+1,"%49s",lab)==1){
                LabelAddress *entry = findLabel(lab);
                if(!entry){
                    fprintf(stderr,"Error: label '%s' not found\n",lab);
                    fclose(fin);
                    free(codeBuffer);
                    free(dataBuffer);
                    abortAssembly();
                }
                *col = '\0';
                char temp[256];
                sprintf(temp, "%s0x%x", line, entry->address);
                strcpy(line, temp);
            }
        }

        if(currentSection == CODE){
            char token[16] = {0};
            sscanf(line,"%15s",token);

            if(!strcmp(token,"ld") ||
               !strcmp(token,"push") ||
               !strcmp(token,"pop")  ||
               !strcmp(token,"in")   ||
               !strcmp(token,"out")  ||
               !strcmp(token,"clr")  ||
               !strcmp(token,"halt"))
            {
                char macroExp[4096] = "";
                FILE *tempStream = fmemopen(macroExp, sizeof(macroExp), "w");
                if(!tempStream){
                    perror("fmemopen");
                    fclose(fin);
                    free(codeBuffer);
                    free(dataBuffer);
                    abortAssembly();
                }
                parseMacro(line, tempStream);
                fflush(tempStream);
                fclose(tempStream);
                char *exLine = strtok(macroExp,"\n");
                while(exLine){
                    trim(exLine);
                    if(exLine[0]){
                        assembleInstruction(exLine, assembled);
                        if(strcmp(assembled,"ERROR")==0){
                            fprintf(stderr,"Error assembling line: %s\n", exLine);
                            fclose(fin);
                            free(codeBuffer);
                            free(dataBuffer);
                            abortAssembly();
                        }
                        uint32_t w = binStrToUint32(assembled);
                        if(codeCount >= codeCapacity){
                            codeCapacity *= 2;
                            codeBuffer = realloc(codeBuffer, codeCapacity * sizeof(uint32_t));
                            if(!codeBuffer){
                                perror("realloc codeBuffer");
                                fclose(fin);
                                free(dataBuffer);
                                exit(1);
                            }
                        }
                        codeBuffer[codeCount++] = w;
                    }
                    exLine = strtok(NULL,"\n");
                }
            }
            else if(!strcmp(token,"mov")){
                assembleMov(line, assembled);
                if(strcmp(assembled,"ERROR")==0){
                    fprintf(stderr,"Error assembling line: %s\n", line);
                    fclose(fin);
                    free(codeBuffer);
                    free(dataBuffer);
                    abortAssembly();
                }
                uint32_t w = binStrToUint32(assembled);
                if(codeCount >= codeCapacity){
                    codeCapacity *= 2;
                    codeBuffer = realloc(codeBuffer, codeCapacity * sizeof(uint32_t));
                    if(!codeBuffer){
                        perror("realloc codeBuffer");
                        fclose(fin);
                        free(dataBuffer);
                        exit(1);
                    }
                }
                codeBuffer[codeCount++] = w;
            }
            else if(!strcmp(token,"brr")){
                const char *p = line+3;
                while(isspace((unsigned char)*p)) p++;
                assembleBrrOperand(p, assembled);
                if(strcmp(assembled,"ERROR")==0){
                    fprintf(stderr,"Error assembling line: %s\n", line);
                    fclose(fin);
                    free(codeBuffer);
                    free(dataBuffer);
                    abortAssembly();
                }
                uint32_t w = binStrToUint32(assembled);
                if(codeCount >= codeCapacity){
                    codeCapacity *= 2;
                    codeBuffer = realloc(codeBuffer, codeCapacity * sizeof(uint32_t));
                    if(!codeBuffer){
                        perror("realloc codeBuffer");
                        fclose(fin);
                        free(dataBuffer);
                        exit(1);
                    }
                }
                codeBuffer[codeCount++] = w;
            }
            else if (!strcmp(token, "return")) {
                // Explicitly handle the "return" instruction using your dedicated function.
                assembleReturn(assembled);
                uint32_t w = binStrToUint32(assembled);
                if (codeCount >= codeCapacity) {
                    codeCapacity *= 2;
                    codeBuffer = realloc(codeBuffer, codeCapacity * sizeof(uint32_t));
                    if (!codeBuffer) {
                        perror("realloc codeBuffer");
                        fclose(fin);
                        free(dataBuffer);
                        exit(1);
                    }
                }
                codeBuffer[codeCount++] = w;
            }
            else {
                assembleStandard(line, assembled);
                if(strcmp(assembled,"ERROR")==0){
                    fprintf(stderr,"Error assembling line: %s\n", line);
                    fclose(fin);
                    free(codeBuffer);
                    free(dataBuffer);
                    abortAssembly();
                }
                uint32_t w = binStrToUint32(assembled);
                if(codeCount >= codeCapacity){
                    codeCapacity *= 2;
                    codeBuffer = realloc(codeBuffer, codeCapacity * sizeof(uint32_t));
                    if(!codeBuffer){
                        perror("realloc codeBuffer");
                        fclose(fin);
                        free(dataBuffer);
                        exit(1);
                    }
                }
                codeBuffer[codeCount++] = w;
            }
        }
        else if(currentSection == DATA){
            if(line[0]=='-'){
                fprintf(stderr,"Error: Invalid data: %s\n", line);
                fclose(fin);
                free(codeBuffer);
                free(dataBuffer);
                abortAssembly();
            }
            errno = 0;
            char *endptr = NULL;
            uint64_t val = strtoull(line, &endptr, 0);
            if(errno == ERANGE){
                fprintf(stderr,"Error: Invalid data: %s\n", line);
                fclose(fin);
                free(codeBuffer);
                free(dataBuffer);
                abortAssembly();
            }
            while(endptr && isspace((unsigned char)*endptr)) endptr++;
            if(!endptr || *endptr!='\0'){
                fprintf(stderr,"Error: Invalid data: %s\n", line);
                fclose(fin);
                free(codeBuffer);
                free(dataBuffer);
                abortAssembly();
            }
            if(dataCount >= dataCapacity){
                dataCapacity *= 2;
                dataBuffer = realloc(dataBuffer, dataCapacity * sizeof(uint64_t));
                if(!dataBuffer){
                    perror("realloc dataBuffer");
                    fclose(fin);
                    free(codeBuffer);
                    exit(1);
                }
            }
            dataBuffer[dataCount++] = val;
        }
    }
    fclose(fin);

    uint32_t codeSegSize = codeCount * sizeof(uint32_t);
    uint32_t dataSegSize = dataCount * sizeof(uint64_t);

    // Prepare header with the fixed segment start addresses.
    tinker_file_header header;
    header.file_type = 0;
    header.code_seg_begin = 0x2000;
    header.code_seg_size = codeSegSize;
    header.data_seg_begin = 0x10000;
    header.data_seg_size = dataSegSize;

    strncpy(g_outFilename, outfile, sizeof(g_outFilename)-1);
    g_outFilename[sizeof(g_outFilename)-1] = '\0';
    g_fout = fopen(outfile, "wb");
    if(!g_fout){
        perror("finalAssemble output fopen");
        free(codeBuffer);
        free(dataBuffer);
        exit(1);
    }
    fwrite(&header, sizeof(header), 1, g_fout);
    if(codeSegSize > 0)
        fwrite(codeBuffer, codeSegSize, 1, g_fout);
    if(dataSegSize > 0)
        fwrite(dataBuffer, dataSegSize, 1, g_fout);
    fclose(g_fout);
    g_fout = NULL;
    free(codeBuffer);
    free(dataBuffer);
}

// ===================================================================
//                              main
// ===================================================================
int main(int argc, char *argv[]){
    if(argc != 3){
        fprintf(stderr,"Usage: %s <assembly_file> <output_file>\n", argv[0]);
        return 1;
    }
    pass1(argv[1]);
    populateInstMap();
    finalAssemble(argv[1], argv[2]);
    freeInstMap();
    freeLabelMap();
    return 0;
}