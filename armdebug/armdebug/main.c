
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>

#define ARM_THREAD_STATE    1
#define ARM_THREAD_STATE64  6

struct arm_thread_state
{
    __uint32_t  r[13];
    __uint32_t  sp;
    __uint32_t  lr;
    __uint32_t  pc;
    __uint32_t  cpsr;
};

struct arm_thread_state64
{
    __uint64_t  x[29];
    __uint64_t  fp;
    __uint64_t  lr;
    __uint64_t  sp;
    __uint64_t  pc;
    __uint32_t  cpsr;
};

#define BINARY_TYPE_CONSOLE     0
#define BINARY_TYPE_APP         1
#define BINARY_TYPE_ALL         2

#define MH_EMULATOR                0x10000000

#define SWAP_INT(a) (((a) << 24) | \
                    (((a) << 8) & 0x00ff0000) | \
                    (((a) >> 8) & 0x0000ff00) | \
                    ((unsigned int)(a) >> 24))

char *progname = NULL;

static uint binary_type = -1;

static void usage(void);
static void error(const char *format, ...);
static int load_ofile(const char *input, const char *output);
static int process_single_macho(char *addr, uint64_t size);
static int process_single_macho32(char *addr, uint64_t size);
static int process_single_macho64(char *addr, uint64_t size);
static void fix_sections(struct section *sc, int count, bool bit64);
static int fix_unixthread(struct thread_command *tc, bool bit64);


int main(int argc, char **argv) {
    progname = argv[0];
    
    uint32_t i;
    char *input = NULL;
    char *output = NULL;
    
    for(i = 1; i < argc; i ++) {
        if(!strcmp(argv[i], "-i")) {
            if(i + 1 == argc) {
                error("missing argument to: %s option", argv[i]);
                usage();
            }
            if(input != NULL) {
                error("error than one: %s option specified", argv[i]);
                usage();
            }
            input = argv[i + 1];
            i ++;
        } else if(!strcmp(argv[i], "-o")) {
            if(i + 1 == argc) {
                error("missing argument to: %s option", argv[i]);
                usage();
            }
            if(output != NULL) {
                error("more than one: %s option specified", argv[i]);
                usage();
            }
            output = argv[i + 1];
            i ++;
        } else if(!strcmp(argv[i], "-t")) {
            if(i + 1 == argc) {
                error("missing argument to: %s option", argv[i]);
                usage();
            }
            if(1 != sscanf(argv[i + 1], "%u", &binary_type)) {
                error("option %s must be a number", argv[i]);
                usage();
            }
            
            if(binary_type >= BINARY_TYPE_ALL) {
                error("invalid option %s", argv[i]);
                usage();
            }
            
            i ++;
        } else {
            error("unknown flag: %s", argv[i]);
            usage();
        }
    }
    
    if(input == NULL || output == NULL || binary_type == -1)
        usage();
    
    
    load_ofile(input, output);
    
    return 0;
}

static
void
usage(void)
{
    fprintf(stderr, "Usage: %s -i input -t type -o output\n",
            progname);
    exit(EXIT_FAILURE);
}

static void error(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    fprintf(stderr, "error: %s: ", progname);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}


static int load_ofile(const char *input, const char *output)
{
    int fd;
    struct stat stat_buf;
    uint64_t size;
    uint32_t magic = 0;
    char *addr = NULL;
    
    if((fd = open(input, O_RDONLY)) == -1) {
        error("can't open file: %s", input);
        return -1;
    }
    if(fstat(fd, &stat_buf) == -1) {
        close(fd);
        error("can't stat file: %s", input);
        return -1;
    }
    
    size = stat_buf.st_size;
    if(size != 0) {
        addr = mmap(0, size, PROT_READ | PROT_WRITE, MAP_FILE | MAP_PRIVATE, fd, 0);
        if((intptr_t)addr == -1) {
            error("can't map file: %s", input);
            close(fd);
            return -1;
        }
    }
    
    close(fd);
    
    
    if(size >= sizeof(uint32_t)) {
        magic = *((uint32_t *)addr);
    }
    if((magic == FAT_MAGIC || magic == FAT_CIGAM) && size >= sizeof(struct fat_header)) {
        // it's a fat one. split it.
        struct fat_header *fat_header = (struct fat_header *)addr;
        uint32_t nfat_arch = SWAP_INT(fat_header->nfat_arch);
        
        if(size < sizeof(struct fat_header) +  nfat_arch * sizeof(struct fat_arch)) {
            error("malformed object file: %s", input);
            munmap(addr, size);
            return -1;
        }
        
        //uint64_t useful_size = size - sizeof(struct fat_header) - nfat_arch * sizeof(struct fat_arch);
        //char *useful_addr = addr + sizeof(struct fat_header) + nfat_arch * sizeof(struct fat_arch);
        
        for(uint32_t i = 0; i < nfat_arch; i ++) {
            struct fat_arch *fat_arch =
                (struct fat_arch *)(addr + sizeof(struct fat_header) + i * sizeof(struct fat_arch));
            if(size < SWAP_INT(fat_arch->offset) + SWAP_INT(fat_arch->size)) {
                error("malformed object file: %s", input);
                munmap(addr, size);
                return -1;
            }
            
            cpu_type_t archtype = OSSwapBigToHostInt32(fat_arch->cputype);
            cpu_type_t archsubtype = OSSwapBigToHostInt32(fat_arch->cpusubtype) & ~CPU_SUBTYPE_MASK;
            
            if(archtype == CPU_TYPE_ARM) {
                fat_arch->cputype       = OSSwapHostToBigInt32(CPU_TYPE_X86);
                fat_arch->cpusubtype    = OSSwapHostToBigInt32(CPU_SUBTYPE_X86_ALL |
                                                               (archsubtype & CPU_SUBTYPE_MASK));
                
            } else if(archtype == CPU_TYPE_ARM64) {
                fat_arch->cputype       = OSSwapHostToBigInt32(CPU_TYPE_X86_64);
                fat_arch->cpusubtype    = OSSwapHostToBigInt32(CPU_SUBTYPE_X86_64_ALL |
                                                               (archsubtype & CPU_SUBTYPE_MASK));
            }
            
            if(-1 == process_single_macho(addr + SWAP_INT(fat_arch->offset), SWAP_INT(fat_arch->size))) {
                munmap(addr, size);
                return -1;
            }
        }
    } else {
        if(-1 == process_single_macho(addr, size)) {
            munmap(addr, size);
            return -1;
        }
    }
    
    fd = open(output, O_RDWR | O_CREAT, 0755);
    if(-1 == fd) {
        error("cannot open output file: %s", output);
        return -1;
    }
    
    if(-1 == write(fd, addr, size)) {
        error("cannot write file: %s", output);
        close(fd);
        return -1;
    }
    close(fd);
    
    munmap(addr, size);
    return 0;
}

static int
process_single_macho(char *addr, uint64_t size)
{
    uint32_t magic = 0;
    
    if(size >= sizeof(uint32_t)) {
        magic = *((uint32_t *)addr);
    }
    if((magic == MH_MAGIC || magic == MH_CIGAM) && size >= sizeof(struct mach_header)) {
        return process_single_macho32(addr, size);
    } else if((magic == MH_MAGIC_64 || magic == MH_CIGAM_64) && size >= sizeof(struct mach_header_64)) {
        return process_single_macho64(addr, size);
    }
    error("malformed object file");
    return -1;
}

static int
process_single_macho32(char *addr, uint64_t size)
{
    struct mach_header *mach_header = (struct mach_header *)addr;
    uint32_t ncmds = mach_header->ncmds;
    off_t offset;
    size_t cmdsize;
    struct load_command *lcp;
    struct segment_command *scp;
    
    // The last size check. The following code will not be checking
    // sizes again. Maybe a TODO?
    if(size < sizeof(struct mach_header) + mach_header->sizeofcmds) {
        error("malformed object file");
        return -1;
    }
    
    if(mach_header->cputype == CPU_TYPE_ARM) {
        mach_header->cputype    = CPU_TYPE_X86;
        mach_header->cpusubtype = CPU_SUBTYPE_X86_ALL |
            (mach_header->cpusubtype & CPU_SUBTYPE_MASK);
    }
    
    mach_header->flags |= MH_NO_HEAP_EXECUTION;
    mach_header->flags &= (~MH_PIE);
    if(BINARY_TYPE_APP == binary_type)
        mach_header->flags |= MH_EMULATOR;
    
    
    cmdsize = mach_header->sizeofcmds;
    offset = sizeof(struct mach_header);
    size_t hole = 0;
    
    while(ncmds --) {
        lcp = (struct load_command *)((uint8_t *)mach_header + offset);
        offset += lcp->cmdsize;
        switch(lcp->cmd) {
            case LC_SEGMENT:
                
                scp = (struct segment_command *)lcp;
                if(!strcmp(scp->segname, "__TEXT")) {
                    scp->maxprot |= VM_PROT_WRITE;
                }
                
                fix_sections((struct section *)((char *)lcp + sizeof(struct segment_command)),
                            (lcp->cmdsize - sizeof(struct segment_command)) / sizeof(struct section),
                             false);
                if(!strcmp(scp->segname, "__RESTRICT")) {
                    scp->segname[0] = scp->segname[1] = 'x';
                }
                break;
            case LC_UNIXTHREAD: {
                int l_hole = fix_unixthread((struct thread_command *)lcp, false);
                if(0 == l_hole) {
                    error("fix_unixthread fails");
                    return false;
                }
                hole = l_hole;
                break;
            }
            case LC_CODE_SIGNATURE:
                mach_header->ncmds --;
                hole = lcp->cmdsize;
                break;
            default:
                break;
        }
        if(hole) {
            offset -= hole;
            mach_header->sizeofcmds -= hole;
            cmdsize = mach_header->sizeofcmds;
            
            if(!(cmdsize - offset)) {
                break;
            }
            
            /* there requested a hole, fill it in */
            memmove((void *)      ((uint8_t *)mach_header + offset),
                    (const void *)((uint8_t *)mach_header + offset + hole),
                    cmdsize - offset + sizeof(struct mach_header));
            hole = 0;
        }
    }
    return 0;
}

static int
process_single_macho64(char *addr, uint64_t size)
{
    struct mach_header_64 *mach_header = (struct mach_header_64 *)addr;
    uint32_t ncmds = mach_header->ncmds;
    off_t offset;
    size_t cmdsize;
    struct load_command *lcp;
    struct segment_command_64 *scp;
    
    // The last size check. The following code will not be checking
    // sizes again. Maybe a TODO?
    if(size < sizeof(struct mach_header_64) + mach_header->sizeofcmds) {
        error("malformed object file");
        return -1;
    }
    
    if(mach_header->cputype == CPU_TYPE_ARM64) {
        mach_header->cputype    = CPU_TYPE_X86_64;
        mach_header->cpusubtype = CPU_SUBTYPE_X86_64_ALL |
        (mach_header->cpusubtype & CPU_SUBTYPE_MASK);
    }
    
    mach_header->flags |= MH_NO_HEAP_EXECUTION;
    if(BINARY_TYPE_APP == binary_type)
        mach_header->flags |= MH_EMULATOR;
    
    
    cmdsize = mach_header->sizeofcmds;
    offset = sizeof(struct mach_header_64);
    size_t hole = 0;
    
    while(ncmds --) {
        lcp = (struct load_command *)((uint8_t *)mach_header + offset);
        offset += lcp->cmdsize;
        switch(lcp->cmd) {
            case LC_SEGMENT_64:
                
                scp = (struct segment_command_64 *)lcp;
                if(!strcmp(scp->segname, "__TEXT")) {
                    scp->maxprot |= VM_PROT_WRITE;
                }
                
                fix_sections((struct section *)((char *)lcp + sizeof(struct segment_command_64)),
                             (lcp->cmdsize - sizeof(struct segment_command_64)) / sizeof(struct section_64),
                             true);
                break;
            case LC_UNIXTHREAD: {
                int l_hole = fix_unixthread((struct thread_command *)lcp, true);
                if(0 == l_hole) {
                    error("fix_unixthread fails");
                    return false;
                }
                hole = l_hole;
                break;
            }
            case LC_CODE_SIGNATURE:
                mach_header->ncmds --;
                hole = lcp->cmdsize;
                break;
            default:
                break;
        }
        if(hole) {
            offset -= hole;
            mach_header->sizeofcmds -= hole;
            cmdsize = mach_header->sizeofcmds;
            
            if(!(cmdsize - offset)) {
                break;
            }
            
            /* there requested a hole, fill it in */
            memmove((void *)      ((uint8_t *)mach_header + offset),
                    (const void *)((uint8_t *)mach_header + offset + hole),
                    cmdsize - offset + sizeof(struct mach_header_64));
            hole = 0;
        }
    }
    return 0;
}

static void
fix_sections(struct section *sc, int count, bool bit64)
{
    /*
     * a __dyld section could cause entry point of main binary
     * executed before initialization routine of iqemu. change
     * it to an other name, then our lib will link this section
     * for it. This section is unlikely to be seen in
     * nowadays binaries.
     */
    char *sectname;
    
    for(int i = 0; i < count; i ++) {
        if(bit64) {
            sectname = ((struct section_64 *)sc)->sectname;
            sc = (struct section *)(((char *)sc) + sizeof(struct section_64));
        } else {
            sectname = sc->sectname;
            sc ++;
        }
        if(!strcmp(sectname, "__dyld"))
            strlcpy(sectname, "smdyld", sizeof(sc->sectname));
    }
}

static int
fix_unixthread(struct thread_command *tc, bool bit64)
{
    if(bit64)
        return 0;   /* never seen a 64bit unixthread. maybe they don't exist at all? */
    
    x86_thread_state32_t *x8632;
    struct arm_thread_state *arm32;
    uint32_t *ts = (uint32_t *)((char *)tc + sizeof(struct thread_command));
    int total_size = tc->cmdsize - sizeof(struct thread_command);
    int hole = 0;
    
    while(total_size > 0) {
        int flavor = *ts++;
        uint32_t size = *ts++;
        
        if(ARM_THREAD_STATE != flavor) {
            error("flavour should be %d not %d", ARM_THREAD_STATE, flavor);
            return 0;
        }
        if(size != sizeof(struct arm_thread_state) / sizeof(uint32_t)) {
            error("size should be %d not %d", 17, size);
            return 0;
        }
        
        arm32 = (struct arm_thread_state *)malloc(size * sizeof(uint32_t));
        memcpy(arm32, ts, size * sizeof(uint32_t));
        x8632 = (x86_thread_state32_t *)ts;
        memset(x8632, 0, sizeof(x86_thread_state32_t));
        
        x8632->__eip = arm32->pc;
        x8632->__esp = arm32->sp;
        
        *(ts - 2) = x86_THREAD_STATE32;
        *(ts - 1) = sizeof(x86_thread_state32_t) / sizeof(uint32_t);
        tc->cmdsize -= 4;
        
        free(arm32);
        
        hole += 4;
        ts += size;
        total_size -= (size + 2) * sizeof(uint32_t);
        
        if(total_size > 0) {
            memcpy(ts - 1, ts, total_size);
            total_size -= 4;
            ts --;
        }
    }
    
    
    return hole;
}

