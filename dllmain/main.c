
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

#define SWAP_INT(a) (((a) << 24) | \
                    (((a) << 8) & 0x00ff0000) | \
                    (((a) >> 8) & 0x0000ff00) | \
       ((unsigned int)(a) >> 24))

char *progname = NULL;


static void usage(void);
static void error(const char *format, ...);
static int load_ofile(const char *input, const char *output, const char *last_func_name, const char *first_func_name);
static int process_single_macho(char *addr, uint64_t size, const char *last_func_name, const char *first_func_name);
static int process_single_macho32(char *addr, uint64_t size, const char *last_func_name, const char *first_func_name);
static int process_single_macho64(char *addr, uint64_t size, const char *last_func_name, const char *first_func_name);
static uint32_t lookup_for_symbol32(char *base_addr, struct symtab_command *sm, const char *target_func_name);
static uint64_t lookup_for_symbol64(char *base_addr, struct symtab_command *sm, const char *target_func_name);
static int rebase_init_funcs32(char *base_addr, struct section *sec, uint32_t last, uint32_t first);
static int rebase_init_funcs64(char *base_addr, struct section_64 *sec, uint64_t last, uint64_t first);

int main(int argc, char **argv) {
    progname = argv[0];
    
    uint32_t i;
    char *input = NULL;
    char *last_target_func = NULL;
    char *first_target_func = NULL;
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
            if(last_target_func != NULL) {
                error("more than one %s option specified", argv[i]);
                usage();
            }
            last_target_func = argv[i + 1];
            i ++;
        } else if(!strcmp(argv[i], "-f")) {
            if(i + 1 == argc) {
                error("missing argument to: %s option", argv[i]);
                usage();
            }
            if(first_target_func != NULL) {
                error("more than one %s option specified", argv[i]);
                usage();
            }
            first_target_func = argv[i + 1];
            i ++;
        } else {
            error("unknown flag: %s", argv[i]);
            usage();
        }
    }
    
    if(input == NULL || (last_target_func == NULL && first_target_func == NULL))
        usage();
    
    if(output == NULL)
        output = input;
    
    load_ofile(input, output, last_target_func, first_target_func);
    
    return 0;
}

static
void
usage(void)
{
    fprintf(stderr, "Usage: %s -i input -t last_function_name -f first_function_name [-o output]\n",
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


static int load_ofile(const char *input, const char *output, const char *last_func_name, const char *first_func_name)
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
            if(-1 == process_single_macho(addr + SWAP_INT(fat_arch->offset),
                                          SWAP_INT(fat_arch->size),
                                          last_func_name, first_func_name)) {
                munmap(addr, size);
                return -1;
            }
        }
    } else {
        if(-1 == process_single_macho(addr, size, last_func_name, first_func_name)) {
            munmap(addr, size);
            return -1;
        }
    }

    fd = open(output, O_RDWR);
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
process_single_macho(char *addr, uint64_t size, const char *last_func_name, const char *first_func_name)
{
    uint32_t magic = 0;
    
    if(size >= sizeof(uint32_t)) {
        magic = *((uint32_t *)addr);
    }
    if((magic == MH_MAGIC || magic == MH_CIGAM) && size >= sizeof(struct mach_header)) {
        return process_single_macho32(addr, size, last_func_name, first_func_name);
    } else if((magic == MH_MAGIC_64 || magic == MH_CIGAM_64) && size >= sizeof(struct mach_header_64)) {
        return process_single_macho64(addr, size, last_func_name, first_func_name);
    }
    error("malformed object file");
    return -1;
}

static int
process_single_macho32(char *addr, uint64_t size, const char *last_func_name, const char *first_func_name)
{
    struct mach_header *mach_header = (struct mach_header *)addr;
    uint32_t ncmds = mach_header->ncmds;
    uint32_t last_func_offset = 0;
    uint32_t first_func_offset = 0;
    
    // The last size check. The following code will not be checking
    // sizes again. Maybe a TODO?
    if(size < sizeof(struct mach_header) + mach_header->sizeofcmds) {
        error("malformed object file");
        return -1;
    }
    
    //
    // Multiple passes. The first pass is to looking for symbol table
    // and locate the target function. The second pass is to locating
    // the __mod_init_func section.
    
    for(int pass = 1; pass <= 2; pass ++) {
        
        char *cur_addr = addr + sizeof(struct mach_header);
        for(uint32_t i = 0; i < ncmds; i ++) {
            struct load_command *lc = (struct load_command *)cur_addr;
            switch(lc->cmd) {
                case LC_SEGMENT:
                {
                    if(pass != 2)
                        break;
                    if(0 == last_func_offset && last_func_name) {
                        error("cannot find symbol %s", last_func_name);
                        return -1;
                    }
                    if(0 == first_func_offset && first_func_name) {
                        error("cannot find symbol %s", first_func_name);
                        return -1;
                    }
                    
                    struct segment_command *sg = (struct segment_command *)lc;
                    if(!strcmp(sg->segname, "__DATA_CONST") ||
                       !strcmp(sg->segname, "__DATA")) {
                        struct section *sec =
                        (struct section *)(cur_addr +
                                           i * sizeof(struct segment_command));
                        for(uint32_t j = 0; j < sg->nsects; j ++) {
                            
                            if(!strcmp(sec[j].sectname, "__mod_init_func")) {
                                if(-1 == rebase_init_funcs32(addr, &sec[j], last_func_offset, first_func_offset)) {
                                    error("cannot rebase symbols");
                                    return -1;
                                }
                                
                                return 0;
                                
                            }
                        }
                    }
                    break;
                }
                case LC_SYMTAB:
                {
                    if(pass != 1)
                        break;
                    struct symtab_command *sm = (struct symtab_command *)lc;
                    if(last_func_name)
                        last_func_offset = lookup_for_symbol32(addr, sm, last_func_name);
                    if(first_func_name)
                        first_func_offset = lookup_for_symbol32(addr, sm, first_func_name);
                    break;
                }
                default:
                    break;
            }
            cur_addr += lc->cmdsize;
        }
    }
    return 0;
}

static int
process_single_macho64(char *addr, uint64_t size, const char *last_func_name, const char *first_func_name)
{
    struct mach_header_64 *mach_header = (struct mach_header_64 *)addr;
    uint32_t ncmds = mach_header->ncmds;
    uint64_t last_func_offset = 0;
    uint64_t first_func_offset = 0;
    
    // The last size check. The following code will not be checking
    // sizes again. Maybe a TODO?
    if(size < sizeof(struct mach_header_64) + mach_header->sizeofcmds) {
        error("malformed object file");
        return -1;
    }
    
    //
    // Multiple passes. The first pass is to looking for symbol table
    // and locate the target function. The second pass is to locating
    // the __mod_init_func section.
    
    for(int pass = 1; pass <= 2; pass ++) {
        
        char *cur_addr = addr + sizeof(struct mach_header_64);
        for(uint32_t i = 0; i < ncmds; i ++) {
            struct load_command *lc = (struct load_command *)cur_addr;
            switch(lc->cmd) {
                case LC_SEGMENT_64:
                {
                    if(pass != 2)
                        break;
                    if(0 == last_func_offset && last_func_name) {
                        error("cannot find symbol %s", last_func_name);
                        return -1;
                    }
                    if(0 == first_func_offset && first_func_name) {
                        error("cannot find symbol %s", first_func_name);
                        return -1;
                    }
                    
                    struct segment_command_64 *sg = (struct segment_command_64 *)lc;
                    if(!strcmp(sg->segname, "__DATA_CONST") ||
                       !strcmp(sg->segname, "__DATA")) {
                        struct section_64 *sec =
                            (struct section_64 *)(cur_addr +
                                                  i * sizeof(struct segment_command_64));
                        for(uint32_t j = 0; j < sg->nsects; j ++) {
                            
                            if(!strcmp(sec[j].sectname, "__mod_init_func")) {
                                if(-1 == rebase_init_funcs64(addr, &sec[j], last_func_offset, first_func_offset)) {
                                    error("cannot rebase symbols");
                                    return -1;
                                }
                                
                                return 0;
                                
                            }
                        }
                    }
                    break;
                }
                case LC_SYMTAB:
                {
                    if(pass != 1)
                        break;
                    struct symtab_command *sm = (struct symtab_command *)lc;
                    if(last_func_name)
                        last_func_offset = lookup_for_symbol64(addr, sm, last_func_name);
                    if(first_func_name)
                        first_func_offset = lookup_for_symbol64(addr, sm, first_func_name);
                    
                    break;
                }
                default:
                    break;
            }
            cur_addr += lc->cmdsize;
        }
    }
    return 0;
}

static uint32_t
lookup_for_symbol32(char *base_addr, struct symtab_command *sm, const char *target_func_name)
{
    char *strtab = base_addr + sm->stroff;
    uint32_t strsize = sm->strsize;
    char *symtab = base_addr + sm->symoff;
    uint32_t nsyms = sm->nsyms;
    
    struct nlist *nlist = (struct nlist *)symtab;
    for(uint32_t i = 0; i < nsyms; i ++) {
        if(nlist[i].n_un.n_strx >= strsize) {
            return 0;
        }
        if(!strcmp(nlist[i].n_un.n_strx + strtab, target_func_name)) {
            return nlist[i].n_value;
        }
    }
    
    return 0;
}

static uint64_t
lookup_for_symbol64(char *base_addr, struct symtab_command *sm, const char *target_func_name)
{
    char *strtab = base_addr + sm->stroff;
    uint32_t strsize = sm->strsize;
    char *symtab = base_addr + sm->symoff;
    uint32_t nsyms = sm->nsyms;
    
    struct nlist_64 *nlist = (struct nlist_64 *)symtab;
    for(uint32_t i = 0; i < nsyms; i ++) {
        if(nlist[i].n_un.n_strx >= strsize) {
            return 0;
        }
        if(!strcmp(nlist[i].n_un.n_strx + strtab, target_func_name)) {
            return nlist[i].n_value;
        }
    }
    
    return 0;
}

static int
rebase_init_funcs32(char *base_addr, struct section *sec, uint32_t last, uint32_t first)
{
    uint32_t *offsets = (uint32_t *)(base_addr + sec->offset);
    uint32_t size = sec->size >> 2;
    uint32_t target_i = (uint32_t)-1;
    uint32_t i;
    
    // first process last
    if(last) {
        for(i = 0; i < size; i ++) {
            if(offsets[i] == last) {
                target_i = i;
                break;
            }
        }
        if((uint32_t)-1 == target_i) {
            error("function last not found in init func list.");
            return -1;
        }
        
        for(i = target_i; i < size - 1; i ++) {
            offsets[i] = offsets[i + 1];
        }
        offsets[size - 1] = last;
    }
    
    // then first
    if(first) {
        target_i = (uint32_t)-1;
        for(i = 0; i < size; i ++) {
            if(offsets[i] == first) {
                target_i = i;
                break;
            }
        }
        if((uint32_t)-1 == target_i) {
            error("function first not found in init func list.");
            return -1;
        }
        for(i = target_i; i > 0; i --) {
            offsets[i] = offsets[i - 1];
        }
        offsets[0] = first;
    }
    
    return 0;
}

static int
rebase_init_funcs64(char *base_addr, struct section_64 *sec, uint64_t last, uint64_t first)
{
    uint64_t *offsets = (uint64_t *)(base_addr + sec->offset);
    uint64_t size = sec->size >> 3;
    uint32_t target_i = (uint32_t)-1;
    uint32_t i;
    
    // first process last
    if(last) {
        for(i = 0; i < size; i ++) {
            if(offsets[i] == last) {
                target_i = i;
                break;
            }
        }
        if((uint32_t)-1 == target_i) {
            error("function not found in init func list.");
            return -1;
        }
        
        for(i = target_i; i < size - 1; i ++) {
            offsets[i] = offsets[i + 1];
        }
        offsets[size - 1] = last;
    }
    
    // then first
    if(first) {
        target_i = (uint32_t)-1;
        for(i = 0; i < size; i ++) {
            if(offsets[i] == first) {
                target_i = i;
                break;
            }
        }
        if((uint32_t)-1 == target_i) {
            error("function first not found in init func list.");
            return -1;
        }
        for(i = target_i; i > 0; i --) {
            offsets[i] = offsets[i - 1];
        }
        offsets[0] = first;
    }
    
    return 0;
}

