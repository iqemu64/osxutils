
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define SWAP_INT(a) (((a) << 24) | \
                    (((a) << 8) & 0x00ff0000) | \
                    (((a) >> 8) & 0x0000ff00) | \
                    ((unsigned int)(a) >> 24))

char *progname = NULL;

static void
usage()
{
    fprintf(stderr, "Usage: %s -i input -v version [-o output]\n",
            progname);
    exit(EXIT_FAILURE);
}

static void
error(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    fprintf(stderr, "error: %s: ", progname);
    vfprintf(stderr, format, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}


static int
process_single_macho(char *addr, uint64_t size, uint32_t version)
{
    uint32_t magic = 0;
    uint32_t header_sz = 0;
    
    if(size >= sizeof(uint32_t)) {
        magic = *((uint32_t *)addr);
    }
    
    if((magic == MH_MAGIC || magic == MH_CIGAM) && size >= sizeof(struct mach_header)) {
        header_sz = sizeof(struct mach_header);
    } else if((magic == MH_MAGIC_64 || magic == MH_CIGAM_64) && size >= sizeof(struct mach_header_64)) {
        header_sz = sizeof(struct mach_header_64);
    } else {
        error("malformed object file");
        return -1;
    }
    
    uint32_t ncmds = ((struct mach_header *)addr)->ncmds;
    addr += header_sz;
    while(ncmds --) {
        struct load_command *lc = (struct load_command *)addr;
        addr += lc->cmdsize;
        if(lc->cmd == LC_VERSION_MIN_MACOSX) {
            lc->cmd = LC_VERSION_MIN_IPHONEOS;
            ((struct version_min_command *)lc)->version = version;
            ((struct version_min_command *)lc)->sdk = version;
        } else if(lc->cmd == LC_BUILD_VERSION) {
            ((struct build_version_command *)lc)->platform = PLATFORM_IOSSIMULATOR;
            ((struct build_version_command *)lc)->minos = version;
            ((struct build_version_command *)lc)->sdk = version;
        } else if(lc->cmd == LC_LOAD_DYLIB) {
            const int replace_list_size = 3;
            static const char *replace_list[] =
            {
                "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices",
                "/System/Library/Frameworks/CoreServices.framework/CoreServices",
                "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
                "/System/Library/Frameworks/Foundation.framework/Foundation"
            };
            struct dylib_command *dc = (struct dylib_command *)lc;
            char *dylib_name = ((char *)dc) + dc->dylib.name.offset;
            for(int i = 0; i < replace_list_size; i ++) {
                if(!strcmp(dylib_name, replace_list[i * 2])) {
                    strcpy(dylib_name, replace_list[i * 2 + 1]);
                }
            }
        }
    }
    return 0;
}

static int
load_ofile(const char *input, const char *output, uint32_t version)
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
                                          version)) {
                munmap(addr, size);
                return -1;
            }
        }
    } else {
        if(-1 == process_single_macho(addr, size, version)) {
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

int main(int argc, char * argv[]) {
    progname = argv[0];
    
    uint32_t i;
    char *input = NULL;
    uint32_t version = 0;
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
        } else if(!strcmp(argv[i], "-v")) {
            if(i + 1 == argc) {
                error("missing argument to: %s option", argv[i]);
                usage();
            }
            if(version != 0) {
                error("more than one: %s option specified", argv[i]);
                usage();
            }
            if(1 != sscanf(argv[i + 1], "%x", &version)) {
                error("please specify a number in %s option", argv[i]);
                usage();
            }
            i ++;
        } else {
            error("unknown flag: %s", argv[i]);
            usage();
        }
    }
    
    if(input == NULL || version == 0)
        usage();
    
    if(output == NULL)
        output = input;
    
    load_ofile(input, output, version);
    
    return 0;
}
