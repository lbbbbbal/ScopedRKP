#pragma once
// Local-file ELF metadata and exact inode/device mapping identity. No target calls.
#include <atomic>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <memory>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <vector>

struct SrkpOwnedElf {
    struct Symbol { uintptr_t value; size_t size; };
    struct Mapping { bool scanned=false, conflict=false; uintptr_t base=0; };
    std::vector<unsigned char> bytes;
    struct stat identity{};
    Elf64_Ehdr header{};
    std::string basename;
    bool valid=false;
    template<class T> const T *at(uint64_t offset,size_t count=1) const {
        if(count>bytes.size()/sizeof(T) || offset>bytes.size()-count*sizeof(T) || offset%alignof(T)) return nullptr;
        return reinterpret_cast<const T *>(bytes.data()+offset);
    }
    explicit SrkpOwnedElf(const char *path) {
        const char *name=strrchr(path,'/'); basename=name?name+1:path;
        std::unique_ptr<FILE,decltype(&fclose)> f(fopen(path,"re"),fclose);
        if(!f || fstat(fileno(f.get()),&identity) || identity.st_size<ssize_t(sizeof(header)) || identity.st_size>32*1024*1024) return;
        bytes.resize(identity.st_size);
        if(fread(bytes.data(),1,bytes.size(),f.get())!=bytes.size()) return;
        memcpy(&header,bytes.data(),sizeof(header));
        if(memcmp(header.e_ident,ELFMAG,SELFMAG) || header.e_ident[EI_CLASS]!=ELFCLASS64 || header.e_ident[EI_DATA]!=ELFDATA2LSB
          || header.e_machine!=EM_AARCH64 || header.e_type!=ET_DYN || header.e_shentsize!=sizeof(Elf64_Shdr)
          || header.e_phentsize!=sizeof(Elf64_Phdr) || !header.e_shnum || header.e_shnum>4096 || !header.e_phnum || header.e_phnum>128
          || !at<Elf64_Shdr>(header.e_shoff,header.e_shnum) || !at<Elf64_Phdr>(header.e_phoff,header.e_phnum)) return;
        valid=true;
    }
    bool in_load(uintptr_t va,size_t size,unsigned flags) const {
        const auto *ph=at<Elf64_Phdr>(header.e_phoff,header.e_phnum);
        if(!ph) return false;
        for(unsigned i=0;i<header.e_phnum;i++) {
            const auto &p=ph[i];
            if(p.p_type==PT_LOAD && (p.p_flags&flags)==flags && p.p_memsz>=size && va>=p.p_vaddr && va-p.p_vaddr<=p.p_memsz-size) return true;
        }
        return false;
    }
    std::optional<Symbol> symbol(const char *wanted,unsigned type) const {
        if(!valid) return {};
        const auto *sh=at<Elf64_Shdr>(header.e_shoff,header.e_shnum);
        std::optional<Symbol> found;
        for(unsigned i=0;i<header.e_shnum;i++) {
            const auto &s=sh[i];
            if(s.sh_type!=SHT_DYNSYM) continue;
            if(s.sh_link>=header.e_shnum || s.sh_entsize!=sizeof(Elf64_Sym) || s.sh_size%sizeof(Elf64_Sym) || s.sh_size/sizeof(Elf64_Sym)>65536) return {};
            const auto &str=sh[s.sh_link];
            if(str.sh_type!=SHT_STRTAB || str.sh_size>2*1024*1024 || str.sh_offset>bytes.size() || str.sh_size>bytes.size()-str.sh_offset) return {};
            const auto *sy=at<Elf64_Sym>(s.sh_offset,s.sh_size/sizeof(Elf64_Sym));
            if(!sy) return {};
            for(size_t n=0;n<s.sh_size/sizeof(Elf64_Sym);n++) {
                const auto &x=sy[n];
                if(x.st_name>=str.sh_size) return {};
                const char *name=reinterpret_cast<const char *>(bytes.data()+str.sh_offset+x.st_name);
                if(!memchr(name,0,str.sh_size-x.st_name)) return {};
                if(strcmp(name,wanted) || x.st_shndx==SHN_UNDEF || ELF64_ST_TYPE(x.st_info)!=type || ELF64_ST_BIND(x.st_info)!=STB_GLOBAL) continue;
                if(found || !in_load(x.st_value,x.st_size?x.st_size:1,type==STT_FUNC?PF_X:PF_W)) return {};
                found=Symbol{x.st_value,static_cast<size_t>(x.st_size)};
            }
        }
        return found;
    }
    Mapping mapping(int pid) const {
        Mapping result;
        char proc[64]; snprintf(proc,sizeof(proc),"/proc/%d/maps",pid);
        std::unique_ptr<FILE,decltype(&fclose)> f(fopen(proc,"re"),fclose);
        if(!f || !valid) return result;
        result.scanned=true;
        char line[2048];
        while(fgets(line,sizeof(line),f.get())) {
            unsigned long start,finish,offset,inode; unsigned dev_major,dev_minor; char perms[8],path[1536]={0};
            if(sscanf(line,"%lx-%lx %7s %lx %x:%x %lu %1535[^\n]",&start,&finish,perms,&offset,&dev_major,&dev_minor,&inode,path)!=8) continue;
            const bool same=inode==static_cast<unsigned long>(identity.st_ino) && dev_major==major(identity.st_dev) && dev_minor==minor(identity.st_dev);
            std::string name(path);
            if(name.size()>10 && name.compare(name.size()-10,10," (deleted)")==0) name.resize(name.size()-10);
            const size_t slash=name.find_last_of('/');
            const bool matching_name=name.substr(slash==std::string::npos?0:slash+1)==basename;
            if(matching_name && !same) result.conflict=true;
            if(same && offset==0) {
                if(result.base) result.conflict=true;
                result.base=start;
            }
        }
        return result;
    }
};

#ifdef SRKP_INJECT_LIBRARY_ONLY
inline std::atomic<uint64_t> srkp_image_load_count{0},srkp_image_reuse_count{0};
#endif
