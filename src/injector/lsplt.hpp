// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <sys/mman.h>
namespace lsplt {
struct MapInfo {
    uintptr_t start{},end{},offset{};int perms{};std::string path;
    static std::vector<MapInfo> Scan(const std::string &pid="self") {
        std::vector<MapInfo> result;
        if(pid!="self" && (pid.empty() || pid.find_first_not_of("0123456789")!=std::string::npos)) return result;
        FILE *file=fopen(("/proc/"+pid+"/maps").c_str(),"re");if(!file) return result;
        char line[4096];
        while(fgets(line,sizeof(line),file)) {
            const size_t n=strlen(line);
            if(n==sizeof(line)-1 && line[n-1]!='\n') {int ch;while((ch=fgetc(file))!=EOF && ch!='\n') {}continue;}
            unsigned long start,end,offset,inode;unsigned major,minor;char p[5]{};int used=0;
            if(sscanf(line,"%lx-%lx %4s %lx %x:%x %lu %n",&start,&end,p,&offset,&major,&minor,&inode,&used)!=7 || !used) continue;
            MapInfo m{start,end,offset,(p[0]=='r'?PROT_READ:0)|(p[1]=='w'?PROT_WRITE:0)|(p[2]=='x'?PROT_EXEC:0),line+used};
            if(!m.path.empty() && m.path.back()=='\n') m.path.pop_back();
            result.push_back(std::move(m));
        }
        fclose(file);return result;
    }
};
}
