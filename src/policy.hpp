// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <atomic>
#include <cstdint>
#include <cstring>
#include <type_traits>
constexpr uint64_t SRKP_ACTIVATION_MAGIC=UINT64_C(0x53524b5055494434);
constexpr uint64_t SRKP_STATE_MAGIC=UINT64_C(0x53524b5053544134);
constexpr unsigned SRKP_MAX_UIDS=256;
struct SrkpActivation {
    uint64_t magic=SRKP_ACTIVATION_MAGIC;
    uint32_t version=4,count=0;
    uint32_t uids[SRKP_MAX_UIDS]{};
};
inline bool srkp_activation_valid(const SrkpActivation *p) {
    return p && p->magic==SRKP_ACTIVATION_MAGIC && p->version==4 && p->count>0 && p->count<=SRKP_MAX_UIDS;
}
struct alignas(8) SrkpState {
    uint64_t magic=SRKP_STATE_MAGIC;
    uint32_t abi=4,capacity=SRKP_MAX_UIDS;
    std::atomic<uint64_t> epoch{0};
    std::atomic<uint32_t> enabled{0},count{0};
    std::atomic<uint32_t> uids[SRKP_MAX_UIDS]{};
};
static_assert(std::is_standard_layout_v<SrkpState>);
static_assert(std::atomic<uint32_t>::is_always_lock_free && std::atomic<uint64_t>::is_always_lock_free);
inline bool srkp_applies(const SrkpState &s,uint32_t uid,const char *name,const char *value) {
    if(!name || !value || strcmp(name,"ro.boot.hwc") ||
       !((value[0]=='C'||value[0]=='c') && (value[1]=='N'||value[1]=='n') && value[2]==0)) return false;
    const auto epoch=s.epoch.load();
    if((epoch&1) || !s.enabled.load()) return false;
    const auto count=s.count.load();
    if(count>SRKP_MAX_UIDS) return false;
    bool found=false;
    for(unsigned i=0;i<count;i++) if(s.uids[i].load()==uid) {found=true;break;}
    return found && s.epoch.load()==epoch;
}
inline void srkp_publish(SrkpState &s,const SrkpActivation &input) {
    s.epoch.fetch_add(1);
    for(unsigned i=0;i<input.count;i++) s.uids[i].store(input.uids[i]);
    s.count.store(input.count);s.enabled.store(1);s.epoch.fetch_add(1);
}
inline void srkp_stop(SrkpState &s) {
    s.epoch.fetch_add(1);s.enabled.store(0);s.epoch.fetch_add(1);
}
