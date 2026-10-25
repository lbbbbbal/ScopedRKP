// SPDX-License-Identifier: GPL-3.0-only
#include "policy.hpp"
#include <cassert>
#include <cstdio>
#include <thread>
int main() {
    SrkpState state;
    SrkpActivation a; a.count=2; a.uids[0]=10001; a.uids[1]=1010001;
    assert(srkp_activation_valid(&a));
    assert(!srkp_activation_valid(nullptr));
    assert(!srkp_applies(state,10001,"ro.boot.hwc","CN"));
    srkp_publish(state,a);
    assert(srkp_applies(state,10001,"ro.boot.hwc","CN"));
    assert(srkp_applies(state,1010001,"ro.boot.hwc","cn"));
    for(const char *value : {"", "C", "GLOBAL", "JP", "CNO"})
        assert(!srkp_applies(state,10001,"ro.boot.hwc",value));
    assert(!srkp_applies(state,10002,"ro.boot.hwc","CN"));
    assert(!srkp_applies(state,10001,"ro.boot.other","CN"));
    assert(!srkp_applies(state,10001,nullptr,"CN"));
    assert(!srkp_applies(state,10001,"ro.boot.hwc",nullptr));
    SrkpActivation b; b.count=1; b.uids[0]=54321;
    srkp_publish(state,b);
    assert(!srkp_applies(state,10001,"ro.boot.hwc","CN"));
    assert(srkp_applies(state,54321,"ro.boot.hwc","CN"));
    b.count=0; assert(!srkp_activation_valid(&b));
    b.count=257; assert(!srkp_activation_valid(&b));
    b.count=256;
    for(unsigned i=0;i<256;i++) b.uids[i]=20000+i;
    srkp_publish(state,b);
    assert(srkp_applies(state,20255,"ro.boot.hwc","CN"));
    assert(!srkp_applies(state,20256,"ro.boot.hwc","CN"));
    std::atomic<bool> running{true};
    std::atomic<unsigned> errors{0};
    std::thread outsider([&] {
        while(running.load()) if(srkp_applies(state,60000,"ro.boot.hwc","CN")) ++errors;
    });
    for(unsigned i=0;i<100000;i++) srkp_publish(state,i&1?a:b);
    running.store(false); outsider.join();
    assert(errors.load()==0);
    srkp_stop(state);
    assert(!srkp_applies(state,10001,"ro.boot.hwc","CN"));
    puts("{\"ok\":true,\"concurrent_policy_updates\":100000,\"dynamic_uid_scope\":true}");
}
