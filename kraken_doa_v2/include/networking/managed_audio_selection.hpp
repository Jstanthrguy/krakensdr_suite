#pragma once
#include <atomic>
#include <array>
#include <cstdint>
#include <mutex>
#include <limits>
#ifdef TT01_D2_PUBLISH_QUALIFICATION
#include "networking/audio_publish_fence.hpp"
#endif

namespace managed_iq::audio_selection {
// Sidecar avoids changing DecimatorInstance layout. Slots follow instance
// serial, not VFO id alone. No callbacks or external locks under mu.
struct Slot {uint64_t serial=0,epoch=0;bool heard=false;};
inline std::mutex mu;
inline std::array<Slot,256> slots{};
inline uint64_t next=0;
inline void set(int id,uint64_t serial,std::atomic<bool>& bit,bool on){
    std::lock_guard lock(mu);
    if(id<0||size_t(id)>=slots.size()){bit.store(false);return;}
    auto& s=slots[id];
    if(s.serial>serial){bit.store(false);return;}
    if(s.serial!=serial||s.heard!=on){
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif

        if(next==std::numeric_limits<uint64_t>::max()){
            s={serial,0,false};bit.store(false);return;
        }
        s={serial,++next,on};
    }
    bit.store(on);
}
inline uint64_t capture(int id,uint64_t serial){
    std::lock_guard lock(mu);
    if(id<0||size_t(id)>=slots.size())return 0;
    const auto& s=slots[id];
    return s.serial==serial&&s.heard?s.epoch:0;
}
}
