#pragma once
#include <atomic>
#include <cstdint>
#include <limits>
namespace managed_iq::audio_fence {
// All revocations mark while holding their existing authority lock.
// Commit CAS orders a single synchronous output admission against marks.
// No authority lock is acquired here or held during encoding/network I/O.
inline std::atomic<uint64_t> revision{1},stream{1};
inline void advance(std::atomic<uint64_t>& a){
    auto n=a.load();
    while(n!=UINT64_MAX&&!a.compare_exchange_weak(n,n+1)){}
}
inline void mark(){advance(revision);}
inline void discontinuity(){advance(stream);mark();}
inline uint64_t capture(){return revision.load();}
inline uint64_t stream_id(){return stream.load();}
inline bool commit(uint64_t expected){
    return expected&&expected!=UINT64_MAX&&revision.compare_exchange_strong(expected,expected);
}
}
