#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <limits>
#include "utils/endian_utils.hpp"
#include "managed_iq_provenance.hpp"

namespace iq_ingress {
// Wire framing only: no globals or metadata side effects on invalid/partial
// input. The same parser is used by the actual receiver and offline fixtures.
enum class FrameStatus { incomplete, invalid, complete };
struct Frame {
    uint32_t channels=0, samples=0, phase_flags=0, noise=0;
    uint32_t counter=0, group=0, retuning=0;
    size_t header_size=0, packet_size=0;
    std::array<float,MAX_CHANNELS> center{}, gain{};
    int mode() const {
        return (phase_flags & 0x2000u) ? 3 : (phase_flags & 0x800u) ? 2 :
               (phase_flags & 0x400u) ? 1 : 0;
    }
};
inline FrameStatus inspect(const uint8_t* data, size_t available, Frame& out) {
    if (available < 32) return FrameStatus::incomplete;
    if (EndianUtils::read_be32(data) != TCP_MAGIC) return FrameStatus::invalid;
    Frame f;
    f.channels=EndianUtils::read_be32(data,4);
    f.samples=EndianUtils::read_be32(data,8);
    if (!f.channels || f.channels>MAX_CHANNELS || !f.samples || f.samples>65536)
        return FrameStatus::invalid;
    f.header_size=32+size_t(f.channels)*8;
    f.packet_size=f.header_size+size_t(f.channels)*f.samples*2;
    if (available<f.packet_size) return FrameStatus::incomplete;
    f.phase_flags=EndianUtils::read_be32(data,12);
    f.noise=EndianUtils::read_be32(data,16);
    f.counter=EndianUtils::read_be32(data,20);
    f.group=EndianUtils::read_be32(data,24);
    f.retuning=EndianUtils::read_be32(data,28);
    for (uint32_t ch=0; ch<f.channels; ++ch) {
        f.center[ch]=EndianUtils::read_le_float(data,32+ch*8);
        f.gain[ch]=EndianUtils::read_le_float(data,36+ch*8);
        // Avoid feeding nonfinite or negative RF/gain into existing consumers.
        // Negative gain is valid (auto gain); zero RF is allowed in legacy wire.
        if (!std::isfinite(f.center[ch]) || f.center[ch]<0 || f.center[ch]>=0x1p63f || !std::isfinite(f.gain[ch]))
            return FrameStatus::invalid;
    }
    out=f;
    return FrameStatus::complete;
}
// Globally visible host epoch. One receive thread, independent flush writer.
// Saturation is fail closed, not wraparound.
// Shared admission lock for source AND wire generation transitions.
// The parser never holds it across conversion or I/O.
inline std::mutex& epoch_admission_mutex() { static auto* m=new std::mutex;return *m; }
class Epoch {
    std::atomic<uint64_t> value_{1};
public:
    uint64_t current() const { return value_.load(std::memory_order_acquire); }
    bool valid(uint64_t e) const { return e && e!=UINT64_MAX && current()==e; }
    uint64_t invalidate() {
        std::lock_guard lock(epoch_admission_mutex());
        auto old=current();
        while(old!=UINT64_MAX && !value_.compare_exchange_weak(old,old+1,
                std::memory_order_acq_rel,std::memory_order_acquire)) {}

#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif
        return old==UINT64_MAX ? old : old+1;
    }
    // Resync can advance its own still-current generation but cannot adopt
    // a flush that invalidated the bytes already in its local buffer.
    bool resync(uint64_t& expected) {
        std::lock_guard lock(epoch_admission_mutex());
        if (!expected || expected==UINT64_MAX) return false;
        auto old=expected;
        if (!value_.compare_exchange_strong(old,expected+1,
                std::memory_order_acq_rel,std::memory_order_acquire)) return false;
        ++expected;
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif

        return expected!=UINT64_MAX;
    }
};
inline Epoch& source_epoch() { static Epoch* e=new Epoch; return *e; }
inline Epoch& continuity_epoch() { static Epoch* e=new Epoch; return *e; }
// Point-in-time only; submission/dequeue linearization is B8B4B.
inline bool packet_current(const RawDataPacket& p) {
    return source_epoch().valid(p.source_epoch) &&
           continuity_epoch().valid(p.wire_continuity);
}

template<class F>
inline bool admit_epochs(uint64_t source,uint64_t wire,F&& action) {
    std::lock_guard lock(epoch_admission_mutex());
    return source_epoch().valid(source)&&continuity_epoch().valid(wire)&&action();
}

class Session {
    Epoch& authority_;
    Epoch& wire_;
    uint64_t epoch_=0, continuity_=0;
    Frame previous_{};
    bool have_previous_=false;
    bool playback_=false;
    bool resync_pending_=false;
public:
    explicit Session(Epoch& a=source_epoch(),Epoch& w=continuity_epoch()) : authority_(a),wire_(w) {}
    void open(bool playback) {
        epoch_=authority_.invalidate(); playback_=playback;
        have_previous_=false; continuity_=0; resync_pending_=false;
    }
    void close() {
        authority_.invalidate(); epoch_=0; have_previous_=false; resync_pending_=false;
    }
    bool current() const { return authority_.valid(epoch_); }
    // Caller discards all accumulated bytes before adopting a new epoch.
    void after_discard() {
        epoch_=authority_.current(); have_previous_=false;
        continuity_=0; resync_pending_=false;
    }
    bool invalid_byte() {
        if (!current()) return false;
        if (resync_pending_) return true;
        if (!authority_.resync(epoch_)) return false;
        have_previous_=false; continuity_=0; resync_pending_=true;
        return true;
    }
    bool stamp(const Frame& f, RawDataPacket& packet) {
        if (!current()) return false;
        // A common wire counter does not identify the affected tuner.
        // Conservatively record a whole-stream continuity boundary when
        // observed RF/mode/counter/noise/retune state changes.
        bool changed=!have_previous_ || previous_.channels!=f.channels ||
            previous_.mode()!=f.mode() || previous_.counter!=f.counter ||
            previous_.noise!=f.noise || previous_.retuning!=f.retuning ||
            previous_.center!=f.center ||
            ((previous_.phase_flags^f.phase_flags)&0x1000u);
        if (changed) continuity_=wire_.invalidate();
        if (continuity_==UINT64_MAX) return false;
        previous_=f; have_previous_=true; resync_pending_=false;
        packet.source_epoch=epoch_;
        packet.wire_continuity=continuity_;
        packet.wire_phase_flags=f.phase_flags;
        packet.wire_frequency_counter=f.counter;
        packet.wire_group_index=f.group;
        packet.wire_retuning=f.retuning!=0;
        packet.wire_playback=playback_;
        packet.timestamp=managed_iq::Clock::now();
        packet.seq=managed_iq::note_ingress();
        packet.num_channels=f.channels;
        packet.samples_per_channel=f.samples;
        packet.phase_compensation_state=f.phase_flags&0xffu;
        packet.noise_source_active=f.noise;
        for(uint32_t ch=0;ch<f.channels;++ch) packet.freq_hz[ch]=f.center[ch];
        // A flush racing stamp leaves old epoch attached; it is never restamped.
        return current() && wire_.valid(continuity_) && packet.seq!=UINT64_MAX;
    }
};
} // namespace iq_ingress
