#pragma once

// Managed independent P25 producer seam. The loop is the sole publisher;
// the sequential data receiver owns ProducerHistory and all DSP mutations.
// No publication mutex spans dispatch, DSP, decoder I/O or a thread join.
#include <atomic>
#ifdef TT01_D2_PUBLISH_QUALIFICATION
#include "networking/audio_publish_fence.hpp"
#endif

#include <array>
#include <unordered_map>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include "signal_processing/shared_decimator.hpp"
#include "utils/raw_data_buffer.hpp"

namespace managed_iq {
using Clock = std::chrono::steady_clock;

// Host ingress order only; not a hardware acquisition epoch. Single parser
// writer, loop reader. Saturate on exhaustion rather than reuse sequence IDs.
inline std::atomic<uint64_t> ingress_highwater{0};
inline uint64_t note_ingress() {
    // The increment is the host-stamp linearization point, not the RF
    // acquisition instant. A single total atomic order with cutoff reads.
    auto seq = ingress_highwater.load();
    while(seq!=UINT64_MAX&&!ingress_highwater.compare_exchange_weak(seq,seq+1)){}
    return seq==UINT64_MAX?seq:seq+1;
}

struct Tuple {
    uint64_t instance = 0, decoder = 0;
    int mode = 2, tuner = -1, bandwidth = 0;
    uint64_t requested_center = 0; // historical field name: planner center, NOT proof of request
    float offset = 0;
    std::string plugin;
    std::map<std::string, std::string> options;
    bool operator==(const Tuple&) const = default;
};

struct Target {
    std::string system, channel;
    int site = -1, slot = -1;
    bool group = true;
    uint64_t id = 0;  // manager call-row correlation only
    std::string target_key; // grant target text, not a numeric call row
    bool operator==(const Target&) const = default;
};

// Host configuration domains, distinct from the later packet source epoch.
// A receiver-wide mutation fences every tuner; a tuner-specific mutation
// fences only that tuner. Domain lock precedes publication lock.
struct DomainStamp {
    int tuner = -1;
    uint64_t source = 0, selected = 0;
};
struct Domains {
    struct Counter { uint64_t epoch = 1, writers = 0, cutoff = 0; };
    std::mutex mu;
    Counter source;
    std::array<Counter,MAX_CHANNELS> tuners;
    DomainStamp capture_locked(int t) const {
        return {t,source.epoch,t >= 0 ? tuners[t].epoch : 0};
    }
    bool valid_locked(DomainStamp s) const {
        const auto valid = [](const Counter& c, uint64_t e) {
            return !c.writers && e == c.epoch && e != std::numeric_limits<uint64_t>::max();
        };
        return valid(source,s.source) && (s.tuner < 0 ||
            (s.tuner < MAX_CHANNELS && valid(tuners[s.tuner],s.selected)));
    }
    bool after_locked(DomainStamp s,uint64_t seq)const{
        return seq!=UINT64_MAX&&seq>source.cutoff&&valid_locked(s)&&
            (s.tuner<0||seq>tuners[s.tuner].cutoff);
    }
};
inline Domains& domains() {
    static Domains* d = new Domains;
    return *d;
}
class DomainWrite {
    int tuner_;
public:
    // -1 = receiver-wide; invalid indices conservatively fence all.
    explicit DomainWrite(int t = -1) : tuner_(t >= 0 && t < MAX_CHANNELS ? t : -1) {
        auto& d = domains();
        std::lock_guard lock(d.mu);
        auto& c = tuner_ < 0 ? d.source : d.tuners[tuner_];
        if (c.epoch != std::numeric_limits<uint64_t>::max()) ++c.epoch;
        ++c.writers;
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif

        c.cutoff=ingress_highwater.load();
    }
    ~DomainWrite() {
        auto& d = domains();
        std::lock_guard lock(d.mu);
        auto& c=tuner_<0?d.source:d.tuners[tuner_];
        // Packets stamped during the writer cannot be adopted by the
        // post-write epoch. Last outstanding writer defines the final fence.
        c.cutoff=ingress_highwater.load();
        --c.writers;
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif

    }
    DomainWrite(const DomainWrite&) = delete;
    DomainWrite& operator=(const DomainWrite&) = delete;
};

// The current upstream tuning cache can contain an adopted wire header.
// Its origin is not tracked: never call it an exact command acknowledgement.
struct CenterEvidence {
    double configured_or_adopted_hz = 0;
    uint64_t header_at_readback_hz = 0;
    bool origin_known = false;
};

struct Placement {
    Tuple tuple;
    Target expected;  // grant intent, not decoder-confirmed identity
    uint64_t token = 0, transport = 0, cutoff_seq = 0;
    Clock::time_point cutoff_time;
    DomainStamp domain;
    CenterEvidence center;
};
using Snapshot = std::shared_ptr<const Placement>;

enum class Role { manual, managed, deleted };
struct RoleStamp {
    Role role = Role::manual;
    uint64_t epoch = 0;
    bool operator==(const RoleStamp&) const = default;
};

class Publication {
    mutable std::mutex mu_;
    uint64_t next_token_ = 0, next_transport_ = 0, pending_ = 0;
    uint64_t epoch_ = 1, writers_ = 0, manual_cutoff_ = 0;
    // Loss serial is advanced under the same publication lock that
    // admits native reports and decoder queue insertion. Atomic reads
    // also allow the worker to observe retirement without taking q_mu.
    std::atomic<uint64_t> manual_loss_{1};
    uint64_t manual_last_segment_=0,manual_last_seq_=0,manual_last_role_=0;
    uint64_t manual_origin_seq_=0,manual_submission_epoch_=0;
    Role role_;
    Snapshot current_;
    DomainStamp pending_domain_;
    bool advance_epoch() {
        if (epoch_ == std::numeric_limits<uint64_t>::max()) return false;
        ++epoch_;
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif
        return true;
    }
    void close_locked() {
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        if(current_||pending_)audio_fence::mark();
#endif
        current_.reset(); pending_ = 0; }
public:
    explicit Publication(Role role = Role::managed) : manual_cutoff_(ingress_highwater.load()),role_(role) {}
    bool claim() {
        std::lock_guard lock(mu_);
        if (role_ == Role::deleted || writers_) return false;
        if (role_ == Role::managed) return true;
        if (!advance_epoch()) return false;
        close_locked();
        role_ = Role::managed;
        manual_cutoff_=ingress_highwater.load();
        return true;
    }
    bool hand_back() {
        std::lock_guard lock(mu_);
        close_locked();
        if (role_ == Role::deleted || writers_) return false;
        if (role_ == Role::manual) return true;
        if (!advance_epoch()) return false;
        role_ = Role::manual;
        manual_cutoff_=ingress_highwater.load();
        return true;
    }
    // Delayed last-VFO recovery is allowed only for the same quiescent
    // closed role after readback. Never cancel a new pending placement.
    bool hand_back_if_closed(RoleStamp expected) {
        std::lock_guard lock(mu_);
        if(writers_ || role_!=Role::managed || pending_ || current_ ||
           expected!=RoleStamp{role_,epoch_} || !advance_epoch()) return false;
        role_=Role::manual;
        manual_cutoff_=ingress_highwater.load();
        return true;
    }
    void erase() {
        std::lock_guard lock(mu_);
        close_locked();
        advance_epoch();
        role_ = Role::deleted;
        manual_cutoff_=ingress_highwater.load();
    }
    RoleStamp role() const {
        std::lock_guard lock(mu_);
        return {role_, epoch_};
    }
    std::optional<RoleStamp> capture_role() const {
        std::lock_guard lock(mu_);
        if (writers_ || role_ == Role::deleted || epoch_ == std::numeric_limits<uint64_t>::max())
            return {};
        return RoleStamp{role_,epoch_};
    }
    bool role_current(RoleStamp stamp) const {
        std::lock_guard lock(mu_);
        return !writers_ && role_ != Role::deleted && epoch_ != std::numeric_limits<uint64_t>::max() &&
            stamp == RoleStamp{role_,epoch_};
    }
    template<class F>
    bool admit_manual(RoleStamp stamp,F&& action) const {
        std::lock_guard lock(mu_);
        return !writers_&&role_==Role::manual&&epoch_!=UINT64_MAX&&
               stamp==RoleStamp{role_,epoch_}&&action();
    }
    template<class F>
    bool admit_manual_after(RoleStamp stamp,uint64_t seq,F&& action)const{
        std::lock_guard lock(mu_);
        return !writers_&&role_==Role::manual&&epoch_!=UINT64_MAX&&
            stamp==RoleStamp{role_,epoch_}&&seq!=UINT64_MAX&&seq>manual_cutoff_&&action();
    }
    uint64_t manual_loss_epoch()const{return manual_loss_.load();}
    bool manual_loss_current(uint64_t epoch)const{
        return epoch&&epoch!=UINT64_MAX&&manual_loss_.load()==epoch;
    }
    // Only called from a publication-admitted action. No new mutex.
    void lose_manual_locked(){
        auto n=manual_loss_.load();
        if(n!=UINT64_MAX)manual_loss_.store(n+1);
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif

    }
    // Called by the worker at the first observed native runner loss,
    // never while holding queue or generation locks.
    void lose_manual_if_current(uint64_t epoch){
        std::lock_guard lock(mu_);
        if(manual_loss_current(epoch))lose_manual_locked();
    }
    uint64_t manual_submission_locked(RoleStamp role,uint64_t segment,uint64_t seq,bool overflow){
        if(overflow||(manual_last_segment_&&
            (manual_last_role_!=role.epoch||manual_last_segment_!=segment||
             manual_last_seq_==UINT64_MAX||seq!=manual_last_seq_+1)))lose_manual_locked();
        manual_last_role_=role.epoch;manual_last_segment_=segment;manual_last_seq_=seq;
        return manual_loss_epoch();
    }
    // These helpers run only within the original source/domain/publication
    // admission. A newer prepare never grants an older packet authority.
    uint64_t manual_origin_locked(uint64_t seq,bool discontinuity){
        if(!seq||seq==UINT64_MAX||seq<=manual_origin_seq_)return 0;
        if(discontinuity||(manual_origin_seq_&&seq!=manual_origin_seq_+1))
            lose_manual_locked();
        manual_origin_seq_=seq;
        auto e=manual_loss_epoch();
        return e==UINT64_MAX?0:e;
    }
    bool manual_origin_current_locked(uint64_t seq,uint64_t epoch)const{
        return seq==manual_origin_seq_&&manual_loss_current(epoch);
    }
    void manual_origin_failed_locked(uint64_t seq,uint64_t epoch){
        if(manual_origin_current_locked(seq,epoch))lose_manual_locked();
    }
    uint64_t manual_origin_submission_locked(RoleStamp role,uint64_t segment,uint64_t seq,
                                               uint64_t origin,bool overflow){
        if(!manual_origin_current_locked(seq,origin)||seq<=manual_last_seq_)return 0;
        // A discontinuity already fenced at prepare need not be fenced
        // a second time. Submission-only loss/overflow still retires here.
        if(overflow||(manual_submission_epoch_==origin&&manual_last_segment_&&
            (manual_last_role_!=role.epoch||manual_last_segment_!=segment||
             seq!=manual_last_seq_+1)))lose_manual_locked();
        manual_last_role_=role.epoch;manual_last_segment_=segment;manual_last_seq_=seq;
        manual_submission_epoch_=manual_loss_epoch();
        return manual_submission_epoch_==UINT64_MAX?0:manual_submission_epoch_;
    }
    // Writers register before touching state and unregister after all effects.
    // Only a matching pending-ticket capability preserves the transaction.
    // No mutex remains held across the mutation itself.
    bool enter_writer(uint64_t capability) {
        std::lock_guard lock(mu_);
        if (role_ == Role::deleted || writers_ == std::numeric_limits<uint64_t>::max()) return false;
        current_.reset();
        if (!capability || capability != pending_) {
            pending_ = 0;
            if (!advance_epoch()) return false;
        }
        ++writers_;
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif

        manual_cutoff_=ingress_highwater.load();
        return true;
    }
    void leave_writer() {
        std::lock_guard lock(mu_);
        manual_cutoff_=ingress_highwater.load();
        --writers_;
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif

    }
    uint64_t begin(int tuner = -1) {
        auto& d = domains();
        std::lock_guard domain_lock(d.mu);
        std::lock_guard lock(mu_);
        close_locked();
        if (tuner < -1 || tuner >= MAX_CHANNELS) return 0;
        pending_domain_ = d.capture_locked(tuner);
        if (role_ != Role::managed || writers_ || !d.valid_locked(pending_domain_) ||
            next_token_ == std::numeric_limits<uint64_t>::max()) return 0;
        return pending_ = ++next_token_;
    }
    void abort(uint64_t ticket) {
        std::lock_guard lock(mu_);
        if (ticket && pending_ == ticket) close_locked();
    }
    void retire() {
        std::lock_guard lock(mu_);
        close_locked();
    }
    Snapshot commit(uint64_t ticket, const Tuple& expected, const Tuple& applied,
                    const Target& target, uint64_t ingress_highwater, bool commands_ok, CenterEvidence center = {}) {
        auto& d = domains();
        std::lock_guard domain_lock(d.mu);
        std::lock_guard lock(mu_);
        if (!ticket || ticket != pending_) return {};
        pending_ = 0;
        if (!d.valid_locked(pending_domain_) ||
            (pending_domain_.tuner >= 0 && pending_domain_.tuner != expected.tuner) ||
            writers_ || role_ != Role::managed || !commands_ok || !(expected == applied) ||
            expected.mode != 2 || !expected.instance || !expected.decoder || expected.plugin != "p25" ||
            expected.tuner < 0 || expected.tuner >= MAX_CHANNELS ||
            expected.bandwidth < VFO_BW_MIN_HZ || expected.bandwidth > VFO_BW_MAX_HZ ||
            !expected.requested_center || !std::isfinite(expected.offset) ||
            next_transport_ == std::numeric_limits<uint64_t>::max() ||
            ingress_highwater == std::numeric_limits<uint64_t>::max()) return {};
        current_ = std::make_shared<const Placement>(Placement{
            applied, target, ticket, ++next_transport_, ingress_highwater, Clock::now(), pending_domain_, center});
        return current_;
    }
    template<class Guard>
    Snapshot commit_guarded(uint64_t ticket, const Tuple& expected, const Tuple& applied,
                    const Target& target, uint64_t ingress_highwater, bool commands_ok, CenterEvidence center, Guard&& guard) {
        auto& d = domains();
        std::lock_guard domain_lock(d.mu);
        std::lock_guard lock(mu_);
        if (!ticket || ticket != pending_) return {};
        pending_ = 0;
        if (!d.valid_locked(pending_domain_) ||
            (pending_domain_.tuner >= 0 && pending_domain_.tuner != expected.tuner) ||
            writers_ || role_ != Role::managed || !commands_ok || !(expected == applied) ||
            expected.mode != 2 || !expected.instance || !expected.decoder || expected.plugin != "p25" ||
            expected.tuner < 0 || expected.tuner >= MAX_CHANNELS ||
            expected.bandwidth < VFO_BW_MIN_HZ || expected.bandwidth > VFO_BW_MAX_HZ ||
            !expected.requested_center || !std::isfinite(expected.offset) ||
            next_transport_ == std::numeric_limits<uint64_t>::max() ||
            ingress_highwater == std::numeric_limits<uint64_t>::max()) return {};
        auto candidate = std::make_shared<const Placement>(Placement{
            applied, target, ticket, next_transport_+1, ingress_highwater, Clock::now(), pending_domain_, center});
        // Guard is internal lock-only bookkeeping. On refusal nothing is
        // published. Caller owns the common source epoch lock, and guard
        // acquires distinct control publication and runner locks.
        if(!guard(candidate,[&]{current_=candidate;++next_transport_;return true;}))return {};
        return current_;
    }
    // Queue-only linearization callback. Never call a setter, DSP, plugin,
    // callback or blocking wait inside this scope. Order: source -> domain
    // -> publication -> queue. No reverse acquisition from queue.
    template<class F>
    bool admit(const Snapshot& placement,RoleStamp role,F&& action) const {
        auto& d=domains();
        std::lock_guard domain_lock(d.mu);
        std::lock_guard lock(mu_);
        if(!placement||current_!=placement||writers_||role_!=Role::managed||
           role!=RoleStamp{role_,epoch_}||epoch_==UINT64_MAX||
           !d.valid_locked(placement->domain))return false;
        return action();
    }
    // Only from this publication's admitted action, with its mutex
    // already held. Exact snapshot comparison protects replacement.
    bool retire_admitted(const Snapshot& s){
        if(!s||current_!=s)return false;
        current_.reset();
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif
        return true;
    }
    // Exact cleanup also works after a source/domain loss hid the old
    // snapshot. Never close a newer pending ticket, replacement or role.
    // The callback is limited to atomic stores on the exact instance.
    template<class F>
    bool close_exact(const Snapshot& old,RoleStamp role,F&& disable){
        std::lock_guard lock(mu_);
        if(!old||writers_||pending_||role_!=Role::managed||
           role!=RoleStamp{role_,epoch_}||next_token_!=old->token||
           (current_&&current_!=old))return false;
        current_.reset();
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::mark();
#endif
        return disable();
    }
    Snapshot snapshot() const {
        auto& d = domains();
        std::lock_guard domain_lock(d.mu);
        std::lock_guard lock(mu_);
        return current_ && d.valid_locked(current_->domain) ? current_ : Snapshot{};
    }
    bool current(const Snapshot& s) const {
        auto& d = domains();
        std::lock_guard domain_lock(d.mu);
        std::lock_guard lock(mu_);
        return s && current_ == s && d.valid_locked(s->domain);
    }
};

// Capability is thread-local, exact publication + ticket, installed only
// around the placement's own setter/dispatch calls. Test hooks and readback
// execute outside it. It never authorizes a different instance or thread.
struct Capability { Publication* owner = nullptr; uint64_t ticket = 0; };
inline thread_local Capability writer_capability;
#ifdef TT01_WRITER_TEST
inline void (*writer_test_hook)(int) = nullptr;
#endif
class AuthorizedWrites {
    Capability previous_;
public:
    AuthorizedWrites(Publication* owner, uint64_t ticket) : previous_(writer_capability) {
        writer_capability = {owner,ticket};
    }
    ~AuthorizedWrites() { writer_capability = previous_; }
    AuthorizedWrites(const AuthorizedWrites&) = delete;
    AuthorizedWrites& operator=(const AuthorizedWrites&) = delete;
};
class PendingPlacement {
    std::shared_ptr<Publication> pub_;
    uint64_t ticket_;
public:
    PendingPlacement(std::shared_ptr<Publication> pub, uint64_t ticket)
        : pub_(std::move(pub)),ticket_(ticket) {}
    ~PendingPlacement() { if (pub_) pub_->abort(ticket_); }
    PendingPlacement(const PendingPlacement&) = delete;
};
class Writer {
    std::shared_ptr<Publication> pub_;
    bool entered_ = false;
public:
    explicit Writer(std::shared_ptr<Publication> pub) : pub_(std::move(pub)) {
        if (pub_) entered_ = pub_->enter_writer(
            writer_capability.owner == pub_.get() ? writer_capability.ticket : 0);
    }
    ~Writer() { if (entered_) pub_->leave_writer(); }
    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;
    explicit operator bool() const { return entered_; }
};

// A neutral state exists even before first managed claim; a writer that
// starts in manual mode cannot evade the same lock on a later claim.
class Registry {
    struct Entry {
        std::weak_ptr<void> owner;
        std::shared_ptr<Publication> publication;
    };
    std::mutex mu_;
    std::unordered_map<uint64_t, Entry> entries_;
    void prune_locked() {
        for (auto i = entries_.begin(); i != entries_.end();)
            if (i->second.owner.expired()) i = entries_.erase(i); else ++i;
    }
public:
    std::shared_ptr<Publication> state(uint64_t serial, const std::shared_ptr<void>& owner) {
        if (!serial || !owner) return {};
        std::lock_guard lock(mu_);
        prune_locked();
        auto i = entries_.find(serial);
        if (i != entries_.end()) return i->second.owner.lock() == owner ? i->second.publication : nullptr;
        auto p = std::make_shared<Publication>(Role::manual);
        entries_.emplace(serial, Entry{owner,p});
        return p;
    }
    std::shared_ptr<Publication> claim(uint64_t serial, const std::shared_ptr<void>& owner) {
        auto p = state(serial,owner);
        return p && p->claim() ? p : nullptr;
    }
    std::shared_ptr<Publication> lookup(uint64_t serial, const std::shared_ptr<void>& owner) {
        std::lock_guard lock(mu_);
        auto i = entries_.find(serial);
        if (i == entries_.end() || i->second.owner.lock() != owner ||
            i->second.publication->role().role == Role::manual) return {};
        return i->second.publication;
    }
    Writer write(uint64_t serial, const std::shared_ptr<void>& owner) {
        return Writer(state(serial,owner));
    }
    void erase(uint64_t serial, const std::shared_ptr<void>& owner) {
        if (auto p = state(serial,owner)) p->erase();
    }
    bool hand_back(uint64_t serial, const std::shared_ptr<void>& owner) {
        auto p = state(serial,owner);
        return p && p->hand_back();
    }
    size_t prune() {
        std::lock_guard lock(mu_);
        prune_locked();
        return entries_.size();
    }
};
// Process lifetime, including global DecimatorManager teardown.
inline Registry& registry() {
    static Registry* r = new Registry;
    return *r;
}

struct Provenance {
    Snapshot placement;
    uint64_t packet_seq = 0;
    Clock::time_point packet_time;
    int input = -1;
    float observed_center = 0, offset = 0;
    int bandwidth = 0;
    bool history_reset = false;
    // The command center is not the observed RF. Preserve both.
    double observed_rf() const { return static_cast<double>(observed_center) + offset; }
};

// One state per decimator, owned ONLY by the sequential processing thread.
// If a decimation fails, abandon() before the next prepare().
class ProducerHistory {
    Snapshot last_;
    uint64_t last_seq_ = 0, last_source_ = 0, last_wire_ = 0;
public:
    void abandon() { last_.reset(); last_seq_ = last_source_ = last_wire_ = 0; }

    std::optional<Provenance> prepare(const Publication& publication, const RawDataPacket& packet,
                                      SharedDecimator& decimator, SharedDecimator::VfoBlock& block,
                                      SharedDecimator::MultiChannelDecimated& output) {
        auto p = publication.snapshot();
        if (!p || packet.seq <= p->cutoff_seq || packet.timestamp <= p->cutoff_time ||
            packet.noise_source_active) return {};
        const auto& t = p->tuple;
        const int input = t.tuner;
        if (input < 0 || input >= MAX_CHANNELS ||
            static_cast<unsigned>(input) >= packet.num_channels ||
            static_cast<size_t>(input) >= packet.channel_iq_data.size()) return {};
        const auto& iq = packet.channel_iq_data[input];
        const float center = packet.freq_hz[input];
        // Match the packet's representable float32 center, never promote an
        // unrelated header by borrowing a live requested center.
        if (iq.empty() || iq.size() != packet.samples_per_channel ||
            !std::isfinite(center) || center <= 0 ||
            center != static_cast<float>(t.requested_center)) return {};
        if (last_ == p && packet.seq <= last_seq_) return {};
        const bool reset = last_ != p || last_seq_ == std::numeric_limits<uint64_t>::max() ||
                           packet.seq != last_seq_ + 1 || packet.source_epoch != last_source_ ||
                           packet.wire_continuity != last_wire_;
        if (reset) decimator.reset_stream_history();
        last_ = p;
        last_seq_ = packet.seq;
        last_source_ = packet.source_epoch;
        last_wire_ = packet.wire_continuity;
        // Populate the actual shared-decimator input, not a shadow model.
        block = SharedDecimator::VfoBlock{};
        block.decimator = &decimator;
        block.ptrs[0] = iq.data();
        block.lens[0] = iq.size();
        block.num_channels = 1;
        block.bandwidth_hz = t.bandwidth;
        block.freq_offset_hz = t.offset;
        block.out = &output;
        return Provenance{p, packet.seq, packet.timestamp, input, center, t.offset, t.bandwidth, reset};
    }
};

inline bool eligible_result(const Publication& publication, const Provenance& provenance,
                            const SharedDecimator::MultiChannelDecimated& result) {
    return publication.current(provenance.placement) && result.num_channels == 1 &&
           result.channels.size() == 1 && result.min_samples > 0 &&
           result.channels[0].samples.size() == result.min_samples &&
           result.bandwidth_hz == provenance.bandwidth &&
           result.freq_offset_hz == provenance.offset &&
           result.output_rate_hz == SAMPLE_RATE / decimation_for_bandwidth(provenance.bandwidth);
}
} // namespace managed_iq

namespace trunk {
// Loop-only diagnostic until the producer lifetime registry is qualified.
managed_iq::Snapshot managed_placement(int vfo);
#ifdef TT01_MANAGER_TRANSACTION_TEST
using TransactionHook = void (*)(int vfo, bool after_dispatch);
void set_transaction_test_hook(TransactionHook hook);
void set_commit_test_hook(void (*hook)(int));
#endif
}
