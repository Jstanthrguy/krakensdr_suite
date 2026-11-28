#pragma once
#include "networking/managed_worker_envelope.hpp"
#include "digital/trunk_event.hpp"
#include <string_view>
#include <vector>
#include <array>
#include <algorithm>
namespace managed_iq {
// Runner-local authority, independent of placement retirement (e.g. queue
// overflow / a producer gap can replace the runner under the same placement).
class EventGeneration {
    mutable std::mutex mu_;
    bool alive_=true;
public:
    const uint32_t id;
    explicit EventGeneration(uint32_t n):id(n){}
    void retire(){std::lock_guard lock(mu_);
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        if(alive_)audio_fence::mark();
#endif
        alive_=false;}
    template<class F>bool admit(F&& f)const{
        std::lock_guard lock(mu_);return alive_&&f();
    }
};
// Compact immutable acknowledged-transaction correlation. No IQ retention
// and no strong decoder/instance ownership. Position is the host input
// interval and cumulative child sample interval, NOT event capture time.
class EventStamp {
    const dig::DigitalDecoder* const decoder_;
    const std::shared_ptr<Publication> authority_;
    const RoleStamp role_;
    const std::shared_ptr<EventGeneration> generation_;
public:
    const Provenance provenance;
    const uint64_t source,wire,segment,pos,count,child_begin,child_end;
    const float rate;
    const uint32_t generation,sync;
    EventStamp(const WorkerEnvelope& e,std::shared_ptr<EventGeneration> g,uint32_t s,
               uint64_t begin,uint64_t end)
        :decoder_(e.decoder_),authority_(e.authority_),role_(e.role_),generation_(std::move(g)),
         provenance(e.provenance()),source(e.source()),wire(e.wire()),segment(e.segment()),
         pos(e.pos()),count(e.samples().size()),child_begin(begin),child_end(end),
         rate(e.rate()),generation(generation_->id),sync(s){}
    template<class F>bool admit(const dig::DigitalDecoder* d,F&& action)const{
        return d==decoder_&&generation&&sync>generation&&child_end>=child_begin&&
            iq_ingress::admit_epochs(source,wire,[&]{
                return authority_->admit(provenance.placement,role_,[&]{
                    return generation_->admit(std::forward<F>(action));
                });
            });
    }
    // Called only inside this stamp's admitted action.
    bool retire_admitted()const{return authority_->retire_admitted(provenance.placement);}
    const dig::DigitalDecoder* decoder_identity()const{return decoder_;}
};
enum class CallCheck { matched, malformed, unresolved, wrong_target, wrong_slot, wrong_phase };
inline bool decimal_id(std::string_view s,uint32_t max,bool empty=false){
    if(s.empty())return empty;
    uint32_t n=0;
    for(char c:s){if(c<'0'||c>'9'||n>(max-uint32_t(c-'0'))/10)return false;n=n*10+uint32_t(c-'0');}
    return n>0&&n<=max;
}
// Strict pinned P25 CALL wire parser. No default-to-active, slot fallback,
// empty-target adoption or silent truncation. Logical LCH != lch option.
inline CallCheck check_call(std::string_view raw,const Placement& p,trunk::PluginEvent& ev){
    if(raw.empty()||raw.size()>160)return CallCheck::malformed;
    std::array<std::string_view,6> f;
    size_t at=0;
    for(size_t i=0;i<5;++i){
        auto z=raw.find(char(0),at);if(z==raw.npos)return CallCheck::malformed;
        f[i]=raw.substr(at,z-at);at=z+1;
    }
    f[5]=raw.substr(at);
    if(f[0].size()!=1||f[0][0]<'0'||f[0][0]>'2'||(f[2]!="0"&&f[2]!="1")||
       (f[4]!="-1"&&f[4]!="0"&&f[4]!="1")||
       (f[5]!=""&&f[5]!="e"&&f[5]!="m"&&f[5]!="em")||
       !decimal_id(f[1],f[2]=="1"?65535u:16777215u,true)||!decimal_id(f[3],16777215u,true))
        return CallCheck::malformed;
    if(f[1].empty())return CallCheck::unresolved;
    if(f[1]!=p.expected.target_key||(f[2]=="1")!=p.expected.group)return CallCheck::wrong_target;
    const int slot=f[4]=="-1"?-1:f[4][0]-'0';
    if(slot!=p.expected.slot)return CallCheck::wrong_slot;
    auto opt=[&](const char* k){auto i=p.tuple.options.find(k);return i==p.tuple.options.end()?std::string():i->second;};
    if(p.tuple.plugin!="p25"||
       (slot==-1?(opt("p25.phase")!="1"||(!opt("p25.lch").empty()&&opt("p25.lch")!="0")):
                 (opt("p25.phase")!="2"||opt("p25.lch")!=std::to_string(slot+1))))
        return CallCheck::wrong_phase;
    ev=trunk::PluginEvent{};
    ev.kind=trunk::PluginEvent::CALL;ev.call_state=f[0][0]-'0';
    ev.target=f[1];ev.group=f[2]=="1";ev.source=f[3];ev.call_slot=slot;
    ev.encrypted=f[5].find('e')!=f[5].npos;ev.emergency=f[5].find('m')!=f[5].npos;
    // SDK CALL has no event timestamp, direction or confirmed system/site.
    // The placement's expected identity remains intent, not a radio report.
    ev.t_s=NAN;
    return CallCheck::matched;
}
struct EventBatch {
private:
    mutable std::atomic<bool> submitted_{false};
public:
    bool claim_submission()const{
        bool unused=false;return submitted_.compare_exchange_strong(unused,true);
    }
    const int vfo;
    const EventStamp stamp;
    const std::vector<trunk::PluginEvent> calls;
    EventBatch(int v,const WorkerEnvelope& e,std::shared_ptr<EventGeneration> g,uint32_t s,
               uint64_t begin,uint64_t end,std::vector<trunk::PluginEvent>&& events)
        :vfo(v),stamp(e,std::move(g),s,begin,end),calls(std::move(events)){}
};
namespace event_audit {
constexpr size_t batch_cap=32,queue_cap=64;
struct Stats{
    uint64_t staged=0,filtered=0,discarded=0,accepted=0,refused=0,overflow=0,stale=0,matched=0;
};
enum class Stage{before_enqueue,before_audit,matched,stale};
inline void (*hook)(Stage,const EventBatch&)=nullptr;
void count_staged(size_t n,size_t filtered);
void count_discarded(size_t n);
bool enqueue(std::shared_ptr<const EventBatch>);
Stats stats();
}
}
