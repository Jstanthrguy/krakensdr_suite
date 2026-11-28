#pragma once
#include "networking/managed_event_audit.hpp"
namespace managed_iq::lifecycle {
// Ordered report evidence, not independent direction or capture time.
// RELEASED is terminal for this runner/placement. Physical park/release
// is deliberately deferred until the next qualification boundary.
enum class State{none,active,ended,released};
enum class Effect{active,ended,released,refused};
inline Effect advance(State& state,int report){
    if(state==State::released)return Effect::refused;
    if(report==1){state=State::active;return Effect::active;}
    if(report==0&&state==State::active){state=State::ended;return Effect::ended;}
    if(report==2&&(state==State::active||state==State::ended)){state=State::released;return Effect::released;}
    return Effect::refused;
}
struct Cursor {
    uint32_t generation=0,sync=0;
    uint64_t token=0,seq=0,end=0,child_end=0;
    State state=State::none;
    bool begin(const EventStamp& s){
        if(!s.count||s.count>UINT64_MAX-s.pos||s.child_end<=s.child_begin)return false;
        if(token!=s.provenance.placement->token||generation!=s.generation){
            *this=Cursor{};token=s.provenance.placement->token;generation=s.generation;
        }
        if(s.sync<=sync||s.provenance.packet_seq<=seq||s.pos<end||s.child_begin<child_end)return false;
        sync=s.sync;seq=s.provenance.packet_seq;end=s.pos+s.count;child_end=s.child_end;
        return true;
    }
};
struct Snapshot{
    bool selected=false,current=false;
    State state=State::none;
    uint64_t token=0,seq=0;
    uint32_t generation=0,sync=0;
    std::string manager_state;
};
struct Stats{uint64_t active=0,ended=0,released=0,refused=0,invalidated=0,legacy_refused=0;};
enum class Stage{before_commit,committed};
inline void (*hook)(Stage,const EventBatch&)=nullptr;
// Manager-loop-only observation, no production API.
Snapshot snapshot(int vfo);
Stats stats();
}
