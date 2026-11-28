#pragma once
#include "networking/managed_event_audit.hpp"
#include <cmath>
#include <cstring>
#include <deque>
#include <limits>
#ifdef TT01_D2_MANAGER_QUALIFICATION
#include "networking/managed_pcm_consume.hpp"
#include <chrono>
#endif
namespace managed_iq::pcm {
// Private paired child wire; floats use the SDK's native float encoding.
// Identity is observed by the voice decoder, never copied from the grant.
constexpr uint32_t wire_type=50;
constexpr size_t header=16,max_frame=1440,batch_cap=8000,buffer_cap=8000;
enum class Check{matched,mismatch,malformed};
inline Check parse(std::string_view bytes,const Placement& p,std::vector<float>& out){
    if(bytes.size()<=header||(bytes.size()-header)%sizeof(float))return Check::malformed;
    const size_t n=(bytes.size()-header)/sizeof(float);
    if(n>max_frame||n%160)return Check::malformed;
    auto u=[&](size_t i){return uint32_t(uint8_t(bytes[i]));};
    auto word=[&](size_t i){return (u(i)<<24)|(u(i+1)<<16)|(u(i+2)<<8)|u(i+3);};
    const uint32_t target=word(0),src=word(4),nac=(u(8)<<8)|u(9),phase=u(10),lch=u(11),group=u(12);
    if(!target||target>16777215||src>16777215||group>1||(group&&target>65535)||
       (phase!=1&&phase!=2)||(phase==1?(lch!=0||nac>0xfff):(lch<1||lch>2||nac!=0xffff))||
       u(13)||u(14)||u(15))return Check::malformed;
    auto opt=[&](const char* k){auto i=p.tuple.options.find(k);return i==p.tuple.options.end()?std::string():i->second;};
    if(p.tuple.plugin!="p25"||std::to_string(target)!=p.expected.target_key||bool(group)!=p.expected.group||
       int(lch)!=p.expected.slot+1||opt("p25.phase")!=std::to_string(phase)||opt("p25.lch")!=std::to_string(lch))
        return Check::mismatch;
    if(phase==1){
        const auto s=opt("p25.nac");
        if(s.size()!=3)return Check::mismatch;
        uint32_t value=0;
        for(char c:s){
            if(c>='0'&&c<='9')value=value*16+c-'0';
            else if(c>='A'&&c<='F')value=value*16+c-'A'+10;
            else if(c>='a'&&c<='f')value=value*16+c-'a'+10;
            else return Check::mismatch;
        }
        if(value!=nac)return Check::mismatch;
    }
    const auto old=out.size();out.resize(old+n);
    memcpy(out.data()+old,bytes.data()+header,n*sizeof(float));
    for(size_t i=old;i<out.size();++i)if(!std::isfinite(out[i])||std::fabs(out[i])>4.0f){
        out.resize(old);return Check::malformed;
    }
    return Check::matched;
}
struct Batch{
    const int vfo;
    const EventStamp stamp;
    const std::vector<float> samples;
    mutable std::atomic<bool> submitted{false};
#ifdef TT01_D2_MANAGER_QUALIFICATION
    const uint64_t selection;
    const int64_t acknowledged_ms;
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
    const uint64_t audio_stream;
#endif

    Batch(int v,const WorkerEnvelope& e,std::shared_ptr<EventGeneration> g,uint32_t s,
          uint64_t begin,uint64_t end,std::vector<float>&& x)
        :vfo(v),stamp(e,std::move(g),s,begin,end),samples(std::move(x))
#ifdef TT01_D2_MANAGER_QUALIFICATION
        ,selection(e.selection()),acknowledged_ms(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count())
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        ,audio_stream(e.audio_stream())
#endif

        {}
};
enum class Stage{before_enqueue,before_admit,admitted,refused};
inline void (*hook)(Stage,const Batch&)=nullptr;
struct Stats{uint64_t accepted=0,refused=0,trimmed=0;};
bool enqueue(std::shared_ptr<const Batch>);
Stats stats(int vfo);
// D1 observation on the manager thread only. No mixer/recorder/tap output.
std::vector<float> current_samples(int vfo);
#ifdef TT01_D2_MANAGER_QUALIFICATION
struct DeliveryKey{Snapshot placement;uint32_t generation;uint64_t segment,selection;
#ifdef TT01_D2_PUBLISH_QUALIFICATION
uint64_t audio_stream;
#endif
bool operator==(const DeliveryKey&)const=default;};
using DeliveryQueue=delivery::Queue<Batch,DeliveryKey>;
DeliveryQueue::Read take_samples(int vfo,size_t budget);
bool delivery_current(const DeliveryQueue::Read&);
#ifdef TT01_D2_PUBLISH_QUALIFICATION
// Authority only: no samples, no queue rights, no age extension.
struct EncoderWitness {
    int vfo;
    EventStamp stamp;
    uint64_t selection,audio_stream;
    DeliveryKey key()const{return {stamp.provenance.placement,stamp.generation,stamp.segment,selection,audio_stream};}
};
bool encoder_authority_current(const EncoderWitness&);
#endif
#endif
}
