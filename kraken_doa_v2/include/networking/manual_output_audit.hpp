#pragma once
#include "networking/manual_decoder_envelope.hpp"
#include "networking/iq_wire_ingress.hpp"
#include "digital/trunk_event.hpp"
namespace managed_iq::manual_output {
// Exact operation stamp from actual receiver postpass, not a role read at
// delivery. The sequence identifies the operation that polled the report,
// not the physical event time or exact child input span.
struct Generation {
    mutable std::mutex mu;
    bool current=true;
    const std::shared_ptr<Publication> pub;
    const uint64_t loss;
    explicit Generation(std::shared_ptr<Publication> p={},uint64_t e=0):pub(std::move(p)),loss(e){}
    void retire(){std::lock_guard lock(mu);
#ifdef TT01_D2_PUBLISH_QUALIFICATION
#ifdef TT01_OPERATIONAL_BUILD
        // A local ordinary decoder generation does not own native PCM.
        if(current&&pub)audio_fence::mark();
#else
        if(current)audio_fence::mark();
#endif
#endif
        current=false;}
    template<class F>bool admit(F&& f)const{std::lock_guard lock(mu);return current&&(!pub||pub->manual_loss_current(loss))&&f();}
};
struct Context{
    std::shared_ptr<const ManualEnvelope> stamp;
    bool closing=false;
    std::shared_ptr<Generation> generation;
};
inline thread_local Context context;
class Scope{
    Context previous_;
public:
    Scope(std::shared_ptr<const ManualEnvelope> s,bool closing=false,std::shared_ptr<Generation> g={}):
        previous_(std::exchange(context,Context{std::move(s),closing,std::move(g)})){}
    ~Scope(){context=std::move(previous_);}
    Scope(const Scope&)=delete;
    Scope& operator=(const Scope&)=delete;
};
template<class F>bool admit(const ManualEnvelope& e,const dig::DigitalDecoder* d,
                            const std::shared_ptr<Publication>& pub,F&& f){
    return iq_ingress::admit_epochs(e.source(),e.wire(),[&]{
        return e.admit(d,pub,std::forward<F>(f));
    });
}
inline void retire_context(){
    if(auto g=context.generation){
        if(g->pub)g->pub->lose_manual_if_current(g->loss);
        g->retire();
    }
}
template<class F>bool admit_report(const ManualEnvelope& e,const dig::DigitalDecoder* d,
                                   const std::shared_ptr<Publication>& pub,
                                   const std::shared_ptr<Generation>& g,F&& f){
    return admit(e,d,pub,[&]{
        if(g)return g->admit(std::forward<F>(f));
        return !e.segment()&&f();
    });
}
struct Report{
    int vfo;
    uint64_t decoder;
    std::string plugin;
    trunk::PluginEvent event;
    std::shared_ptr<const ManualEnvelope> stamp;
    std::shared_ptr<Generation> generation;
};
enum class Stage{callback,closing,unattributed,before_enqueue,before_audit,matched,stale};
inline void (*hook)(Stage,const Report&)=nullptr;
struct Stats{
    uint64_t received=0,accepted=0,refused=0,overflow=0,matched=0,stale=0;
    uint64_t closing=0,unattributed=0,callback_refused=0;
};
constexpr size_t cap=128;
void count_quarantined(bool closing);
void count_callback_refused();
Stats stats();
}
