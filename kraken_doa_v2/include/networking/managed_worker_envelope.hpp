#pragma once
#include "networking/iq_wire_ingress.hpp"
#ifdef TT01_D2_MANAGER_QUALIFICATION
#include "networking/managed_audio_selection.hpp"
#endif
namespace dig { class DigitalDecoder; }
namespace managed_iq {
class ReceiverSelection;
// Only ReceiverSelection can mint a new immutable envelope, moving the
// exact postpass vector. No strong owner reference to instance or decoder.
class WorkerEnvelope {
    friend class ReceiverSelection;
    friend class EventStamp;
    friend class dig::DigitalDecoder;
    mutable std::atomic<bool> submitted_{false};
    bool claim_submission() const {bool unused=false;return submitted_.compare_exchange_strong(unused,true);}
    WorkerEnvelope(const dig::DigitalDecoder* decoder,std::shared_ptr<Publication> authority,
        RoleStamp role,Provenance provenance,uint64_t source,uint64_t wire,uint64_t segment,
        uint64_t pos,float rate,std::vector<std::complex<float>>&& samples
#ifdef TT01_D2_MANAGER_QUALIFICATION
        ,uint64_t selection
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        ,uint64_t audio_stream
#endif

        )
        : decoder_(decoder),authority_(std::move(authority)),role_(role),
          provenance_(std::move(provenance)),source_(source),wire_(wire),segment_(segment),
          pos_(pos),rate_(rate),samples_(std::move(samples))
#ifdef TT01_D2_MANAGER_QUALIFICATION
          ,selection_(selection)
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
          ,audio_stream_(audio_stream)
#endif

          {}
    const dig::DigitalDecoder* const decoder_;
    const std::shared_ptr<Publication> authority_;
    const RoleStamp role_;
    const Provenance provenance_;
    const uint64_t source_,wire_,segment_,pos_;
    const float rate_;
    const std::vector<std::complex<float>> samples_;
#ifdef TT01_D2_MANAGER_QUALIFICATION
    const uint64_t selection_;
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
    const uint64_t audio_stream_;
#endif

public:
    WorkerEnvelope(const WorkerEnvelope&)=delete;
    WorkerEnvelope& operator=(const WorkerEnvelope&)=delete;
    const Provenance& provenance() const{return provenance_;}
    uint64_t source()const{return source_;}
    uint64_t wire()const{return wire_;}
    uint64_t segment()const{return segment_;}
    uint64_t pos()const{return pos_;}
    float rate()const{return rate_;}
#ifdef TT01_D2_MANAGER_QUALIFICATION
    uint64_t selection()const{return selection_;}
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
    uint64_t audio_stream()const{return audio_stream_;}
#endif

    const std::vector<std::complex<float>>& samples()const{return samples_;}
    // Check exact decoder identity, both source epochs, and managed role
    // under their admission locks. Callback limited to queue bookkeeping.
    template<class F>
    bool admit(const dig::DigitalDecoder* decoder,F&& action)const{
        if(decoder!=decoder_||samples_.empty()||!provenance_.placement)return false;
        return iq_ingress::admit_epochs(source_,wire_,[&]{
            return authority_->admit(provenance_.placement,role_,std::forward<F>(action));
        });
    }
};
#ifdef TT01_WORKER_QUALIFICATION
namespace worker_test {
enum class Event { before_start, started, stale };
inline void (*hook)(const dig::DigitalDecoder*,Event,const WorkerEnvelope&)=nullptr;
}
#endif
}
