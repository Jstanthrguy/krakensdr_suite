#pragma once
#include "managed_iq_provenance.hpp"
#include "networking/iq_wire_ingress.hpp"
#include "digital/digital_decoder.hpp"
namespace managed_iq {
// Manual coherent input conservatively depends on every tuner domain;
// independent input depends only on the selected tuner and source domain.
struct ManualDomain {
    int tuner=-1;
    std::array<DomainStamp,MAX_CHANNELS> stamps{};
    bool operator==(const ManualDomain& o)const{
        if(tuner!=o.tuner)return false;
        for(int i=0;i<MAX_CHANNELS;++i)
            if(stamps[i].tuner!=o.stamps[i].tuner||stamps[i].source!=o.stamps[i].source||
               stamps[i].selected!=o.stamps[i].selected)return false;
        return true;
    }
    bool valid_locked(const Domains& d)const{
        if(tuner>=0)return tuner<MAX_CHANNELS&&d.valid_locked(stamps[tuner]);
        for(const auto& s:stamps)if(!d.valid_locked(s))return false;
        return true;
    }
    bool after_locked(const Domains& d,uint64_t seq)const{
        if(tuner>=0)return tuner<MAX_CHANNELS&&d.after_locked(stamps[tuner],seq);
        for(const auto& s:stamps)if(!d.after_locked(s,seq))return false;
        return true;
    }
    template<class F>bool admit(const Publication& pub,RoleStamp role,uint64_t seq,F&& f)const{
        auto& d=domains();std::lock_guard lock(d.mu);
        return after_locked(d,seq)&&pub.admit_manual_after(role,seq,std::forward<F>(f));
    }
    static std::optional<ManualDomain> capture(int t){
        ManualDomain m;m.tuner=t;
        if(t>=MAX_CHANNELS)return {};
        auto& d=domains();std::lock_guard lock(d.mu);
        for(int i=0;i<MAX_CHANNELS;++i)m.stamps[i]=d.capture_locked(i);
        if(!m.valid_locked(d))return {};
        // Unrelated independent tuners must not change the history key.
        if(t>=0)for(int i=0;i<MAX_CHANNELS;++i)if(i!=t)m.stamps[i]={};
        return m;
    }
};
// Created at receiver postpass, never reconstructed at queue insertion.
// Both legacy single/aux and array deliveries may use the same stamp.
struct ManualRf {
    bool bound=false;
    float center=0,offset=0,rate=0;
    int bandwidth=0;
    size_t count=0;
    double rf()const{return double(center)+double(offset);}
};
class ManualEnvelope {
    friend class ReceiverSelection;
    friend class dig::DigitalDecoder;
    mutable std::atomic<bool> used_stream_{false},used_array_{false};
    bool claim_submission(bool array)const{
        bool unused=false;
        return (array?used_array_:used_stream_).compare_exchange_strong(unused,true);
    }
    const dig::DigitalDecoder* const decoder_;
    const std::shared_ptr<Publication> authority_;
    const RoleStamp role_;
    const dig::Mode mode_;
    const std::string plugin_;
    const dig::Options options_;
    const uint64_t seq_,source_,wire_,segment_;
    const ManualDomain domain_;
    const uint64_t origin_loss_;
    const ManualRf rf_;
    mutable std::atomic<uint64_t> loss_epoch_{0};
    ManualEnvelope(const dig::DigitalDecoder* decoder,std::shared_ptr<Publication> authority,
        RoleStamp role,dig::Mode mode,std::string plugin,dig::Options options,uint64_t seq,uint64_t source,uint64_t wire,uint64_t segment,ManualDomain domain,uint64_t origin_loss=0,ManualRf rf={})
        : decoder_(decoder),authority_(std::move(authority)),role_(role),mode_(mode),
          plugin_(std::move(plugin)),options_(std::move(options)),seq_(seq),source_(source),wire_(wire),segment_(segment),domain_(domain),origin_loss_(origin_loss),rf_(rf){}
public:
    ManualEnvelope(const ManualEnvelope&)=delete;
    ManualEnvelope& operator=(const ManualEnvelope&)=delete;
    RoleStamp role()const{return role_;}
    dig::Mode mode()const{return mode_;}
    const std::string& plugin()const{return plugin_;}
    const dig::Options& options()const{return options_;}
    uint64_t seq()const{return seq_;}
    uint64_t source()const{return source_;}
    uint64_t wire()const{return wire_;}
    uint64_t segment()const{return segment_;}
    int tuner()const{return domain_.tuner;}
    uint64_t origin_loss()const{return origin_loss_;}
    const ManualRf& observed_rf()const{return rf_;}
    bool matches_rf(double rf,float rate,int bw,size_t n)const{
        return rf_.bound&&rf==rf_.rf()&&rate==rf_.rate&&bw==rf_.bandwidth&&n==rf_.count;
    }
    // Terminal refusal for a known discarded, nonempty qualified result.
    // No effect for an already submitted block or an older origin.
    bool discard_nonempty()const{
        if(!rf_.bound||!rf_.count)return false;
        return iq_ingress::admit_epochs(source_,wire_,[&]{
            return admit(decoder_,authority_,[&]{
                if(!authority_->manual_origin_current_locked(seq_,origin_loss_)||
                   !claim_submission(false))return false;
                authority_->manual_origin_failed_locked(seq_,origin_loss_);
                return true;
            });
        });
    }
    uint64_t loss_epoch()const{return loss_epoch_.load();}
    bool loss_current()const{return authority_->manual_loss_current(loss_epoch());}
    const dig::DigitalDecoder* decoder_identity()const{return decoder_;}
    const std::shared_ptr<Publication>& authority()const{return authority_;}
    template<class F>bool admit(const dig::DigitalDecoder* d,const std::shared_ptr<Publication>& pub,F&& action)const{
        if(d!=decoder_||pub!=authority_)return false;
#ifdef TT01_OPERATIONAL_BUILD
        // Ordinary stamps also retain their exact captured domain and cutoff.
        return domain_.admit(*authority_,role_,seq_,std::forward<F>(action));
#else
        if(segment_){
            return domain_.admit(*authority_,role_,seq_,std::forward<F>(action));
        }
#endif
        return authority_->admit_manual(role_,std::forward<F>(action));
    }
};
namespace role_test {
enum class Stage{before_start,started,finished,stale,retired,idle_closed};
inline void (*hook)(const dig::DigitalDecoder*,Stage,const ManualEnvelope*,const std::complex<float>*,size_t)=nullptr;
}
}
