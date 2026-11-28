#pragma once
#include "decimator_manager.hpp"
#include "networking/managed_worker_envelope.hpp"
#include "networking/manual_decoder_envelope.hpp"
#include "utils/iq_converter.hpp"
#ifdef TT01_OPERATIONAL_BUILD
#include "globals.hpp"
#include "playback.hpp"
#endif

namespace managed_iq {
using Instance=DecimatorManager::DecimatorInstance;
using Result=DecimatorManager::ProcessResult;
using Block=SharedDecimator::VfoBlock;

// Exact-instance offset mutation shared by manager and multi-effect handler.
bool set_instance_offset(const std::shared_ptr<Instance>& instance,float offset_hz);
#ifdef TT01_RECEIVER_TEST
inline void (*frequency_test_hook)(const std::shared_ptr<Instance>&)=nullptr;
#endif

// Independent wire input only. No reset of legacy coherent converter state.
// Counter-only retune attribution is unknown; conservatively reset each
// affected converter on a common counter change. An observed RF change on
// another tuner with unchanged counter does not reset this one.
class IndependentDcHistory {
    struct Track {
        uint64_t source=0,seq=0;
        float center=0,i=0,q=0;
        uint32_t counter=0,noise=0,generic=0,channels=0;
        bool retune=false,seeded=false;
    };
    std::array<Track,MAX_CHANNELS> tracks_{};
public:
    bool convert(const RawDataPacket& p,int ch,const uint8_t* bytes,std::complex<float>* out) {
        auto& s=tracks_.at(ch);
        bool reset=!s.seeded||s.source!=p.source_epoch||s.seq==UINT64_MAX||
            // Slot identity is only established inside the same channel
            // inventory. A layout change cannot prove physical tuner identity.
            p.seq!=s.seq+1||s.channels!=p.num_channels||s.center!=p.freq_hz[ch]||
            s.counter!=p.wire_frequency_counter||s.noise!=p.noise_source_active||
            s.retune!=p.wire_retuning||s.generic!=(p.wire_phase_flags&0x1000u);
        if(reset)s.seeded=false;
        IQConverter::convert_uint8_to_complex_float_tracked_dc(bytes,out,p.samples_per_channel,s.i,s.q,s.seeded);
        s.source=p.source_epoch;s.seq=p.seq;s.center=p.freq_hz[ch];
        s.channels=p.num_channels;s.counter=p.wire_frequency_counter;s.noise=p.noise_source_active;
        s.retune=p.wire_retuning;s.generic=p.wire_phase_flags&0x1000u;
        return reset;
    }
};

// Ordinary assembly is shared with the offline qualification path; release
// code retains its existing input selection and downstream behavior.
inline void legacy_block(const std::shared_ptr<Instance>& inst, const RawDataPacket& packet,
                         bool wideband,bool fm_only,int active,int elements,
                         Block& b,Result& r) {
    r.decimator_id=inst->id;
    r.audio_out=inst->audio_out.load(std::memory_order_relaxed);
    r.instance=inst;
    b=Block{};
    b.decimator=inst->decimator.get();
    b.bandwidth_hz=inst->decimator->getBandwidthHz();
    b.freq_offset_hz=inst->frequency_offset_hz;
    b.out=&r.decimated_data;
    auto take=[&](int ch){
        if(b.num_channels>=static_cast<size_t>(MAX_CHANNELS))return;
        if(ch>=0&&ch<static_cast<int>(packet.channel_iq_data.size())){
            b.ptrs[b.num_channels]=packet.channel_iq_data[ch].data();
            b.lens[b.num_channels]=packet.channel_iq_data[ch].size();
        }
        ++b.num_channels;
    };
    if(wideband)take(inst->tuner_channel.load(std::memory_order_relaxed));
    else if(fm_only)take(active);
    else for(int ch=0;ch<elements;++ch)take(ch);
}

// Offline receiver integration; no new decoder/audio admission. One object
// owned by the sequential receiver processing thread. A Job binds the exact
// instance, source packet, output object and immutable placement; never look
// up a VFO number to decide what a finished block represents.
inline std::atomic<uint64_t> producer_segment_highwater{0};
inline uint64_t allocate_producer_segment(){
    auto old=producer_segment_highwater.load(std::memory_order_relaxed);
    while(old!=UINT64_MAX&&!producer_segment_highwater.compare_exchange_weak(
        old,old+1,std::memory_order_relaxed)){}
    return old==UINT64_MAX?0:old+1;
}
class ReceiverSelection {
public:
    enum class Kind { closed, manual, managed };
    enum class Outcome { rejected, manual, managed_empty, managed_qualified };
    struct Job {
        Kind kind=Kind::closed;
        std::shared_ptr<Instance> instance;
        std::shared_ptr<Publication> authority;
        std::optional<RoleStamp> role;
        std::optional<Provenance> provenance;
        const RawDataPacket* packet=nullptr;
        Result* result=nullptr;
        uint64_t source=0,wire=0,seq=0;
        Clock::time_point time;
        bool finished=false;
    private:
        friend class ReceiverSelection;
        bool mintable=false;
        Snapshot selected;
        bool managed_observed=false;
        bool manual_mintable=false;
        ManualDomain manual_domain;
        bool manual_history_reset=false;
#ifdef TT01_OPERATIONAL_BUILD
        bool ordinary=false;
#endif
        uint64_t origin_loss=0;
        ManualRf manual_rf;
        dig::Mode manual_mode=dig::Mode::OFF;
        std::string manual_plugin;
        dig::Options manual_options;
        std::shared_ptr<dig::DigitalDecoder> decoder;
        uint64_t segment=0,pos=0;
#ifdef TT01_D2_MANAGER_QUALIFICATION
        uint64_t audio_selection=0;
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        uint64_t audio_stream=0;
#endif

        const std::complex<float>* qualified_data=nullptr;
        size_t qualified_size=0;
        uint32_t input_count=0,input_channels=0;
        float qualified_rate=0;
    public:
        Job()=default;
        Job(Job&&)=default;
        Job& operator=(Job&&)=default;
        Job(const Job&)=delete;
        Job& operator=(const Job&)=delete;
    };
private:
    struct History {
        std::weak_ptr<Instance> owner; ProducerHistory dsp; bool managed=false, reset_manual=false;
        uint64_t segment=0,pos=0,manual_segment=0,manual_seq=0,manual_source=0,manual_wire=0;
        RoleStamp manual_role;ManualDomain manual_domain;
        uint64_t manual_loss=0;
        Snapshot observed_placement;
        uint64_t observed_seq=0,observed_source=0,observed_wire=0;
        uint64_t manual_raw=0,managed_raw=0;
        bool manual_pending=false,managed_pending=false;
    };
    std::unordered_map<uint64_t,History> histories_;
    History& history(const std::shared_ptr<Instance>& inst) {
        auto& h=histories_[inst->serial];
        if(h.owner.lock()!=inst){h=History{};h.owner=inst;}
        return h;
    }
    static int wire_mode(uint32_t f) {
        return (f&0x2000u)?3:(f&0x800u)?2:(f&0x400u)?1:0;
    }
    static bool live(const std::shared_ptr<Instance>& inst) {
        return inst&&!inst->being_deleted.load()&&inst->enabled.load();
    }
    static bool actual_tuple(const Instance& inst,const Tuple& t) {
        if(inst.serial!=t.instance || inst.digital_serial.load()!=t.decoder ||
            inst.digital_mode.load()!=static_cast<int>(dig::Mode::PLUGIN) ||
            inst.demod_mode.load()!=DemodulatorMode::DIGITAL ||
            inst.tuner_channel.load()!=t.tuner || inst.bandwidth_hz.load()!=t.bandwidth ||
            inst.decimator->getBandwidthHz()!=t.bandwidth ||
            inst.frequency_offset_hz.load()!=t.offset) return false;
        auto dd=inst.getDigital();
        return dd&&dd->mode()==dig::Mode::PLUGIN&&dd->plugin_id()==t.plugin&&
            dd->options().plugin==t.options&&!dd->wants_array()&&!dd->wants_multichannel()&&
            !dd->wants_streams();
    }
    static bool packet_ok(const RawDataPacket& p) {
        return iq_ingress::packet_current(p)&&wire_mode(p.wire_phase_flags)==2&&
            !p.wire_playback&&!p.wire_retuning&&!p.noise_source_active;
    }
    static void zero_block(const std::shared_ptr<Instance>& inst,Block& b,Result& r) {
        // decimateVfos requires nonnull decimator/out even for zero channels.
        r=Result{};
        r.decimator_id=inst->id;r.instance=inst;
        b=Block{};b.decimator=inst->decimator.get();b.out=&r.decimated_data;
    }
    static bool binding(const Job& j,const RawDataPacket& p,const Block& b,const Result& r) {
        return j.packet==&p&&j.result==&r&&r.instance==j.instance&&
            r.decimator_id==j.instance->id&&b.decimator==j.instance->decimator.get()&&
            b.out==&r.decimated_data&&j.source==p.source_epoch&&j.wire==p.wire_continuity&&
            j.seq==p.seq&&j.time==p.timestamp;
    }
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
    // Exact cold cascade alignment: outputs at raw indices 0,D,2D...
    // A completed channel receipt carries a positive actual factor.
    static bool count_receipt(const Block& b,const Result& r,uint64_t previous){
        const auto& o=r.decimated_data;
        if(b.num_channels!=1||!b.ptrs[0]||!b.lens[0]||
           b.lens[0]>UINT64_MAX-previous||o.num_channels!=1||o.channels.size()!=1)return false;
        const auto& c=o.channels[0];
        const uint64_t d=decimation_for_bandwidth(b.bandwidth_hz);
        if(!d||o.decimation_used!=int(d)||c.decimation_used!=int(d)||
           c.channel_id!=0||c.output_rate_hz!=o.output_rate_hz||
           c.freq_offset_hz!=o.freq_offset_hz||c.num_samples!=o.min_samples||
           c.samples.size()!=o.min_samples)return false;
        auto ceildiv=[&](uint64_t n){return n/d+uint64_t(n%d!=0);};
        return o.min_samples==ceildiv(previous+b.lens[0])-ceildiv(previous);
    }
    static bool exact_input(const Job& j,const RawDataPacket& p,int t){
        return t>=0&&t<MAX_CHANNELS&&static_cast<uint32_t>(t)<p.num_channels&&
            p.num_channels==j.input_channels&&p.num_channels<=MAX_CHANNELS&&
            p.samples_per_channel==j.input_count&&j.input_count&&j.input_count<=65536&&
            static_cast<size_t>(t)<p.channel_iq_data.size()&&
            p.channel_iq_data[t].size()==j.input_count;
    }
    bool current_managed_job(const Job& j){
        if(!j.instance||!j.managed_observed||!j.selected||!j.role||!j.authority)return false;
        auto& h=history(j.instance);
        return h.observed_placement==j.selected&&h.observed_seq==j.seq&&
            h.observed_source==j.source&&h.observed_wire==j.wire;
    }
    // Only an exact current observed obligation can retire its placement.
    // An already superseded source or replacement cannot mutate new history.
    bool fail_managed(Job& j){
        if(!current_managed_job(j))return false;
        bool retired=iq_ingress::admit_epochs(j.source,j.wire,[&]{
            return j.authority->admit(j.selected,*j.role,[&]{
                return j.authority->retire_admitted(j.selected);
            });
        });
        if(retired){auto& h=history(j.instance);h.dsp.abandon();h.managed_pending=false;}
        return retired;
    }
    bool fail_manual(Job& j){
        if(!j.instance||!j.origin_loss||!j.role||!j.authority)return false;
        bool retired=iq_ingress::admit_epochs(j.source,j.wire,[&]{
            return j.manual_domain.admit(*j.authority,*j.role,j.seq,[&]{
                if(!j.authority->manual_origin_current_locked(j.seq,j.origin_loss))return false;
                j.authority->manual_origin_failed_locked(j.seq,j.origin_loss);
                return true;
            });
        });
        if(retired){auto& h=history(j.instance);h.reset_manual=true;h.manual_pending=false;h.dsp.abandon();}
        return retired;
    }
#endif
public:
    void prune() {
        for(auto i=histories_.begin();i!=histories_.end();)
            if(i->second.owner.expired())i=histories_.erase(i);else ++i;
    }
    Job prepare(const std::shared_ptr<Instance>& inst,const RawDataPacket& p,
                bool wideband,bool fm_only,int active,int elements,Block& b,Result& r) {
        Job j; j.instance=inst;j.packet=&p;j.result=&r;
#ifdef TT01_D2_MANAGER_QUALIFICATION
        j.audio_selection=audio_selection::capture(inst->id,inst->serial);
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        j.audio_stream=audio_fence::stream_id();
#endif

        j.source=p.source_epoch;j.wire=p.wire_continuity;j.seq=p.seq;j.time=p.timestamp;
        j.input_count=p.samples_per_channel;j.input_channels=p.num_channels;
        zero_block(inst,b,r);
        auto& h=history(inst);
        j.authority=registry().state(inst->serial,inst);
        if(!live(inst)||!j.authority)return j;
        j.role=j.authority->capture_role();
        if(!j.role)return j;
        if(j.role->role==Role::manual){
#ifdef TT01_OPERATIONAL_BUILD
            // Classify before qualification, never on the result of a failed native check.
            j.decoder=inst->getDigital();
            if(j.decoder){
                j.manual_mode=j.decoder->mode();j.manual_plugin=j.decoder->plugin_id();
                j.manual_options=j.decoder->options();
            }
            const bool fixed_p25=j.decoder&&j.manual_mode==dig::Mode::PLUGIN&&j.manual_plugin=="p25";
            const bool recorded=p.wire_playback&&playback::active();
            const bool native=fixed_p25&&!recorded&&(operating_mode_index()==2||wire_mode(p.wire_phase_flags)==2);
            if(!native){
                auto domain=ManualDomain::capture(wideband?inst->tuner_channel.load():-1);
                if(!domain||!p.seq||!iq_ingress::packet_current(p)||
                   !iq_ingress::admit_epochs(j.source,j.wire,[&]{
                       return domain->admit(*j.authority,*j.role,j.seq,[]{return true;});
                   }))return j;
                j.manual_domain=*domain;
                // Reset once crossing a native/managed DSP boundary, not on
                // each ordinary packet or routine legacy queue gap.
                if(h.managed||h.manual_segment||h.reset_manual){
                    inst->decimator->reset_stream_history();h.dsp.abandon();
                    h.managed=false;h.manual_segment=0;h.manual_pending=false;h.reset_manual=false;
                }
                legacy_block(inst,p,wideband,fm_only,active,elements,b,r);
                if(!j.authority->role_current(*j.role)){zero_block(inst,b,r);return j;}
                j.ordinary=true;j.kind=Kind::manual;
                return j;
            }
            // A live fixed P25 mode mismatch is not an ordinary fallback.
            if(operating_mode_index()!=2||playback::active())return j;
#endif
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
            auto domain=ManualDomain::capture(wideband?inst->tuner_channel.load():-1);
            if(!domain||!iq_ingress::packet_current(p)||!p.seq){
                h.reset_manual=true;return j;
            }
#ifndef TT01_MANUAL_ORIGIN_QUALIFICATION
            if(p.wire_retuning||p.noise_source_active){h.reset_manual=true;return j;}
#endif
            if(!iq_ingress::admit_epochs(j.source,j.wire,[&]{
                return domain->admit(*j.authority,*j.role,j.seq,[]{return true;});
            })){h.reset_manual=true;return j;}
            j.manual_domain=*domain;
#ifdef TT01_MANUAL_ORIGIN_QUALIFICATION
            const bool old_reset=h.reset_manual;
#endif
            if(!h.manual_segment||h.manual_role!=*j.role||h.manual_source!=j.source||
               h.manual_wire!=j.wire||!(h.manual_domain==*domain)||h.manual_seq==UINT64_MAX||
               j.seq!=h.manual_seq+1)h.reset_manual=true;
#ifdef TT01_MANUAL_ORIGIN_QUALIFICATION
            // The producer notices the boundary before DSP or minting.
            // Do not allow an old packet to become a new segment.
            if(!iq_ingress::admit_epochs(j.source,j.wire,[&]{
                return domain->admit(*j.authority,*j.role,j.seq,[&]{
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
                    if(h.manual_loss!=j.authority->manual_loss_epoch()||h.manual_pending)h.reset_manual=true;
#endif
                    j.origin_loss=j.authority->manual_origin_locked(j.seq,h.managed||h.reset_manual);
                    return j.origin_loss!=0;
                });
            })){h.reset_manual=old_reset;return j;}
            // For this fixed control-lane variant, known invalid input
            // is a producer loss even if no block reaches the worker.
            const auto t=domain->tuner;
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            h.manual_pending=false;
            if(!wideband||!packet_ok(p)||!exact_input(j,p,t)){
                fail_manual(j);return j;
            }
#else
            if(!wideband||!packet_ok(p)||t<0||
               static_cast<size_t>(t)>=p.channel_iq_data.size()||
               p.channel_iq_data[t].empty()){
                iq_ingress::admit_epochs(j.source,j.wire,[&]{
                    return domain->admit(*j.authority,*j.role,j.seq,[&]{
                        j.authority->manual_origin_failed_locked(j.seq,j.origin_loss);return true;
                    });
                });
                h.reset_manual=true;return j;
            }
#endif
#endif
            if(h.managed||h.reset_manual){
                h.manual_segment=allocate_producer_segment();
                if(!h.manual_segment)return j;
                j.manual_history_reset=true;
            }
            j.segment=h.manual_segment;
#endif
            if(h.managed||h.reset_manual){
                inst->decimator->reset_stream_history();h.dsp.abandon();
                h.managed=false;h.reset_manual=false;
            }
            j.decoder=inst->getDigital();
            if(j.decoder){
                j.manual_mode=j.decoder->mode();j.manual_plugin=j.decoder->plugin_id();
                j.manual_options=j.decoder->options();
            }
            legacy_block(inst,p,wideband,fm_only,active,elements,b,r);
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            if(j.decoder&&j.manual_mode==dig::Mode::PLUGIN&&j.manual_plugin=="p25"&&j.manual_domain.tuner>=0){
                const auto t=j.manual_domain.tuner;
                j.manual_rf={true,p.freq_hz[t],b.freq_offset_hz,SAMPLE_RATE/decimation_for_bandwidth(b.bandwidth_hz),b.bandwidth_hz,0};
            }
#endif
            if(!j.authority->role_current(*j.role)){zero_block(inst,b,r);return j;}
            j.kind=Kind::manual;
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            h.manual_pending=j.manual_rf.bound;
#endif
            return j;
        }
        h.managed=true;
        auto selected=j.authority->snapshot();
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
        j.selected=selected;
        if(selected&&p.seq>selected->cutoff_seq&&p.seq!=UINT64_MAX&&
           p.timestamp>selected->cutoff_time){
            j.managed_observed=iq_ingress::admit_epochs(j.source,j.wire,[&]{
                return j.authority->admit(selected,*j.role,[&]{
                    if(h.observed_placement==selected){
                        if(p.seq<=h.observed_seq)return false;
                        // A changed source/wire epoch already fences all
                        // old native evidence; permit cold recovery under
                        // the still-current placement as previously qualified.
                        if(h.observed_source==j.source&&h.observed_wire==j.wire&&
                           (h.observed_seq==UINT64_MAX||p.seq!=h.observed_seq+1||h.managed_pending)){
                            j.authority->retire_admitted(selected);
                            h.dsp.abandon();h.managed_pending=false;
                            return false;
                        }
                    }
                    h.observed_placement=selected;h.observed_seq=p.seq;
                    h.observed_source=j.source;h.observed_wire=j.wire;h.managed_pending=true;
                    return true;
                });
            });
        }
        if(!j.managed_observed)return j;
#endif
        if(!wideband||!packet_ok(p)||!selected||!actual_tuple(*inst,selected->tuple)){
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            fail_managed(j);
#endif
            h.dsp.abandon();return j;
        }
        j.provenance=h.dsp.prepare(*j.authority,p,*inst->decimator,b,r.decimated_data);
        if(!j.provenance||j.provenance->placement!=selected||
            !j.authority->role_current(*j.role)||!j.authority->current(selected)){
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            fail_managed(j);
#endif
            h.dsp.abandon();zero_block(inst,b,r);j.provenance.reset();return j;
        }
        j.decoder=inst->getDigital();
        if(!j.decoder||!j.authority->current(selected)){
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            fail_managed(j);
#endif
            h.dsp.abandon();zero_block(inst,b,r);j.provenance.reset();return j;
        }
        j.kind=Kind::managed;
        return j;
    }
    Outcome finish(Job& j,const RawDataPacket& p,const Block& b,const Result& r,bool pass_ok) {
        if(j.finished){
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            // A repeated finish cancels only an untransferred obligation.
            // After successful transfer or empty accounting it is harmless.
            if(j.mintable)fail_managed(j);
            if(j.manual_mintable&&j.manual_rf.bound)fail_manual(j);
#endif
            j.mintable=false;j.manual_mintable=false;return Outcome::rejected;
        }
        j.finished=true;
        auto reject=[&]{
            if(j.instance){
                auto& h=history(j.instance);
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
                if(j.selected){fail_managed(j);return Outcome::rejected;}
                if(j.origin_loss){fail_manual(j);return Outcome::rejected;}
                // Closed/unadmitted old jobs cannot change current history.
                if(j.kind==Kind::closed)return Outcome::rejected;
#endif
                h.dsp.abandon();
                if(j.kind==Kind::manual)h.reset_manual=true;
#ifdef TT01_MANUAL_ORIGIN_QUALIFICATION
                if(j.origin_loss&&j.role&&j.authority)
                    iq_ingress::admit_epochs(j.source,j.wire,[&]{
                        return j.manual_domain.admit(*j.authority,*j.role,j.seq,[&]{
                            j.authority->manual_origin_failed_locked(j.seq,j.origin_loss);return true;
                        });
                    });
#endif
            }
            return Outcome::rejected;
        };
        if(!pass_ok||j.kind==Kind::closed||!live(j.instance)||!j.role||
            !j.authority||!j.authority->role_current(*j.role)||!binding(j,p,b,r))return reject();
        if(j.kind==Kind::manual){
            if(j.decoder!=j.instance->getDigital())return reject();
#ifdef TT01_OPERATIONAL_BUILD
            if(j.ordinary){
                if(!iq_ingress::admit_epochs(j.source,j.wire,[&]{
                    return j.manual_domain.admit(*j.authority,*j.role,j.seq,[]{return true;});
                }))return reject();
                j.manual_mintable=bool(j.decoder);
                return Outcome::manual;
            }
#endif
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            if(j.manual_rf.bound){
                const auto t=j.manual_domain.tuner;
                const auto& f=j.manual_rf;const auto& o=r.decimated_data;
                if(!packet_ok(p)||t!=j.instance->tuner_channel.load()||
                   !exact_input(j,p,t)||
                   b.num_channels!=1||b.ptrs[0]!=p.channel_iq_data[t].data()||
                   b.lens[0]!=p.channel_iq_data[t].size()||p.freq_hz[t]!=f.center||
                   b.freq_offset_hz!=f.offset||b.bandwidth_hz!=f.bandwidth||
                   j.instance->frequency_offset_hz.load()!=f.offset||
                   j.instance->decimator->getBandwidthHz()!=f.bandwidth||
                   o.freq_offset_hz!=f.offset||o.bandwidth_hz!=f.bandwidth||o.output_rate_hz!=f.rate||
                   o.num_channels!=1||o.channels.size()!=1||o.channels[0].samples.size()!=o.min_samples)
                    return reject();
                j.manual_rf.count=o.min_samples;
                j.qualified_data=o.channels[0].samples.data();
            }
#endif
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
            if(!iq_ingress::admit_epochs(j.source,j.wire,[&]{
                return j.manual_domain.admit(*j.authority,*j.role,j.seq,[&]{
#ifdef TT01_MANUAL_ORIGIN_QUALIFICATION
                    if(!j.authority->manual_origin_current_locked(j.seq,j.origin_loss))return false;
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
                    if(j.manual_rf.bound){
                        auto& h=history(j.instance);
                        const auto previous=j.manual_history_reset?0:h.manual_raw;
                        if(!count_receipt(b,r,previous))return false;
                        h.manual_raw=previous+b.lens[0];
                        if(!j.manual_rf.count){
                            // Terminal accounting of a consumed zero-output
                            // input; never manufacture a native sample block.
                            auto epoch=j.authority->manual_origin_submission_locked(*j.role,j.segment,j.seq,j.origin_loss,false);
                            h.manual_pending=false;
                            if(epoch!=j.origin_loss){h.reset_manual=true;return false;}
                        }
                    }
#endif
                    return true;
#else
                    return true;
#endif
                });
            }))return reject();
            auto& h=history(j.instance);
            h.manual_role=*j.role;h.manual_source=j.source;h.manual_wire=j.wire;
            h.manual_domain=j.manual_domain;h.manual_seq=j.seq;h.manual_loss=j.origin_loss;
#endif
            j.manual_mintable=bool(j.decoder);
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            if(j.manual_rf.bound&&!j.manual_rf.count)j.manual_mintable=false;
#endif
            return Outcome::manual;
        }
        const auto& z=*j.provenance;
        const auto& t=z.placement->tuple;
        const auto& o=r.decimated_data;
        if(!packet_ok(p)||!actual_tuple(*j.instance,t)||!j.authority->current(z.placement)||
            z.packet_seq!=p.seq||z.packet_time!=p.timestamp||z.input<0||
            static_cast<size_t>(z.input)>=p.channel_iq_data.size()||
            b.num_channels!=1||b.ptrs[0]!=p.channel_iq_data[z.input].data()||
            b.lens[0]!=p.channel_iq_data[z.input].size()||
            b.freq_offset_hz!=z.offset||b.bandwidth_hz!=z.bandwidth||
            p.freq_hz[z.input]!=z.observed_center||
            o.num_channels!=1||o.channels.size()!=1||
            o.channels[0].samples.size()!=o.min_samples||
            o.freq_offset_hz!=z.offset||o.bandwidth_hz!=z.bandwidth||
            o.output_rate_hz!=SAMPLE_RATE/decimation_for_bandwidth(z.bandwidth))return reject();
        // Final recheck after all mutable readbacks. Still not a linearized
        // worker submission; a retirement immediately after this is possible.
        if(!packet_ok(p)||!j.authority->current(z.placement)||
           !j.authority->role_current(*j.role)||!live(j.instance))return reject();
        auto& h=history(j.instance);
        if(j.instance->getDigital()!=j.decoder)return reject();
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
        const auto previous=z.history_reset?0:h.managed_raw;
        if(!current_managed_job(j)||!h.managed_pending||!exact_input(j,p,z.input)||
           !count_receipt(b,r,previous))return reject();
        h.managed_raw=previous+b.lens[0];
#endif
        if(z.history_reset){
            h.segment=allocate_producer_segment();h.pos=0;
            if(!h.segment)return reject();
        }
        if(!h.segment||o.min_samples>UINT64_MAX-h.pos)return reject();
        j.segment=h.segment;j.pos=h.pos;h.pos+=o.min_samples;
        j.mintable=o.min_samples>0;
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
        if(!j.mintable)h.managed_pending=false;
#endif
        j.qualified_data=o.channels[0].samples.data();j.qualified_size=o.min_samples;j.qualified_rate=o.output_rate_hz;
        return j.mintable?Outcome::managed_qualified:Outcome::managed_empty;
    }
    std::shared_ptr<const ManualEnvelope> take_manual(Job& j,Result& r){
        if(!j.finished||!j.manual_mintable)return {};
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
        if(j.manual_rf.bound&&(j.result!=&r||r.instance!=j.instance||!j.decoder)){
            j.manual_mintable=false;fail_manual(j);return {};
        }
#endif
        if(j.result!=&r||r.instance!=j.instance||!j.decoder)return {};
        j.manual_mintable=false;
#ifdef TT01_OPERATIONAL_BUILD
        if(j.ordinary){
            if(!j.authority->role_current(*j.role)||j.instance->getDigital()!=j.decoder||
               !iq_ingress::admit_epochs(j.source,j.wire,[&]{
                   return j.manual_domain.admit(*j.authority,*j.role,j.seq,[]{return true;});
               }))return {};
            return std::shared_ptr<const ManualEnvelope>(new ManualEnvelope(
                j.decoder.get(),j.authority,*j.role,j.manual_mode,j.manual_plugin,j.manual_options,
                j.seq,j.source,j.wire,0,j.manual_domain,0,{}));
        }
#endif
        if(!j.authority->role_current(*j.role)||j.instance->getDigital()!=j.decoder){
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            fail_manual(j);
#endif
            return {};
        }
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
        if(!iq_ingress::admit_epochs(j.source,j.wire,[&]{
            return j.manual_domain.admit(*j.authority,*j.role,j.seq,[&]{
#ifdef TT01_MANUAL_ORIGIN_QUALIFICATION
                return j.authority->manual_origin_current_locked(j.seq,j.origin_loss);
#else
                return true;
#endif
            });
        })){
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            fail_manual(j);
#else
            history(j.instance).reset_manual=true;
#endif
            return {};
        }
#endif
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
        if(j.manual_rf.bound){
            const auto& o=r.decimated_data;const auto& f=j.manual_rf;
            if(o.num_channels!=1||o.channels.size()!=1||o.min_samples!=f.count||
               o.channels[0].samples.size()!=f.count||o.channels[0].samples.data()!=j.qualified_data||
               o.output_rate_hz!=f.rate||o.bandwidth_hz!=f.bandwidth||o.freq_offset_hz!=f.offset){
                fail_manual(j);return {};
            }
            history(j.instance).manual_pending=false;
        }
#endif
        return std::shared_ptr<const ManualEnvelope>(new ManualEnvelope(
            j.decoder.get(),j.authority,*j.role,j.manual_mode,j.manual_plugin,j.manual_options,j.seq,j.source,j.wire,j.segment,j.manual_domain,j.origin_loss,j.manual_rf));
    }
    // Single-use transfer of the qualified result. No copy or RF reread.
    std::shared_ptr<const WorkerEnvelope> take(Job& j,Result& r){
        if(!j.finished||!j.mintable)return {};
        j.mintable=false;
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
        if(!current_managed_job(j)||!history(j.instance).managed_pending||
           !iq_ingress::admit_epochs(j.source,j.wire,[&]{return j.authority->admit(j.selected,*j.role,[]{return true;});})){
            fail_managed(j);return {};
        }
#endif
        if(j.result!=&r||!j.decoder){
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            fail_managed(j);
#endif
            return {};
        }
        auto& o=r.decimated_data;
        if(o.channels.size()!=1||o.channels[0].samples.size()!=j.qualified_size||
            o.min_samples!=j.qualified_size||o.channels[0].samples.data()!=j.qualified_data||
            o.output_rate_hz!=j.qualified_rate||!o.min_samples){
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
            fail_managed(j);
#endif
            return {};
        }
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
        history(j.instance).managed_pending=false;
#endif
        return std::shared_ptr<const WorkerEnvelope>(new WorkerEnvelope(
            j.decoder.get(),j.authority,*j.role,*j.provenance,j.source,j.wire,j.segment,j.pos,
            o.output_rate_hz,std::move(o.channels[0].samples)
#ifdef TT01_D2_MANAGER_QUALIFICATION
            ,j.audio_selection
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
            ,j.audio_stream
#endif

            ));
    }
    bool submit(Job& j,Result& r){
        auto envelope=take(j,r);
        if(!envelope)return false;
        bool submitted=j.decoder->push_managed(std::move(envelope));
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
        if(!submitted)fail_managed(j);
#endif
        return submitted;
    }
    static void withhold(Outcome o,Result& r) {
        if(o==Outcome::manual)return;
        // No managed or rejected result can reach legacy array/AUTO, MUSIC,
        // decoder, transcription, recorder or FM queue consumers.
        r=Result{};
    }
};
} // namespace managed_iq
