#include "signal_processing/audio_mixer.hpp"
#include "config.hpp"
#ifdef TT01_D2_MIXER_QUALIFICATION
#include "networking/managed_audio_mix.hpp"
#ifdef TT01_D2_PUBLISH_QUALIFICATION
#include "globals.hpp"
#include "networking/binary_message.hpp"
#endif

#include <liquid/liquid.h>
#include <unordered_map>
namespace managed_iq::audio_mix {
namespace {
struct Entry {std::weak_ptr<AudioMixer::Channel> owner;ManualKey key;};
std::mutex keys_mu;
std::unordered_map<const AudioMixer::Channel*,Entry> keys;
void forget(const std::shared_ptr<AudioMixer::Channel>& c){std::lock_guard lk(keys_mu);
#ifdef TT01_D2_PUBLISH_QUALIFICATION
    if(keys.count(c.get()))audio_fence::mark();
#endif
    keys.erase(c.get());}
void remember(const std::shared_ptr<AudioMixer::Channel>& c,const ManualKey& k){
    std::lock_guard lk(keys_mu);
    for(auto i=keys.begin();i!=keys.end();)if(i->second.owner.expired())i=keys.erase(i);else ++i;
    keys[c.get()]={c,k};
}
std::optional<ManualKey> key_of(const std::shared_ptr<AudioMixer::Channel>& c){
    std::lock_guard lk(keys_mu);auto i=keys.find(c.get());
    if(i==keys.end()||i->second.owner.lock()!=c)return {};
    return i->second.key;
}
}
bool channel_matches(const std::shared_ptr<AudioMixer::Channel>& c,const ManualKey& k){
    auto found=key_of(c);return found&&*found==k&&current(k);
}
#ifdef TT01_D2_PUBLISH_QUALIFICATION
namespace {
struct Transaction {uint64_t rev=0;bool entered=false;Candidate candidate;};
thread_local Transaction* pending=nullptr;
thread_local bool publishing=false;
// All encoder sidecar state is on the single manager/audio timer thread.
struct EncoderState {
    bool dirty=true;
    uint64_t epoch=0,seq=0,rev=0;
    std::vector<ManualWitness> manual;
    std::vector<pcm::EncoderWitness> managed;
};
EncoderState encoder;
bool active(){return fm_enabled.load()&&!sweep_mode_enabled.load()&&audio_mixer.is_processing_enabled();}
bool current_candidate(const Candidate& c){
    if(!active())return false;
    for(const auto& m:c.manual)if(!channel_matches(m.channel,m.key))return false;
    for(const auto& r:c.managed)if(!pcm::delivery_current(r))return false;
    return true;
}
bool history_current(){
    for(const auto& m:encoder.manual)if(!channel_matches(m.channel,m.key))return false;
    for(const auto& w:encoder.managed)if(!pcm::encoder_authority_current(w))return false;
    return true;
}
bool prepare_encoder(OpusEncoder* enc,const Transaction& t){
    std::vector<pcm::EncoderWitness> managed;
    for(const auto& r:t.candidate.managed){
        if(r.slices.empty()||!r.slices.front().batch)return false;
        const auto& b=*r.slices.front().batch;
        managed.push_back({b.vfo,b.stamp,b.selection,b.audio_stream});
    }
    // Absence of new PCM is not retirement. Preserve codec history only
    // while every represented identity remains independently current.
    // New/replaced contributors, dirty state and revision changes reset.
    bool reset=encoder.dirty||encoder.rev!=t.rev||encoder.manual!=t.candidate.manual||!history_current();
    if(!reset)for(const auto& w:managed){
        bool found=false;
        for(const auto& old:encoder.managed)if(old.vfo==w.vfo&&old.key()==w.key()){found=true;break;}
        if(!found){reset=true;break;}
    }
    if(reset){
        if(encoder.epoch==UINT64_MAX||opus_encoder_ctl(enc,OPUS_RESET_STATE)!=OPUS_OK)return false;
        ++encoder.epoch;
        encoder.managed=std::move(managed);
    }
    encoder.rev=t.rev;encoder.manual=t.candidate.manual;
    encoder.dirty=false;return history_current();
}
}
#ifdef TT01_D3_TRANSPORT_QUALIFICATION
bool publish_packet_versioned(size_t n,const RevisionSink& sink){
#else
bool publish_packet(size_t n,const Sink& sink){
#endif
    if(publishing||capture_hook||!sink||n!=AUDIO_SAMPLES_PER_PACKET||!active()){encoder.dirty=true;return false;}
    Transaction t;t.rev=audio_fence::capture();
    struct Scope {Scope(Transaction& t){publishing=true;pending=&t;}~Scope(){pending=nullptr;publishing=false;}} scope(t);
    try{
        auto bytes=audio_mixer.get_opus_packet(n);pending=nullptr;
        if(bytes.empty()){encoder.dirty=true;return false;}
        BinaryMessage m;m.add_value(uint32_t(1));m.add_value(uint32_t(n));m.add_value(AUDIO_SAMPLE_RATE);
        m.add_value(uint32_t(bytes.size()));m.add_vector(bytes);
        const auto wire=m.to_string();
        if(encoder.seq==UINT64_MAX||!current_candidate(t.candidate)){encoder.dirty=true;return false;}
        if(stage_hook)stage_hook(Stage::before_commit,-1);
        if(!history_current()||!audio_fence::commit(t.rev)){
            encoder.dirty=true;return false;
        }
        // Commit is the admission point. No async staging, no retry and no
        // receiver locks span the synchronous sink. Later invalidations cannot
        // recall a committed packet; D3 owns client discontinuity.
        const auto seq=++encoder.seq;
#ifdef TT01_D3_TRANSPORT_QUALIFICATION
        if(!sink(wire,t.rev,encoder.epoch,seq)){encoder.dirty=true;return false;}
#else
        if(!sink(wire,encoder.epoch,seq)){encoder.dirty=true;return false;}
#endif
        return true;
    }catch(...){encoder.dirty=true;return false;}
}
#ifdef TT01_D3_TRANSPORT_QUALIFICATION
bool publish_packet(size_t n,const Sink& sink){
    if(!sink)return false;
    return publish_packet_versioned(n,[&](std::string_view w,uint64_t,uint64_t e,uint64_t s){return sink(w,e,s);});
}
#endif
#endif
bool resample(const Read& r,size_t n,std::vector<float>& out){
    out.assign(n,0.0f);
    if(n%6||r.samples>n/6||r.result!=pcm::DeliveryQueue::Result::ready||!r.samples)return false;
    size_t pos=0;
    for(const auto& s:r.slices){
        if(!s.batch||s.begin>s.batch->samples.size()||s.count>s.batch->samples.size()-s.begin||s.count>(n-pos)/6)return false;
        auto q=firinterp_rrrf_create_kaiser(6,8,60.0f);
        if(!q)return false;
        // 2*m+1 input taps; replay only same immutable batch history.
        // No retained DSP or AGC state can cross batch or authority boundaries.
        float y[6];const auto start=s.begin>16?s.begin-16:0;
        for(size_t i=start;i<s.begin+s.count;++i){
            firinterp_rrrf_execute(q,std::tanh(s.batch->samples[i]),y);
            if(i>=s.begin){std::copy_n(y,6,out.begin()+pos);pos+=6;}
        }
        firinterp_rrrf_destroy(q);
    }
    return pos==r.samples*6;
}
}
#endif
#include <algorithm>
#include <chrono>
#include <cmath>
#include <iostream>

namespace {
int64_t steady_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

const char* mode_name(DemodulatorMode m) {
    switch (m) {
        case DemodulatorMode::WBFM: return "WBFM";
        case DemodulatorMode::NBFM: return "NBFM";
        case DemodulatorMode::AM: return "AM";
        case DemodulatorMode::DIGITAL: return "DIGI";
    }
    return "?";
}
}  // namespace

AudioMixer::AudioMixer() = default;

AudioMixer::~AudioMixer() {
    if (enc_) opus_encoder_destroy(enc_);
}

std::shared_ptr<AudioMixer::Channel> AudioMixer::channel(int vfo) {
    if (!enabled_.load()) return nullptr;
#ifdef TT01_D2_MIXER_QUALIFICATION
    namespace am=managed_iq::audio_mix;
    auto key=am::capture(decimator_manager.getDecimator(vfo));
    if(!key)return nullptr;
#endif
    std::lock_guard<std::mutex> lk(mu_);
#ifdef TT01_D2_MIXER_QUALIFICATION
    if(!enabled_.load())return nullptr;
    for(auto it=ch_.begin();it!=ch_.end();++it)if((*it)->vfo==vfo){
        auto old=am::key_of(*it);
        if(old&&*old==*key)return *it;
        if(old&&(old->serial>key->serial||(old->serial==key->serial&&(old->selection>key->selection||old->role.epoch>key->role.epoch
#ifdef TT01_D2_PUBLISH_QUALIFICATION
            ||old->audio_stream>key->audio_stream
#endif
            ))))return nullptr;
        am::forget(*it);ch_.erase(it);break;
    }
#else
    for (const auto& c : ch_)
        if (c->vfo == vfo) return c;
#endif
    auto c = std::make_shared<Channel>(vfo);
#ifdef TT01_D2_MIXER_QUALIFICATION
    am::remember(c,*key);
#endif
    c->fed_ms = steady_ms();
    ch_.push_back(c);
    std::cout << "Audio: D" << vfo << " joins the mix (" << ch_.size() << " VFO"
              << (ch_.size() == 1 ? "" : "s") << ")" << std::endl;
    return c;
}

void AudioMixer::retain(const std::vector<int>& vfos) {
    std::lock_guard<std::mutex> lk(mu_);
    ch_.erase(std::remove_if(ch_.begin(), ch_.end(), [&](const std::shared_ptr<Channel>& c) {
                  const bool drop=std::find(vfos.begin(), vfos.end(), c->vfo) == vfos.end();
#ifdef TT01_D2_MIXER_QUALIFICATION
                  if(drop)managed_iq::audio_mix::forget(c);
#endif
                  return drop;
              }),
              ch_.end());
}

void AudioMixer::reset() {
    std::vector<std::shared_ptr<Channel>> chs;
    {
        std::lock_guard<std::mutex> lk(mu_);
        chs = ch_;
#ifdef TT01_D2_MIXER_QUALIFICATION
        for(const auto& c:ch_)managed_iq::audio_mix::forget(c);
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::discontinuity();
#endif
        ch_.clear();
#endif
    }
    for (const auto& c : chs) c->demod.reset_audio_buffer();
}

void AudioMixer::enable_processing() {
    enabled_ = true;
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::discontinuity();
#endif

    std::cout << "Audio processing enabled" << std::endl;
}

void AudioMixer::disable_processing() {
    enabled_ = false;
    std::lock_guard<std::mutex> lk(mu_);
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        managed_iq::audio_fence::discontinuity();
#endif

#ifdef TT01_D2_MIXER_QUALIFICATION
    for(const auto& c:ch_)managed_iq::audio_mix::forget(c);
#endif
    ch_.clear();
}

std::vector<unsigned char> AudioMixer::get_opus_packet(size_t n) {
    if (n == 0) return {};
#ifdef TT01_D2_PUBLISH_QUALIFICATION
    if(auto* t=managed_iq::audio_mix::pending){
        if(t->entered)return {};
        t->entered=true;
    }else if(!managed_iq::audio_mix::capture_hook||managed_iq::audio_mix::publishing)return {};
#endif

    if (!enc_ && !enc_failed_) {
        // the live audio's settings (were FMDemodulatorRobust's): 48 kHz mono,
        // 32 kbit/s VBR, complexity 5
        int err = 0;
        enc_ = opus_encoder_create(static_cast<opus_int32>(AUDIO_SAMPLE_RATE), 1, OPUS_APPLICATION_AUDIO, &err);
        if (err != OPUS_OK || !enc_) {
            std::cerr << "Failed to create the audio Opus encoder: " << opus_strerror(err) << std::endl;
            enc_ = nullptr;
            enc_failed_ = true;
        } else {
            opus_encoder_ctl(enc_, OPUS_SET_BITRATE(32000));
            opus_encoder_ctl(enc_, OPUS_SET_COMPLEXITY(5));
            opus_encoder_ctl(enc_, OPUS_SET_SIGNAL(OPUS_SIGNAL_MUSIC));
            opus_encoder_ctl(enc_, OPUS_SET_VBR(1));
            opus_encoder_ctl(enc_, OPUS_SET_VBR_CONSTRAINT(0));
            out_.resize(4000);   // the largest Opus packet
        }
    }
    if (!enc_) return {};

    // The channels heard now; those not fed for IDLE_MS leave the mix
    std::vector<std::shared_ptr<Channel>> chs;
    {
        std::lock_guard<std::mutex> lk(mu_);
        const int64_t now = steady_ms();
        ch_.erase(std::remove_if(ch_.begin(), ch_.end(), [&](const std::shared_ptr<Channel>& c) {
                      const bool drop=now - c->fed_ms.load() > IDLE_MS;
#ifdef TT01_D2_MIXER_QUALIFICATION
                      if(drop)managed_iq::audio_mix::forget(c);
#endif
                      return drop;
                  }),
                  ch_.end());
        chs = ch_;
    }

    // Sum: when one VFO is open at a time (the usual case with squelch) it
    // plays at its own level; overlapping ones are soft-limited like a
    // single demodulator's output
    mix_.assign(n, 0.0f);
#ifdef TT01_D2_MIXER_QUALIFICATION
    namespace am=managed_iq::audio_mix;
    am::Candidate candidate;
#endif
    for (const auto& c : chs) {
#ifdef TT01_D2_MIXER_QUALIFICATION
        auto key=am::key_of(c);
        if(!key)continue;
        if(am::stage_hook)am::stage_hook(am::Stage::manual_snapshot,c->vfo);
        if(!am::channel_matches(c,*key))continue;
#endif
        const std::vector<float> a = c->demod.get_audio_buffer(n);
#ifdef TT01_D2_MIXER_QUALIFICATION
        if(!am::channel_matches(c,*key))continue;
        candidate.manual.push_back({c,*key});
#endif
        const size_t m = std::min(n, a.size());
        for (size_t i = 0; i < m; i++) mix_[i] += a[i];
    }
#ifdef TT01_D2_MIXER_QUALIFICATION
    // Qualification only: no managed samples ever enter opus_encode here.
    // D2D will own the final validation and publication transaction.
    if(am::capture_hook
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        ||am::pending
#endif
){
        if(enabled_.load()&&n%6==0&&n/6<=managed_iq::pcm::buffer_cap){
            for(int v=0;v<16;++v){
                auto r=managed_iq::pcm::take_samples(v,n/6);
                if(!managed_iq::pcm::delivery_current(r))continue;
                std::vector<float> x;
                if(!am::resample(r,n,x))continue;
                if(am::stage_hook)am::stage_hook(am::Stage::managed_resampled,v);
                if(!managed_iq::pcm::delivery_current(r))continue;
                for(size_t i=0;i<n;++i)mix_[i]+=x[i];
                candidate.managed.push_back(std::move(r));
            }
        }
        candidate.samples=mix_;
        if(am::capture_hook){am::capture_hook(candidate);return {};}
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        am::pending->candidate=std::move(candidate);
#endif

    }
#endif
#ifdef TT01_D2_PUBLISH_QUALIFICATION
    if(am::stage_hook)am::stage_hook(am::Stage::before_encode,-1);
    if(!am::pending||!am::current_candidate(am::pending->candidate)||
       am::pending->rev!=managed_iq::audio_fence::capture()||!am::prepare_encoder(enc_,*am::pending))return {};
#endif
    pcm_.resize(n);
    for (size_t i = 0; i < n; i++) {
        float v = mix_[i];
        if (std::fabs(v) > 0.95f) v = 0.95f * std::tanh(v / 0.95f);
        pcm_[i] = static_cast<opus_int16>(std::clamp(v, -1.0f, 1.0f) * 32767.0f);
    }

    const opus_int32 bytes = opus_encode(enc_, pcm_.data(), static_cast<int>(n), out_.data(),
                                         static_cast<opus_int32>(out_.size()));
#ifdef TT01_D2_PUBLISH_QUALIFICATION
    if(am::stage_hook)am::stage_hook(am::Stage::after_encode,-1);
#endif
    if (bytes < 0) {
        std::cerr << "Opus encoding failed: " << opus_strerror(bytes) << std::endl;
        return {};
    }
    return std::vector<unsigned char>(out_.begin(), out_.begin() + bytes);
}

AudioMixer::Stats AudioMixer::stats() const {
    std::vector<std::shared_ptr<Channel>> chs;
    {
        std::lock_guard<std::mutex> lk(mu_);
        chs = ch_;
    }
    Stats st;
    st.channels = static_cast<int>(chs.size());
    for (const auto& c : chs) {
        size_t w, r, over, under;
        c->demod.get_buffer_stats(w, r, over, under);
        st.over += over;
        st.under += under;
        st.fill = std::max(st.fill, c->demod.get_buffer_fill());
        st.signal = std::max(st.signal, c->demod.get_signal_strength());
        if (!st.modes.empty()) st.modes += ", ";
        st.modes += "D" + std::to_string(c->vfo) + " " + mode_name(c->mode.load());
    }
    return st;
}
