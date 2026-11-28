#pragma once
// D2C offline mixer seam. No managed encoder/publication rights.
#include "networking/managed_pcm.hpp"
#include "networking/managed_audio_selection.hpp"
#include "decimator_manager.hpp"
#include "signal_processing/audio_mixer.hpp"
#include <optional>
#ifdef TT01_D2_PUBLISH_QUALIFICATION
#include <functional>
#include <string_view>
#endif

namespace managed_iq::audio_mix {
struct ManualKey {
    int vfo=-1;
    uint64_t serial=0,selection=0;
    std::shared_ptr<Publication> publication;
    RoleStamp role;
#ifdef TT01_D2_PUBLISH_QUALIFICATION
    uint64_t audio_stream=0;
#endif

    bool operator==(const ManualKey&)const=default;
};
inline std::optional<ManualKey> capture(const std::shared_ptr<DecimatorManager::DecimatorInstance>& i){
    if(!i||!i->enabled.load()||!i->audio_out.load()||i->being_deleted.load())return {};
    auto p=registry().state(i->serial,i);
    auto role=p?p->capture_role():std::nullopt;
    auto s=audio_selection::capture(i->id,i->serial);
    if(!role||role->role!=Role::manual||!s||!p->role_current(*role))return {};
    return ManualKey{i->id,i->serial,s,p,*role
#ifdef TT01_D2_PUBLISH_QUALIFICATION
        ,audio_fence::stream_id()
#endif
};
}
inline bool current(const ManualKey& k){
    auto i=decimator_manager.getDecimator(k.vfo);
    auto now=capture(i);
    return now&&*now==k;
}
bool channel_matches(const std::shared_ptr<AudioMixer::Channel>&,const ManualKey&);
using Read=pcm::DeliveryQueue::Read;
struct ManualWitness {std::shared_ptr<AudioMixer::Channel> channel;ManualKey key;bool operator==(const ManualWitness&)const=default;};
struct Candidate {
    std::vector<float> samples;
    std::vector<ManualWitness> manual;
    std::vector<Read> managed;
};
enum class Stage { manual_snapshot, managed_resampled, before_encode, after_encode, before_commit };
inline void (*stage_hook)(Stage,int)=nullptr;
inline void (*capture_hook)(const Candidate&)=nullptr;
bool resample(const Read&,size_t,std::vector<float>&);
#ifdef TT01_D2_PUBLISH_QUALIFICATION
using Sink=std::function<bool(std::string_view,uint64_t,uint64_t)>;
// uWS manager thread only. Sink receives legacy wire bytes and internal epoch/sequence.
bool publish_packet(size_t,const Sink&);
#ifdef TT01_D3_TRANSPORT_QUALIFICATION
using RevisionSink=std::function<bool(std::string_view,uint64_t,uint64_t,uint64_t)>;
bool publish_packet_versioned(size_t,const RevisionSink&);
#endif
#endif

}
