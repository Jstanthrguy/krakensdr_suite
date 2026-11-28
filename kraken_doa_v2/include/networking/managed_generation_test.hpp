#pragma once
#include "networking/managed_worker_envelope.hpp"
#include <string_view>
// Offline generation-transition qualification only. No managed SAMPLES
// are transmitted by this subgate.
namespace managed_iq::generation_test {
enum class Stage { closed, reset_sent, rf_sent, option_sent, before_sync,
                   sync_sent, ack, ready, reused, refused };
enum class Fault { none, wrong_sync_id, omit_sync, stop_child };
inline Fault (*hook)(const dig::DigitalDecoder*,Stage,const WorkerEnvelope&,
                     uint32_t,std::string_view)=nullptr;
inline Fault trace(const dig::DigitalDecoder* d,Stage s,const WorkerEnvelope& e,
                   uint32_t id,std::string_view text={}) {
    return hook?hook(d,s,e,id,text):Fault::none;
}
}
