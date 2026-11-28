#pragma once
#include "networking/managed_worker_envelope.hpp"
namespace managed_iq::sample_test {
enum class Stage { before_prepare, before_send, sent, before_sync, before_poll,
                   report, acknowledged, complete, refused };
enum class Fault { none, omit_sync, wrong_sync, stop_child };
inline Fault (*hook)(const dig::DigitalDecoder*,Stage,const WorkerEnvelope&,
                     uint32_t,uint32_t,const void*,size_t)=nullptr;
inline Fault trace(const dig::DigitalDecoder* d,Stage s,const WorkerEnvelope& e,
                   uint32_t id,uint32_t type=0,const void* p=nullptr,size_t n=0) {
    return hook?hook(d,s,e,id,type,p,n):Fault::none;
}
}
