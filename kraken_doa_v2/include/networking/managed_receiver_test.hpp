#pragma once
// Offline-only hooks. Not included by ordinary receiver compilation.
#include "networking/managed_receiver.hpp"
namespace managed_iq::test {
using Selection=ReceiverSelection;
// Bounded offline receiver gate and recoverable exception observations.
inline bool (*demand_hint)(bool)=nullptr;
inline void (*inside_pass)()=nullptr;
inline void (*before_pass)(const RawDataPacket&,const std::vector<Selection::Job>&,
                           const std::vector<Block>&)=nullptr;
inline bool (*after_pass)(const RawDataPacket&,const std::vector<Selection::Job>&,
                          const std::vector<Selection::Outcome>&,
                          const std::vector<Result>&,const std::vector<bool>&)=nullptr;
}
