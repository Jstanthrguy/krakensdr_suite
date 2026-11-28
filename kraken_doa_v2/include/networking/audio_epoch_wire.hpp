#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
namespace managed_iq::audio_wire {
// Type 12 v1, explicit little endian. All counters are exact uint64.
constexpr uint32_t type=12,version=1,header=56,max_opus=4000;
enum class Kind:uint32_t{reset=0,packet=1};
inline void put(std::string& s,uint64_t v,unsigned n){for(unsigned i=0;i<n;++i)s.push_back(char((v>>(8*i))&255));}
inline uint64_t get(std::string_view s,size_t off,unsigned n){uint64_t v=0;for(unsigned i=0;i<n;++i)v|=uint64_t(uint8_t(s[off+i]))<<(8*i);return v;}
inline std::string frame(Kind kind,uint64_t gen,uint64_t rev,uint64_t epoch,uint64_t seq,std::string_view payload={}){
    std::string s;s.reserve(header+payload.size());
    put(s,type,4);put(s,version,4);put(s,uint32_t(kind),4);put(s,payload.size(),4);
    put(s,gen,8);put(s,rev,8);put(s,epoch,8);put(s,seq,8);
    put(s,kind==Kind::packet?1920:0,4);put(s,kind==Kind::packet?48000:0,4);
    s.append(payload);return s;
}
// One loop-owned stream. Reset advertises the last observed admission floor;
// packet epoch changes are also discontinuities. Never relabel committed data.
class Transport {
    uint64_t gen_=1,rev_=0,epoch_=0,last_epoch_=0,seq_=0;
    bool active_=false,blocked_=true,dead_=false;
    bool advance(){if(gen_==UINT64_MAX){dead_=true;return false;}++gen_;return true;}
public:
    std::string snapshot()const{return frame(Kind::reset,gen_,rev_,0,seq_);}
    bool dead()const{return dead_;}
    std::optional<std::string> observe(uint64_t rev,bool active){
        if(!rev||rev==UINT64_MAX||rev<rev_){dead_=true;return {};}
        if(dead_)return {};
        if(rev_==rev&&active_==active)return {};
        rev_=rev;active_=active;epoch_=0;blocked_=true;
        if(!advance())return {};
        return snapshot();
    }
    std::optional<std::string> interrupt(){
        if(dead_||blocked_)return {};
        blocked_=true;epoch_=0;if(!advance())return {};
        return snapshot();
    }
    std::optional<std::string> packet(std::string_view legacy,uint64_t rev,uint64_t epoch,uint64_t seq){
        if(dead_||!active_||!rev||rev!=rev_||!epoch||epoch==UINT64_MAX||!seq||seq==UINT64_MAX||seq<=seq_||
           legacy.size()<16||legacy.size()>16+max_opus||get(legacy,0,4)!=1||get(legacy,4,4)!=1920||
           get(legacy,8,4)!=0x473b8000||get(legacy,12,4)!=legacy.size()-16||legacy.size()==16)return {};
        if((!epoch_&&epoch<=last_epoch_)||(epoch_&&(epoch<epoch_||(epoch==epoch_&&seq!=seq_+1))))return {};
        if(epoch_&&epoch!=epoch_&&!advance())return {};
        epoch_=epoch;last_epoch_=epoch;seq_=seq;blocked_=false;
        return frame(Kind::packet,gen_,rev_,epoch_,seq_,legacy.substr(16));
    }
};
}
