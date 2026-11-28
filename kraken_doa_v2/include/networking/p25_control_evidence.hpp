#pragma once
// Narrow shadow evidence for CRC-checked P25 Phase I TSBKs. No SDK/PluginEvent
// ABI changes on the host, no legacy manager event, no placement capability.
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace dig { class DigitalDecoder; }
namespace p25_control {
constexpr uint32_t wire_type=49;
constexpr size_t wire_size=14; // NAC big endian, then 12 original TSBK bytes
enum class Kind { network, site, iden, grant };
struct Identifier {
    uint64_t base=0;
    uint32_t step=0;
    int64_t offset=0;
    int slots=0; // only FDMA 1 or supported TDMA 2; zero = unusable
    bool operator==(const Identifier&)const=default;
};
struct Grant {
    uint16_t channel=0xffff, uplink=0xffff;
    uint32_t target=0,source=0;
    int service=-1;
    bool group=true,update=false;
};
struct Observation {
    Kind kind=Kind::network;
    uint16_t nac=0,sys=0,cc=0xffff;
    uint32_t wacn=0;
    uint8_t rfss=0,site=0,id=0;
    Identifier table;
    std::array<Grant,2> grants{};
    size_t count=0;
};
inline uint16_t crc(std::string_view s){
    uint16_t c=0;
    for(unsigned char v:s){
        c^=uint16_t(v)<<8;
        for(int k=0;k<8;++k)c=uint16_t((c<<1)^((c&0x8000)?0x1021:0));
    }
    return uint16_t(~c);
}
inline std::optional<Observation> parse(std::string_view p){
    if(p.size()!=wire_size)return {};
    auto u=[&](size_t i){return static_cast<uint8_t>(p[i]);};
    const uint16_t nac=(uint16_t(u(0))<<8)|u(1);
    if(nac>0xfff||crc(p.substr(2,10))!=((uint16_t(u(12))<<8)|u(13)))return {};
    if((u(2)&0x40)||(u(3)!=0&&u(3)!=1))return {}; // protected/nonstandard TSBK
    const auto op=u(2)&0x3f;
    uint64_t a=0;for(size_t i=4;i<12;++i)a=(a<<8)|u(i);
    auto f=[&](int hi,int n){return uint32_t((a>>(hi-n+1))&((uint64_t(1)<<n)-1));};
    Observation o;o.nac=nac;
    auto add=[&](uint32_t ch,uint32_t r,uint32_t t,uint32_t s,int so,bool group,bool upd){
        if(ch==0xffff||!t)return;
        o.grants[o.count++]={uint16_t(ch),uint16_t(r),t,s,so,group,upd};
    };
    switch(op){
    case 0x3b:
        o.kind=Kind::network;o.wacn=f(55,20);o.sys=f(35,12);o.cc=f(23,16);break;
    case 0x3a:
        o.kind=Kind::site;o.sys=f(51,12);o.rfss=f(39,8);o.site=f(31,8);o.cc=f(23,16);break;
    case 0x33: case 0x34: case 0x3d: {
        o.kind=Kind::iden;o.id=f(63,4);
        o.table.base=uint64_t(f(31,32))*5;o.table.step=f(41,10)*125;
        if(op==0x3d)o.table.offset=int64_t(f(49,8))*250000*(f(50,9)&0x100?1:-1);
        else o.table.offset=int64_t(f(54,13))*o.table.step*(f(55,1)?1:-1);
        // P25 channel types 3 and 5 describe two-slot TDMA. Refuse other
        // TDMA shapes rather than coercing them to Phase I or slot zero.
        const auto type=f(59,4);
        o.table.slots=op==0x33?(type==3||type==5?2:0):1;
        if(!o.table.base||o.table.base>6000000000ull||!o.table.step)o.table.slots=0;
        break;
    }
    case 0x00:
        o.kind=Kind::grant;add(f(55,16),0xffff,f(39,16),f(23,24),f(63,8),true,false);break;
    case 0x02:
        o.kind=Kind::grant;add(f(63,16),0xffff,f(47,16),0,-1,true,true);
        if(f(31,16)!=f(63,16)||f(15,16)!=f(47,16))add(f(31,16),0xffff,f(15,16),0,-1,true,true);
        break;
    case 0x03:
        o.kind=Kind::grant;add(f(47,16),f(31,16),f(15,16),0,f(63,8),true,true);break;
    case 0x04: case 0x06:
        o.kind=Kind::grant;add(f(63,16),0xffff,f(47,24),f(23,24),-1,false,op==0x06);break;
    case 0x08: case 0x09:
        o.kind=Kind::grant;add(f(55,16),0xffff,f(23,24),0,f(63,8),false,op==0x09);break;
    default:return {};
    }
    return o;
}
struct Proof {
    uint64_t origin=0,serial=0,down=0,up=0;
    uint64_t revision=0,down_revision=0,up_revision=0;
    uint32_t wacn=0;
    uint16_t sys=0,nac=0;
    uint8_t rfss=0,site=0;
    Grant grant{};
    int phase=0,slot=-1,lch=0;
    int64_t at=0;
};
struct Catalog {
    uint64_t origin=0;
    int nac=-1;
    std::optional<Observation> network,site;
    std::array<Identifier,16> tables{};
    uint64_t revision=0;
    std::array<uint64_t,16> table_revision{};
    std::optional<Proof> latest;
    uint64_t serial=0,observed=0,ready=0,refused=0,iden_seen=0;
    int64_t last=0;
    void clear(uint64_t id,int new_nac){
        if(revision!=UINT64_MAX)++revision;
        origin=id;nac=new_nac;network.reset();site.reset();tables={};table_revision={};latest.reset();last=0;
    }
    bool identity()const{
        return network&&site&&network->sys==site->sys&&network->cc==site->cc&&
            network->cc!=0xffff;
    }
    static uint64_t frequency(const Identifier& t,uint16_t ch){
        if(!t.slots||!t.base||!t.step)return 0;
        const uint64_t hz=t.base+uint64_t((ch&4095)/t.slots)*t.step;
        return hz<=6000000000ull?hz:0;
    }
    bool retains(const Proof& p)const{
        return identity()&&origin==p.origin&&revision==p.revision&&revision!=UINT64_MAX&&
            nac==p.nac&&network->wacn==p.wacn&&network->sys==p.sys&&
            site->rfss==p.rfss&&site->site==p.site&&
            table_revision[p.grant.channel>>12]==p.down_revision&&p.down_revision!=UINT64_MAX&&
            (p.grant.uplink==0xffff||(table_revision[p.grant.uplink>>12]==p.up_revision&&p.up_revision!=UINT64_MAX));
    }
    void observe(uint64_t id,const Observation& o,int64_t at){
        if(origin!=id||nac!=o.nac)clear(id,o.nac);
        ++observed;last=at;
        if(o.kind==Kind::network){
            if((network&&(network->wacn!=o.wacn||network->sys!=o.sys||network->cc!=o.cc))||
               (site&&(site->sys!=o.sys||site->cc!=o.cc)))clear(id,o.nac);
            network=o;last=at;return;
        }
        if(o.kind==Kind::site){
            if((site&&(site->sys!=o.sys||site->rfss!=o.rfss||site->site!=o.site||site->cc!=o.cc))||
               (network&&(network->sys!=o.sys||network->cc!=o.cc)))clear(id,o.nac);
            site=o;last=at;return;
        }
        if(o.kind==Kind::iden){
            ++iden_seen;
            if(identity()){
                auto& old=tables[o.id];
                if(old!=o.table){
                    auto& r=table_revision[o.id];
                    if(r!=UINT64_MAX)++r;
                    latest.reset(); // no retroactive reauthorization
                }
                old=o.table;
            }
            return;
        }
        for(size_t i=0;i<o.count;++i){
            const auto& g=o.grants[i];
            const auto& t=tables[g.channel>>12];
            const uint64_t down=frequency(t,g.channel);
            uint64_t up=0;
            if(g.uplink!=0xffff&&g.uplink!=g.channel)up=frequency(tables[g.uplink>>12],g.uplink);
            else if(g.uplink==0xffff&&t.offset){
                const int64_t hz=int64_t(down)+t.offset;
                if(hz>0&&hz<=6000000000ll)up=uint64_t(hz);
            }
            if(!identity()||!down||(g.uplink!=0xffff&&g.uplink!=g.channel&&!up)||
               serial==UINT64_MAX||revision==UINT64_MAX||
               table_revision[g.channel>>12]==UINT64_MAX||
               (g.uplink!=0xffff&&table_revision[g.uplink>>12]==UINT64_MAX)){++refused;latest.reset();continue;}
            ++ready;
            Proof p;p.origin=id;p.serial=++serial;p.down=down;p.up=up;
            p.revision=revision;p.down_revision=table_revision[g.channel>>12];
            p.up_revision=g.uplink!=0xffff?table_revision[g.uplink>>12]:0;
            p.wacn=network->wacn;p.sys=network->sys;p.nac=o.nac;
            p.rfss=site->rfss;p.site=site->site;p.grant=g;p.at=at;
            p.phase=t.slots==2?2:1;p.slot=t.slots==2?(g.channel&1):-1;p.lch=p.slot+1;
            latest=p;
        }
    }
};
// Called only by the native runner with its original manual operation scope.
bool enqueue(const dig::DigitalDecoder* decoder,const Observation& o);
} // namespace p25_control
