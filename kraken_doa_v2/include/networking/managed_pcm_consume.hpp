#pragma once
// D2A qualification primitive. Manager-thread only. Caller establishes and
// validates exact authority; returned slices are witnesses, NOT publish rights.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <utility>
#include <vector>
namespace managed_iq::pcm::delivery {
template<class Batch, class Key> class Queue {
public:
    struct Slice {
        std::shared_ptr<const Batch> batch;
        std::size_t begin, count;
        std::int64_t acknowledged_ms;
    };
    enum class Result { empty, ready, invalidated };
    struct Read {
        Result result=Result::empty;
        std::vector<Slice> slices;
        std::size_t samples=0;
    };
private:
    struct Entry { std::shared_ptr<const Batch> batch; std::size_t offset; std::int64_t at; };
    std::deque<Entry> q_;
    std::optional<Key> key_;
    std::uint64_t high_=0;
    std::int64_t last_at_=0;
    std::size_t pending_=0;
    const std::size_t cap_;
    const std::int64_t age_;
    void drop_front() {
        pending_-=q_.front().batch->samples.size()-q_.front().offset;
        q_.pop_front();
    }
public:
    explicit Queue(std::size_t cap=8000,std::int64_t age_ms=250):cap_(cap),age_(age_ms){}
    // A clear retains the highwater for this identity. Only a new authorized
    // identity permits a new sequence domain. Caller must refuse stale keys.
    void clear(){q_.clear();pending_=0;}
    std::size_t pending()const{return pending_;}
    // Only the current manager may activate an independently admitted key.
    // Stale producers/consumers never change the active identity.
    void activate(const Key& key){
        if(key_&&*key_==key)return;
        clear();key_=key;high_=0;last_at_=0;
    }
    bool push(const Key& key,std::uint64_t seq,std::int64_t ack_ms,std::int64_t now,
              std::shared_ptr<const Batch> batch){
        if(!batch||batch->samples.empty()||batch->samples.size()>cap_||
           !seq||age_<=0||ack_ms<0||now<ack_ms||now-ack_ms>=age_)return false;
        if(!key_||!(*key_==key)||seq<=high_||ack_ms<last_at_)return false;
        const auto n=batch->samples.size();
        while(!q_.empty()&&pending_>cap_-n)drop_front();
        q_.push_back({std::move(batch),0,ack_ms});
        pending_+=n;high_=seq;last_at_=ack_ms;
        return true;
    }
    template<class Validate> Read take(const Key& key,std::int64_t now,std::size_t budget,Validate&& valid){
        Read out;
        if(!key_||!(*key_==key)){
            out.result=Result::invalidated;return out;
        }
        if(now<last_at_){
            clear();out.result=Result::invalidated;return out;
        }
        while(!q_.empty()&&now-q_.front().at>=age_)drop_front();
        // Stage slices without exposing them to a sink; refusal invalidates
        // the entire tentative read, including slices already consumed.
        while(budget&&!q_.empty()){
            auto& e=q_.front();
            if(!valid(*e.batch)){
                clear();out.slices.clear();out.samples=0;
                out.result=Result::invalidated;return out;
            }
            auto n=std::min(budget,e.batch->samples.size()-e.offset);
            out.slices.push_back({e.batch,e.offset,n,e.at});
            e.offset+=n;pending_-=n;budget-=n;out.samples+=n;
            if(e.offset==e.batch->samples.size())q_.pop_front();
        }
        if(out.samples)out.result=Result::ready;
        return out;
    }
};
}
