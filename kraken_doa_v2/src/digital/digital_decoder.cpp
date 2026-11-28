#include "digital/digital_decoder.hpp"
#include "digital/dig_plugin.hpp"
#ifdef TT01_K_TYPED_CONTROL_QUALIFICATION
#include "networking/p25_control_evidence.hpp"
#ifdef TT01_D1_PCM_QUALIFICATION
#include "networking/managed_pcm.hpp"
#endif
#if !defined(TT01_MANUAL_OUTPUT_QUALIFICATION) || !defined(TT01_MANUAL_CONTINUITY_QUALIFICATION)
#error typed control requires native manual admission
#endif
#endif
#ifdef TT01_WORKER_QUALIFICATION
#include "networking/managed_worker_envelope.hpp"
#ifdef TT01_GENERATION_QUALIFICATION
#include "networking/managed_generation_test.hpp"
#ifdef TT01_SAMPLE_QUALIFICATION
#include "networking/managed_sample_test.hpp"
#ifdef TT01_EVENT_AUDIT_QUALIFICATION
#include "networking/managed_event_audit.hpp"
#endif
#ifdef TT01_ROLE_QUALIFICATION
#include "networking/manual_decoder_envelope.hpp"
#include "networking/managed_role_shutdown_test.hpp"
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
#include "networking/manual_output_audit.hpp"
#endif
#endif
#endif
#endif
#endif

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <limits>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <sstream>

#include <pthread.h>

#include <liquid/liquid.h>

// the wire's shared rules (kp::wire::clean_text, host_option): by path, so
// every build line of this file (tools/digi_test's too) finds it
#include "../../plugins/sdk/kraken_plugin.hpp"
#include "config.hpp"   // efficient_bandwidth_at_least
#include "utils/fs_compat.hpp"
#include "utils/json_escape.hpp"
#include "utils/parse_num.hpp"

namespace dig {

#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
// Isolated qualification fault at the actual settings transport boundary.
// Close the exact child stdin before the real send; no fabricated result.
namespace settings_test {
bool (*before_send)(const DigitalDecoder*,uint32_t)=nullptr;
void (*after_send)(const DigitalDecoder*,uint32_t,bool)=nullptr;
}
#endif
namespace {
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
// Exact old source/domain/role and loss epoch; no fresh authority read
// or locks held across child IO, callbacks, or teardown.
void retire_manual_context_exact(){
    namespace mo=managed_iq::manual_output;
    auto c=mo::context;
    if(!c.stamp||!c.generation||c.closing)return;
#ifdef TT01_OPERATIONAL_BUILD
    if(!c.stamp->segment())return;
#endif
    mo::admit(*c.stamp,c.stamp->decoder_identity(),c.stamp->authority(),[&]{
        if(c.stamp->authority()->manual_loss_current(c.generation->loss))
            c.stamp->authority()->lose_manual_locked();
        return true;
    });
    c.generation->retire();
}
#endif
constexpr float AFC_LIMIT_HZ = 4000.0f;
constexpr int64_t DETECT_WINDOW_MS = 4000;
constexpr size_t QUEUE_MAX_SECONDS = 1;
constexpr size_t PLUGIN_CHUNK = 16384;          // samples per SAMPLES message
constexpr int64_t PLUGIN_RETRY_MS = 5000;       // missing / unbuilt plugin: look again
constexpr int64_t CHECK_MS = 2000;              // rebuilt plugins / changed plugin list
// AFC: the plugins report the carrier offset they see a few blocks late
// (pipe latency; up to ~1 s when one falls behind), so corrections are
// averaged and applied at most every AFC_PERIOD_MS, and reports made before
// the previous correction reached the plugin (AFC_SETTLE_MS) are ignored -
// an every-report integrator ran away with the delay
constexpr int64_t AFC_PERIOD_MS = 300;
constexpr int64_t AFC_SETTLE_MS = 300;

// plugins/sdk/kraken_plugin.hpp kp::wire
constexpr uint32_t W_SAMPLES = 1, W_OPTION = 2, W_RESET = 3, W_VOICE_WANTED = 4, W_SYNC = 5, W_STATION = 6, W_RF = 7,
                   W_FACT = 16, W_EVENT = 17, W_VALID = 18, W_AUDIO = 19, W_VOICE_STATE = 20, W_FREQ_ERROR = 21,
                   W_SYNC_DONE = 22, W_MAP_POINT = 23, W_MAP_REMOVE = 24, W_TABLE_COLUMNS = 25, W_TABLE_ROW = 26,
                   W_TABLE_REMOVE = 27, W_MESSAGE = 28, W_RAW = 29, W_TALKER = 30, W_TALKER_END = 31,
                   W_TABLE_KEEP = 32, W_TALKER_FORGET = 33, W_AUDIO_CHANNEL = 34, W_SAMPLES_MC = 8,
                   W_SAMPLES_ARRAY = 9, W_SPATIAL = 35, W_PLOT = 36, W_TUNE = 37, W_TABLE_DETAIL = 38,
                   W_SPATIAL_REMOVE = 39, W_VIDEO = 40, W_PLOT_EX = 41, W_OPTION_CHOICES = 42, W_TRUNK_SYSTEM = 43,
                   W_TRUNK_CHANNEL = 44, W_CONTROL_CHANNEL = 45, W_GRANT = 46, W_GRANT_END = 47, W_CALL = 48;
// kp::wire::TRUNK_* limits (trunked systems; a plugin is untrusted input:
// everything is checked again here)
constexpr size_t TRUNK_KEY_MAX = 48, TRUNK_TEXT_MAX = 64, TRUNK_NAME_MAX = 32, TRUNK_ID_MAX = 32, TRUNK_DEMOD_MAX = 16,
                 TRUNK_OPTIONS_MAX = 16, TRUNK_OPTION_VALUE_MAX = 100;
constexpr int TRUNK_SLOT_MAX = 15;
constexpr double TRUNK_FREQ_MAX_HZ = 6e9, TRUNK_BW_MAX_HZ = 2.4e6;
constexpr size_t GRANT_FIXED_KNOWN = 12;   // kp::wire::GRANT's fixed fields this host reads
// kp::Host::option_choices limits (kp::wire::CHOICES_MAX ...)
constexpr size_t CHOICES_MAX = 100, CHOICE_VALUE_MAX = 100, CHOICE_LABEL_MAX = 80;
// named plots (kp::Plot::id) one plugin may keep
constexpr size_t MAX_PLOTS_PER_PLUGIN = 8;
// a plugin's retune requests (kp::Host::tune): at most one per this
constexpr int64_t TUNE_MIN_GAP_MS = 2000;
constexpr size_t MAX_PAYLOAD = 1u << 20;   // kp::wire::MAX_PAYLOAD
// how far back a plugin's sample positions stay mappable to the VFO stream
constexpr double POS_MAP_SECONDS = 60;
// a talker packet (kp::Talker::packet) longer than this is not one
constexpr double MAX_PACKET_S = 0.25;   // ADS-B 120 us .. AIS 5 slots (133 ms)
constexpr double MAX_SIGNAL_SPAN_S = 3.0;   // a valid frame's samples (Host::valid(start, end)): RS41 0.9 s, POCSAG batch at 512 bit/s 1.1 s, FLEX block 0 with its syncs 0.28 s

std::mutex record_mu;
RecordHandler record_handler;
// "Allow logging to disk" (set_log_allowed): Log All's raw frames and verbose
std::atomic<bool> log_allowed_{false};
std::atomic<bool> video_wanted{false};   // a browser is subscribed to decoder video
void deliver_record(DigitalDecoder* d, const LogRecord& r) {
    RecordHandler h;
    {
        std::lock_guard<std::mutex> lk(record_mu);
        h = record_handler;
    }
    if (h) h(d, r);
}

std::mutex voice_tap_mu;
VoiceTapHandler voice_tap_handler;
void deliver_voice_tap(DigitalDecoder* d, const float* x, size_t n, const std::string& plugin, const std::string& tid,
                       const std::string& tlabel, double rf_hz) {
    VoiceTapHandler h;
    {
        std::lock_guard<std::mutex> lk(voice_tap_mu);
        h = voice_tap_handler;
    }
    if (h) h(d, x, n, plugin, tid, tlabel, rf_hz);
}

std::mutex record_voice_mu;
RecordVoiceHandler record_voice_handler;
void deliver_record_voice(DigitalDecoder* d, const float* x, size_t n) {
    RecordVoiceHandler h;
    {
        std::lock_guard<std::mutex> lk(record_voice_mu);
        h = record_voice_handler;
    }
    if (h) h(d, x, n);
}

std::mutex message_mu;
MessageHandler message_handler;
void deliver_message(DigitalDecoder* d, const std::string& plugin, const std::string& from, const std::string& text,
                     double rf_hz) {
    MessageHandler h;
    {
        std::lock_guard<std::mutex> lk(message_mu);
        h = message_handler;
    }
    if (h) h(d, plugin, from, text, rf_hz);
}

// '\0'-separated fields of a wire message
std::vector<std::string> split0(const char* p, size_t len, size_t max_fields) {
    std::vector<std::string> f;
    size_t s = 0;
    for (size_t i = 0; i <= len && f.size() < max_fields; i++)
        if (i == len || p[i] == '\0') {
            f.emplace_back(p + s, i - s);
            s = i + 1;
        }
    return f;
}

// Without internal streams (an offline caller - DigitalDecoder's
// internal_streams false) Auto detect leaves out the plugins that need a VFO
// more than this many times wider than the one it runs on (ADS-B wants the
// whole 2.4 MHz: run on a 12.5 kHz VFO it would only burn CPU on upsampled
// samples). The live pipeline makes internal streams instead (below)
constexpr double AUTO_MAX_RATE_SHORTFALL = 2.0;

// Auto detect's internal streams: a plugin whose min_vfo_rate is more than
// the VFO's bandwidth gets the VFO's centre at efficient_bandwidth_at_least
// (min_vfo_rate) - what the page's "Set X kHz" would set. Needs close to each
// other share one stream: sorted, a need joins the current group while its
// width is at most AUTO_STREAM_MERGE_RATIO x the group's narrowest, and the
// group's stream is its widest (the others are resampled down from it, as
// on a VFO that wide). More groups than DigitalDecoder::MAX_STREAMS: the two
// neighbours closest in width merge until they fit. Today's plugins on a
// 12.5 kHz VFO: 25 kHz (aprs, v23, radiosonde, tetra, vdl2), 48 kHz (ils),
// 150 kHz (rds), 2.4 MHz (analogtv)
constexpr double AUTO_STREAM_MERGE_RATIO = 2.0;

// Station location for the plugins (set_station_location); gen bumps on a change
std::mutex station_mu;
std::string station_text;          // "lat,lon" or "" (unknown)
std::atomic<uint64_t> station_gen{1};

// of a plugin's exe: a rebuild restarts it. Windows: the build replaces the
// running decoder.exe with MSYS2's mv -f (it moves the busy file aside) - the
// mtime changes as on Linux
int64_t mtime_ms(const std::string& path) { return fs_mtime_ms(path); }
}  // namespace

void set_record_handler(RecordHandler h) {
    std::lock_guard<std::mutex> lk(record_mu);
    record_handler = std::move(h);
}

void set_log_allowed(bool on) { log_allowed_ = on; }
bool log_allowed() { return log_allowed_.load(); }
void set_video_wanted(bool on) { video_wanted = on; }

void set_voice_tap_handler(VoiceTapHandler h) {
    std::lock_guard<std::mutex> lk(voice_tap_mu);
    voice_tap_handler = std::move(h);
}

void set_record_voice_handler(RecordVoiceHandler h) {
    std::lock_guard<std::mutex> lk(record_voice_mu);
    record_voice_handler = std::move(h);
}

void set_message_handler(MessageHandler h) {
    std::lock_guard<std::mutex> lk(message_mu);
    message_handler = std::move(h);
}

void set_station_location(bool valid, double lat, double lon) {
    std::string t;
    // is_finite_value, not std::isfinite: right under fast-math flags too
    if (valid && is_finite_value(lat) && is_finite_value(lon) && std::fabs(lat) <= 90 && std::fabs(lon) <= 180) {
        char b[64];
        snprintf(b, sizeof b, "%.6f,%.6f", lat, lon);
        t = b;
    }
    std::lock_guard<std::mutex> lk(station_mu);
    if (t != station_text) {
        station_text = t;
        station_gen++;
    }
}

// ---------------------------------------------------------------------------
// One plugin process of a decoder
// ---------------------------------------------------------------------------
struct Runner {
    std::string id;
    PluginInfo info;                   // of the running process (or the last lookup)
    bool known = false;                // info is valid
    std::unique_ptr<PluginProcess> proc;
    int64_t retry_ms = 0, started_ms = 0;
    int crashes = 0;
    std::string note;                  // last problem logged (no repeats)
    int verbose_sent = -1, voice_sent = -1, raw_sent = -1, video_sent = -1;
    uint64_t station_sent = 0;         // station_gen sent
    double rf_sent = -1;               // kp::Host::rf_hz sent (0 = unknown, -1 = nothing yet)
    std::map<std::string, std::string> opts_sent;   // key (without the id prefix) -> value
    uint32_t sync_sent = 0, sync_done = 0;
    // trunked-system reports are dropped until sync_done reaches this (the
    // SYNC sent after a RESET: reports still in the pipe from before it)
    uint32_t trunk_fence = 0;
    std::string state = "starting", error;
    std::vector<std::string> tail;
    uint64_t dropped = 0;
    // plugin input sample p0 + i = VFO stream position v0 + i * step (talker
    // spans arrive in the plugin's Host::time(), counted from its start)
    struct PosSeg { uint64_t p0, n; double v0, step; };
    std::deque<PosSeg> pos_map;
    uint64_t written = 0;              // samples this process was sent
    // the open talker of each talker channel (kp::Talker::channel, DMR timeslot)
    struct OpenTalker { std::string id, label; uint64_t start = 0, end = 0; };
    std::map<int, OpenTalker> talkers;
    // the talker channel its audio is from (wire AUDIO_CHANNEL, DMR: the
    // timeslot it plays), -1 = not said - Voice to Text names that radio
    int audio_channel = -1;
    // array plugins: Host::time() = VFO stream position / its rate
    double array_rate = 0;
    // the stream it runs on: 0 = the VFO's own, else Auto detect's internal
    // stream of this width (Engine::assign_streams)
    int stream_w = 0;
    // a plugin at its stream's own rate (kp::Info::sample_rate 0): the rate
    // it was started at (--serve --rate); a new rate restarts it
    double vfo_rate = 0;
    // the rate this process gets its samples at
    double prate() const { return info.sample_rate > 0 ? info.sample_rate : vfo_rate; }
    int64_t last_tune_ms = -1000000;   // kp::Host::tune rate limit
    uint64_t array_next = ~0ull;       // stream position after the last block sent (gap detection)
    // Host::time() seconds -> VFO stream position (false: not mappable)
    bool vfo_pos(double t, double rate, uint64_t* out) const {
        if (info.array) {
            if (!(array_rate > 0) || !is_finite_value(t) || t < 0) return false;
            *out = static_cast<uint64_t>(std::llround(t * array_rate));
            return true;
        }
        if (pos_map.empty() || !is_finite_value(t) || t < 0) return false;
        const double p = t * rate;
        if (p < static_cast<double>(pos_map.front().p0)) return false;
        const PosSeg* g = &pos_map.back();
        for (auto it = pos_map.rbegin(); it != pos_map.rend(); ++it)
            if (static_cast<double>(it->p0) <= p) { g = &*it; break; }
        const double off = std::min(p - static_cast<double>(g->p0), static_cast<double>(g->n));
        *out = static_cast<uint64_t>(std::llround(std::max(0.0, g->v0 + off * g->step)));
        return true;
    }
};

// ---------------------------------------------------------------------------
// Engine: AFC mixer + per-rate resamplers + the plugin processes. Owned and
// driven by one thread at a time (the decoder's worker, or process()).
// ---------------------------------------------------------------------------
class Engine {
public:
    Engine(Report& r, DigitalDecoder* owner, bool sync_io, bool streams)
        : report_(r), owner_(owner), sync_io_(sync_io), streams_on_(streams) {}
    ~Engine() {
#ifdef TT01_EVENT_AUDIT_QUALIFICATION
        if(event_generation_)event_generation_->retire();
#endif
        stop_all();
        destroy_resamplers();
    }

    void configure(Mode m, const Options& o, const std::string& plugin) {
        opts_ = o;
        if (m == mode_ && (m != Mode::PLUGIN || plugin == plugin_)) return;
        mode_ = m;
        plugin_ = m == Mode::PLUGIN ? plugin : "";
        rebuild_runners();
    }

#ifdef TT01_GENERATION_QUALIFICATION
    // Worker-owned cold runner transition. B2A qualifies the control
    // exchange only. The actual PluginProcess carries RESET/options/RF/SYNC;
    // no SAMPLES and no callbacks from that pipe are admitted here.
    void close_managed_generation() {
#ifdef TT01_EVENT_AUDIT_QUALIFICATION
        if(event_generation_)event_generation_->retire();
        event_generation_.reset();
#endif
        configure(Mode::OFF,Options{},"");
        destroy_resamplers();
        reset_all();
        in_rate_=0;rf_hz_=0;next_pos_=0;nco_phase_=0;vfo_bw_=0;
        check_ms_=0;afc_changed_ms_=0;mixed_.clear();sbuf_.clear();
    }
    bool prepare_managed_generation(const managed_iq::WorkerEnvelope& e,uint32_t id,const std::function<bool()>& worker_running
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
        ,const std::function<void()>& retire
#endif
    ) {
        namespace gt=managed_iq::generation_test;
        using gt::Stage;
        const auto& t=e.provenance().placement->tuple;
        auto current=[&]{return e.admit(owner_,[&]{
            return worker_running();
        });};
        auto say=[&](Stage stage,std::string_view detail={}){
            return gt::trace(owner_,stage,e,id,detail);
        };
        auto fail=[&](std::string_view why){
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
            retire();
#endif
            close_managed_generation();
            say(Stage::refused,why);
            return false;
        };
        close_managed_generation();
        say(Stage::closed);
        if(!id||t.mode!=2||t.plugin!="p25"||!(e.rate()>0)||
           !is_finite_value(e.provenance().observed_rf())||
           !(e.provenance().observed_rf()>0)||!current())
            return fail("invalid or retired envelope");
        auto o=owner_->options();
        if(owner_->mode()!=Mode::PLUGIN||owner_->plugin_id()!="p25"||o.plugin!=t.options)
            return fail("live configuration mismatch");
        // The tuple is authoritative for assignment options; require all
        // supplied P25 keys to be declared, including hidden grant options.
        PluginInfo pi;
        if(!PluginRegistry::instance().get("p25",&pi)||!pi.built||
           pi.array||pi.multichannel||pi.sample_rate!=48000)
            return fail("unsupported runner");
        std::map<std::string,std::string> full;
        for(const auto& opt:pi.options)full.emplace(opt.key,opt.def);
        for(const auto& kv:t.options){
            if(kv.first.rfind("p25.",0)!=0)continue;
            auto it=full.find(kv.first.substr(4));
            if(it==full.end()||kv.second.size()>100||
               std::any_of(kv.second.begin(),kv.second.end(),[](unsigned char c){return c<32||c==127;}))
                return fail("invalid assignment option");
            if(!kv.second.empty())it->second=kv.second;
        }
        if(!current())return fail("retired before runner start");
        in_rate_=e.rate();vfo_bw_=t.bandwidth;rf_hz_=e.provenance().observed_rf();
        next_pos_=e.pos();o.plugin=t.options;
        configure(Mode::PLUGIN,o,"p25");
        if(runners_.size()!=1)return fail("wrong runner count");
        auto& r=*runners_.front();
        start(r,now_ms());
        if(!r.proc||!r.proc->alive(nullptr)||r.stream_w!=0)
            return fail("runner failed to start");
        // Cold process identity isolates all earlier pipe bytes; every
        // control send is checked. SYNC means SDK processed preceding
        // messages, not that option semantics or RF acquisition are proved.
        auto send=[&](uint32_t type,const void* p,size_t n){
            return current()&&r.proc->alive(nullptr)&&r.proc->send(type,p,n,0);
        };
        if(!send(W_RESET,nullptr,0))return fail("RESET send refused");
        say(Stage::reset_sent);
        char rf[64];snprintf(rf,sizeof rf,"%.1f",rf_hz_);
        if(!send(W_RF,rf,strlen(rf)))return fail("RF send refused");
        r.rf_sent=rf_hz_;say(Stage::rf_sent,rf);
        for(const auto& kv:full){
            const std::string payload=kv.first+"="+kv.second;
            if(!send(W_OPTION,payload.data(),payload.size()))return fail("OPTION send refused");
            say(Stage::option_sent,payload);
        }
        // Qualification child cannot produce audio or log data, even if
        // this code is later exercised with an accidental sample input.
#ifdef TT01_D1_PCM_QUALIFICATION
        const char pcm_opt[]="__tt01_pcm=1";
        if(!send(W_OPTION,pcm_opt,sizeof pcm_opt-1))return fail("typed PCM opt-in refused");
        const uint8_t voice=1;
#else
        const uint8_t voice=0;
#endif
        if(!send(W_VOICE_WANTED,&voice,1))return fail("voice control send refused");
        const auto fault=say(Stage::before_sync);
        if(fault==gt::Fault::stop_child)r.proc->stop();
        const uint32_t sent=fault==gt::Fault::wrong_sync_id?(id==UINT32_MAX?id-1:id+1):id;
        if(fault!=gt::Fault::omit_sync){
            if(!send(W_SYNC,&sent,sizeof sent))return fail("SYNC send refused");
            say(Stage::sync_sent,std::to_string(sent));
        }
        // Absolute monotonic deadline. Do not use legacy drain() which
        // treats a dead process as done. All other reports stay quarantined.
        bool ack=false,bad=false;
        const auto deadline=managed_iq::Clock::now()+std::chrono::milliseconds(500);
        while(managed_iq::Clock::now()<deadline){
            if(!current())return fail("retired while awaiting SYNC");
            if(!r.proc->alive(nullptr)||r.proc->protocol_error())return fail("child died or malformed pipe");
            r.proc->poll([&](uint32_t type,const char* payload,size_t len){
                if(type!=W_SYNC_DONE)return;
                uint32_t got=0;
                if(len==sizeof got)memcpy(&got,payload,sizeof got);
                if(len!=sizeof got||got!=id||ack)bad=true;
                else ack=true;
            });
            if(bad||r.proc->protocol_error())return fail("wrong or malformed SYNC_DONE");
            if(ack){
                if(!r.proc->alive(nullptr)||r.proc->pending_writes())return fail("ACK with dead child or pending controls");
                say(Stage::ack);
                if(!current()||!r.proc->alive(nullptr))return fail("retired after ACK");
                r.sync_sent=r.sync_done=r.trunk_fence=id;
#ifdef TT01_EVENT_AUDIT_QUALIFICATION
                event_generation_=std::make_shared<managed_iq::EventGeneration>(id);
#endif
                return true;
            }
            r.proc->wait_io(1);
        }
        return fail("SYNC_DONE deadline");
    }
#ifdef TT01_SAMPLE_QUALIFICATION
    // Offline B2B1: bounded single-block wire transaction. Authorization
    // of each operation is its linearization point. Retirement may race
    // an already authorized nonblocking operation; that operation belongs
    // only to the old process. No further operation is admitted, and the
    // caller closes/reaps the old runner before any new generation.
    bool deliver_managed_samples(const managed_iq::WorkerEnvelope& e,uint32_t generation,const std::function<bool()>& worker_running
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
        ,const std::function<void()>& retire
#endif
    ) {
        namespace st=managed_iq::sample_test;
        using st::Stage;
        const auto& t=e.provenance().placement->tuple;
        auto say=[&](Stage stage,uint32_t type=0,const void* p=nullptr,size_t n=0){
            return st::trace(owner_,stage,e,generation,type,p,n);
        };
#ifdef TT01_EVENT_AUDIT_QUALIFICATION
        namespace ea=managed_iq::event_audit;
        std::vector<trunk::PluginEvent> staged;
        size_t filtered=0;
        bool stage_overflow=false;
#ifdef TT01_D1_PCM_QUALIFICATION
        std::vector<float> pcm_stage;
        bool pcm_fault=false;
#endif
        struct StageAccounting{
            std::vector<trunk::PluginEvent>& events;size_t& filtered;
            bool published=false,finished=false;
            void finish(){if(finished)return;finished=true;ea::count_staged(events.size(),filtered);if(!published)ea::count_discarded(events.size());}
            ~StageAccounting(){finish();}
        } stage_accounting{staged,filtered};
#endif
        auto fail=[&](const char* why){
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
            retire();
#endif
#ifdef TT01_EVENT_AUDIT_QUALIFICATION
            stage_accounting.finish();
#endif
            say(Stage::refused,0,why,strlen(why));return false;
        };
        auto permit=[&]{
            // Manager-fenced assignment writes are ordered by e.admit.
            // Direct public decoder setters are not all fenced yet; this
            // readback is additional refusal, not an exclusive config lock.
            return owner_->mode()==Mode::PLUGIN&&owner_->plugin_id()=="p25"&&
                owner_->options().plugin==t.options&&
                e.admit(owner_,[&]{
                    return worker_running();
                });
        };
        say(Stage::before_prepare);
        if(!permit()||!managed_runner_alive()||e.rate()!=in_rate_||
           e.provenance().observed_rf()!=rf_hz_||e.pos()!=next_pos_)
            return fail("retired or incompatible before sample preparation");
        auto& r=*runners_[0];
        if(r.proc->pending_writes()||r.sync_sent==UINT32_MAX)
            return fail("pending wire work or sync exhaustion");
        const uint32_t id=++r.sync_sent;
        // Existing Engine DSP; do not enter generic process()/run()
        // which could rebuild the runner or send mutable settings.
        mix(e.samples().data(),e.samples().size(),in_rate_,nco_phase_,mixed_);
        resample(e.samples().size());
        const auto* rb=rate_buf(r);
        if(!rb||rb->rate!=48000||r.stream_w!=0||rb->ny>48000)
            return fail("invalid prepared resampling result");
        size_t sent=0;
        for(size_t p=0;p<rb->ny;p+=PLUGIN_CHUNK){
            size_t n=std::min<size_t>(PLUGIN_CHUNK,rb->ny-p);
            const auto fault=say(Stage::before_send,W_SAMPLES,rb->out.data()+p,n*sizeof(std::complex<float>));
            if(fault==st::Fault::stop_child)r.proc->stop();
            if(!permit()||!r.proc->alive(nullptr)||
               !r.proc->send(W_SAMPLES,rb->out.data()+p,n*sizeof(std::complex<float>),48000*8))
                return fail("sample send refused");
            sent+=n;
            say(Stage::sent,W_SAMPLES,nullptr,n);
        }
        auto fault=say(Stage::before_sync);
        if(fault==st::Fault::stop_child)r.proc->stop();
        const uint32_t wire_id=fault==st::Fault::wrong_sync?(id==UINT32_MAX?id-1:id+1):id;
        if(!permit()||!r.proc->alive(nullptr))return fail("retired before sample SYNC");
        if(fault!=st::Fault::omit_sync&&!r.proc->send(W_SYNC,&wire_id,sizeof wire_id,0))
            return fail("sample SYNC send refused");
        bool ack=false,bad=false;
        const auto deadline=managed_iq::Clock::now()+std::chrono::milliseconds(500);
        while(managed_iq::Clock::now()<deadline){
            say(Stage::before_poll);
            if(!permit()||!r.proc->alive(nullptr)||r.proc->protocol_error())
                return fail("retired or dead before sample poll");
            // poll() flushes only under an old-generation operation permit;
            // no generic idle flush. Raw replies never reach on_message.
            r.proc->poll([&](uint32_t type,const char* data,size_t len){
                if(type==W_SYNC_DONE){
                    uint32_t got=0;if(len==sizeof got)memcpy(&got,data,sizeof got);
                    if(len!=sizeof got||got!=id||ack)bad=true;else ack=true;
                }else{
                    const auto report_fault=say(Stage::report,type,data,len);
                    (void)report_fault;
#ifdef TT01_EVENT_AUDIT_QUALIFICATION
#ifdef TT01_D1_PCM_QUALIFICATION
                    if(type==managed_iq::pcm::wire_type){
                        namespace pc=managed_iq::pcm;
                        if(ack)pcm_fault=true;
                        else{
                            auto status=pc::parse(std::string_view(data,len),*e.provenance().placement,pcm_stage);
                            if(status==pc::Check::malformed||pcm_stage.size()>pc::batch_cap)pcm_fault=true;
                        }
                    }else
#endif
                    if(type==W_CALL){
                        trunk::PluginEvent ev;
                        if(ack||managed_iq::check_call(std::string_view(data,len),*e.provenance().placement,ev)!=managed_iq::CallCheck::matched)++filtered;
                        else {
                            size_t copies=1;
#ifdef TT01_STAGE_CAP_STRESS
                            // Explicit synthetic fan-out of a validated native
                            // report, only in the stress variant. Real cap unchanged.
                            if(report_fault==st::Fault::wrong_sync)copies=ea::batch_cap;
                            if(report_fault==st::Fault::omit_sync)copies=ea::batch_cap+1;
#endif
                            for(size_t i=0;i<copies;++i){
                                if(staged.size()>=ea::batch_cap){
                                    stage_overflow=true;++filtered;
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
                                    retire(); // first known loss, before further ACK admission
#endif
                                }else staged.push_back(ev);
                            }
                        }
                    }else if((type>=W_TRUNK_SYSTEM&&type<=W_CALL)
#ifdef TT01_K_TYPED_CONTROL_QUALIFICATION
                        ||type==p25_control::wire_type
#endif
                    )++filtered;
#endif
                }
            });
#if defined(TT01_MANAGED_STAGE_LOSS_QUALIFICATION) && defined(TT01_EVENT_AUDIT_QUALIFICATION)
            if(stage_overflow)return fail("staged CALL overflow");
#endif
#ifdef TT01_D1_PCM_QUALIFICATION
            if(pcm_fault)return fail("malformed or overflow typed PCM");
#endif
            if(bad||r.proc->protocol_error())return fail("bad sample SYNC_DONE");
            if(ack){
                say(Stage::acknowledged,W_SYNC_DONE,&id,sizeof id);
                if(!permit()||!r.proc->alive(nullptr)||r.proc->pending_writes())
                    return fail("retired or pending after sample ACK");
#ifdef TT01_EVENT_AUDIT_QUALIFICATION
                if(!staged.empty()&&!stage_overflow&&event_generation_){
                    // Copy the small typed event vector; the accounting
                    // scope retains count until its destructor. No samples
                    // survive in the event queue.
                    auto copy=staged;
                    auto batch=std::make_shared<const managed_iq::EventBatch>(
                        owner_->vfo(),e,event_generation_,id,r.written,r.written+sent,std::move(copy));
                    stage_accounting.published=ea::enqueue(std::move(batch));
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
                    if(!stage_accounting.published)return fail("acknowledged CALL batch refused");
#endif
                }
                stage_accounting.finish();
#ifdef TT01_D1_PCM_QUALIFICATION
                if(!pcm_stage.empty()&&event_generation_){
                    auto batch=std::make_shared<const managed_iq::pcm::Batch>(
                        owner_->vfo(),e,event_generation_,id,r.written,r.written+sent,std::move(pcm_stage));
                    if(!managed_iq::pcm::enqueue(std::move(batch)))return fail("acknowledged PCM refused");
                }
#endif
#endif
                r.sync_done=id;r.written+=sent;
                next_pos_=e.pos()+e.samples().size();
                say(Stage::complete,0,nullptr,sent);
                return true;
            }
            r.proc->wait_io(1);
        }
        return fail("sample SYNC deadline");
    }
#endif
    bool managed_runner_alive() {
        return runners_.size()==1&&runners_[0]->proc&&runners_[0]->proc->alive(nullptr)&&
               !runners_[0]->proc->protocol_error();
    }
#ifdef TT01_INTEGRATED_RESIDUAL_QUALIFICATION
    // No generic report callback or write flush outside the acknowledged
    // operation. Pending writes at this boundary are themselves a fault.
    bool managed_idle_clean(){
        if(!managed_runner_alive())return false;
        auto& r=*runners_[0];
        if(r.proc->pending_writes())return false;
        bool unexpected=false;
        r.proc->poll([&](uint32_t type,const char*,size_t){
            if(type==W_SYNC_DONE||(type>=W_TRUNK_SYSTEM&&type<=W_CALL)
#ifdef TT01_K_TYPED_CONTROL_QUALIFICATION
                ||type==p25_control::wire_type
#endif
#ifdef TT01_D1_PCM_QUALIFICATION
                ||type==managed_iq::pcm::wire_type
#endif
            )unexpected=true;
        });
        return !unexpected&&managed_runner_alive()&&!r.proc->pending_writes();
    }
#endif
#endif

    // the VFO moved (> 100 Hz): everything starts over
    void check_rf(double rf) {
        if (std::fabs(rf - rf_hz_) > 100.0) {
            if (rf_hz_ != 0.0) {
                reset_all();
                report_.clear_all();
                report_.map_clear();
                report_.table_clear();
                report_.plot_clear();
            }
            rf_hz_ = rf;
        }
    }

    // Array plugins: every antenna's block (x = m x n, antenna-major) as
    // SAMPLES_ARRAY (int16 I/Q with a per-message scale)
    void process_array(const std::complex<float>* x, int m, size_t n, float rate, double rf, uint64_t pos) {
        if (rate <= 0 || n == 0 || m < 1 || m > 8) return;
        check_rf(rf);
        for (size_t i = 0; i < runners_.size(); i++) {
            Runner& r = *runners_[i];
            if (!r.known || !r.info.array || !r.proc) continue;
            r.array_rate = rate;
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            if(!send_settings(r))continue;
#else
            send_settings(r);
#endif
            const size_t per = (MAX_PAYLOAD - 32) / (4 * static_cast<size_t>(m));
            const size_t backlog = sync_io_ ? SIZE_MAX : static_cast<size_t>(rate) * 4 * static_cast<size_t>(m);   // ~1 s
            for (size_t a = 0; a < n; a += per) {
                const size_t k = std::min(per, n - a);
                float mx = 1e-9f;
                for (int c = 0; c < m; c++)
                    for (size_t j = a; j < a + k; j++) {
                        const std::complex<float> v = x[static_cast<size_t>(c) * n + j];
                        mx = std::max(mx, std::max(std::fabs(v.real()), std::fabs(v.imag())));
                    }
                const float scale = mx / 32000.0f;
                arr_buf_.resize(32 + k * static_cast<size_t>(m) * 4);
                char* p = arr_buf_.data();
                const uint32_t mm = static_cast<uint32_t>(m), nn = static_cast<uint32_t>(k);
                const uint64_t at = pos + a;
                const uint32_t flags = at != r.array_next ? 1u : 0u;
                const double rr = rate, t0 = static_cast<double>(at) / rate;
                memcpy(p, &mm, 4);
                memcpy(p + 4, &nn, 4);
                memcpy(p + 8, &flags, 4);
                memcpy(p + 12, &scale, 4);
                memcpy(p + 16, &rr, 8);
                memcpy(p + 24, &t0, 8);
                int16_t* q = reinterpret_cast<int16_t*>(p + 32);
                const float inv = 1.0f / scale;
                for (size_t j = a; j < a + k; j++)
                    for (int c = 0; c < m; c++) {
                        const std::complex<float> v = x[static_cast<size_t>(c) * n + j];
                        *q++ = static_cast<int16_t>(std::lrint(v.real() * inv));
                        *q++ = static_cast<int16_t>(std::lrint(v.imag() * inv));
                    }
                if (!r.proc->send(W_SAMPLES_ARRAY, arr_buf_.data(), arr_buf_.size(), backlog)) {
                    r.dropped += k;
                    continue;   // the next block is a gap for the plugin
                }
                r.array_next = at + k;
            }
            auto handler = [this, i](uint32_t type, const char* pp, size_t len) { on_message(i, type, pp, len); };
            if (sync_io_) r.proc->flush_blocking(handler, 60000);
            else r.proc->poll(handler);
        }
        housekeeping();
    }

    void process(const std::complex<float>* x, size_t n, float rate, double rf, uint64_t pos,
                 const std::complex<int16_t>* mc = nullptr, int mc_m = 0, int bw_hz = 0,
                 const AuxStream* aux = nullptr, size_t naux = 0) {
        // n = 0 with internal streams: the VFO's samples were held back this
        // block (the beamformer) - only the internal streams' plugins get
        // samples; the VFO stream's state (AFC phase, resamplers, positions)
        // is left as it is, its plugins are only kept up to date
        if (rate <= 0 || (n == 0 && naux == 0)) return;
        if (pos == DigitalDecoder::NO_POS) pos = next_pos_;
        next_pos_ = pos + n;
        check_rf(rf);
        bool reassign = false;
        if (rate != in_rate_) {
            in_rate_ = rate;
            // plugins at the VFO's own rate start over at the new one
            for (auto& r : runners_)
                if (r->proc && r->known && r->info.sample_rate <= 0 && !r->info.array && r->stream_w == 0 &&
                    r->vfo_rate != in_rate_) {
                    r->proc->stop();
                    r->proc.reset();
                    close_talker(*r);
                    trunk_reset_if(*r);
                    r->retry_ms = 0;
                    r->note = "new VFO rate";
                }
            // Auto detect without internal streams: the plugin set depends on the VFO's rate
            if (mode_ == Mode::AUTO && auto_ids() != runner_ids()) rebuild_runners();
            else reassign = true;
        }
        // the VFO's bandwidth (not its rate) decides which plugins need a
        // wider stream - the page's "too narrow" test
        const int bw = bw_hz > 0 ? bw_hz : static_cast<int>(std::lround(rate));
        if (bw != vfo_bw_) {
            vfo_bw_ = bw;
            reassign = true;
        }
        if (reassign) assign_streams();
        const int64_t t = now_ms();
        if (t - check_ms_ > CHECK_MS) {
            check_ms_ = t;
            periodic(t);
        }
        // AFC mixer at each stream's rate: the VFO's own, then the internal
        // ones this block brought (a wanted one it lacks - the pipeline makes
        // it from the next block - gives its plugins nothing this time)
        const bool afc_off = afc_hz_ == 0.0f;
        if (n > 0) mix(x, n, in_rate_, nco_phase_, mixed_);
        for (auto& s : sbuf_) {
            s.x = nullptr;
            s.n = 0;
            for (size_t k = 0; k < naux; k++) {
                const AuxStream& a = aux[k];
                if (a.width_hz != s.w || !a.x || a.n == 0) continue;
                mix(a.x, a.n, static_cast<float>(s.w), s.nco, s.mixed);
                s.x = a.x;
                s.n = a.n;
                s.pos = a.pos;
                s.mc = afc_off && a.mc && a.mc_m >= 2 ? a.mc : nullptr;
                s.mc_m = s.mc ? a.mc_m : 0;
                break;
            }
        }
        resample(n);
        // every antenna (multichannel plugins at their stream's rate, no AFC
        // correction to apply: what they get is the stream's samples as they are)
        const bool mc_ok = mc && mc_m >= 2 && afc_off;
        for (size_t i = 0; i < runners_.size(); i++) {
            Runner& rn = *runners_[i];
            // array plugins get their samples in process_array(); here they
            // are only started / kept up to date (settings, replies)
            if (rn.known && rn.info.array) {
                run(i, nullptr, 0, static_cast<double>(pos), 1.0);
                continue;
            }
            const Resampled* r = rate_buf(rn);
            if (rn.stream_w == 0) {
                const bool multi = mc_ok && rn.info.multichannel && rate_of(rn) == in_rate_;
                run(i, r ? r->out.data() : nullptr, r ? r->ny : 0, static_cast<double>(pos), r ? in_rate_ / r->rate : 1.0,
                    multi ? mc : nullptr, multi ? mc_m : 0, n);
                continue;
            }
            // an internal stream: its samples' positions in the VFO's stream
            // (the pipeline took the two cascades' delays off), one VFO sample
            // every in_rate_ / plugin rate of its samples
            const StreamBuf* s = stream_buf(rn.stream_w);
            const bool have = s && s->x && r && r->ny;
            const bool multi = have && s->mc && rn.info.multichannel && rate_of(rn) == static_cast<float>(s->w);
            run(i, have ? r->out.data() : nullptr, have ? r->ny : 0, have ? s->pos : 0.0, r ? in_rate_ / r->rate : 1.0,
                multi ? s->mc : nullptr, multi ? s->mc_m : 0, have ? s->n : 0);
        }
        housekeeping();
    }
    // Writes what the plugins' pipes take of what is still queued for them
    // (and reads their replies meanwhile); true while some is left. A burst of
    // an array plugin is ~17 MB, the pipe holds 1 MB: written only when a new
    // block came in, the plugin got ~10 MB/s between bursts (the 100 ms
    // ticks) - less than the 17 MB/s it is sent - and the queue grew
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
    // Only used with a retained sample-bearing fixed P25 manual origin.
    bool manual_runner_alive(){
        return runners_.size()==1&&runners_[0]->proc&&
            runners_[0]->proc->alive(nullptr)&&!runners_[0]->proc->protocol_error();
    }
    // Caller supplies the original retained operation scope. Poll even
    // when there are no pending writes; this is not a new sample origin.
    bool poll_manual_retained(){
        if(!manual_runner_alive())return false;
        auto& r=*runners_[0];
        r.proc->poll([this](uint32_t type,const char* p,size_t n){on_message(0,type,p,n);});
        return manual_runner_alive();
    }
#endif
    bool flush_pending() {
        bool more = false;
        for (size_t i = 0; i < runners_.size(); i++) {
            Runner& r = *runners_[i];
            if (!r.proc || !r.proc->pending_writes()) continue;
            r.proc->poll([this, i](uint32_t type, const char* p, size_t len) { on_message(i, type, p, len); });
            more = more || r.proc->pending_writes();
        }
        return more;
    }
    // a running decoder plugin on the VFO's own stream takes every antenna
    // (kp::Info::multichannel; one on an internal stream asks with StreamWant::mc)
    bool multichannel() const {
        for (const auto& r : runners_)
            if (r->info.multichannel && r->stream_w == 0) return true;
        return false;
    }

    // Everything back to a cold start (VFO retune, decoder switched off and
    // on): the plugins get a RESET, detection starts over
    void reset_all() {
        for (auto& r : runners_) {
            if (r->proc && r->proc->running()) {
                r->proc->send(W_RESET, nullptr, 0, 0);
                // what it reports about a trunked system before it has seen
                // the RESET is stale: dropped until it answers this SYNC
                r->trunk_fence = ++r->sync_sent;
                r->proc->send(W_SYNC, &r->trunk_fence, 4, 0);
            }
            close_talker(*r);   // the plugin forgets its call with the RESET
        }
        trunk_reset();   // ... and its trunked system
        std::lock_guard<std::mutex> lk(st_mu_);
        detected_.clear();
        valid_.clear();
        totals_.clear();
        last_valid_ms_ = 0;
        last_valid_by_.clear();
        afc_hz_ = 0;
        residual_hz_ = 0;
        afc_sum_ = 0;
        afc_n_ = 0;
    }

    // Offline: wait until every plugin answered a SYNC sent after all input
    void drain(int timeout_ms) {
        for (auto& r : runners_)
            if (r->proc && r->proc->running()) {
                uint32_t id = ++r->sync_sent;
                r->proc->send(W_SYNC, &id, 4, 0);
            }
        for (int i = 0; i < timeout_ms; i++) {
            bool done = true;
            for (size_t k = 0; k < runners_.size(); k++) {
                Runner& r = *runners_[k];
                if (!r.proc || !r.proc->running()) continue;
                r.proc->poll([this, k](uint32_t type, const char* p, size_t len) { on_message(k, type, p, len); });
                if (r.sync_done != r.sync_sent) {
                    done = false;
                    if (!r.proc->alive(nullptr)) r.sync_done = r.sync_sent;   // died: nothing more to come
                }
            }
            if (done) break;
            for (auto& r : runners_)
                if (r->proc && r->proc->running() && r->sync_done != r->sync_sent) {
                    r->proc->wait_io(1);
                    break;
                }
        }
        housekeeping();
    }

    struct PluginStatus {
        std::string id, name, version, state, error;
        std::vector<std::string> tail;
        uint64_t dropped = 0;
        double rate = 0, min_vfo_rate = 0;
        int stream_hz = 0;   // the internal stream it runs on (0 = the VFO's own)
        bool map = false;
    };
    struct Status {
        std::string detected, detected_name;
        float offset_hz = 0;
        float rate = 0;
        float min_rate = 0;
        std::map<std::string, std::pair<int, uint64_t>> frames;   // id -> (4 s window, total)
        std::vector<PluginStatus> plugins;
    };
    std::string detected() const {
        std::lock_guard<std::mutex> lk(st_mu_);
        return detected_;
    }
    Status status() const {
        std::lock_guard<std::mutex> lk(st_mu_);
        Status s;
        s.detected = detected_;
        s.offset_hz = afc_hz_ + residual_hz_;
        s.rate = in_rate_;
        int64_t t = now_ms();
        for (const auto& kv : totals_) s.frames[kv.first] = {0, kv.second};
        for (const auto& v : valid_)
            if (t - v.first < DETECT_WINDOW_MS) s.frames[v.second].first++;
        for (const auto& p : status_plugins_) {
            s.plugins.push_back(p);
            // (a plugin on an internal stream has its bandwidth: rate_ok = the VFO's own stream's plugins get theirs)
            if (p.stream_hz == 0) s.min_rate = std::max<float>(s.min_rate, static_cast<float>(p.min_vfo_rate));
            if (p.id == detected_) s.detected_name = p.name;
        }
        return s;
    }

private:
    Report& report_;
    DigitalDecoder* owner_;
    const bool sync_io_;
    const bool streams_on_;            // the caller makes internal streams (DigitalDecoder::internal_streams)
    Mode mode_ = Mode::OFF;
    std::string plugin_;
    Options opts_;
    std::vector<std::unique_ptr<Runner>> runners_;
#ifdef TT01_EVENT_AUDIT_QUALIFICATION
    std::shared_ptr<managed_iq::EventGeneration> event_generation_;
#endif
    uint64_t reg_gen_ = 0;
    int64_t check_ms_ = 0;

    float in_rate_ = 0;
    double rf_hz_ = 0;
    uint64_t next_pos_ = 0;            // VFO stream position after the last block
    double nco_phase_ = 0;
    std::vector<std::complex<float>> mixed_;
    std::vector<char> mc_buf_;   // a SAMPLES_MC message
    // the internal streams in use (Auto detect; StreamWant): this block's
    // samples (x null = none came), mixed by the AFC like the VFO's own
    int vfo_bw_ = 0;                   // the VFO's bandwidth (Hz) of the last block
    struct StreamBuf {
        int w = 0;                     // width = rate
        double nco = 0;
        std::vector<std::complex<float>> mixed;
        const std::complex<float>* x = nullptr;
        size_t n = 0;
        double pos = 0;
        const std::complex<int16_t>* mc = nullptr;
        int mc_m = 0;
    };
    std::vector<StreamBuf> sbuf_;
    std::vector<StreamWant> wants_sent_;
    struct Resampled {
        int w = 0;                     // its stream (0 = the VFO's own)
        float rate = 0;
        msresamp_crcf q = nullptr;     // nullptr = same rate as the input
        std::vector<std::complex<float>> out;
        unsigned int ny = 0;
    };
    std::vector<Resampled> rs_;
    std::vector<char> arr_buf_;        // one SAMPLES_ARRAY message

    // detection / AFC / status (status() reads them from another thread)
    mutable std::mutex st_mu_;
    std::deque<std::pair<int64_t, std::string>> valid_;
    std::map<std::string, uint64_t> totals_;
    std::string detected_;
    float afc_hz_ = 0;
    float residual_hz_ = 0;
    float afc_sum_ = 0;
    int afc_n_ = 0;
    int64_t afc_changed_ms_ = 0;
    int64_t last_valid_ms_ = 0;
    std::map<std::string, int64_t> last_valid_by_;   // plugin -> its last valid frame (the Digital squelch)
    std::map<std::string, int64_t> hold_ms_by_;      // plugin -> its squelch hold (kp::Info::squelch_hold_s)
    std::string lead_tid_sent_, lead_tlabel_sent_;   // what set_lead_talker last got (worker thread)
    // the plugin whose trunked-system reports went out since the last trunk
    // RESET ("" = none: nothing to reset)
    std::string trunk_from_;
    std::vector<PluginStatus> status_plugins_;

    // --- runner set ---------------------------------------------------------
    // all plugins get EOF at once and exit in parallel (a decoder in Auto
    // detect runs several; this can run on the uWS thread when a VFO is removed)
    void stop_all() {
        for (auto& r : runners_) {
            if (r->proc) r->proc->request_stop();
            close_talker(*r);
        }
        trunk_reset();
        for (auto& r : runners_)
            if (r->proc) r->proc->stop();
        runners_.clear();
    }

    void rebuild_runners() {
        for (const auto& r : runners_) report_.choices_clear(r->id);   // their processes stop
        stop_all();
        {
            std::lock_guard<std::mutex> lk(st_mu_);
            detected_.clear();
            valid_.clear();
            totals_.clear();
            afc_hz_ = residual_hz_ = 0;
            afc_sum_ = 0;
            afc_n_ = 0;
        }
        auto& reg = PluginRegistry::instance();
        reg_gen_ = reg.generation();
        std::vector<std::string> ids;
        if (mode_ == Mode::PLUGIN) {
            ids.push_back(plugin_);
        } else if (mode_ == Mode::AUTO) {
            ids = auto_ids();
            bool any = false;
            for (const auto& p : reg.list()) any |= p.built && p.auto_detect && !p.manual_only;
#ifdef _WIN32
            // the Windows build of the plugins is build_windows.bat
            if (!any) report_.event("", "Auto detect: no auto-detect decoder plugins are built (run build_windows.bat)", 0.0);
#else
            if (!any) report_.event("", "Auto detect: no auto-detect decoder plugins are built (run make)", 0.0);
#endif
        }
        for (const auto& id : ids) {
            auto r = std::make_unique<Runner>();
            r->id = id;
            r->known = reg.get(id, &r->info);
            report_.set_label(id, r->known ? r->info.name : id);
            runners_.push_back(std::move(r));
        }
        assign_streams();   // + the resamplers, the status
        update_array_wanted();
    }

    // the pipeline offers every antenna while an array plugin runs here (and
    // only ticks the single-channel path when nothing else needs it)
    void update_array_wanted() {
        bool on = false, only = !runners_.empty();
        double burst = 0.25, period = 1.0;
        for (const auto& r : runners_) {
            if (r->known && r->info.array) {
                on = true;
                burst = r->info.array_burst_s;
                period = r->info.array_period_s;
            } else {
                only = false;
            }
        }
        owner_->set_array_wanted(on, burst, period, on && only);
    }

    // The plugins Auto detect runs on this VFO: the ticked ones, without the
    // manual-only ones. With internal streams every one of them, whatever the
    // VFO's width (assign_streams gives each the stream it needs); without
    // (offline callers) not those that need a much wider VFO either - none
    // until the VFO's rate is known
    std::vector<std::string> auto_ids() const {
        std::vector<std::string> ids;
        if (!streams_on_ && in_rate_ <= 0) return ids;
        for (const auto& p : PluginRegistry::instance().list())
            if (p.built && p.auto_detect && !p.manual_only &&
                (streams_on_ || p.min_vfo_rate <= in_rate_ * AUTO_MAX_RATE_SHORTFALL))
                ids.push_back(p.id);
        return ids;
    }

    // Each runner's stream (Runner::stream_w; AUTO_STREAM_MERGE_RATIO above):
    // the VFO's own when its bandwidth holds the plugin's min_vfo_rate - and
    // always outside Auto detect, without internal streams, before the
    // bandwidth is known, for array plugins - else an internal stream. A
    // plugin at its stream's rate (sample_rate 0) that changes stream starts
    // over at the new rate ("new VFO rate" as on the VFO's own); the others
    // just get their samples from the new one. Then the resamplers, the
    // widths wanted from the pipeline and the status follow
    void assign_streams() {
        std::vector<int> need(runners_.size(), 0);   // efficient width needed, 0 = the VFO's own stream
        if (mode_ == Mode::AUTO && streams_on_ && vfo_bw_ > 0) {
            for (size_t i = 0; i < runners_.size(); i++) {
                const Runner& r = *runners_[i];
                if (!r.known || r.info.array || !(r.info.min_vfo_rate > vfo_bw_)) continue;
                need[i] = efficient_bandwidth_at_least(static_cast<int>(std::ceil(r.info.min_vfo_rate)));
            }
        }
        // the groups: [narrowest, widest] of the needs, ascending
        std::vector<int> u;
        for (int w : need)
            if (w > 0) u.push_back(w);
        std::sort(u.begin(), u.end());
        u.erase(std::unique(u.begin(), u.end()), u.end());
        std::vector<std::pair<int, int>> g;
        for (int w : u) {
            if (g.empty() || w > AUTO_STREAM_MERGE_RATIO * g.back().first) g.push_back({w, w});
            else g.back().second = w;
        }
        while (g.size() > static_cast<size_t>(DigitalDecoder::MAX_STREAMS)) {
            size_t best = 0;
            double bq = 1e300;
            for (size_t k = 0; k + 1 < g.size(); k++) {
                const double q = static_cast<double>(g[k + 1].second) / g[k].first;
                if (q < bq) bq = q, best = k;
            }
            g[best].second = g[best + 1].second;
            g.erase(g.begin() + static_cast<std::ptrdiff_t>(best) + 1);
        }
        for (size_t i = 0; i < runners_.size(); i++) {
            Runner& r = *runners_[i];
            int w = 0;
            if (need[i] > 0)
                for (const auto& p : g)
                    if (need[i] >= p.first && need[i] <= p.second) w = p.second;
            if (w == r.stream_w) continue;
            r.stream_w = w;
            if (r.proc && r.known && r.info.sample_rate <= 0 && r.vfo_rate != stream_rate(w)) {
                r.proc->stop();
                r.proc.reset();
                close_talker(r);
                r.retry_ms = 0;
                r.note = "new VFO rate";
            }
        }
        // the stream buffers (an existing one keeps its AFC phase)
        std::vector<StreamBuf> sb;
        std::vector<StreamWant> wants;
        for (const auto& p : g) {
            StreamWant sw;
            sw.width_hz = p.second;
            for (const auto& r : runners_)
                if (r->stream_w == p.second && r->known && r->info.multichannel && rate_of(*r) == static_cast<float>(p.second))
                    sw.mc = true;
            wants.push_back(sw);
            StreamBuf b;
            b.w = p.second;
            for (auto& o : sbuf_)
                if (o.w == b.w) b = std::move(o);
            sb.push_back(std::move(b));
        }
        sbuf_ = std::move(sb);
        bool same = wants.size() == wants_sent_.size();
        for (size_t k = 0; same && k < wants.size(); k++)
            same = wants[k].width_hz == wants_sent_[k].width_hz && wants[k].mc == wants_sent_[k].mc;
        if (!same) {
            wants_sent_ = wants;
            owner_->set_wanted_streams(wants);
        }
        rebuild_resamplers();
        publish_status();
    }
    float stream_rate(int w) const { return w > 0 ? static_cast<float>(w) : in_rate_; }
    const StreamBuf* stream_buf(int w) const {
        for (const auto& s : sbuf_)
            if (s.w == w) return &s;
        return nullptr;
    }

    // the AFC mixer: x down by afc_hz_ at `rate` into out. No correction
    // (yet, or the plugins report no offset - e.g. ADS-B at 2.4 MHz): a plain
    // copy instead of a sin/cos per sample, and nothing to keep continuous -
    // the mixer's phase goes back to 0. It used to keep the last correction's
    // phase for good, so once any decoder on this VFO had reported a
    // frequency error (D-STAR, P25, ...) every later multichannel plugin
    // (lora, ism) got one antenna only (mc_ok in process) until kraken_doa
    // restarted
    void mix(const std::complex<float>* x, size_t n, float rate, double& phase, std::vector<std::complex<float>>& out) {
        out.resize(n);
        const float w = -2.0f * static_cast<float>(M_PI) * afc_hz_ / rate;
        if (w == 0.0f) {
            phase = 0.0;
            std::copy(x, x + n, out.begin());
            return;
        }
        for (size_t i = 0; i < n; i++) {
            out[i] = x[i] * std::polar(1.0f, static_cast<float>(phase));
            phase += w;
        }
        phase = std::remainder(phase, 2.0 * M_PI);
    }
    std::vector<std::string> runner_ids() const {
        std::vector<std::string> ids;
        for (const auto& r : runners_) ids.push_back(r->id);
        return ids;
    }

    void destroy_resamplers() {
        for (auto& r : rs_)
            if (r.q) msresamp_crcf_destroy(r.q);
        rs_.clear();
    }

    // a plugin's input rate (kp::Info::sample_rate 0: its stream's own)
    float rate_of(const Runner& rn) const {
        if (!rn.known) return 48000.0f;
        return rn.info.sample_rate > 0 ? static_cast<float>(rn.info.sample_rate) : stream_rate(rn.stream_w);
    }

    // one resampler per (stream, plugin rate) in use
    void rebuild_resamplers() {
        destroy_resamplers();
        if (in_rate_ <= 0) return;
        for (auto& rn : runners_) {
            if (rn->known && rn->info.array) continue;   // their samples aren't resampled
            const float rate = rate_of(*rn);
            bool have = false;
            for (auto& r : rs_) have |= r.w == rn->stream_w && r.rate == rate;
            if (have) continue;
            Resampled r;
            r.w = rn->stream_w;
            r.rate = rate;
            const float in = stream_rate(r.w);
            if (std::fabs(rate - in) > 0.5f) r.q = msresamp_crcf_create(rate / in, 60.0f);
            rs_.push_back(std::move(r));
        }
    }

    // this block of every stream to the rates its plugins take (a stream
    // this block didn't bring: nothing)
    void resample(size_t n) {
        for (auto& r : rs_) {
            const std::complex<float>* in = mixed_.data();
            size_t k = n;
            if (r.w > 0) {
                const StreamBuf* s = stream_buf(r.w);
                in = s && s->x ? s->mixed.data() : nullptr;
                k = in ? s->n : 0;
            }
            unsigned int ny = 0;
            if (k > 0) {
                r.out.resize(static_cast<size_t>(std::ceil(k * r.rate / stream_rate(r.w))) + 64);
                if (r.q) {
                    msresamp_crcf_execute(r.q, const_cast<std::complex<float>*>(in), static_cast<unsigned int>(k),
                                          r.out.data(), &ny);
                } else {
                    std::copy(in, in + k, r.out.begin());
                    ny = static_cast<unsigned int>(k);
                }
            }
            r.ny = ny;
        }
    }

    const Resampled* rate_buf(const Runner& rn) const {
        const float rate = rate_of(rn);
        for (const auto& r : rs_)
            if (r.w == rn.stream_w && r.rate == rate) return &r;
        return nullptr;
    }

    // every CHECK_MS: rebuilt plugins, the plugin list (Auto detect), status
    void periodic(int64_t t) {
        auto& reg = PluginRegistry::instance();
        if (mode_ == Mode::AUTO && reg.generation() != reg_gen_) {
            report_.event("", "Decoder plugins changed - restarting auto detection", 0.0);
            rebuild_runners();
            return;
        }
        for (auto& r : runners_) {
            if (!r->proc) continue;
            int64_t m = mtime_ms(r->info.exe);
            if (m != 0 && m != r->info.mtime) {
                r->proc->stop();
                r->proc.reset();
                close_talker(*r);
                trunk_reset_if(*r);
                r->retry_ms = 0;
                r->note = "rebuilt";
                continue;
            }
            if (t - r->started_ms > 60000) r->crashes = 0;
            r->tail = r->proc->stderr_tail();
        }
        publish_status();
    }

    void publish_status() {
        std::vector<PluginStatus> v;
        for (const auto& r : runners_) {
            PluginStatus p;
            p.id = r->id;
            p.name = r->known ? r->info.name : r->id;
            p.version = r->known ? r->info.version : "";
            p.state = r->state;
            p.error = r->error;
            p.tail = r->tail;
            p.dropped = r->dropped;
            p.rate = r->known ? rate_of(*r) : 0;
            p.min_vfo_rate = r->known ? r->info.min_vfo_rate : 12500;
            p.stream_hz = r->stream_w;
            p.map = r->known && r->info.map;
            v.push_back(std::move(p));
        }
        std::lock_guard<std::mutex> lk(st_mu_);
        status_plugins_ = std::move(v);
    }

    // --- one plugin ---------------------------------------------------------
    // the plugin whose voice / carrier offset counts: the fixed one, or the
    // one Auto detect locked onto
    bool is_lead(const Runner& r) const { return mode_ == Mode::PLUGIN || r.id == detected_; }

    void problem(Runner& r, const std::string& state, const std::string& err, int64_t retry_ms) {
        r.state = state;
        r.error = err;
        if (err != r.note) report_.event(r.id, err, 0.0);
        r.note = err;
        r.retry_ms = now_ms() + retry_ms;
        publish_status();
    }

    void start(Runner& r, int64_t t) {
        auto& reg = PluginRegistry::instance();
        PluginInfo pi;
        bool found = reg.get(r.id, &pi);
        if (!found || !pi.built || pi.mtime != mtime_ms(pi.exe)) {
            reg.scan();   // new / rebuilt since the last scan
            found = reg.get(r.id, &pi);
        }
        if (!found) return problem(r, "missing", "Plugin '" + r.id + "' is not installed", PLUGIN_RETRY_MS);
        if (!pi.built) return problem(r, "not built", pi.name + ": " + pi.error, PLUGIN_RETRY_MS);
        // at the VFO's own rate: not before it is known
        const bool native = pi.sample_rate <= 0 && !pi.array;
        if (native && !(in_rate_ > 0)) return;
        const bool rebuilt = r.note == "rebuilt";
        const bool rate_changed = !r.known || pi.sample_rate != r.info.sample_rate;
        // a rebuilt plugin may need another bandwidth: its stream follows
        const bool need_changed = !r.known || pi.min_vfo_rate != r.info.min_vfo_rate ||
                                  pi.multichannel != r.info.multichannel || pi.array != r.info.array;
        r.info = pi;
        r.known = true;
        report_.set_label(r.id, pi.name);
        {
            std::lock_guard<std::mutex> lk(st_mu_);
            if (pi.squelch_hold_s > 0) hold_ms_by_[r.id] = static_cast<int64_t>(pi.squelch_hold_s * 1000);
            else hold_ms_by_.erase(r.id);
        }
        if (need_changed) assign_streams();   // (+ the resamplers)
        else if (rate_changed) rebuild_resamplers();
        update_array_wanted();
        r.array_next = ~0ull;
        const double srate = stream_rate(r.stream_w);
        r.vfo_rate = native ? srate : 0;
        r.proc = std::make_unique<PluginProcess>();
        std::string err;
        std::vector<std::string> args{pi.exe, "--serve"};
        if (native) {
            char b[32];
            snprintf(b, sizeof b, "%.3f", srate);
            args.push_back("--rate");
            args.push_back(b);
        }
        if (!r.proc->start(args, &err)) {
            r.proc.reset();
            return problem(r, "error", pi.name + ": " + err, PLUGIN_RETRY_MS);
        }
        r.started_ms = t;
        close_talker(r);
        report_.choices_clear(r.id);   // a new process: what the old one listed is gone
        r.audio_channel = -1;
        r.written = 0;
        r.pos_map.clear();
        if (pi.messages) deliver_message(owner_, r.id, "", "", 0);   // get the street data ready
        r.verbose_sent = r.voice_sent = r.raw_sent = r.video_sent = -1;
        r.station_sent = 0;
        r.rf_sent = -1;
        r.opts_sent.clear();
        r.sync_sent = r.sync_done = r.trunk_fence = 0;
        r.state = "running";
        r.error.clear();
        // a fixed decoder says it started; in Auto detect only restarts are news
        if (rebuilt) report_.event(r.id, "Rebuilt plugin loaded: " + pi.name + " " + pi.version, 0.0);
        else if (!r.note.empty()) report_.event(r.id, pi.name + " restarted", 0.0);
        else if (mode_ == Mode::PLUGIN) report_.event(r.id, "Plugin started: " + pi.name + " " + pi.version, 0.0);
        r.note.clear();
        publish_status();
    }

    // the VFO is set to Log All and logging to disk is allowed: raw frames
    // and the repeated messages are wanted
    bool log_all() const { return opts_.log == LOG_ALL && log_allowed_.load(); }

#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
    bool send_settings(Runner& r) {
        bool failed=false;
        auto send=[&](uint32_t type,const void* data,size_t len,size_t cap){
            if(failed)return;
            if(settings_test::before_send&&settings_test::before_send(owner_,type))
                r.proc->request_stop();
            const bool sent=r.proc->send(type,data,len,cap);
            if(!sent){failed=true;retire_manual_context_exact();}
            if(settings_test::after_send)settings_test::after_send(owner_,type,sent);
        };
#else
    void send_settings(Runner& r) {
#endif
        // kp::Host::verbose: "Show all messages", or Log All in effect
        const int verbose = opts_.verbose || log_all() ? 1 : 0;
        if (verbose != r.verbose_sent) {
            std::string kv = std::string("verbose=") + (verbose ? "1" : "0");
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            send(W_OPTION, kv.data(), kv.size(), 0);
#else
            r.proc->send(W_OPTION, kv.data(), kv.size(), 0);
#endif
            r.verbose_sent = verbose;
        }
        // the receiver's location (kp::Host::station)
        const uint64_t sg = station_gen.load();
        if (sg != r.station_sent) {
            std::string st;
            {
                std::lock_guard<std::mutex> lk(station_mu);
                st = station_text;
            }
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            send(W_STATION, st.data(), st.size(), 0);
#else
            r.proc->send(W_STATION, st.data(), st.size(), 0);
#endif
            r.station_sent = sg;
        }
        // the RF of the plugin's 0 Hz (kp::Host::rf_hz): the VFO's frequency
        // plus the AFC correction (the mixer moves afc_hz_ to 0 Hz). Resent when
        // it moves > 10 Hz, and after a (re)start. Never ",1" (mirrored) since
        // the Invert option went
        if (const double rf0 = rf_hz_ > 0 ? rf_hz_ + afc_hz_ : 0.0; r.rf_sent < 0 || std::fabs(rf0 - r.rf_sent) > 10.0) {
            char b[64] = "";
            if (rf0 > 0) snprintf(b, sizeof b, "%.1f", rf0);
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            send(W_RF, b, strlen(b), 0);
#else
            r.proc->send(W_RF, b, strlen(b), 0);
#endif
            r.rf_sent = rf0;
        }
        // raw frames for the decoder data log (Log All)
        const int raw = log_all() ? 1 : 0;
        if (raw != r.raw_sent) {
            std::string kv = std::string("log_raw=") + (raw ? "1" : "0");
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            send(W_OPTION, kv.data(), kv.size(), 0);
#else
            r.proc->send(W_OPTION, kv.data(), kv.size(), 0);
#endif
            r.raw_sent = raw;
        }
        // video plugins: is anyone watching? (kp::Host::video_wanted - they
        // skip the render / encode while not)
        if (r.info.video) {
            const int vid = video_wanted.load() ? 1 : 0;
            if (vid != r.video_sent) {
                std::string kv = std::string("video_wanted=") + (vid ? "1" : "0");
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
                send(W_OPTION, kv.data(), kv.size(), 0);
#else
                r.proc->send(W_OPTION, kv.data(), kv.size(), 0);
#endif
                r.video_sent = vid;
            }
        }
        // only the decoder whose voice is played (transcribed, recorded) runs its vocoder
        const int voice = (is_lead(r) && (owner_->voice_wanted() || owner_->voice_tap() || owner_->record_tap())) ? 1 : 0;
        if (voice != r.voice_sent) {
            uint8_t b = static_cast<uint8_t>(voice);
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            send(W_VOICE_WANTED, &b, 1, 0);
#else
            r.proc->send(W_VOICE_WANTED, &b, 1, 0);
#endif
            r.voice_sent = voice;
        }
        // the plugin's own options ("<id>.<key>"); a removed one goes back
        // to the default (value "")
        const std::string prefix = r.id + ".";
        std::map<std::string, std::string> want;
        for (auto it = opts_.plugin.lower_bound(prefix); it != opts_.plugin.end() && it->first.rfind(prefix, 0) == 0; ++it)
            want[it->first.substr(prefix.size())] = it->second;
        for (const auto& kv : want) {
            auto s = r.opts_sent.find(kv.first);
            if (s != r.opts_sent.end() && s->second == kv.second) continue;
            std::string m = kv.first + "=" + kv.second;
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            send(W_OPTION, m.data(), m.size(), 0);
#else
            r.proc->send(W_OPTION, m.data(), m.size(), 0);
#endif
            r.opts_sent[kv.first] = kv.second;
        }
        for (auto it = r.opts_sent.begin(); it != r.opts_sent.end();) {
            if (want.count(it->first)) { ++it; continue; }
            std::string m = it->first + "=";
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            send(W_OPTION, m.data(), m.size(), 0);
#else
            r.proc->send(W_OPTION, m.data(), m.size(), 0);
#endif
            it = r.opts_sent.erase(it);
        }
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
        return !failed;
#endif
    }

    // y = this block resampled to the plugin's rate; its sample j is VFO
    // stream position pos + j * step (an internal stream's: a fractional pos,
    // step = the VFO's rate / the plugin's)
    void run(size_t idx, const std::complex<float>* y, unsigned int ny, double pos, double step,
             const std::complex<int16_t>* mc = nullptr, int mc_m = 0, size_t mc_n = 0) {
        Runner& r = *runners_[idx];
        const int64_t t = now_ms();
        if (!r.proc) {
            if (t < r.retry_ms) return;
            start(r, t);
            if (!r.proc) return;
            // start() may have rebuilt the resamplers (new rate): this block
            // is skipped for this plugin
            const Resampled* rb = rate_buf(r);
            if (!rb || rb->out.data() != y) ny = 0;
        }
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
        if(!send_settings(r))return;
#else
        send_settings(r);
#endif
        if (mc && ny) {
            // every antenna: SAMPLES_MC = uint32 m + n x m complex int16 (the
            // stream's rate: step 1 on the VFO's own)
            const size_t backlog = sync_io_ ? SIZE_MAX : static_cast<size_t>(r.prate()) * 4 * static_cast<size_t>(mc_m);
            const size_t n = std::min<size_t>(mc_n, ny);
            for (size_t p = 0; p < n; p += PLUGIN_CHUNK) {
                const size_t k = std::min<size_t>(PLUGIN_CHUNK, n - p);
                mc_buf_.resize(4 + k * static_cast<size_t>(mc_m) * 4);
                const uint32_t m32 = static_cast<uint32_t>(mc_m);
                memcpy(mc_buf_.data(), &m32, 4);
                std::complex<int16_t>* d = reinterpret_cast<std::complex<int16_t>*>(mc_buf_.data() + 4);
                const std::complex<int16_t>* q = mc + p * static_cast<size_t>(mc_m);
                const size_t cnt = k * static_cast<size_t>(mc_m);
                std::copy(q, q + cnt, d);
                if (!r.proc->send(W_SAMPLES_MC, mc_buf_.data(), mc_buf_.size(), backlog)) {
                    r.dropped += k;
                    continue;
                }
                r.pos_map.push_back({r.written, k, pos + static_cast<double>(p) * step, step});
                r.written += k;
            }
            ny = 0;   // (sent)
        }
        const size_t backlog = sync_io_ ? SIZE_MAX : static_cast<size_t>(r.prate()) * 8;   // 1 s
        for (size_t p = 0; p < ny; p += PLUGIN_CHUNK) {
            size_t k = std::min<size_t>(PLUGIN_CHUNK, ny - p);
            if (!r.proc->send(W_SAMPLES, y + p, k * sizeof(std::complex<float>), backlog)) {
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
                retire_manual_context_exact();
#else
                managed_iq::manual_output::retire_context();
#endif
#endif
                r.dropped += k;   // never reaches the plugin: its clock doesn't advance
                continue;
            }
            r.pos_map.push_back({r.written, k, pos + static_cast<double>(p) * step, step});
            r.written += k;
        }
        const uint64_t keep = static_cast<uint64_t>(r.prate() * POS_MAP_SECONDS);
        while (r.pos_map.size() > 1 && r.pos_map.front().p0 + r.pos_map.front().n + keep < r.written)
            r.pos_map.pop_front();
        auto handler = [this, idx](uint32_t type, const char* p, size_t len) { on_message(idx, type, p, len); };
        if (sync_io_) r.proc->flush_blocking(handler, 60000);
        else r.proc->poll(handler);
        kproc::ExitStatus st;
        const bool bad = r.proc->protocol_error();
        if (bad || !r.proc->alive(&st)) {
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            retire_manual_context_exact();
#else
            managed_iq::manual_output::retire_context();
#endif
#endif
            r.proc->poll(handler);   // whatever it said last
            std::string why;
            if (bad) why = "sent a malformed message (printing to stdout?)";
            else why = st.describe();   // "crashed (<strsignal>)" / "exited with status N"
            r.tail = r.proc->stderr_tail();
            if (!r.tail.empty()) why += " - last output: " + r.tail.back();
            r.proc->stop();
            r.proc.reset();
            close_talker(r);
            trunk_reset_if(r);
            report_.choices_clear(r.id);   // (the restarted process sends its own)
            r.crashes++;
            int64_t delay = std::min<int64_t>(30000, 1000LL << std::min(r.crashes, 5));
            r.note.clear();
            problem(r, "crashed", r.info.name + " " + why + "; restarting in " + std::to_string(delay / 1000) + " s", delay);
        }
    }

    void on_message(size_t idx, uint32_t type, const char* p, size_t len) {
        Runner& r = *runners_[idx];
        switch (type) {
            case W_FACT: {
                size_t z = std::find(p, p + len, '\0') - p;
                std::string k(p, z), v = z < len ? std::string(p + z + 1, len - z - 1) : std::string();
                if (k.empty() || k.size() > 64) break;
                if (v.size() > 400) v.resize(400);
                if (v.empty()) report_.erase(r.id, k);
                else report_.set(r.id, k, v);
                break;
            }
            case W_EVENT: {
                if (len < 4) break;
                float d;
                memcpy(&d, p, 4);
                std::string text(p + 4, std::min<size_t>(len - 4, 1000));
                if (report_.event(r.id, text, is_finite_value(d) ? std::clamp<double>(d, 0.0, 3600.0) : 2.0)) {
                    LogRecord lr;
                    lr.type = "event";
                    lr.plugin = r.id;
                    lr.text = text;
                    lr.rf_hz = rf_hz_;
                    deliver_record(owner_, lr);
                }
                break;
            }
            case W_VALID:
                on_valid(r.id);
                if (len > 0) on_valid_span(r, p, len);
                break;
            case W_AUDIO:
                if (is_lead(r) && (owner_->voice_wanted() || owner_->voice_tap() || owner_->record_tap()) && len >= 4) {
                    std::vector<float> a(len / 4);
                    memcpy(a.data(), p, a.size() * 4);
                    for (float& v : a)
                        if (!is_finite_value(v)) v = 0;
                    if (owner_->voice_wanted()) owner_->push_voice(a.data(), a.size());
                    if (owner_->voice_tap()) {
                        // who is talking: the open talker on the channel the
                        // plugin says its audio is from (DMR: the timeslot it
                        // plays - with both slots busy, the most recent talker
                        // was often the OTHER slot's radio); not said: the one
                        // that started first (decoders play the first to talk)
                        const Runner::OpenTalker* t = nullptr;
                        if (r.audio_channel >= 0) {
                            auto it = r.talkers.find(r.audio_channel);
                            if (it != r.talkers.end()) t = &it->second;
                        } else {
                            for (const auto& kv : r.talkers)
                                if (!t || kv.second.start < t->start) t = &kv.second;
                        }
                        deliver_voice_tap(owner_, a.data(), a.size(), r.id, t ? t->id : "", t ? t->label : "", rf_hz_);
                    }
                    if (owner_->record_tap()) deliver_record_voice(owner_, a.data(), a.size());
                }
                break;
            case W_AUDIO_CHANNEL:
                if (len >= 4) {
                    int32_t c;
                    memcpy(&c, p, 4);
                    r.audio_channel = c >= 0 && c < 8 ? c : -1;
                }
                break;
            case W_VOICE_STATE:
                if (is_lead(r)) owner_->set_voice_state(std::string(p, std::min<size_t>(len, 200)));
                break;
            case W_FREQ_ERROR:
                if (is_lead(r) && len >= 4) {
                    float hz;
                    memcpy(&hz, p, 4);
                    if (is_finite_value(hz)) on_freq_error(std::clamp(hz, -AFC_LIMIT_HZ, AFC_LIMIT_HZ));
                }
                break;
            case W_SYNC_DONE:
                if (len >= 4) memcpy(&r.sync_done, p, 4);
                break;
            case W_MAP_POINT:
                on_map_point(r.id, p, len);
                break;
            case W_MAP_REMOVE:
                report_.map_remove(r.id, std::string(p, std::min<size_t>(len, 32)));
                break;
            case W_TABLE_COLUMNS: {
                // no columns (an empty payload) = no table: the page shows none
                auto f = len ? split0(p, len, 40) : std::vector<std::string>{};
                for (auto& c : f) c.resize(std::min<size_t>(c.size(), 40));
                report_.table_columns(r.id, std::move(f));
                break;
            }
            case W_TABLE_ROW: {
                auto f = split0(p, len, 41);
                if (f.empty() || f[0].empty() || f[0].size() > 64) break;
                std::string key = f[0];
                f.erase(f.begin());
                for (auto& c : f) c.resize(std::min<size_t>(c.size(), 200));
                report_.table_row(r.id, key, std::move(f));
                break;
            }
            case W_RAW: {
                if (!log_all() || len == 0) break;
                LogRecord lr;
                lr.type = "raw";
                lr.plugin = r.id;
                lr.text.assign(p, std::min<size_t>(len, 2000));
                lr.rf_hz = rf_hz_;
                deliver_record(owner_, lr);
                break;
            }
            case W_TABLE_REMOVE:
                report_.table_remove(r.id, std::string(p, std::min<size_t>(len, 64)));
                break;
            case W_TABLE_KEEP: {
                const double s = strtod(std::string(p, std::min<size_t>(len, 32)).c_str(), nullptr);
                if (is_finite_value(s)) report_.table_keep(r.id, static_cast<int64_t>(s * 1000));
                break;
            }
            case W_TABLE_DETAIL: {
                // key, then label / value pairs
                auto f = split0(p, len, 1 + 2 * 200);
                if (f.empty() || f[0].empty() || f[0].size() > 64) break;
                std::vector<std::pair<std::string, std::string>> lines;
                for (size_t i = 1; i + 1 < f.size(); i += 2) {
                    f[i].resize(std::min<size_t>(f[i].size(), 80));
                    f[i + 1].resize(std::min<size_t>(f[i + 1].size(), 400));
                    lines.emplace_back(std::move(f[i]), std::move(f[i + 1]));
                }
                report_.table_detail(r.id, f[0], std::move(lines));
                break;
            }
            case W_TALKER:
                on_talker(r, p, len);
                break;
            case W_TALKER_FORGET: {
                if (len == 0) break;
                TalkerSpan s;
                s.plugin = r.id;
                s.id.assign(p, std::min<size_t>(len, 32));
                s.forget = true;
                owner_->deliver_talker(s);
                break;
            }
            case W_TALKER_END: {
                auto f = split0(p, std::min<size_t>(len, 64), 2);
                if (f.empty()) break;
                auto it = r.talkers.find(f.size() > 1 ? talker_channel(f[1]) : 0);
                if (it == r.talkers.end()) break;
                uint64_t at;
                if (r.vfo_pos(strtod(f[0].c_str(), nullptr), r.prate(), &at))
                    it->second.end = std::max(it->second.start, at);
                close_talker(r, it);
                break;
            }
            case W_SPATIAL:
                on_spatial(r, p, len);
                break;
            case W_SPATIAL_REMOVE: {
                // kp::Host::spatial_remove: id, "" = every spatial talker of the plugin
                SpatialReport s;
                s.plugin = r.id;
                s.id.assign(p, std::min<size_t>(len, 32));
                s.remove = true;
                owner_->deliver_spatial(s);
                break;
            }
            case W_PLOT:
                on_plot(r, p, len);
                break;
            case W_PLOT_EX:
                on_plot_ex(r, p, len);
                break;
            case W_VIDEO:
                on_video(r, p, len);
                break;
            case W_OPTION_CHOICES:
                on_option_choices(r, p, len);
                break;
#ifdef TT01_K_TYPED_CONTROL_QUALIFICATION
            case p25_control::wire_type: {
                // Dedicated native evidence; no PluginEvent, ordinary
                // callback, catalog fallback or managed voice CALL.
                namespace mo=managed_iq::manual_output;
                const auto& ctx=mo::context;
                if(r.id!="p25"||!is_lead(r)||r.sync_done<r.trunk_fence||
                   !ctx.stamp||ctx.closing||!ctx.generation||
                   !ctx.stamp->segment()||!ctx.stamp->observed_rf().bound||
                   ctx.stamp->decoder_identity()!=owner_)break;
                if(auto o=p25_control::parse(std::string_view(p,len)))
                    p25_control::enqueue(owner_,*o);
                else retire_manual_context_exact();
                break;
            }
#endif
            case W_TRUNK_SYSTEM:
            case W_TRUNK_CHANNEL:
            case W_CONTROL_CHANNEL:
            case W_GRANT:
            case W_GRANT_END:
            case W_CALL:
                on_trunk(r, type, p, len);
                break;
            case W_TUNE: {
                // kp::Host::tune - only plugins that declare kp::Info::tunes
                const double hz = num_or_nan(std::string(p, std::min<size_t>(len, 32)));
                char mhz[32];
                snprintf(mhz, sizeof mhz, "%.6f MHz", is_finite_value(hz) ? hz / 1e6 : 0.0);
                std::string why;
                const int64_t now = now_ms();
                if (!r.info.tunes) why = "the plugin doesn't declare kp::Info::tunes";
                else if (!is_finite_value(hz) || hz <= 0) why = "not a frequency";
                else if (now - r.last_tune_ms < TUNE_MIN_GAP_MS) why = "too soon after the last one";
                else why = owner_->deliver_tune(hz);
                if (why.empty()) r.last_tune_ms = now;
                else report_.event("", "Retune to " + std::string(mhz) + " asked by " + r.info.name + " refused: " + why, 10.0);
                break;
            }
            case W_MESSAGE: {
                auto f = split0(p, len, 2);
                if (f.size() == 2 && !f[1].empty()) {
                    deliver_message(owner_, r.id, f[0].substr(0, 64), f[1].substr(0, 2000), rf_hz_);
                    LogRecord lr;
                    lr.type = "message";
                    lr.plugin = r.id;
                    lr.from = f[0].substr(0, 64);
                    lr.text = f[1].substr(0, 2000);
                    lr.rf_hz = rf_hz_;
                    deliver_record(owner_, lr);
                }
                break;
            }
            default:
                break;
        }
    }

    // --- trunked systems (kp::wire::TRUNK_SYSTEM .. CALL) -----------------
    // the lead plugin's reports, checked again (cut to the limits, control
    // characters removed, frequencies outside (0, 6 GHz] NAN, slots outside
    // -1..15 -1, options checked), to the owner's TrunkHandler. A channel
    // without a name, a CALL with an unknown state or a GRANT whose E fields
    // aren't there are dropped
    double stream_time() const { return in_rate_ > 0 ? static_cast<double>(next_pos_) / in_rate_ : static_cast<double>(NAN); }
    void trunk_send(const std::string& plugin, trunk::PluginEvent&& ev) {
        ev.t_s = stream_time();
        owner_->deliver_trunk(plugin, std::move(ev));
    }
    // the reports so far are stale: one RESET (only if there were any)
    void trunk_reset() {
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
        retire_manual_context_exact();
#else
        managed_iq::manual_output::retire_context();
#endif
#endif
        if (trunk_from_.empty()) return;
        std::string id;
        id.swap(trunk_from_);
        owner_->set_trunk_reported(false);
        trunk::PluginEvent ev;
        ev.kind = trunk::PluginEvent::RESET;
        trunk_send(id, std::move(ev));
    }
    void trunk_reset_if(const Runner& r) {
        if (trunk_from_ == r.id) trunk_reset();
    }
    // text: valid UTF-8 without C0 / DEL / C1 controls, cut to max bytes at
    // a character boundary - the SDK's own rule (kp::wire::clean_text, the
    // plugin side applied it already), so a name is the same bytes everywhere
    static std::string tk_text(const std::string& in, size_t max) { return kp::wire::clean_text(in, max); }
    // a lowercase token ([a-z0-9_], with '-' if dash) of <= max bytes, else ""
    static std::string tk_token(const std::string& in, size_t max, bool dash) {
        if (in.size() > max) return "";
        for (char c : in)
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || (dash && c == '-'))) return "";
        return in;
    }
    static double tk_freq(const std::string& t) {
        const double v = num_or_nan(t);
        return is_finite_value(v) && v > 0 && v <= TRUNK_FREQ_MAX_HZ ? v : static_cast<double>(NAN);
    }
    // a whole decimal integer in lo..hi, else def ("" = def)
    static long long tk_int(const std::string& t, long long lo, long long hi, long long def) {
        if (t.empty() || t.size() > 20) return def;
        char* e = nullptr;
        errno = 0;
        const long long v = strtoll(t.c_str(), &e, 10);
        return (e && *e == '\0' && errno == 0 && v >= lo && v <= hi) ? v : def;
    }
    // a channel from f[at] ..: name, number, freq_hz, slot - and uplink_hz in f[up] (NAN when not there)
    static bool tk_channel(const std::vector<std::string>& f, size_t at, size_t up, trunk::Channel* c) {
        auto fld = [&](size_t i) { return i < f.size() ? f[i] : std::string(); };
        c->name = tk_text(fld(at), TRUNK_NAME_MAX);
        if (c->name.empty()) return false;
        c->number = tk_int(fld(at + 1), 0, std::numeric_limits<long long>::max(), -1);
        c->freq_hz = tk_freq(fld(at + 2));
        c->slot = static_cast<int>(tk_int(fld(at + 3), -1, TRUNK_SLOT_MAX, -1));
        c->uplink_hz = tk_freq(fld(up));
        return true;
    }
    void on_trunk(Runner& r, uint32_t type, const char* p, size_t len) {
        if (!is_lead(r)) return;   // Auto detect: only the plugin it locked onto
        if (r.sync_done < r.trunk_fence) return;   // from before the last RESET
        trunk::PluginEvent ev;
        auto fl = [](const std::string& flags, char c) { return flags.find(c) != std::string::npos; };
        switch (type) {
            case W_TRUNK_SYSTEM: {
                auto f = split0(p, len, 4);
                f.resize(4);
                ev.kind = trunk::PluginEvent::SYSTEM;
                ev.sys_key = f[0].substr(0, TRUNK_KEY_MAX);
                for (char& c : ev.sys_key)
                    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) c = '_';
                ev.sys_name = tk_text(f[1], TRUNK_TEXT_MAX);
                ev.sys_site = tk_text(f[2], TRUNK_TEXT_MAX);
                ev.control = f[3] == "1";
                break;
            }
            case W_TRUNK_CHANNEL:
            case W_CONTROL_CHANNEL:
            case W_GRANT_END: {
                const auto f = split0(p, len, 5);
                if (!tk_channel(f, 0, 4, &ev.ch)) return;
                ev.kind = type == W_TRUNK_CHANNEL     ? trunk::PluginEvent::CHANNEL
                          : type == W_CONTROL_CHANNEL ? trunk::PluginEvent::CONTROL
                                                      : trunk::PluginEvent::GRANT_END;
                break;
            }
            case W_GRANT: {
                // E, E fixed fields (the ones this host knows taken, the rest
                // skipped), then option key / value pairs
                const size_t nl = static_cast<size_t>(std::find(p, p + std::min<size_t>(len, 4), '\0') - p);
                const std::string es(p, nl);
                if (es.empty() || es.size() > 2 || es.find_first_not_of("0123456789") != std::string::npos) return;
                const size_t ne = static_cast<size_t>(std::stoi(es));
                const auto f = split0(p, len, 1 + ne + 2 * 64);
                if (f.size() < 1 + ne) return;
                std::vector<std::string> x(GRANT_FIXED_KNOWN);
                for (size_t i = 0; i < GRANT_FIXED_KNOWN && i < ne; i++) x[i] = f[1 + i];
                // name, number, freq_hz, slot, target, group, source, flags, decoder, demod, bw_hz, uplink_hz
                if (!tk_channel(x, 0, 11, &ev.ch)) return;
                ev.kind = trunk::PluginEvent::GRANT;
                ev.target = tk_text(x[4], TRUNK_ID_MAX);
                ev.group = x[5] != "0";
                ev.source = tk_text(x[6], TRUNK_ID_MAX);
                ev.encrypted = fl(x[7], 'e');
                ev.emergency = fl(x[7], 'm');
                ev.data = fl(x[7], 'd');
                ev.update = fl(x[7], 'u');
                ev.decoder = tk_token(x[8], TRUNK_ID_MAX, true);
                ev.demod = tk_token(x[9], TRUNK_DEMOD_MAX, false);
                const double bw = num_or_nan(x[10]);
                ev.bw_hz = is_finite_value(bw) && bw > 0 && bw <= TRUNK_BW_MAX_HZ ? bw : 0.0;
                for (size_t i = 1 + ne; i + 1 < f.size() && ev.options.size() < TRUNK_OPTIONS_MAX; i += 2) {
                    const std::string& k = f[i];
                    const std::string& v = f[i + 1];
                    // not one of the host's own OPTION keys (verbose, log_raw,
                    // video_wanted: kp::wire::host_option), the value clean text
                    bool ok = !tk_token(k, 32, false).empty() && !kp::wire::host_option(k) &&
                              v.size() <= TRUNK_OPTION_VALUE_MAX && kp::wire::clean_text(v, v.size()) == v;
                    for (const auto& o : ev.options) ok = ok && o.first != k;
                    if (ok) ev.options.emplace_back(k, v);
                }
                break;
            }
            case W_CALL: {
                auto f = split0(p, len, 6);
                f.resize(6);
                const long long st = f[0].empty() ? 1 : tk_int(f[0], 0, 2, -1);
                if (st < 0) return;
                ev.kind = trunk::PluginEvent::CALL;
                ev.call_state = static_cast<int>(st);
                ev.target = tk_text(f[1], TRUNK_ID_MAX);
                ev.group = f[2] != "0";
                ev.source = tk_text(f[3], TRUNK_ID_MAX);
                ev.call_slot = static_cast<int>(tk_int(f[4], -1, TRUNK_SLOT_MAX, -1));
                ev.encrypted = fl(f[5], 'e');
                ev.emergency = fl(f[5], 'm');
                break;
            }
            default:
                return;
        }
        if (!trunk_from_.empty() && trunk_from_ != r.id) trunk_reset();   // (another plugin's state)
        trunk_from_ = r.id;
        owner_->set_trunk_reported(true);   // (before the report goes: a reader that sees false has none in the pipe)
        trunk_send(r.id, std::move(ev));
    }

    // kp::wire::OPTION_CHOICES: key, then value / label pairs (kp::Host::option_choices).
    // Only for an option the plugin declares; the text comes from a child process (and
    // a DAB label from the air), so it is bounded and checked here again: a value the
    // page couldn't set (DIGITAL_OPT: <= 100 bytes, no control characters) or that
    // repeats is dropped, a label cut at a character boundary
    void on_option_choices(Runner& r, const char* p, size_t len) {
        auto f = split0(p, len, 1 + 2 * CHOICES_MAX);
        if (f.empty() || !r.known) return;
        bool declared = false;
        for (const auto& o : r.info.options) declared = declared || o.key == f[0];
        if (!declared) return;
        std::vector<std::pair<std::string, std::string>> list;
        for (size_t i = 1; i + 1 < f.size(); i += 2) {
            std::string& v = f[i];
            std::string& l = f[i + 1];
            bool ok = v.size() <= CHOICE_VALUE_MAX;
            for (unsigned char c : v) ok = ok && c >= 0x20 && c != 0x7F;
            for (const auto& x : list) ok = ok && x.first != v;
            if (!ok) continue;
            for (char& c : l)
                if (static_cast<unsigned char>(c) < 0x20 || c == 0x7F) c = ' ';
            if (l.size() > CHOICE_LABEL_MAX) {
                size_t e = CHOICE_LABEL_MAX;
                while (e > 0 && (static_cast<unsigned char>(l[e]) & 0xC0) == 0x80) e--;
                l.resize(e);
            }
            if (l.empty()) l = v;
            list.emplace_back(std::move(v), std::move(l));
        }
        report_.choices_set(r.id, f[0], std::move(list));
    }

    // kp::wire::SPATIAL: id, label, start_s, end_s, delay_us, power_db, snr_db,
    // ref, avg_s, m, cov ("re,im" pairs, row-major) - '\0'-separated text
    static double num_or_nan(const std::string& t) {
        if (t.empty()) return NAN;
        char* e = nullptr;
        const double v = strtod(t.c_str(), &e);
        return (e && *e == '\0' && is_finite_value(v)) ? v : static_cast<double>(NAN);
    }
    void on_spatial(Runner& r, const char* p, size_t len) {
        auto f = split0(p, len, 11);
        if (f.size() < 11 || f[0].empty()) return;
        SpatialReport s;
        s.plugin = r.id;
        s.id = f[0].substr(0, 32);
        s.label = f[1].substr(0, 64);
        uint64_t a, b;
        const double ta = num_or_nan(f[2]), tb = num_or_nan(f[3]);
        if (!r.vfo_pos(ta, r.array_rate > 0 ? r.array_rate : in_rate_, &a) ||
            !r.vfo_pos(tb, r.array_rate > 0 ? r.array_rate : in_rate_, &b))
            return;
        s.start = a;
        s.end = std::max(a, b);
        s.rate = r.array_rate > 0 ? static_cast<float>(r.array_rate) : in_rate_;
        s.delay_us = num_or_nan(f[4]);
        s.power_db = num_or_nan(f[5]);
        s.snr_db = num_or_nan(f[6]);
        s.ref = f[7] == "1";
        const double avg = num_or_nan(f[8]);
        s.avg_s = is_finite_value(avg) ? std::clamp(avg, 0.0, 3600.0) : 0.0;
        s.m = static_cast<int>(strtol(f[9].c_str(), nullptr, 10));
        if (s.m < 1 || s.m > 8) return;
        std::vector<double> v;
        v.reserve(static_cast<size_t>(2 * s.m * s.m));
        const char* c = f[10].c_str();
        while (*c && v.size() < static_cast<size_t>(2 * s.m * s.m)) {
            char* e = nullptr;
            const double x = strtod(c, &e);
            if (e == c || !is_finite_value(x)) return;
            v.push_back(x);
            c = *e == ',' ? e + 1 : e;
        }
        if (v.size() != static_cast<size_t>(2 * s.m * s.m)) return;
        s.cov.resize(static_cast<size_t>(s.m * s.m));
        for (size_t i = 0; i < s.cov.size(); i++) s.cov[i] = {v[2 * i], v[2 * i + 1]};
        owner_->deliver_spatial(s);
    }

    // kp::wire::PLOT -> the decoder's latest plot (JSON for the page)
    void on_plot(Runner& r, const char* p, size_t len) {
        auto f = split0(p, len, 8 + 3 * 64 + 1);
        std::string o = plot_json(f);
        if (!o.empty()) report_.plot_set(r.id, r.id, std::move(o));
    }

    // kp::wire::PLOT_EX: E, E extension fields (id, place, click_option,
    // click_also, click_snap, click_step - later ones skipped), then a PLOT
    // payload. Stored as "<plugin>/<id>" (or "<plugin>" with no id, as PLOT),
    // the extension as more JSON keys: id, pos ("video" = beside the video
    // display), opt / also (a click sets them; only valid option keys and
    // printable values pass), snap, step. A page that doesn't know them
    // shows a "<plugin>" plot as before and never looks at the others.
    void on_plot_ex(Runner& r, const char* p, size_t len) {
        const size_t nl = static_cast<size_t>(std::find(p, p + std::min<size_t>(len, 4), '\0') - p);
        const std::string es(p, nl);
        if (es.empty() || es.size() > 2 || es.find_first_not_of("0123456789") != std::string::npos) return;
        const size_t ne = static_cast<size_t>(std::stoi(es));
        auto f = split0(p, len, 1 + ne + 8 + 3 * 64 + 1);
        if (f.size() < 1 + ne) return;
        auto ext = [&](size_t i) { return i < ne ? f[1 + i] : std::string(); };
        const std::string id = ext(0);
        if (id.size() > 32) return;
        for (unsigned char c : id)
            if (!(std::isalnum(c) || c == '_' || c == '.' || c == '-')) return;
        std::string opt = ext(2), also = ext(3);
        if (!opt.empty() && !valid_option_key(r.id + "." + opt)) opt.clear();
        if (!also.empty()) {
            const size_t eq = also.find('=');
            bool ok = eq != std::string::npos && valid_option_key(r.id + "." + also.substr(0, eq)) && also.size() - eq - 1 <= 100;
            for (unsigned char c : also)
                if (c < 0x20 || c == 0x7F) ok = false;
            if (!ok) also.clear();
        }
        auto jn = [](const std::string& t) {
            const double v = num_or_nan(t);
            if (!is_finite_value(v) || v <= 0) return std::string("null");
            char b[48];
            snprintf(b, sizeof b, "%.9g", v);
            return std::string(b);
        };
        std::string o = plot_json(std::vector<std::string>(f.begin() + static_cast<std::ptrdiff_t>(1 + ne), f.end()));
        if (o.empty()) return;
        o.pop_back();   // the closing brace
        o += ",\"id\":\"" + json_escape(id) + "\",\"pos\":\"" + std::string(ext(1) == "1" ? "video" : "") + "\",\"opt\":\"" +
             json_escape(opt) + "\",\"also\":\"" + json_escape(also) + "\",\"snap\":" + jn(ext(4)) + ",\"step\":" + jn(ext(5)) + "}";
        report_.plot_set(r.id, id.empty() ? r.id : r.id + "/" + id, std::move(o), MAX_PLOTS_PER_PLUGIN);
    }

    // a PLOT payload's fields as the page's JSON; "" = malformed
    static std::string plot_json(const std::vector<std::string>& f) {
        if (f.size() < 9) return "";
        auto jn = [](const std::string& t, int prec) {
            const double v = num_or_nan(t);
            if (!is_finite_value(v)) return std::string("null");
            char b[48];
            snprintf(b, sizeof b, "%.*g", prec, v);
            return std::string(b);
        };
        std::string o = "{\"t\":\"" + json_escape(f[0].substr(0, 80)) + "\",\"xu\":\"" + json_escape(f[1].substr(0, 16)) +
                        "\",\"yu\":\"" + json_escape(f[2].substr(0, 16)) + "\",\"x0\":" + jn(f[3], 9) + ",\"dx\":" + jn(f[4], 9) +
                        ",\"ymin\":" + jn(f[5], 6) + ",\"ymax\":" + jn(f[6], 6) + ",\"thr\":" + jn(f[7], 6) + ",\"y\":[";
        const char* c = f[8].c_str();
        int n = 0;
        while (*c && n < 1000) {
            char* e = nullptr;
            const double x = strtod(c, &e);
            if (e == c) break;
            char b[32];
            snprintf(b, sizeof b, "%.4g", is_finite_value(x) ? x : 0.0);
            o += (n ? "," : "") + std::string(b);
            n++;
            c = *e == ',' ? e + 1 : e;
        }
        o += "],\"mk\":[";
        for (size_t i = 9, k = 0; i + 2 < f.size() + 0 && k < 64; i += 3, k++)
            o += std::string(k ? "," : "") + "[" + jn(f[i], 9) + ",\"" + json_escape(f[i + 1].substr(0, 16)) + "\",\"" +
                 json_escape(f[i + 2].substr(0, 32)) + "\"]";
        o += "]}";
        return o;
    }

    // kp::wire::VIDEO: uint16 width, height; uint8 format, flags; uint16
    // label_len; label; then width*height*bpp pixel bytes (bpp = 1 GRAY8 /
    // 3 RGB24), all little-endian. Forwarded as a binary frame to the panel's
    // canvas; a frame whose length doesn't match its header is dropped.
    void on_video(Runner& r, const char* p, size_t len) {
        constexpr size_t HDR = 8;   // width, height, format, encoding, label_len
        if (len < HDR || !video_wanted.load(std::memory_order_relaxed)) return;   // no viewer: no copies
        const auto* u = reinterpret_cast<const uint8_t*>(p);
        const uint32_t w = static_cast<uint32_t>(u[0]) | (static_cast<uint32_t>(u[1]) << 8);
        const uint32_t h = static_cast<uint32_t>(u[2]) | (static_cast<uint32_t>(u[3]) << 8);
        const uint8_t format = u[4];
        const uint8_t encoding = u[5];   // 0 = raw pixels, 2 = JPEG bitstream
        const uint32_t label_len = static_cast<uint32_t>(u[6]) | (static_cast<uint32_t>(u[7]) << 8);
        if (format > 1 || encoding > 2 || w == 0 || h == 0) return;
        if (len < HDR + label_len) return;   // the label must fit
        size_t data_len;
        if (encoding == 0) {   // raw: the pixel count must match the geometry exactly
            const size_t bpp = format == 1 ? 3 : 1;
            data_len = static_cast<size_t>(w) * static_cast<size_t>(h) * bpp;
            if (HDR + label_len + data_len != len) return;
        } else {   // JPEG: a variable-length blob - the host forwards it opaquely
            data_len = len - HDR - label_len;
            if (data_len == 0) return;
        }
        VideoFrameReport vf;
        vf.width = static_cast<int>(w);
        vf.height = static_cast<int>(h);
        vf.format = format;
        vf.encoding = encoding;
        vf.label.assign(p + HDR, label_len);
        vf.pixels.assign(u + HDR + label_len, u + HDR + label_len + data_len);
        owner_->deliver_video(vf);
        (void)r;
    }

    // kp::wire::MAP_POINT: id, lat, lon, label, kind, heading, altitude_m,
    // speed_kmh, ttl_s, info - '\0'-separated, numbers as text ("" = unknown)
    void on_map_point(const std::string& plugin, const char* p, size_t len) {
        std::vector<std::string> f = split0(p, len, 10);
        if (f.size() < 3) return;
        f.resize(10);
        auto num = [](const std::string& t) {
            if (t.empty()) return static_cast<double>(NAN);
            char* e = nullptr;
            double v = strtod(t.c_str(), &e);
            return (e && *e == '\0' && is_finite_value(v)) ? v : static_cast<double>(NAN);
        };
        MapPoint m;
        m.plugin = plugin;
        m.id = f[0].substr(0, 32);
        m.lat = num(f[1]);
        m.lon = num(f[2]);
        if (m.id.empty() || !is_finite_value(m.lat) || !is_finite_value(m.lon) || std::fabs(m.lat) > 90 ||
            std::fabs(m.lon) > 180)
            return;
        m.label = f[3].substr(0, 64);
        m.kind = f[4].empty() ? "point" : f[4].substr(0, 16);
        m.heading = static_cast<float>(num(f[5]));
        m.alt_m = static_cast<float>(num(f[6]));
        m.speed_kmh = static_cast<float>(num(f[7]));
        double ttl = num(f[8]);
        m.ttl_s = is_finite_value(ttl) ? std::clamp(ttl, 10.0, 86400.0) : 300.0;
        m.info = f[9].substr(0, 1000);
        LogRecord lr;
        lr.type = "position";
        lr.plugin = plugin;
        lr.point = &m;
        lr.rf_hz = rf_hz_;
        deliver_record(owner_, lr);
        report_.map_set(std::move(m));
    }

    // --- talkers (kp::wire::TALKER: id, label, start_s, end_s [, channel [, flags,
    // freq, bw, avg [, lat, lon, alt [, keep [, m, cov]]]]]) -------------------------
    using OpenTalker = Runner::OpenTalker;
    static int talker_channel(const std::string& v) {
        return static_cast<int>(std::clamp(strtol(v.c_str(), nullptr, 10), 0L, 7L));
    }
    void on_talker(Runner& r, const char* p, size_t len) {
        auto f = split0(p, len, 15);
        if (f.size() < 4 || f[0].empty()) return;
        const std::string id = f[0].substr(0, 32);
        const int ch = f.size() > 4 ? talker_channel(f[4]) : 0;
        if (f.size() > 5 && f[5].find('p') != std::string::npos) {
            // one packet: exactly these samples, nothing stays open
            uint64_t a, b;
            if (!r.vfo_pos(strtod(f[2].c_str(), nullptr), r.prate(), &a) ||
                !r.vfo_pos(strtod(f[3].c_str(), nullptr), r.prate(), &b) || b <= a ||
                static_cast<double>(b - a) > in_rate_ * MAX_PACKET_S)
                return;
            TalkerSpan s;
            s.plugin = r.id;
            s.id = id;
            s.label = f[1].substr(0, 64);
            s.start = a;
            s.end = b;
            s.closed = true;
            s.rate = in_rate_;
            s.packet = true;
            if (f.size() > 8) {
                // the plugin's frequency -> the VFO's: the AFC mixer moved the band
                // down by afc_hz_
                if (!f[6].empty()) {
                    const double pf = strtod(f[6].c_str(), nullptr);
                    if (is_finite_value(pf)) s.freq_hz = pf + afc_hz_;
                }
                s.bw_hz = std::clamp(strtod(f[7].c_str(), nullptr), 0.0, static_cast<double>(in_rate_));
                s.avg_s = std::clamp(strtod(f[8].c_str(), nullptr), 0.0, 3600.0);
                if (!is_finite_value(s.bw_hz)) s.bw_hz = 0;
                if (!is_finite_value(s.avg_s)) s.avg_s = 0;
            }
            if (f.size() > 11) {
                // where the talker was (the array calibration from aircraft)
                const double la = strtod(f[9].c_str(), nullptr), lo = strtod(f[10].c_str(), nullptr),
                             al = strtod(f[11].c_str(), nullptr);
                if (is_finite_value(la) && is_finite_value(lo) && is_finite_value(al) && std::fabs(la) <= 90 &&
                    std::fabs(lo) <= 180 && al > -1000 && al < 100000 && !(la == 0 && lo == 0)) {
                    s.lat = la;
                    s.lon = lo;
                    s.alt_m = al;
                }
            }
            if (f.size() > 12) {
                // how long the talker is kept after its last packet (0 = the default)
                const double k = strtod(f[12].c_str(), nullptr);
                if (is_finite_value(k)) s.keep_s = std::clamp(k, 0.0, 7 * 86400.0);
            }
            if (f.size() > 14) {
                // the packet's own covariance (kp::Talker::cov: separation by code)
                const long m = strtol(f[13].c_str(), nullptr, 10);
                if (m >= 2 && m <= 8) {
                    std::vector<std::complex<double>> c;
                    c.reserve(static_cast<size_t>(m * m));
                    const char* q = f[14].c_str();
                    char* e = nullptr;
                    while (*q && c.size() < static_cast<size_t>(m * m)) {
                        const double re = strtod(q, &e);
                        if (e == q || *e != ',') break;
                        q = e + 1;
                        const double im = strtod(q, &e);
                        if (e == q) break;
                        if (!is_finite_value(re) || !is_finite_value(im)) break;
                        c.emplace_back(re, im);
                        q = *e == ',' ? e + 1 : e;
                    }
                    if (c.size() == static_cast<size_t>(m * m)) {
                        s.cov_m = static_cast<int>(m);
                        s.cov = std::move(c);
                    }
                }
            }
            owner_->deliver_talker(s);
            return;
        }
        auto it = r.talkers.find(ch);
        uint64_t a, b;
        if (!r.vfo_pos(strtod(f[3].c_str(), nullptr), r.prate(), &b)) return;
        if (!r.vfo_pos(strtod(f[2].c_str(), nullptr), r.prate(), &a)) {
            // began before the oldest mapped sample (a transmission > POS_MAP_SECONDS)
            if (it != r.talkers.end() && it->second.id == id) a = it->second.start;
            else a = static_cast<uint64_t>(std::max(0.0, r.pos_map.front().v0));
        }
        if (it != r.talkers.end() && it->second.id != id) {
            // another radio on this channel: the previous one ended where this one starts
            it->second.end = std::clamp(a, it->second.start, it->second.end);
            close_talker(r, it);
            it = r.talkers.end();
        }
        if (it == r.talkers.end()) it = r.talkers.emplace(ch, Runner::OpenTalker{id, "", a, a}).first;
        OpenTalker& t = it->second;
        t.label = f[1].substr(0, 64);
        t.end = std::max(t.end, b);
        send_talker(r, ch, t, false);
    }
    void send_talker(const Runner& r, int ch, const OpenTalker& t, bool closed) {
        TalkerSpan s;
        s.channel = ch;
        s.plugin = r.id;
        s.id = t.id;
        s.label = t.label;
        s.start = t.start;
        s.end = t.end;
        s.closed = closed;
        s.rate = in_rate_;
        owner_->deliver_talker(s);
    }
    void close_talker(Runner& r, std::map<int, OpenTalker>::iterator it) {
        send_talker(r, it->first, it->second, true);
        r.talkers.erase(it);
    }
    void close_talker(Runner& r) {   // all of the plugin's
        while (!r.talkers.empty()) close_talker(r, r.talkers.begin());
    }

    // --- detection / AFC ----------------------------------------------------
    void on_valid(const std::string& id) {
        std::lock_guard<std::mutex> lk(st_mu_);
        int64_t t = now_ms();
        valid_.emplace_back(t, id);
        totals_[id]++;
        last_valid_ms_ = t;
        last_valid_by_[id] = t;
    }
    // kp::Host::valid(start, end): the frame's samples -> the VFO's stream
    // positions, as a signal span (the Digital squelch's DoA material)
    void on_valid_span(Runner& r, const char* p, size_t len) {
        auto f = split0(p, len, 2);
        if (f.size() < 2) return;
        uint64_t a, b;
        if (!r.vfo_pos(strtod(f[0].c_str(), nullptr), r.prate(), &a) ||
            !r.vfo_pos(strtod(f[1].c_str(), nullptr), r.prate(), &b) || b <= a ||
            static_cast<double>(b - a) > in_rate_ * MAX_SIGNAL_SPAN_S)
            return;
        TalkerSpan s;
        s.plugin = r.id;
        s.signal = true;
        s.start = a;
        s.end = b;
        s.closed = true;
        s.rate = in_rate_;
        owner_->deliver_talker(s);
    }
public:
    int64_t last_valid_of(const std::string& id) const {
        std::lock_guard<std::mutex> lk(st_mu_);
        auto it = last_valid_by_.find(id);
        return it == last_valid_by_.end() ? 0 : it->second;
    }
    int64_t squelch_hold_ms(const std::string& id, int64_t def) const {
        std::lock_guard<std::mutex> lk(st_mu_);
        auto it = hold_ms_by_.find(id);
        return it == hold_ms_by_.end() ? def : it->second;
    }
private:

    void on_freq_error(float hz) {
        std::lock_guard<std::mutex> lk(st_mu_);
        residual_hz_ = hz;
        if (now_ms() - afc_changed_ms_ < AFC_SETTLE_MS) return;   // measured before the last correction
        afc_sum_ += hz;
        afc_n_++;
    }

    // slow integrator (the plugins tolerate the residual themselves)
    void afc_update(int64_t t) {
        if (afc_n_ == 0 || t - afc_changed_ms_ < AFC_PERIOD_MS) return;
        float mean = afc_sum_ / static_cast<float>(afc_n_);
        afc_hz_ = std::clamp(afc_hz_ + 0.5f * mean, -AFC_LIMIT_HZ, AFC_LIMIT_HZ);
        residual_hz_ -= 0.5f * mean;
        afc_sum_ = 0;
        afc_n_ = 0;
        afc_changed_ms_ = t;
    }

    std::string name_of(const std::string& id) const {
        for (const auto& r : runners_)
            if (r->id == id) return r->known ? r->info.name : id;
        return id;
    }

    void housekeeping() {
        int64_t t = now_ms();
        std::string old, now;
        {
            std::lock_guard<std::mutex> lk(st_mu_);
            while (!valid_.empty() && t - valid_.front().first > DETECT_WINDOW_MS) valid_.pop_front();
            std::map<std::string, int> cnt;
            for (const auto& v : valid_) cnt[v.second]++;
            afc_update(t);
            old = detected_;
            // A plugin whose valid frames come further apart than the window
            // (its squelch hold says so: inmarsat_c, 8.64 s frames) stays
            // detected for that hold - else the status would say "Signal
            // lost" / "Receiving" once per frame
            auto held = [&](const std::string& id) {
                const auto h = hold_ms_by_.find(id);
                const auto lv = last_valid_by_.find(id);
                return h != hold_ms_by_.end() && h->second > DETECT_WINDOW_MS &&
                       lv != last_valid_by_.end() && t - lv->second < h->second;
            };
            if (mode_ == Mode::PLUGIN) {
                detected_ = cnt[plugin_] > 0 || held(plugin_) ? plugin_ : "";
            } else {
                std::string best;
                int bc = 0;
                for (const auto& kv : cnt)
                    if (kv.second > bc) { bc = kv.second; best = kv.first; }
                // switch only on a clear majority (2+ frames), keep the
                // current one while it is still receiving - or held (above)
                // with no other plugin taking over
                if (!detected_.empty() && cnt[detected_] > 0 && cnt[detected_] * 2 >= bc) {
                    // keep
                } else if (bc >= 2) {
                    detected_ = best;
                } else if (detected_.empty() || !held(detected_)) {
                    detected_ = "";
                }
            }
            now = detected_;
            if (now.empty() && t - last_valid_ms_ > 5000) {
                // drift back to the VFO centre when idle - and land on it (a
                // float decaying by 0.99 takes minutes of denormals to reach
                // 0; at exactly 0 the mixer is a copy and multichannel
                // plugins get every antenna again)
                afc_hz_ = std::fabs(afc_hz_) < 0.5f ? 0.0f : afc_hz_ * 0.99f;
                residual_hz_ = 0;
            }
        }
        // Auto detect locked onto another plugin: what the previous lead
        // said about a trunked system is stale (it going quiet is not)
        if (now != old && !now.empty() && !trunk_from_.empty() && now != trunk_from_) trunk_reset();
        if (now != old) {
            if (!now.empty())
                report_.event(now, std::string(mode_ == Mode::AUTO ? "Detected " : "Receiving ") + name_of(now), 0.0);
            else
                report_.event(old, "Signal lost", 0.0);
        }
        // who has the VFO's voice (Voice to Text): the lead plugin if it decodes
        // voice; in Auto detect, still searching, any of its plugins that does;
        // an unknown plugin (not started yet) counts as a voice decoder
        bool voice = false;
        const Runner* lead = nullptr;
        for (const auto& r : runners_) {
            if (mode_ == Mode::PLUGIN || (!now.empty() && r->id == now)) lead = r.get();
            if (mode_ == Mode::AUTO && now.empty() && (!r->known || r->info.voice)) voice = true;
        }
        if (lead) voice = !lead->known || lead->info.voice;
        else if (mode_ == Mode::PLUGIN) voice = true;
        owner_->set_takes_voice(voice);
        // its talker now: the open one that started first
        const Runner::OpenTalker* tk = nullptr;
        if (lead)
            for (const auto& kv : lead->talkers)
                if (!tk || kv.second.start < tk->start) tk = &kv.second;
        const std::string tid = tk && tk->id != "?" ? tk->id : "", tl = tk && tk->id != "?" ? tk->label : "";
        if (tid != lead_tid_sent_ || tl != lead_tlabel_sent_) {
            lead_tid_sent_ = tid;
            lead_tlabel_sent_ = tl;
            owner_->set_lead_talker(tid, tl);
        }
    }
};

// ---------------------------------------------------------------------------
// DigitalDecoder
// ---------------------------------------------------------------------------
DigitalDecoder::DigitalDecoder(bool threaded, bool internal_streams)
    : engine_(std::make_unique<Engine>(report_, this, !threaded, internal_streams)), internal_streams_(internal_streams) {
    interp_ = firinterp_rrrf_create_kaiser(6, 8, 60.0f);
    if (threaded) worker_ = std::thread([this] {
        pthread_setname_np(pthread_self(), "digital-dec");
        run();
    });
}

DigitalDecoder::~DigitalDecoder() {
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
    managed_iq::Writer stopping(role_authority_.load());
#endif
    {
        std::lock_guard<std::mutex> lk(q_mu_);
        stop_ = true;
    }
    q_cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    engine_.reset();   // stops the plugin processes
    if (interp_) firinterp_rrrf_destroy(static_cast<firinterp_rrrf>(interp_));
}

// ---------------------------------------------------------------------------
// Decoded voice: 8 kHz from the vocoders -> AGC -> 48 kHz FIFO -> audio thread
// ---------------------------------------------------------------------------
namespace {
constexpr size_t VOICE_RATE = 48000;
constexpr size_t VOICE_PREFILL = VOICE_RATE / 4;     // 250 ms: frames arrive in bursts (P25 LDU = 180 ms)
constexpr size_t VOICE_MAX = VOICE_RATE * 2;
constexpr int64_t VOICE_DRAIN_MS = 300;              // a call's tail plays without prefill
constexpr int64_t VOICE_WANTED_MS = 500;
}  // namespace

void DigitalDecoder::push_voice(const float* x, size_t n) {
    if (n == 0) return;
    // slow AGC towards ~-15 dBFS rms while speech is present
    double e = 0;
    for (size_t i = 0; i < n; i++) e += x[i] * x[i];
    float rms = static_cast<float>(std::sqrt(e / n));
    std::lock_guard<std::mutex> lk(v_mu_);
    if (rms > 0.002f) {
        float want = std::clamp(0.18f / rms, 0.5f, 30.0f);
        agc_gain_ += 0.15f * (want - agc_gain_);
    }
    auto q = static_cast<firinterp_rrrf>(interp_);
    float y[6];
    for (size_t i = 0; i < n; i++) {
        float v = std::tanh(x[i] * agc_gain_);   // soft limit
        firinterp_rrrf_execute(q, v, y);
        for (float s : y) vfifo_.push_back(s);
    }
    while (vfifo_.size() > VOICE_MAX) vfifo_.pop_front();
    v_last_push_ms_ = now_ms();
}

void DigitalDecoder::pull_voice(float* out, size_t n) {
    int64_t t = now_ms();
    voice_wanted_until_.store(t + VOICE_WANTED_MS, std::memory_order_relaxed);
    std::lock_guard<std::mutex> lk(v_mu_);
    if (!v_playing_ && !vfifo_.empty() &&
        (vfifo_.size() >= VOICE_PREFILL || t - v_last_push_ms_ > VOICE_DRAIN_MS))
        v_playing_ = true;
    size_t k = 0;
    if (v_playing_) {
        for (; k < n && !vfifo_.empty(); k++) {
            out[k] = vfifo_.front();
            vfifo_.pop_front();
        }
        if (vfifo_.empty()) v_playing_ = false;   // underrun: prefill again
    }
    for (; k < n; k++) out[k] = 0.0f;
}

void DigitalDecoder::set_voice_state(const std::string& s) {
    std::lock_guard<std::mutex> lk(v_mu_);
    voice_state_ = s;
}

bool DigitalDecoder::voice_wanted() const {
    return now_ms() < voice_wanted_until_.load(std::memory_order_relaxed);
}

void DigitalDecoder::set_mode(Mode m, const std::string& plugin) {
#ifdef TT01_ROLE_QUALIFICATION
    auto authority=role_authority_.load();
    managed_iq::Writer writer(authority);
    if(authority&&!writer)return;
#endif
    bool plugin_changed;
    {
        std::lock_guard<std::mutex> lk(opt_mu_);
        std::string p = m == Mode::PLUGIN ? plugin : "";
        plugin_changed = p != plugin_id_;
        plugin_id_ = p;
    }
    Mode old = mode_.exchange(m);
    if (old != m || plugin_changed) {
        {
            std::lock_guard<std::mutex> lk(q_mu_);
            reset_pending_.store(true);
        }
        q_cv_.notify_all();   // the worker reconfigures (starts / stops plugins) even without data
        report_.clear_all();
        report_.map_clear();
        report_.table_clear();
        report_.plot_clear();
        set_voice_state("");
        if (m == Mode::PLUGIN) report_.event("", "Decoder set to " + plugin, 0.0);
        else if (m == Mode::AUTO) report_.event("", "Decoder on, detecting the mode automatically", 0.0);
    }
#ifdef TT01_ROLE_QUALIFICATION
    if (!authority && !worker_.joinable()) {
#else
    if (!worker_.joinable()) {
#endif
        if (reset_pending_.exchange(false)) engine_->reset_all();
        engine_->configure(m, options(), plugin_id());
    }
}

std::string DigitalDecoder::plugin_id() const {
    std::lock_guard<std::mutex> lk(opt_mu_);
    return plugin_id_;
}

void DigitalDecoder::set_options(const Options& o) {
#ifdef TT01_ROLE_QUALIFICATION
    auto authority=role_authority_.load();
    managed_iq::Writer writer(authority);
    if(authority&&!writer)return;
#endif
    std::lock_guard<std::mutex> lk(opt_mu_);
    opts_ = o;
    log_mode_.store(o.log, std::memory_order_relaxed);
    pos_s_.store(o.pos_s, std::memory_order_relaxed);
}

Options DigitalDecoder::options() const {
    std::lock_guard<std::mutex> lk(opt_mu_);
    return opts_;
}

void DigitalDecoder::set_talker_handler(TalkerHandler h) {
    std::lock_guard<std::mutex> lk(talker_mu_);
    talker_handler_ = std::move(h);
}

void DigitalDecoder::deliver_talker(const TalkerSpan& s) {
    TalkerHandler h;
    {
        std::lock_guard<std::mutex> lk(talker_mu_);
        h = talker_handler_;
    }
    if (h) h(s);
}

void DigitalDecoder::push(const std::complex<float>* x, size_t n, float rate_hz, double rf_hz, uint64_t pos,
                          const std::complex<int16_t>* mc, int mc_m, int bw_hz, const AuxStream* aux, size_t naux,
                          std::shared_ptr<const managed_iq::ManualEnvelope> manual) {
#ifdef TT01_ROLE_QUALIFICATION
    auto authority=role_authority_.load();
    if((authority||manual)&&(!authority||!manual||!manual->admit(this,authority,[]{return true;}))){
        std::lock_guard lock(q_mu_);++role_stats_.refused;return;
    }
#endif
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
    if(manual&&manual->observed_rf().bound&&manual->observed_rf().count&&
       (!x||!n||!(rate_hz>0)||mode()==Mode::OFF||array_only_.load(std::memory_order_relaxed))){
        manual->discard_nonempty();
        std::lock_guard lock(q_mu_);++role_stats_.refused;return;
    }
#endif
    // n = 0 with internal streams: the VFO has no samples this block (the
    // beamformer held them back) - its internal streams still go, so they
    // stay continuous
    if (!internal_streams_ || !aux) naux = 0;
    if (n > 0 && !x) n = 0;
    if (mode() == Mode::OFF || (n == 0 && naux == 0) || !(rate_hz > 0)) return;
    // only an array plugin runs: it never sees this stream - a one-sample
    // tick every 100 ms keeps the engine going (starts the plugin, reads its
    // replies, follows the RF) without copying 2.4 MHz of samples
    if (array_only_.load(std::memory_order_relaxed)) {
        if (n == 0) return;
        if (pos != NO_POS && tick_pos_ != NO_POS && pos >= tick_pos_ && static_cast<double>(pos - tick_pos_) < 0.1 * rate_hz) return;
        tick_pos_ = pos;
        n = 1;
        naux = 0;
    }
    // the copies are made outside the queue's lock (the worker takes it per block)
    Block b;
    if(n)b.x.assign(x, x + n);
    b.manual=std::move(manual);
    b.rate = rate_hz;
    b.rf = rf_hz;
    b.pos = pos;
    b.ns = n;
    b.bw = bw_hz;
    b.dur = static_cast<double>(n) / rate_hz;
    if (mc && mc_m >= 2) {
        b.mc.assign(mc, mc + n * static_cast<size_t>(mc_m));
        b.m = mc_m;
    }
    if (aux && naux && internal_streams_) {
        b.aux.resize(naux);
        for (size_t k = 0; k < naux; k++) {
            AuxBlock& a = b.aux[k];
            a.w = aux[k].width_hz;
            a.rate = aux[k].rate_hz;
            a.pos = aux[k].pos;
            if (aux[k].x) a.x.assign(aux[k].x, aux[k].x + aux[k].n);
            if (aux[k].mc && aux[k].mc_m >= 2) {
                a.mc.assign(aux[k].mc, aux[k].mc + aux[k].n * static_cast<size_t>(aux[k].mc_m));
                a.m = aux[k].mc_m;
            }
        }
        // the block's signal by its internal streams: they come every block,
        // while the beamformer's output for the VFO is withheld some blocks
        // and longer in the next one (no double count either way)
        double d = 0;
        for (const auto& a : b.aux)
            if (a.rate > 0) d = std::max(d, static_cast<double>(a.x.size()) / a.rate);
        if (d > 0) b.dur = d;
    }
    enqueue(std::move(b));
}

// The queue holds at most QUEUE_MAX_SECONDS of signal - the VFO's block and
// its internal streams go and stay together, so the cap bounds both (a 2.4
// MHz internal stream is 19 MB a second). A decoder that fell behind (CPU
// starved) loses the oldest blocks
void DigitalDecoder::enqueue_locked(Block&& b) {
    queued_s_ += b.dur;
    queue_.push_back(std::move(b));
    while (queued_s_ > static_cast<double>(QUEUE_MAX_SECONDS) && queue_.size() > 1) {
        queued_s_ -= queue_.front().dur;
        if(queue_.front().managed)++managed_stats_.overflow;
        if(queue_.front().manual)++role_stats_.overflow;
        queue_.pop_front();
        dropped_++;
    }
    if (queue_.size() == 1) queued_s_ = queue_.front().dur;   // (no drift)
}
void DigitalDecoder::enqueue(Block&& b) {
#ifdef TT01_ROLE_QUALIFICATION
    auto pub=role_authority_.load();
    if(pub||b.manual){
        if(pub&&b.manual&&
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
            managed_iq::manual_output::admit(*b.manual,this,pub,[&]{
#else
            b.manual->admit(this,pub,[&]{
#endif
            std::lock_guard lock(q_mu_);
            if(stop_||!b.manual->claim_submission(b.am>0))return false;
#ifdef TT01_MANUAL_LOSS_QUALIFICATION
            // This first consumable candidate scope is fixed independent
            // P25 single-stream only; other inputs cannot mint report authority.
            if(b.manual->segment()&&b.manual->tuner()>=0&&
                b.manual->mode()==Mode::PLUGIN&&b.manual->plugin()=="p25"&&
                !b.am&&!b.m&&b.aux.empty()){
#ifdef TT01_MANUAL_ORIGIN_QUALIFICATION
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
                if(!b.manual->matches_rf(b.rf,b.rate,b.bw,b.x.size())){
                    pub->manual_origin_failed_locked(b.manual->seq(),b.manual->origin_loss());
                    return false;
                }
#endif
                auto epoch=pub->manual_origin_submission_locked(b.manual->role(),b.manual->segment(),b.manual->seq(),
                    b.manual->origin_loss(),!queue_.empty()&&queued_s_+b.dur>double(QUEUE_MAX_SECONDS));
                if(!epoch)return false;
#else
                auto epoch=pub->manual_submission_locked(b.manual->role(),b.manual->segment(),
                    b.manual->seq(),!queue_.empty()&&queued_s_+b.dur>double(QUEUE_MAX_SECONDS));
                if(epoch==UINT64_MAX)return false;
#endif
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
                // The overflow/gap-triggering old DSP block may be queued
                // for eviction accounting, but never adopts the new epoch.
                b.manual->loss_epoch_.store(b.manual->origin_loss());
#else
                b.manual->loss_epoch_.store(epoch);
#endif
            }else if(b.manual->segment()){
                // Refuse unsupported lanes in this qualification variant.
                // No old control output survives a known unqualified input.
#ifdef TT01_MANUAL_ORIGIN_QUALIFICATION
                pub->manual_origin_failed_locked(b.manual->seq(),b.manual->origin_loss());
#else
                pub->lose_manual_locked();
#endif
                return false;
            }
#endif
            enqueue_locked(std::move(b));++role_stats_.accepted;return true;
        })){q_cv_.notify_one();return;}
        std::lock_guard lock(q_mu_);++role_stats_.refused;return;
    }
#endif
    {
        std::lock_guard<std::mutex> lk(q_mu_);
        enqueue_locked(std::move(b));
    }
    q_cv_.notify_one();
}

void DigitalDecoder::bind_role(std::shared_ptr<managed_iq::Publication> pub){
#ifdef TT01_ROLE_QUALIFICATION
    std::shared_ptr<managed_iq::Publication> empty;
    if(pub)role_authority_.compare_exchange_strong(empty,std::move(pub));
#else
    (void)pub;
#endif
}
DigitalDecoder::RoleQueueStats DigitalDecoder::role_queue_stats(){
    std::lock_guard lock(q_mu_);return role_stats_;
}
#ifndef TT01_OPERATIONAL_BUILD
bool DigitalDecoder::qualification_stop(){
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
    managed_iq::Writer stopping(role_authority_.load());
#endif
#ifdef TT01_ROLE_QUALIFICATION
    {std::lock_guard lock(q_mu_);stop_=true;}
    q_cv_.notify_all();
    if(managed_iq::role_test::shutdown_hook)managed_iq::role_test::shutdown_hook(this);
    if(worker_.joinable())worker_.join();
    return true;
#else
    return false;
#endif
}
#endif // !TT01_OPERATIONAL_BUILD
DigitalDecoder::ManagedQueueStats DigitalDecoder::managed_queue_stats() {
    std::lock_guard lock(q_mu_);return managed_stats_;
}

bool DigitalDecoder::push_managed(std::shared_ptr<const managed_iq::WorkerEnvelope> envelope) {
#ifdef TT01_WORKER_QUALIFICATION
#ifdef TT01_ROLE_QUALIFICATION
    // Bound instances are manager-created threaded decoders. Do not read
    // std::thread::joinable concurrently with the qualification stop/join.
    const auto authority=role_authority_.load();
    if(authority&&envelope&&authority==envelope->authority_&&envelope->claim_submission()){
#else
    if(envelope&&worker_.joinable()&&envelope->claim_submission()){
#endif
        Block b;
        b.rate=envelope->rate();b.rf=envelope->provenance().observed_rf();
        b.pos=envelope->pos();b.ns=envelope->samples().size();
        b.bw=envelope->provenance().bandwidth;b.dur=double(b.ns)/b.rate;
        b.managed=envelope;
        // Exactly one insertion per immutable envelope. Queue-only lock
        // nested under source/domain/publication; no DSP or callback here.
        if(b.rate>0&&b.dur<=QUEUE_MAX_SECONDS&&envelope->admit(this,[&]{
            std::lock_guard lock(q_mu_);
            if(stop_||mode()!=Mode::PLUGIN)return false;
#ifdef TT01_MANAGED_LOSS_QUALIFICATION
            // Exact current placement is retired before known eviction.
            // Preserve actual bounded queue accounting; the new block and
            // every retained old-token block must fail future admission.
            if(!queue_.empty()&&queued_s_+b.dur>double(QUEUE_MAX_SECONDS))
                envelope->authority_->retire_admitted(envelope->provenance().placement);
#endif
            enqueue_locked(std::move(b));++managed_stats_.accepted;return true;
        })){
            q_cv_.notify_one();return true;
        }
    }
#else
    (void)envelope;
#endif
    std::lock_guard lock(q_mu_);++managed_stats_.refused;return false;
}

int DigitalDecoder::wanted_streams(StreamWant* out) const {
    std::lock_guard<std::mutex> lk(streams_mu_);
    const int n = streams_n_.load(std::memory_order_relaxed);
    for (int i = 0; i < n; i++) out[i] = streams_[i];
    return n;
}

void DigitalDecoder::set_wanted_streams(const std::vector<StreamWant>& w) {
    std::lock_guard<std::mutex> lk(streams_mu_);
    const int n = std::min<int>(static_cast<int>(w.size()), MAX_STREAMS);
    for (int i = 0; i < n; i++) streams_[i] = w[static_cast<size_t>(i)];
    streams_n_.store(n, std::memory_order_relaxed);
    streams_gen_.fetch_add(1, std::memory_order_release);
}

void DigitalDecoder::set_array_wanted(bool on, double burst_s, double period_s, bool only) {
    arr_burst_.store(std::max(0.01, burst_s), std::memory_order_relaxed);
    arr_period_.store(std::max(burst_s, period_s), std::memory_order_relaxed);
    want_array_.store(on, std::memory_order_relaxed);
    array_only_.store(only, std::memory_order_relaxed);
}

void DigitalDecoder::push_array(const std::complex<float>* const* ch, int m, size_t n, float rate_hz, double rf_hz,
                                uint64_t pos,std::shared_ptr<const managed_iq::ManualEnvelope> manual) {
#ifdef TT01_ROLE_QUALIFICATION
    auto authority=role_authority_.load();
    if((authority||manual)&&(!authority||!manual||!manual->admit(this,authority,[]{return true;}))){
        std::lock_guard lock(q_mu_);++role_stats_.refused;return;
    }
#endif
    if (mode() == Mode::OFF || n == 0 || m < 1 || m > 8 || !wants_array() || !(rate_hz > 0)) return;
    // only the plugin's bursts (stream time): a block whose first sample is in one
    const double burst = arr_burst_.load(std::memory_order_relaxed), period = arr_period_.load(std::memory_order_relaxed);
    if (burst < period && std::fmod(static_cast<double>(pos) / rate_hz, period) >= burst) return;
    Block b;
    b.am = m;
    b.manual=std::move(manual);
    b.ns = n;
    b.rate = rate_hz;
    b.rf = rf_hz;
    b.pos = pos;
    b.x.resize(static_cast<size_t>(m) * n);
    for (int k = 0; k < m; k++) std::copy_n(ch[k], n, b.x.data() + static_cast<size_t>(k) * n);
    b.dur = static_cast<double>(n) / rate_hz;
    enqueue(std::move(b));
}

void DigitalDecoder::set_tune_handler(TuneHandler h) {
    std::lock_guard<std::mutex> lk(talker_mu_);
    tune_handler_ = std::move(h);
}

std::string DigitalDecoder::deliver_tune(double rf_hz) {
    TuneHandler h;
    {
        std::lock_guard<std::mutex> lk(talker_mu_);
        h = tune_handler_;
    }
    return h ? h(rf_hz) : std::string("this receiver can't retune for plugins");
}

void DigitalDecoder::set_trunk_handler(TrunkHandler h) {
    std::lock_guard<std::mutex> lk(talker_mu_);
    trunk_handler_ = std::move(h);
}

void DigitalDecoder::deliver_trunk(const std::string& plugin, trunk::PluginEvent&& ev) {
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
    namespace mo=managed_iq::manual_output;
    if(auto pub=role_authority_.load()){
        const auto ctx=mo::context;
        if(ctx.closing||!ctx.stamp||ctx.stamp->decoder_identity()!=this||ctx.stamp->authority()!=pub){
            mo::count_quarantined(ctx.closing);
            if(mo::hook)mo::hook(ctx.closing?mo::Stage::closing:mo::Stage::unattributed,
                mo::Report{vfo(),0,plugin,ev,ctx.stamp,ctx.generation});
            return;
        }
        // No authority mutex around a callback. The manager enqueue
        // revalidates the original scope after any callback barrier.
        if(mo::hook)mo::hook(mo::Stage::callback,mo::Report{vfo(),0,plugin,ev,ctx.stamp,ctx.generation});
        if(!mo::admit_report(*ctx.stamp,this,pub,ctx.generation,[]{return true;})){
            mo::count_callback_refused();return;
        }
    }
#endif
    TrunkHandler h;
    {
        std::lock_guard<std::mutex> lk(talker_mu_);
        h = trunk_handler_;
    }
    if (h) h(plugin, std::move(ev));
}

void DigitalDecoder::set_spatial_handler(SpatialHandler h) {
    std::lock_guard<std::mutex> lk(talker_mu_);
    spatial_handler_ = std::move(h);
}

void DigitalDecoder::deliver_spatial(const SpatialReport& s) {
    SpatialHandler h;
    {
        std::lock_guard<std::mutex> lk(talker_mu_);
        h = spatial_handler_;
    }
    if (h) h(s);
}

void DigitalDecoder::set_video_handler(VideoHandler h) {
    std::lock_guard<std::mutex> lk(talker_mu_);
    video_handler_ = std::move(h);
}

void DigitalDecoder::deliver_video(const VideoFrameReport& f) {
    VideoHandler h;
    {
        std::lock_guard<std::mutex> lk(talker_mu_);
        h = video_handler_;
    }
    if (h) h(f);
}

void DigitalDecoder::process(const std::complex<float>* x, size_t n, float rate_hz, double rf_hz, uint64_t pos,
                             const std::complex<int16_t>* mc, int mc_m, int bw_hz, const AuxStream* aux, size_t naux) {
#ifdef TT01_ROLE_QUALIFICATION
    if(role_authority_.load()){std::lock_guard lock(q_mu_);++role_stats_.refused;return;}
#endif
    if (reset_pending_.exchange(false)) engine_->reset_all();
    engine_->configure(mode(), options(), plugin_id());
    want_mc_.store(engine_->multichannel(), std::memory_order_relaxed);
    engine_->process(x, n, rate_hz, rf_hz, pos, mc, mc_m, bw_hz, internal_streams_ ? aux : nullptr,
                     internal_streams_ ? naux : 0);
}

void DigitalDecoder::drain(int timeout_ms) {
#ifdef TT01_ROLE_QUALIFICATION
    if(role_authority_.load()){std::lock_guard lock(q_mu_);++role_stats_.refused;return;}
#endif
    engine_->drain(timeout_ms);
}

void DigitalDecoder::run() {
    bool pending = false;   // samples still queued for a plugin's pipe
#ifdef TT01_GENERATION_QUALIFICATION
    // Permanent quarantine of the managed decoder in this offline variant;
    // B2B will qualify manual-role transitions before activating delivery.
    bool managed_lane=false;
    std::shared_ptr<const managed_iq::WorkerEnvelope> managed_ready;
    uint64_t expected_pos=0;
    uint32_t sync_id=0;
    const auto worker_running=[&]{std::lock_guard lock(q_mu_);return !stop_;};
    auto close_ready=[&]{
        engine_->close_managed_generation();
        if(managed_ready)managed_iq::generation_test::trace(this,
            managed_iq::generation_test::Stage::closed,*managed_ready,sync_id);
        managed_ready.reset();
    };
#ifdef TT01_INTEGRATED_RESIDUAL_QUALIFICATION
    auto retire_dead_managed=[&]{
        if(!managed_ready)return;
        if(!managed_ready->admit(this,[]{return true;})){
            close_ready();return;
        }
        if(!engine_->managed_idle_clean()){
            // The exact original envelope, never the currently selected
            // VFO identity. Revalidate under its admission locks.
            managed_ready->admit(this,[&]{
                return managed_ready->authority_->retire_admitted(managed_ready->provenance().placement);
            });
            close_ready();
        }
    };
#endif
#endif
#ifdef TT01_ROLE_QUALIFICATION
    std::optional<managed_iq::RoleStamp> manual_ready;
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
    namespace mo=managed_iq::manual_output;
    std::shared_ptr<const managed_iq::ManualEnvelope> manual_last;
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
    std::shared_ptr<mo::Generation> manual_generation;
#endif
#endif
    auto close_manual=[&]{
        if(manual_ready){
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
            if(manual_generation)manual_generation->retire();
            manual_generation.reset();
#endif
            mo::Scope closing(manual_last,true);
            manual_last.reset();
#endif
            engine_->close_managed_generation();manual_ready.reset();pending=false;
            if(managed_iq::role_test::hook)managed_iq::role_test::hook(this,
                managed_iq::role_test::Stage::idle_closed,nullptr,nullptr,0);
        }
    };
#endif
    for (;;) {
        Block b;
        bool have = false;
        {
            std::unique_lock<std::mutex> lk(q_mu_);
            const auto ready = [this] { return stop_ || !queue_.empty() || reset_pending_.load(); };
#ifdef TT01_GENERATION_QUALIFICATION
#ifdef TT01_ROLE_QUALIFICATION
            if(role_authority_.load()){
                q_cv_.wait_for(lk,std::chrono::milliseconds(pending?2:10),ready);
            }else
#endif
            if(managed_lane){
                if(!q_cv_.wait_for(lk,std::chrono::milliseconds(10),ready)){
                    lk.unlock();
                    // No plugin flush or report delivery in this lane.
                    // Revalidate retained authority even without further IQ.
                    if(managed_ready&&(!managed_ready->admit(this,[]{return true;})||!engine_->managed_runner_alive()))close_ready();
                    continue;
                }
            } else
#endif
            if (!pending) {
                q_cv_.wait(lk, ready);
            } else if (!q_cv_.wait_for(lk, std::chrono::milliseconds(2), ready)) {
                // no new block: keep the plugins' pipes full
                lk.unlock();
                pending = engine_->flush_pending();
                continue;
            }
            if (stop_) {
#ifdef TT01_ROLE_QUALIFICATION
                for(auto& q:queue_){
                    if(q.manual)++role_stats_.shutdown;
                    if(q.managed)++role_stats_.managed_shutdown;
                }
                queue_.clear();queued_s_=0;lk.unlock();
                close_manual();
                if(managed_ready)close_ready();
#endif
                return;
            }
            if (!queue_.empty()) {
                b = std::move(queue_.front());
                queue_.pop_front();
                queued_s_ = queue_.empty() ? 0.0 : queued_s_ - b.dur;
                have = true;
            }
        }
#ifdef TT01_INTEGRATED_RESIDUAL_QUALIFICATION
        // Both an idle bound worker and one about to take fresh work
        // retire a known dead retained runner before admitting new work.
        retire_dead_managed();
#endif
        if(have&&b.managed){
#ifdef TT01_WORKER_QUALIFICATION
            using namespace managed_iq::worker_test;
            if(hook)hook(this,Event::before_start,*b.managed);
            const bool admitted=b.managed->admit(this,[&]{
                std::lock_guard lock(q_mu_);
                if(stop_||mode()!=Mode::PLUGIN)return false;
                ++managed_stats_.started;return true;
            });
            if(!admitted){std::lock_guard lock(q_mu_);++managed_stats_.stale;}
            if(hook)hook(this,admitted?Event::started:Event::stale,*b.managed);
#ifdef TT01_GENERATION_QUALIFICATION
            namespace gt=managed_iq::generation_test;
#ifdef TT01_ROLE_QUALIFICATION
            if(admitted)close_manual();
#endif
            managed_lane=true;pending=false;
            // A reset notification cannot cause an unfenced legacy engine
            // transition in this qualification variant.
            reset_pending_.exchange(false);
            if(!admitted){
                if(managed_ready&&(!managed_ready->admit(this,[]{return true;})||!engine_->managed_runner_alive()))close_ready();
                continue;
            }
#ifdef TT01_ROLE_QUALIFICATION
            bool delivered=false;
            struct CountManaged {
                std::mutex& mu;RoleQueueStats& stats;bool& delivered;
                ~CountManaged(){std::lock_guard lock(mu);if(delivered)++stats.managed_completed;else ++stats.managed_failed;}
            } accounting{q_mu_,role_stats_,delivered};
#endif
            const auto& e=*b.managed;
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
            auto retire=[&]{
                e.admit(this,[&]{return e.authority_->retire_admitted(e.provenance().placement);});
            };
#endif
            const bool same=managed_ready&&
                managed_ready->provenance().placement==e.provenance().placement&&
                managed_ready->source()==e.source()&&managed_ready->wire()==e.wire()&&
                managed_ready->segment()==e.segment()&&expected_pos==e.pos()&&
                managed_ready->rate()==e.rate()&&
                managed_ready->provenance().observed_rf()==e.provenance().observed_rf()&&
                engine_->managed_runner_alive();
            if(!same){
#ifdef TT01_INTEGRATED_RESIDUAL_QUALIFICATION
                retire_dead_managed();
                if(!e.admit(this,[]{return true;}))continue;
#endif
                if(managed_ready)close_ready();
                if(sync_id==UINT32_MAX){
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
                    retire();
#endif
                    gt::trace(this,gt::Stage::refused,e,sync_id,"SYNC identity exhausted");continue;
                }
                ++sync_id;
                if(!engine_->prepare_managed_generation(e,sync_id,worker_running
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
                    ,retire
#endif
                ))continue;
            }
            // Readiness linearizes independently from prior B1 start and
            // ACK. No authority lock spans the wire exchange or hooks.
            if(!e.admit(this,[]{return true;})){
                close_ready();gt::trace(this,gt::Stage::refused,e,sync_id,"retired before readiness");continue;
            }
            managed_ready=b.managed;
            gt::trace(this,same?gt::Stage::reused:gt::Stage::ready,e,sync_id);
#ifdef TT01_SAMPLE_QUALIFICATION
            if(!engine_->deliver_managed_samples(e,sync_id,worker_running
#ifdef TT01_MANAGED_STAGE_LOSS_QUALIFICATION
                ,retire
#endif
            )){
                close_ready();continue;
            }
#ifdef TT01_ROLE_QUALIFICATION
            delivered=true;
#endif
#endif
            expected_pos=e.pos()+e.samples().size();
#endif
#endif
            // B1 only: even a valid start is NOT allowed to enter Engine.
            // B2 must qualify ordered reset/options/SYNC and retire pipe work.
            continue;
        }
#ifdef TT01_ROLE_QUALIFICATION
        auto bound=role_authority_.load();
        if(bound){
            namespace rt=managed_iq::role_test;
            reset_pending_.exchange(false);
            if(managed_ready&&!managed_ready->admit(this,[]{return true;}))close_ready();
            if(manual_ready&&!bound->role_current(*manual_ready))close_manual();
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
            if(manual_last&&!mo::admit(*manual_last,this,bound,[]{return true;}))close_manual();
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
            if(manual_generation&&!manual_generation->admit([]{return true;}))close_manual();
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            if(manual_last&&manual_generation&&manual_last->mode()==Mode::PLUGIN&&manual_last->plugin()=="p25"
#ifdef TT01_OPERATIONAL_BUILD
               &&manual_last->segment()
#endif
               ){
                bool healthy;
                {mo::Scope operation(manual_last,false,manual_generation);
                    healthy=engine_->poll_manual_retained();
                    if(!healthy)retire_manual_context_exact();
                }
                if(!healthy||!manual_generation->admit([]{return true;}))close_manual();
            }
#endif
            if(have&&b.manual&&manual_last){
                // Retire before any next-generation sample is processed.
                // A stream and array delivery from one packet may share seq.
                const auto old=manual_last->seq(),next=b.manual->seq();
                // Qualified nonempty envelopes can skip host packet
                // sequence only across publisher-accounted empty passes.
                // The exact segment/loss ledger fences all missing submits.
                bool gap=next!=old&&(old==UINT64_MAX||next!=old+1);
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
                if(b.manual->observed_rf().bound&&manual_last->observed_rf().bound&&
                   b.manual->loss_epoch()==manual_last->loss_epoch()&&b.manual->loss_current())gap=false;
#endif
                if(b.manual->segment()!=manual_last->segment()||next<old||
#ifdef TT01_OPERATIONAL_BUILD
                   (b.manual->segment()&&gap)
#else
                   gap
#endif
                   )close_manual();
            }
#endif
#endif
            if(have){
                auto trace=[&](rt::Stage stage){if(rt::hook)rt::hook(this,stage,b.manual.get(),b.x.data(),b.x.size());};
                trace(rt::Stage::before_start);
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
#ifdef TT01_PRODUCER_COLD_QUALIFICATION
                if(b.manual&&b.manual->observed_rf().bound&&
                    !b.manual->matches_rf(b.rf,b.rate,b.bw,b.x.size())){
                    {std::lock_guard lock(q_mu_);++role_stats_.stale;}
                    trace(rt::Stage::stale);continue;
                }
#endif
                if(!b.manual||!mo::admit(*b.manual,this,bound,[&]{
#ifdef TT01_MANUAL_LOSS_QUALIFICATION
#ifdef TT01_OPERATIONAL_BUILD
                    return !b.manual->segment()||b.manual->loss_current();
#else
                    return b.manual->loss_current();
#endif
#else
                    return true;
#endif
                })){
#else
                if(!b.manual||!b.manual->admit(this,bound,[]{return true;})){
#endif
                    {std::lock_guard lock(q_mu_);++role_stats_.stale;}
                    trace(rt::Stage::stale);continue;
                }
                if(managed_ready)close_ready();
                managed_lane=false;
                if(!manual_ready||*manual_ready!=b.manual->role()){
                    close_manual();engine_->close_managed_generation();
                    manual_ready=b.manual->role();
                }
                // Configuration belongs to the captured role; the engine
                // is worker-owned, so in-flight old work cannot use a new
                // managed runner. Revalidate after a close/start barrier.
                if(!b.manual->admit(this,bound,[&]{
                    std::lock_guard lock(q_mu_);if(stop_)return false;
#ifdef TT01_MANUAL_LOSS_QUALIFICATION
#ifdef TT01_OPERATIONAL_BUILD
                    if(b.manual->segment()&&!b.manual->loss_current())return false;
#else
                    if(!b.manual->loss_current())return false;
#endif
#endif
                    ++role_stats_.started;return true;
                })){
                    {std::lock_guard lock(q_mu_);++role_stats_.stale;}
                    close_manual();trace(rt::Stage::stale);continue;
                }
                trace(rt::Stage::started);
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
                if(!mo::admit(*b.manual,this,bound,[&]{
                    std::lock_guard lock(q_mu_);
#ifdef TT01_MANUAL_LOSS_QUALIFICATION
#ifdef TT01_OPERATIONAL_BUILD
                    if(b.manual->segment()&&!b.manual->loss_current())return false;
#else
                    if(!b.manual->loss_current())return false;
#endif
#endif
                    return !stop_;
                })){
#else
                if(!b.manual->admit(this,bound,[&]{std::lock_guard lock(q_mu_);return !stop_;})){
#endif
                    {std::lock_guard lock(q_mu_);++role_stats_.finished;++role_stats_.retired;}
                    close_manual();trace(rt::Stage::retired);continue;
                }
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
                manual_last=b.manual;
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
                // Configure before minting a new output generation. A
                // startup RESET cannot inherit sample provenance.
                if(!manual_generation){
                    engine_->configure(b.manual->mode(),b.manual->options(),b.manual->plugin());
#ifdef TT01_MANUAL_LOSS_QUALIFICATION
#ifdef TT01_OPERATIONAL_BUILD
                    if(!b.manual->segment())manual_generation=std::make_shared<mo::Generation>();
                    else
#endif
                    manual_generation=std::make_shared<mo::Generation>(bound,b.manual->loss_epoch());
#else
                    manual_generation=std::make_shared<mo::Generation>();
#endif
                }
                mo::Scope operation(manual_last,false,manual_generation);
#else
                mo::Scope operation(manual_last);
#endif
#endif
                engine_->configure(b.manual->mode(),b.manual->options(),b.manual->plugin());
                want_mc_.store(engine_->multichannel(),std::memory_order_relaxed);
                if(b.manual->mode()!=Mode::OFF){
                    if(b.am>0)engine_->process_array(b.x.data(),b.am,b.ns,b.rate,b.rf,b.pos);
                    else{
                        AuxStream aux[MAX_STREAMS];size_t naux=0;
                        for(const auto& a:b.aux){
                            if(naux>=static_cast<size_t>(MAX_STREAMS))break;
                            auto& s=aux[naux++];s.width_hz=a.w;s.rate_hz=a.rate;s.x=a.x.data();
                            s.n=a.x.size();s.pos=a.pos;s.mc=a.m?a.mc.data():nullptr;s.mc_m=a.m;
                        }
                        engine_->process(b.x.data(),b.x.size(),b.rate,b.rf,b.pos,
                            b.m?b.mc.data():nullptr,b.m,b.bw,aux,naux);
                    }
                }
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
                if(b.manual->mode()==Mode::PLUGIN&&b.manual->plugin()=="p25"&&
#ifdef TT01_OPERATIONAL_BUILD
                   b.manual->segment()&&
#endif
                   !engine_->manual_runner_alive())retire_manual_context_exact();
#endif
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
                const bool current=mo::admit(*b.manual,this,bound,[&]{
#ifdef TT01_MANUAL_LOSS_QUALIFICATION
#ifdef TT01_OPERATIONAL_BUILD
                    return !b.manual->segment()||b.manual->loss_current();
#else
                    return b.manual->loss_current();
#endif
#else
                    return true;
#endif
                });
#else
                const bool current=b.manual->admit(this,bound,[]{return true;});
#endif
                {std::lock_guard lock(q_mu_);++role_stats_.finished;if(!current)++role_stats_.retired;}
                if(!current){close_manual();trace(rt::Stage::retired);}
                else trace(rt::Stage::finished);
                continue;
            }
            // Idle configuration enables array/AUTO wants without adopting
            // sample provenance. Flush only an authorized existing role.
            auto role=bound->capture_role();
            if(!role||role->role!=managed_iq::Role::manual)continue;
            if(managed_ready)close_ready();
            if(!manual_ready||*manual_ready!=*role){
                close_manual();
                auto m=mode();auto o=options();auto plugin=plugin_id();
                if(!bound->admit_manual(*role,[]{return true;}))continue;
                engine_->close_managed_generation();manual_ready=*role;
                engine_->configure(m,o,plugin);
                want_mc_.store(engine_->multichannel(),std::memory_order_relaxed);
            }
#ifdef TT01_MANUAL_OUTPUT_QUALIFICATION
            // No sample-bearing operation has occurred yet: do not invent
            // provenance for a startup/idle report.
            if(manual_last&&mo::admit(*manual_last,this,bound,[]{return true;})){
#ifdef TT01_MANUAL_CONTINUITY_QUALIFICATION
                mo::Scope operation(manual_last,false,manual_generation);
#else
                mo::Scope operation(manual_last);
#endif
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
                if(manual_last->mode()==Mode::PLUGIN&&manual_last->plugin()=="p25"
#ifdef TT01_OPERATIONAL_BUILD
                   &&manual_last->segment()
#endif
                   ){
                    // Retained fixed lane was already polled above.
                    pending=false;
                }else pending=engine_->flush_pending();
#else
                pending=engine_->flush_pending();
#endif
            }else if(manual_last)close_manual();
#ifdef TT01_MANUAL_RUNNER_QUALIFICATION
            if(manual_generation&&!manual_generation->admit([]{return true;}))close_manual();
#endif
#else
            if(bound->admit_manual(*manual_ready,[]{return true;}))pending=engine_->flush_pending();
            else close_manual();
#endif
            if(manual_ready&&!bound->role_current(*manual_ready))close_manual();
            continue;
        }
#endif
#ifdef TT01_GENERATION_QUALIFICATION
        if(managed_lane){
            reset_pending_.exchange(false);
            if(managed_ready&&(!managed_ready->admit(this,[]{return true;})||!engine_->managed_runner_alive()))close_ready();
            continue; // ordinary/manual re-admission is deliberately unqualified
        }
#endif
        if (reset_pending_.exchange(false)) engine_->reset_all();
        engine_->configure(mode(), options(), plugin_id());
        want_mc_.store(mode() != Mode::OFF && engine_->multichannel(), std::memory_order_relaxed);
        if (have && mode() != Mode::OFF) {
            if (b.am > 0) {
                engine_->process_array(b.x.data(), b.am, b.ns, b.rate, b.rf, b.pos);
            } else {
                AuxStream aux[MAX_STREAMS];
                size_t naux = 0;
                for (const auto& a : b.aux) {
                    if (naux >= static_cast<size_t>(MAX_STREAMS)) break;
                    AuxStream& s = aux[naux++];
                    s.width_hz = a.w;
                    s.rate_hz = a.rate;
                    s.x = a.x.data();
                    s.n = a.x.size();
                    s.pos = a.pos;
                    s.mc = a.m ? a.mc.data() : nullptr;
                    s.mc_m = a.m;
                }
                engine_->process(b.x.data(), b.x.size(), b.rate, b.rf, b.pos, b.m ? b.mc.data() : nullptr, b.m, b.bw,
                                 aux, naux);
            }
        }
        pending = engine_->flush_pending();
    }
}

std::string DigitalDecoder::active_plugin() const {
    const Mode m = mode();
    if (m == Mode::PLUGIN) return plugin_id();
    if (m == Mode::AUTO) return engine_->detected();
    return "";
}

bool DigitalDecoder::squelch_open(int64_t def_ms) const {
    const std::string id = active_plugin();
    if (id.empty()) return false;
    const int64_t t = engine_->last_valid_of(id);
    return t != 0 && now_ms() - t < engine_->squelch_hold_ms(id, def_ms);
}

bool DigitalDecoder::lead_talker(std::string* id, std::string* label) const {
    std::lock_guard<std::mutex> lk(lead_mu_);
    if (lead_tid_.empty()) return false;
    *id = lead_tid_;
    *label = lead_tlabel_;
    return true;
}

void DigitalDecoder::set_lead_talker(const std::string& id, const std::string& label) {
    std::lock_guard<std::mutex> lk(lead_mu_);
    lead_tid_ = id;
    lead_tlabel_ = label;
}

bool DigitalDecoder::frames_within(int64_t ms) const {
    const std::string id = active_plugin();
    if (id.empty()) return false;
    const int64_t t = engine_->last_valid_of(id);
    return t != 0 && now_ms() - t < ms;
}

std::string DigitalDecoder::status_json(uint64_t events_after, size_t max_events, bool tables) const {
    Engine::Status s = engine_->status();
    Mode m = mode();
    std::ostringstream o;
    char buf[64];
    o << "{\"mode\":\"" << json_escape(mode_string(m, plugin_id())) << "\",\"detected\":\"" << json_escape(s.detected)
      << "\",\"detected_name\":\"" << json_escape(s.detected_name) << "\"";
    const char* state = m == Mode::OFF ? "off" : (!s.detected.empty() ? "receiving" : "searching");
    o << ",\"state\":\"" << state << "\"";
    snprintf(buf, sizeof buf, "%.0f", s.offset_hz);
    o << ",\"offset_hz\":" << buf << ",\"rate\":" << static_cast<int>(s.rate);
    o << ",\"rate_ok\":" << ((s.rate == 0 || s.rate >= s.min_rate) ? "true" : "false");
    o << ",\"min_rate\":" << static_cast<int>(s.min_rate);
    o << ",\"frames\":{";
    bool first = true;
    for (const auto& f : s.frames) {
        o << (first ? "" : ",") << "\"" << json_escape(f.first) << "\":[" << f.second.first << "," << f.second.second << "]";
        first = false;
    }
    bool map_capable = false;
    for (const auto& p : s.plugins) map_capable |= p.map;
    o << "},\"dropped\":" << dropped_.load() << ",\"map_capable\":" << (map_capable ? "true" : "false")
      << ",\"map_points\":" << report_.map_size() << ",\"plugins\":[";
    for (size_t i = 0; i < s.plugins.size(); i++) {
        const auto& p = s.plugins[i];
        o << (i ? "," : "") << "{\"id\":\"" << json_escape(p.id) << "\",\"name\":\"" << json_escape(p.name)
          << "\",\"version\":\"" << json_escape(p.version) << "\",\"state\":\"" << json_escape(p.state)
          << "\",\"error\":\"" << json_escape(p.error) << "\",\"rate\":" << p.rate << ",\"dropped\":" << p.dropped;
        // Auto detect's internal stream it runs on (Hz; absent = the VFO's own)
        if (p.stream_hz > 0) o << ",\"stream_hz\":" << p.stream_hz;
        o << ",\"log\":[";
        for (size_t k = 0; k < p.tail.size(); k++) o << (k ? "," : "") << "\"" << json_escape(p.tail[k]) << "\"";
        o << "]}";
    }
    o << "]";
    {
        std::lock_guard<std::mutex> lk(v_mu_);
        o << ",\"voice\":{\"listening\":" << (voice_wanted() ? "true" : "false")
          << ",\"state\":\"" << json_escape(voice_state_) << "\"}";
    }
    Options op = options();
    o << ",\"opts\":{\"verbose\":" << (op.verbose ? "true" : "false") << ",\"log\":" << op.log << ",\"pos_s\":" << op.pos_s
      << ",\"map\":" << (op.map ? "true" : "false")
      << ",\"plugin\":{";
    first = true;
    for (const auto& kv : op.plugin) {
        o << (first ? "" : ",") << "\"" << json_escape(kv.first) << "\":\"" << json_escape(kv.second) << "\"";
        first = false;
    }
    o << "}}";
    // the options' run-time choices (kp::Host::option_choices), keyed as opts.plugin;
    // {} = none: the page draws the declared list / text field
    o << ",\"choices\":" << report_.choices_json();
    // always when asked ({} = none): pages keep the last tables between pushes without them
    if (tables) {
        o << ",\"tables\":" << report_.tables_json() << ",\"plots\":" << report_.plots_json();
    }
    o << ",\"info\":" << report_.info_json() << ",\"events\":" << report_.events_json(events_after, max_events)
      << ",\"seq\":" << report_.last_seq() << "}";
    return o.str();
}

}  // namespace dig
