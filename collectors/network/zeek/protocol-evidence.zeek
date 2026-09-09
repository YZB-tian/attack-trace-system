##! Optional bounded HTTP body and ICMP Echo payload evidence for the course lab.
##! Outputs measurements and hashes only; no plaintext payload is written to logs.
@load base/protocols/http
@load base/protocols/conn

module ATSProtocolEvidence;

export {
    redef enum Log::ID += { LOG };
    const body_sample_limit: count = 1024 &redef;
    const icmp_sample_limit: count = 512 &redef;
    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        proto: string &log;
        is_orig: bool &log;
        icmp_type: count &log;
        icmp_code: count &log;
        echo_id: count &log;
        echo_seq: count &log;
        payload_len: count &log;
        payload_sample_len: count &log;
        payload_entropy: double &log;
        payload_sha256: string &log;
    };
}

redef record HTTP::Info += {
    ats_body_sample: string &default="";
    ats_body_sample_len: count &log &optional;
    ats_body_entropy: double &log &optional;
    ats_body_sha256: string &log &optional;
};

event zeek_init()
    {
    Log::create_stream(LOG, [$columns=Info, $path="icmp_payload"]);
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig || ! c?$http_state ) return;
    local depth = c$http_state$current_request;
    if ( depth !in c$http_state$pending ) return;
    local h = c$http_state$pending[depth];
    if ( |h$ats_body_sample| >= body_sample_limit ) return;
    local remaining = body_sample_limit - |h$ats_body_sample|;
    h$ats_body_sample += sub_bytes(data, 0, remaining as int);
    h$ats_body_sample_len = |h$ats_body_sample|;
    if ( h$ats_body_sample_len > 0 )
        {
        h$ats_body_entropy = find_entropy(h$ats_body_sample)$entropy;
        h$ats_body_sha256 = sha256_hash(h$ats_body_sample);
        }
    c$http_state$pending[depth] = h;
    }

function log_echo(c: connection, info: icmp_info, echo_id: count, seq: count, payload: string)
    {
    local sample = sub_bytes(payload, 0, icmp_sample_limit as int);
    local h = 0.0;
    if ( |sample| > 0 ) h = find_entropy(sample)$entropy;
    Log::write(LOG, [$ts=network_time(), $uid=c$uid, $id=c$id,
        $proto=info$v6 ? "icmp6" : "icmp",
        $is_orig=port_to_count(c$id$orig_p) == info$itype,
        $icmp_type=info$itype, $icmp_code=info$icode, $echo_id=echo_id, $echo_seq=seq,
        $payload_len=|payload|, $payload_sample_len=|sample|,
        $payload_entropy=h, $payload_sha256=sha256_hash(sample)]);
    }

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string)
    {
    log_echo(c, info, id, seq, payload);
    }

event icmp_echo_reply(c: connection, info: icmp_info, id: count, seq: count, payload: string)
    {
    log_echo(c, info, id, seq, payload);
    }
