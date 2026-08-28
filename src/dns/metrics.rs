use std::time::Duration;

use hickory_proto::op::ResponseCode;
use metrics::{counter, gauge, histogram};

/// Low-cardinality DNS metrics facade.
///
/// Callers may label configured upstreams, transports and bounded outcomes. Query
/// names and client addresses are intentionally absent from this interface.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct DnsMetrics;

impl DnsMetrics {
    pub(super) fn request(&self, transport: &'static str) {
        counter!("wlt_dns_requests_total", "transport" => transport).increment(1);
    }

    pub(super) fn response(&self, transport: &'static str, response_code: ResponseCode) {
        counter!(
            "wlt_dns_responses_total",
            "transport" => transport,
            "rcode" => response_code_label(response_code),
        )
        .increment(1);
    }

    pub(super) fn rejected(&self, transport: &'static str, reason: &'static str) {
        counter!(
            "wlt_dns_rejected_requests_total",
            "transport" => transport,
            "reason" => reason,
        )
        .increment(1);
    }

    pub(super) fn cache_lookup(&self, hit: bool) {
        counter!(
            "wlt_dns_cache_lookups_total",
            "result" => if hit { "hit" } else { "miss" },
        )
        .increment(1);
    }

    pub(super) fn cache_size(&self, entries: u64, weight: u64) {
        gauge!("wlt_dns_cache_entries").set(entries as f64);
        gauge!("wlt_dns_cache_weight_bytes").set(weight as f64);
    }

    pub(super) fn upstream_request(
        &self,
        upstream: &str,
        transport: &'static str,
        result: &'static str,
        elapsed: Duration,
    ) {
        let upstream = upstream.to_owned();
        counter!(
            "wlt_dns_upstream_requests_total",
            "upstream" => upstream.clone(),
            "transport" => transport,
            "result" => result,
        )
        .increment(1);
        histogram!(
            "wlt_dns_upstream_request_duration_seconds",
            "upstream" => upstream,
            "transport" => transport,
        )
        .record(elapsed.as_secs_f64());
    }
}

fn response_code_label(response_code: ResponseCode) -> &'static str {
    match response_code {
        ResponseCode::NoError => "noerror",
        ResponseCode::FormErr => "formerr",
        ResponseCode::ServFail => "servfail",
        ResponseCode::NXDomain => "nxdomain",
        ResponseCode::NotImp => "notimp",
        ResponseCode::Refused => "refused",
        ResponseCode::YXDomain => "yxdomain",
        ResponseCode::YXRRSet => "yxrrset",
        ResponseCode::NXRRSet => "nxrrset",
        ResponseCode::NotAuth => "notauth",
        ResponseCode::NotZone => "notzone",
        ResponseCode::BADVERS => "badvers",
        ResponseCode::BADSIG => "badsig",
        ResponseCode::BADKEY => "badkey",
        ResponseCode::BADTIME => "badtime",
        ResponseCode::BADMODE => "badmode",
        ResponseCode::BADNAME => "badname",
        ResponseCode::BADALG => "badalg",
        ResponseCode::BADTRUNC => "badtrunc",
        ResponseCode::BADCOOKIE => "badcookie",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use hickory_proto::op::ResponseCode;

    use super::{DnsMetrics, response_code_label};

    #[test]
    fn response_code_labels_are_prometheus_friendly() {
        assert_eq!(response_code_label(ResponseCode::NoError), "noerror");
        assert_eq!(response_code_label(ResponseCode::NXDomain), "nxdomain");
        assert_eq!(response_code_label(ResponseCode::ServFail), "servfail");
    }

    #[test]
    fn facade_records_without_a_global_recorder() {
        let metrics = DnsMetrics;
        metrics.request("udp");
        metrics.response("udp", ResponseCode::NoError);
        metrics.rejected("tcp", "overloaded");
        metrics.cache_lookup(true);
        metrics.cache_size(3, 512);
        metrics.upstream_request("primary", "doh", "success", std::time::Duration::ZERO);
    }
}
