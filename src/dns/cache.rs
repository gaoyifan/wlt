use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{Name, RData, RecordType},
};
use moka::{Expiry, future::Cache};

use super::{AddressFamily, policy::Selection};

/// Everything that can change the answer for an otherwise identical DNS question.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct CacheKey {
    /// Full request wire form after clearing ID and removing ECS.
    pub normalized_request: Arc<[u8]>,
    pub peer_family: AddressFamily,
    pub selection: Selection,
    pub outlet_group: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct ViewKey {
    pub name: Name,
    pub peer_family: AddressFamily,
    pub selection: Selection,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct LearnedView {
    pub outlet_group: usize,
    pub ttl: Duration,
}

#[derive(Clone, Debug)]
struct CachedResponse {
    message: Message,
    inserted_at: Instant,
    ttl: Duration,
    weight: u32,
}

#[derive(Debug)]
struct DnsExpiry;

impl Expiry<CacheKey, CachedResponse> for DnsExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CachedResponse,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

#[derive(Debug)]
struct LearnedViewExpiry;

impl Expiry<ViewKey, LearnedView> for LearnedViewExpiry {
    fn expire_after_create(
        &self,
        _key: &ViewKey,
        value: &LearnedView,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

pub(super) struct LearnedViewCache {
    inner: Cache<ViewKey, LearnedView>,
}

impl LearnedViewCache {
    pub(super) fn new(max_entries: u64) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(max_entries)
                .expire_after(LearnedViewExpiry)
                .build(),
        }
    }

    pub(super) async fn get(&self, key: &ViewKey) -> Option<LearnedView> {
        self.inner.get(key).await
    }

    pub(super) async fn insert_if_absent(&self, key: ViewKey, view: LearnedView) -> LearnedView {
        self.inner.entry(key).or_insert(view).await.into_value()
    }
}

/// A weighted asynchronous cache for complete DNS responses.
///
/// Moka exposes one capacity dimension when a weigher is installed. Each entry
/// therefore receives at least `ceil(max_weight / max_entries)` synthetic bytes.
/// This conservatively enforces both configured limits, at the cost of possibly
/// evicting small entries earlier when response sizes vary substantially.
pub(super) struct DnsCache {
    inner: Cache<CacheKey, CachedResponse>,
}

impl DnsCache {
    pub(super) fn new(max_entries: u64, max_weight: u64) -> Self {
        assert!(
            max_entries > 0,
            "DNS cache max_entries must be greater than zero"
        );
        assert!(
            max_weight > 0,
            "DNS cache max_weight must be greater than zero"
        );

        let minimum_entry_weight = max_weight.div_ceil(max_entries).max(1);
        let minimum_entry_weight = u32::try_from(minimum_entry_weight)
            .expect("DNS cache per-entry weight must fit in u32");

        let inner = Cache::builder()
            .max_capacity(max_weight)
            .weigher(move |_key: &CacheKey, value: &CachedResponse| {
                value.weight.max(minimum_entry_weight)
            })
            .expire_after(DnsExpiry)
            .build();

        Self { inner }
    }

    /// Returns a cloned response with every resource-record TTL aged in place.
    async fn get(&self, key: &CacheKey) -> Option<Message> {
        let cached = self.inner.get(key).await?;
        let mut message = cached.message;
        age_ttls(&mut message, cached.inserted_at.elapsed());
        Some(message)
    }

    /// Returns a cached response or coalesces concurrent loads for the same key.
    /// Successful but uncacheable responses use a zero expiry: all waiters share
    /// the result, while later requests still go back to the upstream.
    pub(super) async fn get_or_try_insert_with<F>(
        &self,
        key: CacheKey,
        init: F,
    ) -> Result<(Message, bool), Arc<anyhow::Error>>
    where
        F: Future<Output = Result<Message>>,
    {
        if let Some(message) = self.get(&key).await {
            return Ok((message, true));
        }

        let cached = self
            .inner
            .try_get_with(key, async move {
                let mut message = init.await?;
                let ttl = cache_ttl(&mut message)
                    .map(|ttl| Duration::from_secs(u64::from(ttl)))
                    .unwrap_or(Duration::ZERO);
                let weight = message
                    .to_vec()
                    .ok()
                    .and_then(|encoded| u32::try_from(encoded.len()).ok())
                    .unwrap_or(u32::MAX);
                Ok::<_, anyhow::Error>(CachedResponse {
                    message,
                    inserted_at: Instant::now(),
                    ttl,
                    weight,
                })
            })
            .await?;
        let mut message = cached.message;
        age_ttls(&mut message, cached.inserted_at.elapsed());
        Ok((message, false))
    }

    pub(super) fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }

    pub(super) fn weighted_size(&self) -> u64 {
        self.inner.weighted_size()
    }
}

pub(super) fn cache_ttl(message: &mut Message) -> Option<u32> {
    let query_type = message.queries.first()?.query_type();
    let response_code = message.response_code;
    let negative = match response_code {
        ResponseCode::NXDomain => true,
        ResponseCode::NoError => {
            let has_soa = message
                .authorities
                .iter()
                .any(|record| matches!(&record.data, RData::SOA(_)));
            let has_requested_answer = query_type == RecordType::ANY && !message.answers.is_empty()
                || message
                    .answers
                    .iter()
                    .any(|record| record.record_type() == query_type);
            has_soa && !has_requested_answer
        }
        _ => return None,
    };

    let mut ttl = if negative {
        message.authorities.iter_mut().find_map(|record| {
            let RData::SOA(soa) = &record.data else {
                return None;
            };
            let negative_ttl = record.ttl.min(soa.minimum);
            record.ttl = negative_ttl;
            Some(negative_ttl)
        })?
    } else {
        u32::MAX
    };

    for record in message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
    {
        ttl = ttl.min(record.ttl);
    }

    (ttl > 0 && ttl != u32::MAX).then_some(ttl)
}

fn age_ttls(message: &mut Message, elapsed: Duration) {
    let elapsed = u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX);
    for record in message
        .answers
        .iter_mut()
        .chain(&mut message.authorities)
        .chain(&mut message.additionals)
    {
        record.ttl = record.ttl.saturating_sub(elapsed);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{A, SOA},
        },
    };

    use super::{
        AddressFamily, CacheKey, DnsCache, LearnedView, LearnedViewCache, Selection, ViewKey,
        age_ttls, cache_ttl,
    };

    fn key(map_mark: u32) -> CacheKey {
        CacheKey {
            normalized_request: Arc::from([0_u8, 0, 1, 0]),
            peer_family: AddressFamily::Ipv4,
            selection: Selection {
                map_mark,
                default_mark: 2,
            },
            outlet_group: 0,
        }
    }

    fn view_key(map_mark: u32) -> ViewKey {
        ViewKey {
            name: Name::from_ascii("example.test.").unwrap(),
            peer_family: AddressFamily::Ipv4,
            selection: Selection {
                map_mark,
                default_mark: 2,
            },
        }
    }

    fn positive(ttl: u32) -> Message {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        message
    }

    fn negative(response_code: ResponseCode, soa_ttl: u32, minimum: u32) -> Message {
        let mut message = Message::new(7, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::A,
        ));
        message.metadata.response_code = response_code;
        message.add_authority(Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            soa_ttl,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example.test.").unwrap(),
                Name::from_ascii("hostmaster.example.test.").unwrap(),
                1,
                3600,
                600,
                86_400,
                minimum,
            )),
        ));
        message
    }

    #[test]
    fn positive_expiry_is_minimum_record_ttl() {
        let mut message = positive(30);
        message.add_additional(Record::from_rdata(
            Name::from_ascii("extra.example.test.").unwrap(),
            12,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 2))),
        ));

        assert_eq!(cache_ttl(&mut message), Some(12));
    }

    #[test]
    fn negative_expiry_uses_soa_minimum_and_normalizes_soa_ttl() {
        let mut message = negative(ResponseCode::NXDomain, 300, 60);

        assert_eq!(cache_ttl(&mut message), Some(60));
        assert_eq!(message.authorities[0].ttl, 60);
    }

    #[test]
    fn uncacheable_responses_are_rejected() {
        let mut servfail = positive(30);
        servfail.metadata.response_code = ResponseCode::ServFail;
        assert_eq!(cache_ttl(&mut servfail), None);

        let mut nodata_without_soa = Message::response(1, OpCode::Query);
        nodata_without_soa.add_query(Query::query(
            Name::from_ascii("example.test.").unwrap(),
            RecordType::A,
        ));
        assert_eq!(cache_ttl(&mut nodata_without_soa), None);

        let mut zero_ttl = positive(0);
        assert_eq!(cache_ttl(&mut zero_ttl), None);
    }

    #[test]
    fn hit_time_aging_covers_all_record_sections() {
        let mut message = positive(10);
        message.add_authority(Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            8,
            RData::SOA(SOA::new(Name::root(), Name::root(), 1, 1, 1, 1, 1)),
        ));
        message.add_additional(Record::from_rdata(
            Name::from_ascii("extra.example.test.").unwrap(),
            2,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));

        age_ttls(&mut message, Duration::from_secs(3));

        assert_eq!(message.answers[0].ttl, 7);
        assert_eq!(message.authorities[0].ttl, 5);
        assert_eq!(message.additionals[0].ttl, 0);
    }

    #[tokio::test]
    async fn cache_key_separates_routing_selections() {
        let cache = DnsCache::new(10, 10_000);
        cache
            .get_or_try_insert_with(key(1), async { Ok(positive(30)) })
            .await
            .unwrap();

        assert!(cache.get(&key(1)).await.is_some());
        assert!(cache.get(&key(9)).await.is_none());
        let mut other_group = key(1);
        other_group.outlet_group = 1;
        assert!(cache.get(&other_group).await.is_none());
    }

    #[tokio::test]
    async fn entries_expire_at_the_dns_ttl() {
        let cache = DnsCache::new(10, 10_000);
        cache
            .get_or_try_insert_with(key(1), async { Ok(positive(1)) })
            .await
            .unwrap();
        assert!(cache.get(&key(1)).await.is_some());

        tokio::time::sleep(Duration::from_millis(1_050)).await;

        assert!(cache.get(&key(1)).await.is_none());
    }

    #[tokio::test]
    async fn synthetic_weight_conservatively_enforces_entry_limit() {
        let cache = DnsCache::new(2, 10_000);
        for map_mark in 0..3 {
            cache
                .get_or_try_insert_with(key(map_mark), async { Ok(positive(30)) })
                .await
                .unwrap();
        }
        cache.inner.run_pending_tasks().await;

        assert!(cache.entry_count() <= 2);
        assert!(cache.weighted_size() <= 10_000);
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_load() {
        let cache = DnsCache::new(10, 10_000);
        let calls = Arc::new(AtomicUsize::new(0));
        let load = || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok::<_, anyhow::Error>(positive(30))
            }
        };

        let (first, second) = tokio::join!(
            cache.get_or_try_insert_with(key(1), load()),
            cache.get_or_try_insert_with(key(1), load()),
        );

        assert!(!first.unwrap().1);
        assert!(!second.unwrap().1);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn learned_view_keeps_the_first_non_default_group_until_expiry() {
        let cache = LearnedViewCache::new(10);
        let first = LearnedView {
            outlet_group: 1,
            ttl: Duration::from_secs(30),
        };
        let second = LearnedView {
            outlet_group: 2,
            ttl: Duration::from_secs(30),
        };

        let (first_result, second_result) = tokio::join!(
            cache.insert_if_absent(view_key(1), first),
            cache.insert_if_absent(view_key(1), second),
        );

        assert_eq!(first_result.outlet_group, second_result.outlet_group);
        assert_eq!(
            cache.get(&view_key(1)).await.unwrap().outlet_group,
            first_result.outlet_group
        );
    }

    #[tokio::test]
    async fn learned_views_expire_and_do_not_cross_selections() {
        let cache = LearnedViewCache::new(10);
        cache
            .insert_if_absent(
                view_key(1),
                LearnedView {
                    outlet_group: 1,
                    ttl: Duration::from_millis(10),
                },
            )
            .await;

        assert!(cache.get(&view_key(9)).await.is_none());
        let mut other_family = view_key(1);
        other_family.peer_family = AddressFamily::Ipv6;
        assert!(cache.get(&other_family).await.is_none());
        let mut other_name = view_key(1);
        other_name.name = Name::from_ascii("other.test.").unwrap();
        assert!(cache.get(&other_name).await.is_none());
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(cache.get(&view_key(1)).await.is_none());
    }
}
