use parking_lot::Mutex;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

const INLINE_REPLAY_KEY_CAPACITY: usize = 80;
const DEFAULT_INDEX_PREALLOC_CAPACITY: usize = 4096;

#[derive(Clone, Debug, Eq)]
struct ReplayKey {
    len: u8,
    bytes: [u8; INLINE_REPLAY_KEY_CAPACITY],
}

impl ReplayKey {
    fn new(key: &[u8]) -> Self {
        assert!(
            key.len() <= INLINE_REPLAY_KEY_CAPACITY,
            "replay key length {} exceeds inline capacity {}",
            key.len(),
            INLINE_REPLAY_KEY_CAPACITY
        );
        let mut bytes = [0_u8; INLINE_REPLAY_KEY_CAPACITY];
        bytes[..key.len()].copy_from_slice(key);
        Self {
            len: key.len() as u8,
            bytes,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl PartialEq for ReplayKey {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.as_slice() == other.as_slice()
    }
}

impl Hash for ReplayKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.as_slice().hash(state);
    }
}

#[derive(Debug)]
struct ReplaySlot {
    key: ReplayKey,
    expires_at: Instant,
}

#[derive(Debug)]
pub struct TimedReplaySet {
    timeout: Duration,
    max_entries: usize,
    len: usize,
    slots: Vec<Option<ReplaySlot>>,
    free: Vec<usize>,
    index: HashMap<u64, Vec<usize>>,
    order: VecDeque<usize>,
    hash_builder: RandomState,
}

impl TimedReplaySet {
    pub fn with_capacity(timeout: Duration, max_entries: usize) -> Self {
        let index_capacity = initial_index_capacity(max_entries);
        Self {
            timeout,
            max_entries: max_entries.max(1),
            len: 0,
            slots: Vec::with_capacity(index_capacity),
            free: Vec::new(),
            index: HashMap::with_capacity(index_capacity),
            order: VecDeque::with_capacity(index_capacity),
            hash_builder: RandomState::new(),
        }
    }

    pub fn insert_unique(&mut self, key: &[u8]) -> bool {
        let now = Instant::now();
        self.sweep_expired(now);
        let replay_key = ReplayKey::new(key);
        let hash = self.key_hash(&replay_key);
        if self.contains_hashed(hash, &replay_key, now) {
            return false;
        }
        while self.len >= self.max_entries {
            if !self.evict_oldest() {
                break;
            }
        }
        let expires_at = now.checked_add(self.timeout).unwrap_or(now);
        let slot_idx = self.free.pop().unwrap_or_else(|| {
            self.slots.push(None);
            self.slots.len() - 1
        });
        self.slots[slot_idx] = Some(ReplaySlot {
            key: replay_key,
            expires_at,
        });
        self.index.entry(hash).or_default().push(slot_idx);
        self.order.push_back(slot_idx);
        self.len += 1;
        true
    }

    fn sweep_expired(&mut self, now: Instant) {
        while let Some(&slot_idx) = self.order.front() {
            let Some(slot) = self.slots.get(slot_idx).and_then(|slot| slot.as_ref()) else {
                self.order.pop_front();
                continue;
            };
            if slot.expires_at >= now {
                break;
            }
            self.order.pop_front();
            self.remove_slot(slot_idx);
        }
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some(slot_idx) = self.order.pop_front() {
            if self.remove_slot(slot_idx) {
                return true;
            }
        }
        false
    }

    fn remove_slot(&mut self, slot_idx: usize) -> bool {
        let Some(slot) = self.slots.get_mut(slot_idx).and_then(Option::take) else {
            return false;
        };
        let hash = self.key_hash(&slot.key);
        let mut should_remove_bucket = false;
        if let Some(bucket) = self.index.get_mut(&hash) {
            if let Some(pos) = bucket.iter().position(|idx| *idx == slot_idx) {
                bucket.swap_remove(pos);
            }
            should_remove_bucket = bucket.is_empty();
        }
        if should_remove_bucket {
            self.index.remove(&hash);
        }
        self.free.push(slot_idx);
        self.len = self.len.saturating_sub(1);
        true
    }

    fn contains_hashed(&self, hash: u64, key: &ReplayKey, now: Instant) -> bool {
        self.index.get(&hash).is_some_and(|bucket| {
            bucket.iter().copied().any(|slot_idx| {
                self.slots
                    .get(slot_idx)
                    .and_then(|slot| slot.as_ref())
                    .is_some_and(|slot| slot.key == *key && slot.expires_at > now)
            })
        })
    }

    fn key_hash<T: Hash>(&self, value: &T) -> u64 {
        let mut hasher = self.hash_builder.build_hasher();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[cfg(test)]
    pub fn contains(&self, key: &[u8]) -> bool {
        let now = Instant::now();
        let replay_key = ReplayKey::new(key);
        self.contains_hashed(self.key_hash(&replay_key), &replay_key, now)
    }

    #[cfg(test)]
    pub(crate) fn len_for_test(&self) -> usize {
        self.len
    }
}

#[derive(Debug)]
pub struct ClientQueue {
    front: u32,
    back: u32,
    alloc: HashSet<u32>,
    enable: bool,
    last_update: Instant,
    ref_count: u32,
}

impl ClientQueue {
    pub fn new(begin_id: u32) -> Self {
        Self {
            front: begin_id.saturating_sub(64),
            back: begin_id.saturating_add(1),
            alloc: HashSet::new(),
            enable: true,
            last_update: Instant::now(),
            ref_count: 0,
        }
    }

    pub fn update(&mut self) {
        self.last_update = Instant::now();
    }

    pub fn add_ref(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    pub fn del_ref(&mut self) {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
    }

    pub fn is_active(&self) -> bool {
        self.ref_count > 0 && self.last_update.elapsed() < Duration::from_secs(60 * 10)
    }

    pub fn re_enable(&mut self, connection_id: u32) {
        self.enable = true;
        self.front = connection_id.saturating_sub(64);
        self.back = connection_id.saturating_add(1);
        self.alloc.clear();
        self.last_update = Instant::now();
    }

    pub fn insert(&mut self, connection_id: u32) -> bool {
        if !self.enable {
            return false;
        }
        if !self.is_active() {
            self.re_enable(connection_id);
        }
        self.update();

        if connection_id < self.front {
            return false;
        }
        if connection_id > self.front.saturating_add(0x4000) {
            return false;
        }
        if self.alloc.contains(&connection_id) {
            return false;
        }

        if self.back <= connection_id {
            self.back = connection_id.saturating_add(1);
        }
        self.alloc.insert(connection_id);

        while self.alloc.contains(&self.front) || self.front.saturating_add(0x1000) < self.back {
            self.alloc.remove(&self.front);
            self.front = self.front.saturating_add(1);
        }
        self.add_ref();
        true
    }
}

#[derive(Debug)]
pub struct UserClientRegistry {
    max_client: usize,
    users: HashMap<u32, HashMap<u32, ClientQueue>>,
}

impl UserClientRegistry {
    pub fn new(max_client: usize) -> Self {
        Self {
            max_client,
            users: HashMap::new(),
        }
    }

    pub fn set_max_client(&mut self, max_client: usize) {
        self.max_client = max_client.max(1);
    }

    pub fn insert(&mut self, user_id: u32, client_id: u32, connection_id: u32) -> bool {
        let local = self.users.entry(user_id).or_default();

        if let Some(queue) = local.get_mut(&client_id) {
            return queue.insert(connection_id);
        }

        if local.len() < self.max_client {
            let mut q = ClientQueue::new(connection_id);
            let ok = q.insert(connection_id);
            local.insert(client_id, q);
            return ok;
        }

        let stale_key = local
            .iter()
            .find_map(|(k, q)| if !q.is_active() { Some(*k) } else { None });
        if let Some(k) = stale_key {
            local.remove(&k);
            let mut q = ClientQueue::new(connection_id);
            let ok = q.insert(connection_id);
            local.insert(client_id, q);
            return ok;
        }

        false
    }

    pub fn update(&mut self, user_id: u32, client_id: u32) {
        if let Some(local) = self.users.get_mut(&user_id) {
            if let Some(queue) = local.get_mut(&client_id) {
                queue.update();
            }
        }
    }

    pub fn remove(&mut self, user_id: u32, client_id: u32) {
        if let Some(local) = self.users.get_mut(&user_id) {
            if let Some(queue) = local.get_mut(&client_id) {
                queue.del_ref();
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct SharedUserRegistry {
    inner: Arc<Mutex<UserClientRegistry>>,
}

impl SharedUserRegistry {
    pub fn new(max_client: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(UserClientRegistry::new(max_client))),
        }
    }

    pub fn set_max_client(&self, max_client: usize) {
        self.inner.lock().set_max_client(max_client);
    }

    pub fn insert(&self, user_id: u32, client_id: u32, connection_id: u32) -> bool {
        self.inner.lock().insert(user_id, client_id, connection_id)
    }

    pub fn update(&self, user_id: u32, client_id: u32) {
        self.inner.lock().update(user_id, client_id)
    }

    pub fn remove(&self, user_id: u32, client_id: u32) {
        self.inner.lock().remove(user_id, client_id)
    }
}

fn initial_index_capacity(max_entries: usize) -> usize {
    max_entries.min(DEFAULT_INDEX_PREALLOC_CAPACITY).max(1)
}

#[cfg(test)]
mod tests {
    use super::{ClientQueue, SharedUserRegistry, TimedReplaySet, UserClientRegistry};
    use std::time::Duration;

    #[test]
    fn replay_set_enforces_capacity_limit() {
        let mut replay = TimedReplaySet::with_capacity(Duration::from_secs(300), 2);
        assert!(
            replay.insert_unique(b"first"),
            "first insert should succeed"
        );
        assert!(
            replay.insert_unique(b"second"),
            "second insert should succeed"
        );
        assert_eq!(replay.len_for_test(), 2, "cache should reach its capacity");

        assert!(
            replay.insert_unique(b"third"),
            "third insert should evict the oldest entry"
        );
        assert_eq!(replay.len_for_test(), 2, "cache should remain bounded");
        assert!(
            !replay.contains(b"first"),
            "oldest entry should be evicted once the cache is full"
        );
        assert!(
            replay.contains(b"second"),
            "newer entry should remain cached"
        );
        assert!(
            replay.contains(b"third"),
            "newly inserted entry should remain cached"
        );
    }

    #[test]
    fn replay_set_rejects_duplicate_key_within_window() {
        let mut replay = TimedReplaySet::with_capacity(Duration::from_secs(300), 4);
        assert!(replay.insert_unique(b"dup-key"));
        assert!(
            !replay.insert_unique(b"dup-key"),
            "second insert should be rejected within replay window"
        );
    }

    #[test]
    fn client_queue_enforces_connection_id_window() {
        let mut queue = ClientQueue::new(1000);
        assert!(queue.insert(1000), "initial id should be accepted");
        assert!(
            !queue.insert(1000),
            "duplicate connection id should be rejected"
        );
        assert!(
            !queue.insert(900),
            "ids older than the sliding front should be rejected"
        );
        assert!(
            !queue.insert(1000 + 0x5000),
            "far-future ids outside the acceptance window should be rejected"
        );
        assert!(queue.insert(1001), "next in-window id should be accepted");
    }

    #[test]
    fn user_client_registry_tracks_client_lifecycle() {
        let mut registry = UserClientRegistry::new(2);
        assert!(registry.insert(7, 11, 100));
        registry.update(7, 11);
        registry.remove(7, 11);

        let queue = registry
            .users
            .get(&7)
            .and_then(|local| local.get(&11))
            .expect("client queue");
        assert_eq!(queue.ref_count, 0, "remove should release one reference");
    }

    #[test]
    fn shared_user_registry_rejects_duplicate_connection_ids() {
        let registry = SharedUserRegistry::new(2);
        assert!(registry.insert(9, 15, 200));
        assert!(
            !registry.insert(9, 15, 200),
            "duplicate connection ids for the same user/client should be rejected"
        );
    }
}
