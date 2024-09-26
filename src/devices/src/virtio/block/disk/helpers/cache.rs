use super::super::BlockResult;
use super::FutureJoin;
use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock as AsyncRwLock;

pub struct AsyncLruCacheEntryInner<V> {
    value: V,
    last_used: AtomicUsize,
    dirty: AtomicBool,
}

pub type AsyncLruCacheEntry<V> = Arc<AsyncLruCacheEntryInner<V>>;

pub struct AsyncLruCache<K: Clone + PartialEq + Eq + Hash, V> {
    map: AsyncRwLock<HashMap<K, Arc<AsyncLruCacheEntryInner<V>>>>,
    lru_timer: AtomicUsize,
    limit: usize,
}

impl<K: Clone + PartialEq + Eq + Hash, V> AsyncLruCache<K, V> {
    pub fn new(size: usize) -> Self {
        AsyncLruCache {
            map: Default::default(),
            lru_timer: AtomicUsize::new(0),
            limit: size,
        }
    }

    pub async fn get_or_insert<
        ReadFuture: Future<Output = BlockResult<V>>,
        FlushFut: Future<Output = BlockResult<()>>,
        FlushGenerator: Fn(AsyncLruCacheEntry<V>) -> FlushFut,
    >(
        &self,
        key: K,
        read: ReadFuture,
        flush: FlushGenerator,
    ) -> BlockResult<AsyncLruCacheEntry<V>> {
        {
            let map = self.map.read().await;
            if let Some(entry) = map.get(&key) {
                entry.last_used.store(
                    self.lru_timer.fetch_add(1, Ordering::Relaxed),
                    Ordering::Relaxed,
                );
                return Ok(Arc::clone(entry));
            }
        }

        let mut map = self.map.write().await;
        if let Some(entry) = map.get(&key) {
            entry.last_used.store(
                self.lru_timer.fetch_add(1, Ordering::Relaxed),
                Ordering::Relaxed,
            );
            return Ok(Arc::clone(entry));
        }

        while map.len() > self.limit {
            let now = self.lru_timer.load(Ordering::Relaxed);
            let mut oldest = map.iter().fold((0, None), |oldest, (key, entry)| {
                // Cannot drop entries that are in use
                if Arc::strong_count(entry) > 1 {
                    return oldest;
                }

                let age = now.wrapping_sub(entry.last_used.load(Ordering::Relaxed));
                if age >= oldest.0 {
                    (age, Some(key.clone()))
                } else {
                    oldest
                }
            });

            let oldest_key = oldest.1.take().unwrap();
            let oldest_entry = map.remove(&oldest_key).unwrap();

            if oldest_entry.is_dirty() {
                oldest_entry.mark_clean();
                if let Err(err) = flush(Arc::clone(&oldest_entry)).await {
                    oldest_entry.mark_dirty();
                    map.insert(oldest_key, oldest_entry);
                    return Err(err);
                }
            }
        }

        let new_entry = Arc::new(AsyncLruCacheEntryInner {
            value: read.await?,
            last_used: AtomicUsize::new(self.lru_timer.fetch_add(1, Ordering::Relaxed)),
            dirty: AtomicBool::new(false),
        });
        map.insert(key, Arc::clone(&new_entry));

        Ok(new_entry)
    }

    pub async fn flush<
        FlushFut: Future<Output = BlockResult<()>>,
        FlushGenerator: Fn(AsyncLruCacheEntry<V>) -> FlushFut + Clone,
    >(
        &self,
        flush: FlushGenerator,
    ) -> BlockResult<()> {
        let mut futs = FutureJoin::new();

        let map = self.map.read().await;
        for entry in map.values() {
            if entry.is_dirty() {
                let entry = Arc::clone(entry);
                let flush = flush.clone();

                futs.push(Box::pin(async move {
                    entry.mark_clean();
                    if let Err(err) = flush(Arc::clone(&entry)).await {
                        entry.mark_dirty();
                        Err(err)
                    } else {
                        Ok(())
                    }
                }));
            }
        }

        futs.await
    }

    pub async fn flush_entry<
        FlushFut: Future<Output = BlockResult<()>>,
        FlushGenerator: FnOnce(AsyncLruCacheEntry<V>) -> FlushFut + Clone,
    >(
        &self,
        key: &K,
        flush: FlushGenerator,
    ) -> BlockResult<()> {
        let map = self.map.read().await;
        if let Some(entry) = map.get(key) {
            if entry.is_dirty() {
                entry.mark_clean();
                if let Err(err) = flush(Arc::clone(entry)).await {
                    entry.mark_dirty();
                    return Err(err);
                }
            }
        }

        Ok(())
    }
}

impl<V> AsyncLruCacheEntryInner<V> {
    pub fn value(&self) -> &V {
        &self.value
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty.load(Ordering::Relaxed)
    }

    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed)
    }

    fn mark_clean(&self) {
        self.dirty.store(false, Ordering::Relaxed)
    }
}

impl<V> Drop for AsyncLruCacheEntryInner<V> {
    fn drop(&mut self) {
        assert!(!self.is_dirty());
    }
}