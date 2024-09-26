use super::super::BlockResult;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{self, RwLock};
use std::thread::{self, ThreadId};


/// A map that associates objects of type `V` with thread IDs such that a thread can only access
/// its object from the map.
pub struct ThreadMap<V> {
    /// Maps thread IDs to values
    map: HashMap<ThreadId, V>,
}

impl<V> ThreadMap<V> {
    pub fn get(&self) -> Option<&V> {
        let thread_id = thread::current().id();
        self.map.get(&thread_id)
    }

    pub fn insert(&mut self, value: V) -> Option<V> {
        let thread_id = thread::current().id();
        self.map.insert(thread_id, value)
    }
}

impl<V> Default for ThreadMap<V> {
    fn default() -> Self {
        ThreadMap::<V> {
            map: Default::default(),
        }
    }
}


/// Wraps a value to be set only once, i.e. a singleton, that is to be used only from a single
/// thread (e.g. because it does not implement `Send` or `Sync`).
/// Once set, the object can only be retrieved from the original thread, which allows this type as
/// a whole to implement `Send` and `Sync` so it can be used in global static declarations.
/// (Note however that its `Send`/`Sync` properties are limited to guaranteeing runtime safety by
/// allowing access to the encapsulated object only from the original thread, i.e. precisely *not*
/// to send/access the object to/from a different thread.)
pub struct SingleThreadSingleton<V> {
    thread: RwLock<Option<ThreadId>>,
    value: RefCell<Option<Rc<V>>>,
}

// Safe, as described above
unsafe impl<V> Send for SingleThreadSingleton<V> {}
unsafe impl<V> Sync for SingleThreadSingleton<V> {}

impl<V> SingleThreadSingleton<V> {
    /// Store an object in the singleton.  Must only be used once.
    fn set(&self, value: V) -> BlockResult<()> {
        let mut thread = self.thread.write().unwrap();
        if thread.is_some() {
            return Err("Attempted to set single-thread variable twice".into());
        }

        thread.replace(thread::current().id());
        let previous = self.value.borrow_mut().replace(Rc::new(value));
        assert!(previous.is_none());

        Ok(())
    }

    /// Try to retrieve a reference to the object in the singleton.  Returns an error if this is
    /// the wrong thread, `Ok(None)` if it is the right thread but no object has been stored so
    /// far, and `Ok(Some(x))` if some object could be retrieved.
    fn get_only(&self) -> Result<Option<Rc<V>>, ()> {
        match *self.thread.read().unwrap() {
            None => Ok(None),
            Some(id) if id == thread::current().id() => {
                Ok(Some(Rc::clone(self.value.borrow().as_ref().unwrap())))
            }
            Some(_) => Err(()),
        }
    }

    /// Retrieve a reference to the object in the singleton, and if there is none yet, store one by
    /// invoking `generate()` (and return that new object).
    /// Returns `None` if this is the wrong thread.
    pub fn get<F: FnOnce() -> V>(&self, generate: F) -> Option<Rc<V>> {
        match self.get_only() {
            Err(()) => None,
            Ok(None) => {
                self.set(generate()).ok()?;
                self.get_only().ok().flatten()
            }
            Ok(Some(x)) => Some(x),
        }
    }

    /// Create a new singleton.  Marked `const` so it can be used for static variables.
    pub const fn new() -> Self {
        SingleThreadSingleton::<V> {
            thread: RwLock::new(None),
            value: RefCell::new(None),
        }
    }
}

/// Marker trait: Marks object whose `drop()` implementation can be run from any thread even if the
/// object itself is not `Send` or `Sync`.
pub trait SendDrop {}

// `sync::Weak<T>` can be dropped from any thread, regardless of whether `T` is `Send` or `Sync`,
// because it will never cause `T` to be dropped.
// Note that in contrast we cannot mark `rc::Weak` `SendDrop`.  Dropping a `Weak` type will only
// drop the wrapper, not the wrappee; but `rc::Weak` itself is not thread-safe (in contrast to
// `sync::Weak`), so it must be dropped in its home thread and thus is not `SendDrop`.
impl<T> SendDrop for sync::Weak<T> {}

/// Wraps a value in such a way that it can only be unwrapped in the thread in which it was
/// wrapped.  This is useful for example when you want to set up a background worker with
/// `monitor::monitor().spawn_in_thread()` that takes a non-`Send` value, but generating that value
/// may fail.  `.spawn_in_thread()` does not allow the future to fail, so you can move the
/// generation to `monitor::monitor().run_in_thread()` and wrap it in `ThreadBound`, then move it
/// to the worker after checking for errors.
pub struct ThreadBound<V> {
    thread: ThreadId,
    value: Cell<Option<V>>,
    send_drop: bool,
}

// Safe because we check at runtime that only the original thread will access this object
unsafe impl<V> Send for ThreadBound<V> {}
unsafe impl<V> Sync for ThreadBound<V> {}

impl<V: SendDrop> ThreadBound<V> {
    /// Wrap a value in `ThreadBound`.  The caller need not ensure the object is dropped in the
    /// calling thread, because `V: SendDrop`.
    pub fn new(value: V) -> Self {
        ThreadBound {
            thread: thread::current().id(),
            value: Cell::new(Some(value)),
            send_drop: true,
        }
    }
}

impl<V> ThreadBound<V> {
    /// Wrap a value in `ThreadBound`.  Unsafe because the caller *must* ensure that the object is
    /// dropped in the calling thread.
    pub unsafe fn new_unsafe(value: V) -> Self {
        ThreadBound {
            thread: thread::current().id(),
            value: Cell::new(Some(value)),
            send_drop: false,
        }
    }

    /// Unwrapped the previously wrapped value; must be run in the same thread where this object
    /// was created.
    pub fn unwrap(self) -> V {
        assert!(self.thread == thread::current().id());
        self.take().unwrap()
    }

    /// Same as `unwrap()`, but does not consume the object.  Once this function has been called,
    /// the object is gone and can thus be considered dropped for the purpose of determining
    /// `new_unsafe()`'s safety.  Subsequent calls to `take()` will return `None`.
    pub fn take(&self) -> Option<V> {
        assert!(self.thread == thread::current().id());
        self.value.take()
    }

    pub fn thread_id(&self) -> ThreadId {
        self.thread
    }
}

impl<V> std::convert::AsMut<V> for ThreadBound<V> {
    fn as_mut(&mut self) -> &mut V {
        assert!(self.thread == thread::current().id());
        self.value.get_mut().as_mut().unwrap()
    }
}

impl<V> Drop for ThreadBound<V> {
    fn drop(&mut self) {
        assert!(
            self.send_drop
                || self.value.get_mut().is_none()
                || self.thread == thread::current().id()
        );
    }
}

/// Mark the containing struct as main-thread-only.  The wrapped type ensures `!Send`.
pub struct MainThreadOnlyMarker(std::marker::PhantomData<std::sync::MutexGuard<'static, ()>>);

impl Default for MainThreadOnlyMarker {
    fn default() -> Self {
        // TODO: This is probably not the best way to detect this
        assert!(thread::current().name() == Some("main"));
        MainThreadOnlyMarker(Default::default())
    }
}