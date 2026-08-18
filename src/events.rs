//! In-memory ring buffer of notable daemon events.
//!
//! Served to the TUI over the control socket (`Events` request) so the
//! "what just happened" answer lives in the UI instead of `journalctl`.
//! Bounded; the oldest events fall off. Deliberately not persisted — the
//! journal and the JSONL log remain the durable record.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::control::Event;

pub struct EventLog {
    inner: Mutex<VecDeque<Event>>,
    cap: usize,
}

impl EventLog {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(cap)),
            cap: cap.max(1),
        }
    }

    pub fn push(&self, ev: Event) {
        let mut q = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() == self.cap {
            q.pop_front();
        }
        q.push_back(ev);
    }

    /// Newest last.
    pub fn snapshot(&self) -> Vec<Event> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .cloned()
            .collect()
    }
}
