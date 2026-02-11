//! Breakthrough #5: Streaming Accumulation
//!
//! Process data in chunks, accumulate results, discard raw data.
//! The generalized concept from gradient accumulation: process K windows
//! with 1/K memory. Used by ~110 of 203 security components.

use std::collections::VecDeque;

/// A streaming accumulator that processes items in windows.
/// Items flow in, get accumulated into a summary, and raw items are discarded.
///
/// `T` = input item type, `A` = accumulator/summary type.
pub struct StreamAccumulator<T, A> {
    /// Current window of unprocessed items
    window: VecDeque<T>,
    /// Maximum items to buffer before forcing a flush
    window_size: usize,
    /// The accumulation function: (current_accumulator, &[items]) -> updated_accumulator
    accumulate_fn: Box<dyn Fn(&mut A, &[T]) + Send + Sync>,
    /// Current accumulated state
    accumulator: A,
    /// Total items processed (lifetime)
    total_processed: u64,
    /// Total flushes performed
    flush_count: u64,
}

impl<T, A> StreamAccumulator<T, A>
where
    T: Send + Sync,
    A: Send + Sync,
{
    /// Create a new streaming accumulator.
    /// - `window_size`: max items to buffer before auto-flush
    /// - `initial`: initial accumulator value
    /// - `accumulate_fn`: function that updates the accumulator with a batch of items
    pub fn new<F>(window_size: usize, initial: A, accumulate_fn: F) -> Self
    where
        F: Fn(&mut A, &[T]) + Send + Sync + 'static,
    {
        Self {
            window: VecDeque::with_capacity(window_size),
            window_size,
            accumulate_fn: Box::new(accumulate_fn),
            accumulator: initial,
            total_processed: 0,
            flush_count: 0,
        }
    }

    /// Push a single item. If the window is full, automatically flushes.
    pub fn push(&mut self, item: T) {
        self.window.push_back(item);
        if self.window.len() >= self.window_size {
            self.flush();
        }
    }

    /// Push multiple items. Flushes as needed.
    pub fn push_batch(&mut self, items: impl IntoIterator<Item = T>) {
        for item in items {
            self.push(item);
        }
    }

    /// Flush: accumulate current window and discard raw items.
    pub fn flush(&mut self) {
        if self.window.is_empty() {
            return;
        }
        let items: Vec<T> = self.window.drain(..).collect();
        self.total_processed += items.len() as u64;
        (self.accumulate_fn)(&mut self.accumulator, &items);
        self.flush_count += 1;
    }

    /// Get a reference to the current accumulator state.
    pub fn state(&self) -> &A {
        &self.accumulator
    }

    /// Get a mutable reference to the current accumulator state.
    pub fn state_mut(&mut self) -> &mut A {
        &mut self.accumulator
    }

    /// Take the accumulator, resetting it to a new value.
    pub fn take_state(&mut self, replacement: A) -> A {
        self.flush();
        std::mem::replace(&mut self.accumulator, replacement)
    }

    /// Number of items currently buffered (not yet flushed).
    pub fn buffered(&self) -> usize {
        self.window.len()
    }

    /// Total items processed over lifetime.
    pub fn total_processed(&self) -> u64 {
        self.total_processed
    }

    /// Total flush operations performed.
    pub fn flush_count(&self) -> u64 {
        self.flush_count
    }
}

/// A time-windowed streaming accumulator. Accumulates over fixed time windows,
/// producing a summary per window.
pub struct TimeWindowAccumulator<T, A> {
    inner: StreamAccumulator<T, A>,
    window_duration: std::time::Duration,
    window_start: std::time::Instant,
    /// Completed window summaries (ring buffer of last N)
    completed_windows: VecDeque<A>,
    max_completed_windows: usize,
}

impl<T, A> TimeWindowAccumulator<T, A>
where
    T: Send + Sync,
    A: Clone + Send + Sync,
{
    pub fn new<F>(
        window_duration: std::time::Duration,
        max_buffer: usize,
        initial: A,
        max_completed: usize,
        accumulate_fn: F,
    ) -> Self
    where
        F: Fn(&mut A, &[T]) + Send + Sync + 'static,
        A: Clone,
    {
        Self {
            inner: StreamAccumulator::new(max_buffer, initial.clone(), accumulate_fn),
            window_duration,
            window_start: std::time::Instant::now(),
            completed_windows: VecDeque::with_capacity(max_completed),
            max_completed_windows: max_completed,
        }
    }

    /// Push an item. If the time window has expired, rotates to new window.
    pub fn push(&mut self, item: T)
    where
        A: Default,
    {
        if self.window_start.elapsed() >= self.window_duration {
            self.rotate_window(A::default());
        }
        self.inner.push(item);
    }

    /// Force window rotation.
    fn rotate_window(&mut self, new_initial: A) {
        let completed = self.inner.take_state(new_initial);
        if self.completed_windows.len() >= self.max_completed_windows {
            self.completed_windows.pop_front();
        }
        self.completed_windows.push_back(completed);
        self.window_start = std::time::Instant::now();
    }

    /// Get the current (in-progress) window state.
    pub fn current_state(&self) -> &A {
        self.inner.state()
    }

    /// Get completed window summaries.
    pub fn completed_windows(&self) -> &VecDeque<A> {
        &self.completed_windows
    }

    /// Number of completed windows stored.
    pub fn completed_count(&self) -> usize {
        self.completed_windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_accumulator_basic() {
        let mut acc = StreamAccumulator::new(5, 0u64, |state, items: &[i32]| {
            *state += items.iter().map(|x| *x as u64).sum::<u64>();
        });

        for i in 1..=10 {
            acc.push(i);
        }
        acc.flush();

        assert_eq!(*acc.state(), 55); // 1+2+...+10
        assert_eq!(acc.total_processed(), 10);
        assert_eq!(acc.flush_count(), 2); // flushed at 5 and at 10
    }

    #[test]
    fn test_stream_accumulator_auto_flush() {
        let mut acc = StreamAccumulator::new(3, Vec::<i32>::new(), |state, items: &[i32]| {
            state.push(items.len() as i32);
        });

        acc.push(1);
        acc.push(2);
        acc.push(3); // triggers auto-flush
        acc.push(4);
        acc.flush();

        assert_eq!(*acc.state(), vec![3, 1]); // batch of 3, then batch of 1
    }
}
