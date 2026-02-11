//! Breakthrough #3: Reversible Computation
//!
//! Don't store intermediate results — recompute them from inputs when needed.
//! Trade CPU time for memory savings. For security tools on memory-constrained
//! devices, this is exactly the right trade.
//!
//! Used by ~45 of 203 security components (correlation, behavioral analysis,
//! compliance auditing, forensic reconstruction, etc.)

use std::sync::Arc;

/// A reversible computation that stores only inputs and final output,
/// and can recompute any intermediate state on demand.
///
/// `I` = input type, `O` = output type
pub struct ReversibleComputation<I, O> {
    /// The stored inputs (minimal — just what's needed to recompute)
    inputs: Vec<I>,
    /// The final output/result
    output: Option<O>,
    /// The computation function: given all inputs, produce output
    compute_fn: Arc<dyn Fn(&[I]) -> O + Send + Sync>,
    /// Optional: function to compute intermediate state at position k
    intermediate_fn: Option<Arc<dyn Fn(&[I], usize) -> O + Send + Sync>>,
    /// Maximum inputs to retain (ring buffer behavior)
    max_inputs: usize,
}

impl<I, O> ReversibleComputation<I, O>
where
    I: Clone + Send + Sync,
    O: Clone + Send + Sync,
{
    /// Create a new reversible computation.
    /// - `compute_fn`: given all inputs, produce the final output
    /// - `max_inputs`: max inputs to retain before oldest are discarded
    pub fn new<F>(max_inputs: usize, compute_fn: F) -> Self
    where
        F: Fn(&[I]) -> O + Send + Sync + 'static,
    {
        Self {
            inputs: Vec::new(),
            output: None,
            compute_fn: Arc::new(compute_fn),
            intermediate_fn: None,
            max_inputs,
        }
    }

    /// Set an optional function for computing intermediate state at position k.
    pub fn with_intermediate_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&[I], usize) -> O + Send + Sync + 'static,
    {
        self.intermediate_fn = Some(Arc::new(f));
        self
    }

    /// Add an input and recompute the output.
    pub fn push(&mut self, input: I) {
        self.inputs.push(input);
        if self.inputs.len() > self.max_inputs {
            self.inputs.remove(0);
        }
        self.output = Some((self.compute_fn)(&self.inputs));
    }

    /// Add a batch of inputs and recompute.
    pub fn push_batch(&mut self, inputs: impl IntoIterator<Item = I>) {
        for input in inputs {
            self.inputs.push(input);
            if self.inputs.len() > self.max_inputs {
                self.inputs.remove(0);
            }
        }
        self.output = Some((self.compute_fn)(&self.inputs));
    }

    /// Get the current output (stored, no recomputation needed).
    pub fn output(&self) -> Option<&O> {
        self.output.as_ref()
    }

    /// Recompute intermediate state at position k.
    /// This is the "reversible" part — we recompute instead of storing.
    pub fn intermediate_at(&self, k: usize) -> Option<O> {
        if let Some(ref f) = self.intermediate_fn {
            if k <= self.inputs.len() {
                return Some(f(&self.inputs, k));
            }
        }
        // Fallback: compute from inputs[0..k]
        if k <= self.inputs.len() {
            Some((self.compute_fn)(&self.inputs[..k]))
        } else {
            None
        }
    }

    /// Number of stored inputs.
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Memory savings: we store N inputs + 1 output instead of N intermediate states.
    /// Returns (actual_stored, would_have_stored, ratio).
    pub fn memory_savings(&self) -> (usize, usize, f64) {
        let input_size = self.inputs.len() * std::mem::size_of::<I>();
        let output_size = std::mem::size_of::<O>();
        let actual = input_size + output_size;
        // Without reversible: would store intermediate output at every step
        let would_store = self.inputs.len() * output_size;
        let ratio = if actual > 0 {
            would_store as f64 / actual as f64
        } else {
            1.0
        };
        (actual, would_store, ratio)
    }

    /// Clear all inputs and output.
    pub fn clear(&mut self) {
        self.inputs.clear();
        self.output = None;
    }

    /// Get a reference to all stored inputs.
    pub fn inputs(&self) -> &[I] {
        &self.inputs
    }
}

/// A "lazy recompute" wrapper. Stores the result of an expensive computation,
/// but can invalidate and recompute on demand. Used for compliance checks,
/// cert validations, etc. where we store the verdict but can re-verify.
pub struct LazyRecompute<T> {
    cached: Option<T>,
    compute_fn: Arc<dyn Fn() -> T + Send + Sync>,
    is_valid: bool,
}

impl<T: Clone + Send + Sync> LazyRecompute<T> {
    pub fn new<F>(compute_fn: F) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            cached: None,
            compute_fn: Arc::new(compute_fn),
            is_valid: false,
        }
    }

    /// Get the cached value, computing it if not available.
    pub fn get(&mut self) -> &T {
        if !self.is_valid || self.cached.is_none() {
            self.cached = Some((self.compute_fn)());
            self.is_valid = true;
        }
        self.cached.as_ref().unwrap()
    }

    /// Invalidate the cached value (next get() will recompute).
    pub fn invalidate(&mut self) {
        self.is_valid = false;
    }

    /// Force recomputation regardless of cache state.
    pub fn recompute(&mut self) -> &T {
        self.cached = Some((self.compute_fn)());
        self.is_valid = true;
        self.cached.as_ref().unwrap()
    }

    /// Check if the cached value is currently valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reversible_computation() {
        // Sum accumulator — only stores inputs, computes sum on demand
        let mut rc = ReversibleComputation::new(100, |inputs: &[i32]| -> i64 {
            inputs.iter().map(|&x| x as i64).sum()
        });

        rc.push(10);
        rc.push(20);
        rc.push(30);

        assert_eq!(*rc.output().unwrap(), 60);
        assert_eq!(rc.intermediate_at(2).unwrap(), 30); // sum of first 2
        assert_eq!(rc.input_count(), 3);
    }

    #[test]
    fn test_lazy_recompute() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_clone = counter.clone();

        let mut lazy = LazyRecompute::new(move || {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            42
        });

        assert_eq!(*lazy.get(), 42);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Second get should NOT recompute
        assert_eq!(*lazy.get(), 42);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Invalidate and get should recompute
        lazy.invalidate();
        assert_eq!(*lazy.get(), 42);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 2);
    }
}
