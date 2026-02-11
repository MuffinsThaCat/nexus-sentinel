use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Global memory metrics tracker — implements Breakthrough #6 (Theoretical Verifier).
/// Every component registers its theoretical memory bound, and this tracker
/// continuously verifies actual usage stays within bounds.
#[derive(Clone)]
pub struct MemoryMetrics {
    inner: Arc<MemoryMetricsInner>,
}

struct MemoryMetricsInner {
    total_budget: AtomicUsize,
    total_used: AtomicUsize,
    component_bounds: RwLock<HashMap<String, ComponentMemoryBound>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentMemoryBound {
    pub name: String,
    pub theoretical_bound: usize,
    pub current_used: usize,
    pub peak_used: usize,
    pub allocation_count: u64,
    pub violation_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryReport {
    pub total_budget: usize,
    pub total_used: usize,
    pub utilization_percent: f64,
    pub components: Vec<ComponentMemoryBound>,
    pub violations: Vec<String>,
}

impl MemoryMetrics {
    pub fn new(total_budget: usize) -> Self {
        Self {
            inner: Arc::new(MemoryMetricsInner {
                total_budget: AtomicUsize::new(total_budget),
                total_used: AtomicUsize::new(0),
                component_bounds: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Register a component with its theoretical memory bound.
    pub fn register_component(&self, name: &str, theoretical_bound: usize) {
        let mut bounds = self.inner.component_bounds.write();
        bounds.insert(
            name.to_string(),
            ComponentMemoryBound {
                name: name.to_string(),
                theoretical_bound,
                current_used: 0,
                peak_used: 0,
                allocation_count: 0,
                violation_count: 0,
            },
        );
    }

    /// Record memory allocation for a component. Returns Err if bound exceeded.
    pub fn record_allocation(
        &self,
        component: &str,
        bytes: usize,
    ) -> Result<(), crate::SentinelError> {
        let mut bounds = self.inner.component_bounds.write();
        if let Some(bound) = bounds.get_mut(component) {
            bound.current_used = bound.current_used.saturating_add(bytes);
            bound.allocation_count += 1;
            if bound.current_used > bound.peak_used {
                bound.peak_used = bound.current_used;
            }
            if bound.current_used > bound.theoretical_bound {
                bound.violation_count += 1;
                return Err(crate::SentinelError::ComponentBoundExceeded {
                    component: component.to_string(),
                    used: bound.current_used,
                    bound: bound.theoretical_bound,
                });
            }
        }
        self.inner.total_used.fetch_add(bytes, Ordering::Relaxed);

        let total_used = self.inner.total_used.load(Ordering::Relaxed);
        let budget = self.inner.total_budget.load(Ordering::Relaxed);
        if total_used > budget {
            return Err(crate::SentinelError::MemoryBudgetExceeded {
                used: total_used,
                budget,
            });
        }
        Ok(())
    }

    /// Record memory deallocation for a component.
    pub fn record_deallocation(&self, component: &str, bytes: usize) {
        let mut bounds = self.inner.component_bounds.write();
        if let Some(bound) = bounds.get_mut(component) {
            bound.current_used = bound.current_used.saturating_sub(bytes);
        }
        self.inner.total_used.fetch_sub(bytes, Ordering::Relaxed);
    }

    /// Get current memory usage for a component.
    pub fn component_usage(&self, component: &str) -> Option<usize> {
        let bounds = self.inner.component_bounds.read();
        bounds.get(component).map(|b| b.current_used)
    }

    /// Get total memory usage across all components.
    pub fn total_used(&self) -> usize {
        self.inner.total_used.load(Ordering::Relaxed)
    }

    /// Get total memory budget.
    pub fn total_budget(&self) -> usize {
        self.inner.total_budget.load(Ordering::Relaxed)
    }

    /// Generate a full memory report — this is what the Health Monitor displays.
    pub fn report(&self) -> MemoryReport {
        let bounds = self.inner.component_bounds.read();
        let total_used = self.inner.total_used.load(Ordering::Relaxed);
        let total_budget = self.inner.total_budget.load(Ordering::Relaxed);

        let mut violations = Vec::new();
        let mut components: Vec<ComponentMemoryBound> = bounds.values().cloned().collect();
        components.sort_by(|a, b| b.current_used.cmp(&a.current_used));

        for c in &components {
            if c.current_used > c.theoretical_bound {
                violations.push(format!(
                    "{}: {} bytes used > {} bytes bound ({:.1}% over)",
                    c.name,
                    c.current_used,
                    c.theoretical_bound,
                    ((c.current_used as f64 / c.theoretical_bound as f64) - 1.0) * 100.0
                ));
            }
        }

        MemoryReport {
            total_budget,
            total_used,
            utilization_percent: if total_budget > 0 {
                (total_used as f64 / total_budget as f64) * 100.0
            } else {
                0.0
            },
            components,
            violations,
        }
    }

    /// Check if all components are within bounds. Returns list of violations.
    pub fn verify_all_bounds(&self) -> Vec<String> {
        self.report().violations
    }

    /// Set a new total memory budget.
    pub fn set_budget(&self, budget: usize) {
        self.inner.total_budget.store(budget, Ordering::Relaxed);
    }
}
