//! Opt-in timing for the MCP snapshot worker. Nested phases are exclusive.
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap, time::Instant};

struct Timing {
    baseline: bool,
    scope_baseline: bool,
    started: Instant,
    switched: Instant,
    phase: &'static str,
    phases: BTreeMap<&'static str, u64>,
    counts: BTreeMap<&'static str, u64>,
    details: Value,
}

thread_local! {
    static CURRENT: RefCell<Option<Timing>> = const { RefCell::new(None) };
}

pub(crate) struct Report;

pub(crate) fn begin() -> Option<Report> {
    let mode = std::env::var("AIDBG_SNAPSHOT_TIMING").ok()?;
    let baseline = match mode.as_str() {
        "1" | "scope-baseline" => false,
        "baseline" => true,
        _ => return None,
    };
    let started = Instant::now();
    CURRENT.with_borrow_mut(|slot| {
        *slot = Some(Timing {
            baseline,
            scope_baseline: baseline || mode == "scope-baseline",
            started,
            switched: started,
            phase: "other",
            phases: BTreeMap::new(),
            counts: BTreeMap::new(),
            details: Value::Null,
        });
    });
    Some(Report)
}

fn switch(timing: &mut Timing, next: &'static str, now: Instant) -> &'static str {
    *timing.phases.entry(timing.phase).or_default() +=
        now.duration_since(timing.switched).as_nanos() as u64;
    timing.switched = now;
    std::mem::replace(&mut timing.phase, next)
}

impl Drop for Report {
    fn drop(&mut self) {
        if let Some(mut timing) = CURRENT.with_borrow_mut(Option::take) {
            let now = Instant::now();
            switch(&mut timing, "other", now);
            eprintln!(
                "aidbg snapshot timing {}",
                json!({
                    "baseline": timing.baseline, "scope_baseline": timing.scope_baseline, "worker_ns": now.duration_since(timing.started).as_nanos() as u64,
                    "phases_ns": timing.phases, "counts": timing.counts, "details": timing.details,
                })
            );
        }
    }
}

pub(crate) struct Phase(&'static str);

pub(crate) fn phase(name: &'static str) -> Option<Phase> {
    CURRENT.with_borrow_mut(|slot| {
        slot.as_mut()
            .map(|timing| Phase(switch(timing, name, Instant::now())))
    })
}

impl Drop for Phase {
    fn drop(&mut self) {
        CURRENT.with_borrow_mut(|slot| {
            if let Some(timing) = slot {
                switch(timing, self.0, Instant::now());
            }
        });
    }
}

pub(crate) fn measure<T>(name: &'static str, operation: impl FnOnce() -> T) -> T {
    let _phase = phase(name);
    operation()
}

pub(crate) fn count(name: &'static str) {
    count_by(name, 1);
}

pub(crate) fn count_by(name: &'static str, n: usize) {
    CURRENT.with_borrow_mut(|slot| {
        if let Some(timing) = slot {
            *timing.counts.entry(name).or_default() += n as u64;
        }
    });
}

pub(crate) fn details(make: impl FnOnce() -> Value) {
    CURRENT.with_borrow_mut(|slot| {
        if let Some(timing) = slot {
            timing.details = make();
        }
    });
}

pub(crate) fn baseline() -> bool {
    CURRENT.with_borrow(|slot| slot.as_ref().is_some_and(|timing| timing.baseline))
}

pub(crate) fn scope_baseline() -> bool {
    CURRENT.with_borrow(|slot| slot.as_ref().is_some_and(|timing| timing.scope_baseline))
}
