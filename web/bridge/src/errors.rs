//! Bound upstream panics to a stage. The Node subprocess also has time/output limits.
use std::panic::{AssertUnwindSafe, catch_unwind};
pub fn guarded<T, E: std::fmt::Display>(f: impl FnOnce() -> Result<T, E>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(f))
        .map_err(|_| "Engine panicked while inspecting this input".to_string())?
        .map_err(|e| e.to_string())
}
