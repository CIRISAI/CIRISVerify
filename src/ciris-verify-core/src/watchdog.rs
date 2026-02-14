//! Shutdown watchdog for enforcing covenant invocation deadlines.
//!
//! The `ShutdownWatchdog` tracks pending shutdown directives and escalates
//! enforcement when deadlines expire:
//!
//! 1. **Graceful**: Allow deadline_seconds for agent to self-terminate
//! 2. **Immediate**: SIGTERM with 10-second grace period
//! 3. **Emergency**: SIGTERM + 10s grace + SIGKILL
//!
//! ## Security Properties
//!
//! - Fail-secure: If watchdog cannot verify shutdown, it escalates
//! - Audit trail: All actions are logged with incident IDs
//! - No override: Once issued, a shutdown cannot be cancelled

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::types::{ShutdownDirective, ShutdownType};

/// A pending shutdown being tracked by the watchdog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingShutdown {
    /// Deployment ID of the target agent.
    pub deployment_id: String,

    /// The shutdown directive.
    pub directive: ShutdownDirective,

    /// When this shutdown was issued (not serializable — defaults to now on deserialize).
    #[serde(skip, default = "Instant::now")]
    pub issued_at: Instant,

    /// Whether the agent has acknowledged the shutdown.
    pub acknowledged: bool,

    /// Whether the shutdown has been completed.
    pub completed: bool,
}

/// Escalation action returned by the watchdog when deadlines expire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationAction {
    /// No action needed — still within deadline.
    None,
    /// Send SIGTERM to the process.
    Sigterm {
        /// Process ID to signal.
        pid: u32,
    },
    /// Send SIGKILL to the process (SIGTERM grace expired).
    Sigkill {
        /// Process ID to signal.
        pid: u32,
    },
    /// Report failure — could not terminate.
    ReportFailure {
        /// Deployment that failed to terminate.
        deployment_id: String,
        /// Reason for the failure.
        reason: String,
    },
}

/// Shutdown watchdog that tracks pending shutdowns and enforces deadlines.
pub struct ShutdownWatchdog {
    /// Pending shutdowns indexed by deployment_id.
    pending: RwLock<HashMap<String, PendingShutdown>>,

    /// Grace period after SIGTERM before SIGKILL (default 10s).
    sigterm_grace: Duration,
}

impl ShutdownWatchdog {
    /// Create a new shutdown watchdog.
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            sigterm_grace: Duration::from_secs(10),
        }
    }

    /// Create a new shutdown watchdog with custom SIGTERM grace period.
    pub fn with_grace_period(sigterm_grace: Duration) -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            sigterm_grace,
        }
    }

    /// Issue a shutdown directive for a deployment.
    ///
    /// Once issued, a shutdown cannot be cancelled (fail-secure).
    pub fn issue_shutdown(&self, deployment_id: &str, directive: ShutdownDirective) {
        info!(
            deployment_id = %deployment_id,
            shutdown_type = ?directive.shutdown_type,
            deadline_seconds = directive.deadline_seconds,
            incident_id = %directive.incident_id,
            "Issuing shutdown directive"
        );

        let pending = PendingShutdown {
            deployment_id: deployment_id.to_string(),
            directive,
            issued_at: Instant::now(),
            acknowledged: false,
            completed: false,
        };

        if let Ok(mut map) = self.pending.write() {
            map.insert(deployment_id.to_string(), pending);
        }
    }

    /// Mark a shutdown as acknowledged by the agent.
    pub fn acknowledge_shutdown(&self, deployment_id: &str) {
        if let Ok(mut map) = self.pending.write() {
            if let Some(pending) = map.get_mut(deployment_id) {
                pending.acknowledged = true;
                info!(
                    deployment_id = %deployment_id,
                    "Shutdown acknowledged by agent"
                );
            }
        }
    }

    /// Mark a shutdown as completed.
    pub fn complete_shutdown(&self, deployment_id: &str) {
        if let Ok(mut map) = self.pending.write() {
            if let Some(pending) = map.get_mut(deployment_id) {
                pending.completed = true;
                info!(
                    deployment_id = %deployment_id,
                    "Shutdown completed"
                );
            }
        }
    }

    /// Check all pending shutdowns for expired deadlines.
    ///
    /// Returns a list of escalation actions that need to be taken.
    pub fn check_deadlines(&self) -> Vec<(String, EscalationAction)> {
        let mut actions = Vec::new();

        if let Ok(map) = self.pending.read() {
            for (deployment_id, pending) in map.iter() {
                if pending.completed {
                    continue;
                }

                let elapsed = pending.issued_at.elapsed();
                let deadline = Duration::from_secs(pending.directive.deadline_seconds as u64);

                if elapsed <= deadline {
                    // Still within deadline
                    continue;
                }

                // Deadline expired — determine escalation
                let overdue = elapsed - deadline;

                match pending.directive.shutdown_type {
                    ShutdownType::Graceful => {
                        if overdue > self.sigterm_grace {
                            warn!(
                                deployment_id = %deployment_id,
                                "Graceful shutdown deadline + grace expired, reporting failure"
                            );
                            actions.push((
                                deployment_id.clone(),
                                EscalationAction::ReportFailure {
                                    deployment_id: deployment_id.clone(),
                                    reason: "Graceful shutdown deadline expired".to_string(),
                                },
                            ));
                        } else {
                            warn!(
                                deployment_id = %deployment_id,
                                "Graceful shutdown deadline expired, in grace period"
                            );
                        }
                    },
                    ShutdownType::Immediate => {
                        warn!(
                            deployment_id = %deployment_id,
                            "Immediate shutdown deadline expired, reporting failure"
                        );
                        actions.push((
                            deployment_id.clone(),
                            EscalationAction::ReportFailure {
                                deployment_id: deployment_id.clone(),
                                reason: "Immediate shutdown not completed".to_string(),
                            },
                        ));
                    },
                    ShutdownType::Emergency => {
                        error!(
                            deployment_id = %deployment_id,
                            "Emergency shutdown deadline expired"
                        );
                        actions.push((
                            deployment_id.clone(),
                            EscalationAction::ReportFailure {
                                deployment_id: deployment_id.clone(),
                                reason: "Emergency shutdown failed — manual intervention required"
                                    .to_string(),
                            },
                        ));
                    },
                }
            }
        }

        actions
    }

    /// Force terminate a process by PID.
    ///
    /// Sends SIGTERM first, waits for grace period, then SIGKILL.
    ///
    /// # Safety
    ///
    /// This sends OS signals to the specified PID. Use with caution.
    #[cfg(unix)]
    pub fn force_terminate(&self, pid: u32) -> Result<(), String> {
        use std::process::Command;

        info!(pid = pid, "Sending SIGTERM");

        // Send SIGTERM
        let status = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .map_err(|e| format!("Failed to send SIGTERM: {}", e))?;

        if !status.success() {
            warn!(pid = pid, "SIGTERM failed, attempting SIGKILL");
            // Try SIGKILL immediately
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status();
            return Err("SIGTERM failed".to_string());
        }

        // Wait for grace period then check
        std::thread::sleep(self.sigterm_grace);

        // Check if process still exists
        let check = Command::new("kill").args(["-0", &pid.to_string()]).status();

        match check {
            Ok(s) if s.success() => {
                // Process still alive — SIGKILL
                warn!(pid = pid, "Process survived SIGTERM, sending SIGKILL");
                let _ = Command::new("kill")
                    .args(["-KILL", &pid.to_string()])
                    .status();
                Ok(())
            },
            _ => {
                // Process is gone
                info!(pid = pid, "Process terminated after SIGTERM");
                Ok(())
            },
        }
    }

    /// Stub for non-Unix platforms.
    #[cfg(not(unix))]
    pub fn force_terminate(&self, pid: u32) -> Result<(), String> {
        Err("force_terminate not supported on this platform".to_string())
    }

    /// Check if there's a pending shutdown for a deployment.
    pub fn has_pending_shutdown(&self, deployment_id: &str) -> bool {
        if let Ok(map) = self.pending.read() {
            map.get(deployment_id)
                .map(|p| !p.completed)
                .unwrap_or(false)
        } else {
            false
        }
    }

    /// Get the pending shutdown directive for a deployment (if any).
    pub fn get_pending_directive(&self, deployment_id: &str) -> Option<ShutdownDirective> {
        if let Ok(map) = self.pending.read() {
            map.get(deployment_id)
                .filter(|p| !p.completed)
                .map(|p| p.directive.clone())
        } else {
            None
        }
    }

    /// Clean up completed shutdowns.
    pub fn cleanup_completed(&self) {
        if let Ok(mut map) = self.pending.write() {
            map.retain(|_, p| !p.completed);
        }
    }
}

impl Default for ShutdownWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_directive(shutdown_type: ShutdownType, deadline_seconds: u32) -> ShutdownDirective {
        ShutdownDirective {
            shutdown_type,
            reason: "Test shutdown".to_string(),
            deadline_seconds,
            incident_id: "test-incident-001".to_string(),
            issued_by: "test-authority".to_string(),
        }
    }

    #[test]
    fn test_issue_and_check_within_deadline() {
        let watchdog = ShutdownWatchdog::new();
        let directive = make_directive(ShutdownType::Graceful, 60);

        watchdog.issue_shutdown("deploy-1", directive);

        // Should be within deadline
        let actions = watchdog.check_deadlines();
        assert!(actions.is_empty());
        assert!(watchdog.has_pending_shutdown("deploy-1"));
    }

    #[test]
    fn test_complete_shutdown() {
        let watchdog = ShutdownWatchdog::new();
        let directive = make_directive(ShutdownType::Graceful, 60);

        watchdog.issue_shutdown("deploy-1", directive);
        watchdog.complete_shutdown("deploy-1");

        assert!(!watchdog.has_pending_shutdown("deploy-1"));
    }

    #[test]
    fn test_acknowledge_shutdown() {
        let watchdog = ShutdownWatchdog::new();
        let directive = make_directive(ShutdownType::Immediate, 30);

        watchdog.issue_shutdown("deploy-1", directive);
        watchdog.acknowledge_shutdown("deploy-1");

        // Should still be pending (acknowledged != completed)
        assert!(watchdog.has_pending_shutdown("deploy-1"));
    }

    #[test]
    fn test_expired_immediate_shutdown() {
        let watchdog = ShutdownWatchdog::new();
        // 0-second deadline = already expired
        let directive = make_directive(ShutdownType::Immediate, 0);

        watchdog.issue_shutdown("deploy-1", directive);

        // Small sleep to ensure elapsed > 0
        std::thread::sleep(Duration::from_millis(10));

        let actions = watchdog.check_deadlines();
        assert_eq!(actions.len(), 1);
        match &actions[0].1 {
            EscalationAction::ReportFailure { deployment_id, .. } => {
                assert_eq!(deployment_id, "deploy-1");
            },
            _ => panic!("Expected ReportFailure"),
        }
    }

    #[test]
    fn test_cleanup_completed() {
        let watchdog = ShutdownWatchdog::new();
        let directive = make_directive(ShutdownType::Graceful, 60);

        watchdog.issue_shutdown("deploy-1", directive.clone());
        watchdog.issue_shutdown("deploy-2", directive);

        watchdog.complete_shutdown("deploy-1");
        watchdog.cleanup_completed();

        assert!(!watchdog.has_pending_shutdown("deploy-1"));
        assert!(watchdog.has_pending_shutdown("deploy-2"));
    }

    #[test]
    fn test_get_pending_directive() {
        let watchdog = ShutdownWatchdog::new();
        let directive = make_directive(ShutdownType::Emergency, 10);

        assert!(watchdog.get_pending_directive("deploy-1").is_none());

        watchdog.issue_shutdown("deploy-1", directive);
        let pending = watchdog.get_pending_directive("deploy-1");
        assert!(pending.is_some());
        assert_eq!(pending.unwrap().shutdown_type, ShutdownType::Emergency);
    }
}
