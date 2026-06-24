use crate::{
    config::{AppConfig, RuntimeConfig},
    BoxError,
};

const NOFILE_BASE_RESERVE: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeLimitStatus {
    pub soft: u64,
    pub hard: u64,
    pub target: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NofilePlan {
    Disabled,
    AlreadyMeets { soft: u64, hard: u64 },
    Raise { target: u64 },
    CannotMeet { target: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NofileCapacityEstimate {
    pub required: u64,
    pub soft_limit: u64,
    pub reserve: u64,
    pub listeners: u64,
    pub http_downstream: u64,
    pub http_upstream_in_flight: u64,
    pub http_upstream_idle_pool: u64,
    pub tcp_downstream: u64,
    pub tcp_upstream: u64,
}

pub fn apply_runtime_limits(cfg: &RuntimeConfig) -> Result<Option<RuntimeLimitStatus>, BoxError> {
    if cfg.min_nofile == 0 {
        return Ok(None);
    }
    apply_nofile_floor(cfg.min_nofile).map(Some)
}

pub fn validate_nofile_capacity(
    cfg: &AppConfig,
    status: Option<&RuntimeLimitStatus>,
) -> Result<Option<NofileCapacityEstimate>, BoxError> {
    if cfg.runtime.min_nofile == 0 {
        return Ok(None);
    }
    validate_capacity_inputs(cfg)?;
    let soft_limit = status.map_or(cfg.runtime.min_nofile, |status| status.soft);
    let estimate = estimate_nofile_capacity(cfg, soft_limit);
    if estimate.required > estimate.soft_limit {
        return Err(format!(
            "runtime.min_nofile capacity check failed: configured connection caps require at least {} file descriptors, but the process soft RLIMIT_NOFILE is {}. Breakdown: reserve={}, listeners={}, http_downstream={}, http_upstream_in_flight={}, http_upstream_idle_pool={}, tcp_downstream={}, tcp_upstream={}. Increase runtime.min_nofile and the service hard limit, or lower HTTP/TCP connection caps.",
            estimate.required,
            estimate.soft_limit,
            estimate.reserve,
            estimate.listeners,
            estimate.http_downstream,
            estimate.http_upstream_in_flight,
            estimate.http_upstream_idle_pool,
            estimate.tcp_downstream,
            estimate.tcp_upstream,
        )
        .into());
    }
    Ok(Some(estimate))
}

fn validate_capacity_inputs(cfg: &AppConfig) -> Result<(), BoxError> {
    if let Some(http) = &cfg.http {
        if http.limits.max_connections == 0 {
            return Err(
                "runtime.min_nofile capacity check requires finite http.limits.max_connections"
                    .into(),
            );
        }
    }
    for tcp in &cfg.tcp {
        if tcp.limits.max_connections == 0 {
            return Err(format!(
                "runtime.min_nofile capacity check requires finite tcp[{}].limits.max_connections",
                tcp.name
            )
            .into());
        }
    }
    Ok(())
}

fn estimate_nofile_capacity(cfg: &AppConfig, soft_limit: u64) -> NofileCapacityEstimate {
    let reserve = NOFILE_BASE_RESERVE;
    let http_listeners = cfg
        .http
        .as_ref()
        .map_or(0, |http| listener_fd_count(http.accept_shards));
    let tcp_listeners = cfg.tcp.iter().fold(0_u64, |total, tcp| {
        total.saturating_add(listener_fd_count(tcp.accept_shards))
    });
    let listeners = http_listeners.saturating_add(tcp_listeners);
    let mut estimate = NofileCapacityEstimate {
        required: reserve.saturating_add(listeners),
        soft_limit,
        reserve,
        listeners,
        http_downstream: 0,
        http_upstream_in_flight: 0,
        http_upstream_idle_pool: 0,
        tcp_downstream: 0,
        tcp_upstream: 0,
    };

    if let Some(http) = &cfg.http {
        estimate.http_downstream = usize_to_u64(http.limits.max_connections);
        estimate.http_upstream_in_flight = if http.limits.max_in_flight_requests == 0 {
            estimate.http_downstream
        } else {
            usize_to_u64(http.limits.max_in_flight_requests)
        };
        estimate.http_upstream_idle_pool = usize_to_u64(http.upstream_pool_max_idle_per_host);
    }

    for tcp in &cfg.tcp {
        let active = usize_to_u64(tcp.limits.max_connections);
        estimate.tcp_downstream = estimate.tcp_downstream.saturating_add(active);
        estimate.tcp_upstream = estimate.tcp_upstream.saturating_add(active);
    }

    estimate.required = estimate
        .required
        .saturating_add(estimate.http_downstream)
        .saturating_add(estimate.http_upstream_in_flight)
        .saturating_add(estimate.http_upstream_idle_pool)
        .saturating_add(estimate.tcp_downstream)
        .saturating_add(estimate.tcp_upstream);
    estimate
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn listener_fd_count(accept_shards: usize) -> u64 {
    usize_to_u64(accept_shards.max(1))
}

#[cfg(unix)]
fn apply_nofile_floor(min_nofile: u64) -> Result<RuntimeLimitStatus, BoxError> {
    let current = get_nofile_limit()?;
    match plan_nofile(current.soft, current.hard, min_nofile) {
        NofilePlan::Disabled => Ok(RuntimeLimitStatus {
            soft: current.soft,
            hard: current.hard,
            target: current.soft,
            changed: false,
        }),
        NofilePlan::AlreadyMeets { soft, hard } => Ok(RuntimeLimitStatus {
            soft,
            hard,
            target: soft,
            changed: false,
        }),
        NofilePlan::Raise { target } | NofilePlan::CannotMeet { target } => {
            set_nofile_soft_limit(target).map_err(|err| {
                format!(
                    "failed to raise RLIMIT_NOFILE soft limit to {target}; set systemd LimitNOFILE or shell ulimit first: {err}"
                )
            })?;
            let updated = get_nofile_limit()?;
            if updated.soft < min_nofile {
                return Err(format!(
                    "RLIMIT_NOFILE soft limit is {}, below configured runtime.min_nofile {}; hard limit is {}. Increase systemd LimitNOFILE or shell ulimit.",
                    updated.soft, min_nofile, updated.hard
                )
                .into());
            }
            Ok(RuntimeLimitStatus {
                soft: updated.soft,
                hard: updated.hard,
                target,
                changed: updated.soft != current.soft,
            })
        }
    }
}

#[cfg(not(unix))]
fn apply_nofile_floor(min_nofile: u64) -> Result<RuntimeLimitStatus, BoxError> {
    Err(format!("runtime.min_nofile={min_nofile} is only supported on Unix-like platforms").into())
}

#[cfg(unix)]
fn get_nofile_limit() -> Result<RuntimeLimitStatus, BoxError> {
    let mut raw = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut raw) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let soft = rlim_to_u64(raw.rlim_cur);
    let hard = rlim_to_u64(raw.rlim_max);
    Ok(RuntimeLimitStatus {
        soft,
        hard,
        target: soft,
        changed: false,
    })
}

#[cfg(unix)]
fn set_nofile_soft_limit(target: u64) -> std::io::Result<()> {
    let mut raw = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let get_rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut raw) };
    if get_rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    raw.rlim_cur = u64_to_rlim(target);
    let set_rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw) };
    if set_rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn plan_nofile(soft: u64, hard: u64, min_nofile: u64) -> NofilePlan {
    if min_nofile == 0 {
        return NofilePlan::Disabled;
    }
    if soft >= min_nofile {
        return NofilePlan::AlreadyMeets { soft, hard };
    }
    if hard >= min_nofile {
        return NofilePlan::Raise { target: min_nofile };
    }
    NofilePlan::CannotMeet { target: hard }
}

#[cfg(unix)]
fn rlim_to_u64(value: libc::rlim_t) -> u64 {
    if value == libc::RLIM_INFINITY {
        u64::MAX
    } else {
        value
    }
}

#[cfg(unix)]
fn u64_to_rlim(value: u64) -> libc::rlim_t {
    if value == u64::MAX {
        libc::RLIM_INFINITY
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{
        estimate_nofile_capacity, plan_nofile, validate_nofile_capacity, NofilePlan,
        RuntimeLimitStatus,
    };
    use crate::config::AppConfig;

    #[test]
    fn nofile_plan_is_disabled_at_zero() {
        assert_eq!(plan_nofile(128, 256, 0), NofilePlan::Disabled);
    }

    #[test]
    fn nofile_plan_accepts_sufficient_soft_limit() {
        assert_eq!(
            plan_nofile(65_536, 65_536, 32_768),
            NofilePlan::AlreadyMeets {
                soft: 65_536,
                hard: 65_536
            }
        );
    }

    #[test]
    fn nofile_plan_raises_soft_to_requested_floor() {
        assert_eq!(
            plan_nofile(1_024, 65_536, 32_768),
            NofilePlan::Raise { target: 32_768 }
        );
    }

    #[test]
    fn nofile_plan_reports_hard_limit_blocker() {
        assert_eq!(
            plan_nofile(1_024, 4_096, 32_768),
            NofilePlan::CannotMeet { target: 4_096 }
        );
    }

    #[test]
    fn nofile_capacity_estimate_counts_proxy_socket_budget() {
        let cfg = capacity_test_config();
        let estimate = estimate_nofile_capacity(&cfg, 1_024);

        assert_eq!(estimate.reserve, 256);
        assert_eq!(estimate.listeners, 5);
        assert_eq!(estimate.http_downstream, 100);
        assert_eq!(estimate.http_upstream_in_flight, 80);
        assert_eq!(estimate.http_upstream_idle_pool, 5);
        assert_eq!(estimate.tcp_downstream, 25);
        assert_eq!(estimate.tcp_upstream, 25);
        assert_eq!(estimate.required, 496);
    }

    #[test]
    fn nofile_capacity_estimate_normalizes_zero_accept_shards_to_one_listener() {
        let mut cfg = capacity_test_config();
        cfg.http.as_mut().unwrap().accept_shards = 0;
        cfg.tcp[0].accept_shards = 0;
        let estimate = estimate_nofile_capacity(&cfg, 1_024);

        assert_eq!(estimate.listeners, 2);
        assert_eq!(estimate.required, 493);
    }

    #[test]
    fn nofile_capacity_validation_accepts_sufficient_soft_limit() {
        let cfg = capacity_test_config();
        let status = limit_status(496);

        let estimate = validate_nofile_capacity(&cfg, Some(&status))
            .unwrap()
            .unwrap();

        assert_eq!(estimate.required, 496);
        assert_eq!(estimate.soft_limit, 496);
    }

    #[test]
    fn nofile_capacity_validation_rejects_undersized_soft_limit() {
        let cfg = capacity_test_config();
        let status = limit_status(495);

        let err = validate_nofile_capacity(&cfg, Some(&status))
            .unwrap_err()
            .to_string();

        assert!(err.contains("require at least 496 file descriptors"));
        assert!(err.contains("soft RLIMIT_NOFILE is 495"));
    }

    #[test]
    fn nofile_capacity_validation_is_disabled_without_runtime_floor() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{
                "http": {
                    "listen": "127.0.0.1:0",
                    "upstream": "http://127.0.0.1:1",
                    "limits": {"max_connections": 0}
                }
            }"#,
        )
        .unwrap();

        assert!(validate_nofile_capacity(&cfg, None).unwrap().is_none());
    }

    #[test]
    fn nofile_capacity_validation_rejects_unbounded_connection_caps() {
        let cfg: AppConfig = serde_json::from_str(
            r#"{
                "runtime": {"min_nofile": 1024},
                "http": {
                    "listen": "127.0.0.1:0",
                    "upstream": "http://127.0.0.1:1",
                    "limits": {"max_connections": 0}
                }
            }"#,
        )
        .unwrap();
        let status = limit_status(1_024);

        let err = validate_nofile_capacity(&cfg, Some(&status))
            .unwrap_err()
            .to_string();

        assert!(err.contains("finite http.limits.max_connections"));
    }

    fn capacity_test_config() -> AppConfig {
        serde_json::from_str(
            r#"{
                "runtime": {"min_nofile": 1024},
                "http": {
                    "listen": "127.0.0.1:0",
                    "upstream": "http://127.0.0.1:1",
                    "upstream_pool_max_idle_per_host": 5,
                    "accept_shards": 3,
                    "limits": {
                        "max_connections": 100,
                        "max_in_flight_requests": 80
                    }
                },
                "tcp": [{
                    "name": "raw",
                    "listen": "127.0.0.1:0",
                    "upstream": "127.0.0.1:1",
                    "accept_shards": 2,
                    "limits": {"max_connections": 25}
                }]
            }"#,
        )
        .unwrap()
    }

    fn limit_status(soft: u64) -> RuntimeLimitStatus {
        RuntimeLimitStatus {
            soft,
            hard: soft,
            target: soft,
            changed: false,
        }
    }
}
