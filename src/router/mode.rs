use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{RoutingConfig, RoutingProfileConfig, ScheduleConfig};
use crate::router::migration::Detector;
use crate::router::rules::build_detector;
use crate::terminal::state::CmdInfo;

pub(crate) struct ModeResolver {
    schedule: Option<ScheduleConfig>,
    profiles: HashMap<String, RoutingProfileConfig>,
    detectors: HashMap<String, Arc<dyn Detector>>,
}

impl ModeResolver {
    pub(crate) fn new(config: &RoutingConfig) -> Result<Self> {
        let mut profiles = HashMap::new();
        let mut detectors = HashMap::new();

        for profile in &config.profiles {
            if profiles
                .insert(profile.name.clone(), profile.clone())
                .is_some()
            {
                bail!("duplicate routing profile '{}'", profile.name);
            }

            let profile_routing = RoutingConfig {
                command: profile.command.clone(),
                ..RoutingConfig::default()
            };
            detectors.insert(profile.name.clone(), build_detector(&profile_routing)?);
        }

        if let Some(schedule) = &config.schedule {
            validate_schedule(schedule, &profiles)?;
        }

        Ok(Self {
            schedule: config.schedule.clone(),
            profiles,
            detectors,
        })
    }

    pub(crate) fn current_profile_name(&self) -> Option<String> {
        let schedule = self.schedule.as_ref().filter(|schedule| schedule.enabled)?;
        self.profile_name_at(unix_seconds(), schedule)
    }

    pub(crate) fn profile_name_at(
        &self,
        timestamp: i64,
        schedule: &ScheduleConfig,
    ) -> Option<String> {
        if schedule.sequence.is_empty() || schedule.interval_seconds == 0 {
            return None;
        }

        let local_timestamp = timestamp + schedule_offset_seconds(schedule);
        let slot = local_timestamp.div_euclid(schedule.interval_seconds as i64) as usize;
        schedule
            .sequence
            .get(slot % schedule.sequence.len())
            .cloned()
    }

    pub(crate) fn default_backend(&self, profile_name: &str) -> Option<&str> {
        self.profiles
            .get(profile_name)
            .map(|profile| profile.default_backend.as_str())
    }

    pub(crate) fn detect(
        &self,
        profile_name: &str,
        command: &CmdInfo,
        username: &str,
        password: &str,
    ) -> Option<String> {
        self.detectors
            .get(profile_name)?
            .detect(command, username, password)
    }
}

fn validate_schedule(
    schedule: &ScheduleConfig,
    profiles: &HashMap<String, RoutingProfileConfig>,
) -> Result<()> {
    if schedule.interval_seconds == 0 {
        bail!("schedule interval_seconds must be greater than zero");
    }
    if schedule.sequence.is_empty() {
        bail!("schedule sequence must not be empty");
    }
    if !matches!(schedule.timezone.as_str(), "UTC" | "Asia/Tokyo") {
        bail!(
            "unsupported schedule timezone '{}'; use UTC or Asia/Tokyo",
            schedule.timezone
        );
    }

    for profile_name in &schedule.sequence {
        profiles
            .get(profile_name)
            .with_context(|| format!("schedule references unknown profile '{profile_name}'"))?;
    }
    Ok(())
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn schedule_offset_seconds(schedule: &ScheduleConfig) -> i64 {
    match schedule.timezone.as_str() {
        "Asia/Tokyo" => 9 * 60 * 60,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, backend: &str) -> RoutingProfileConfig {
        RoutingProfileConfig {
            name: name.to_string(),
            default_backend: backend.to_string(),
            command: Vec::new(),
        }
    }

    #[test]
    fn resolves_profiles_from_fixed_epoch_slots() {
        let config = RoutingConfig {
            schedule: Some(ScheduleConfig {
                enabled: true,
                timezone: "UTC".to_string(),
                interval_seconds: 10,
                sequence: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            }),
            profiles: vec![
                profile("a", "cowrie"),
                profile("b", "beelzebub"),
                profile("c", "cowrie"),
            ],
            ..RoutingConfig::default()
        };
        let resolver = ModeResolver::new(&config).expect("resolver should build");
        let schedule = config.schedule.as_ref().unwrap();

        assert_eq!(resolver.profile_name_at(0, schedule), Some("a".to_string()));
        assert_eq!(
            resolver.profile_name_at(10, schedule),
            Some("b".to_string())
        );
        assert_eq!(
            resolver.profile_name_at(29, schedule),
            Some("c".to_string())
        );
        assert_eq!(
            resolver.profile_name_at(30, schedule),
            Some("a".to_string())
        );
    }

    #[test]
    fn applies_tokyo_offset_to_slot_boundaries() {
        let config = RoutingConfig {
            schedule: Some(ScheduleConfig {
                enabled: true,
                timezone: "Asia/Tokyo".to_string(),
                interval_seconds: 86_400,
                sequence: vec!["day-a".to_string(), "day-b".to_string()],
            }),
            profiles: vec![profile("day-a", "cowrie"), profile("day-b", "beelzebub")],
            ..RoutingConfig::default()
        };
        let resolver = ModeResolver::new(&config).expect("resolver should build");
        let schedule = config.schedule.as_ref().unwrap();

        assert_eq!(
            resolver.profile_name_at(0, schedule),
            Some("day-a".to_string())
        );
        assert_eq!(
            resolver.profile_name_at(15 * 60 * 60, schedule),
            Some("day-b".to_string())
        );
    }
}
