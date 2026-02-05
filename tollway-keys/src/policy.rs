// policy.rs - Key policy enforcement

// KeyPolicy::default() → sensible defaults (1 year expiration, 10k usage limit)
// evaluate_policy(identity) → PolicyViolation or Ok
// policies: max_age (time-based), max_usage (operation count), manual_rotation_only
