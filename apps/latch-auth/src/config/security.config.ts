// src/config/security.config.ts

/**
 * Centralized security configuration for retention and monitoring.
 * These values are used by session cleaner, event services,
 * and security-monitor.service.
 */
export const SecurityConfig = {
  // Used refresh tokens retention window (for reuse detection)
  REFRESH_TOKEN_RETENTION_DAYS: 14,

  // How long to keep event logs before archiving/deletion
  EVENT_LOG_RETENTION_DAYS: 90,

  // How often the SessionCleaner runs (in CRON format)
  CLEANUP_CRON_EXPRESSION: '0 * * * *', // every hour

  // Optional: threshold for anomaly detection (can be used in security-monitor.service)
  MAX_REUSE_ALERT_WINDOW_HOURS: 24,
};
