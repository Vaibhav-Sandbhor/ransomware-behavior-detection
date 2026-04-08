/**
 * Utility functions for formatting ISO timestamps to local time
 * All times are stored as UTC in backend and converted to local time for display
 */

/**
 * Format ISO timestamp to user-friendly local time string
 * @param {string} isoTimestamp - ISO format timestamp (e.g., "2026-04-08T10:30:00Z")
 * @param {string} locale - Locale string (default: "en-IN" for India)
 * @returns {string} Formatted time string
 */
export const formatDateTime = (isoTimestamp, locale = "en-IN") => {
  if (!isoTimestamp) return "N/A";

  try {
    const date = new Date(isoTimestamp);
    
    // Validate date
    if (isNaN(date.getTime())) {
      console.warn(`Invalid timestamp: ${isoTimestamp}`);
      return isoTimestamp;
    }

    return date.toLocaleString(locale, {
      dateStyle: "medium",
      timeStyle: "short",
    });
  } catch (error) {
    console.error(`Error formatting timestamp "${isoTimestamp}":`, error);
    return isoTimestamp;
  }
};

/**
 * Format ISO timestamp to time only (HH:MM AM/PM)
 * @param {string} isoTimestamp - ISO format timestamp
 * @param {string} locale - Locale string (default: "en-IN")
 * @returns {string} Time string
 */
export const formatTime = (isoTimestamp, locale = "en-IN") => {
  if (!isoTimestamp) return "N/A";

  try {
    const date = new Date(isoTimestamp);
    
    if (isNaN(date.getTime())) {
      return isoTimestamp;
    }
    
    return date.toLocaleTimeString(locale, {
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch (error) {
    console.error(`Error formatting time "${isoTimestamp}":`, error);
    return isoTimestamp;
  }
};

/**
 * Format duration in seconds to human-readable string
 * @param {number} seconds - Duration in seconds
 * @returns {string} Duration string (e.g., "1h 30m", "45m", "Active")
 */
export const formatDurationSeconds = (seconds) => {
  if (seconds === null || seconds === undefined || seconds < 0) {
    return "Active";
  }

  const totalMinutes = Math.floor(seconds / 60);
  const hours = Math.floor(totalMinutes / 60);
  const mins = totalMinutes % 60;

  if (hours > 0) {
    return `${hours}h ${mins}m`;
  }
  
  if (mins > 0) {
    return `${mins}m`;
  }
  
  return "< 1m";
};

/**
 * Format duration between two timestamps (ISO format)
 * @param {string} startTime - ISO format start timestamp
 * @param {string} endTime - ISO format end timestamp (null for active sessions)
 * @returns {string} Duration string (e.g., "1h 30m", "45m", "Active")
 */
export const formatDuration = (startTime, endTime) => {
  if (!startTime) return "Unknown";
  
  // For active sessions (no end time), show "Active"
  if (!endTime) return "Active";

  try {
    const startDate = new Date(startTime);
    const endDate = new Date(endTime);
    
    // Validate dates
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return "Invalid";
    }
    
    const diffMs = endDate - startDate;

    if (diffMs < 0) return "Invalid";

    const diffSeconds = Math.floor(diffMs / 1000);
    return formatDurationSeconds(diffSeconds);
  } catch (error) {
    console.error(
      `Error calculating duration between "${startTime}" and "${endTime}":`,
      error
    );
    return "Unknown";
  }
};

/**
 * Format ISO timestamp to date only (MMM DD, YYYY)
 * @param {string} isoTimestamp - ISO format timestamp
 * @param {string} locale - Locale string (default: "en-IN")
 * @returns {string} Date string
 */
export const formatDate = (isoTimestamp, locale = "en-IN") => {
  if (!isoTimestamp) return "N/A";

  try {
    const date = new Date(isoTimestamp);
    
    if (isNaN(date.getTime())) {
      return isoTimestamp;
    }
    
    return date.toLocaleDateString(locale, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch (error) {
    console.error(`Error formatting date "${isoTimestamp}":`, error);
    return isoTimestamp;
  }
};

/**
 * Format session display for sidebar (compact format)
 * @param {object} session - Session object with id, start_time, status
 * @returns {object} Formatted display object
 */
export const formatSessionDisplay = (session) => {
  if (!session) return null;

  const startDate = session.start_time ? new Date(session.start_time) : null;
  
  return {
    label: `Session #${session.id}`,
    date: startDate ? formatDate(session.start_time) : "Unknown",
    time: startDate ? formatTime(session.start_time) : "",
    status: session.status === "ACTIVE" ? "Active" : formatDurationSeconds(session.duration_seconds),
    isActive: session.status === "ACTIVE",
  };
};
