export type EffectivePlan = "free" | "pro";

export type StoredPlan = {
  plan?: unknown;
  plan_expires_at?: unknown;
};

// Require an explicit timezone so entitlement decisions never depend on the
// server's locale. Date.parse then rejects invalid offsets and non-dates.
const TIMESTAMP_WITH_TIMEZONE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function isCalendarTimestamp(match: RegExpExecArray): boolean {
  const [, yearText, monthText, dayText, hourText, minuteText, secondText] =
    match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const daysInMonth = [
    31,
    leapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];

  return (
    month >= 1 &&
    month <= 12 &&
    day >= 1 &&
    day <= daysInMonth[month - 1] &&
    hour <= 23 &&
    minute <= 59 &&
    second <= 59
  );
}

/**
 * Convert legacy database plan fields into the only plans the application may
 * authorize. Anything incomplete, unknown, malformed, or expired is free.
 */
export function effectivePlan(
  stored: StoredPlan,
  nowMs: number = Date.now(),
): EffectivePlan {
  if (stored.plan !== "pro") return "free";
  if (typeof stored.plan_expires_at !== "string") return "free";
  const timestampMatch = TIMESTAMP_WITH_TIMEZONE.exec(stored.plan_expires_at);
  if (!timestampMatch || !isCalendarTimestamp(timestampMatch)) return "free";

  const expiresAt = Date.parse(stored.plan_expires_at);
  if (!Number.isFinite(expiresAt) || !Number.isFinite(nowMs)) return "free";

  return expiresAt > nowMs ? "pro" : "free";
}
