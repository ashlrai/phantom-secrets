export const DEVICE_USER_CODE_LENGTH = 8;

export function normalizeDeviceUserCode(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
}

export function formatDeviceUserCode(value: string): string {
  const normalized = normalizeDeviceUserCode(value).slice(0, DEVICE_USER_CODE_LENGTH);
  if (normalized.length <= 4) {
    return normalized;
  }
  return `${normalized.slice(0, 4)}-${normalized.slice(4)}`;
}

export function isValidDeviceUserCode(value: string): boolean {
  return normalizeDeviceUserCode(value).length === DEVICE_USER_CODE_LENGTH;
}
