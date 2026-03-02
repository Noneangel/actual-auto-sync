import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  enforceReadOnlyRootFilesystem,
  isContainerRootFilesystemReadOnly,
  isRootFilesystemReadOnly,
  shouldEnforceReadOnlyRootFilesystem,
} from '../container-security.js';

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
}));

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(),
}));

const ROOT_RW_MOUNTINFO = '36 28 0:32 / / rw,relatime - overlay overlay rw,lowerdir=/foo';
const ROOT_RO_MOUNTINFO = '36 28 0:32 / / ro,relatime - overlay overlay rw,lowerdir=/foo';

describe('container-security', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('isRootFilesystemReadOnly', () => {
    it('returns true when root mount has ro option', () => {
      expect(isRootFilesystemReadOnly(ROOT_RO_MOUNTINFO)).toBe(true);
    });

    it('returns false when root mount is rw', () => {
      expect(isRootFilesystemReadOnly(ROOT_RW_MOUNTINFO)).toBe(false);
    });

    it('throws when root mount entry is missing', () => {
      expect(() => isRootFilesystemReadOnly('11 22 0:99 /tmp /tmp rw - tmpfs tmpfs rw')).toThrow(
        'Unable to locate root mount entry in /proc/self/mountinfo',
      );
    });
  });

  describe('enforceReadOnlyRootFilesystem', () => {
    it('skips validation outside containers', async () => {
      vi.mocked(existsSync).mockReturnValue(false);

      await expect(enforceReadOnlyRootFilesystem()).resolves.toBeUndefined();
      expect(readFile).not.toHaveBeenCalled();
    });

    it('passes when container root filesystem is read-only', async () => {
      vi.mocked(existsSync).mockReturnValue(true);
      vi.mocked(readFile).mockResolvedValue(ROOT_RO_MOUNTINFO);

      await expect(enforceReadOnlyRootFilesystem()).resolves.toBeUndefined();
    });

    it('fails when container root filesystem is writable', async () => {
      vi.mocked(existsSync).mockReturnValue(true);
      vi.mocked(readFile).mockResolvedValue(ROOT_RW_MOUNTINFO);

      await expect(enforceReadOnlyRootFilesystem()).rejects.toThrow(
        'Container root filesystem is writable.',
      );
    });
  });

  describe('isContainerRootFilesystemReadOnly', () => {
    it('returns non-container state outside containers', async () => {
      vi.mocked(existsSync).mockReturnValue(false);

      await expect(isContainerRootFilesystemReadOnly()).resolves.toEqual({
        isContainer: false,
        isReadOnly: true,
      });
    });

    it('returns container read-only state', async () => {
      vi.mocked(existsSync).mockReturnValue(true);
      vi.mocked(readFile).mockResolvedValue(ROOT_RO_MOUNTINFO);

      await expect(isContainerRootFilesystemReadOnly()).resolves.toEqual({
        isContainer: true,
        isReadOnly: true,
      });
    });
  });

  describe('shouldEnforceReadOnlyRootFilesystem', () => {
    it('treats true-like values as enabled', () => {
      expect(shouldEnforceReadOnlyRootFilesystem('true')).toBe(true);
      expect(shouldEnforceReadOnlyRootFilesystem('1')).toBe(true);
      expect(shouldEnforceReadOnlyRootFilesystem('yes')).toBe(true);
      expect(shouldEnforceReadOnlyRootFilesystem('on')).toBe(true);
    });

    it('defaults to disabled for false-like and missing values', () => {
      expect(shouldEnforceReadOnlyRootFilesystem(undefined)).toBe(false);
      expect(shouldEnforceReadOnlyRootFilesystem('false')).toBe(false);
      expect(shouldEnforceReadOnlyRootFilesystem('0')).toBe(false);
      expect(shouldEnforceReadOnlyRootFilesystem('off')).toBe(false);
    });
  });
});
