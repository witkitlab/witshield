import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

afterEach(() => cleanup());

Object.defineProperty(globalThis.navigator, 'clipboard', {
  configurable: true,
  value: { writeText: async () => undefined },
});
