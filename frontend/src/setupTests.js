// Loaded automatically by react-scripts test (CRA convention).
import '@testing-library/jest-dom';

// jsdom implements neither of these, and Ant Design 5 needs both: rc-select renders its dropdown
// through rc-virtual-list (ResizeObserver) and the responsive Grid reads matchMedia. Without the
// polyfills any test that opens a Select throws before it can assert anything.
if (!global.ResizeObserver) {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

if (!window.matchMedia) {
  window.matchMedia = (query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}
