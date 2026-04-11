// Shared test setup: pre-loads the WASM module once for all test files.

import { init } from '../dist/index.js';
await init();
