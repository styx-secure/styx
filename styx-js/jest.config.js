export default {
  transform: {},
  testMatch: ['**/test/**/*.test.js'],
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/**/index.js',
    '!src/storage/indexeddb-store.js',
    '!src/transport/webrtc-transport.js',
    '!src/storage/store-interface.js',
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 80,
      lines: 85,
      statements: 85,
    },
    './src/crypto/': {
      branches: 80,
      functions: 90,
      lines: 90,
      statements: 90,
    },
  },
};
