module.exports = {
  testEnvironment: 'node',
  // Exclude Miniflare integration tests from default run (use npm run test:integration)
  testPathIgnorePatterns: ['/node_modules/', 'worker\\.integration\\.test\\.js'],
  // Transform ESM modules in src/api/ to CJS so Jest can load them
  transform: {
    '(src/api/.+\\.js$|node_modules/hono/.+\\.js$)': [
      'babel-jest',
      {
        plugins: ['@babel/plugin-transform-modules-commonjs'],
      },
    ],
  },
  // Transform src/api and hono (ESM packages) to CJS for Jest
  transformIgnorePatterns: ['/node_modules/(?!hono/)'],
  // Coverage configuration
  collectCoverageFrom: [
    'src/api/**/*.js',
    '!src/api/worker.js',
    '!src/api/handlers/docs.js',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'text-summary', 'json-summary', 'lcov'],
};
