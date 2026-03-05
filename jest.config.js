module.exports = {
  testEnvironment: 'node',
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
};
