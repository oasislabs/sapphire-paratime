/** @type {import('@jest/types').Config.InitialOptions} */
const config = {
  coverageDirectory: 'coverage/jest',
  coveragePathIgnorePatterns: ['test/*'],
  coverageReporters: ['lcov', 'text', 'cobertura', 'html'],
  /*
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
    'src/networks.ts': {
      branches: 50
    }
  },
  */
  moduleFileExtensions: ['js', 'ts'],
  moduleNameMapper: {
    '^@oasisprotocol/sapphire-paratime$': '<rootDir>/src/index',
    '^@oasisprotocol/sapphire-paratime/(.*)\\.js$': '<rootDir>/src/$1',
    '^(\\..+)\\.js$': '$1',
  },
  testEnvironment: 'node',
  testRegex: 'test/.*\\.spec\\.ts$',
  transform: {
    '\\.ts$': 'ts-jest',
  },
};

export default config;
