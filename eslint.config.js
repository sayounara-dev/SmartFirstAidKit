const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
    {
        ignores: [
            'node_modules/**',
            'coverage/**',
            '.husky/**',
            'server/.env',
            'js/auth.js',
            'js/background-simple.js',
            'js/medicine-safety.js',
            'js/meds-database.js',
            'js/medsdatabase.js',
            'js/ocr.js',
            'js/script.js'
        ]
    },
    js.configs.recommended,
    {
        files: ['js/**/*.js'],
        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'script',
            globals: {
                ...globals.browser,
                ...globals.es2021,
                ymaps: 'readonly',
                Tesseract: 'readonly'
            }
        },
        rules: {
            'no-console': 'off',
            'preserve-caught-error': 'off',
            'no-redeclare': 'off',
            'no-undef': 'off',
            'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }]
        }
    },
    {
        files: ['server/**/*.js', 'scripts/**/*.cjs', '*.js'],
        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'commonjs',
            globals: {
                ...globals.node,
                ...globals.es2021
            }
        },
        rules: {
            'no-console': 'off',
            'preserve-caught-error': 'off',
            'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }]
        }
    },
    {
        files: ['tests/**/*.mjs', 'vitest.config.mjs'],
        languageOptions: {
            ecmaVersion: 'latest',
            sourceType: 'module',
            globals: {
                ...globals.node,
                ...globals.es2021
            }
        }
    }
];
