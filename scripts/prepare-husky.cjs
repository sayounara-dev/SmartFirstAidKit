const fs = require('fs');
const { spawnSync } = require('child_process');

const isWin = process.platform === 'win32';

if (!fs.existsSync('.git')) {
    console.log('[prepare-husky] .git directory not found, skipping hook install.');
    process.exit(0);
}

const gitCheck = spawnSync('git', ['--version'], {
    stdio: 'ignore',
    shell: isWin
});

if (gitCheck.status !== 0) {
    console.log('[prepare-husky] git is not available in PATH, skipping hook install.');
    process.exit(0);
}

const huskyInstall = spawnSync('npx', ['husky'], {
    stdio: 'inherit',
    shell: isWin
});

if (huskyInstall.status !== 0) {
    console.log('[prepare-husky] husky install command failed, continuing without hooks.');
}

process.exit(0);
