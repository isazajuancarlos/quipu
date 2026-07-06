// Builds libquipu_capi in release and copies it into prebuilds/<platform>-<arch>/.
import { execFileSync } from 'node:child_process';
import { mkdirSync, copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');
const ext = process.platform === 'darwin' ? 'dylib' : process.platform === 'win32' ? 'dll' : 'so';
const libFile = process.platform === 'win32' ? `quipu_capi.${ext}` : `libquipu_capi.${ext}`;

execFileSync('cargo', ['build', '-p', 'quipu-capi', '--release'], { cwd: repoRoot, stdio: 'inherit' });

const src = join(repoRoot, 'target', 'release', libFile);
const destDir = join(here, '..', 'prebuilds', `${process.platform}-${process.arch}`);
mkdirSync(destDir, { recursive: true });
copyFileSync(src, join(destDir, libFile));
console.log(`copied ${libFile} -> ${destDir}`);
