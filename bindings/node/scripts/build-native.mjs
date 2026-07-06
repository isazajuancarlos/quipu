// Builds libquipu_capi in release and copies it into prebuilds/<platform>-<arch>/.
//
// Optional cross-compilation (used to build darwin-x64 on an Apple-Silicon
// runner, since Intel macOS runners are scarce):
//   node build-native.mjs --target x86_64-apple-darwin --arch x64
// --target passes a Rust target triple to cargo; --arch overrides the folder
// arch label (defaults to the host process.arch). Run `rustup target add` first.
import { execFileSync } from 'node:child_process';
import { mkdirSync, copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');
const ext = process.platform === 'darwin' ? 'dylib' : process.platform === 'win32' ? 'dll' : 'so';
const libFile = process.platform === 'win32' ? `quipu_capi.${ext}` : `libquipu_capi.${ext}`;

const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
const rustTarget = flag('--target');           // e.g. x86_64-apple-darwin
const archLabel = flag('--arch') || process.arch; // folder label; host arch by default

const cargoArgs = ['build', '-p', 'quipu-capi', '--release'];
if (rustTarget) cargoArgs.push('--target', rustTarget);
execFileSync('cargo', cargoArgs, { cwd: repoRoot, stdio: 'inherit' });

// Cross builds land in target/<triple>/release/ instead of target/release/.
const releaseDir = rustTarget ? join('target', rustTarget, 'release') : join('target', 'release');
const src = join(repoRoot, releaseDir, libFile);
const destDir = join(here, '..', 'prebuilds', `${process.platform}-${archLabel}`);
mkdirSync(destDir, { recursive: true });
copyFileSync(src, join(destDir, libFile));
console.log(`copied ${libFile} -> ${destDir}`);
