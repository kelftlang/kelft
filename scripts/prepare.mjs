// Explicit online preparation; build.mjs never fetches Cargo dependencies.
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {root, options, run, requireThat, hostTarget} from './common.mjs';
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = options(process.argv.slice(2), ['--cargo']);
  requireThat(args.cargo && path.isAbsolute(args.cargo), 'Supply the absolute Cargo executable from Rust 1.99.0');
  const target = hostTarget(), triple = (target.endsWith('arm64') ? 'aarch64' : 'x86_64') + (target.startsWith('windows') ? '-pc-windows-msvc' : target.startsWith('macos') ? '-apple-darwin' : '-unknown-linux-gnu');
  requireThat(run(args.cargo, ['--version']).stdout.startsWith('cargo 1.99.0 '), 'Pinned Cargo 1.99.0 required');
  run(args.cargo, ['fetch', '--locked', '--manifest-path', path.join(root, 'host/driver/Cargo.toml'), '--target', triple]);
  console.log(JSON.stringify({status: 'prepared', target, note: 'Prepare the documented platform SDK and linker separately.'}));
}
