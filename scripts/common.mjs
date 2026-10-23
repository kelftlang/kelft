import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const sha256 = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export const json = value => Buffer.from(JSON.stringify(value, null, 2) + '\n');
export const readJSON = file => JSON.parse(fs.readFileSync(file, 'utf8'));
export function requireThat(condition, message) { if (!condition) throw Error(message); }
export function safeName(name) {
  requireThat(typeof name === 'string' && name.length > 0 && name.length <= 240 && /^[A-Za-z0-9._+/-]+$/.test(name) && !name.startsWith('/'), 'Unsafe path: ' + name);
  requireThat(!name.split('/').some(p => !p || p === '.' || p === '..' || /[. ]$/.test(p) || p.toLowerCase() === '.git' || /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p)), 'Unsafe path: ' + name);
  return name;
}
export function safeFile(directory, name) {
  safeName(name);
  let current = path.resolve(directory);
  requireThat(!fs.lstatSync(current).isSymbolicLink(), 'Symlink root: ' + current);
  for (const part of name.split('/')) {
    current = path.join(current, part);
    if (fs.existsSync(current)) requireThat(!fs.lstatSync(current).isSymbolicLink(), 'Symlink input: ' + name);
  }
  return current;
}
export function inventory(directory, {exclude = () => false} = {}) {
  const rows = [];
  function walk(prefix = '') {
    for (const item of fs.readdirSync(path.join(directory, prefix), {withFileTypes: true}).sort((a,b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const name = prefix + item.name;
      if (exclude(name, item.isDirectory())) continue;
      const file = safeFile(directory, name), stat = fs.lstatSync(file);
      if (stat.isDirectory()) walk(name + '/');
      else {
        requireThat(stat.isFile() && stat.size <= 256 * 1024 * 1024, 'Invalid file: ' + name);
        rows.push({path: name, bytes: stat.size, mode: stat.mode & 0o777, sha256: sha256(fs.readFileSync(file))});
      }
    }
  }
  walk();
  requireThat(rows.length <= 8192, 'Inventory exceeds 8192 files');
  return rows;
}
export function verifyInventory(directory, rows, {exact = true, exclude} = {}) {
  requireThat(Array.isArray(rows) && rows.length > 0 && rows.length <= 8192, 'Invalid inventory');
  const seen = new Set();
  for (const row of rows) {
    requireThat(!seen.has(row.path.toLowerCase()), 'Duplicate inventory path: ' + row.path); seen.add(row.path.toLowerCase());
    requireThat(/^sha256:[a-f0-9]{64}$/.test(row.sha256), 'Invalid file digest');
    const file = safeFile(directory, row.path), stat = fs.lstatSync(file);
    requireThat(stat.isFile() && stat.size === row.bytes && sha256(fs.readFileSync(file)) === row.sha256, 'Changed input: ' + row.path);
  }
  if (exact) requireThat(JSON.stringify(inventory(directory, {exclude}).map(r => r.path).sort()) === JSON.stringify(rows.map(r => r.path).sort()), 'Uninventoried or missing files');
}
export function hostTarget() {
  const platform = {win32: 'windows', darwin: 'macos', linux: 'linux'}[process.platform], arch = {x64: 'x86_64', arm64: 'arm64'}[process.arch];
  requireThat(platform && arch, 'Unsupported native host'); return platform + '-' + arch;
}
export function run(file, args, {cwd = root, env = process.env, timeout = 600000, expected = 0} = {}) {
  const result = spawnSync(file, args, {cwd, env, timeout, encoding: 'utf8', windowsHide: true, maxBuffer: 17 << 20});
  requireThat(expected === null ? result.status !== null : result.status === expected, path.basename(file) + ' failed: ' + (result.error?.message || result.stderr || result.stdout).slice(0, 3000));
  return result;
}
export function compilerEnvironment() {
  return {PATH: '', ...(process.platform === 'win32' ? {SystemRoot: process.env.SystemRoot, TEMP: process.env.TEMP, TMP: process.env.TMP} : {LC_ALL: 'C'})};
}
export function newDirectory(directory) {
  directory = path.resolve(directory);
  requireThat(!fs.existsSync(directory), 'Use a new output directory: ' + directory);
  let current = path.parse(directory).root;
  for (const part of path.relative(current, directory).split(path.sep)) {
    current = path.join(current, part);
    if (fs.existsSync(current)) requireThat(!fs.lstatSync(current).isSymbolicLink(), 'Symlink output ancestor: ' + current);
  }
  fs.mkdirSync(directory, {recursive: true}); return directory;
}
export function options(args, allowed) {
  const result = {};
  for (let i = 0; i < args.length; i += 2) {
    requireThat(allowed.includes(args[i]) && args[i + 1] && !Object.hasOwn(result, args[i].slice(2)), 'Unknown, duplicate, or missing option: ' + args[i]);
    result[args[i].slice(2)] = args[i + 1];
  }
  return result;
}
