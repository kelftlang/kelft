import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {pathToFileURL} from 'node:url';
import {readJSON, json, sha256, requireThat, inventory, run, compilerEnvironment, options} from './common.mjs';

export function smoke(packageRoot, output) {
  const suffix = process.platform === 'win32' ? '.exe' : '', cli = path.join(packageRoot, 'bin/kelft' + suffix), env = compilerEnvironment(), project = fs.mkdtempSync(path.join(os.tmpdir(), 'kelft-public-'));
  const report = {schema: 'kelft.alpha-smoke/1', status: 'running', coordinatorSHA256: sha256(fs.readFileSync(cli)), checks: [], qualified: false, releaseEligible: false};
  const check = (name, args, expected = 0) => {const result = run(cli, args, {cwd: project, env, expected}); report.checks.push(name); return result;};
  try {
    check('help', ['--help']); check('version', ['version']);
    requireThat(JSON.parse(check('doctor', ['doctor', '--json']).stdout).status === 'success', 'Doctor failed');
    fs.writeFileSync(path.join(project, 'hello.kelft'), 'fn main()->i32 {println("Hello, Kelft!");return 42;}\n');
    check('check', ['check', 'hello.kelft', '--json']);
    fs.writeFileSync(path.join(project, 'bad.kelft'), 'fn main()->void {let x:i32="wrong";}\n');
    check('rejected-check', ['check', 'bad.kelft', '--json'], 1);
    check('invalid-arguments', ['check', 'hello.kelft', '--unknown'], 64);
    check('build', ['build', 'hello.kelft', '-o', path.join(project, 'hello' + suffix)]);
    requireThat(check('execute', ['run', 'hello.kelft', '--project-root', project], 42).stdout === 'Hello, Kelft!\n', 'Hello World differs');
    const tampered = path.join(project, 'tampered-package'); fs.cpSync(packageRoot, tampered, {recursive: true});
    const compiler = path.join(tampered, 'rootfs/compiler' + suffix), changed = fs.readFileSync(compiler); changed[0] ^= 1;
    fs.chmodSync(compiler, 0o644); fs.writeFileSync(compiler, changed);
    run(path.join(tampered, 'bin/kelft' + suffix), ['doctor', '--json'], {cwd: project, env, expected: 1}); report.checks.push('tampered-compiler');
    report.status = 'passed'; return report;
  } catch (error) {report.status = 'failed'; report.error = error.message; throw error;}
  finally {fs.writeFileSync(output, json(report)); fs.rmSync(project, {recursive: true});}
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = options(process.argv.slice(2), ['--package', '--out']); console.log(JSON.stringify(smoke(path.resolve(args.package), path.resolve(args.out))));
}
