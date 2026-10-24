import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {root, readJSON, json, run, requireThat, compilerEnvironment, newDirectory, safeFile, options} from './common.mjs';
import {checkSource} from './check.mjs';

export function testLanguage(packageRoot, output, directory = root) {
  checkSource(directory); output = newDirectory(output);
  const project = path.join(output, 'project'); fs.mkdirSync(project);
  requireThat(!packageRoot.startsWith(project + path.sep) && !project.startsWith(packageRoot + path.sep), 'Test project must be separate from the installation');
  const manifest = readJSON(path.join(directory, '.publication.json'));
  for (const row of manifest.files.filter(row => /^(selfhost|stdlib|tests)\//.test(row.path) || row.path === 'examples/hello.kelft')) {
    const file = path.join(project, row.path); fs.mkdirSync(path.dirname(file), {recursive: true}); fs.copyFileSync(safeFile(directory, row.path), file);
  }
  const cli = path.join(packageRoot, 'bin/kelft' + (process.platform === 'win32' ? '.exe' : '')), reports = [];
  for (const [name, args] of [['compiler', ['tests/kelft/compiler.test.kelft']], ['conformance', ['--corpus', 'tests/conformance.json']]]) {
    const result = run(cli, ['test', ...args, '--project-root', project, '--json'], {cwd: project, env: compilerEnvironment(), expected: null});
    const report = JSON.parse(result.stdout); fs.writeFileSync(path.join(output, name + '.json'), json(report));
    requireThat(report.status === 'passed', name + ' language checks failed'); reports.push({name, totals: report.totals});
  }
  return {status: 'passed', reports, qualified: false};
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = options(process.argv.slice(2), ['--package', '--out']); console.log(JSON.stringify(testLanguage(path.resolve(args.package), path.resolve(args.out))));
}
