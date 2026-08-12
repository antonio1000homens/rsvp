import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { build } from 'esbuild';

const root = new URL('../', import.meta.url);
const output = new URL('../dist/frontend/', import.meta.url);
await mkdir(output, { recursive: true });

const bundle = async (entry, extension, loader) => {
  const result = await build({
    entryPoints: [new URL(entry, root).pathname],
    bundle: true,
    minify: true,
    write: false,
    loader,
  });
  const contents = result.outputFiles[0].contents;
  const hash = createHash('sha256').update(contents).digest('hex').slice(0, 12);
  const name = `app.${hash}.${extension}`;
  await writeFile(new URL(name, output), contents);
  return name;
};

const jsName = await bundle('frontend/src/main.js', 'js');
const cssName = await bundle('frontend/src/styles.css', 'css', { '.css': 'css' });
const template = await readFile(new URL('frontend/index.html', root), 'utf8');
const html = template.replace('__APP_JS__', jsName).replace('__APP_CSS__', cssName);
await writeFile(new URL('index.html', output), html);
await copyFile(new URL('frontend/favicon.svg', root), new URL('favicon.svg', output));
