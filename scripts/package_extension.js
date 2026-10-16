import fs from 'fs';
import path from 'path';
import JSZip from 'jszip';

async function packageExtension() {
  const zip = new JSZip();
  const extDir = path.join(process.cwd(), 'extension');
  const staticDir = path.join(process.cwd(), 'app', 'static');

  function addDirToZip(currentDir, relativePath = '') {
    const items = fs.readdirSync(currentDir);
    for (const item of items) {
      const fullPath = path.join(currentDir, item);
      const zipPath = relativePath ? `${relativePath}/${item}` : item;
      const stat = fs.statSync(fullPath);
      if (stat.isDirectory()) {
        addDirToZip(fullPath, zipPath);
      } else {
        zip.file(zipPath, fs.readFileSync(fullPath));
      }
    }
  }

  addDirToZip(extDir);

  const buffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
  const outPath = path.join(staticDir, 'url-guard-extension.zip');
  fs.writeFileSync(outPath, buffer);
  console.log(`[URL-Guard] Extension ZIP created at: ${outPath} (${(buffer.length / 1024).toFixed(1)} KB)`);
}

packageExtension().catch(err => {
  console.error('Failed to package extension:', err);
  process.exit(1);
});
