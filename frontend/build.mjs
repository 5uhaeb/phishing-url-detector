import { cp, mkdir } from 'node:fs/promises';
await mkdir('dist', { recursive: true });
for (const file of ['index.html', 'app.js']) await cp(file, `dist/${file}`);
await cp('../static/style.css', 'dist/style.css');
