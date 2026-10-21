// Run BEFORE deploying: Vercel reads routing configuration before the build.
import { writeFile } from 'node:fs/promises';
const raw = process.env.BACKEND_URL;
if (!raw) throw new Error('Set BACKEND_URL to the deployed Render HTTPS URL.');
const backend = new URL(raw);
if (backend.protocol !== 'https:' || backend.username || backend.password || backend.pathname !== '/' || backend.search || backend.hash) {
  throw new Error('BACKEND_URL must be a plain HTTPS origin.');
}
await writeFile('vercel.json', JSON.stringify({
  buildCommand: 'node build.mjs', outputDirectory: 'dist',
  rewrites: [{ source: '/api/:path*', destination: `${backend.origin}/api/:path*` }],
  headers: [{ source: '/(.*)', headers: [
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'Referrer-Policy', value: 'same-origin' },
    { key: 'X-Frame-Options', value: 'DENY' },
    { key: 'Cache-Control', value: 'no-store' },
    { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" },
  ] }],
}, null, 2) + '\n');
console.log('Vercel routing configured for', backend.origin);
