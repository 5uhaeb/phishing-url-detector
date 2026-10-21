# GitHub, Render and Vercel

## Project deployment

- Frontend: https://phishing-url-detector-xi.vercel.app
- Backend: https://linkguard-api-5m93.onrender.com
- Health: https://linkguard-api-5m93.onrender.com/health
- GitHub: https://github.com/5uhaeb/phishing-url-detector (private)

The committed `frontend/vercel.json` forwards `/api/*` to this Render service.
The Render frontend-origin allowlist includes the production frontend above.
Render deploys are manual so documentation and frontend-only pushes do not
retrain the backend. After backend changes, deploy the latest commit from
Render and verify `/health` and a prediction from the Vercel frontend.

The repository root is the Python backend. Set the Vercel project root to
`frontend`, enable access to files outside that directory, and use the static
output directory `dist`. The frontend has no runtime npm dependencies.

## Backend on Render

Create a Blueprint from `render.yaml`. It uses the free plan, installs Python
dependencies, and trains the same full mixed-source model during the build.
The model and raw datasets stay outside Git. Training can take several minutes
and needs substantially more memory than inference. Hosting capacity and
build success still need verification on the actual account.

The build also runs `prepare_runtime.py` and downloads the initial public feed
snapshots. The runtime copy keeps the exact trained parameters and scores,
omits evaluation-only domain hashes, and stores uncompressed arrays for
memory-mapped loading. The full research artifact remains available for
independent-domain evaluation. `MODEL_PATH=runtime-model.joblib` and
`MODEL_MMAP=1` select this copy on Render. Resource limits still need a live
startup check; local Windows memory figures do not establish Linux usage.

Set `FRONTEND_ORIGINS` to the exact Vercel production origin, for example
`https://linkguard-example.vercel.app`. Multiple explicitly trusted origins
can be comma-separated. Never use a wildcard for preview deployments.
Render's external hostname is added to trusted hosts automatically.
The server listens on `0.0.0.0:$PORT` and `/health` returns 200 only when
the trained model is loaded. Public feeds refresh in a background thread.
Missing feeds are reported as unavailable until downloaded; a missing match
is never treated as proof of safety.

Optional: `WEB_RISK_API_KEY` enables consent-gated Google Web Risk lookups.
It belongs only on the backend. The default rate limiter uses single-process
memory; configure `RATELIMIT_STORAGE_URI` with Redis before scaling instances.

## Frontend on Vercel

After Render provides its URL, generate routing configuration **before**
Vercel reads the source. In PowerShell:

```powershell
cd frontend
$env:BACKEND_URL = 'https://your-actual-service.onrender.com'
node configure-vercel.mjs
npm ci
npm run check
npm run build
```

Commit the generated `frontend/vercel.json` before a Git-based deployment,
or deploy this directory using Vercel CLI after configuration. The script
generates exact `/api/*` rewrites to the backend and security headers.
Run it again if the backend URL changes. The build command is
`node build.mjs`; routing is deliberately configured before the build.

After the frontend URL is known, update Render's `FRONTEND_ORIGINS` and
redeploy the backend. The browser submits to its own `/api/predict` route;
Vercel proxies that request to Render. Flask permits that request only for
the configured frontend origin. Verify this behavior against the deployed
proxy, including host/origin headers, before considering launch complete.

## Local verification

Run the backend tests after training:

```powershell
.\.venv\Scripts\python.exe -m unittest -v
cd frontend
npm ci
npm run check
npm run build
npm test
```

The browser suite uses installed Google Chrome and starts an isolated local
server with the real Python model. It checks 320, 375, 768 and 1440 pixel
widths, WCAG A/AA rules via axe, analysis, JSON downloads, request failures,
clearing pending requests and safe rendering of untrusted URL text.
Set `LINKGUARD_PYTHON` if the virtual environment lives elsewhere.
The test preview server is local only and is not a production start command.

## Launch verification

- Confirm Render `/health` is ready and `/api/status` matches the model and feeds.
- Submit a known ordinary URL from the Vercel production frontend.
- Check the error state, a narrow mobile viewport and a JSON download.
- Verify requests from an unrelated origin still receive HTTP 403.
- Remember that free service cold starts and ephemeral storage can affect
  availability and feed freshness. The UI surfaces network failures and
  feed status; it never replaces a failed analysis with a safe verdict.

Configuration references: [Vercel rewrites](https://vercel.com/docs/routing/rewrites)
and [Render Blueprint specification](https://render.com/docs/blueprint-spec).
