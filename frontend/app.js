'use strict';
const $ = (id) => document.getElementById(id);
let latestResult = null;
let controller = null;
let generation = 0;

function addRows(target, rows) {
  target.replaceChildren();
  for (const [label, value] of rows) {
    const row = document.createElement('tr');
    for (const text of [label, value]) {
      const cell = document.createElement('td');
      cell.textContent = String(text ?? 'Unavailable');
      row.append(cell);
    }
    target.append(row);
  }
}

async function readResponse(response) {
  let body;
  try { body = await response.json(); }
  catch { throw new Error('The analysis service is unavailable. Please try again shortly.'); }
  if (!response.ok) {
    if (response.status === 429) {
      const wait = response.headers.get('Retry-After');
      throw new Error(wait && /^\d+$/.test(wait) ? `Too many checks. Try again in ${wait} seconds.` : 'Too many checks. Wait a minute before trying again.');
    }
    throw new Error(body.error || 'Unable to complete the check. Please try again.');
  }
  return body;
}

function showResult(result) {
  latestResult = result;
  $('result-heading').textContent = result.prediction;
  const risk = ['Low', 'Medium', 'High', 'Unknown'].includes(result.risk) ? result.risk : 'Unknown';
  $('risk').className = `risk risk-${risk.toLowerCase()}`;
  $('risk').textContent = `${risk} risk`;
  $('verification').textContent = result.verification;
  $('action').textContent = result.action;
  $('analyzed-url').textContent = `Analyzed URL: ${result.url}`;
  const rows = [
    ['Decision evidence', result.evidence],
    ['Public-feed exact URL check', result.public_feeds.status.replaceAll('_', ' ')],
    [`${result.model_name || 'Detection model'} score`, `${result.model_score}%${result.calibrated ? ' (historically calibrated)' : ''}`],
    ['Model share of risk index', `${Math.round((result.model_weight ?? .8) * 100)}%`],
    ['Rule score', `${result.rule_score} / 100`],
    ['Combined risk index', `${result.hybrid_score} / 100`],
    ['Phishing decision threshold', `${result.threshold} / 100`],
    ['Analysis time', `${result.latency_ms} ms`],
  ];
  for (const source of result.public_feeds.sources || []) rows.push(['Feed evidence', `${source.name}; downloaded ${source.fetched_at} (UTC)`]);
  if (result.external_reputation.status !== 'not_requested') rows.push(['Google Web Risk', result.external_reputation.status.replaceAll('_', ' ')]);
  addRows($('measures'), rows);
  addRows($('features'), Object.entries(result.features));
  $('feed-message').textContent = result.public_feeds.message;
  $('reputation-message').hidden = result.external_reputation.status === 'not_requested';
  $('reputation-message').textContent = result.external_reputation.message;
  $('indicators').replaceChildren();
  for (const indicator of result.indicators.length ? result.indicators : ['No configured warning rules triggered.']) {
    const item = document.createElement('li');
    item.textContent = indicator;
    $('indicators').append(item);
  }
  $('result').hidden = false;
  $('result').focus({ preventScroll: true });
  $('result').scrollIntoView({ block: 'start' });
}

$('check-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (controller) return;
  const current = ++generation;
  controller = new AbortController();
  const activeController = controller;
  const timeout = setTimeout(() => activeController.abort(), 65000);
  $('input-error').hidden = true;
  $('url').removeAttribute('aria-invalid');
  $('result').hidden = true;
  latestResult = null;
  $('check-button').disabled = true;
  $('check-button').textContent = 'Checking…';
  $('check-form').setAttribute('aria-busy', 'true');
  $('status').textContent = 'Analyzing the URL. The service may take a moment to wake up.';
  try {
    const response = await fetch('/api/predict', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: $('url').value.trim(), consent: $('consent').checked }),
      signal: controller.signal, cache: 'no-store',
    });
    const result = await readResponse(response);
    if (current !== generation) return;
    showResult(result);
    $('status').textContent = 'Check complete. Review the evidence below.';
  } catch (error) {
    if (current !== generation) return;
    $('input-error').textContent = error.name === 'AbortError' ? 'The check timed out. Please try again; the service may be starting.' : error instanceof TypeError ? 'Could not reach the service. Check your connection and try again.' : error.message;
    $('input-error').hidden = false;
    $('url').setAttribute('aria-invalid', 'true');
    $('status').textContent = 'Check could not be completed.';
  } finally {
    clearTimeout(timeout);
    if (current === generation) {
      controller = null;
      $('check-button').disabled = false;
      $('check-button').textContent = 'Check URL';
      $('check-form').removeAttribute('aria-busy');
    }
  }
});

$('clear-button').addEventListener('click', () => {
  generation++;
  controller?.abort();
  controller = null;
  latestResult = null;
  $('check-form').reset();
  $('check-form').removeAttribute('aria-busy');
  $('check-button').disabled = false;
  $('check-button').textContent = 'Check URL';
  $('url').removeAttribute('aria-invalid');
  $('result').hidden = true;
  $('input-error').hidden = true;
  $('status').textContent = 'Ready for a new check.';
  $('url').focus();
});

$('download-button').addEventListener('click', () => {
  if (!latestResult) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(latestResult, null, 2)], { type: 'application/json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'url-analysis.json';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

fetch('/api/status', { cache: 'no-store', signal: AbortSignal.timeout(65000) })
  .then(readResponse)
  .then((state) => {
    $('consent-row').hidden = !state.reputation_configured;
    if (generation === 0) $('status').textContent = state.model_ready ? 'Ready to check. Your link will not be opened.' : 'The analysis model is unavailable. Please try again later.';
    $('feed-status').textContent = `Status: ${state.public_feeds.status}. ${state.public_feeds.total_indicators} public indicators available.`;
  })
  .catch(() => {
    if (generation === 0) $('status').textContent = 'The service is taking longer to respond. You can still try a check.';
    $('feed-status').textContent = 'Feed status could not be loaded.';
  });
