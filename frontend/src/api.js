const BASE = '/api';

async function req(path, { method = 'GET', body } = {}) {
  const r = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) {
    const detail = data?.detail;
    const err = new Error(typeof detail === 'string'
      ? detail
      : detail?.message || `${r.status} ${r.statusText}`);
    err.status = r.status;
    err.detail = typeof detail === 'object' ? detail : null;
    throw err;
  }
  return data;
}

export const api = {
  listPolicies: () => req('/policies'),
  getPolicy: (id) => req(`/policies/${id}`),
  createPolicy: (b) => req('/policies', { method: 'POST', body: b }),
  setRules: (id, rules, default_action) =>
    req(`/policies/${id}/rules`, { method: 'PUT', body: { rules, default_action } }),
  analyze: (id) => req(`/policies/${id}/analyze`),
  classify: (id, prefix) =>
    req(`/policies/${id}/classify`, { method: 'POST', body: { prefix } }),
  batch: (id, probes) =>
    req(`/policies/${id}/classify/batch`, { method: 'POST', body: { probes } }),
  trie: (id) => req(`/policies/${id}/trie`),
  snapshots: (id) => req(`/policies/${id}/snapshots`),
  snapshot: (id, label, created_by = 'lab') =>
    req(`/policies/${id}/snapshots`, { method: 'POST', body: { label, created_by } }),
  getSnapshot: (id) => req(`/snapshots/${id}`),
  diff: (a, b) => req('/snapshots/diff', { method: 'POST', body: { old_snapshot_id: a, new_snapshot_id: b } }),
  replay: (id, probes) =>
    req(`/snapshots/${id}/replay`, { method: 'POST', body: { probes } }),
  scenarios: () => req('/scenarios'),
  scenario: (id) => req(`/scenarios/${id}`),
  replayScenario: (id) => req(`/scenarios/${id}/replay`, { method: 'POST' }),
  neighbors: () => req('/neighbors'),
  frrStatus: () => req('/frr/status'),
  crossValidate: (id, probes, node = 'a') =>
    req(`/snapshots/${id}/cross-validate`, { method: 'POST', body: { probes, node } }),
  runs: () => req('/runs'),
  // config import
  uploadImport: (filename, text) =>
    req('/imports', { method: 'POST', body: { filename, text } }),
  imports: () => req('/imports'),
  importDetail: (id) => req(`/imports/${id}`),
  importPreview: (id) => req(`/imports/${id}/preview`),
  importResolve: (id, diagnostic_id, action = 'drop') =>
    req(`/imports/${id}/resolve`, { method: 'POST', body: { diagnostic_id, action } }),
  importAdopt: (id, body) => req(`/imports/${id}/adopt`, { method: 'POST', body }),
  importCrossValidate: (id, draft_id, probes, node = 'a') =>
    req(`/imports/${id}/cross-validate`, { method: 'POST', body: { draft_id, probes, node } }),
};
