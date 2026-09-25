const BASE = '/api';

async function req(path, { method = 'GET', body } = {}) {
  const r = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  const data = text ? JSON.parse(text) : null;
  if (!r.ok) throw new Error(data?.detail || `${r.status} ${r.statusText}`);
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
  // config import closed loop
  uploadImport: (filename, text) =>
    req('/imports', { method: 'POST', body: { filename, text } }),
  imports: () => req('/imports'),
  importSession: (id) => req(`/imports/${id}`),
  updateDraft: (iid, did, body) =>
    req(`/imports/${iid}/drafts/${did}`, { method: 'PUT', body }),
  adoptDraft: (iid, did, expected_revision) =>
    req(`/imports/${iid}/drafts/${did}/adopt`,
      { method: 'POST', body: { expected_revision } }),
  crossValidateDraft: (iid, did, probes, node = 'a') =>
    req(`/imports/${iid}/drafts/${did}/cross-validate`,
      { method: 'POST', body: { probes, node } }),
  adoptions: () => req('/adoptions'),
};
