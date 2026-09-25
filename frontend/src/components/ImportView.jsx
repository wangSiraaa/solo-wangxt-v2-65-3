import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const KIND_LABEL = {
  rule: '规则', comment: '注释', blank: '空行',
  description: '描述', unparsed: '未识别',
}
const SEV_LABEL = { error: '错误', warning: '警告', info: '提示' }

export default function ImportView({ policies, onChange }) {
  const [sessions, setSessions] = useState([])
  const [sel, setSel] = useState(null)          // full session detail
  const [text, setText] = useState('')
  const [filename, setFilename] = useState('frr.conf')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  async function refreshSessions(keepId) {
    const list = await api.imports()
    setSessions(list)
    if (keepId) setSel(await api.importSession(keepId))
  }
  useEffect(() => { refreshSessions().catch(() => {}) }, [])

  async function upload() {
    if (!text.trim()) { setMsg('错误：请粘贴或选择配置文件'); return }
    setBusy(true); setMsg('')
    try {
      const up = await api.uploadImport(filename, text)
      setMsg(up.deduplicated
        ? `相同内容已导入过（会话 #${up.id}），直接打开原会话——重复提交只生成一次`
        : `已解析为隔离草稿（会话 #${up.id}），主线规则未被触碰`)
      setText('')
      await refreshSessions(up.id)
      await onChange()
    } catch (e) { setMsg('错误：' + e.message) }
    finally { setBusy(false) }
  }

  function pickFile(e) {
    const f = e.target.files?.[0]
    if (!f) return
    setFilename(f.name)
    f.text().then(setText)
  }

  async function open(id) {
    setMsg('')
    try { setSel(await api.importSession(id)) } catch (e) { setMsg(e.message) }
  }

  return (
    <div className="importview">
      <div className="bar">
        <span>离线导入 FRR prefix-list：先形成<b>隔离草稿</b>，诊断全部处理后才原子生成快照</span>
        <input type="file" accept=".conf,.txt,.cfg" onChange={pickFile} />
        <input value={filename} onChange={(e) => setFilename(e.target.value)}
          style={{ width: 180 }} />
        <button className="primary" onClick={upload} disabled={busy}>上传并解析</button>
        <span className={msg.startsWith('错误') ? 'error' : 'ok'}>{msg}</span>
      </div>
      <textarea rows={6} value={text} placeholder={
        '粘贴 vtysh 配置，例如：\nip prefix-list EDGE-IN seq 10 permit 192.168.0.0/16 le 24\nipv6 prefix-list EDGE-IN6 seq 10 permit 2001:db8::/32 le 48'}
        onChange={(e) => setText(e.target.value)} />

      <div className="cols" style={{ marginTop: 12 }}>
        <div>
          <h4>导入会话（内容寻址，重复提交幂等）</h4>
          <table>
            <thead><tr><th>#</th><th>文件</th><th>状态</th><th>草稿</th><th>时间</th></tr></thead>
            <tbody>
              {sessions.map((s) => (
                <tr key={s.id} className={sel?.id === s.id ? 'okrow' : ''}
                  onClick={() => open(s.id)} style={{ cursor: 'pointer' }}>
                  <td>{s.id}</td>
                  <td>{s.filename || <span className="muted">(未命名)</span>}</td>
                  <td><StatusChip status={s.status} /></td>
                  <td>{s.draft_count}</td>
                  <td className="muted">{s.created_at?.slice(0, 19).replace('T', ' ')}</td>
                </tr>
              ))}
              {!sessions.length && <tr><td colSpan={5} className="muted">尚无导入会话</td></tr>}
            </tbody>
          </table>
          <p className="muted">
            会话保存原始文本、逐行诊断与草稿；采纳历史见「映射历史」。
          </p>
          <AdoptionHistory />
        </div>

        <div>
          {sel
            ? <SessionDetail session={sel} policies={policies}
                onRefresh={async () => { await refreshSessions(sel.id); await onChange() }} />
            : <p className="muted">选择左侧会话查看逐行诊断、语义差异与采纳操作。</p>}
        </div>
      </div>
    </div>
  )
}

function StatusChip({ status }) {
  const label = {
    draft: '草稿', 'partially-adopted': '部分采纳', adopted: '已采纳',
  }[status] || status
  const cls = status === 'adopted' ? 'up' : status === 'draft' ? 'down' : ''
  return <span className={`badge ${cls}`}>{label}</span>
}

function Diag({ d }) {
  return (
    <li className={`diag-${d.severity}`}>
      <b>[{SEV_LABEL[d.severity] || d.severity} · {d.code}]</b>{' '}
      {d.line_no != null && <code className="chip">行 {d.line_no}</code>} {d.message}
    </li>
  )
}

function SessionDetail({ session, policies, onRefresh }) {
  const errLines = session.lines.filter((l) =>
    (l.diagnostics || []).some((d) => d.severity === 'error'))
  return (
    <div>
      <h4>会话 #{session.id} · {session.filename || '(未命名)'} ·{' '}
        <StatusChip status={session.status} /></h4>
      <p className="muted">
        sha256 <code>{session.content_hash.slice(0, 16)}…</code> ·
        {' '}{session.lines.length} 行 · {errLines.length} 行含错误
      </p>

      {session.drafts.map((d) => (
        <DraftCard key={d.id} session={session} draft={d}
          policies={policies} onRefresh={onRefresh} />
      ))}

      <details>
        <summary>原始文本逐行视图（来源保真：行号 / 注释 / 未识别指令全部保留）</summary>
        <table className="linetable">
          <thead><tr><th style={{ width: 50 }}>行</th><th style={{ width: 70 }}>类别</th>
            <th>原文</th><th>诊断</th></tr></thead>
          <tbody>
            {session.lines.map((l) => (
              <tr key={l.line_no}
                className={(l.diagnostics || []).some((d) => d.severity === 'error')
                  ? 'badrow' : (l.diagnostics || []).length ? 'partial' : ''}>
                <td className="muted">{l.line_no}</td>
                <td>{KIND_LABEL[l.kind] || l.kind}</td>
                <td><code>{l.raw || ' '}</code></td>
                <td>
                  {(l.diagnostics || []).map((d, i) => (
                    <div key={i} className={`diag-${d.severity}`}>
                      <b>{d.code}</b> {d.message}
                    </div>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  )
}

function DraftCard({ session, draft, policies, onRefresh }) {
  const [defAction, setDefAction] = useState(draft.default_action)
  const [confirmed, setConfirmed] = useState(draft.default_confirmed)
  const [target, setTarget] = useState(draft.target_policy_id ?? '')
  const [probesText, setProbesText] = useState('')
  const [cv, setCv] = useState(null)
  const [msg, setMsg] = useState('')
  const [conflict, setConflict] = useState('')
  const [busy, setBusy] = useState(false)

  const sameFamily = policies.filter((p) => p.family === draft.family)
  const ready = draft.readiness.ready
  const diff = draft.diff

  async function saveMeta() {
    setBusy(true); setMsg(''); setConflict('')
    try {
      await api.updateDraft(session.id, draft.id, {
        default_action: defAction,
        confirm_default: confirmed,
        retarget: true,
        target_policy_id: target === '' ? null : Number(target),
      })
      setMsg('草稿已更新（诊断已重算）')
      await onRefresh()
    } catch (e) { setMsg('错误：' + e.message) }
    finally { setBusy(false) }
  }

  async function adopt() {
    setBusy(true); setMsg(''); setConflict('')
    try {
      const r = await api.adoptDraft(session.id, draft.id, draft.base_revision)
      setMsg(`已原子采纳：快照 v${r.snapshot.version}（行为见证 ${r.witness_count} 个），`
        + '规则替换与快照在同一事务内完成')
      await onRefresh()
    } catch (e) {
      if (e.message.includes('revision') || e.message.includes('moved')
          || e.message.includes('409')) {
        setConflict('版本冲突：主线在你预览之后已被修改。草稿、诊断与原始文本均已保留，'
          + '请刷新重看差异后再采纳。')
      } else {
        setMsg('错误：' + e.message)
      }
    } finally { setBusy(false) }
  }

  async function crossValidate() {
    setBusy(true); setMsg(''); setCv(null)
    try {
      const probes = probesText.split(/[\s,]+/).filter(Boolean)
      setCv(await api.crossValidateDraft(session.id, draft.id, probes,
        undefined))
    } catch (e) { setMsg('错误：' + e.message) }
    finally { setBusy(false) }
  }

  return (
    <div className="draftcard">
      <div className="bar">
        <b>{draft.name}</b> <span className="chip">IPv{draft.family}</span>
        <StatusChip status={draft.status === 'ready' ? 'draft' : draft.status} />
        {draft.stale && <span className="tag warn">主线已更新（r{draft.base_revision} →
          r{draft.current_revision}），请刷新</span>}
        {draft.adopted_snapshot_id &&
          <span className="tag">快照 #{draft.adopted_snapshot_id}</span>}
      </div>

      {draft.readiness.blocking.length > 0 && (
        <div className="diagbox">
          <b className="deny">阻断项（全部处理后才能采纳）：</b>
          <ul>{draft.readiness.blocking.map((d, i) => <Diag key={i} d={d} />)}</ul>
        </div>
      )}
      {draft.readiness.warnings.length > 0 && (
        <div className="diagbox">
          <b className="warn">警告：</b>
          <ul>{draft.readiness.warnings.map((d, i) => <Diag key={i} d={d} />)}</ul>
        </div>
      )}

      <table className="rules">
        <thead><tr><th>seq</th><th>动作</th><th>前缀</th><th>ge</th><th>le</th></tr></thead>
        <tbody>
          {draft.rules.map((r) => (
            <tr key={r.seq}>
              <td>{r.seq}</td>
              <td className={r.action}>{r.action}</td>
              <td><code>{r.prefix}</code></td>
              <td>{r.ge ?? '—'}</td><td>{r.le ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="bar">
        <label>隐式默认：
          <select value={defAction} onChange={(e) => setDefAction(e.target.value)}>
            <option value="deny">deny</option>
            <option value="permit">permit</option>
          </select>
        </label>
        <label>
          <input type="checkbox" checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)} />
          {' '}已确认默认行为（文件未携带）
        </label>
        <label>映射到：
          <select value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">新建策略 {draft.name}</option>
            {sameFamily.map((p) => (
              <option key={p.id} value={p.id}>{p.name}（r{p.revision}）</option>
            ))}
          </select>
        </label>
        <button onClick={saveMeta} disabled={busy || draft.status === 'adopted'}>
          保存草稿设置
        </button>
      </div>

      {diff && (
        <div className="diffmini">
          <b>与当前主线的最小行为变化（语义，非文本）：</b>
          {diff.witness_count === 0
            ? <span className="ok"> 无行为变化——重排/改写不影响任何前缀的转发结果。</span>
            : <table className="witness">
                <thead><tr><th>见证前缀</th><th>旧</th><th>新</th><th>变化</th></tr></thead>
                <tbody>
                  {diff.witnesses.map((w) => (
                    <tr key={w.prefix} className={w.change}>
                      <td><code className="chip">{w.prefix}</code></td>
                      <td className={w.old_action}>{w.old_action}{w.old_seq == null ? '（默认）' : ` #${w.old_seq}`}</td>
                      <td className={w.new_action}>{w.new_action}{w.new_seq == null ? '（默认）' : ` #${w.new_seq}`}</td>
                      <td>{w.change}</td>
                    </tr>
                  ))}
                </tbody>
              </table>}
          <div className="muted">
            基线：{diff.baseline} · 默认 {diff.old_default} ⟶ {diff.new_default}
          </div>
        </div>
      )}

      <div className="bar">
        <input placeholder="FRR 交叉验证探针（空格分隔，可选）" value={probesText}
          onChange={(e) => setProbesText(e.target.value)} style={{ minWidth: 260 }} />
        <button onClick={crossValidate}
          disabled={busy || !probesText.trim() || !draft.readiness.rules_valid}>
          本地 FRR 交叉验证
        </button>
        <button className="primary" onClick={adopt} disabled={busy || !ready}>
          原子采纳（替换规则 + 生成快照）
        </button>
        {!ready && draft.status !== 'adopted' &&
          <span className="muted">采纳前需处理全部阻断项并确认默认行为</span>}
      </div>

      {conflict && (
        <div className="conflict">
          ⚠ {conflict}{' '}
          <button className="small" onClick={onRefresh}>刷新草稿</button>
        </div>
      )}
      {msg && <div className={msg.startsWith('错误') ? 'error' : 'ok'}>{msg}</div>}

      {cv && (
        <div className={`cvbox ${cv.status}`}>
          <b>FRR 交叉验证（{cv.node === 'a' ? 'router-a' : 'router-b'}）：</b>
          {cv.status === 'match'
            ? <span className="ok"> ✓ {cv.rows.length} 个探针全部一致</span>
            : <span className="error"> ✗ {cv.mismatch_count} 处不一致{cv.setup_error ? `：${cv.setup_error}` : ''}</span>}
          {cv.rows?.length > 0 && (
            <table className="cv">
              <thead><tr><th>#</th><th>前缀</th><th>模拟器</th><th>FRR</th></tr></thead>
              <tbody>
                {cv.rows.map((r) => (
                  <tr key={r.order}
                    className={r.action_match && r.seq_match ? 'okrow' : 'badrow'}>
                    <td>{r.order + 1}</td><td><code>{r.prefix}</code></td>
                    <td className={r.sim_action}>{r.sim_action} #{r.sim_seq ?? '默认'}</td>
                    <td className={r.frr_action}>{r.frr_action} #{r.frr_seq ?? '默认'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

function AdoptionHistory() {
  const [rows, setRows] = useState([])
  useEffect(() => { api.adoptions().then(setRows).catch(() => {}) }, [])
  if (!rows.length) return null
  return (
    <details>
      <summary>映射历史（草稿 → 策略快照）</summary>
      <table>
        <thead><tr><th>会话</th><th>草稿</th><th>策略</th><th>快照</th>
          <th>基线 rev</th><th>版本</th><th>见证数</th></tr></thead>
        <tbody>
          {rows.map((a) => (
            <tr key={a.id}>
              <td>#{a.session_id}</td><td>#{a.draft_id}</td>
              <td>#{a.policy_id}</td><td>#{a.snapshot_id}</td>
              <td>{a.base_revision ?? '—'}</td><td>v{a.new_version}</td>
              <td>{a.witness_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </details>
  )
}
