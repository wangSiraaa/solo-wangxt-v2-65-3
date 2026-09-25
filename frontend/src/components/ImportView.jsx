import React, { useCallback, useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'

const KIND_LABEL = {
  duplicate_seq: '序号重复',
  mixed_family: '地址族混用',
  invalid_range: '非法 ge/le 范围',
  missing_default: '默认行为缺失',
  unrecognized: '无法识别指令',
  parse_error: '解析错误',
  seq_assigned: '自动编号',
}
const LINE_KIND_LABEL = {
  rule: '规则', description: '描述', comment: '注释',
  blank: '空行', unrecognized: '未识别',
}
const STATUS_LABEL = {
  pending: '待处理', ready: '可采纳', partial: '部分采纳', adopted: '已采纳',
}

export default function ImportView({ onChange }) {
  const [sessions, setSessions] = useState([])
  const [sel, setSel] = useState(null)
  const [detail, setDetail] = useState(null)
  const [preview, setPreview] = useState(null)
  const [filename, setFilename] = useState('upload.conf')
  const [text, setText] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  const loadList = useCallback(async (keepSel = true) => {
    const list = await api.imports()
    setSessions(list)
    if (!keepSel) setSel(list[0]?.id ?? null)
    return list
  }, [])

  const loadDetail = useCallback(async (id) => {
    if (id == null) { setDetail(null); setPreview(null); return }
    const [d, p] = await Promise.all([api.importDetail(id), api.importPreview(id)])
    setDetail(d)
    setPreview(p)
  }, [])

  useEffect(() => { loadList(false).catch((e) => setMsg('错误：' + e.message)) }, [loadList])
  useEffect(() => { loadDetail(sel).catch((e) => setMsg('错误：' + e.message)) }, [sel, loadDetail])

  async function upload() {
    if (!text.trim()) { setMsg('请粘贴或选择配置文件'); return }
    setBusy(true); setMsg('')
    try {
      const d = await api.uploadImport(filename || 'upload.conf', text)
      await loadList()
      setSel(d.id)
      setText('')
      setMsg(d.deduplicated
        ? `相同文件已导入过（会话 #${d.id}），未重复创建——幂等`
        : `已创建导入会话 #${d.id}：${d.drafts.length} 个列表草稿，` +
          `${d.error_count} 个待处理错误`)
    } catch (e) { setMsg('错误：' + e.message) }
    finally { setBusy(false) }
  }

  function pickFile(ev) {
    const f = ev.target.files?.[0]
    if (!f) return
    setFilename(f.name)
    f.text().then(setText)
  }

  async function resolve(diagId) {
    setBusy(true); setMsg('')
    try {
      const d = await api.importResolve(detail.id, diagId, 'drop')
      setDetail(d)
      setPreview(await api.importPreview(detail.id))
      setMsg('已丢弃该行并重新校验')
    } catch (e) { setMsg('错误：' + e.message) }
    finally { setBusy(false) }
  }

  return (
    <div className="importview">
      <div className="bar">
        <span>FRR prefix-list 离线导入（先隔离草稿，审查后原子采纳）</span>
        <input style={{ width: 180 }} value={filename}
          onChange={(e) => setFilename(e.target.value)} />
        <input type="file" accept=".conf,.txt,.cfg" onChange={pickFile} />
        <button className="primary" onClick={upload} disabled={busy}>导入为草稿</button>
        <span className={msg.startsWith('错误') ? 'error' : 'ok'}>{msg}</span>
      </div>
      <textarea rows={6} value={text} onChange={(e) => setText(e.target.value)}
        placeholder={'粘贴 FRR prefix-list 配置，例如：\n' +
          'ip prefix-list EDGE-IN seq 5 permit 10.0.0.0/8 ge 16 le 24\n' +
          'ipv6 prefix-list EDGE-IN-V6 seq 5 permit 2001:db8::/32 le 48'} />

      <div className="importcols">
        <div className="importlist">
          <h4>导入会话 / 映射历史</h4>
          {sessions.length === 0 && <div className="muted">尚无导入记录</div>}
          {sessions.map((s) => (
            <button key={s.id}
              className={'sessitem' + (s.id === sel ? ' active' : '')}
              onClick={() => { setSel(s.id); setMsg('') }}>
              <div>
                <b>#{s.id} {s.filename}</b>
                <span className={`tag st-${s.status}`}>{STATUS_LABEL[s.status]}</span>
              </div>
              <div className="muted small">
                {s.drafts.map((d) => `${d.name}(IPv${d.family})`).join('，') || '无草稿'}
                {s.error_count > 0 && <span className="deny"> · {s.error_count} 错误</span>}
                {' · '}{new Date(s.created_at).toLocaleString()}
              </div>
            </button>
          ))}
        </div>

        {detail && (
          <SessionDetail
            detail={detail} preview={preview} busy={busy}
            onResolve={resolve}
            onChanged={async (m) => {
              setMsg(m)
              await loadList()
              await loadDetail(detail.id)
              onChange?.()
            }}
            setBusy={setBusy} setMsg={setMsg} />
        )}
      </div>
    </div>
  )
}

function SessionDetail({ detail, preview, onResolve, onChanged, busy, setBusy, setMsg }) {
  const diagsByLine = useMemo(() => {
    const m = new Map()
    for (const d of detail.diagnostics) {
      if (d.line_no == null) continue
      if (!m.has(d.line_no)) m.set(d.line_no, [])
      m.get(d.line_no).push(d)
    }
    return m
  }, [detail])

  const openErrors = detail.diagnostics.filter((d) => d.severity === 'error' && !d.resolved)

  return (
    <div className="importdetail">
      <div className="summary">
        <span>会话 #{detail.id} · <b>{detail.filename}</b></span>
        <span className={`tag st-${detail.status}`}>{STATUS_LABEL[detail.status]}</span>
        <span className={openErrors.length ? 'deny2' : 'permit2'}>
          {openErrors.length ? `${openErrors.length} 个错误待处理` : '无阻塞错误'}
        </span>
        <span className="muted">sha256 {detail.content_hash.slice(0, 12)}…</span>
      </div>

      <h4>原始文本与行级诊断（来源保真）</h4>
      <table className="lines">
        <tbody>
          {detail.lines.map((l) => {
            const diags = diagsByLine.get(l.line_no) || []
            const sev = diags.some((d) => d.severity === 'error' && !d.resolved) ? 'error'
              : diags.some((d) => d.severity === 'warning') ? 'warning'
              : diags.length ? 'info' : ''
            return (
              <tr key={l.line_no} className={`ln-${l.kind} sev-${sev}`}>
                <td className="lineno">{l.line_no}</td>
                <td className="rawline"><code>{l.raw || ' '}</code></td>
                <td className="linetag"><span className="tag">{LINE_KIND_LABEL[l.kind]}</span></td>
                <td className="linediag">
                  {diags.map((d) => (
                    <div key={d.id} className={`diag ${d.severity} ${d.resolved ? 'resolved' : ''}`}>
                      <b>[{KIND_LABEL[d.kind] || d.kind}]</b> {d.message}
                      {d.resolved && <span className="muted">（已处理：丢弃该行）</span>}
                      {d.severity === 'error' && !d.resolved && (
                        <button className="mini" disabled={busy}
                          onClick={() => onResolve(d.id)}>丢弃此行</button>
                      )}
                    </div>
                  ))}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>

      {detail.diagnostics.filter((d) => d.line_no == null).map((d) => (
        <div key={d.id} className={`diag ${d.severity}`}>
          <b>[{KIND_LABEL[d.kind] || d.kind}]</b> {d.message}
        </div>
      ))}

      <h4>列表草稿（规范化后）</h4>
      {detail.drafts.length === 0 &&
        <div className="muted">文件中没有可识别的 prefix-list 规则。</div>}
      {detail.drafts.map((d) => (
        <DraftCard key={d.id} draft={d}
          preview={preview?.drafts?.find((p) => p.draft_id === d.id)}
          sessionId={detail.id} sessionStatus={detail.status}
          openErrors={openErrors.length}
          onChanged={onChanged} busy={busy} setBusy={setBusy} setMsg={setMsg} />
      ))}
    </div>
  )
}

function DraftCard({ draft, preview, sessionId, sessionStatus, openErrors,
                     onChanged, busy, setBusy, setMsg }) {
  const [conflict, setConflict] = useState(null)
  const [probes, setProbes] = useState('')
  const [cv, setCv] = useState(null)
  const [adopted, setAdopted] = useState(null)

  async function adopt(token) {
    setBusy(true); setConflict(null); setMsg('')
    try {
      const out = await api.importAdopt(sessionId, {
        draft_id: draft.id, expected_base_updated_at: token ?? null,
      })
      setAdopted(out)
      await onChanged(`草稿 ${draft.name} 已原子采纳：快照 #${out.snapshot_id} (v${out.version})`)
    } catch (e) {
      if (e.status === 409) setConflict({
        message: e.message, current: e.detail?.current_updated_at ?? null,
      })
      else setMsg('错误：' + e.message)
    } finally { setBusy(false) }
  }

  async function crossValidate() {
    setBusy(true); setCv(null); setMsg('')
    try {
      const list = probes.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
      setCv(await api.importCrossValidate(sessionId, draft.id, list))
    } catch (e) { setMsg('交叉验证失败：' + e.message) }
    finally { setBusy(false) }
  }

  const canAdopt = draft.status !== 'adopted' && openErrors === 0 && !preview?.error

  return (
    <div className={`draftcard st-${draft.status}`}>
      <div className="bar">
        <b>{draft.name}</b> <span className="muted">IPv{draft.family}</span>
        <span className={`tag st-${draft.status}`}>{STATUS_LABEL[draft.status]}</span>
        {draft.description && <span className="muted">“{draft.description}”</span>}
        {draft.adopted_snapshot_id &&
          <span className="permit2">已采纳 → 快照 #{draft.adopted_snapshot_id}</span>}
      </div>

      <table className="rules">
        <thead><tr>
          <th>seq</th><th>前缀（规范化）</th><th>动作</th><th>ge</th><th>le</th>
        </tr></thead>
        <tbody>
          {draft.rules.map((r) => (
            <tr key={r.seq}>
              <td>{r.seq}</td>
              <td><code className="chip">{r.prefix}</code></td>
              <td className={r.action}>{r.action}</td>
              <td>{r.ge ?? '—'}</td><td>{r.le ?? '—'}</td>
            </tr>
          ))}
          {draft.rules.length === 0 &&
            <tr><td colSpan={5} className="muted">（无候选规则）</td></tr>}
        </tbody>
      </table>

      {preview && (
        <div className="preview">
          {preview.error
            ? <div className="error">{preview.error}</div>
            : (
              <>
                <div className="summary">
                  <span>与主线语义差异：
                    {preview.target_policy_id
                      ? `策略 #${preview.target_policy_id}（${preview.current_rule_count} 条，默认 ${preview.current_default}）`
                      : '（主线尚无此策略，将与空策略比较）'}
                  </span>
                  <span className="deny2">新增拒绝 {preview.newly_denied.length}</span>
                  <span className="permit2">新增放行 {preview.newly_permitted.length}</span>
                </div>
                {preview.witness_count === 0
                  ? <div className="ok">✓ 无行为变化——即使规则文本/顺序不同，语义完全等价。</div>
                  : (
                    <table className="witness">
                      <thead><tr>
                        <th>见证前缀</th><th>主线结果</th><th>草稿结果</th><th>变化</th>
                      </tr></thead>
                      <tbody>
                        {preview.witnesses.map((w) => (
                          <tr key={w.prefix} className={w.change}>
                            <td><code className="chip big">{w.prefix}</code></td>
                            <td className={w.old_action}>{w.old_action}{w.old_seq == null ? '（默认）' : ` #${w.old_seq}`}</td>
                            <td className={w.new_action}>{w.new_action}{w.new_seq == null ? '（默认）' : ` #${w.new_seq}`}</td>
                            <td>{w.change}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
              </>
            )}
        </div>
      )}

      <div className="bar">
        <button className="primary" disabled={!canAdopt || busy}
          title={openErrors ? '仍有未处理错误' : ''}
          onClick={() => adopt(preview?.base_updated_at)}>
          原子采纳（替换主线 + 生成快照）
        </button>
        {openErrors > 0 &&
          <span className="deny2">须先处理全部 {openErrors} 个错误，绝不生成半快照</span>}
        <input placeholder="探针（空格分隔），如 10.1.0.0/16" className="probe"
          value={probes} onChange={(e) => setProbes(e.target.value)} />
        <button disabled={busy || !probes.trim() || openErrors > 0}
          onClick={crossValidate}>FRR 交叉验证</button>
      </div>

      {conflict && (
        <div className="conflict">
          <b>⚠ 版本冲突：</b>{conflict.message}
          <button className="small" disabled={busy}
            onClick={() => adopt(conflict.current)}>
            以当前主线为基线重新采纳
          </button>
          <span className="muted">（草稿、诊断与原始文本均已保留，可先刷新核对）</span>
        </div>
      )}
      {adopted && (
        <div className="ok">已采纳：策略 {adopted.policy}（{adopted.rule_count} 条，
          默认 {adopted.default_action}），快照 #{adopted.snapshot_id} v{adopted.version}。</div>
      )}

      {cv && (
        <div className={`cvbox ${cv.status === 'match' ? 'match' : 'mismatch'}`}>
          <b>FRR 交叉验证（{cv.node}，{cv.family === 4 ? 'IPv4' : 'IPv6'}）：</b>
          {cv.status === 'match' && <span className="ok"> 全部 {cv.rows.length} 条一致 ✓</span>}
          {cv.status === 'mismatch' && <span className="error"> {cv.mismatch_count} 条不一致</span>}
          {cv.status === 'error' && <span className="error"> 实验环境错误：{cv.setup_error}</span>}
          {cv.rows.length > 0 && (
            <table>
              <thead><tr>
                <th>探针</th><th>模拟器</th><th>FRR</th><th>一致</th>
              </tr></thead>
              <tbody>
                {cv.rows.map((r) => (
                  <tr key={r.order} className={r.action_match && r.seq_match ? 'okrow' : 'badrow'}>
                    <td><code className="chip">{r.prefix}</code></td>
                    <td>{r.sim_action}{r.sim_seq == null ? '' : ` #${r.sim_seq}`}</td>
                    <td>{r.frr_action}{r.frr_seq == null ? '' : ` #${r.frr_seq}`}</td>
                    <td>{r.action_match && r.seq_match ? '✓' : '✗'}</td>
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
