import React, { useEffect, useMemo, useState } from 'react'
import { api } from './api.js'
import PolicyEditor from './components/PolicyEditor.jsx'
import TrieView from './components/TrieView.jsx'
import DiffView from './components/DiffView.jsx'
import ReplayLab from './components/ReplayLab.jsx'
import Neighbors from './components/Neighbors.jsx'
import ImportView from './components/ImportView.jsx'

const TABS = [
  { id: 'edit', label: '① 规则编辑 / 遮蔽检查', comp: PolicyEditor },
  { id: 'trie', label: '② 前缀树 / 命中链', comp: TrieView },
  { id: 'diff', label: '③ 语义差异（最小见证）', comp: DiffView },
  { id: 'replay', label: '④ 回放 / FRR 交叉验证', comp: ReplayLab },
  { id: 'neighbors', label: '⑤ 邻居', comp: Neighbors },
  { id: 'import', label: '⑥ 配置导入', comp: ImportView },
]

export default function App() {
  const [tab, setTab] = useState('edit')
  const [policies, setPolicies] = useState([])
  const [pid, setPid] = useState(null)
  const [frr, setFrr] = useState({})
  const [err, setErr] = useState('')

  async function refresh() {
    try {
      const ps = await api.listPolicies()
      setPolicies(ps)
      setPid((cur) => cur ?? ps[0]?.id ?? null)
      setFrr(await api.frrStatus())
      setErr('')
    } catch (e) {
      setErr(e.message)
    }
  }

  useEffect(() => { refresh() }, [])

  const policy = useMemo(() => policies.find((p) => p.id === pid) || null,
    [policies, pid])

  const Current = TABS.find((t) => t.id === tab).comp

  return (
    <div className="app">
      <header>
        <div className="brand">🛰 路由策略离线推演工作台 <span className="sub">
          FastAPI + ipaddress · PostgreSQL · FRRouting 容器 · 不连生产</span></div>
        <div className="frr">
          FRR router-a: <Badge ok={frr.a?.reachable} />
          router-b: <Badge ok={frr.b?.reachable} />
        </div>
      </header>

      <nav className="tabs">
        {TABS.map((t) => (
          <button key={t.id} className={tab === t.id ? 'active' : ''}
            onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </nav>

      <div className="policypicker">
        <label>当前策略：</label>
        <select value={pid ?? ''} onChange={(e) => setPid(Number(e.target.value))}>
          {policies.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name} (IPv{p.family}, 默认 {p.default_action}, {p.rules.length} 条)
            </option>
          ))}
        </select>
        <button className="small" onClick={refresh}>刷新</button>
        {err && <span className="error">{err}</span>}
      </div>

      <main>
        {(policy || tab === 'import') &&
          <Current key={(policy?.id ?? 'none') + tab} policy={policy}
            onChange={refresh} setPid={setPid} policies={policies} />}
      </main>

      <footer>
        模拟器使用 Python <code>ipaddress</code> 精确判定（包含关系 + ge/le 窗口 + 首条匹配 +
        隐式默认拒绝）；v4/v6 严格隔离；差异基于精确单元划分，非文本 diff。
      </footer>
    </div>
  )
}

function Badge({ ok }) {
  return <span className={ok ? 'badge up' : 'badge down'}>
    {ok ? '● 在线' : '○ 离线'}
  </span>
}
