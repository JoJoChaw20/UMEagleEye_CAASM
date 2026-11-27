// The one detail panel of the Threat Intelligence pages (tiPanelContext.js explains the controls). It shows
// the top view of a stack in the shared SidePanel: wide for an advisory, an event or a technique, which list
// things inside them; a link at the top returns to the view underneath.
import { useCallback, useMemo, useState } from 'react'
import { ArrowLeft } from 'lucide-react'
import { SidePanel } from '../common/PageParts'
import { TiPanelContext } from './tiPanelContext'
import { IndicatorView } from './IndicatorPanel'
import { EventView, EventForm } from './TiEventsPanel'
import TechniqueView from './TechniqueView'
import { MatchView } from './MatchesPanel'

const VIEWS = { indicator: IndicatorView, event: EventView, eventForm: EventForm, technique: TechniqueView, match: MatchView }
const WIDE = new Set(['event', 'eventForm', 'technique'])
const keyOf = (v) => `${v.kind}:${v.id ?? v.value ?? v.tech?.id ?? v.alert?.event_id ?? 'new'}`

export function TiPanelProvider({ children, showToast }) {
  const [stack, setStack] = useState([])
  const [head, setHead] = useState({})
  const [version, setVersion] = useState(0)

  const api = useMemo(() => ({
    open: (view) => { setHead({}); setStack([view]) },
    push: (view) => { setHead({}); setStack((s) => [...s, view]) },
    replace: (view) => { setHead({}); setStack((s) => [...s.slice(0, -1), view]) },
    back: () => { setHead({}); setStack((s) => s.slice(0, -1)) },
    close: () => { setHead({}); setStack([]) },
    changed: () => setVersion((v) => v + 1),
  }), [])
  const value = useMemo(() => ({ ...api, version }), [api, version])

  const top = stack[stack.length - 1]
  const under = stack[stack.length - 2]
  const View = top ? VIEWS[top.kind] : null
  const setHeadStable = useCallback((h) => setHead(h), [])

  return (
    <TiPanelContext.Provider value={value}>
      {children}
      {View && (
        <SidePanel title={head.title ?? top.label ?? ''} subtitle={head.subtitle} onClose={api.close} footer={head.footer}
          dirty={!!head.dirty} width={WIDE.has(top.kind) ? 'sm:w-[760px]' : 'sm:w-[560px]'}>
          {under && (
            <button type="button" onClick={api.back} className="-mt-1 flex max-w-full items-center gap-1 text-xs text-dark-400 hover:text-eagle-400">
              <ArrowLeft className="h-3.5 w-3.5 shrink-0" /><span className="truncate">{under.label}</span>
            </button>
          )}
          <View key={keyOf(top)} view={top} setHead={setHeadStable} panel={value} showToast={showToast} />
        </SidePanel>
      )}
    </TiPanelContext.Provider>
  )
}
