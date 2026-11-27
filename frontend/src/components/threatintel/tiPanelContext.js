// The Threat Intelligence detail panel's controls (TiPanel.jsx provides them): every row's details open in
// the one right-hand panel, as a stack, so a list inside a panel (a technique's indicators) can open one of
// them and come back ("← T1555").
//   open(view)     show a view, replacing whatever the panel showed
//   push(view)     show a view on top; the panel offers a way back to the one under it
//   replace(view)  swap the top view (a new event, once saved, becomes its own page)
//   back(), close()
//   changed()      something was saved: lists showing it load again (their effects depend on `version`)
// A view is { kind: 'indicator' | 'event' | 'eventForm' | 'technique' | 'match', label, ...its props };
// `label` names it on the way back.
import { createContext, useContext } from 'react'

export const TiPanelContext = createContext(null)

export function useTiPanel() {
  const ctx = useContext(TiPanelContext)
  if (!ctx) throw new Error('useTiPanel needs a TiPanelProvider')
  return ctx
}
