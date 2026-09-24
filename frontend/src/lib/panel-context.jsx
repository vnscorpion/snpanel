import { createContext, useContext } from 'react';

// What the page components read from App: state, setters and handlers.
//
// The pages used to be render functions inside App, closing over its scope.
// This carries the same names across a module boundary. It is one object for
// now because that is what the closure was; a page that is redesigned takes
// its own state with it and stops reading it from here.
export const PanelContext = createContext(null);

export function usePanel() {
  const value = useContext(PanelContext);
  if (!value) throw new Error('usePanel() outside PanelContext');
  return value;
}
