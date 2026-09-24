// The code editor, and ace with it.
//
// Its own module so that it can be loaded lazily: ace and its modes and
// themes are several hundred kilobytes, and the only place the panel shows
// an editor is the standalone editor window. Before this, every page load
// downloaded all of it.
import { useEffect, useRef, useState } from 'react';
import ace from 'ace-builds/src-noconflict/ace';
import 'ace-builds/src-noconflict/ext-language_tools';
import 'ace-builds/src-noconflict/ext-searchbox';
import 'ace-builds/src-noconflict/mode-css';
import 'ace-builds/src-noconflict/mode-html';
import 'ace-builds/src-noconflict/mode-ini';
import 'ace-builds/src-noconflict/mode-javascript';
import 'ace-builds/src-noconflict/mode-json';
import 'ace-builds/src-noconflict/mode-php';
import 'ace-builds/src-noconflict/mode-text';
import 'ace-builds/src-noconflict/mode-yaml';
import 'ace-builds/src-noconflict/theme-textmate';
import 'ace-builds/src-noconflict/theme-tomorrow_night';
import { THEME_EVENT, currentTheme } from '../lib/panel.jsx';

/* Subscribe to the active theme without owning it. */
export function useThemeName() {
  const [theme, setTheme] = useState(currentTheme);
  useEffect(() => {
    const handler = event => setTheme(event.detail);
    document.addEventListener(THEME_EVENT, handler);
    return () => document.removeEventListener(THEME_EVENT, handler);
  }, []);
  return theme;
}

export const EDITOR_FONT_FAMILY = "Consolas, 'SFMono-Regular', 'Liberation Mono', Menlo, monospace";

export function aceModeName(mode) {
  if (mode === 'PHP') return 'php';
  if (mode === 'JavaScript') return 'javascript';
  if (mode === 'CSS') return 'css';
  if (mode === 'HTML') return 'html';
  if (mode === 'JSON') return 'json';
  if (mode === 'YAML') return 'yaml';
  if (mode === 'Config') return 'ini'; // .env, .htaccess, .ini, .conf -> Ace's ini mode
  return 'text';
}

export const ACE_THEMES = { light: 'ace/theme/textmate', dark: 'ace/theme/tomorrow_night' };

export const aceThemeFor = theme => ACE_THEMES[theme] || ACE_THEMES.light;

export default function CodeEditor({ value, mode, disabled, onChange, onCursorChange }) {
  const hostRef = useRef(null);
  const editorRef = useRef(null);
  const suppressChangeRef = useRef(false);
  const onChangeRef = useRef(onChange);
  const onCursorChangeRef = useRef(onCursorChange);
  const themeName = useThemeName();
  const themeRef = useRef(themeName);

  useEffect(() => { onChangeRef.current = onChange; }, [onChange]);
  useEffect(() => { onCursorChangeRef.current = onCursorChange; }, [onCursorChange]);
  useEffect(() => {
    themeRef.current = themeName;
    editorRef.current?.setTheme(aceThemeFor(themeName));
  }, [themeName]);

  useEffect(() => {
    if (!hostRef.current) return undefined;
    const editor = ace.edit(hostRef.current, {
      mode: `ace/mode/${aceModeName(mode)}`,
      theme: aceThemeFor(themeRef.current),
      value: value || '',
      readOnly: !!disabled,
      showPrintMargin: false,
      highlightActiveLine: true,
      fontSize: 13,
      tabSize: 2,
      useSoftTabs: true,
      wrap: false,
      selectionStyle: 'text',
    });

    editor.setOptions({
      enableBasicAutocompletion: true,
      enableLiveAutocompletion: true,
      enableMatchBrackets: true,
      enableSnippets: false,
      fontFamily: EDITOR_FONT_FAMILY,
    });
    editor.session.setUseWorker(false);
    editor.session.setNewLineMode('unix');

    let destroyed = false;
    const reportCursor = () => {
      if (destroyed || !editorRef.current || !onCursorChangeRef.current) return;
      const pos = editorRef.current.getCursorPosition();
      onCursorChangeRef.current({ line: pos.row + 1, column: pos.column + 1 });
    };
    const handleChange = () => {
      if (destroyed || !editorRef.current) return;
      if (!suppressChangeRef.current) {
        if (onChangeRef.current) onChangeRef.current(editorRef.current.getValue());
      }
      // Only report cursor on explicit cursor moves, not on every content change
    };

    editor.session.on('change', handleChange);
    editor.selection.on('changeCursor', reportCursor);
    editorRef.current = editor;
    reportCursor();

    return () => {
      destroyed = true;
      editor.session.off('change', handleChange);
      editor.selection.off('changeCursor', reportCursor);
      editor.destroy();
      editorRef.current = null;
      if (hostRef.current) hostRef.current.textContent = '';
    };
  }, []);

  useEffect(() => {
    const editor = editorRef.current;
    if (!editor) return;
    const nextValue = value || '';
    if (nextValue === editor.getValue()) return;
    const cursor = editor.getCursorPosition();
    suppressChangeRef.current = true;
    editor.setValue(nextValue, -1);
    const newRow = Math.max(0, Math.min(cursor.row, editor.session.getLength() - 1));
    editor.moveCursorTo(newRow, cursor.column);
    suppressChangeRef.current = false;
  }, [value]);

  useEffect(() => {
    const editor = editorRef.current;
    if (!editor) return;
    editor.session.setMode(`ace/mode/${aceModeName(mode)}`);
  }, [mode]);

  useEffect(() => {
    const editor = editorRef.current;
    if (!editor) return;
    editor.setReadOnly(!!disabled);
  }, [disabled]);

  return <div className="code-editor-host" ref={hostRef}></div>;
}
