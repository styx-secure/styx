// Inline SVG icons. Stroke uses currentColor; no external assets.
const base = (props) => ({
  width: props.size || 20,
  height: props.size || 20,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: props.sw || 1.9,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
});

export const ShieldCheck = (p) => (
  <svg {...base(p)}><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
);
export const Lock = (p) => (
  <svg {...base(p)}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 018 0v3" /></svg>
);
export const Search = (p) => (
  <svg {...base(p)}><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.2-3.2" /></svg>
);
export const Plus = (p) => (
  <svg {...base(p)}><path d="M12 5v14M5 12h14" /></svg>
);
export const Gear = (p) => (
  <svg {...base(p)}><circle cx="12" cy="12" r="3.2" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1" /></svg>
);
export const Sun = (p) => (
  <svg {...base(p)}><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M19.1 4.9l-1.4 1.4M6.3 17.7l-1.4 1.4" /></svg>
);
export const Moon = (p) => (
  <svg {...base(p)}><path d="M21 12.8A8.5 8.5 0 1111.2 3a6.6 6.6 0 009.8 9.8z" /></svg>
);
export const Back = (p) => (
  <svg {...base(p)}><path d="M15 5l-7 7 7 7" /></svg>
);
export const Paperplane = (p) => (
  <svg {...base(p)}><path d="M21 3L10.5 13.5M21 3l-6.5 18-4-8-8-4L21 3z" /></svg>
);
export const Clock = (p) => (
  <svg {...base(p)}><circle cx="12" cy="12" r="8" /><path d="M12 8v4l3 2" /></svg>
);
export const Check = (p) => (
  <svg {...base(p)}><path d="M5 13l4 4L19 7" /></svg>
);
export const DoubleCheck = (p) => (
  <svg {...base(p)}><path d="M2 13l4 4 8.5-9" /><path d="M11 17l1.5 1.5L21 8" /></svg>
);
export const Warning = (p) => (
  <svg {...base(p)}><path d="M12 4l9 16H3l9-16z" /><path d="M12 10v4M12 17.5v.5" /></svg>
);
export const Close = (p) => (
  <svg {...base(p)}><path d="M6 6l12 12M18 6L6 18" /></svg>
);
export const Copy = (p) => (
  <svg {...base(p)}><rect x="9" y="9" width="11" height="11" rx="2" /><path d="M5 15V5a2 2 0 012-2h8" /></svg>
);
export const Trash = (p) => (
  <svg {...base(p)}><path d="M4 7h16M9 7V5a1 1 0 011-1h4a1 1 0 011 1v2M6 7l1 13h10l1-13" /></svg>
);
export const QrFrame = (p) => (
  <svg {...base(p)}><path d="M4 8V5a1 1 0 011-1h3M16 4h3a1 1 0 011 1v3M20 16v3a1 1 0 01-1 1h-3M8 20H5a1 1 0 01-1-1v-3" /></svg>
);
