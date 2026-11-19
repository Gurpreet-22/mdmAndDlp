/**
 * Inline SVG icons.
 *
 * Hand-drawn rather than an icon package, for the same reason `styles.css` is
 * hand-written: this console is a handful of tables and forms, and an icon
 * library would add a dependency, a bundle and a licence to audit for the
 * dozen glyphs actually used. These are 24x24, 1.75px stroke, `currentColor`,
 * so an icon inherits the colour of whatever it sits in and a status pill
 * needs no icon-specific CSS at all.
 *
 * `aria-hidden` by default. Every icon in this app sits beside its own text
 * label, so announcing it would make a screen reader say everything twice.
 * Pass a `title` only for an icon that is genuinely the only content of a
 * control -- and prefer not to build those.
 */

export type IconName =
  | "devices"
  | "employees"
  | "enrollment"
  | "audit"
  | "admins"
  | "usb"
  | "shield"
  | "check"
  | "alert"
  | "cross"
  | "clock"
  | "download"
  | "copy"
  | "logout"
  | "external"
  | "lock"
  | "search"
  | "refresh"
  | "plus";

/** 24x24 path data, stroked with `currentColor`. */
const PATHS: Record<IconName, React.ReactNode> = {
  // A laptop: the device list.
  devices: (
    <>
      <rect x="3" y="4" width="18" height="12" rx="2" />
      <path d="M2 20h20" />
    </>
  ),
  employees: (
    <>
      <circle cx="9" cy="8" r="3.2" />
      <path d="M2.5 20a6.5 6.5 0 0 1 13 0" />
      <path d="M16 5.5a3 3 0 0 1 0 5.6" />
      <path d="M17.5 20a6.3 6.3 0 0 0-2-4.4" />
    </>
  ),
  // A ticket: a one-time enrollment token.
  enrollment: (
    <>
      <path d="M3 9.5V7a1 1 0 0 1 1-1h16a1 1 0 0 1 1 1v2.5a2.5 2.5 0 0 0 0 5V17a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-2.5a2.5 2.5 0 0 0 0-5Z" />
      <path d="M12 8.5v7" strokeDasharray="2 2" />
    </>
  ),
  audit: (
    <>
      <path d="M5 3h9l5 5v13a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z" />
      <path d="M14 3v5h5" />
      <path d="M8 13h8M8 17h5" />
    </>
  ),
  admins: (
    <>
      <circle cx="12" cy="8" r="3.4" />
      <path d="M5 20a7 7 0 0 1 14 0" />
    </>
  ),
  usb: (
    <>
      <path d="M12 21V6" />
      <path d="M12 3.5 10 6h4l-2-2.5Z" />
      <path d="M8 12.5v2.5l4 2" />
      <path d="M16 11v4l-4 2" />
      <circle cx="8" cy="11" r="1.2" />
      <rect x="14.6" y="8.6" width="2.8" height="2.8" rx="0.5" />
    </>
  ),
  shield: <path d="M12 3 5 6v5.5c0 4.3 2.9 7.8 7 9.5 4.1-1.7 7-5.2 7-9.5V6l-7-3Z" />,
  check: <path d="M4.5 12.5 9.5 17.5 19.5 7" />,
  alert: (
    <>
      <path d="M12 4.5 2.8 20h18.4L12 4.5Z" />
      <path d="M12 10v4.5" />
      <path d="M12 17.4h.01" />
    </>
  ),
  cross: <path d="M6 6l12 12M18 6 6 18" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 7.5V12l3 2" />
    </>
  ),
  download: (
    <>
      <path d="M12 3.5v11" />
      <path d="M7.5 10.5 12 15l4.5-4.5" />
      <path d="M4.5 19.5h15" />
    </>
  ),
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M15 6.5V5a1 1 0 0 0-1-1H5a1 1 0 0 0-1 1v9a1 1 0 0 0 1 1h1.5" />
    </>
  ),
  logout: (
    <>
      <path d="M15 4.5h3.5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1H15" />
      <path d="M11 8.5 7 12l4 3.5" />
      <path d="M7 12h8" />
    </>
  ),
  external: (
    <>
      <path d="M14 4.5h5.5V10" />
      <path d="M19 5 11.5 12.5" />
      <path d="M18 14v4.5a1 1 0 0 1-1 1H5.5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1H10" />
    </>
  ),
  lock: (
    <>
      <rect x="4.5" y="10.5" width="15" height="9.5" rx="2" />
      <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6.5" />
      <path d="M16 16l4 4" />
    </>
  ),
  refresh: (
    <>
      <path d="M20 12a8 8 0 1 1-2.6-5.9" />
      <path d="M20 4.5V10h-5.5" />
    </>
  ),
  plus: <path d="M12 5.5v13M5.5 12h13" />,
};

export function Icon({
  name,
  size = 18,
  title,
  className,
}: {
  name: IconName;
  size?: number;
  /** Supply only when the icon is the sole content of a control. */
  title?: string;
  className?: string;
}) {
  return (
    <svg
      className={className ? `icon ${className}` : "icon"}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      // Decorative unless it has been given a name.
      aria-hidden={title ? undefined : true}
      role={title ? "img" : undefined}
      focusable="false"
    >
      {title ? <title>{title}</title> : null}
      {PATHS[name]}
    </svg>
  );
}

export default Icon;
