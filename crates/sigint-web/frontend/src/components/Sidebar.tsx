/**
 * Sidebar — collapsible icon rail navigation.
 *
 * 48px wide when collapsed, expands to 200px on hover via CSS transition.
 * Nav items use Unicode characters as icons — no icon font dependency.
 * Active route is highlighted with the accent colour.
 *
 * @decision DEC-WEB-025
 * @title Sidebar uses CSS hover expansion (48px → 200px) with no JS state
 * @status accepted
 * @rationale Pure CSS transition on width avoids a useState toggle and
 * re-render on every hover; the inner container is fixed at 200px so text
 * is always laid out correctly and simply clipped by the overflow:hidden
 * parent during collapse.
 */

import { h } from "preact";

interface NavItem {
  icon: string;
  label: string;
  href: string;
}

const NAV_ITEMS: NavItem[] = [
  { icon: "⊞", label: "Dashboard",  href: "#/"                },
  { icon: "⊕", label: "New Scan",   href: "#/scan/new"        },
  { icon: "≡", label: "Sessions",   href: "#/sessions"        },
  { icon: "⎙", label: "Reports",    href: "#/reports"         },
  { icon: "⊟", label: "Diff",       href: "#/diff"            },
  { icon: "◈", label: "Models",     href: "#/models"          },
  { icon: "≈", label: "Evaluate",   href: "#/train/evaluate"  },
  { icon: "⚙", label: "Settings",   href: "#/settings"        },
];

interface SidebarProps {
  currentHash: string;
}

function isActive(href: string, currentHash: string): boolean {
  if (href === "#/") {
    return currentHash === "" || currentHash === "#/" || currentHash === "#";
  }
  return currentHash.startsWith(href);
}

export function Sidebar({ currentHash }: SidebarProps) {
  return (
    <nav class="sidebar">
      <div class="sidebar-inner">
        {NAV_ITEMS.map(item => (
          <a
            key={item.href}
            href={item.href}
            class={`sidebar-item${isActive(item.href, currentHash) ? " sidebar-item--active" : ""}`}
            title={item.label}
          >
            <span class="sidebar-icon">{item.icon}</span>
            <span class="sidebar-label">{item.label}</span>
          </a>
        ))}
      </div>
      <style>{`
        .sidebar {
          width: var(--sidebar-collapsed);
          min-width: var(--sidebar-collapsed);
          background-color: var(--surface);
          border-right: 1px solid var(--border);
          overflow: hidden;
          transition: width var(--transition-mid);
          flex-shrink: 0;
        }
        .sidebar:hover {
          width: var(--sidebar-expanded);
        }
        .sidebar-inner {
          display: flex;
          flex-direction: column;
          padding: 8px 0;
          width: var(--sidebar-expanded);
        }
        .sidebar-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 10px 14px;
          color: var(--text-secondary);
          text-decoration: none;
          white-space: nowrap;
          transition: background-color var(--transition-fast), color var(--transition-fast);
          border-left: 2px solid transparent;
        }
        .sidebar-item:hover {
          background-color: rgba(255,255,255,0.05);
          color: var(--text);
          text-decoration: none;
        }
        .sidebar-item--active {
          color: var(--accent);
          border-left-color: var(--accent);
          background-color: rgba(88,166,255,0.08);
        }
        .sidebar-icon {
          font-size: 16px;
          width: 20px;
          text-align: center;
          flex-shrink: 0;
        }
        .sidebar-label {
          font-size: 13px;
          font-weight: 500;
        }
      `}</style>
    </nav>
  );
}
