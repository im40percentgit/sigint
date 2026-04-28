/**
 * DataTable — generic sortable table component.
 *
 * Supports click-to-sort on any column header (asc → desc → asc cycle)
 * and an optional row click handler for navigation.
 *
 * Row-selection is optional and fully controlled: callers supply a
 * `rowSelection` prop with the current Set of selected IDs and an onChange
 * callback. When `rowSelection` is omitted the component behaves exactly as
 * before (backward compatible).
 *
 * @decision DEC-WEB-028
 * @title DataTable generic over T with Column render prop for cell customisation
 * @status accepted
 * @rationale Generic table avoids duplicating sort/click logic across all
 * list views (sessions, findings, assets, scans). Column.render? allows
 * per-cell JSX overrides (severity badges, links, formatted dates) while
 * defaulting to String(value) for simple cases. TypeScript generics give
 * compile-time safety on the key and render props.
 *
 * @decision REQ-P26-P1-002
 * @title Row-selection is opt-in, controlled, and "select all visible" scoped
 * @status accepted
 * @rationale
 *   1. Optional / back-compat: existing callers pass no `rowSelection` prop
 *      so the checkbox column never appears for them. No existing table breaks.
 *   2. Controlled component: selection state lives in the parent (Sessions.tsx).
 *      DataTable is a pure view — it fires onChange and the parent decides what
 *      to do. This matches how form elements work in React/Preact and keeps
 *      DataTable free of business logic.
 *   3. "Select all visible" not "select all matching": DataTable only knows
 *      about the rows currently rendered (after sort). A cross-page or
 *      filter-crossing "select all" would require the parent to propagate
 *      query state here, coupling layers that should be separate. Visible-only
 *      is the right default — no surprise bulk actions.
 */

import { h } from "preact";
import { useState } from "preact/hooks";

export interface Column<T> {
  key: keyof T & string;
  label: string;
  /** Optional tooltip shown on the column header <th>. */
  headerTitle?: string;
  render?: (value: T[keyof T], row: T) => h.JSX.Element;
}

/**
 * Controlled row-selection descriptor.
 * When provided, DataTable renders a checkbox column as the first column.
 */
export interface RowSelectionProps<T> {
  /** The current set of selected row IDs. */
  selectedIds: Set<string>;
  /** Called whenever the selection changes (after user interaction). */
  onChange: (selectedIds: Set<string>) => void;
  /** Extracts a stable string ID from a row. */
  getRowId: (row: T) => string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (row: T) => void;
  /** Optional controlled row-selection. Omit to disable checkboxes entirely. */
  rowSelection?: RowSelectionProps<T>;
}

type SortDir = "asc" | "desc";

export function DataTable<T extends object>({
  columns,
  data,
  onRowClick,
  rowSelection,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<keyof T | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  function handleHeaderClick(key: keyof T) {
    if (sortKey === key) {
      setSortDir(d => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  }

  const sorted = sortKey
    ? [...data].sort((a, b) => {
        const av = a[sortKey];
        const bv = b[sortKey];
        const cmp =
          av === null || av === undefined ? -1
          : bv === null || bv === undefined ? 1
          : String(av).localeCompare(String(bv), undefined, { numeric: true });
        return sortDir === "asc" ? cmp : -cmp;
      })
    : data;

  // ── Selection helpers ──────────────────────────────────────────────────────

  const allVisibleIds: string[] = rowSelection
    ? sorted.map(row => rowSelection.getRowId(row))
    : [];

  const visibleCount = allVisibleIds.length;
  const allSelected =
    visibleCount > 0 &&
    allVisibleIds.every(id => rowSelection!.selectedIds.has(id));
  const someSelected =
    rowSelection !== undefined &&
    rowSelection.selectedIds.size > 0 &&
    !allSelected;

  function handleHeaderCheckbox() {
    if (!rowSelection) return;
    if (allSelected) {
      // Deselect all visible rows
      const next = new Set(rowSelection.selectedIds);
      for (const id of allVisibleIds) next.delete(id);
      rowSelection.onChange(next);
    } else {
      // Select all visible rows
      const next = new Set(rowSelection.selectedIds);
      for (const id of allVisibleIds) next.add(id);
      rowSelection.onChange(next);
    }
  }

  function handleRowCheckbox(id: string, checked: boolean) {
    if (!rowSelection) return;
    const next = new Set(rowSelection.selectedIds);
    if (checked) {
      next.add(id);
    } else {
      next.delete(id);
    }
    rowSelection.onChange(next);
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  const totalCols = columns.length + (rowSelection ? 1 : 0);

  return (
    <div class="datatable-wrap">
      <table>
        <thead>
          <tr>
            {rowSelection && (
              <th
                class="datatable-select-col"
                aria-label={allSelected ? "Deselect all" : "Select all visible"}
              >
                <input
                  type="checkbox"
                  checked={allSelected}
                  ref={(el: HTMLInputElement | null) => {
                    // indeterminate must be set as a DOM property, not an attribute
                    if (el) el.indeterminate = someSelected;
                  }}
                  onChange={handleHeaderCheckbox}
                  onClick={(e) => e.stopPropagation()}
                  style={{ accentColor: "var(--accent)", cursor: "pointer" }}
                  aria-label={
                    allSelected
                      ? "Deselect all"
                      : someSelected
                      ? "Select all visible (some selected)"
                      : "Select all visible"
                  }
                />
              </th>
            )}
            {columns.map(col => (
              <th
                key={col.key}
                onClick={() => handleHeaderClick(col.key)}
                title={col.headerTitle}
                aria-sort={
                  sortKey === col.key
                    ? sortDir === "asc" ? "ascending" : "descending"
                    : "none"
                }
              >
                {col.label}
                {sortKey === col.key && (
                  <span class="datatable-sort-icon">
                    {sortDir === "asc" ? " ↑" : " ↓"}
                  </span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 ? (
            <tr>
              <td
                colspan={totalCols}
                style={{ textAlign: "center", color: "var(--text-secondary)", padding: "24px" }}
              >
                No data
              </td>
            </tr>
          ) : (
            sorted.map((row, i) => {
              const rowId = rowSelection
                ? rowSelection.getRowId(row)
                : String(i);
              const isSelected = rowSelection
                ? rowSelection.selectedIds.has(rowId)
                : false;
              return (
                <tr
                  key={i}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  style={{
                    ...(onRowClick ? { cursor: "pointer" } : {}),
                    ...(isSelected
                      ? {
                          background:
                            "var(--datatable-selected-bg, rgba(88,166,255,0.08))",
                        }
                      : {}),
                  }}
                  class={isSelected ? "datatable-row-selected" : undefined}
                >
                  {rowSelection && (
                    <td
                      class="datatable-select-col"
                      onClick={(e) => {
                        // Prevent row-click navigation from firing when checking
                        e.stopPropagation();
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={(e) => {
                          e.stopPropagation();
                          handleRowCheckbox(
                            rowId,
                            (e.target as HTMLInputElement).checked
                          );
                        }}
                        style={{ accentColor: "var(--accent)", cursor: "pointer" }}
                        aria-label={`Select row ${rowId}`}
                      />
                    </td>
                  )}
                  {columns.map(col => (
                    <td key={col.key}>
                      {col.render
                        ? col.render(row[col.key], row)
                        : <span>{String(row[col.key] ?? "")}</span>
                      }
                    </td>
                  ))}
                </tr>
              );
            })
          )}
        </tbody>
      </table>
      <style>{`
        .datatable-wrap {
          overflow-x: auto;
          border: 1px solid var(--border);
          border-radius: var(--radius-md);
        }
        .datatable-wrap table {
          border-radius: 0;
        }
        .datatable-sort-icon {
          color: var(--accent);
          font-size: 11px;
        }
        .datatable-select-col {
          width: 36px;
          text-align: center;
          padding-left: 8px;
          padding-right: 4px;
        }
        .datatable-row-selected {
          background: var(--datatable-selected-bg, rgba(88,166,255,0.08)) !important;
        }
      `}</style>
    </div>
  );
}
