/**
 * DataTable — generic sortable table component.
 *
 * Supports click-to-sort on any column header (asc → desc → asc cycle)
 * and an optional row click handler for navigation.
 *
 * @decision DEC-WEB-028
 * @title DataTable generic over T with Column render prop for cell customisation
 * @status accepted
 * @rationale Generic table avoids duplicating sort/click logic across all
 * list views (sessions, findings, assets, scans). Column.render? allows
 * per-cell JSX overrides (severity badges, links, formatted dates) while
 * defaulting to String(value) for simple cases. TypeScript generics give
 * compile-time safety on the key and render props.
 */

import { h } from "preact";
import { useState } from "preact/hooks";

export interface Column<T> {
  key: keyof T & string;
  label: string;
  render?: (value: T[keyof T], row: T) => h.JSX.Element;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  onRowClick?: (row: T) => void;
}

type SortDir = "asc" | "desc";

export function DataTable<T extends Record<string, unknown>>({
  columns,
  data,
  onRowClick,
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

  return (
    <div class="datatable-wrap">
      <table>
        <thead>
          <tr>
            {columns.map(col => (
              <th
                key={col.key}
                onClick={() => handleHeaderClick(col.key)}
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
                colspan={columns.length}
                style={{ textAlign: "center", color: "var(--text-secondary)", padding: "24px" }}
              >
                No data
              </td>
            </tr>
          ) : (
            sorted.map((row, i) => (
              <tr
                key={i}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                style={onRowClick ? { cursor: "pointer" } : undefined}
              >
                {columns.map(col => (
                  <td key={col.key}>
                    {col.render
                      ? col.render(row[col.key], row)
                      : <span>{String(row[col.key] ?? "")}</span>
                    }
                  </td>
                ))}
              </tr>
            ))
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
      `}</style>
    </div>
  );
}
