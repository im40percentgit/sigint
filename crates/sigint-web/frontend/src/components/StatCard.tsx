/**
 * StatCard — compact metric display card.
 *
 * Renders a labelled numeric or string value in a surface card.
 * Used on the Dashboard for session/finding/asset counts.
 */

import { h } from "preact";

interface StatCardProps {
  label: string;
  value: number | string;
  color?: string;
}

export function StatCard({ label, value, color }: StatCardProps) {
  return (
    <div class="card stat-card">
      <div class="stat-card-label">{label}</div>
      <div
        class="stat-card-value"
        style={color ? { color } : undefined}
      >
        {value}
      </div>
      <style>{`
        .stat-card {
          display: flex;
          flex-direction: column;
          gap: 6px;
          min-width: 120px;
        }
        .stat-card-label {
          font-size: 11px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.06em;
          color: var(--text-secondary);
        }
        .stat-card-value {
          font-size: 28px;
          font-weight: 700;
          color: var(--text);
          line-height: 1;
        }
      `}</style>
    </div>
  );
}
