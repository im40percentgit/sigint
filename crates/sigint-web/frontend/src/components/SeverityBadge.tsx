/**
 * SeverityBadge — inline severity label using the theme badge classes.
 */

import { h } from "preact";

interface SeverityBadgeProps {
  severity: string;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return (
    <span class={`badge badge-${severity.toLowerCase()}`}>
      {severity}
    </span>
  );
}
