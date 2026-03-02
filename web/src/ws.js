// ws.js — WebSocket connection with auto-reconnect for the SIGINT event stream.
//
// @decision DEC-WEB-003
// @title Native WebSocket with exponential-backoff reconnect, no external library
// @status accepted
// @rationale The /ws/events endpoint is a simple event stream. A raw WebSocket
// with manual reconnect logic is ~50 lines and avoids adding a socket.io or
// similar dependency. Exponential backoff (capped at 30 s) prevents hammering
// the server when it restarts. Subscribers receive parsed event objects; the
// connection lifecycle is managed internally.

const WS_URL = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/events`;

const MIN_DELAY = 1000;
const MAX_DELAY = 30_000;

/**
 * Create a managed WebSocket connection to /ws/events.
 *
 * Returns a handle with:
 *   - subscribe(fn)   — add a listener; returns unsubscribe fn
 *   - status()        — 'connecting' | 'connected' | 'disconnected'
 *   - close()         — permanently close (no reconnect)
 */
export function createWsConnection() {
  const listeners = new Set();
  let ws = null;
  let delay = MIN_DELAY;
  let closed = false;
  let currentStatus = 'disconnected';

  function connect() {
    if (closed) return;
    currentStatus = 'connecting';
    notifyStatus();

    ws = new WebSocket(WS_URL);

    ws.addEventListener('open', () => {
      delay = MIN_DELAY;
      currentStatus = 'connected';
      notifyStatus();
    });

    ws.addEventListener('message', (evt) => {
      try {
        const data = JSON.parse(evt.data);
        listeners.forEach(fn => fn({ type: 'event', data }));
      } catch {
        // Ignore malformed frames
      }
    });

    ws.addEventListener('close', () => {
      if (closed) return;
      currentStatus = 'disconnected';
      notifyStatus();
      const d = delay;
      delay = Math.min(delay * 2, MAX_DELAY);
      setTimeout(connect, d);
    });

    ws.addEventListener('error', () => {
      // Error always followed by close; no extra action needed
    });
  }

  function notifyStatus() {
    listeners.forEach(fn => fn({ type: 'status', status: currentStatus }));
  }

  function subscribe(fn) {
    listeners.add(fn);
    // Immediately deliver current status so new subscribers know the state
    fn({ type: 'status', status: currentStatus });
    return () => listeners.delete(fn);
  }

  function status() { return currentStatus; }

  function close() {
    closed = true;
    if (ws) ws.close();
  }

  connect();
  return { subscribe, status, close };
}
