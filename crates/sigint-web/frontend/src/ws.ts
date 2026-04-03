/**
 * WebSocketManager — singleton WebSocket client for the SIGINT event stream.
 *
 * Connects to ws://{host}/ws/events. Subscribers receive typed WsEvent
 * objects. Auto-reconnects on close with a 3-second delay.
 *
 * Usage:
 *   wsManager.connect();
 *   const unsub = wsManager.subscribe(event => { ... });
 *   // later:
 *   unsub();
 *
 * @decision DEC-WEB-023
 * @title WebSocketManager singleton with auto-reconnect and subscribe/unsubscribe pattern
 * @status accepted
 * @rationale A singleton prevents multiple WS connections from different
 * components; subscribe returns an unsubscribe function matching Preact's
 * useEffect cleanup convention; 3s reconnect delay avoids reconnect storms
 * on server restart or network blip.
 */

import type { WsEvent, ApprovalResponse } from "./types";

type EventHandler = (event: WsEvent) => void;

const RECONNECT_DELAY_MS = 3000;

class WebSocketManager {
  private ws: WebSocket | null = null;
  private handlers = new Set<EventHandler>();
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private _connected = false;
  private shouldReconnect = false;

  /** True when the WebSocket is open and ready. */
  get connected(): boolean {
    return this._connected;
  }

  /** Open the WebSocket connection. Idempotent — safe to call multiple times. */
  connect(): void {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }
    this.shouldReconnect = true;
    this.openSocket();
  }

  /** Close the connection and stop auto-reconnect. */
  disconnect(): void {
    this.shouldReconnect = false;
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this._connected = false;
  }

  /**
   * Register an event handler. Returns an unsubscribe function.
   * Designed to be used directly in Preact useEffect:
   *   useEffect(() => wsManager.subscribe(handler), []);
   */
  subscribe(handler: EventHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  /**
   * Send an approval response back to the server.
   * Serialized as JSON over the WebSocket.
   */
  send(data: ApprovalResponse): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }

  private openSocket(): void {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/ws/events`;

    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      this._connected = true;
      if (this.reconnectTimer !== null) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }
    };

    this.ws.onmessage = (evt: MessageEvent) => {
      try {
        const event = JSON.parse(evt.data as string) as WsEvent;
        this.handlers.forEach(h => h(event));
      } catch {
        // Ignore malformed frames
      }
    };

    this.ws.onclose = () => {
      this._connected = false;
      this.ws = null;
      if (this.shouldReconnect) {
        this.reconnectTimer = setTimeout(() => {
          this.reconnectTimer = null;
          this.openSocket();
        }, RECONNECT_DELAY_MS);
      }
    };

    this.ws.onerror = () => {
      // onclose fires immediately after onerror — reconnect handled there
      this._connected = false;
    };
  }
}

/** Singleton instance shared across the entire application. */
export const wsManager = new WebSocketManager();
