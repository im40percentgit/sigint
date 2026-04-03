/**
 * Application entry point.
 *
 * Imports the theme CSS (esbuild extracts it to app.css alongside app.js),
 * renders the App component into #app, and connects the WebSocket manager.
 */

import "./theme.css";
import { h, render } from "preact";
import { App } from "./app";
import { wsManager } from "./ws";

const root = document.getElementById("app");
if (root) {
  render(<App />, root);
  wsManager.connect();
}
