import { render } from "preact";
import { App } from "./App.tsx";
import "./styles.css";

render(<App />, document.getElementById("app")!);

if (import.meta.env.PROD && "serviceWorker" in navigator) {
	window.addEventListener("load", () => {
		navigator.serviceWorker.register("/sw.js").catch((err) => console.error("Service worker registration failed", err));
	});
}
