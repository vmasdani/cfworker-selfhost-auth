import { useEffect, useRef, useState } from "preact/hooks";
import { decodeImageFile, drawToCanvas, getDecoder } from "../lib/qr.ts";

interface Props {
	/** Called for every decoded QR value. Return true to stop scanning. */
	onResult: (value: string) => boolean | void;
	hint?: string;
}

/** Camera QR scanner with an image-file fallback. Video never leaves the device. */
export function QrScanner({ onResult, hint }: Props) {
	const video = useRef<HTMLVideoElement>(null);
	const [camera, setCamera] = useState<"off" | "starting" | "on">("off");
	const [error, setError] = useState<string | null>(null);
	const onResultRef = useRef(onResult);
	onResultRef.current = onResult;
	const stopRef = useRef<() => void>(() => {});

	useEffect(() => () => stopRef.current(), []);

	async function startCamera() {
		setError(null);
		if (!navigator.mediaDevices?.getUserMedia) return setError("Camera is not available in this browser. Upload an image instead.");
		setCamera("starting");
		let stream: MediaStream;
		try {
			stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
		} catch {
			setCamera("off");
			return setError("Camera permission denied or no camera found. Upload an image instead.");
		}
		const v = video.current!;
		v.srcObject = stream;
		await v.play().catch(() => {});
		setCamera("on");

		const decode = await getDecoder();
		const canvas = document.createElement("canvas");
		let stopped = false;
		let last = "";
		const stop = () => {
			stopped = true;
			for (const t of stream.getTracks()) t.stop();
			v.srcObject = null;
			setCamera("off");
		};
		stopRef.current = stop;
		const tick = async () => {
			if (stopped) return;
			if (v.readyState >= 2 && v.videoWidth) {
				const value = await decode(drawToCanvas(v, v.videoWidth, v.videoHeight, canvas, 800)).catch(() => null);
				if (value && value !== last) {
					last = value;
					navigator.vibrate?.(30);
					if (onResultRef.current(value)) return stop();
				}
			}
			setTimeout(tick, 200);
		};
		void tick();
	}

	async function onFile(e: Event) {
		const input = e.currentTarget as HTMLInputElement;
		const files = [...(input.files ?? [])];
		input.value = "";
		setError(null);
		let found = 0;
		for (const f of files) {
			try {
				const value = await decodeImageFile(f);
				if (value) {
					found++;
					if (onResultRef.current(value)) break;
				}
			} catch {
				// unreadable image; reported below
			}
		}
		if (!found) setError("No QR code found in the image.");
	}

	return (
		<div class="scanner">
			<video ref={video} class={camera === "on" ? "" : "hidden"} playsInline muted />
			{hint && <p class="hint">{hint}</p>}
			<div class="actions">
				{camera === "on" ? (
					<button type="button" onClick={() => stopRef.current()}>Stop camera</button>
				) : (
					<button type="button" class="primary" onClick={startCamera} disabled={camera === "starting"}>
						{camera === "starting" ? "Starting…" : "Scan with camera"}
					</button>
				)}
				<label class="button">
					Upload image
					<input type="file" accept="image/*" multiple hidden onChange={onFile} />
				</label>
			</div>
			{error && <p class="error">{error}</p>}
		</div>
	);
}
