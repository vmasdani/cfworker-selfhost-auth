// QR decoding: native BarcodeDetector when it supports QR, otherwise jsQR (loaded on demand).

interface DetectedBarcode {
	rawValue: string;
}
interface BarcodeDetectorLike {
	detect(source: CanvasImageSource | ImageData): Promise<DetectedBarcode[]>;
}
interface BarcodeDetectorCtor {
	new (opts: { formats: string[] }): BarcodeDetectorLike;
	getSupportedFormats(): Promise<string[]>;
}

type Decoder = (canvas: HTMLCanvasElement) => Promise<string | null>;

let decoderPromise: Promise<Decoder> | undefined;

async function makeDecoder(): Promise<Decoder> {
	const BD = (globalThis as { BarcodeDetector?: BarcodeDetectorCtor }).BarcodeDetector;
	if (BD) {
		try {
			if ((await BD.getSupportedFormats()).includes("qr_code")) {
				const detector = new BD({ formats: ["qr_code"] });
				return async (canvas) => (await detector.detect(canvas))[0]?.rawValue ?? null;
			}
		} catch {
			// fall through to jsQR
		}
	}
	const { default: jsQR } = await import("jsqr");
	return async (canvas) => {
		const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
		const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
		return jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" })?.data ?? null;
	};
}

export function getDecoder(): Promise<Decoder> {
	decoderPromise ??= makeDecoder();
	return decoderPromise;
}

/** Draw a source onto a canvas, downscaled so the long side is at most `max` px. */
export function drawToCanvas(
	source: CanvasImageSource,
	width: number,
	height: number,
	canvas = document.createElement("canvas"),
	max = 1024,
): HTMLCanvasElement {
	const scale = Math.min(1, max / Math.max(width, height));
	canvas.width = Math.max(1, Math.round(width * scale));
	canvas.height = Math.max(1, Math.round(height * scale));
	const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
	ctx.imageSmoothingEnabled = false;
	ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
	return canvas;
}

export async function decodeImageFile(file: File): Promise<string | null> {
	const bitmap = await createImageBitmap(file);
	try {
		const decode = await getDecoder();
		// Try full detail first, then a smaller copy (helps jsQR with huge screenshots).
		return (
			(await decode(drawToCanvas(bitmap, bitmap.width, bitmap.height, undefined, 2048))) ??
			(await decode(drawToCanvas(bitmap, bitmap.width, bitmap.height, undefined, 800)))
		);
	} finally {
		bitmap.close();
	}
}
