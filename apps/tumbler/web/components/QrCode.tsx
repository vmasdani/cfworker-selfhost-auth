import { useMemo } from "preact/hooks";
import { encode } from "uqr";

/** QR code as inline SVG (no network, no canvas). */
export function QrCode({ value, label }: { value: string; label: string }) {
	const { path, size } = useMemo(() => {
		const qr = encode(value, { ecc: "M", border: 2 });
		let d = "";
		qr.data.forEach((row, y) => row.forEach((on, x) => { if (on) d += `M${x} ${y}h1v1h-1z`; }));
		return { path: d, size: qr.size };
	}, [value]);
	return (
		<svg class="qr" viewBox={`0 0 ${size} ${size}`} role="img" aria-label={label} shape-rendering="crispEdges">
			<rect width={size} height={size} fill="#fff" />
			<path d={path} fill="#000" />
		</svg>
	);
}
