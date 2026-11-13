// Generates the Tumbler logo (SVG) and PWA icon PNGs into public/.
// Run: bun run icons   (re-run after changing the design; outputs are committed)
//
// Design: a combination-lock dial. Six ring segments = six code digits, and the
// dimmed segments read as the TOTP countdown. A pointer marks the dial top;
// a keyhole sits in the middle.

import { Resvg } from "@resvg/resvg-js";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const OUT = join(import.meta.dir, "..", "public");

const R = 150; // ring radius
const STROKE = 34;
const C = 2 * Math.PI * R;
const GAP = 22;
const DASH = C / 6 - GAP;
const f = (n: number) => n.toFixed(2);
const ROTATE = -90 + ((GAP / C) * 360) / 2; // centre a gap under the pointer

function art(): string {
	const bright = `${f(DASH)} ${GAP} `.repeat(3) + `${f(DASH)} ${f(C - (4 * DASH + 3 * GAP))}`;
	return `
	<circle cx="256" cy="256" r="${R}" fill="none" stroke="#34d399" stroke-opacity="0.26" stroke-width="${STROKE}"
		stroke-dasharray="${f(DASH)} ${GAP}" transform="rotate(${f(ROTATE)} 256 256)"/>
	<circle cx="256" cy="256" r="${R}" fill="none" stroke="url(#ring)" stroke-width="${STROKE}"
		stroke-dasharray="${bright}" transform="rotate(${f(ROTATE)} 256 256)"/>
	<path d="M256 58 L272 84 H240 Z" fill="#ecfdf5" stroke="#ecfdf5" stroke-width="6" stroke-linejoin="round"/>
	<circle cx="256" cy="236" r="36" fill="#ecfdf5"/>
	<path d="M236 252 L222 318 Q221 326 229 326 H283 Q291 326 290 318 L276 252 Z" fill="#ecfdf5"/>`;
}

const defs = `
	<defs>
		<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
			<stop offset="0" stop-color="#0f1b33"/>
			<stop offset="1" stop-color="#0a3a2e"/>
		</linearGradient>
		<linearGradient id="ring" x1="0" y1="0" x2="1" y2="1">
			<stop offset="0" stop-color="#6ee7b7"/>
			<stop offset="1" stop-color="#10b981"/>
		</linearGradient>
	</defs>`;

/** `rounded`: transparent corners (purpose "any"). Otherwise full-bleed square; `scale` shrinks art into the maskable safe zone. */
function svg({ rounded, scale = 1 }: { rounded: boolean; scale?: number }): string {
	const bg = rounded
		? `<rect width="512" height="512" rx="112" fill="url(#bg)"/>`
		: `<rect width="512" height="512" fill="url(#bg)"/>`;
	const t = 256 * (1 - scale);
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">${defs}
	${bg}
	<g transform="translate(${f(t)} ${f(t)}) scale(${scale})">${art()}
	</g>
</svg>
`;
}

function png(source: string, size: number, file: string) {
	const out = new Resvg(source, { fitTo: { mode: "width", value: size } }).render().asPng();
	writeFileSync(join(OUT, file), out);
	console.log(`${file} ${size}x${size}`);
}

const any = svg({ rounded: true });
const full = svg({ rounded: false, scale: 0.92 });
// Maskable safe zone is a circle of radius 40% of the size; art outer radius is ~200/256, so scale to fit.
const maskable = svg({ rounded: false, scale: 0.78 });

writeFileSync(join(OUT, "icon.svg"), any);
console.log("icon.svg");
png(any, 192, "icon-192.png");
png(any, 512, "icon-512.png");
png(maskable, 512, "icon-maskable-512.png");
png(full, 180, "apple-touch-icon.png");
png(any, 32, "favicon-32.png");
