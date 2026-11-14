// Generates the Coffer logo (SVG) and icon PNGs into public/.
// Run: bun run icons   (re-run after changing the design; outputs are committed)
//
// Design: a strongbox. Domed lid, banded body, and a keyhole plate on the front.

import { Resvg } from "@resvg/resvg-js";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const OUT = join(import.meta.dir, "..", "public");
const f = (n: number) => n.toFixed(2);

function art(): string {
	return `
	<path d="M112 214 Q112 132 194 132 H318 Q400 132 400 214 V226 H112 Z" fill="url(#gold)"/>
	<path d="M112 214 Q112 132 194 132 H318 Q400 132 400 214" fill="none" stroke="#fde68a" stroke-opacity="0.55" stroke-width="6"/>
	<rect x="112" y="238" width="288" height="150" rx="22" fill="url(#gold)"/>
	<rect x="172" y="132" width="26" height="256" fill="#78350f" fill-opacity="0.35"/>
	<rect x="314" y="132" width="26" height="256" fill="#78350f" fill-opacity="0.35"/>
	<rect x="214" y="204" width="84" height="108" rx="18" fill="#1c1408" stroke="#fde68a" stroke-width="6"/>
	<circle cx="256" cy="246" r="15" fill="#fbbf24"/>
	<path d="M248 254 L242 286 Q241 292 247 292 H265 Q271 292 270 286 L264 254 Z" fill="#fbbf24"/>`;
}

const defs = `
	<defs>
		<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
			<stop offset="0" stop-color="#0f1b33"/>
			<stop offset="1" stop-color="#3a230a"/>
		</linearGradient>
		<linearGradient id="gold" x1="0" y1="0" x2="0" y2="1">
			<stop offset="0" stop-color="#fcd34d"/>
			<stop offset="1" stop-color="#d97706"/>
		</linearGradient>
	</defs>`;

/** `rounded`: transparent corners (purpose "any"). Otherwise full-bleed square; `scale` shrinks art into the maskable safe zone. */
function svg({ rounded, scale = 1 }: { rounded: boolean; scale?: number }): string {
	const bg = rounded ? `<rect width="512" height="512" rx="112" fill="url(#bg)"/>` : `<rect width="512" height="512" fill="url(#bg)"/>`;
	const t = 256 * (1 - scale);
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">${defs}
	${bg}
	<g transform="translate(${f(t)} ${f(t)}) scale(${scale})">${art()}
	</g>
</svg>
`;
}

function png(source: string, size: number, file: string) {
	writeFileSync(join(OUT, file), new Resvg(source, { fitTo: { mode: "width", value: size } }).render().asPng());
	console.log(`${file} ${size}x${size}`);
}

const any = svg({ rounded: true });
writeFileSync(join(OUT, "icon.svg"), any);
console.log("icon.svg");
png(any, 192, "icon-192.png");
png(any, 512, "icon-512.png");
png(svg({ rounded: false, scale: 0.92 }), 180, "apple-touch-icon.png");
png(any, 32, "favicon-32.png");
