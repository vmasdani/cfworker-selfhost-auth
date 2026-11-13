import { ClaimError } from "../nodewarden.ts";

/** What public DNS (Cloudflare DoH) says, to spot a local resolver with stale or hijacked answers. */
async function publicA(host: string): Promise<string[]> {
	try {
		const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
			headers: { Accept: "application/dns-json" },
			signal: AbortSignal.timeout(8000),
		});
		const j = (await res.json()) as { Answer?: { type: number; data: string }[] };
		return (j.Answer ?? []).filter((a) => a.type === 1).map((a) => a.data);
	} catch {
		return [];
	}
}

async function localA(host: string): Promise<string[]> {
	try {
		return (await Bun.dns.lookup(host, { family: 4 })).map((r) => r.address);
	} catch {
		return [];
	}
}

/** New custom domains need DNS + a certificate; that can take a few minutes. */
export async function waitHealthy(url: string, path: string, log: (m: string) => void): Promise<void> {
	const deadline = Date.now() + 10 * 60_000;
	const host = new URL(url).hostname;
	let announced = false;
	let dnsChecked = false;
	while (Date.now() < deadline) {
		try {
			const res = await fetch(`${url}${path}`, { signal: AbortSignal.timeout(10_000) });
			if (res.ok) {
				log("✓ server is up");
				return;
			}
		} catch {
			// DNS or TLS not ready yet
		}
		if (!announced) {
			log("• waiting for the domain and certificate (can take a few minutes)…");
			announced = true;
		} else if (!dnsChecked) {
			dnsChecked = true;
			const [pub, loc] = await Promise.all([publicA(host), localA(host)]);
			if (pub.length && loc.length && !loc.some((ip) => pub.includes(ip))) {
				log(
					`⚠ This machine's DNS resolves ${host} to ${loc.join(", ")}, but public DNS says ${pub.join(", ")}.\n` +
						"  Your local resolver has a stale or wrong answer; the site itself may be fine. Point this machine at public DNS\n" +
						"  (e.g. `sudo resolvectl dns <interface> 1.1.1.1 1.0.0.1 && sudo resolvectl flush-caches`); I keep waiting.",
				);
			}
		}
		await Bun.sleep(5000);
	}
	throw new ClaimError(`${url} did not come up within 10 minutes. Re-run the installer later; it is safe to repeat.`);
}
