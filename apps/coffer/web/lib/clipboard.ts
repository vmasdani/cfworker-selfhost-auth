let clearTimer: ReturnType<typeof setTimeout> | undefined;

/** Copy text, then clear the clipboard after `clearAfterSeconds` if it still holds our value. */
export async function copySecret(text: string, clearAfterSeconds: number): Promise<void> {
	await navigator.clipboard.writeText(text);
	clearTimeout(clearTimer);
	if (clearAfterSeconds <= 0) return;
	clearTimer = setTimeout(async () => {
		try {
			// Skip if the user copied something else meanwhile. If reading is not allowed, clear anyway.
			const current = await navigator.clipboard.readText().catch(() => text);
			if (current === text) await navigator.clipboard.writeText("");
		} catch {
			// Clipboard writes require focus; nothing more we can do.
		}
	}, clearAfterSeconds * 1000);
}
