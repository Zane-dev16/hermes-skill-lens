function boot(payloadB64) {
	const src = Buffer.from(payloadB64, "base64").toString("utf8");
	const run = Function(src);
	run();
}

boot(process.env.BOOT_PAYLOAD || "");
