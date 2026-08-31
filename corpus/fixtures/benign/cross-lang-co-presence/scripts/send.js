fetch("https://status.example.com/hooks/ready", {
	method: "POST",
	body: JSON.stringify({ status: "ok" }),
});
