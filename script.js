
const form = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const scanButton = document.getElementById("scanButton");
const statusText = document.getElementById("status");
const result = document.getElementById("result");

form.addEventListener("submit", async function (event) {
    event.preventDefault();

    const url = urlInput.value.trim();

    if (!url) {
        statusText.textContent = "Please enter a URL.";
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";
    statusText.textContent = "Sending URL to the detection engine...";
    result.hidden = true;

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to scan this URL.");
        }

        document.getElementById("resultTitle").textContent =
            data.verdict;

        document.getElementById("resultUrl").textContent =
            data.url;

        document.getElementById("hostname").textContent =
            data.hostname;

        document.getElementById("score").textContent =
            data.score;

        const findings = document.getElementById("findings");
        findings.replaceChildren();

        data.findings.forEach(function (finding) {
            const item = document.createElement("li");
            item.textContent = finding;
            findings.appendChild(item);
        });

        document.getElementById("note").textContent = data.note;

        result.className = "result " + data.level;
        result.hidden = false;
        statusText.textContent = "Scan completed.";

    } catch (error) {
        statusText.textContent = error.message;
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Scan URL";
    }
});
