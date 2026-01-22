/**
 * Black-Box Web Vulnerability Scanner - Frontend Application Logic
 * 
 * Handles:
 * - Form interactions and validation
 * - WebSocket connection for real-time logs
 * - Scan lifecycle management
 * - Results display and download
 */

// ============================================================================
// Global State
// ============================================================================

let socket = null;
let currentScanId = null;
let autoScroll = true;
let scanInProgress = false;

// ============================================================================
// DOM Elements
// ============================================================================

const elements = {
    // Form elements
    form: document.getElementById('scanForm'),
    inputTypeRadios: document.getElementsByName('inputType'),
    urlInputGroup: document.getElementById('urlInputGroup'),
    fileInputGroup: document.getElementById('fileInputGroup'),
    targetUrl: document.getElementById('targetUrl'),
    targetFile: document.getElementById('targetFile'),
    fileName: document.getElementById('fileName'),
    
    // Recon elements
    enableRecon: document.getElementById('enableRecon'),
    reconOptions: document.getElementById('reconOptions'),
    reconModeRadios: document.getElementsByName('reconMode'),
    
    // Module elements
    moduleCheckboxes: document.getElementsByName('modules'),
    moduleError: document.getElementById('moduleError'),
    
    // Callback section (XSS)
    callbackSection: document.getElementById('callbackSection'),
    callbackUrl: document.getElementById('callbackUrl'),
    
    // Buttons
    startScanBtn: document.getElementById('startScanBtn'),
    stopScanBtn: document.getElementById('stopScanBtn'),
    resetBtn: document.getElementById('resetBtn'),
    clearLogsBtn: document.getElementById('clearLogsBtn'),
    scrollLockBtn: document.getElementById('scrollLockBtn'),
    downloadJsonBtn: document.getElementById('downloadJsonBtn'),
    downloadTxtBtn: document.getElementById('downloadTxtBtn'),
    
    // Display elements
    scanStatus: document.getElementById('scanStatus'),
    terminal: document.getElementById('terminal'),
    resultsContainer: document.getElementById('resultsContainer'),
    resultsControls: document.getElementById('resultsControls')
};

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    initializeWebSocket();
    attachEventListeners();
    logToTerminal('INFO', 'Frontend initialized successfully');
});

// ============================================================================
// WebSocket Management
// ============================================================================

function initializeWebSocket() {
    try {
        // Connect to Flask-SocketIO server
        socket = io({
            transports: ['websocket', 'polling'],
            reconnection: true,
            reconnectionDelay: 1000,
            reconnectionAttempts: 5
        });
        
        // Connection handlers
        socket.on('connect', () => {
            logToTerminal('SUCCESS', 'WebSocket connected');
            socket.emit('subscribe_logs');
        });
        
        socket.on('disconnect', () => {
            logToTerminal('WARNING', 'WebSocket disconnected');
        });
        
        socket.on('connection_response', (data) => {
            console.log('Connection response:', data);
        });
        
        socket.on('subscription_confirmed', (data) => {
            console.log('Subscription confirmed:', data);
        });
        
        // Scan log streaming
        socket.on('scan_log', (data) => {
            handleScanLog(data);
        });
        
        // Scan status updates
        socket.on('scan_status', (data) => {
            handleStatusUpdate(data);
        });
        
        // Error handling
        socket.on('error', (error) => {
            logToTerminal('ERROR', `WebSocket error: ${error.message || error}`);
        });
        
    } catch (error) {
        console.error('WebSocket initialization error:', error);
        logToTerminal('ERROR', 'Failed to initialize WebSocket connection');
    }
}

function handleScanLog(data) {
    const { timestamp, level, message, scan_id } = data;
    
    // Only display logs for current scan
    if (scan_id === currentScanId || !currentScanId) {
        logToTerminal(level, message, timestamp);
    }
}

function handleStatusUpdate(data) {
    const { scan_id, status } = data;
    
    if (scan_id === currentScanId) {
        updateScanStatus(status);
        
        // If scan completed, fetch and display results
        if (status === 'completed') {
            fetchResults(scan_id);
        }
        
        // Re-enable form on completion or failure
        if (status === 'completed' || status === 'failed') {
            enableForm();
            scanInProgress = false;
        }
    }
}

// ============================================================================
// Event Listeners
// ============================================================================

function attachEventListeners() {
    // Input type toggle
    elements.inputTypeRadios.forEach(radio => {
        radio.addEventListener('change', handleInputTypeChange);
    });
    
    // File selection
    elements.targetFile.addEventListener('change', handleFileSelect);
    
    // Recon toggle
    elements.enableRecon.addEventListener('change', handleReconToggle);
    
    // Module selection - show/hide callback section
    elements.moduleCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', handleModuleChange);
    });
    
    // Form submission
    elements.form.addEventListener('submit', handleFormSubmit);
    
    // Form reset
    elements.resetBtn.addEventListener('click', handleFormReset);
    
    // Stop scan
    elements.stopScanBtn.addEventListener('click', handleStopScan);
    
    // Terminal controls
    elements.clearLogsBtn.addEventListener('click', clearTerminal);
    elements.scrollLockBtn.addEventListener('click', toggleAutoScroll);
    
    // Download buttons
    elements.downloadJsonBtn.addEventListener('click', () => downloadReport('json'));
    elements.downloadTxtBtn.addEventListener('click', () => downloadReport('txt'));
}

function handleInputTypeChange(event) {
    const inputType = event.target.value;
    
    if (inputType === 'url') {
        elements.urlInputGroup.style.display = 'block';
        elements.fileInputGroup.style.display = 'none';
        elements.targetUrl.required = true;
        elements.targetFile.required = false;
    } else {
        elements.urlInputGroup.style.display = 'none';
        elements.fileInputGroup.style.display = 'block';
        elements.targetUrl.required = false;
        elements.targetFile.required = true;
    }
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        elements.fileName.textContent = file.name;
    } else {
        elements.fileName.textContent = '';
    }
}

function handleReconToggle(event) {
    const enabled = event.target.checked;
    elements.reconOptions.style.display = enabled ? 'block' : 'none';
}

function handleModuleChange(event) {
    // Check if XSS module is selected
    const xssSelected = Array.from(elements.moduleCheckboxes)
        .some(cb => cb.value === 'bxss' && cb.checked);
    
    // Show callback section only if XSS is selected
    elements.callbackSection.style.display = xssSelected ? 'block' : 'none';
}

// ============================================================================
// Form Submission & Validation
// ============================================================================

function handleFormSubmit(event) {
    event.preventDefault();
    
    // Clear previous error
    elements.moduleError.style.display = 'none';
    
    // Validate module selection
    const selectedModules = getSelectedModules();
    if (selectedModules.length === 0) {
        elements.moduleError.style.display = 'block';
        elements.moduleError.textContent = 'Please select at least one scan module';
        return;
    }
    
    // Validate callback URL if XSS is selected
    if (selectedModules.includes('bxss')) {
        const callbackUrl = elements.callbackUrl.value.trim();
        if (!callbackUrl) {
            alert('Callback Server URL is required for Blind XSS module');
            elements.callbackUrl.focus();
            return;
        }
        if (!isValidUrl(callbackUrl)) {
            alert('Please enter a valid callback URL (e.g., https://your-ngrok-url.ngrok.io)');
            elements.callbackUrl.focus();
            return;
        }
    }
    
    // Get form data
    const formData = getFormData();
    
    // Validate URL if input type is URL
    if (formData.input_type === 'url' && !isValidUrl(formData.target)) {
        alert('Please enter a valid URL (e.g., https://example.com/page?param=value)');
        return;
    }
    
    // Validate file if input type is file
    if (formData.input_type === 'file' && !elements.targetFile.files[0]) {
        alert('Please select a target file');
        return;
    }
    
    // Start scan
    startScan(formData);
}

function getFormData() {
    const inputType = document.querySelector('input[name="inputType"]:checked').value;
    
    const formData = {
        input_type: inputType,
        target: inputType === 'url' ? elements.targetUrl.value.trim() : '',
        recon: elements.enableRecon.checked,
        modules: getSelectedModules()
    };
    
    // Add recon mode if recon is enabled
    if (formData.recon) {
        const reconMode = document.querySelector('input[name="reconMode"]:checked');
        formData.recon_mode = reconMode ? reconMode.value : 'passive';
    }
    
    // Add callback URL if XSS is selected
    if (formData.modules.includes('bxss')) {
        formData.callback_url = elements.callbackUrl.value.trim();
    }
    
    return formData;
}

function getSelectedModules() {
    const modules = [];
    elements.moduleCheckboxes.forEach(checkbox => {
        if (checkbox.checked) {
            modules.push(checkbox.value);
        }
    });
    return modules;
}

function isValidUrl(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch {
        return false;
    }
}

// ============================================================================
// Scan Management
// ============================================================================

async function startScan(formData) {
    try {
        scanInProgress = true;
        disableForm();
        clearTerminal();
        clearResults();
        
        logToTerminal('INFO', 'Initializing scan...');
        updateScanStatus('running');
        
        // Prepare request
        let requestData;
        let url = '/api/scan/start';
        
        if (formData.input_type === 'file') {
            // Use FormData for file upload
            const formDataObj = new FormData();
            formDataObj.append('input_type', 'file');
            formDataObj.append('file', elements.targetFile.files[0]);
            formDataObj.append('recon', formData.recon);
            if (formData.recon) {
                formDataObj.append('recon_mode', formData.recon_mode);
            }
            formDataObj.append('modules', formData.modules.join(','));
            
            requestData = {
                method: 'POST',
                body: formDataObj
            };
        } else {
            // Use JSON for URL input
            requestData = {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            };
        }
        
        // Send request
        const response = await fetch(url, requestData);
        const result = await response.json();
        
        if (result.success) {
            currentScanId = result.scan_id;
            logToTerminal('SUCCESS', `Scan started successfully (ID: ${currentScanId})`);
        } else {
            throw new Error(result.error || 'Failed to start scan');
        }
        
    } catch (error) {
        console.error('Start scan error:', error);
        logToTerminal('ERROR', `Failed to start scan: ${error.message}`);
        enableForm();
        updateScanStatus('failed');
        scanInProgress = false;
    }
}

async function handleStopScan() {
    if (!confirm('Are you sure you want to stop the current scan?')) {
        return;
    }
    
    try {
        logToTerminal('WARNING', 'Stopping scan...');
        
        const response = await fetch('/api/scan/stop', {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (result.success) {
            logToTerminal('WARNING', 'Scan stopped by user');
            updateScanStatus('idle');
            enableForm();
            scanInProgress = false;
        } else {
            throw new Error(result.error || 'Failed to stop scan');
        }
        
    } catch (error) {
        console.error('Stop scan error:', error);
        logToTerminal('ERROR', `Failed to stop scan: ${error.message}`);
    }
}

// ============================================================================
// Results Management
// ============================================================================

async function fetchResults(scanId) {
    try {
        logToTerminal('INFO', 'Fetching scan results...');
        
        const response = await fetch(`/api/results/${scanId}`);
        const result = await response.json();
        
        if (result.success && result.results) {
            displayResults(result.results);
            elements.resultsControls.style.display = 'flex';
        } else {
            throw new Error(result.error || 'No results found');
        }
        
    } catch (error) {
        console.error('Fetch results error:', error);
        logToTerminal('ERROR', `Failed to fetch results: ${error.message}`);
    }
}

function displayResults(results) {
    const findings = results.findings || [];
    
    if (findings.length === 0) {
        elements.resultsContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✓</div>
                <p>Scan completed - No vulnerabilities found</p>
                <small>All tested parameters appear to be secure</small>
            </div>
        `;
        return;
    }
    
    // Build results table
    let tableHtml = `
        <table class="results-table">
            <thead>
                <tr>
                    <th>Module</th>
                    <th>URL</th>
                    <th>Parameter</th>
                    <th>Confidence</th>
                    <th>Evidence</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    findings.forEach(finding => {
        const module = finding.module || 'unknown';
        const url = finding.url || finding.target || 'N/A';
        const param = finding.parameter || finding.param || 'N/A';
        const evidence = finding.evidence || finding.callback_url || finding.delay || 'See logs';
        
        // Use normalized confidence from backend (or extract if needed)
        const confidence = finding.confidence || extractConfidenceLevel(finding);
        const confidenceBadgeClass = getConfidenceBadgeClass(confidence);
        
        tableHtml += `
            <tr>
                <td><span class="badge badge-module">${module.toUpperCase()}</span></td>
                <td><span class="evidence-text" title="${url}">${url}</span></td>
                <td><code>${param}</code></td>
                <td><span class="badge badge-${confidenceBadgeClass}">${confidence}</span></td>
                <td><span class="evidence-text" title="${evidence}">${evidence}</span></td>
            </tr>
        `;
    });
    
    tableHtml += `
            </tbody>
        </table>
    `;
    
    elements.resultsContainer.innerHTML = tableHtml;
    
    logToTerminal('SUCCESS', `Displayed ${findings.length} finding(s)`);
}

function clearResults() {
    elements.resultsContainer.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon">📋</div>
            <p>No scan results yet</p>
            <small>Results will appear here after scan completion</small>
        </div>
    `;
    elements.resultsControls.style.display = 'none';
}

async function downloadReport(format) {
    if (!currentScanId) {
        alert('No scan results available');
        return;
    }
    
    try {
        const url = `/api/report/download/${currentScanId}/${format}`;
        
        // Open download in new window
        window.open(url, '_blank');
        
        logToTerminal('INFO', `Downloading ${format.toUpperCase()} report...`);
        
    } catch (error) {
        console.error('Download error:', error);
        logToTerminal('ERROR', `Failed to download report: ${error.message}`);
    }
}

// ============================================================================
// Results Helper Functions
// ============================================================================

function extractConfidenceLevel(finding) {
    /**
     * Extract confidence level from finding object
     * Checks multiple possible field names from different backend modules
     */
    
    // Check for explicit confidence field
    if (finding.confidence) {
        return normalizeConfidence(finding.confidence);
    }
    
    // Check for confidence_level field
    if (finding.confidence_level) {
        return normalizeConfidence(finding.confidence_level);
    }
    
    // Check for status field that contains confidence
    if (finding.status) {
        const normalized = normalizeConfidence(finding.status);
        if (['HIGH', 'MEDIUM', 'LOW'].includes(normalized)) {
            return normalized;
        }
    }
    
    // Check for delay_confidence (SQLi module)
    if (finding.delay_confidence) {
        return normalizeConfidence(finding.delay_confidence);
    }
    
    // Check for certainty field
    if (finding.certainty) {
        return normalizeConfidence(finding.certainty);
    }
    
    // Check for score (0-100) and convert to confidence
    if (typeof finding.score === 'number') {
        if (finding.score >= 70) return 'HIGH';
        if (finding.score >= 40) return 'MEDIUM';
        return 'LOW';
    }
    
    // Default fallback
    return 'MEDIUM';
}

function normalizeConfidence(value) {
    /**
     * Normalize confidence value to HIGH/MEDIUM/LOW
     */
    if (!value) return 'MEDIUM';
    
    const val = String(value).toUpperCase().trim();
    
    // Match HIGH confidence
    if (val.includes('HIGH') || val.includes('CONFIRMED') || val === '3' || val === '100') {
        return 'HIGH';
    }
    
    // Match LOW confidence
    if (val.includes('LOW') || val.includes('POTENTIAL') || val === '1') {
        return 'LOW';
    }
    
    // Match MEDIUM confidence (default)
    if (val.includes('MEDIUM') || val.includes('LIKELY') || val === '2') {
        return 'MEDIUM';
    }
    
    // Fallback
    return 'MEDIUM';
}

function getConfidenceBadgeClass(confidence) {
    /**
     * Get CSS class name for confidence level badge
     */
    const level = String(confidence).toUpperCase();
    
    if (level === 'HIGH') return 'high';
    if (level === 'LOW') return 'low';
    return 'medium';
}

// ============================================================================
// Terminal Management
// ============================================================================

function logToTerminal(level, message, timestamp = null) {
    const terminalLine = document.createElement('div');
    terminalLine.className = 'terminal-line';
    
    // Generate timestamp if not provided
    if (!timestamp) {
        const now = new Date();
        timestamp = now.toTimeString().split(' ')[0];
    }
    
    // Create timestamp span
    const timestampSpan = document.createElement('span');
    timestampSpan.className = 'timestamp';
    timestampSpan.textContent = `[${timestamp}]`;
    
    // Create message span with appropriate class
    const messageSpan = document.createElement('span');
    messageSpan.className = `log-${level.toLowerCase()}`;
    messageSpan.textContent = message;
    
    terminalLine.appendChild(timestampSpan);
    terminalLine.appendChild(messageSpan);
    
    elements.terminal.appendChild(terminalLine);
    
    // Auto-scroll to bottom if enabled (use requestAnimationFrame for smooth scroll)
    if (autoScroll) {
        requestAnimationFrame(() => {
            elements.terminal.scrollTop = elements.terminal.scrollHeight;
        });
    }
}

function clearTerminal() {
    elements.terminal.innerHTML = '';
    logToTerminal('INFO', 'Terminal cleared');
}

function toggleAutoScroll() {
    autoScroll = !autoScroll;
    
    const icon = elements.scrollLockBtn.querySelector('span');
    icon.textContent = autoScroll ? '🔒' : '🔓';
    
    elements.scrollLockBtn.title = autoScroll ? 'Auto-scroll enabled' : 'Auto-scroll disabled';
    
    logToTerminal('INFO', `Auto-scroll ${autoScroll ? 'enabled' : 'disabled'}`);
}

// ============================================================================
// UI State Management
// ============================================================================

function updateScanStatus(status) {
    const statusDot = elements.scanStatus.querySelector('.status-dot');
    const statusText = elements.scanStatus.querySelector('.status-text');
    
    // Remove all status classes
    statusDot.classList.remove('idle', 'running', 'completed', 'failed');
    
    // Add new status class
    statusDot.classList.add(status);
    
    // Update text
    const statusTexts = {
        'idle': 'Idle',
        'initializing': 'Initializing',
        'running': 'Scanning',
        'completed': 'Completed',
        'failed': 'Failed'
    };
    
    statusText.textContent = statusTexts[status] || status;
}

function disableForm() {
    // Disable all inputs
    elements.targetUrl.disabled = true;
    elements.targetFile.disabled = true;
    elements.enableRecon.disabled = true;
    
    elements.inputTypeRadios.forEach(radio => radio.disabled = true);
    elements.reconModeRadios.forEach(radio => radio.disabled = true);
    elements.moduleCheckboxes.forEach(checkbox => checkbox.disabled = true);
    
    // Disable buttons
    elements.startScanBtn.disabled = true;
    elements.resetBtn.disabled = true;
    elements.stopScanBtn.disabled = false;
}

function enableForm() {
    // Enable all inputs
    elements.targetUrl.disabled = false;
    elements.targetFile.disabled = false;
    elements.enableRecon.disabled = false;
    
    elements.inputTypeRadios.forEach(radio => radio.disabled = false);
    elements.reconModeRadios.forEach(radio => radio.disabled = false);
    elements.moduleCheckboxes.forEach(checkbox => checkbox.disabled = false);
    
    // Enable buttons
    elements.startScanBtn.disabled = false;
    elements.resetBtn.disabled = false;
    elements.stopScanBtn.disabled = true;
}

function handleFormReset() {
    if (scanInProgress && !confirm('This will reset the form. Continue?')) {
        return;
    }
    
    // Reset form
    elements.form.reset();
    
    // Reset UI state
    elements.fileInputGroup.style.display = 'none';
    elements.urlInputGroup.style.display = 'block';
    elements.reconOptions.style.display = 'none';
    elements.callbackSection.style.display = 'none';
    elements.fileName.textContent = '';
    elements.moduleError.style.display = 'none';
    
    // Clear results and terminal
    clearResults();
    clearTerminal();
    
    logToTerminal('INFO', 'Form reset');
}

// ============================================================================
// Utility Functions
// ============================================================================

function showNotification(message, type = 'info') {
    // Simple notification system (can be enhanced)
    console.log(`[${type.toUpperCase()}] ${message}`);
    logToTerminal(type.toUpperCase(), message);
}

// ============================================================================
// Export for debugging (optional)
// ============================================================================

window.scannerApp = {
    socket,
    currentScanId,
    logToTerminal,
    updateScanStatus
};
