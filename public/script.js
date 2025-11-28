const API_BASE = '/api/scan';

const getElement = id => document.getElementById(id);

const updateResult = (content, display = true) => {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
};

const showLoading = message => updateResult(`
    <div class="loading">
        <p>${message}</p>
        <div class="spinner"></div>
    </div>
`);

const showError = message => updateResult(`
    <div class="error">
        <strong>Error:</strong> ${message}
    </div>
`);

async function makeAPIRequest(type, data = null, analysisId = null) {
    const response = await fetch(API_BASE, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            type: type,
            data: data,
            analysisId: analysisId
        })
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Request failed!' }));
        throw new Error(error.error || 'API request failed!');
    }

    return response.json();
}

async function scanURL() {
    const url = getElement('urlInput').value.trim();
    if (!url) return showError("Please enter a URL!");

    try {
        new URL(url);
    } catch {
        return showError("Please enter a valid URL (e.g., https://example.com)");
    }

    try {
        showLoading("Submitting URL for scanning...");

        const submitResult = await makeAPIRequest('scan-url', url);

        if (!submitResult.data?.id) {
            throw new Error("Failed to get analysis ID");
        }

        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading("Getting scan results...");
        await pollAnalysisResults(submitResult.data.id);
    } catch (error) {
        console.error("Scan URL Error:", error);
        showError(`Error: ${error.message}`);
    }
}

async function scanFile() {
    const fileInput = getElement('fileInput');
    const file = fileInput.files[0];
    
    if (!file) return showError("Please select a file!");
    if (file.size > 32 * 1024 * 1024) return showError("File size exceeds 32MB limit.");
    if (file.size === 0) return showError("File is empty!");

    try {
        showLoading(`Uploading ${file.name} to VirusTotal...`);

        // Upload langsung ke VirusTotal API
        const formData = new FormData();
        formData.append("file", file);

        const VIRUSTOTAL_API_KEY = "4f4a6df58b549868e190a4c2c6d34c5370d6e0e0e1d19a5fbbcff420ae5c8b6a";
        
        const response = await fetch("https://www.virustotal.com/api/v3/files", {
            method: "POST",
            headers: {
                "x-apikey": VIRUSTOTAL_API_KEY
            },
            body: formData
        });

        if (!response.ok) {
            let errorMessage = `Upload failed with status: ${response.status}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.error?.message || errorMessage;
            } catch (e) {
                errorMessage = await response.text() || errorMessage;
            }
            throw new Error(errorMessage);
        }

        const uploadResult = await response.json();

        if (!uploadResult.data?.id) {
            throw new Error("VirusTotal did not return analysis ID");
        }

        const analysisId = uploadResult.data.id;

        // Tunggu sebentar sebelum polling
        await new Promise(resolve => setTimeout(resolve, 5000));

        showLoading(`Analyzing ${file.name}...`);
        await pollAnalysisResults(analysisId, file.name);

    } catch (error) {
        console.error("File Scan Error:", error);
        showError(`File scan failed: ${error.message}`);
    }
}

async function pollAnalysisResults(analysisId, fileName = '') {
    const maxAttempts = 20;
    let attempts = 0;
    let interval = 3000;

    while (attempts < maxAttempts) {
        try {
            const timeRemaining = ((maxAttempts - attempts) * interval / 1000).toFixed(0);
            showLoading(`Analyzing${fileName ? ` ${fileName}` : ''}... (${timeRemaining}s remaining)`);

            const report = await makeAPIRequest('get-analysis', null, analysisId);
            const status = report.data?.attributes?.status;

            if (!status) throw new Error("Invalid analysis response!");

            if (status === "completed") {
                showFormattedResult(report);
                return;
            }

            if (status === "failed") {
                throw new Error("Analysis failed!");
            }

            attempts++;
            if (attempts >= maxAttempts) {
                throw new Error("Analysis timeout - please try again!");
            }

            interval = Math.min(interval * 1.2, 10000);
            await new Promise(resolve => setTimeout(resolve, interval));
        } catch (error) {
            console.error("Polling Error:", error);
            showError(`Error: ${error.message}`);
            break;
        }
    }
}

function showFormattedResult(data) {
    if (!data?.data?.attributes?.stats) return showError("Invalid response format!");

    const stats = data.data.attributes.stats;
    const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
    if (!total) return showError("No analysis results available!");

    const getPercent = val => ((val / total) * 100).toFixed(1);

    const categories = {
        malicious: { color: 'malicious', label: 'Malicious' },
        suspicious: { color: 'suspicious', label: 'Suspicious' },
        harmless: { color: 'safe', label: 'Clean' },
        undetected: { color: 'undetected', label: 'Undetected' }
    };

    const percents = Object.keys(categories).reduce((acc, key) => {
        acc[key] = getPercent(stats[key]);
        return acc;
    }, {});

    const verdict = stats.malicious > 0 ? "Malicious" : stats.suspicious > 0 ? "Suspicious" : "Safe";
    const verdictClass = stats.malicious > 0 ? "malicious" : stats.suspicious > 0 ? "suspicious" : "safe";

    const verdictIcons = {
        malicious: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6 18L18 6M6 6L18 18" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
        suspicious: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 9V11M12 15H12.01M5 12C5 8.13401 8.13401 5 12 5C15.866 5 19 8.13401 19 12C19 15.866 15.866 19 12 19C8.13401 19 5 15.866 5 12Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
        safe: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 13L9 17L19 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`
    };

    updateResult(`
        <div class="scan-report">
            <h3>Security Scan Report</h3>
            <div class="verdict ${verdictClass}">
                <div class="verdict-icon">${verdictIcons[verdictClass]}</div>
                <div>
                    <strong>Verdict:</strong> ${verdict}
                </div>
            </div>
            <div class="progress-section">
                <div class="progress-label">
                    <span>Detection Results</span>
                    <span class="progress-percent">${percents.malicious}% Detection Rate</span>
                </div>
                <div class="progress-stacked">
                    ${Object.entries(categories).map(([key, { color }]) => `
                        <div class="progress-bar ${color}" style="width: ${percents[key]}%" title="${categories[key].label}: ${stats[key]} (${percents[key]}%)">
                            <span class="progress-label-overlay">${stats[key]}</span>
                        </div>
                    `).join('')}
                </div>
                <div class="progress-legend">
                    ${Object.entries(categories).map(([key, { color, label }]) => `
                        <div class="legend-item">
                            <span class="legend-color ${color}"></span>
                            <span>${label} (${percents[key]}%)</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="detection-details">
                ${Object.entries(categories).map(([key, { color, label }]) => `
                    <div class="detail-item ${color}">
                        <span class="detail-label">${label}</span>
                        <span class="detail-value">${stats[key]}</span>
                        <span class="detail-percent">${percents[key]}%<span>
                    </div>
                `).join('')}
            </div>
            <button class="report-btn" onclick="showFullReport(this.getAttribute('data-report'))" data-report='${JSON.stringify(data)}'>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M9 12H15M9 16H15M17 21H7C5.89543 21 5 20.1046 5 19V5C5 3.89543 5.89543 3 7 3H12.5858C12.851 3 13.1054 3.10536 13.2929 3.29289L18.7071 8.70711C18.8946 8.89464 19 9.149 19 9.41421V19C19 20.1046 18.1046 21 17 21Z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                View Full Report
            </button>
        </div>
    `);

    setTimeout(() => {
        const progressStacked = getElement('result').querySelector('.progress-stacked');
        if (progressStacked) {
            progressStacked.classList.add('animate');
        }
    }, 100);
}

function showFullReport(reportData) {
    const data = typeof reportData === 'string' ? JSON.parse(reportData) : reportData;
    const modal = getElement("fullReportModal");
    const results = data.data?.attributes?.results;

    getElement("fullReportContent").innerHTML = `
        <h3>Detailed Analysis Results</h3>
        ${results ? `
            <table>
                <tr><th>Security Engine</th><th>Result</th></tr>
                ${Object.entries(results).map(([engine, { category }]) => `
                    <tr>
                        <td>${engine}</td>
                        <td class="${category === "malicious" ? "malicious" : category === "suspicious" ? "suspicious" : "safe"}">${category}</td>
                    </tr>
                `).join('')}
            </table>
        ` : '<p>No detailed results available!</p>'}
    `;

    modal.style.display = "block";
    modal.offsetHeight;
    modal.classList.add("show");
}

const closeModal = () => {
    const modal = getElement("fullReportModal");
    modal.classList.remove("show");
    setTimeout(() => modal.style.display = "none", 300);
}

window.addEventListener('load', () => {
    const modal = getElement("fullReportModal");
    const fileInput = getElement('fileInput');
    const fileInputText = getElement('fileInputText');
    
    window.addEventListener('click', e => e.target === modal && closeModal());
    
    if (fileInput && fileInputText) {
        fileInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                fileInputText.textContent = this.files[0].name;
            } else {
                fileInputText.textContent = 'Choose a file';
            }
        });
    }
});