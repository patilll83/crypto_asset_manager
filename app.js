let allAssets = [];
let filteredAssets = [];
let scanInterval = null;
let currentSort = 'risk_score';

document.addEventListener('DOMContentLoaded', function() {
    window.refreshData();
});

const API_BASE = '/api';

async function fetchApi(endpoint, options = {}) {
    const response = await fetch(API_BASE + endpoint, options);
    if (!response.ok) throw new Error('API error: ' + response.status);
    return await response.json();
}

window.refreshData = async function() {
    try {
        const summary = await fetchApi('/assets/summary');
        document.getElementById('total-assets').textContent = summary.total_assets;
        document.getElementById('vulnerable-assets').textContent = summary.vulnerable_assets;
        const compliance = await fetchApi('/compliance/report');
        document.getElementById('compliance-score').textContent = compliance.compliance_percentage.toFixed(1) + '%';
        const assetsData = await fetchApi('/assets');
        allAssets = assetsData.assets;
        filteredAssets = [...allAssets];
        if (allAssets.length > 0) {
            const avgRisk = allAssets.reduce((sum, asset) => sum + asset.risk_score, 0) / allAssets.length;
            document.getElementById('risk-score').textContent = (avgRisk * 100).toFixed(0) + '%';
        }
        renderAssetsTable();
    } catch (error) {
        console.error('Error refreshing data:', error);
        showError('Failed to load data. Please try again.');
    }
}

window.startScan = async function() {
    const scanBtn = document.getElementById('scan-btn');
    const progressDiv = document.getElementById('scan-progress');
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<div class="loading-spinner"></div> Scanning...';
    progressDiv.style.display = 'block';
    try {
        const resp = await fetch(API_BASE + '/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        if (!resp.ok) throw new Error('Failed to start scan');
        await pollScanStatus();
        showSuccess('Scan completed successfully!');
        window.refreshData();
    } catch (error) {
        showError('Scan failed. Please try again.');
    } finally {
        resetScanUI();
    }
}

window.resetScans = async function() {
    if (!confirm("Are you sure you want to reset all scans and assets? This cannot be undone.")) return;
    try {
        const res = await fetch('/api/reset', { method: 'POST' });
        if (res.ok) {
            alert('All scans and assets have been reset.');
            refreshData();
        } else {
            alert('Failed to reset scans.');
        }
    } catch (e) {
        alert('Error resetting scans.');
    }
}


async function pollScanStatus() {
    let done = false;
    while (!done) {
        try {
            const status = await fetchApi('/scan/status');
            if (!status.scanning) {
                done = true;
                break;
            }
        } catch (e) {
            break;
        }
        await new Promise(r => setTimeout(r, 1500));
    }
}

window.exportCSV = function() {
    const headers = ['ID', 'Type', 'Source', 'Algorithm', 'Key Size', 'Status', 'Quantum Vulnerable', 'Risk Score', 'Last Updated'];
    const csvRows = [
        headers.join(','),
        ...filteredAssets.map(asset => [
            asset.id || '', // fallback to empty if missing
            asset.type,
            asset.source,
            asset.algorithm,
            asset.key_size || '',
            asset.status,
            asset.quantum_vulnerable ? 'TRUE' : 'FALSE',
            asset.risk_score,
            formatDate(asset.last_updated)
        ].join(','))
    ];
    const csvContent = csvRows.join('\n'); // Use real newline
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'crypto-assets.csv';
    a.click();
    window.URL.revokeObjectURL(url);
}

window.showMigrationPlan = async function() {
    const modal = document.getElementById('migration-modal');
    const content = document.getElementById('migration-content');
    modal.style.display = 'flex';
    try {
        const plan = await fetchApi('/migration/plan');
        let planHTML = '';
        planHTML += '<div class="migration-overview">';
        planHTML += '<h3>Migration Overview<\/h3>';
        planHTML += '<p><strong>Total Vulnerable Assets:<\/strong> ' + plan.total_vulnerable_assets + '<\/p>';
        planHTML += '<p><strong>Estimated Total Effort:<\/strong> ' + plan.estimated_total_effort + ' hours<\/p>';
        planHTML += '<div class="priority-breakdown">';
        planHTML += '<h4>Priority Breakdown<\/h4>';
        planHTML += '<p>High Priority: ' + plan.priority_breakdown.high + ' assets<\/p>';
        planHTML += '<p>Medium Priority: ' + plan.priority_breakdown.medium + ' assets<\/p>';
        planHTML += '<p>Low Priority: ' + plan.priority_breakdown.low + ' assets<\/p>';
        planHTML += '<\/div>';
        planHTML += '<h4>Migration Tasks<\/h4>';
        planHTML += '<\/div>';
        plan.migration_tasks.forEach(task => {
            planHTML += '<div class="migration-task ' + task.priority + '-priority">';
            planHTML += '<div class="task-header">';
            planHTML += '<span class="task-title">' + formatType(task.asset_type) + ' - ' + task.current_algorithm + '<\/span>';
            planHTML += '<span class="priority-badge priority-' + task.priority + '">' + task.priority + '<\/span>';
            planHTML += '<\/div>';
            planHTML += '<p><strong>Target:<\/strong> ' + task.target_algorithm + '<\/p>';
            planHTML += '<p><strong>Effort:<\/strong> ' + task.estimated_effort + ' hours<\/p>';
            planHTML += '<p><strong>Timeline:<\/strong> ' + task.recommended_timeline + '<\/p>';
            planHTML += '<p><strong>Dependencies:<\/strong> ' + task.dependencies.join(', ') + '<\/p>';
            planHTML += '<\/div>';
        });
        content.innerHTML = planHTML;
    } catch (error) {
        content.innerHTML = '<p>Error loading migration plan.<\\/p>';
    }
}

window.showComplianceReport = async function() {
    const modal = document.getElementById('compliance-modal');
    const content = document.getElementById('compliance-content');
    modal.style.display = 'flex';
    try {
        const report = await fetchApi('/compliance/report');
        let reportHTML = '';
        reportHTML += '<div class="compliance-overview">';
        reportHTML += '<h3>Compliance Overview<\/h3>';
        reportHTML += '<p><strong>Overall Compliance:<\/strong> ' + report.compliance_percentage.toFixed(1) + '%<\/p>';
        reportHTML += '<p><strong>Compliant Assets:<\/strong> ' + report.compliant_assets + ' / ' + report.total_assets + '<\/p>';
        reportHTML += '<h4>Issues Identified<\/h4>';
        reportHTML += '<ul>';
        reportHTML += '<li>Deprecated Algorithms: ' + report.issues.deprecated_algorithms + '<\/li>';
        reportHTML += '<li>Weak Key Sizes: ' + report.issues.weak_key_sizes + '<\/li>';
        reportHTML += '<li>Quantum Vulnerable: ' + report.issues.quantum_vulnerable + '<\/li>';
        reportHTML += '<\/ul>';
        reportHTML += '<h4>Recommendations<\/h4>';
        reportHTML += '<ul>';
        report.recommendations.forEach(rec => {
            reportHTML += '<li>' + rec + '<\/li>';
        });
        reportHTML += '<\/ul>';
        reportHTML += '<\/div>';
        content.innerHTML = reportHTML;
    } catch (error) {
        content.innerHTML = '<p>Error loading compliance report.<\\/p>';
    }
}

window.clearFilters = function() {
    document.getElementById('type-filter').value = '';
    document.getElementById('status-filter').value = '';
    document.getElementById('algorithm-filter').value = '';
    document.getElementById('search-filter').value = '';
    document.getElementById('sort-select').value = 'risk_score';
    filteredAssets = [...allAssets];
    renderAssetsTable();
}

function renderAssetsTable() {
    const container = document.getElementById('assets-container');
    if (filteredAssets.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📋</div>
                <div class="empty-state-title">No assets found</div>
                <p>Try adjusting your filters or start a new scan.</p>
            </div>
        `;
        return;
    }
    let tableHTML = `
        <table class="assets-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Algorithm</th>
                    <th>Key Size</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Source</th>
                    <th>Last Updated</th>
                </tr>
            </thead>
            <tbody>
    `;
    filteredAssets.forEach(asset => {
        const statusClass = getStatusClass(asset.status);
        const riskClass = getRiskClass(asset.risk_score);
        const riskLevel = getRiskLevel(asset.risk_score);
        tableHTML += `
            <tr>
                <td>${formatType(asset.type)}</td>
                <td>${asset.algorithm}</td>
                <td>${asset.key_size || 'N/A'}</td>
                <td><span class="status-badge ${statusClass}">${asset.status}</span></td>
                <td><span class="risk-indicator ${riskClass}">${riskLevel}</span></td>
                <td title="${asset.source}">${truncateSource(asset.source)}</td>
                <td>${formatDate(asset.last_updated)}</td>
            </tr>
        `;
    });
    tableHTML += '</tbody></table>';
    container.innerHTML = tableHTML;
}

function getStatusClass(status) {
    const statusMap = {
        'vulnerable': 'status-vulnerable',
        'secure': 'status-secure',
        'expired': 'status-expired',
        'deprecated': 'status-deprecated',
        'weak': 'status-weak'
    };
    return statusMap[status] || 'status-badge';
}

function getRiskClass(score) {
    if (score <= 0.3) return 'risk-low';
    if (score <= 0.7) return 'risk-medium';
    return 'risk-high';
}

function getRiskLevel(score) {
    if (score <= 0.3) return 'Low';
    if (score <= 0.7) return 'Medium';
    return 'High';
}

function formatType(type) {
    const typeMap = {
        'certificate': 'Certificate',
        'ssh_key': 'SSH Key',
        'code_reference': 'Code Reference'
    };
    return typeMap[type] || type;
}

function truncateSource(source) {
    return source.length > 40 ? source.substring(0, 37) + '...' : source;
}

function formatDate(dateString) {
    return new Date(dateString).toLocaleDateString();
}

function applyFilters() {
    const typeFilter = document.getElementById('type-filter').value;
    const statusFilter = document.getElementById('status-filter').value;
    const algorithmFilter = document.getElementById('algorithm-filter').value;
    const searchFilter = document.getElementById('search-filter').value.toLowerCase();
    filteredAssets = allAssets.filter(asset => {
        return (!typeFilter || asset.type === typeFilter) &&
               (!statusFilter || asset.status === statusFilter) &&
               (!algorithmFilter || asset.algorithm === algorithmFilter) &&
               (!searchFilter || asset.source.toLowerCase().includes(searchFilter));
    });
    renderAssetsTable();
}

function sortAssets() {
    const sortBy = document.getElementById('sort-select').value;
    filteredAssets.sort((a, b) => {
        if (sortBy === 'risk_score') {
            return b.risk_score - a.risk_score;
        } else if (sortBy === 'last_updated') {
            return new Date(b.last_updated) - new Date(a.last_updated);
        } else {
            return a[sortBy].localeCompare(b[sortBy]);
        }
    });
    renderAssetsTable();
}

function resetScanUI() {
    const scanBtn = document.getElementById('scan-btn');
    const progressDiv = document.getElementById('scan-progress');
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<span>🔍</span> Start Full Scan';
    progressDiv.style.display = 'none';
}

function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.style.display = 'block';
    setTimeout(() => errorDiv.style.display = 'none', 5000);
}

function showSuccess(message) {
    const successDiv = document.getElementById('success-message');
    successDiv.textContent = message;
    successDiv.style.display = 'block';
    setTimeout(() => successDiv.style.display = 'none', 3000);
}

// Close modals when clicking outside
window.onclick = function(event) {
    const migrationModal = document.getElementById('migration-modal');
    const complianceModal = document.getElementById('compliance-modal');
    if (event.target === migrationModal) {
        migrationModal.style.display = 'none';
    }
    if (event.target === complianceModal) {
        complianceModal.style.display = 'none';
    }
}