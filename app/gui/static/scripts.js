// Foundation Dashboard Sidebar Toggle
$('[data-app-dashboard-toggle-shrink]').on('click', function(e) {
    e.preventDefault();
    $(this).parents('.app-dashboard').toggleClass('shrink-medium').toggleClass('shrink-large');
});

// Dashboard State Management
class IBIDashboard {
    constructor() {
        this.apiBaseUrl = 'http://127.0.0.1:8000';
        this.refreshInterval = 10000; // 30 seconds
        this.intervals = [];
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadDashboardData();
        this.startAutoRefresh();
        
        // Initialize Foundation components
        $(document).foundation();
    }

    setupEventListeners() {
        // Search functionality
        $('.app-dashboard-search').on('input', (e) => {
            this.handleSearch(e.target.value);
        });

        // Tab switching
        $('[data-tabs]').on('change.zf.tabs', (e, tab) => {
            this.handleTabChange(tab);
        });

        // Intent type filter
        $('#intent-type-filter').on('change', (e) => {
            this.filterIntents(e.target.value);
        });

        // Create intent form
        $('#create-intent-form').on('submit', (e) => {
            e.preventDefault();
            this.createNewIntent();
        });
    }

    async loadDashboardData() {
        try {
            await Promise.all([
                this.loadIntents(),
                this.loadThreats(),
                this.updateSystemStatus(),
                this.updateStatistics()
            ]);
        } catch (error) {
            console.error('Error loading dashboard data:', error);
            this.showNotification('Error loading dashboard data', 'alert');
        }
    }

    async loadIntents() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/intents`);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            
            const data = await response.json();
            this.renderIntentsTable(data.intents || data);
            this.updateIntentsCount(data.intents ? data.intents.length : (Array.isArray(data) ? data.length : 0));
        } catch (error) {
            console.error('Error loading intents:', error);
            this.renderIntentsError();
        }
    }

    async loadThreats() {
        try {
            // Assuming threats endpoint exists or we extract from intents
            const response = await fetch(`${this.apiBaseUrl}/system-states`);
            if (!response.ok) {
                // Fallback to extracting threats from intents
                return this.extractThreatsFromIntents();
            }
            
            const data = await response.json();
            this.renderThreatsTable(data);
        } catch (error) {
            console.error('Error loading threats:', error);
            this.extractThreatsFromIntents();
        }
    }

    async extractThreatsFromIntents() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/intents`);
            const data = await response.json();
            const intents = data.intents || data;
            
            // Group by threat type
            const threats = {};
            intents.forEach(intent => {
                if (!threats[intent.threat]) {
                    threats[intent.threat] = {
                        threat_type: intent.threat,
                        affected_hosts: new Set(),
                        status: 'detected',
                        first_detected: intent.start_time,
                        related_intents: []
                    };
                }
                threats[intent.threat].affected_hosts.add(...intent.host);
                threats[intent.threat].related_intents.push(intent.uid);
            });

            // Convert to array
            const threatsArray = Object.values(threats).map(threat => ({
                ...threat,
                affected_hosts: Array.from(threat.affected_hosts)
            }));

            this.renderThreatsTable(threatsArray);
        } catch (error) {
            console.error('Error extracting threats:', error);
            this.renderThreatsError();
        }
    }

    renderIntentsTable(intents) {
        const container = document.getElementById('intents-table-container');
        if (!container) return;

        if (!intents || intents.length === 0) {
            container.innerHTML = this.getEmptyStateHTML('intents');
            return;
        }

        const tableHTML = `
            <div class="intents-table-wrapper">
                <div class="table-controls">
                    <div class="grid-x grid-padding-x align-middle">
                        <div class="large-6 cell">
                            <div class="input-group">
                                <span class="input-group-label">
                                    <i class="fas fa-filter"></i>
                                </span>
                                <select class="input-group-field" id="intent-type-filter">
                                    <option value="">All Types</option>
                                    <option value="mitigation">Mitigation</option>
                                    <option value="prevention">Prevention</option>
                                    <option value="detection">Detection</option>
                                </select>
                            </div>
                        </div>
                        <div class="large-6 cell text-right">
                            <div class="button-group">
                                <button class="button secondary small" onclick="dashboard.exportIntentsData()">
                                    <i class="fas fa-download"></i> Export
                                </button>
                                <button class="button primary small" onclick="dashboard.showCreateIntentModal()">
                                    <i class="fas fa-plus"></i> New Intent
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <table class="dashboard-table responsive-table">
                    <thead>
                        <tr>
                            <th>Intent ID</th>
                            <th>Type</th>
                            <th>Threat</th>
                            <th>Affected Hosts</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Duration</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${intents.map(intent => this.renderIntentRow(intent)).join('')}
                    </tbody>
                </table>
            </div>
        `;

        container.innerHTML = tableHTML;
    }

    renderIntentRow(intent) {
        const createdDate = new Date(intent.start_time ? intent.start_time * 1000 : Date.now());
        const status = intent.status || 'new';
        const intentType = intent.intent_type || 'unknown';
        const hosts = Array.isArray(intent.host) ? intent.host : [intent.host];

        return `
            <tr data-intent-id="${intent.uid}">
                <td>
                    <div class="intent-id-cell">
                        <i class="fas fa-shield-alt" style="color: #007bff; margin-right: 8px;"></i>
                        <span class="intent-id">${intent.uid}</span>
                    </div>
                </td>
                <td>
                    <span class="intent-type-badge ${intentType}">${intentType}</span>
                </td>
                <td class="threat-cell">
                    <strong>${intent.threat}</strong>
                </td>
                <td class="host-list">
                    ${hosts.slice(0, 3).join('<br>')}
                    ${hosts.length > 3 ? `<br><small>+${hosts.length - 3} more</small>` : ''}
                </td>
                <td>
                    <span class="status-badge ${status}">${status.replace('_', ' ')}</span>
                </td>
                <td class="timestamp">
                    ${createdDate.toLocaleDateString()}<br>
                    <small>${createdDate.toLocaleTimeString()}</small>
                </td>
                <td>
                    ${intent.duration}s
                </td>
                <td>
                    <div class="action-buttons">
                        <button class="button tiny secondary" onclick="dashboard.showIntentDetails('${intent.uid}')">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="button tiny alert" onclick="dashboard.deleteIntent('${intent.uid}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }

    renderThreatsTable(threats) {
        const container = document.getElementById('threats-table-container');
        if (!container) return;

        if (!threats || threats.length === 0) {
            container.innerHTML = this.getEmptyStateHTML('threats');
            return;
        }

        const tableHTML = `
            <div class="threats-table-wrapper">
                <table class="dashboard-table responsive-table">
                    <thead>
                        <tr>
                            <th>Threat Type</th>
                            <th>Affected Hosts</th>
                            <th>Status</th>
                            <th>First Detected</th>
                            <th>Related Intents</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${threats.map(threat => this.renderThreatRow(threat)).join('')}
                    </tbody>
                </table>
            </div>
        `;

        container.innerHTML = tableHTML;
    }

    renderThreatRow(threat) {
        const detectedDate = new Date(threat.first_detected ? threat.first_detected * 1000 : Date.now());
        const hosts = Array.isArray(threat.affected_hosts) ? threat.affected_hosts : [threat.affected_hosts];

        return `
            <tr data-threat-type="${threat.threat_type}">
                <td>
                    <div class="threat-type-cell">
                        <i class="fas fa-exclamation-triangle" style="color: #dc3545; margin-right: 8px;"></i>
                        <strong>${threat.threat_type}</strong>
                    </div>
                </td>
                <td class="host-list">
                    ${hosts.slice(0, 3).join('<br>')}
                    ${hosts.length > 3 ? `<br><small>+${hosts.length - 3} more</small>` : ''}
                </td>
                <td>
                    <span class="status-badge ${threat.status}">${threat.status}</span>
                </td>
                <td class="timestamp">
                    ${detectedDate.toLocaleDateString()}<br>
                    <small>${detectedDate.toLocaleTimeString()}</small>
                </td>
                <td>
                    <span class="badge secondary">${threat.related_intents ? threat.related_intents.length : 0} intents</span>
                </td>
                <td>
                    <div class="action-buttons">
                        <button class="button tiny primary" onclick="dashboard.showThreatDetails('${threat.threat_type}')">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `;
    }

    renderIntentsError() {
        const container = document.getElementById('intents-table-container');
        if (container) {
            container.innerHTML = `
                <div class="callout alert">
                    <h6><i class="fas fa-exclamation-triangle"></i> Error Loading Intents</h6>
                    <p>Unable to load intents data. Please check your connection and try again.</p>
                    <button class="button primary small" onclick="dashboard.loadIntents()">
                        <i class="fas fa-sync-alt"></i> Retry
                    </button>
                </div>
            `;
        }
    }

    renderThreatsError() {
        const container = document.getElementById('threats-table-container');
        if (container) {
            container.innerHTML = `
                <div class="callout alert">
                    <h6><i class="fas fa-exclamation-triangle"></i> Error Loading Threats</h6>
                    <p>Unable to load threats data. Please check your connection and try again.</p>
                    <button class="button primary small" onclick="dashboard.loadThreats()">
                        <i class="fas fa-sync-alt"></i> Retry
                    </button>
                </div>
            `;
        }
    }

    getEmptyStateHTML(type) {
        const icons = {
            intents: 'fa-shield-alt',
            threats: 'fa-exclamation-triangle'
        };

        const messages = {
            intents: 'No security intents found',
            threats: 'No active threats detected'
        };

        return `
            <div class="empty-state">
                <div class="empty-state-icon">
                    <i class="fas ${icons[type]}"></i>
                </div>
                <h6>${messages[type]}</h6>
                <p>When ${type} are detected, they will appear here.</p>
                ${type === 'intents' ? '<button class="button primary" onclick="dashboard.showCreateIntentModal()">Create New Intent</button>' : ''}
            </div>
        `;
    }

    async updateStatistics() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/intents`);
            const data = await response.json();
            const intents = data.intents || data;

            const stats = {
                total: intents.length,
                active: intents.filter(i => ['new', 'processing', 'under_mitigation'].includes(i.status)).length,
                mitigated: intents.filter(i => i.status === 'mitigated').length,
                processing: intents.filter(i => i.status === 'processing').length
            };

            document.getElementById('total-intents').textContent = stats.total;
            document.getElementById('active-threats').textContent = stats.active;
            document.getElementById('mitigated-threats').textContent = stats.mitigated;
            document.getElementById('processing-intents').textContent = stats.processing;

        } catch (error) {
            console.error('Error updating statistics:', error);
        }
    }

    async updateSystemStatus() {
        // Update system status indicators
        const services = ['es', 'ckb', 'rtr'];
        
        for (const service of services) {
            const indicator = document.getElementById(`${service}-status`);
            if (indicator) {
                try {
                    // Mock service check - replace with actual health endpoints
                    const isHealthy = await this.checkServiceHealth(service);
                    indicator.innerHTML = isHealthy 
                        ? '<i class="fas fa-circle text-success"></i> Online'
                        : '<i class="fas fa-circle text-danger"></i> Offline';
                } catch (error) {
                    indicator.innerHTML = '<i class="fas fa-circle text-warning"></i> Unknown';
                }
            }
        }
    }

    async checkServiceHealth(service) {
        // Mock implementation - replace with actual health checks
        return Math.random() > 0.2; // 80% chance of being healthy
    }

    startAutoRefresh() {
        // Clear existing intervals
        this.intervals.forEach(interval => clearInterval(interval));
        this.intervals = [];

        // Set up auto-refresh intervals
        this.intervals.push(setInterval(() => this.loadIntents(), this.refreshInterval));
        this.intervals.push(setInterval(() => this.loadThreats(), this.refreshInterval));
        this.intervals.push(setInterval(() => this.updateStatistics(), this.refreshInterval));
        this.intervals.push(setInterval(() => this.updateSystemStatus(), this.refreshInterval * 2));
    }

    // Navigation methods
    showIntentsTab() {
        const tab = document.querySelector('[href="#intents-panel"]');
        if (tab) tab.click();
    }

    showThreatsTab() {
        const tab = document.querySelector('[href="#threats-panel"]');
        if (tab) tab.click();
    }

    showMonitoringTab() {
        const tab = document.querySelector('[href="#monitoring-panel"]');
        if (tab) tab.click();
    }

    // Modal methods
    showCreateIntentModal() {
        $('#create-intent-modal').foundation('open');
    }

    showIntentDetails(intentId) {
        // Implement intent details modal
        console.log('Show intent details for:', intentId);
    }

    showThreatDetails(threatType) {
        // Implement threat details modal
        console.log('Show threat details for:', threatType);
    }

    // Utility methods
    handleSearch(query) {
        // Implement search functionality
        console.log('Search query:', query);
    }

    filterIntents(type) {
        // Implement intent filtering
        console.log('Filter intents by type:', type);
    }

    exportIntentsData() {
        // Implement data export
        console.log('Export intents data');
    }

    showNotification(message, type = 'primary') {
        // Implement notification system
        console.log(`${type.toUpperCase()}: ${message}`);
    }

    // Manual refresh methods
    refreshIntents() {
        this.loadIntents();
    }

    refreshThreats() {
        this.loadThreats();
    }

    refreshSystemStatus() {
        this.updateSystemStatus();
        this.updateStatistics();
    }
}

// Global functions for template access
function showIntentsTab() { dashboard.showIntentsTab(); }
function showThreatsTab() { dashboard.showThreatsTab(); }
function showMonitoringTab() { dashboard.showMonitoringTab(); }
function showAPIDocumentation() { console.log('API Documentation'); }
function showSettings() { console.log('Settings'); }
function showAbout() { console.log('About HORSE IBI'); }
function refreshIntents() { dashboard.refreshIntents(); }
function refreshThreats() { dashboard.refreshThreats(); }
function refreshSystemStatus() { dashboard.refreshSystemStatus(); }
function createNewIntent() { dashboard.showCreateIntentModal(); }

// Initialize dashboard when DOM is ready
$(document).ready(function() {
    window.dashboard = new IBIDashboard();
});
