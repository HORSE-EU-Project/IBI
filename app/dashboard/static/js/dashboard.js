// Dashboard JavaScript

$(document).ready(function() {
    // Initialize Foundation
    $(document).foundation();

    // Set up navigation
    setupNavigation();
    
    // Load initial data
    loadDashboardData();
        
    // Auto-refresh data every 5 seconds
    setInterval(loadDashboardData, 2 * 1000);
});

// Navigation setup
function setupNavigation() {
    $('.menu-item').on('click', function(e) {
        e.preventDefault();
        
        const page = $(this).data('page');
        
        // Update active menu item
        $('.menu-item').removeClass('active');
        $(this).addClass('active');
        
        // Show/hide pages
        $('.page-content').hide();
        $(`#${page}-page`).show();
        
        // Load page-specific data
        if (page === 'dashboard') {
            loadDashboardData();
        } else if (page === 'mitigations') {
            loadMitigationsData();
        } else if (page === 'intents') {
            loadIntentsManagementData();
        }
    });
}

// Load dashboard data
async function loadDashboardData() {
    try {
        // Load IBI status
        const ibiStatus = await fetchAPI('/stats/ibi');
        updateIBIStatus(ibiStatus);
        
        // Load intents summary
        const intentsSummary = await fetchAPI('/stats/intents-summary');
        updateIntentsSummary(intentsSummary);
        
        // Load threat status
        const threatStatus = await fetchAPI('/stats/threat-status');
        updateThreatStatus(threatStatus);

        // Load IA-NDT status
        const ndtStatus = await fetchAPI('/stats/ndt');
        updateNdtStatus(ndtStatus);
        
        // Load intents table
        const intents = await fetchAPI('/stats/intents');
        updateIntentsTable(intents.intents);
        updateIntentManagementTable(intents.intents);
        
        // Load threats table
        const threats = await fetchAPI('/stats/threats');
        updateThreatsTable(threats.threats);

        // Load component status
        const componentStatus = await fetchAPI('/stats/component-status');
        updateComponentStatusTable(componentStatus);
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showError('Failed to load dashboard data');
    }
}

// Load mitigations data
async function loadMitigationsData() {
    try {
        const mitigations = await fetchAPI('/stats/mitigations');
        updateMitigationsTable(mitigations.mitigations);
    } catch (error) {
        console.error('Error loading mitigations data:', error);
        showError('Failed to load mitigations data');
    }
}

// Load intents data
async function loadIntentsManagementData() {
    try {
        const intents = await fetchAPI('/stats/intents');
        updateIntentManagementTable(intents.intents);
    } catch (error) {
        console.error('Error loading intents data:', error);
        showError('Failed to load intents data');
    }
}

// Generic API fetch function
async function fetchAPI(endpoint, method = 'GET') {
    const response = await fetch(endpoint, {
        method: method,
    });
    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }
    return await response.json();
}

// Update IBI status
function updateIBIStatus(data) {
    $('#ibi-alert').toggle(data.status === 'stopped');
}

// Update intents summary cards
function updateIntentsSummary(data) {
    $('#fulfilled-count').text(data.fulfilled);
    $('#not-fulfilled-count').text(data.not_fulfilled);
}

// Update threat status cards
function updateThreatStatus(data) {
    $('#threats-new').text(data.new);
    $('#threats-under-emulation').text(data.under_emulation);
    $('#threats-under-mitigation').text(data.under_mitigation);
    $('#threats-reincident').text(data.reincident);
    $('#threats-mitigated').text(data.mitigated);
}

// Update IA-NDT status cards
function updateNdtStatus(data) {
    $('#ndt-queue-size').text(data.queue_size);
    if (data.ndt_status === "available") {
        $('#ndt-status').text("Available");
        // go two divs up and change the class of the parent
        $('#ndt-status').parent().parent().removeClass("primary-card");
        $('#ndt-status').parent().parent().addClass("success-card");
        // go to sibling i element and change the icon
        $('#ndt-status').siblings('i').removeClass("primary-icon");
        $('#ndt-status').siblings('i').addClass("success-icon");
    } else {
        $('#ndt-status').text("Busy");
        $('#ndt-status').parent().parent().removeClass("success-card");
        $('#ndt-status').parent().parent().addClass("primary-card");
        // go to sibling i element and change the icon
        $('#ndt-status').siblings('i').removeClass("success-icon");
        $('#ndt-status').siblings('i').addClass("primary-icon");
    }
}

// Update intents table
function updateIntentsTable(intents) {
    const tbody = $('#intents-table-body');
    tbody.empty();
    
    if (intents.length === 0) {
        tbody.append('<tr><td colspan="6" class="text-center">No intents found</td></tr>');
        return;
    }
    
    intents.forEach(intent => {
        const statusClass = intent.status === 'fulfilled' ? 'status-fulfilled' : 'status-not-fulfilled';
        const statusText = intent.status === 'fulfilled' ? 'Fulfilled' : 'Not Fulfilled';
        
        const row = `
            <tr>
                <td>${intent.id}</td>
                <td>${intent.description}</td>
                <td><span class="status-label ${statusClass}">${statusText}</span></td>
                <td>${formatDate(intent.created_at)}</td>
                <td>${formatDate(intent.updated_at)}</td>
            </tr>
        `;
        tbody.append(row);
    });
}

// Update threats table
function updateThreatsTable(threats) {
    const tbody = $('#threats-table-body');
    tbody.empty();
    
    if (threats.length === 0) {
        tbody.append('<tr><td colspan="7" class="text-center">No threats found</td></tr>');
        return;
    }
    
    threats.forEach(threat => {
        const statusClass = getStatusClass(threat.status);
        const row = `
            <tr>
                <td>${threat.id}</td>
                <td><strong>${threat.name}</strong></td>
                <td>${threat.type}</td>
                <td><span class="status-label ${statusClass}">${formatStatus(threat.status)}</span></td>
                <td>${threat.hosts}</td>
                <td>${formatDate(threat.reported_at)}</td>
                <td>${formatDate(threat.last_update)}</td>
            </tr>
        `;
        tbody.append(row);
    });
}

// Update component status table
function updateComponentStatusTable(componentStatus) {
    const tbody = $('#component-status-table-body');
    tbody.empty();
    
    if (componentStatus.length === 0) {
        tbody.append('<tr><td colspan="2" class="text-center">Components not being monitored</td></tr>');
        return;
    } else {
        componentStatus.forEach(component => {
            const statusClass = component.status === 'Online' ? 'led-online' : 'led-offline';
            const row = `
            <tr>
                <td>${component.name}</td>
                <td>
                    <span class="led-status ${statusClass}"></span>
                    <span>${component.status}</span>
                </td>
            </tr>`;
            tbody.append(row);
        });
    }
}
// Update mitigations table
function updateMitigationsTable(mitigations) {
    const tbody = $('#mitigations-table-body');
    tbody.empty();
    
    if (mitigations.length === 0) {
        tbody.append('<tr><td colspan="7" class="text-center">No mitigation actions found</td></tr>');
        return;
    }
    
    mitigations.forEach(mitigation => {
        const statusClass = getMitigationStatusClass(mitigation.enabled);
        
        const row = `
            <tr>
                <td>${mitigation.id}</td>
                <td><strong>${mitigation.name}</strong></td>
                <td>${mitigation.category}</td>
                <td>${mitigation.threats}</td>
                <td>${mitigation.priority}</td>
                <td><span class="status-label ${statusClass}">${formatMitigationStatus(mitigation.enabled)}</span></td>
            </tr>
        `;
        tbody.append(row);
    });
}

// Update intent management table
function updateIntentManagementTable(intents) {
    const tbody = $('#intent-management-table-body');
    tbody.empty();
    
    if (intents.length === 0) {
        tbody.append('<tr><td colspan="7" class="text-center">No intents found</td></tr>');
        return;
    }
    
    intents.forEach(intent => {
        const statusClass = intent.status === 'fulfilled' ? 'status-fulfilled' : 'status-not-fulfilled';
        const statusText = intent.status === 'fulfilled' ? 'Fulfilled' : 'Not Fulfilled';
        
        const row = `
            <tr>
                <td>${intent.id}</td>
                <td>${intent.description}</td>
                <td><span class="status-label ${statusClass}">${statusText}</span></td>
                <td>${formatDate(intent.created_at)}</td>
                <td>${formatDate(intent.updated_at)}</td>
                <td><a href="#" class="delete-intent fa fa-trash" data-intent-id="${intent.uid}" onclick="deleteIntent('${intent.uid}', event)"></a></td>
            </tr>
        `;
        tbody.append(row);
    });
}

// Helper functions
function getStatusClass(status) {
    const statusMap = {
        'new': 'status-new',
        'under_emulation': 'status-under-emulation',
        'under_mitigation': 'status-under-mitigation',
        'reincident': 'status-reincident',
        'mitigated': 'status-mitigated',
        'fulfilled': 'status-fulfilled',
        'not-fulfilled': 'status-not-fulfilled'
    };
    return statusMap[status] || 'status-pending';
}

function getMitigationStatusClass(status) {
    const statusMap = {
        'true': 'status-completed',
        'false': 'status-in-progress'
    };
    return statusMap[status] || 'status-pending';
}

function formatStatus(status) {
    return status.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function formatMitigationStatus(status) {
    if (status) {
        return 'Enabled';
    } else {
        return 'Disabled';
    }
}

function formatDate(dateString) {
    if (!dateString) return '-';
    const date = new Date(dateString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
}

function showError(message) {
    // Create a simple error notification
    const errorDiv = $(`
        <div class="callout alert" style="position: fixed; top: 20px; right: 20px; z-index: 1000; max-width: 300px;">
            <h5>Error</h5>
            <p>${message}</p>
            <button class="close-button" aria-label="Close alert" type="button">
                <span aria-hidden="true">&times;</span>
            </button>
        </div>
    `);
    
    $('body').append(errorDiv);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        errorDiv.fadeOut(() => errorDiv.remove());
    }, 5000);
    
    // Manual close
    errorDiv.find('.close-button').on('click', () => {
        errorDiv.fadeOut(() => errorDiv.remove());
    });
}

function deleteIntent(intentId) {
    fetchAPI(
        `/intents/${intentId}`, 
        'DELETE'
    ).then(response => {
        console.log(response);
    }).catch(error => {
        console.error('Error deleting intent:', error);
    });
    loadIntentsManagementData();
}

// Add loading states
function showLoading(elementId) {
    $(`#${elementId}`).html('<tr><td colspan="6" class="text-center loading">Loading...</td></tr>');
}

// Initialize tooltips and other Foundation components
$(document).on('opened.zf.tooltip', function() {
    // Tooltip opened
});


