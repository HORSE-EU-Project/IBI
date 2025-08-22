$(document).foundation()

// Dashboard JavaScript
$('[data-app-dashboard-toggle-shrink]').on('click', function(e) {
  e.preventDefault();
  $(this).parents('.app-dashboard').toggleClass('shrink-medium').toggleClass('shrink-large');
});

// Update last update time
function updateLastUpdateTime() {
  const now = new Date();
  const timeString = now.toLocaleTimeString();
  const element = document.getElementById('last-update-time');
  if (element) {
    element.textContent = timeString;
  }
}

// Global refresh function
function refreshAllData() {
  updateLastUpdateTime();
  
  // Trigger refresh on both dashboards
  if (typeof updateDashboard === 'function') {
    updateDashboard();
  }
  if (typeof updateStatistics === 'function') {
    updateStatistics();
  }
  
  // Show refresh indicator
  if (typeof showRefreshIndicator === 'function') {
    showRefreshIndicator();
  }
}

// Update time every minute
setInterval(updateLastUpdateTime, 60000);

// Initialize on page load
$(document).ready(function() {
  updateLastUpdateTime();
});

