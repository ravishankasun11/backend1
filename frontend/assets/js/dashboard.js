// Dashboard JavaScript

// Global variables
let currentUser = null;
let currentTravelData = null;
let recordsCache = [];

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    checkAuthentication();
    initializeEventListeners();
    updateTimestamp();
    setInterval(updateTimestamp, 30000); // Update every 30 seconds
});

// Authentication check
function checkAuthentication() {
    const token = localStorage.getItem('authToken');
    const user = localStorage.getItem('user');
    
    if (!token || !user) {
        window.location.href = 'index.html';
        return;
    }
    
    currentUser = JSON.parse(user);
    displayUserInfo();
}

// Display user information
function displayUserInfo() {
    const userInfo = document.getElementById('user-info');
    const userName = currentUser.name || currentUser.email || 'USER.001';
    
    userInfo.innerHTML = `
        <span class="user-name">${userName.toUpperCase()}</span>
        <button class="logout-btn" onclick="logout()">→ EXIT</button>
    `;
}

// Initialize event listeners
function initializeEventListeners() {
    // Search form
    document.getElementById('travel-form').addEventListener('submit', handleSearchSubmit);
    
    // Save button
    document.getElementById('save-data-btn').addEventListener('click', handleSaveData);
    
    // Load records button
    document.getElementById('load-records-btn').addEventListener('click', handleLoadRecords);
}

// Handle search form submission
async function handleSearchSubmit(e) {
    e.preventDefault();
    
    const city = document.getElementById('city').value.trim();
    const country = document.getElementById('country').value.trim().toUpperCase();
    
    if (!city || !country) {
        showAlert('INPUT_ERROR: City and country code required', 'error');
        return;
    }
    
    if (country.length !== 2) {
        showAlert('VALIDATION_ERROR: Country code must be 2 characters', 'error');
        return;
    }
    
    // Check rate limiting
    if (!rateLimiter.canMakeRequest('weather') || !rateLimiter.canMakeRequest('advisory')) {
        showAlert('RATE_LIMIT: Too many requests, please wait', 'warning');
        return;
    }
    
    await performSearch(city, country);
}

// Perform the search operation
async function performSearch(city, country) {
    const searchBtn = document.getElementById('search-btn');
    const loadingOverlay = document.getElementById('loading-overlay');
    
    // Update UI state
    searchBtn.disabled = true;
    searchBtn.innerHTML = '→ PROCESSING...';
    loadingOverlay.classList.add('active');
    
    // Update status indicators
    updateDataStatus('weather', 'loading');
    updateDataStatus('advisory', 'loading');
    
    try {
        console.log(`Initiating search for ${city}, ${country}`);
        
        // Fetch data concurrently
        const [weatherData, travelAdvisory] = await Promise.all([
            ExternalAPIs.fetchWeatherData(city, country),
            ExternalAPIs.fetchTravelAdvisory(country)
        ]);
        
        // Store the result
        currentTravelData = {
            city,
            country,
            weatherData,
            travelAdvisory,
            timestamp: new Date().toISOString()
        };
        
        console.log('Search completed successfully:', currentTravelData);
        
        // Display results
        displayWeatherData(weatherData);
        displayAdvisoryData(travelAdvisory);
        
        // Show results panel
        document.getElementById('results-panel').classList.add('active');
        document.getElementById('save-data-btn').disabled = false;
        
        // Update status indicators
        updateDataStatus('weather', 'active');
        updateDataStatus('advisory', 'active');
        
        showAlert('DATA_RETRIEVED: Information updated successfully', 'success');
        
    } catch (error) {
        console.error('Search error:', error);
        const errorMessage = APIErrorHandler.handle(error);
        showAlert(errorMessage, 'error');
        
        // Update status indicators
        updateDataStatus('weather', 'error');
        updateDataStatus('advisory', 'error');
        
    } finally {
        // Reset UI state
        searchBtn.disabled = false;
        searchBtn.innerHTML = '→ EXECUTE SCAN';
        loadingOverlay.classList.remove('active');
    }
}

// Display weather data
function displayWeatherData(data) {
    document.getElementById('temp-value').textContent = `${Math.round(data.temperature)}°C`;
    document.getElementById('condition-value').textContent = capitalizeWords(data.description);
    document.getElementById('humidity-value').textContent = `${data.humidity}%`;
    document.getElementById('wind-value').textContent = `${data.windSpeed} m/s`;
    document.getElementById('pressure-value').textContent = `${data.pressure} hPa`;
    document.getElementById('visibility-value').textContent = `${(data.visibility / 1000).toFixed(1)} km`;
}

// Display advisory data
function displayAdvisoryData(data) {
    const safetyLevel = getSafetyLevel(data.score);
    const safetyScore = document.getElementById('safety-score');
    
    // Update score display
    safetyScore.querySelector('.score-number').textContent = data.score;
    safetyScore.className = `safety-score ${safetyLevel.level}`;
    
    // Update other fields
    document.getElementById('sources-value').textContent = data.sources_active;
    document.getElementById('updated-value').textContent = formatTimestamp(data.updated);
    document.getElementById('advisory-message').textContent = data.message;
}

// Update data status indicators
function updateDataStatus(type, status) {
    const statusElement = document.querySelector(`#${type}-block .data-status`);
    if (statusElement) {
        statusElement.className = `data-status ${status}`;
        statusElement.textContent = status.toUpperCase();
    }
}

// Handle save data
async function handleSaveData() {
    if (!currentTravelData) {
        showAlert('NO_DATA: No data available to save', 'error');
        return;
    }
    
    const saveBtn = document.getElementById('save-data-btn');
    const originalText = saveBtn.innerHTML;
    
    saveBtn.disabled = true;
    saveBtn.innerHTML = '→ ARCHIVING...';
    
    try {
        await apiClient.saveTravelData(currentTravelData);
        showAlert('DATA_ARCHIVED: Record saved successfully', 'success');
        
        // Refresh records if they're currently displayed
        if (recordsCache.length > 0) {
            await handleLoadRecords();
        }
        
    } catch (error) {
        console.error('Save error:', error);
        const errorMessage = APIErrorHandler.handle(error);
        showAlert(errorMessage, 'error');
    } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = originalText;
    }
}

// Handle load records
async function handleLoadRecords() {
    const loadBtn = document.getElementById('load-records-btn');
    const recordsContainer = document.getElementById('records-container');
    
    loadBtn.disabled = true;
    loadBtn.innerHTML = '→ LOADING...';
    recordsContainer.innerHTML = '<div class="loading-content"><div class="loading-spinner"></div><p>LOADING RECORDS...</p></div>';
    
    try {
        const response = await apiClient.getRecords();
        recordsCache = response.records;
        displayRecords(recordsCache);
        
    } catch (error) {
        console.error('Load records error:', error);
        const errorMessage = APIErrorHandler.handle(error);
        showAlert(errorMessage, 'error');
        displayEmptyRecords();
    } finally {
        loadBtn.disabled = false;
        loadBtn.innerHTML = '→ LOAD';
    }
}

// Display records
function displayRecords(records) {
    const recordsContainer = document.getElementById('records-container');
    
    if (records.length === 0) {
        displayEmptyRecords();
        return;
    }
    
    const recordsHTML = records.map(record => {
        const safetyLevel = getSafetyLevel(record.travelAdvisory.score);
        return `
            <div class="record-item">
                <div class="record-header">
                    <div class="record-title">${record.city}, ${record.country}</div>
                    <div class="record-date">${formatTimestamp(record.timestamp)}</div>
                </div>
                <div class="record-stats">
                    <div class="stat-item">
                        <span class="stat-value">${Math.round(record.weatherData.temperature)}°C</span>
                        <span class="stat-label">TEMPERATURE</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value">${record.weatherData.windSpeed} m/s</span>
                        <span class="stat-label">WIND SPEED</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value safety-score ${safetyLevel.level}">${record.travelAdvisory.score}/5</span>
                        <span class="stat-label">SAFETY SCORE</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value">${record.travelAdvisory.sources_active}</span>
                        <span class="stat-label">SOURCES</span>
                    </div>
                </div>
            </div>
        `;
    }).join('');
    
    recordsContainer.innerHTML = recordsHTML;
}

// Display empty records state
function displayEmptyRecords() {
    const recordsContainer = document.getElementById('records-container');
    recordsContainer.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon">□</div>
            <p>NO ARCHIVED RECORDS</p>
        </div>
    `;
}

// Update timestamp
function updateTimestamp() {
    const timestampElement = document.getElementById('timestamp');
    if (timestampElement) {
        timestampElement.textContent = formatTimestamp(new Date());
    }
}

// Alert system
function showAlert(message, type) {
    const alertContainer = document.getElementById('alert-container');
    const alertId = `alert-${Date.now()}`;
    
    const alertElement = document.createElement('div');
    alertElement.id = alertId;
    alertElement.className = `alert alert-${type}`;
    alertElement.textContent = message;
    
    alertContainer.appendChild(alertElement);
    
    // Animate in
    setTimeout(() => {
        alertElement.style.opacity = '1';
        alertElement.style.transform = 'translateX(0)';
    }, 100);
    
    // Auto remove after delay
    setTimeout(() => {
        removeAlert(alertId);
    }, type === 'success' ? 3000 : 5000);
}

function removeAlert(alertId) {
    const alertElement = document.getElementById(alertId);
    if (alertElement) {
        alertElement.style.opacity = '0';
        alertElement.style.transform = 'translateX(100%)';
        setTimeout(() => {
            alertElement.remove();
        }, 300);
    }
}

// Logout function
function logout() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
    window.location.href = 'index.html';
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + Enter to submit search
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const form = document.getElementById('travel-form');
        if (form) {
            form.dispatchEvent(new Event('submit'));
        }
    }
    
    // Escape to clear current search
    if (e.key === 'Escape') {
        document.getElementById('city').value = '';
        document.getElementById('country').value = '';
        document.getElementById('results-panel').classList.remove('active');
    }
});

// Auto-focus on city input
document.getElementById('city').focus();

// Theme Management (same as auth.js)
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcon(savedTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.textContent = theme === 'light' ? '🌙' : '☀️';
    }
}

// Update your existing DOMContentLoaded function
document.addEventListener('DOMContentLoaded', () => {
    initTheme(); // Add this line
    checkAuthentication();
    // ... rest of existing code
});