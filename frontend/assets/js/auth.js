// Configuration
const API_BASE_URL = 'http://localhost:3000/api';
let googleConfig = null;

// Initialize Google Auth when page loads
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    initializeGoogleAuth();
    setupFormValidation();
});

// Fetch Google OAuth configuration from backend
async function initializeGoogleAuth() {
    try {
        const response = await fetch(`${API_BASE_URL}/config`);
        if (!response.ok) {
            throw new Error('Failed to fetch config');
        }
        
        const config = await response.json();
        googleConfig = config;
        
        // Update the Google OAuth div with actual client ID
        const googleDiv = document.getElementById('g_id_onload');
        googleDiv.setAttribute('data-client_id', config.googleClientId);
        
        // Initialize Google Identity Services
        if (window.google && window.google.accounts) {
            google.accounts.id.initialize({
                client_id: config.googleClientId,
                callback: handleCredentialResponse,
                auto_select: false,
                cancel_on_tap_outside: true
            });
        }
        
        console.log('Google OAuth initialized successfully');
        
    } catch (error) {
        console.error('Failed to load Google config:', error);
        showAlert('CONNECTION_ERROR: Authentication service unavailable', 'error');
    }
}

// Setup form validation
function setupFormValidation() {
    // Real-time form validation
    document.getElementById('signin-email').addEventListener('blur', function() {
        if (this.value && !validateEmail(this.value)) {
            this.style.borderColor = 'rgba(255, 0, 0, 0.5)';
        } else {
            this.style.borderColor = '';
        }
    });

    document.getElementById('signup-email').addEventListener('blur', function() {
        if (this.value && !validateEmail(this.value)) {
            this.style.borderColor = 'rgba(255, 0, 0, 0.5)';
        } else {
            this.style.borderColor = '';
        }
    });

    document.getElementById('signup-password').addEventListener('input', function() {
        if (this.value && !validatePassword(this.value)) {
            this.style.borderColor = 'rgba(255, 0, 0, 0.5)';
        } else {
            this.style.borderColor = '';
        }
    });

    document.getElementById('signup-confirm-password').addEventListener('input', function() {
        const password = document.getElementById('signup-password').value;
        if (this.value && this.value !== password) {
            this.style.borderColor = 'rgba(255, 0, 0, 0.5)';
        } else {
            this.style.borderColor = '';
        }
    });
}

// Tab switching function
function switchTab(tab) {
    currentTab = tab;
    
    // Update tab buttons
    const tabs = document.querySelectorAll('.auth-tab');
    tabs.forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    
    // Show/hide forms
    const signinForm = document.getElementById('signin-form');
    const signupForm = document.getElementById('signup-form');
    
    if (tab === 'signin') {
        signinForm.style.display = 'block';
        signupForm.style.display = 'none';
    } else {
        signinForm.style.display = 'none';
        signupForm.style.display = 'block';
    }
    
    // Clear any existing alerts
    hideAlert();
}

// Remove the demo function and replace with:
function signInWithGoogle() {
    // This will be called by the actual Google button
    if (typeof google !== 'undefined' && google.accounts) {
        google.accounts.id.prompt();
    } else {
        showAlert('GOOGLE_OAUTH: Loading Google Sign-In...', 'warning');
        setTimeout(() => {
            if (typeof google !== 'undefined') {
                google.accounts.id.prompt();
            } else {
                showAlert('GOOGLE_OAUTH: Please refresh the page and try again', 'error');
            }
        }, 2000);
    }
}

// Make sure this function exists for handling the response
function handleCredentialResponse(response) {
    console.log('Google OAuth response received:', response.credential);
    
    fetch(`${API_BASE_URL}/auth/google`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ token: response.credential })
    })
    .then(response => response.json())
    .then(data => {
        if (data.token) {
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            showAlert('GOOGLE_AUTH: Authentication successful', 'success');
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1500);
        } else {
            showAlert('OAUTH_ERROR: Authentication failed', 'error');
        }
    })
    .catch(error => {
        console.error('Google auth error:', error);
        showAlert('OAUTH_ERROR: Authentication failed', 'error');
    });
}
// Form submission handlers
document.getElementById('signin-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('signin-email').value;
    const password = document.getElementById('signin-password').value;
    
    if (!email || !password) {
        showAlert('MISSING_CREDENTIALS: All fields required', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/signin`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Store token and user data
            localStorage.setItem('authToken', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            
            showAlert('ACCESS_GRANTED: Redirecting to dashboard', 'success');
            setTimeout(() => {
                window.location.href = 'dashboard.html';
            }, 1500);
        } else {
            showAlert(`AUTH_ERROR: ${data.error || 'Invalid credentials'}`, 'error');
        }
    } catch (error) {
        console.error('Sign in error:', error);
        showAlert('CONNECTION_ERROR: Unable to reach server', 'error');
    }
});

document.getElementById('signup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;
    const confirmPassword = document.getElementById('signup-confirm-password').value;
    
    if (!name || !email || !password || !confirmPassword) {
        showAlert('VALIDATION_ERROR: All fields required', 'error');
        return;
    }
    
    if (password !== confirmPassword) {
        showAlert('PASSWORD_MISMATCH: Passwords do not match', 'error');
        return;
    }
    
    if (password.length < 6) {
        showAlert('WEAK_PASSWORD: Minimum 6 characters required', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/auth/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name, email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert('ACCOUNT_CREATED: Please sign in with your credentials', 'success');
            setTimeout(() => {
                switchTab('signin');
                // Clear form
                document.getElementById('signup-form').reset();
            }, 2000);
        } else {
            showAlert(`REGISTRATION_ERROR: ${data.error || 'Failed to create account'}`, 'error');
        }
    } catch (error) {
        console.error('Sign up error:', error);
        showAlert('CONNECTION_ERROR: Unable to reach server', 'error');
    }
});

// Alert system
function showAlert(message, type) {
    const alert = document.getElementById('alert-message');
    alert.textContent = message;
    alert.className = `alert alert-${type}`;
    alert.style.display = 'block';
    
    // Auto-hide success messages
    if (type === 'success') {
        setTimeout(() => {
            hideAlert();
        }, 5000);
    }
}

function hideAlert() {
    const alert = document.getElementById('alert-message');
    alert.style.display = 'none';
}

function showForgotPassword() {
    showAlert('PASSWORD_RESET: Recovery functionality would be implemented', 'success');
}

// Check if user is already authenticated
function checkAuth() {
    const token = localStorage.getItem('authToken');
    const user = localStorage.getItem('user');
    
    if (token && user) {
        // User is already authenticated, redirect to dashboard
        window.location.href = 'dashboard.html';
    }
}

// Input validation helpers
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    return password.length >= 6;
}
// Theme Management
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

// Initialize theme on page load
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    // ... your existing DOMContentLoaded code
});