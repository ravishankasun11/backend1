// API Utilities and Configuration

// Configuration
const API_CONFIG = {
    BASE_URL: 'http://localhost:3000/api',
    OPENWEATHER_API_KEY: '83909c266fcdf428cd0b09d0195fc25b',
    TIMEOUT: 10000 // 10 seconds
};

// API Helper Functions
class APIClient {
    constructor() {
        this.baseURL = API_CONFIG.BASE_URL;
    }

    // Get auth headers
    getAuthHeaders() {
        const token = localStorage.getItem('authToken');
        const user = JSON.parse(localStorage.getItem('user'));
        
        const headers = {
            'Content-Type': 'application/json'
        };
        
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        if (user && user.apiKey) {
            headers['X-API-Key'] = user.apiKey;
        }
        
        return headers;
    }

    // Generic API request method
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: this.getAuthHeaders(),
            ...options
        };

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.TIMEOUT);
            
            const response = await fetch(url, {
                ...config,
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            if (error.name === 'AbortError') {
                throw new Error('Request timeout');
            }
            throw error;
        }
    }

    // Authentication methods
    async signIn(email, password) {
        return this.request('/auth/signin', {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
    }

    async signUp(name, email, password) {
        return this.request('/auth/signup', {
            method: 'POST',
            body: JSON.stringify({ name, email, password })
        });
    }

    async googleAuth(token) {
        return this.request('/auth/google', {
            method: 'POST',
            body: JSON.stringify({ token })
        });
    }

    // Travel data methods
    async saveTravelData(data) {
        return this.request('/travel-data', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    async getRecords(page = 1, limit = 10) {
        return this.request(`/records?page=${page}&limit=${limit}`);
    }

    async getUserProfile() {
        return this.request('/user/profile');
    }
}

// External API Functions
class ExternalAPIs {
    // Fetch weather data from OpenWeatherMap
    static async fetchWeatherData(city, country) {
        const url = `https://api.openweathermap.org/data/2.5/weather?q=${city},${country}&appid=${API_CONFIG.OPENWEATHER_API_KEY}&units=metric`;
        
        try {
            const response = await fetch(url);
            
            if (!response.ok) {
                throw new Error(`Weather API error: ${response.status}`);
            }
            
            const data = await response.json();
            
            return {
                temperature: data.main.temp,
                description: data.weather[0].description,
                humidity: data.main.humidity,
                windSpeed: data.wind?.speed || 0,
                visibility: data.visibility || 10000,
                pressure: data.main.pressure,
                icon: data.weather[0].icon
            };
        } catch (error) {
            console.error('Weather API error:', error);
            throw new Error(`Failed to fetch weather data: ${error.message}`);
        }
    }

    // Fetch travel advisory data
    static async fetchTravelAdvisory(country) {
        const url = `https://www.travel-advisory.info/api?countrycode=${country}`;
        
        try {
            const response = await fetch(url);
            
            if (!response.ok) {
                throw new Error(`Travel Advisory API error: ${response.status}`);
            }
            
            const data = await response.json();
            const countryData = data.data[country.toUpperCase()];
            
            if (!countryData) {
                throw new Error('Country not found in travel advisory data');
            }
            
            return {
                score: countryData.advisory.score,
                sources_active: countryData.advisory.sources_active,
                message: countryData.advisory.message,
                updated: countryData.advisory.updated
            };
        } catch (error) {
            console.error('Travel Advisory API error:', error);
            // Return fallback data if API fails
            return {
                score: 2,
                sources_active: 1,
                message: 'Advisory data temporarily unavailable. Exercise normal precautions.',
                updated: new Date().toISOString()
            };
        }
    }
}

// Error Handler
class APIErrorHandler {
    static handle(error) {
        console.error('API Error:', error);
        
        if (error.message.includes('timeout')) {
            return 'CONNECTION_TIMEOUT: Server response timeout';
        }
        
        if (error.message.includes('401')) {
            // Clear auth data on unauthorized
            localStorage.removeItem('authToken');
            localStorage.removeItem('user');
            window.location.href = 'index.html';
            return 'AUTH_EXPIRED: Please sign in again';
        }
        
        if (error.message.includes('403')) {
            return 'ACCESS_DENIED: Insufficient permissions';
        }
        
        if (error.message.includes('404')) {
            return 'NOT_FOUND: Resource not available';
        }
        
        if (error.message.includes('500')) {
            return 'SERVER_ERROR: Internal server error';
        }
        
        if (error.message.includes('Network')) {
            return 'NETWORK_ERROR: Check internet connection';
        }
        
        return `API_ERROR: ${error.message}`;
    }
}

// Rate Limiter
class RateLimiter {
    constructor() {
        this.requests = new Map();
        this.limits = {
            weather: { max: 60, window: 60000 }, // 60 requests per minute
            advisory: { max: 100, window: 60000 }, // 100 requests per minute
            api: { max: 1000, window: 60000 } // 1000 requests per minute
        };
    }

    canMakeRequest(type = 'api') {
        const now = Date.now();
        const limit = this.limits[type];
        
        if (!limit) return true;
        
        if (!this.requests.has(type)) {
            this.requests.set(type, []);
        }
        
        const requests = this.requests.get(type);
        
        // Remove old requests outside the window
        while (requests.length > 0 && now - requests[0] > limit.window) {
            requests.shift();
        }
        
        if (requests.length >= limit.max) {
            return false;
        }
        
        requests.push(now);
        return true;
    }
}

// Initialize instances
const apiClient = new APIClient();
const rateLimiter = new RateLimiter();

// Utility functions
function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
    });
}

function getSafetyLevel(score) {
    if (score <= 2) return { level: 'low', text: 'LOW RISK' };
    if (score <= 3) return { level: 'medium', text: 'MODERATE RISK' };
    return { level: 'high', text: 'HIGH RISK' };
}

function capitalizeWords(str) {
    return str.replace(/\w\S*/g, (txt) => 
        txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase()
    );
}

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        APIClient,
        ExternalAPIs,
        APIErrorHandler,
        RateLimiter,
        apiClient,
        rateLimiter
    };
}