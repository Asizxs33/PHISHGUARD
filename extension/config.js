// config.js
// Centralized configuration for the extension

export const config = {
    // Use the local backend by default for testing, 
    // or switch to the production Render URL when deploying.
    // API_URL: "https://phishguard-api.onrender.com",
    API_URL: "https://phishguard-api.onrender.com",

    // Cache check results for this long (in milliseconds)
    CACHE_TTL: 1000 * 60 * 60 // 1 hour
};
