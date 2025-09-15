// =======================================================================
// FILE: client/src/services/api.js
// ** FINAL CORRECTED VERSION **
// =======================================================================
const API_URL = 'https://link-space-it1cn8t6n-kunamsanthosh994-cpus-projects.vercel.app'; // Your live Railway URL

const apiRequest = async (endpoint, method = 'GET', body = null) => {
    const config = {
        method,
        headers: {
            'Content-Type': 'application/json',
        },
    };
    const token = localStorage.getItem('chat_token');
    if (token) {
        config.headers['Authorization'] = `Bearer ${token}`;
    }
    if (body) {
        config.body = JSON.stringify(body);
    }
    try {
        const response = await fetch(`${API_URL}${endpoint}`, config);
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Something went wrong');
        }
        if (response.status === 204) return null;
        return response.json();
    } catch (err) {
        console.error(`API Error on ${method} ${endpoint}:`, err);
        throw err;
    }
};
export default apiRequest;
