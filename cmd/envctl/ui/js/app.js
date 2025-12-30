// envctl Web UI

import { api } from './api.js';
import { ws } from './ws.js';

// Import components
import './components/es-app.js';
import './components/es-dashboard.js';
import './components/es-team.js';
import './components/es-requests.js';
import './components/es-peers.js';
import './components/es-members.js';
import './components/es-logs.js';

// Initialize app
document.addEventListener('DOMContentLoaded', async () => {
    console.log('envctl UI initializing...');

    // Connect WebSocket
    ws.connect();

    // Check daemon status
    try {
        const status = await api.getStatus();
        console.log('Daemon status:', status);
    } catch (err) {
        console.error('Failed to connect to daemon:', err);
    }
});
