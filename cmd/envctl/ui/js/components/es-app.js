// Main App Shell Component

import { api } from '../api.js';
import { ws } from '../ws.js';

class EsApp extends HTMLElement {
    constructor() {
        super();
        this.currentPage = 'dashboard';
        this.status = null;
    }

    connectedCallback() {
        this.render();
        this.loadStatus();

        // Listen for WebSocket events
        ws.on('connected', () => this.updateConnectionStatus(true));
        ws.on('disconnected', () => this.updateConnectionStatus(false));
    }

    async loadStatus() {
        try {
            this.status = await api.getStatus();
            this.render();
        } catch (err) {
            console.error('Failed to load status:', err);
        }
    }

    updateConnectionStatus(connected) {
        const indicator = this.querySelector('.connection-status');
        if (indicator) {
            indicator.className = `connection-status ${connected ? 'connected' : 'disconnected'}`;
        }
    }

    navigate(page) {
        this.currentPage = page;
        this.render();
    }

    render() {
        const identity = this.status?.identity || 'Loading...';
        const fingerprint = this.status?.fingerprint || '';

        this.innerHTML = `
            <aside class="sidebar">
                <div class="sidebar-header">
                    <div class="sidebar-logo">envctl</div>
                    <div class="text-sm text-muted">${identity}</div>
                    <div class="text-sm text-mono text-muted">${fingerprint}</div>
                </div>
                <nav class="sidebar-nav">
                    <div class="nav-item ${this.currentPage === 'dashboard' ? 'active' : ''}" data-page="dashboard">
                        Dashboard
                    </div>
                    <div class="nav-item ${this.currentPage === 'team' ? 'active' : ''}" data-page="team">
                        Projects
                    </div>
                    <div class="nav-item ${this.currentPage === 'requests' ? 'active' : ''}" data-page="requests">
                        Requests
                    </div>
                    <div class="nav-item ${this.currentPage === 'peers' ? 'active' : ''}" data-page="peers">
                        Peers
                    </div>
                    <div class="nav-item ${this.currentPage === 'members' ? 'active' : ''}" data-page="members">
                        Members
                    </div>
                    <div class="nav-item ${this.currentPage === 'logs' ? 'active' : ''}" data-page="logs">
                        Logs
                    </div>
                </nav>
                <div class="sidebar-footer">
                    <div class="connection-status"></div>
                </div>
            </aside>
            <main class="main-content">
                ${this.renderPage()}
            </main>
        `;

        // Add navigation listeners
        this.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', () => {
                this.navigate(item.dataset.page);
            });
        });
    }

    renderPage() {
        switch (this.currentPage) {
            case 'dashboard':
                return '<es-dashboard></es-dashboard>';
            case 'team':
                return '<es-team></es-team>';
            case 'requests':
                return '<es-requests></es-requests>';
            case 'peers':
                return '<es-peers></es-peers>';
            case 'members':
                return '<es-members></es-members>';
            case 'logs':
                return '<es-logs></es-logs>';
            default:
                return '<div>Page not found</div>';
        }
    }
}

customElements.define('es-app', EsApp);
