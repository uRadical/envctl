// Dashboard Component

import { api } from '../api.js';
import { ws } from '../ws.js';

class EsDashboard extends HTMLElement {
    constructor() {
        super();
        this.status = null;
    }

    connectedCallback() {
        this.loadData();

        // Listen for real-time updates
        ws.on('chains.reloaded', () => this.loadData());
        ws.on('peer_connected', () => this.loadData());
        ws.on('peer_disconnected', () => this.loadData());
    }

    async loadData() {
        try {
            this.status = await api.getStatus();
            this.render();
        } catch (err) {
            console.error('Failed to load dashboard:', err);
            this.renderError(err);
        }
    }

    render() {
        if (!this.status) {
            this.innerHTML = '<div class="card">Loading...</div>';
            return;
        }

        this.innerHTML = `
            <h1 class="mb-4">Dashboard</h1>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">${this.status.peer_count}</div>
                    <div class="stat-label">Connected Peers</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${this.status.team_count}</div>
                    <div class="stat-label">Projects</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">${this.status.uptime || '-'}</div>
                    <div class="stat-label">Uptime</div>
                </div>
            </div>

            <div class="card mt-4">
                <div class="card-header">
                    <h2 class="card-title">Status</h2>
                </div>
                <table class="table">
                    <tr>
                        <td class="text-muted">Identity</td>
                        <td>${this.status.identity}</td>
                    </tr>
                    <tr>
                        <td class="text-muted">Fingerprint</td>
                        <td class="text-mono">${this.status.fingerprint}</td>
                    </tr>
                    <tr>
                        <td class="text-muted">PID</td>
                        <td>${this.status.pid}</td>
                    </tr>
                    <tr>
                        <td class="text-muted">Started</td>
                        <td>${new Date(this.status.start_time).toLocaleString()}</td>
                    </tr>
                </table>
            </div>
        `;
    }

    renderError(err) {
        this.innerHTML = `
            <div class="card">
                <div class="empty-state">
                    <div class="empty-state-icon">!</div>
                    <p>Failed to connect to daemon</p>
                    <p class="text-sm text-muted">${err.message}</p>
                </div>
            </div>
        `;
    }
}

customElements.define('es-dashboard', EsDashboard);
