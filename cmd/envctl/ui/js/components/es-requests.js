// Requests Component

import { api } from '../api.js';

class EsRequests extends HTMLElement {
    constructor() {
        super();
        this.requests = [];
        this.loading = true;
    }

    connectedCallback() {
        this.loadData();
    }

    async loadData() {
        try {
            this.requests = await api.getRequests();
            this.loading = false;
            this.render();
        } catch (err) {
            console.error('Failed to load requests:', err);
            this.loading = false;
            this.requests = [];
            this.render();
        }
    }

    async approveRequest(id) {
        try {
            await api.approveRequest(id, []);
            this.loadData();
        } catch (err) {
            console.error('Failed to approve request:', err);
            alert('Failed to approve request: ' + err.message);
        }
    }

    async denyRequest(id) {
        try {
            await api.denyRequest(id);
            this.loadData();
        } catch (err) {
            console.error('Failed to deny request:', err);
            alert('Failed to deny request: ' + err.message);
        }
    }

    render() {
        if (this.loading) {
            this.innerHTML = '<div class="card">Loading...</div>';
            return;
        }

        this.innerHTML = `
            <h1 class="mb-4">Requests</h1>

            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Pending Requests</h2>
                    <span class="badge badge-info">${this.requests.length} pending</span>
                </div>

                ${this.requests.length === 0 ? `
                    <div class="empty-state">
                        <p>No pending requests.</p>
                        <p class="text-sm text-muted">When someone requests your environment, it will appear here.</p>
                    </div>
                ` : `
                    <table class="table">
                        <thead>
                            <tr>
                                <th>From</th>
                                <th>Environment</th>
                                <th>Requested</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${this.requests.map(r => `
                                <tr>
                                    <td>${r.from}</td>
                                    <td>
                                        <span class="badge badge-${this.envColor(r.env)}">${r.env}</span>
                                    </td>
                                    <td>${this.timeAgo(r.timestamp)}</td>
                                    <td class="flex gap-2">
                                        <button class="btn btn-primary btn-approve" data-id="${r.id}">Approve</button>
                                        <button class="btn btn-secondary btn-deny" data-id="${r.id}">Deny</button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `}
            </div>
        `;

        // Add event listeners
        this.querySelectorAll('.btn-approve').forEach(btn => {
            btn.addEventListener('click', () => this.approveRequest(btn.dataset.id));
        });

        this.querySelectorAll('.btn-deny').forEach(btn => {
            btn.addEventListener('click', () => this.denyRequest(btn.dataset.id));
        });
    }

    envColor(env) {
        switch (env) {
            case 'prod':
            case 'production':
                return 'danger';
            case 'stage':
            case 'staging':
                return 'warning';
            default:
                return 'success';
        }
    }

    timeAgo(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);

        if (seconds < 60) return 'just now';
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return `${Math.floor(seconds / 86400)}d ago`;
    }
}

customElements.define('es-requests', EsRequests);
