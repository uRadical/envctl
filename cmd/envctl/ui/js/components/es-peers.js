// Peers Component

import { api } from '../api.js';

class EsPeers extends HTMLElement {
    constructor() {
        super();
        this.peers = [];
        this.loading = true;
    }

    connectedCallback() {
        this.loadData();
    }

    async loadData() {
        try {
            this.peers = await api.getPeers();
            this.loading = false;
            this.render();
        } catch (err) {
            console.error('Failed to load peers:', err);
            this.loading = false;
            this.peers = [];
            this.render();
        }
    }

    async addPeer() {
        const addr = prompt('Enter peer address (host:port):');
        if (!addr) return;

        try {
            await api.addPeer(addr);
            this.loadData();
        } catch (err) {
            console.error('Failed to add peer:', err);
            alert('Failed to add peer: ' + err.message);
        }
    }

    render() {
        if (this.loading) {
            this.innerHTML = '<div class="card">Loading...</div>';
            return;
        }

        const connectedCount = this.peers.filter(p => p.connected).length;

        this.innerHTML = `
            <div class="flex gap-4 mb-4">
                <h1>Peers</h1>
                <button class="btn btn-primary" id="add-peer-btn">Add Peer</button>
            </div>

            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">Connected Peers</h2>
                    <span class="badge badge-success">${connectedCount} connected</span>
                </div>

                ${this.peers.length === 0 ? `
                    <div class="empty-state">
                        <p>No peers connected.</p>
                        <p class="text-sm text-muted">Peers are discovered automatically via mDNS on the local network.</p>
                        <p class="text-sm text-muted">You can also add peers manually.</p>
                    </div>
                ` : `
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Name</th>
                                <th>Address</th>
                                <th>Status</th>
                                <th>Teams</th>
                                <th>Last Seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${this.peers.map(p => `
                                <tr>
                                    <td>${p.name || '-'}</td>
                                    <td class="text-mono">${p.addr}</td>
                                    <td>
                                        <span class="badge ${p.connected ? 'badge-success' : 'badge-danger'}">
                                            ${p.connected ? 'connected' : 'disconnected'}
                                        </span>
                                    </td>
                                    <td>${(p.teams || []).join(', ') || '-'}</td>
                                    <td>${p.last_seen ? this.timeAgo(p.last_seen) : '-'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                `}
            </div>
        `;

        // Add event listener
        this.querySelector('#add-peer-btn').addEventListener('click', () => this.addPeer());
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

customElements.define('es-peers', EsPeers);
