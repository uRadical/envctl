// Log Viewer Component

import { api } from '../api.js';

class EsLogs extends HTMLElement {
    constructor() {
        super();
        this.logs = [];
        this.filteredLogs = [];
        this.levelFilter = 'ALL';
        this.searchQuery = '';
        this.timeRange = '1h';
        this.loading = true;
        this.expandedRow = null;
    }

    connectedCallback() {
        this.render();
        this.loadLogs();
    }

    async loadLogs() {
        this.loading = true;
        this.render();

        try {
            const params = new URLSearchParams();

            if (this.timeRange !== 'all') {
                const since = this.getTimeRangeStart();
                params.set('since', since.toISOString());
            }

            params.set('limit', '5000');

            const response = await fetch(`/api/logs?${params}`);
            const data = await response.json();
            this.logs = data.entries || [];
            this.applyFilters();
        } catch (err) {
            console.error('Failed to load logs:', err);
            this.logs = [];
            this.filteredLogs = [];
        }

        this.loading = false;
        this.render();
    }

    getTimeRangeStart() {
        const now = new Date();
        switch (this.timeRange) {
            case '5m': return new Date(now - 5 * 60 * 1000);
            case '15m': return new Date(now - 15 * 60 * 1000);
            case '1h': return new Date(now - 60 * 60 * 1000);
            case '24h': return new Date(now - 24 * 60 * 60 * 1000);
            default: return new Date(0);
        }
    }

    applyFilters() {
        this.filteredLogs = this.logs.filter(log => {
            // Level filter
            if (this.levelFilter !== 'ALL') {
                const levels = { 'DEBUG': 0, 'INFO': 1, 'WARN': 2, 'ERROR': 3 };
                if (levels[log.level] < levels[this.levelFilter]) {
                    return false;
                }
            }

            // Search filter
            if (this.searchQuery) {
                const query = this.searchQuery.toLowerCase();
                const inMessage = log.msg.toLowerCase().includes(query);
                const inFields = log.fields && Object.entries(log.fields)
                    .some(([k, v]) =>
                        k.toLowerCase().includes(query) ||
                        String(v).toLowerCase().includes(query)
                    );

                if (!inMessage && !inFields) {
                    return false;
                }
            }

            return true;
        });

        // Sort newest first
        this.filteredLogs.sort((a, b) => new Date(b.ts) - new Date(a.ts));
    }

    countByLevel(level) {
        return this.logs.filter(l => l.level === level).length;
    }

    truncate(str, len) {
        if (!str) return '';
        str = String(str);
        if (str.length <= len) return str;
        return str.substring(0, len) + '...';
    }

    highlightSearch(text) {
        if (!this.searchQuery || !text) return text;
        const escaped = this.searchQuery.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`(${escaped})`, 'gi');
        return text.replace(regex, '<span class="highlight">$1</span>');
    }

    renderFields(fields) {
        if (!fields || Object.keys(fields).length === 0) {
            return '';
        }

        return Object.entries(fields)
            .slice(0, 3)
            .map(([k, v]) => `<span class="field-key">${k}</span>=<span class="field-value">${this.truncate(String(v), 20)}</span>`)
            .join(' ');
    }

    renderLogRow(log, idx) {
        const time = new Date(log.ts).toLocaleTimeString();
        const level = log.level.toLowerCase();
        const fields = this.renderFields(log.fields);
        const message = this.highlightSearch(log.msg);

        return `
            <tr data-idx="${idx}" class="${this.expandedRow === idx ? 'expanded' : ''}">
                <td class="time">${time}</td>
                <td class="level ${level}">${log.level}</td>
                <td class="message">${message}</td>
                <td class="fields">${fields}</td>
            </tr>
            ${this.expandedRow === idx ? `
                <tr class="expanded-row">
                    <td colspan="4">
                        <div class="expanded-fields">
                            <pre>${JSON.stringify(log, null, 2)}</pre>
                        </div>
                    </td>
                </tr>
            ` : ''}
        `;
    }

    renderLogs() {
        if (this.loading) {
            return `<div class="empty-state"><span class="spinner">Loading...</span></div>`;
        }

        if (this.filteredLogs.length === 0) {
            return `<div class="empty-state">No logs match the current filters</div>`;
        }

        return `
            <table class="log-table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Level</th>
                        <th>Message</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    ${this.filteredLogs.map((log, idx) => this.renderLogRow(log, idx)).join('')}
                </tbody>
            </table>
        `;
    }

    exportLogs() {
        const data = JSON.stringify(this.filteredLogs, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `envshare-logs-${new Date().toISOString().split('T')[0]}.json`;
        a.click();

        URL.revokeObjectURL(url);
    }

    render() {
        this.innerHTML = `
            <style>
                .logs-container {
                    display: flex;
                    flex-direction: column;
                    height: calc(100vh - 2rem);
                    gap: 1rem;
                }

                .toolbar {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 1rem;
                    align-items: center;
                    padding: 1rem;
                    background: var(--surface-color, #1e1e2e);
                    border-radius: 8px;
                    border: 1px solid var(--border-color, #313244);
                }

                .filter-group {
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }

                .filter-group label {
                    font-size: 0.875rem;
                    color: var(--text-muted, #6c7086);
                }

                select, input[type="text"] {
                    padding: 0.5rem 0.75rem;
                    border: 1px solid var(--border-color, #313244);
                    border-radius: 4px;
                    background: var(--bg-color, #11111b);
                    color: var(--text-color, #cdd6f4);
                    font-size: 0.875rem;
                }

                input[type="text"] {
                    width: 200px;
                }

                .level-buttons {
                    display: flex;
                    gap: 2px;
                }

                .level-btn {
                    padding: 0.25rem 0.5rem;
                    border: 1px solid var(--border-color, #313244);
                    background: var(--bg-color, #11111b);
                    color: var(--text-muted, #6c7086);
                    font-size: 0.75rem;
                    cursor: pointer;
                    transition: all 0.15s;
                }

                .level-btn:first-child {
                    border-radius: 4px 0 0 4px;
                }

                .level-btn:last-child {
                    border-radius: 0 4px 4px 0;
                }

                .level-btn.active {
                    background: var(--primary-color, #89b4fa);
                    color: var(--bg-color, #11111b);
                    border-color: var(--primary-color, #89b4fa);
                }

                .level-btn.debug.active { background: var(--text-muted, #6c7086); border-color: var(--text-muted, #6c7086); }
                .level-btn.info.active { background: var(--info-color, #89dceb); border-color: var(--info-color, #89dceb); }
                .level-btn.warn.active { background: var(--warning-color, #f9e2af); border-color: var(--warning-color, #f9e2af); }
                .level-btn.error.active { background: var(--danger-color, #f38ba8); border-color: var(--danger-color, #f38ba8); }

                .actions {
                    margin-left: auto;
                    display: flex;
                    gap: 0.5rem;
                }

                button {
                    padding: 0.5rem 0.75rem;
                    border: 1px solid var(--border-color, #313244);
                    border-radius: 4px;
                    background: var(--surface-color, #1e1e2e);
                    color: var(--text-color, #cdd6f4);
                    font-size: 0.875rem;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    gap: 0.25rem;
                }

                button:hover {
                    background: var(--hover-color, #313244);
                }

                .log-container {
                    flex: 1;
                    overflow: auto;
                    background: var(--surface-color, #1e1e2e);
                    border: 1px solid var(--border-color, #313244);
                    border-radius: 8px;
                    font-family: 'SF Mono', 'Consolas', 'Monaco', monospace;
                    font-size: 0.8125rem;
                }

                .log-table {
                    width: 100%;
                    border-collapse: collapse;
                }

                .log-table th {
                    position: sticky;
                    top: 0;
                    background: var(--hover-color, #313244);
                    padding: 0.5rem 0.75rem;
                    text-align: left;
                    font-weight: 600;
                    font-size: 0.75rem;
                    color: var(--text-muted, #6c7086);
                    text-transform: uppercase;
                    border-bottom: 1px solid var(--border-color, #313244);
                }

                .log-table td {
                    padding: 0.5rem 0.75rem;
                    border-bottom: 1px solid var(--border-color, #313244);
                    vertical-align: top;
                }

                .log-table tr:hover {
                    background: var(--hover-color, #313244);
                    cursor: pointer;
                }

                .log-table tr.expanded {
                    background: var(--hover-color, #313244);
                }

                .time {
                    color: var(--text-muted, #6c7086);
                    white-space: nowrap;
                    width: 90px;
                }

                .level {
                    width: 60px;
                    font-weight: 600;
                }

                .level.debug { color: var(--text-muted, #6c7086); }
                .level.info { color: var(--info-color, #89dceb); }
                .level.warn { color: var(--warning-color, #f9e2af); }
                .level.error { color: var(--danger-color, #f38ba8); }

                .message {
                    color: var(--text-color, #cdd6f4);
                }

                .fields {
                    color: var(--text-muted, #6c7086);
                    font-size: 0.75rem;
                }

                .field-key {
                    color: var(--primary-color, #89b4fa);
                }

                .field-value {
                    color: var(--text-muted, #6c7086);
                }

                .expanded-fields {
                    padding: 0.5rem 0.75rem;
                    background: var(--bg-color, #11111b);
                    border-radius: 4px;
                    margin-top: 0.5rem;
                }

                .expanded-fields pre {
                    margin: 0;
                    white-space: pre-wrap;
                    word-break: break-all;
                    color: var(--text-color, #cdd6f4);
                }

                .status-bar {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 0.5rem 0.75rem;
                    background: var(--surface-color, #1e1e2e);
                    border-radius: 8px;
                    border: 1px solid var(--border-color, #313244);
                    font-size: 0.875rem;
                    color: var(--text-muted, #6c7086);
                }

                .status-bar .counts {
                    display: flex;
                    gap: 1rem;
                }

                .count-item {
                    display: flex;
                    align-items: center;
                    gap: 0.25rem;
                }

                .count-dot {
                    width: 8px;
                    height: 8px;
                    border-radius: 50%;
                }

                .count-dot.error { background: var(--danger-color, #f38ba8); }
                .count-dot.warn { background: var(--warning-color, #f9e2af); }
                .count-dot.info { background: var(--info-color, #89dceb); }

                .empty-state {
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    height: 200px;
                    color: var(--text-muted, #6c7086);
                }

                .highlight {
                    background: var(--warning-color, #f9e2af);
                    color: var(--bg-color, #11111b);
                    padding: 0 2px;
                    border-radius: 2px;
                }

                h1 {
                    margin: 0 0 1rem 0;
                }
            </style>

            <h1>Logs</h1>

            <div class="logs-container">
                <div class="toolbar">
                    <div class="filter-group">
                        <label>Level:</label>
                        <div class="level-buttons">
                            <button class="level-btn ${this.levelFilter === 'ALL' ? 'active' : ''}" data-level="ALL">All</button>
                            <button class="level-btn debug ${this.levelFilter === 'DEBUG' ? 'active' : ''}" data-level="DEBUG">Debug</button>
                            <button class="level-btn info ${this.levelFilter === 'INFO' ? 'active' : ''}" data-level="INFO">Info</button>
                            <button class="level-btn warn ${this.levelFilter === 'WARN' ? 'active' : ''}" data-level="WARN">Warn</button>
                            <button class="level-btn error ${this.levelFilter === 'ERROR' ? 'active' : ''}" data-level="ERROR">Error</button>
                        </div>
                    </div>

                    <div class="filter-group">
                        <label>Time:</label>
                        <select id="time-range">
                            <option value="5m" ${this.timeRange === '5m' ? 'selected' : ''}>Last 5 minutes</option>
                            <option value="15m" ${this.timeRange === '15m' ? 'selected' : ''}>Last 15 minutes</option>
                            <option value="1h" ${this.timeRange === '1h' ? 'selected' : ''}>Last hour</option>
                            <option value="24h" ${this.timeRange === '24h' ? 'selected' : ''}>Last 24 hours</option>
                            <option value="all" ${this.timeRange === 'all' ? 'selected' : ''}>All</option>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label>Search:</label>
                        <input type="text" id="search" placeholder="Filter logs..." value="${this.searchQuery}">
                    </div>

                    <div class="actions">
                        <button id="refresh-btn">Refresh</button>
                        <button id="export-btn">Export</button>
                    </div>
                </div>

                <div class="log-container">
                    ${this.renderLogs()}
                </div>

                <div class="status-bar">
                    <div class="counts">
                        <span>${this.filteredLogs.length} entries shown</span>
                        <span class="count-item"><span class="count-dot error"></span> ${this.countByLevel('ERROR')} errors</span>
                        <span class="count-item"><span class="count-dot warn"></span> ${this.countByLevel('WARN')} warnings</span>
                    </div>
                    <div>
                        Buffer: ${this.logs.length} / 10,000
                    </div>
                </div>
            </div>
        `;

        this.setupEventListeners();
    }

    setupEventListeners() {
        // Level filter buttons
        this.querySelectorAll('.level-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.levelFilter = e.target.dataset.level;
                this.applyFilters();
                this.render();
            });
        });

        // Time range
        const timeRange = this.querySelector('#time-range');
        if (timeRange) {
            timeRange.addEventListener('change', (e) => {
                this.timeRange = e.target.value;
                this.loadLogs();
            });
        }

        // Search
        const search = this.querySelector('#search');
        if (search) {
            let searchTimeout;
            search.addEventListener('input', (e) => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    this.searchQuery = e.target.value;
                    this.applyFilters();
                    this.render();
                }, 200);
            });
        }

        // Refresh
        const refreshBtn = this.querySelector('#refresh-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.loadLogs();
            });
        }

        // Export
        const exportBtn = this.querySelector('#export-btn');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                this.exportLogs();
            });
        }

        // Row click for expansion
        const tbody = this.querySelector('.log-table tbody');
        if (tbody) {
            tbody.addEventListener('click', (e) => {
                const row = e.target.closest('tr[data-idx]');
                if (row) {
                    const idx = parseInt(row.dataset.idx);
                    this.expandedRow = this.expandedRow === idx ? null : idx;
                    this.render();
                }
            });
        }
    }
}

customElements.define('es-logs', EsLogs);
