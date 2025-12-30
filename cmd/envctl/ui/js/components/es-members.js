// Members Component - Shows project members with online status

import { api } from '../api.js';
import { ws } from '../ws.js';

class EsMembers extends HTMLElement {
    constructor() {
        super();
        this.projects = [];
        this.members = [];
        this.selectedProject = null;
        this.refreshInterval = null;
    }

    connectedCallback() {
        this.render();
        this.loadProjects();

        // Auto-refresh every 30 seconds
        this.refreshInterval = setInterval(() => this.refreshMembers(), 30000);

        // Listen for peer events
        ws.on('peer_connected', () => this.refreshMembers());
        ws.on('peer_disconnected', () => this.refreshMembers());
    }

    disconnectedCallback() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
        }
    }

    async loadProjects() {
        try {
            this.projects = await api.getProjects();
            if (this.projects.length > 0 && !this.selectedProject) {
                this.selectedProject = this.projects[0].name;
            }
            this.render();
            if (this.selectedProject) {
                this.loadMembers();
            }
        } catch (err) {
            console.error('Failed to load projects:', err);
        }
    }

    async loadMembers() {
        if (!this.selectedProject) return;

        try {
            this.members = await api.getProjectMembers(this.selectedProject);
            this.render();
        } catch (err) {
            console.error('Failed to load members:', err);
        }
    }

    async refreshMembers() {
        if (this.selectedProject) {
            await this.loadMembers();
        }
    }

    selectProject(projectName) {
        this.selectedProject = projectName;
        this.loadMembers();
    }

    formatLastSeen(lastSeen) {
        if (!lastSeen || lastSeen === '0001-01-01T00:00:00Z') {
            return 'Never';
        }

        const date = new Date(lastSeen);
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);

        if (diffSec < 60) return 'Just now';
        if (diffMin < 60) return `${diffMin}m ago`;
        if (diffHour < 24) return `${diffHour}h ago`;
        if (diffDay < 7) return `${diffDay}d ago`;

        return date.toLocaleDateString();
    }

    render() {
        const onlineCount = this.members.filter(m => m.online).length;
        const totalCount = this.members.length;

        this.innerHTML = `
            <div class="members-container">
                <div class="members-header">
                    <h2>Members</h2>
                    <div class="members-controls">
                        <select class="project-select">
                            ${this.projects.map(p => `
                                <option value="${p.name}" ${p.name === this.selectedProject ? 'selected' : ''}>
                                    ${p.name}
                                </option>
                            `).join('')}
                        </select>
                        <button class="btn-refresh" title="Refresh">Refresh</button>
                    </div>
                </div>

                <div class="members-stats">
                    <span class="stat-online">${onlineCount} online</span>
                    <span class="stat-total">${totalCount} total</span>
                </div>

                <div class="members-list">
                    ${this.members.length === 0 ? `
                        <div class="members-empty">
                            ${this.projects.length === 0
                                ? 'No projects found. Create a project to see members.'
                                : 'No members in this project.'}
                        </div>
                    ` : this.members.map(m => this.renderMember(m)).join('')}
                </div>
            </div>

            <style>
                .members-container {
                    padding: 1.5rem;
                    max-width: 800px;
                }

                .members-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 1rem;
                }

                .members-header h2 {
                    margin: 0;
                    font-size: 1.25rem;
                    font-weight: 600;
                }

                .members-controls {
                    display: flex;
                    gap: 0.5rem;
                    align-items: center;
                }

                .project-select {
                    padding: 0.5rem;
                    border: 1px solid var(--border);
                    border-radius: 4px;
                    background: var(--bg-secondary);
                    color: var(--text);
                    font-size: 0.875rem;
                }

                .btn-refresh {
                    padding: 0.5rem 1rem;
                    border: 1px solid var(--border);
                    border-radius: 4px;
                    background: var(--bg-secondary);
                    color: var(--text);
                    cursor: pointer;
                    font-size: 0.875rem;
                }

                .btn-refresh:hover {
                    background: var(--bg-tertiary);
                }

                .members-stats {
                    display: flex;
                    gap: 1rem;
                    margin-bottom: 1rem;
                    font-size: 0.875rem;
                    color: var(--text-muted);
                }

                .stat-online {
                    color: var(--success);
                }

                .members-list {
                    display: flex;
                    flex-direction: column;
                    gap: 0.5rem;
                }

                .members-empty {
                    text-align: center;
                    padding: 2rem;
                    color: var(--text-muted);
                }

                .member-card {
                    display: flex;
                    align-items: center;
                    padding: 1rem;
                    background: var(--bg-secondary);
                    border: 1px solid var(--border);
                    border-radius: 6px;
                    gap: 1rem;
                }

                .member-status {
                    width: 10px;
                    height: 10px;
                    border-radius: 50%;
                    flex-shrink: 0;
                }

                .member-status.online {
                    background: var(--success);
                    box-shadow: 0 0 6px var(--success);
                }

                .member-status.offline {
                    background: var(--text-muted);
                }

                .member-info {
                    flex: 1;
                    min-width: 0;
                }

                .member-name {
                    font-weight: 500;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }

                .member-name .self-badge {
                    font-size: 0.7rem;
                    padding: 0.1rem 0.4rem;
                    background: var(--accent);
                    color: white;
                    border-radius: 3px;
                }

                .member-fingerprint {
                    font-family: var(--font-mono);
                    font-size: 0.75rem;
                    color: var(--text-muted);
                }

                .member-role {
                    font-size: 0.75rem;
                    padding: 0.2rem 0.5rem;
                    border-radius: 3px;
                    text-transform: capitalize;
                }

                .member-role.admin {
                    background: var(--warning);
                    color: black;
                }

                .member-role.member {
                    background: var(--bg-tertiary);
                    color: var(--text);
                }

                .member-envs {
                    display: flex;
                    gap: 0.25rem;
                    flex-wrap: wrap;
                }

                .member-env {
                    font-size: 0.7rem;
                    padding: 0.1rem 0.4rem;
                    background: var(--bg-tertiary);
                    border-radius: 3px;
                    color: var(--text-muted);
                }

                .member-lastseen {
                    font-size: 0.75rem;
                    color: var(--text-muted);
                    text-align: right;
                    min-width: 80px;
                }
            </style>
        `;

        // Add event listeners
        const projectSelect = this.querySelector('.project-select');
        if (projectSelect) {
            projectSelect.addEventListener('change', (e) => {
                this.selectProject(e.target.value);
            });
        }

        const refreshBtn = this.querySelector('.btn-refresh');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refreshMembers());
        }
    }

    renderMember(member) {
        const envBadges = (member.environments || [])
            .map(env => `<span class="member-env">${env}</span>`)
            .join('');

        // Check if this is ourselves (fingerprint matches daemon identity)
        const isSelf = member.online && member.last_seen &&
            (new Date() - new Date(member.last_seen)) < 1000;

        return `
            <div class="member-card">
                <div class="member-status ${member.online ? 'online' : 'offline'}"></div>
                <div class="member-info">
                    <div class="member-name">
                        ${member.name}
                        ${isSelf ? '<span class="self-badge">you</span>' : ''}
                    </div>
                    <div class="member-fingerprint">${member.fingerprint}</div>
                </div>
                <div class="member-envs">${envBadges}</div>
                <div class="member-role ${member.role}">${member.role}</div>
                <div class="member-lastseen">
                    ${member.online ? 'Online' : this.formatLastSeen(member.last_seen)}
                </div>
            </div>
        `;
    }
}

customElements.define('es-members', EsMembers);
