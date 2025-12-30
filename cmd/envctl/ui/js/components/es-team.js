// Projects Component (formerly Teams)

import { api } from '../api.js';
import { ws } from '../ws.js';

class EsTeam extends HTMLElement {
    constructor() {
        super();
        this.projects = [];
        this.selectedProject = null;
        this.members = [];
        this.loading = true;
    }

    connectedCallback() {
        this.loadProjects();

        // Listen for chain reload events for real-time updates
        ws.on('chains.reloaded', () => this.loadProjects());
    }

    async loadProjects() {
        try {
            const allProjects = await api.getTeams();
            // Filter out dissolved projects
            this.projects = allProjects.filter(t => !t.dissolved);
            this.loading = false;
            this.render();
        } catch (err) {
            console.error('Failed to load projects:', err);
            this.loading = false;
            this.render();
        }
    }

    async selectProject(projectName) {
        this.selectedProject = projectName;
        this.loading = true;
        this.render();

        try {
            this.members = await api.getMembers(projectName);
            this.loading = false;
            this.render();
        } catch (err) {
            console.error('Failed to load project members:', err);
            this.loading = false;
            this.render();
        }
    }

    goBack() {
        this.selectedProject = null;
        this.members = [];
        this.render();
    }

    render() {
        if (this.loading) {
            this.innerHTML = '<div class="card">Loading...</div>';
            return;
        }

        if (this.selectedProject) {
            this.renderProjectDetail();
        } else {
            this.renderProjectsList();
        }
    }

    renderProjectsList() {
        const project = this.projects.find(t => t.name === this.selectedProject);

        this.innerHTML = `
            <div class="flex gap-4 mb-4">
                <h1>Projects</h1>
            </div>

            ${this.projects.length === 0 ? `
                <div class="card">
                    <div class="empty-state">
                        <p>No projects found.</p>
                        <p class="text-sm text-muted">Create a project using: envctl project create &lt;name&gt;</p>
                    </div>
                </div>
            ` : `
                <div class="projects-grid">
                    ${this.projects.map(p => `
                        <div class="card project-card" data-project="${p.name}">
                            <div class="card-header">
                                <h2 class="card-title">${p.name}</h2>
                            </div>
                            <div class="project-stats">
                                <div class="stat">
                                    <span class="stat-value">${p.member_count}</span>
                                    <span class="stat-label">member${p.member_count !== 1 ? 's' : ''}</span>
                                </div>
                                <div class="stat">
                                    <span class="stat-value">${p.block_count}</span>
                                    <span class="stat-label">block${p.block_count !== 1 ? 's' : ''}</span>
                                </div>
                            </div>
                            <div class="project-envs">
                                ${(p.environments || []).map(e => `
                                    <span class="badge badge-info">${e}</span>
                                `).join('')}
                            </div>
                        </div>
                    `).join('')}
                </div>
            `}

            <style>
                .projects-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                    gap: 1rem;
                }
                .project-card {
                    cursor: pointer;
                    transition: transform 0.15s, box-shadow 0.15s;
                }
                .project-card:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                }
                .project-stats {
                    display: flex;
                    gap: 2rem;
                    margin: 1rem 0;
                }
                .stat {
                    display: flex;
                    flex-direction: column;
                }
                .stat-value {
                    font-size: 1.5rem;
                    font-weight: 600;
                }
                .stat-label {
                    font-size: 0.875rem;
                    color: var(--text-muted);
                }
                .project-envs {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 0.5rem;
                }
            </style>
        `;

        // Add click listeners
        this.querySelectorAll('.project-card').forEach(card => {
            card.addEventListener('click', () => {
                this.selectProject(card.dataset.project);
            });
        });
    }

    renderProjectDetail() {
        const project = this.projects.find(p => p.name === this.selectedProject);

        this.innerHTML = `
            <div class="flex gap-4 mb-4 align-center">
                <button class="btn btn-secondary back-btn">&larr; Back</button>
                <h1>${this.selectedProject}</h1>
            </div>

            <div class="project-detail-grid">
                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Members</h2>
                        <span class="badge badge-info">${this.members.length}</span>
                    </div>

                    ${this.members.length === 0 ? `
                        <div class="empty-state">
                            <p>No members found.</p>
                        </div>
                    ` : `
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Role</th>
                                    <th>Environments</th>
                                    <th>Joined</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${this.members.map(m => `
                                    <tr>
                                        <td>${m.name}</td>
                                        <td>
                                            <span class="badge ${m.role === 'admin' ? 'badge-warning' : 'badge-info'}">
                                                ${m.role}
                                            </span>
                                        </td>
                                        <td>${(m.environments || []).join(', ') || '-'}</td>
                                        <td>${new Date(m.joined_at).toLocaleDateString()}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    `}
                </div>

                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Environments</h2>
                    </div>
                    <div class="env-list">
                        ${(project?.environments || []).map(e => `
                            <div class="env-item">
                                <span class="badge badge-info">${e}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <div class="card">
                    <div class="card-header">
                        <h2 class="card-title">Info</h2>
                    </div>
                    <div class="info-list">
                        <div class="info-row">
                            <span class="info-label">Blocks</span>
                            <span class="info-value">${project?.block_count || 0}</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Status</span>
                            <span class="info-value">Active</span>
                        </div>
                    </div>
                </div>
            </div>

            <style>
                .back-btn {
                    padding: 0.5rem 1rem;
                }
                .align-center {
                    align-items: center;
                }
                .project-detail-grid {
                    display: grid;
                    grid-template-columns: 2fr 1fr;
                    gap: 1rem;
                }
                .project-detail-grid > .card:first-child {
                    grid-row: span 2;
                }
                .env-list {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 0.5rem;
                    padding: 1rem;
                }
                .info-list {
                    padding: 0 1rem 1rem;
                }
                .info-row {
                    display: flex;
                    justify-content: space-between;
                    padding: 0.5rem 0;
                    border-bottom: 1px solid var(--border-color);
                }
                .info-row:last-child {
                    border-bottom: none;
                }
                .info-label {
                    color: var(--text-muted);
                }
                .info-value {
                    font-weight: 500;
                }
                @media (max-width: 768px) {
                    .project-detail-grid {
                        grid-template-columns: 1fr;
                    }
                    .project-detail-grid > .card:first-child {
                        grid-row: auto;
                    }
                }
            </style>
        `;

        // Add back button listener
        this.querySelector('.back-btn').addEventListener('click', () => {
            this.goBack();
        });
    }
}

customElements.define('es-team', EsTeam);
