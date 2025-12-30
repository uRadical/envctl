// API Client

const BASE_URL = '/api';

async function request(method, path, body = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
        },
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(`${BASE_URL}${path}`, options);

    if (!response.ok) {
        const error = await response.json().catch(() => ({ message: response.statusText }));
        throw new Error(error.message || 'Request failed');
    }

    return response.json();
}

export const api = {
    // Status
    async getStatus() {
        return request('GET', '/status');
    },

    // Peers
    async getPeers() {
        return request('GET', '/peers');
    },

    async addPeer(addr) {
        return request('POST', '/peers', { addr });
    },

    // Teams
    async getTeams() {
        return request('GET', '/teams');
    },

    async getMembers(teamName = '') {
        const query = teamName ? `?team=${encodeURIComponent(teamName)}` : '';
        return request('GET', `/team/members${query}`);
    },

    async getAccess() {
        return request('GET', '/team/access');
    },

    async getPending() {
        return request('GET', '/team/pending');
    },

    async getLog() {
        return request('GET', '/team/log');
    },

    async invite(name, pubkey, envs, role) {
        return request('POST', '/team/invite', { name, pubkey, envs, role });
    },

    async approveProposal(id) {
        return request('POST', `/team/approve/${id}`);
    },

    async denyProposal(id) {
        return request('POST', `/team/deny/${id}`);
    },

    async grant(member, envs) {
        return request('POST', '/team/grant', { member, envs });
    },

    async revoke(member, envs) {
        return request('POST', '/team/revoke', { member, envs });
    },

    // Requests
    async getRequests() {
        return request('GET', '/requests');
    },

    async approveRequest(id, vars) {
        return request('POST', `/requests/${id}/approve`, { vars });
    },

    async denyRequest(id) {
        return request('POST', `/requests/${id}/deny`);
    },

    // Environment
    async getEnv() {
        return request('GET', '/env');
    },

    async analyzeEnv() {
        return request('GET', '/env/analyze');
    },

    async switchEnv(name) {
        return request('POST', '/env/switch', { name });
    },

    async notifyEnv(env) {
        return request('POST', '/env/notify', { env });
    },

    // Audit
    async getAudit() {
        return request('GET', '/audit');
    },

    // Projects
    async getProjects() {
        return request('GET', '/projects');
    },

    async getProject(name) {
        return request('GET', `/projects/${encodeURIComponent(name)}`);
    },

    async getProjectMembers(name) {
        return request('GET', `/projects/${encodeURIComponent(name)}/members`);
    },
};
