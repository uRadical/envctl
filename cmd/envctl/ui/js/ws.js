// WebSocket Client

class WebSocketClient {
    constructor() {
        this.socket = null;
        this.listeners = new Map();
        this.reconnectDelay = 3000;
        this.reconnectTimer = null;
    }

    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = `${protocol}//${window.location.host}/ws`;

        try {
            this.socket = new WebSocket(url);

            this.socket.onopen = () => {
                console.log('WebSocket connected');
                this.emit('connected');
            };

            this.socket.onclose = () => {
                console.log('WebSocket disconnected');
                this.emit('disconnected');
                this.scheduleReconnect();
            };

            this.socket.onerror = (err) => {
                console.error('WebSocket error:', err);
            };

            this.socket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleMessage(data);
                } catch (err) {
                    console.error('Failed to parse message:', err);
                }
            };
        } catch (err) {
            console.error('Failed to connect WebSocket:', err);
            this.scheduleReconnect();
        }
    }

    scheduleReconnect() {
        if (this.reconnectTimer) return;

        this.reconnectTimer = setTimeout(() => {
            this.reconnectTimer = null;
            this.connect();
        }, this.reconnectDelay);
    }

    handleMessage(data) {
        if (data.event) {
            this.emit(data.event, data.payload);
        }
    }

    on(event, callback) {
        if (!this.listeners.has(event)) {
            this.listeners.set(event, new Set());
        }
        this.listeners.get(event).add(callback);
    }

    off(event, callback) {
        if (this.listeners.has(event)) {
            this.listeners.get(event).delete(callback);
        }
    }

    emit(event, payload) {
        if (this.listeners.has(event)) {
            for (const callback of this.listeners.get(event)) {
                try {
                    callback(payload);
                } catch (err) {
                    console.error('Event handler error:', err);
                }
            }
        }
    }

    send(data) {
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.send(JSON.stringify(data));
        }
    }

    close() {
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
            this.reconnectTimer = null;
        }
        if (this.socket) {
            this.socket.close();
        }
    }
}

export const ws = new WebSocketClient();
