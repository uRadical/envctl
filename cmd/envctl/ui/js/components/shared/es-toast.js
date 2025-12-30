// Toast notification component

import { BaseComponent } from '../base.js';

class EsToast extends BaseComponent {
    static get observedAttributes() {
        return ['variant', 'duration', 'dismissible'];
    }

    styles() {
        return `
            :host {
                display: block;
            }

            .toast {
                display: flex;
                align-items: flex-start;
                gap: 0.75rem;
                padding: 0.75rem 1rem;
                border-radius: 0.5rem;
                animation: slideIn 0.2s ease;
                min-width: 280px;
                max-width: 400px;
            }

            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateY(-10px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }

            @keyframes slideOut {
                from {
                    opacity: 1;
                    transform: translateY(0);
                }
                to {
                    opacity: 0;
                    transform: translateY(-10px);
                }
            }

            .toast--closing {
                animation: slideOut 0.2s ease forwards;
            }

            .toast--info {
                background: var(--color-info-bg, #1e3a5f);
                border: 1px solid var(--color-info, #3b82f6);
                color: var(--color-text, #f9fafb);
            }

            .toast--success {
                background: var(--color-success-bg, #064e3b);
                border: 1px solid var(--color-success, #10b981);
                color: var(--color-text, #f9fafb);
            }

            .toast--warning {
                background: var(--color-warning-bg, #78350f);
                border: 1px solid var(--color-warning, #f59e0b);
                color: var(--color-text, #f9fafb);
            }

            .toast--error {
                background: var(--color-error-bg, #7f1d1d);
                border: 1px solid var(--color-error, #ef4444);
                color: var(--color-text, #f9fafb);
            }

            .toast__icon {
                flex-shrink: 0;
                font-size: 1.25rem;
                line-height: 1;
            }

            .toast__content {
                flex: 1;
            }

            .toast__title {
                font-weight: 600;
                margin-bottom: 0.25rem;
            }

            .toast__message {
                font-size: 0.875rem;
                opacity: 0.9;
            }

            .toast__close {
                flex-shrink: 0;
                background: none;
                border: none;
                color: currentColor;
                opacity: 0.6;
                cursor: pointer;
                padding: 0;
                font-size: 1.25rem;
                line-height: 1;
            }

            .toast__close:hover {
                opacity: 1;
            }
        `;
    }

    template() {
        const variant = this.attr('variant', 'info');
        const title = this.attr('title', '');
        const dismissible = this.hasAttr('dismissible');

        const icons = {
            info: 'ℹ️',
            success: '✓',
            warning: '⚠️',
            error: '✕'
        };

        return `
            <div class="toast toast--${variant}">
                <span class="toast__icon">${icons[variant] || icons.info}</span>
                <div class="toast__content">
                    ${title ? `<div class="toast__title">${title}</div>` : ''}
                    <div class="toast__message"><slot></slot></div>
                </div>
                ${dismissible ? '<button class="toast__close">&times;</button>' : ''}
            </div>
        `;
    }

    setup() {
        // Auto-dismiss
        const duration = parseInt(this.attr('duration', '5000'));
        if (duration > 0) {
            this._timeout = setTimeout(() => this.dismiss(), duration);
        }

        // Close button
        this.$('.toast__close')?.addEventListener('click', () => {
            this.dismiss();
        });
    }

    cleanup() {
        if (this._timeout) {
            clearTimeout(this._timeout);
        }
    }

    dismiss() {
        const toast = this.$('.toast');
        if (toast) {
            toast.classList.add('toast--closing');
            toast.addEventListener('animationend', () => {
                this.emit('dismiss');
                this.remove();
            });
        }
    }
}

customElements.define('es-toast', EsToast);

// Toast container for managing multiple toasts
class EsToastContainer extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.shadowRoot.innerHTML = `
            <style>
                :host {
                    position: fixed;
                    top: 1rem;
                    right: 1rem;
                    display: flex;
                    flex-direction: column;
                    gap: 0.5rem;
                    z-index: 1000;
                }
            </style>
            <slot></slot>
        `;
    }

    show(message, options = {}) {
        const toast = document.createElement('es-toast');
        toast.textContent = message;

        if (options.variant) toast.setAttribute('variant', options.variant);
        if (options.title) toast.setAttribute('title', options.title);
        if (options.duration !== undefined) toast.setAttribute('duration', options.duration);
        if (options.dismissible !== false) toast.setAttribute('dismissible', '');

        this.appendChild(toast);
        return toast;
    }

    info(message, title = '') {
        return this.show(message, { variant: 'info', title });
    }

    success(message, title = '') {
        return this.show(message, { variant: 'success', title });
    }

    warning(message, title = '') {
        return this.show(message, { variant: 'warning', title });
    }

    error(message, title = '') {
        return this.show(message, { variant: 'error', title });
    }
}

customElements.define('es-toast-container', EsToastContainer);

export { EsToast, EsToastContainer };
