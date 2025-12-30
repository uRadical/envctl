// Badge component for status indicators

import { BaseComponent } from '../base.js';

class EsBadge extends BaseComponent {
    static get observedAttributes() {
        return ['variant', 'size'];
    }

    attributeChangedCallback() {
        this.render();
    }

    styles() {
        return `
            :host {
                display: inline-flex;
                align-items: center;
            }

            .badge {
                display: inline-flex;
                align-items: center;
                padding: 0.125rem 0.5rem;
                font-size: 0.75rem;
                font-weight: 500;
                border-radius: 9999px;
                white-space: nowrap;
            }

            /* Size variants */
            .badge--sm {
                padding: 0.0625rem 0.375rem;
                font-size: 0.625rem;
            }

            .badge--lg {
                padding: 0.25rem 0.75rem;
                font-size: 0.875rem;
            }

            /* Color variants */
            .badge--default {
                background: var(--color-surface-2, #374151);
                color: var(--color-text, #f9fafb);
            }

            .badge--success {
                background: var(--color-success-bg, #064e3b);
                color: var(--color-success, #10b981);
            }

            .badge--warning {
                background: var(--color-warning-bg, #78350f);
                color: var(--color-warning, #f59e0b);
            }

            .badge--error {
                background: var(--color-error-bg, #7f1d1d);
                color: var(--color-error, #ef4444);
            }

            .badge--info {
                background: var(--color-info-bg, #1e3a5f);
                color: var(--color-info, #3b82f6);
            }

            .badge--online {
                background: var(--color-success-bg, #064e3b);
                color: var(--color-success, #10b981);
            }

            .badge--offline {
                background: var(--color-surface-2, #374151);
                color: var(--color-text-muted, #9ca3af);
            }

            .badge--admin {
                background: var(--color-primary-bg, #312e81);
                color: var(--color-primary, #818cf8);
            }

            .badge--member {
                background: var(--color-surface-2, #374151);
                color: var(--color-text, #f9fafb);
            }

            /* Dot indicator */
            .badge--dot::before {
                content: '';
                width: 0.5rem;
                height: 0.5rem;
                border-radius: 50%;
                margin-right: 0.375rem;
            }

            .badge--online.badge--dot::before {
                background: var(--color-success, #10b981);
            }

            .badge--offline.badge--dot::before {
                background: var(--color-text-muted, #9ca3af);
            }
        `;
    }

    template() {
        const variant = this.attr('variant', 'default');
        const size = this.attr('size', 'md');
        const dot = this.hasAttr('dot');

        const classes = [
            'badge',
            `badge--${variant}`,
            size !== 'md' ? `badge--${size}` : '',
            dot ? 'badge--dot' : ''
        ].filter(Boolean).join(' ');

        return `<span class="${classes}"><slot></slot></span>`;
    }
}

customElements.define('es-badge', EsBadge);

export { EsBadge };
