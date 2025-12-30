// Button component

import { BaseComponent } from '../base.js';

class EsButton extends BaseComponent {
    static get observedAttributes() {
        return ['variant', 'size', 'disabled', 'loading'];
    }

    attributeChangedCallback() {
        this.render();
    }

    styles() {
        return `
            :host {
                display: inline-block;
            }

            button {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                gap: 0.5rem;
                padding: 0.5rem 1rem;
                font-family: inherit;
                font-size: 0.875rem;
                font-weight: 500;
                border: 1px solid transparent;
                border-radius: 0.375rem;
                cursor: pointer;
                transition: all 0.15s ease;
                white-space: nowrap;
            }

            button:focus {
                outline: 2px solid var(--color-primary, #818cf8);
                outline-offset: 2px;
            }

            button:disabled {
                opacity: 0.5;
                cursor: not-allowed;
            }

            /* Size variants */
            button.btn--sm {
                padding: 0.25rem 0.75rem;
                font-size: 0.75rem;
            }

            button.btn--lg {
                padding: 0.75rem 1.5rem;
                font-size: 1rem;
            }

            /* Color variants */
            button.btn--primary {
                background: var(--color-primary, #818cf8);
                color: white;
                border-color: var(--color-primary, #818cf8);
            }

            button.btn--primary:hover:not(:disabled) {
                background: var(--color-primary-hover, #6366f1);
            }

            button.btn--secondary {
                background: var(--color-surface-2, #374151);
                color: var(--color-text, #f9fafb);
                border-color: var(--color-border, #4b5563);
            }

            button.btn--secondary:hover:not(:disabled) {
                background: var(--color-surface-3, #4b5563);
            }

            button.btn--ghost {
                background: transparent;
                color: var(--color-text, #f9fafb);
                border-color: transparent;
            }

            button.btn--ghost:hover:not(:disabled) {
                background: var(--color-surface-2, #374151);
            }

            button.btn--danger {
                background: var(--color-error, #ef4444);
                color: white;
                border-color: var(--color-error, #ef4444);
            }

            button.btn--danger:hover:not(:disabled) {
                background: var(--color-error-hover, #dc2626);
            }

            button.btn--success {
                background: var(--color-success, #10b981);
                color: white;
                border-color: var(--color-success, #10b981);
            }

            button.btn--success:hover:not(:disabled) {
                background: var(--color-success-hover, #059669);
            }

            /* Loading spinner */
            .spinner {
                width: 1em;
                height: 1em;
                border: 2px solid currentColor;
                border-right-color: transparent;
                border-radius: 50%;
                animation: spin 0.75s linear infinite;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }
        `;
    }

    template() {
        const variant = this.attr('variant', 'primary');
        const size = this.attr('size', 'md');
        const disabled = this.hasAttr('disabled');
        const loading = this.hasAttr('loading');

        const classes = [
            `btn--${variant}`,
            size !== 'md' ? `btn--${size}` : ''
        ].filter(Boolean).join(' ');

        return `
            <button class="${classes}" ${disabled || loading ? 'disabled' : ''}>
                ${loading ? '<span class="spinner"></span>' : ''}
                <slot></slot>
            </button>
        `;
    }

    setup() {
        this.$('button')?.addEventListener('click', (e) => {
            if (!this.hasAttr('disabled') && !this.hasAttr('loading')) {
                this.emit('click', e);
            }
        });
    }
}

customElements.define('es-button', EsButton);

export { EsButton };
