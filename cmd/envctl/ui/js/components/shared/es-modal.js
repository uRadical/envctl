// Modal dialog component

import { BaseComponent } from '../base.js';

class EsModal extends BaseComponent {
    static get observedAttributes() {
        return ['open', 'size'];
    }

    attributeChangedCallback(name, oldValue, newValue) {
        if (name === 'open') {
            if (newValue !== null) {
                this.show();
            } else {
                this.hide();
            }
        }
    }

    styles() {
        return `
            :host {
                display: none;
            }

            :host([open]) {
                display: block;
            }

            .overlay {
                position: fixed;
                inset: 0;
                background: rgba(0, 0, 0, 0.75);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 100;
                padding: 1rem;
                animation: fadeIn 0.15s ease;
            }

            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }

            .modal {
                background: var(--color-surface, #1f2937);
                border: 1px solid var(--color-border, #374151);
                border-radius: 0.5rem;
                max-height: 90vh;
                overflow: hidden;
                display: flex;
                flex-direction: column;
                animation: slideIn 0.15s ease;
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

            .modal--sm {
                width: 100%;
                max-width: 400px;
            }

            .modal--md {
                width: 100%;
                max-width: 560px;
            }

            .modal--lg {
                width: 100%;
                max-width: 800px;
            }

            .modal--full {
                width: 100%;
                max-width: calc(100vw - 2rem);
                max-height: calc(100vh - 2rem);
            }

            .modal__header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 1rem;
                border-bottom: 1px solid var(--color-border, #374151);
            }

            .modal__title {
                font-size: 1.125rem;
                font-weight: 600;
                margin: 0;
            }

            .modal__close {
                background: none;
                border: none;
                color: var(--color-text-muted, #9ca3af);
                cursor: pointer;
                padding: 0.25rem;
                line-height: 1;
                font-size: 1.5rem;
            }

            .modal__close:hover {
                color: var(--color-text, #f9fafb);
            }

            .modal__body {
                padding: 1rem;
                overflow-y: auto;
                flex: 1;
            }

            .modal__footer {
                display: flex;
                align-items: center;
                justify-content: flex-end;
                gap: 0.5rem;
                padding: 1rem;
                border-top: 1px solid var(--color-border, #374151);
                background: var(--color-surface-2, #111827);
            }
        `;
    }

    template() {
        const size = this.attr('size', 'md');
        const title = this.attr('title', '');
        const hasFooter = this.querySelector('[slot="footer"]');

        return `
            <div class="overlay">
                <div class="modal modal--${size}" role="dialog" aria-modal="true">
                    <div class="modal__header">
                        <h2 class="modal__title">${title}</h2>
                        <button class="modal__close" aria-label="Close">&times;</button>
                    </div>
                    <div class="modal__body">
                        <slot></slot>
                    </div>
                    ${hasFooter ? '<div class="modal__footer"><slot name="footer"></slot></div>' : ''}
                </div>
            </div>
        `;
    }

    setup() {
        // Close on overlay click
        this.$('.overlay')?.addEventListener('click', (e) => {
            if (e.target === e.currentTarget) {
                this.close();
            }
        });

        // Close button
        this.$('.modal__close')?.addEventListener('click', () => {
            this.close();
        });

        // Close on Escape key
        this._handleKeydown = (e) => {
            if (e.key === 'Escape' && this.hasAttr('open')) {
                this.close();
            }
        };
        document.addEventListener('keydown', this._handleKeydown);
    }

    cleanup() {
        if (this._handleKeydown) {
            document.removeEventListener('keydown', this._handleKeydown);
        }
    }

    show() {
        this.setAttribute('open', '');
        document.body.style.overflow = 'hidden';
        this.emit('open');
    }

    hide() {
        this.removeAttribute('open');
        document.body.style.overflow = '';
        this.emit('close');
    }

    close() {
        this.emit('before-close');
        this.hide();
    }
}

customElements.define('es-modal', EsModal);

export { EsModal };
