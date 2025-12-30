// Card container component

import { BaseComponent } from '../base.js';

class EsCard extends BaseComponent {
    static get observedAttributes() {
        return ['variant', 'padding'];
    }

    attributeChangedCallback() {
        this.render();
    }

    styles() {
        return `
            :host {
                display: block;
            }

            .card {
                background: var(--color-surface, #1f2937);
                border: 1px solid var(--color-border, #374151);
                border-radius: 0.5rem;
                overflow: hidden;
            }

            .card--elevated {
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1),
                            0 2px 4px -2px rgba(0, 0, 0, 0.1);
            }

            .card--outlined {
                background: transparent;
            }

            .card--interactive {
                cursor: pointer;
                transition: all 0.15s ease;
            }

            .card--interactive:hover {
                border-color: var(--color-primary, #818cf8);
            }

            .card__header {
                padding: 1rem;
                border-bottom: 1px solid var(--color-border, #374151);
            }

            .card__body {
                padding: 1rem;
            }

            .card__body--sm {
                padding: 0.75rem;
            }

            .card__body--lg {
                padding: 1.5rem;
            }

            .card__body--none {
                padding: 0;
            }

            .card__footer {
                padding: 1rem;
                border-top: 1px solid var(--color-border, #374151);
                background: var(--color-surface-2, #111827);
            }

            ::slotted([slot="header"]) {
                margin: 0;
            }

            ::slotted([slot="footer"]) {
                margin: 0;
            }
        `;
    }

    template() {
        const variant = this.attr('variant', 'default');
        const padding = this.attr('padding', 'md');
        const hasHeader = this.querySelector('[slot="header"]');
        const hasFooter = this.querySelector('[slot="footer"]');

        const cardClasses = [
            'card',
            variant !== 'default' ? `card--${variant}` : ''
        ].filter(Boolean).join(' ');

        const bodyClasses = [
            'card__body',
            padding !== 'md' ? `card__body--${padding}` : ''
        ].filter(Boolean).join(' ');

        return `
            <div class="${cardClasses}">
                ${hasHeader ? '<div class="card__header"><slot name="header"></slot></div>' : ''}
                <div class="${bodyClasses}">
                    <slot></slot>
                </div>
                ${hasFooter ? '<div class="card__footer"><slot name="footer"></slot></div>' : ''}
            </div>
        `;
    }

    setup() {
        if (this.hasAttr('clickable')) {
            this.$('.card')?.classList.add('card--interactive');
            this.$('.card')?.addEventListener('click', () => {
                this.emit('click');
            });
        }
    }
}

customElements.define('es-card', EsCard);

export { EsCard };
