// Base component class for web components

export class BaseComponent extends HTMLElement {
    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.render();
        this.setup?.();
    }

    disconnectedCallback() {
        this.cleanup?.();
    }

    render() {
        this.shadowRoot.innerHTML = `
            <style>${this.styles()}</style>
            ${this.template()}
        `;
    }

    // Override in subclasses
    styles() {
        return `
            :host {
                display: block;
            }
        `;
    }

    // Override in subclasses
    template() {
        return '';
    }

    // Query selector in shadow root
    $(selector) {
        return this.shadowRoot.querySelector(selector);
    }

    // Query selector all in shadow root
    $$(selector) {
        return this.shadowRoot.querySelectorAll(selector);
    }

    // Emit a custom event
    emit(name, detail) {
        this.dispatchEvent(new CustomEvent(name, {
            detail,
            bubbles: true,
            composed: true
        }));
    }

    // Get attribute with default
    attr(name, defaultValue = '') {
        return this.getAttribute(name) ?? defaultValue;
    }

    // Check if attribute is present
    hasAttr(name) {
        return this.hasAttribute(name);
    }

    // Set multiple attributes
    setAttrs(attrs) {
        for (const [key, value] of Object.entries(attrs)) {
            if (value === null || value === undefined) {
                this.removeAttribute(key);
            } else {
                this.setAttribute(key, value);
            }
        }
    }

    // Update part of the shadow DOM
    update(selector, html) {
        const el = this.$(selector);
        if (el) {
            el.innerHTML = html;
        }
    }
}
