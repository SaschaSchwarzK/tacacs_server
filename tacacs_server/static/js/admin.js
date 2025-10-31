/**
 * API Client for the Admin Panel
 */
class AdminAPI {
    constructor(baseUrl = '/api/v1', apiToken) {
        this.baseUrl = baseUrl;
        this.apiToken = apiToken;
        this.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        };
        if (this.apiToken) {
            this.headers['Authorization'] = `Bearer ${this.apiToken}`;
        }
    }

    async _request(method, endpoint, data = null) {
        const url = `${this.baseUrl}${endpoint}`;
        const options = {
            method,
            headers: this.headers,
        };
        if (data) {
            options.body = JSON.stringify(data);
        }

        try {
            showLoading();
            const response = await fetch(url, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'An unknown error occurred.' }));
                throw new Error(errorData.message || response.statusText);
            }
            return await response.json();
        } catch (error) {
            showFlash(error.message, 'error');
            throw error;
        } finally {
            hideLoading();
        }
    }

    async get(endpoint) {
        return this._request('GET', endpoint);
    }

    async post(endpoint, data) {
        return this._request('POST', endpoint, data);
    }

    async put(endpoint, data) {
        return this._request('PUT', endpoint, data);
    }

    async delete(endpoint) {
        return this._request('DELETE', endpoint);
    }
}

/**
 * Shows a flash message at the top of the screen.
 */
function showFlash(message, type = 'info', duration = 5000) {
    const flashContainer = document.getElementById('flash-container');
    if (!flashContainer) {
        console.error('#flash-container not found in the DOM.');
        return;
    }

    const type_classes = {
        success: 'bg-green-100 text-green-700',
        error: 'bg-red-100 text-red-700',
        warning: 'bg-yellow-100 text-yellow-700',
        info: 'bg-blue-100 text-blue-700',
    };

    const alert = document.createElement('div');
    alert.className = `rounded-md ${type_classes[type] || type_classes.info} p-4 m-4 shadow-lg`;
    alert.innerHTML = `<p>${message}</p>`;

    flashContainer.appendChild(alert);

    setTimeout(() => {
        alert.style.transition = 'opacity 0.5s ease';
        alert.style.opacity = '0';
        setTimeout(() => alert.remove(), 500);
    }, duration);
}

/**
 * Shows a confirmation dialog using a modal.
 * Relies on an Alpine.js modal component that listens for 'open-modal'.
 */
function confirmAction(message, onConfirm) {
    window.dispatchEvent(new CustomEvent('open-modal', { detail: { id: 'confirm-modal', message } }));

    const confirmButton = document.getElementById('confirm-modal-button');
    const cancelButton = document.getElementById('cancel-modal-button');

    if (!confirmButton) {
        console.error('#confirm-modal-button not found');
        return;
    }

    const confirmHandler = () => {
        onConfirm();
        cleanup();
    };

    const cleanup = () => {
        confirmButton.removeEventListener('click', confirmHandler);
        window.dispatchEvent(new CustomEvent('close-modal', { detail: { id: 'confirm-modal' } }));
    };

    confirmButton.addEventListener('click', confirmHandler, { once: true });
    cancelButton.addEventListener('click', cleanup, { once: true });
}

/**
 * Shows a global loading spinner overlay.
 */
function showLoading() {
    let overlay = document.getElementById('loading-overlay');
    if (!overlay) {
        overlay = document.createElement('div');
        overlay.id = 'loading-overlay';
        overlay.className = 'fixed inset-0 bg-black bg-opacity-50 z-50 flex items-center justify-center';
        overlay.innerHTML = `
            <div class="animate-spin rounded-full h-32 w-32 border-t-2 border-b-2 border-white"></div>
        `;
        document.body.appendChild(overlay);
    }
    overlay.style.display = 'flex';
}

/**
 * Hides the global loading spinner overlay.
 */
function hideLoading() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

/**
 * Copies text to the clipboard and shows a confirmation flash message.
 */
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showFlash('Copied to clipboard!', 'success');
    }, (err) => {
        showFlash('Failed to copy', 'error');
        console.error('Could not copy text: ', err);
    });
}

// Placeholder for more complex, app-specific validation
function validateForm(formElement) {
    console.log('Validating form:', formElement);
    return true;
}

// Placeholder for polling
async function pollUntil(checkFn, timeout = 30000, interval = 1000) {
    console.log('Polling...');
    return new Promise((resolve, reject) => {
        const startTime = Date.now();
        const intervalId = setInterval(() => {
            if (checkFn()) {
                clearInterval(intervalId);
                resolve(true);
            } else if (Date.now() - startTime > timeout) {
                clearInterval(intervalId);
                reject(new Error('Polling timed out'));
            }
        }, interval);
    });
}