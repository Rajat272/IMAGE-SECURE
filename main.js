/**
 * SECURE-IMG | DES Image Encryption Engine
 * Logic for handling image processing and DES encryption/decryption
 */

// DOM Elements
const elements = {
    imageInput: document.getElementById('imageInput'),
    dropZone: document.getElementById('dropZone'),
    encryptionKey: document.getElementById('encryptionKey'),
    encryptBtn: document.getElementById('encryptBtn'),
    decryptBtn: document.getElementById('decryptBtn'),
    resetBtn: document.getElementById('resetBtn'),
    originalCanvas: document.getElementById('originalCanvas'),
    encryptedCanvas: document.getElementById('encryptedCanvas'),
    decryptedCanvas: document.getElementById('decryptedCanvas'),
    originalInfo: document.getElementById('originalInfo'),
    encryptedInfo: document.getElementById('encryptedInfo'),
    decryptedInfo: document.getElementById('decryptedInfo'),
    procTime: document.getElementById('procTime'),
    integrityStatus: document.getElementById('integrityStatus'),
    appStatus: document.getElementById('appStatus'),
    loader: document.getElementById('loader'),
    originalView: document.getElementById('originalView'),
    encryptedView: document.getElementById('encryptedView'),
    decryptedView: document.getElementById('decryptedView')
};

// Application State
let state = {
    originalImageData: null,
    encryptedData: null, 
    originalWidth: 0,
    originalHeight: 0
};

// Initialize
function init() {
    setupEventListeners();
}

function setupEventListeners() {
    elements.dropZone.addEventListener('click', () => elements.imageInput.click());
    elements.imageInput.addEventListener('change', handleFileSelect);
    
    elements.dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        elements.dropZone.style.borderColor = 'var(--accent-color)';
    });
    
    elements.dropZone.addEventListener('dragleave', () => {
        elements.dropZone.style.borderColor = 'var(--border-color)';
    });
    
    elements.dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        elements.dropZone.style.borderColor = 'var(--border-color)';
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) {
            processImage(file);
        }
    });

    elements.encryptBtn.addEventListener('click', handleEncrypt);
    elements.decryptBtn.addEventListener('click', handleDecrypt);
    elements.resetBtn.addEventListener('click', resetApp);
    
    elements.encryptionKey.addEventListener('input', () => {
        const isValid = elements.encryptionKey.value.length === 8;
        elements.encryptBtn.disabled = !isValid || !state.originalImageData;
    });
}

function handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) processImage(file);
}

function processImage(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
            state.originalWidth = img.width;
            state.originalHeight = img.height;
            
            const ctx = elements.originalCanvas.getContext('2d');
            elements.originalCanvas.width = img.width;
            elements.originalCanvas.height = img.height;
            ctx.drawImage(img, 0, 0);
            
            state.originalImageData = ctx.getImageData(0, 0, img.width, img.height);
            
            elements.originalInfo.textContent = `${img.width}x${img.height}px | ${Math.round(file.size / 1024)} KB`;
            elements.originalView.querySelector('.empty-state').style.display = 'none';
            elements.appStatus.textContent = 'Image Loaded';
            
            const keyValid = elements.encryptionKey.value.length === 8;
            elements.encryptBtn.disabled = !keyValid;
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

async function handleEncrypt() {
    const keyStr = elements.encryptionKey.value;
    if (keyStr.length !== 8) return;

    showLoader(true);
    elements.appStatus.textContent = 'Encrypting...';
    
    setTimeout(() => {
        const startTime = performance.now();
        
        try {
            // Convert to standard Uint8Array
            const pixels = new Uint8Array(state.originalImageData.data);
            const wordArray = CryptoJS.lib.WordArray.create(pixels);
            
            // Parse key as literal 8-byte WordArray
            const key = CryptoJS.enc.Utf8.parse(keyStr);
            
            // Perform DES Encryption in ECB mode
            const encrypted = CryptoJS.DES.encrypt(wordArray, key, {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.Pkcs7
            });
            state.encryptedData = encrypted;
            
            // Visualize
            const ciphertextBytes = encrypted.ciphertext;
            const encryptedPixels = new Uint8ClampedArray(state.originalImageData.data.length);
            
            for (let i = 0; i < encryptedPixels.length; i++) {
                const wordIndex = Math.floor(i / 4);
                const byteOffset = i % 4;
                const word = ciphertextBytes.words[wordIndex];
                const byte = (word >> (24 - byteOffset * 8)) & 0xff;
                encryptedPixels[i] = byte;
            }
            
            renderToCanvas(elements.encryptedCanvas, encryptedPixels, state.originalWidth, state.originalHeight);
            
            const endTime = performance.now();
            elements.procTime.textContent = `${Math.round(endTime - startTime)}ms`;
            elements.encryptedInfo.textContent = `DES-ECB Encrypted`;
            elements.encryptedView.querySelector('.empty-state').style.display = 'none';
            elements.appStatus.textContent = 'Encryption Complete';
            elements.decryptBtn.disabled = false;
            
        } catch (err) {
            console.error("Encryption Error:", err);
            elements.appStatus.textContent = 'Encryption Failed';
        } finally {
            showLoader(false);
        }
    }, 50);
}

async function handleDecrypt() {
    const keyStr = elements.encryptionKey.value;
    showLoader(true);
    elements.appStatus.textContent = 'Decrypting...';

    setTimeout(() => {
        const startTime = performance.now();
        
        try {
            const key = CryptoJS.enc.Utf8.parse(keyStr);
            const decrypted = CryptoJS.DES.decrypt(state.encryptedData, key, {
                mode: CryptoJS.mode.ECB,
                padding: CryptoJS.pad.Pkcs7
            });
            
            const decryptedPixels = wordToUint8(decrypted);
            renderToCanvas(elements.decryptedCanvas, decryptedPixels, state.originalWidth, state.originalHeight);
            
            const endTime = performance.now();
            elements.procTime.textContent = `${Math.round(endTime - startTime)}ms`;
            elements.decryptedInfo.textContent = `Reconstructed`;
            elements.decryptedView.querySelector('.empty-state').style.display = 'none';
            elements.appStatus.textContent = 'Decryption Complete';
            
            checkIntegrity(decryptedPixels);
            
        } catch (err) {
            console.error("Decryption Error:", err);
            elements.appStatus.textContent = 'Decryption Failed';
            elements.integrityStatus.textContent = 'FAILED';
            elements.integrityStatus.style.color = 'var(--error-color)';
        } finally {
            showLoader(false);
        }
    }, 50);
}

function checkIntegrity(decryptedPixels) {
    const original = state.originalImageData.data;
    let match = true;
    for (let i = 0; i < original.length; i++) {
        if (original[i] !== decryptedPixels[i]) {
            match = false;
            break;
        }
    }
    
    if (match) {
        elements.integrityStatus.textContent = 'MATCHED';
        elements.integrityStatus.style.color = 'var(--success-color)';
    } else {
        elements.integrityStatus.textContent = 'CORRUPTED';
        elements.integrityStatus.style.color = 'var(--error-color)';
    }
}

function renderToCanvas(canvas, pixels, width, height) {
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    const imgData = ctx.createImageData(width, height);
    imgData.data.set(pixels.slice(0, imgData.data.length));
    ctx.putImageData(imgData, 0, 0);
}

function wordToUint8(wordArray) {
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    const u8 = new Uint8ClampedArray(sigBytes);
    for (let i = 0; i < sigBytes; i++) {
        const byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        u8[i] = byte;
    }
    return u8;
}

function showLoader(show) {
    if (show) elements.loader.classList.remove('hidden');
    else elements.loader.classList.add('hidden');
}

function resetApp() {
    location.reload();
}

init();
