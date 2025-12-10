// Modern encryption helpers using the built-in Web Crypto API
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function ensureWebCrypto() {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API is unavailable in this browser.');
  }
}

async function deriveKey(passkey, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(passkey),
    'PBKDF2',
    false,
    ['deriveKey'],
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt'],
  );
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

function fromBase64(input) {
  const binary = atob(input);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function encodeMessage(plainText, passkey) {
  if (!passkey) throw new Error('Passphrase cannot be empty');
  ensureWebCrypto();

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passkey, salt);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(plainText),
  );

  const payload = new Uint8Array(salt.length + iv.length + cipherBuffer.byteLength);
  payload.set(salt, 0);
  payload.set(iv, salt.length);
  payload.set(new Uint8Array(cipherBuffer), salt.length + iv.length);

  return toBase64(payload.buffer);
}

async function decodeMessage(cipherText, passkey) {
  if (!passkey) throw new Error('Passphrase cannot be empty');
  ensureWebCrypto();

  const payload = fromBase64(cipherText);
  if (payload.byteLength <= 28) {
    throw new Error('Invalid cipher payload.');
  }

  const salt = payload.slice(0, 16);
  const iv = payload.slice(16, 28);
  const data = payload.slice(28);

  try {
    const key = await deriveKey(passkey, salt);
    const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return decoder.decode(plainBuffer);
  } catch (e) {
    throw new Error('Invalid passphrase or corrupted data');
  }
}

const { createApp } = Vue;

createApp({
  data() {
    return {
      message: '',
      realMessage: '',
      displayMessage: '',
      passkey: '',
      mode: 'encode',
      decodeSpeed: 'fast',
      status: { message: 'Awaiting input. Choose encode or decode to begin.', isError: false },
      result: '',
      displayedResult: '',
      fullDecodedText: '',
      isAnimating: false,
      animationTimer: null,
      showPass: false,
      maskTimer: null,
      lastSelectionStart: 0,
      lastSelectionEnd: 0,
    };
  },
  computed: {
    placeholderText() {
      return this.mode === 'encode'
        ? 'Encoded text will appear here with your passkey applied.'
        : 'Decoded text will reveal here once processed.';
    },
  },
  methods: {
    setMode(next) {
      if (this.mode === next) return;
      this.clearMaskTimer();
      if (next === 'decode') {
        this.message = this.realMessage || this.message;
        this.displayMessage = this.realMessage;
      } else {
        this.realMessage = this.message || this.realMessage;
        this.updateDisplayMessage(false);
        this.resetMaskTimer();
      }
      this.mode = next;
      this.status = {
        message: `${next === 'encode' ? 'Encoding' : 'Decoding'} mode selected.`,
        isError: false,
      };
      this.stopAnimation();
      this.displayedResult = '';
      this.result = '';
      this.fullDecodedText = '';
      this.persist();
    },
    toggleDecodeSpeed() {
      this.decodeSpeed = this.decodeSpeed === 'fast' ? 'slow' : 'fast';
    },
    async handleAction() {
      this.stopAnimation();
      if (this.passkey.length === 0) {
        this.setStatus('Passkey is required before processing.', true);
        return;
      }
      const inputText = this.mode === 'encode' ? this.realMessage : this.message;
      if (!inputText || inputText.trim() === '') {
        this.setStatus('Please enter a message to process.', true);
        return;
      }

      try {
        if (this.mode === 'encode') {
          const encoded = await encodeMessage(this.realMessage, this.passkey);
          this.result = encoded;
          this.displayedResult = encoded;
          this.fullDecodedText = '';
          this.setStatus('Message encoded successfully.');
        } else {
          const decoded = await decodeMessage(this.message, this.passkey);
          this.result = decoded;
          this.fullDecodedText = decoded;
          this.setStatus('Decoding with animated reveal...');
          this.animateDecode(decoded);
        }
        this.persist();
      } catch (err) {
        this.result = '';
        this.displayedResult = '';
        this.fullDecodedText = '';
        this.setStatus(err.message || 'An unexpected error occurred.', true);
      }
    },
    animateDecode(text) {
      this.isAnimating = true;
      this.displayedResult = '';
      let index = 0;
      const nextDelay = () => (this.decodeSpeed === 'fast' ? 12 + Math.random() * 18 : 40 + Math.random() * 30);
      const reveal = () => {
        index += 1;
        const partial = text.slice(0, index);
        this.displayedResult = this.computeMaskedDecoded(partial);

        if (index < text.length) {
          this.animationTimer = setTimeout(reveal, nextDelay());
          return;
        }

        this.isAnimating = false;
        this.displayedResult = this.computeMaskedDecoded(text);
        this.animationTimer = null;
        this.setStatus('Message decoded successfully.');
      };
      reveal();
    },
    stopAnimation() {
      if (this.animationTimer) {
        clearTimeout(this.animationTimer);
        this.animationTimer = null;
      }
      this.isAnimating = false;
    },
    clearAll() {
      this.stopAnimation();
      this.clearMaskTimer();
      this.message = '';
      this.realMessage = '';
      this.displayMessage = '';
      this.lastSelectionStart = 0;
      this.lastSelectionEnd = 0;
      this.result = '';
      this.displayedResult = '';
      this.fullDecodedText = '';
      this.setStatus('Cleared. Ready for a new message.');
    },
    handleMessageInput(event) {
      const value = event.target.value;
      if (this.mode === 'encode') {
        const start = this.lastSelectionStart ?? 0;
        const end = this.lastSelectionEnd ?? 0;
        const inputType = event.inputType || '';
        const data = event.data;
        let nextReal = this.realMessage;

        if (inputType.startsWith('delete')) {
          let deleteStart = start;
          let deleteEnd = end;

          if (start === end) {
            if (inputType === 'deleteContentBackward' && start > 0) {
              deleteStart = start - 1;
            } else if (inputType === 'deleteContentForward' && end < this.realMessage.length) {
              deleteEnd = end + 1;
            }
          }

          nextReal = `${this.realMessage.slice(0, deleteStart)}${this.realMessage.slice(deleteEnd)}`;
        } else {
          const baseLength = this.realMessage.length - (end - start);
          const insertedLength = Math.max(0, value.length - baseLength);
          const insertedText = data !== null && data !== undefined
            ? data
            : value.slice(start, start + insertedLength);

          nextReal = `${this.realMessage.slice(0, start)}${insertedText}${this.realMessage.slice(end)}`;
        }

        this.realMessage = nextReal;
        this.updateDisplayMessage(false);
        this.resetMaskTimer();
      } else {
        this.message = value;
      }
      this.recordSelection(event);
    },
    recordSelection(event) {
      this.lastSelectionStart = event.target.selectionStart || 0;
      this.lastSelectionEnd = event.target.selectionEnd || 0;
    },
    computeDisplayMessage(text, maskLastWord) {
      const tokens = text.match(/(\S+|\s+)/g) || [];
      let lastWordIndex = -1;

      tokens.forEach((token, index) => {
        if (!/\s/.test(token[0])) {
          lastWordIndex = index;
        }
      });

      if (lastWordIndex === -1) return text;

      return tokens
        .map((token, index) => {
          if (/\s/.test(token[0])) return token;
          if (maskLastWord || index !== lastWordIndex) {
            return '*'.repeat(token.length);
          }
          return token;
        })
        .join('');
    },
    updateDisplayMessage(maskLastWord) {
      this.displayMessage = this.computeDisplayMessage(this.realMessage, maskLastWord);
    },
    splitIntoSentences(text) {
      const sentences = [];
      let start = 0;

      for (let i = 0; i < text.length; i += 1) {
        const char = text[i];
        if (char === '.' || char === '!' || char === '?') {
          const next = text[i + 1];
          if (next === undefined || /\s/.test(next)) {
            let end = i + 1;
            while (end < text.length && /\s/.test(text[end])) {
              end += 1;
            }
            if (end > start) {
              sentences.push(text.slice(start, end));
              start = end;
              i = end - 1;
            }
          }
        }
      }

      if (start < text.length) {
        sentences.push(text.slice(start));
      }

      return sentences.filter(Boolean);
    },
    computeMaskedDecoded(text) {
      if (!text) return '';
      const sentences = this.splitIntoSentences(text);
      if (!sentences.length) return text;
      const visibleStart = Math.max(0, sentences.length - 3);

      return sentences
        .map((segment, index) => {
          if (index < visibleStart) {
            return segment.replace(/[^\s]/g, '*');
          }

          // When there are only a few sentences, still mask the leading portion
          // of the visible text so decoded content is never fully exposed.
          if (sentences.length <= 3 && index === visibleStart) {
            return this.maskLeadingPortion(segment);
          }

          return segment;
        })
        .join('');
    },
    maskLeadingPortion(segment) {
      if (!segment) return '';
      const keepCharacters = Math.max(6, Math.floor(segment.length * 0.25));
      const maskLength = Math.max(0, segment.length - keepCharacters);
      const masked = segment
        .slice(0, maskLength)
        .replace(/[^\s]/g, '*');
      return `${masked}${segment.slice(maskLength)}`;
    },
    resetMaskTimer() {
      this.clearMaskTimer();
      if (!this.realMessage) return;
      this.maskTimer = setTimeout(() => {
        this.updateDisplayMessage(true);
        this.maskTimer = null;
      }, 5000);
    },
    clearMaskTimer() {
      if (this.maskTimer) {
        clearTimeout(this.maskTimer);
        this.maskTimer = null;
      }
    },
    copyResult() {
      const text = this.result || this.displayedResult;
      if (!text) return;
      navigator.clipboard
        .writeText(text)
        .then(() => this.setStatus('Result copied to clipboard.'))
        .catch(() => this.setStatus('Unable to access clipboard. Please copy manually.', true));
    },
    setStatus(message, isError = false) {
      this.status = { message, isError };
    },
    persist() {
      try {
        localStorage.setItem('anzen.mode', this.mode);
        localStorage.setItem('anzen.decodeSpeed', this.decodeSpeed);
        localStorage.setItem('anzen.passkey', this.passkey);
      } catch (e) {
        console.warn('Persistence unavailable', e);
      }
    },
    hydrate() {
      try {
        const mode = localStorage.getItem('anzen.mode');
        const anim = localStorage.getItem('anzen.animation');
        const storedSpeed = localStorage.getItem('anzen.decodeSpeed');
        const key = localStorage.getItem('anzen.passkey');
        if (mode === 'encode' || mode === 'decode') this.mode = mode;
        if (storedSpeed === 'fast' || storedSpeed === 'slow') {
          this.decodeSpeed = storedSpeed;
        } else if (anim !== null) {
          this.decodeSpeed = JSON.parse(anim) ? 'fast' : 'slow';
        }
        if (key) this.passkey = key;
      } catch (e) {
        console.warn('Unable to restore preferences', e);
      }
    },
  },
  mounted() {
    this.hydrate();
  },
  watch: {
    passkey() {
      this.persist();
    },
    decodeSpeed() {
      this.persist();
    },
  },
}).mount('#app');
