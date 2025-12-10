// Core encryption helpers preserved for compatibility
function encodeMessage(plainText, passkey) {
  if (!passkey) throw new Error('Passphrase cannot be empty');
  return CryptoJS.AES.encrypt(plainText, passkey).toString();
}

function decodeMessage(cipherText, passkey) {
  if (!passkey) throw new Error('Passphrase cannot be empty');
  const result = CryptoJS.AES.decrypt(cipherText, passkey).toString(
    CryptoJS.enc.Utf8,
  );
  if (!result) throw new Error('Invalid passphrase or corrupted data');
  return result;
}

const { createApp } = Vue;

createApp({
  data() {
    return {
      message: '',
      passkey: '',
      mode: 'encode',
      animationEnabled: true,
      status: { message: 'Awaiting input. Choose encode or decode to begin.', isError: false },
      result: '',
      displayedResult: '',
      isAnimating: false,
      animationTimer: null,
      showPass: false,
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
      this.mode = next;
      this.status = {
        message: `${next === 'encode' ? 'Encoding' : 'Decoding'} mode selected.`,
        isError: false,
      };
      this.stopAnimation();
      this.displayedResult = '';
      this.result = '';
      this.persist();
    },
    handleAction() {
      this.stopAnimation();
      if (this.passkey.length === 0) {
        this.setStatus('Passkey is required before processing.', true);
        return;
      }
      if (!this.message || this.message.trim() === '') {
        this.setStatus('Please enter a message to process.', true);
        return;
      }

      try {
        if (this.mode === 'encode') {
          const encoded = encodeMessage(this.message, this.passkey);
          this.result = encoded;
          this.displayedResult = encoded;
          this.setStatus('Message encoded successfully.');
        } else {
          const decoded = decodeMessage(this.message, this.passkey);
          this.result = decoded;
          if (this.animationEnabled) {
            this.setStatus('Decoding with animated reveal...');
            this.animateDecode(decoded);
          } else {
            this.displayedResult = decoded;
            this.setStatus('Message decoded successfully.');
          }
        }
        this.persist();
      } catch (err) {
        this.result = '';
        this.displayedResult = '';
        this.setStatus(err.message || 'An unexpected error occurred.', true);
      }
    },
    animateDecode(text) {
      this.isAnimating = true;
      this.displayedResult = '';
      let index = 0;
      const reveal = () => {
        this.displayedResult = text.slice(0, index);
        index += 1;
        if (index <= text.length) {
          this.animationTimer = setTimeout(reveal, 14 + Math.random() * 26);
        } else {
          this.isAnimating = false;
          this.setStatus('Message decoded successfully.');
        }
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
      this.message = '';
      this.result = '';
      this.displayedResult = '';
      this.setStatus('Cleared. Ready for a new message.');
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
        localStorage.setItem('anzen.animation', JSON.stringify(this.animationEnabled));
        localStorage.setItem('anzen.passkey', this.passkey);
      } catch (e) {
        console.warn('Persistence unavailable', e);
      }
    },
    hydrate() {
      try {
        const mode = localStorage.getItem('anzen.mode');
        const anim = localStorage.getItem('anzen.animation');
        const key = localStorage.getItem('anzen.passkey');
        if (mode === 'encode' || mode === 'decode') this.mode = mode;
        if (anim !== null) this.animationEnabled = JSON.parse(anim);
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
    animationEnabled() {
      this.persist();
    },
  },
}).mount('#app');
