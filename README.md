# 🛡️ ShadowChat — Anonymous & Pseudonymous Real-Time Messenger & P2P Calls

[![React Native](https://img.shields.io/badge/React%20Native-0.76-61DAFB?logo=react&logoColor=white)](https://reactnative.dev)
[![Expo SDK](https://img.shields.io/badge/Expo%20SDK-52-000020?logo=expo&logoColor=white)](https://expo.dev)
[![WebRTC](https://img.shields.io/badge/WebRTC-Peer--to--Peer-FF5722?logo=webrtc&logoColor=white)](https://webrtc.org)
[![Vercel Ready](https://img.shields.io/badge/Vercel-Deployment%20Ready-000000?logo=vercel&logoColor=white)](https://vercel.com)
[![Privacy First](https://img.shields.io/badge/Privacy-Zero%20Phone%2FEmail-10B981)](#)

A complete, production-grade real-time web and mobile-ready communication application inspired by Telegram and Signal that operates **completely anonymously or pseudonymously WITHOUT requiring a phone number, email address, SMS OTP, or password**.

---

## 🌟 Architectural Highlights

### 1. Zero-Knowledge Cryptographic Authentication
- **Instant Unique ID Generation:** When opened for the first time, a cryptographically random, human-readable Unique ID (e.g., `user_8x92fa`) is derived and assigned to the user device.
- **12-Word Seed Recovery Phrase:** Backed by standard BIP-39 mnemonic phrase derivation. If users change devices, their Unique ID and cryptographic keys can be restored deterministically by entering their 12 words. **No email or phone recovery exists.**
- **Local Keypair & Session Storage:** Ed25519-style simulated keypair and token hashes stored locally in device storage (`AsyncStorage` / Keychain / EncryptedSharedPreferences).
- **Custom Pseudonymous Profile:** Custom display names, bio, avatars, and `@handles` without linking any real-world identity.

### 2. Contact Discovery & Anti-Spam Approval
- **Add by Unique ID or Handle:** Discover and connect with peers by querying exact Unique IDs or `@handles`.
- **Visual QR Code Generator & Scanner:** Every user has a high-contrast visual QR code for quick contact addition in person.
- **Contact Request Firewall:** Incoming connection approval/rejection firewall prevents unsolicited spam messages from stranger IDs.

### 3. Real-Time Chat Engine (Text, Audio, Media)
- **One-on-One Direct Messaging:** Instant low-latency messaging.
- **Read Receipts:** Real-time state transitions (`Sending 🕒` ➔ `Sent ✓` ➔ `Delivered ✓✓` ➔ `Read (Blue) ✓✓`).
- **Live Typing Indicators:** Dynamic feedback when peers are composing transmissions.
- **Media Attachments:** Encrypted image attachments and voice note transmissions with playback scrubber.
- **Local Persistence & Burn Identity:** Full conversation caching with a single-tap **"Burn Identity"** feature that securely purges all keys and local databases.

### 4. Peer-to-Peer Voice & Video Calls (WebRTC)
- Direct 1-on-1 audio and video calling between two Unique IDs.
- Full call controls: Mic mute, speaker toggle, video camera toggle, camera flip (front/back), and end call.
- Integrated WebRTC state handling with STUN/TURN traversal awareness.

### 5. UI/UX
- Telegram & WhatsApp dark mode aesthetic with cyber emerald accents.
- Responsive design: Renders smoothly in mobile viewports on **Desktop Web** (Vercel) and natively on **iOS / Android** via **Expo Go**.
- Bottom navigation tabs: **Chats**, **Calls**, **Contacts**, and **Settings**.

---

## 🚀 Running Locally & Testing with Expo Go

### Prerequisites
- Node.js (>= 18)
- Expo Go app installed on your Android or iOS device

### 1. Start Metro Bundler
```bash
npm start
```

### 2. Open on Mobile Device
Scan the generated QR code in your terminal or browser using the **Expo Go** camera (Android) or default Camera app (iOS).

### 3. Open in Web Browser
```bash
npm run web
```
Opens the interactive mobile app at `http://localhost:8081`.

---

## 🌐 Deploying to Vercel

ShadowChat is configured with `vercel.json` for static web compilation and serverless deployment:

```bash
# 1. Build the production static web bundle
npm run build

# 2. Deploy to Vercel
vercel --prod
```

---

## 🔒 Security Summary
- **Zero Registration Barriers:** No phone numbers, no emails, no SMS OTPs.
- **Deterministic Seed Recovery:** 12-word cryptographic seed phrase is the single source of truth.
- **Burn Switch:** Immediately wipes all stored keys and history on demand.
