export type MessageType = 'text' | 'image' | 'voice' | 'file';
export type MessageStatus = 'sending' | 'sent' | 'delivered' | 'read';

export interface UserSession {
  uid: string;                 // e.g. "user_8x92fa"
  handle: string;              // e.g. "@shadow_8x92"
  displayName: string;         // e.g. "Ghost Agent"
  bio: string;                 // e.g. "Zero footprint, zero logs."
  avatar: string;              // URL or avatar preset identifier
  seedPhrase: string;          // 12-word mnemonic backup
  publicKey: string;           // Derived public cryptographic key
  privateKey: string;          // Derived local private key
  createdAt: string;
}

export interface Contact {
  uid: string;
  handle: string;
  displayName: string;
  avatar: string;
  bio: string;
  status: 'pending_incoming' | 'pending_outgoing' | 'accepted' | 'blocked';
  unreadCount: number;
  lastSeen?: string;
  isOnline: boolean;
  publicKey?: string;
}

export interface Message {
  id: string;
  chatId: string;
  senderUid: string;
  receiverUid: string;
  type: MessageType;
  content: string;
  mediaUrl?: string;
  duration?: number;           // For voice notes in seconds
  fileSize?: string;
  timestamp: string;
  status: MessageStatus;
}

export interface ChatThread {
  contact: Contact;
  lastMessage?: Message;
  unreadCount: number;
  updatedAt: string;
}

export type CallType = 'audio' | 'video';
export type CallStatus = 'ringing' | 'connecting' | 'connected' | 'ended' | 'declined';

export interface CallRecord {
  id: string;
  peerUid: string;
  peerName: string;
  peerAvatar: string;
  type: CallType;
  direction: 'incoming' | 'outgoing' | 'missed';
  status: CallStatus;
  duration: number;            // In seconds
  timestamp: string;
}

export interface ActiveCallState {
  callId: string;
  peer: Contact;
  type: CallType;
  direction: 'incoming' | 'outgoing';
  status: CallStatus;
  duration: number;
  isMuted: boolean;
  isSpeakerOn: boolean;
  isVideoEnabled: boolean;
  isFrontCamera: boolean;
}

export interface PrivacySettings {
  allowContactRequests: boolean;
  showReadReceipts: boolean;
  showOnlineStatus: boolean;
  encryptLocalCache: boolean;
}
