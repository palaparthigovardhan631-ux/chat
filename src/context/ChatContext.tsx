import React, { createContext, useContext, useState, useEffect } from 'react';
import { Contact, Message, ChatThread, MessageType } from '../types';
import { StorageService } from '../services/storageService';
import { useAuth } from './AuthContext';
import { encryptPayload, decryptPayload } from '../services/cryptoService';

interface ChatContextType {
  contacts: Contact[];
  threads: ChatThread[];
  activeChatMessages: Message[];
  activeChatContact: Contact | null;
  isPeerTyping: boolean;
  setActiveChatContact: (contact: Contact | null) => void;
  loadMessagesForContact: (contact: Contact) => Promise<void>;
  sendMessage: (content: string, type?: MessageType, mediaUrl?: string, duration?: number) => Promise<void>;
  sendContactRequest: (uidOrHandle: string) => Promise<{ success: boolean; message: string }>;
  respondToContactRequest: (uid: string, action: 'accept' | 'reject') => Promise<void>;
  markAsRead: (contactUid: string) => Promise<void>;
  deleteChat: (contactUid: string) => Promise<void>;
}

const ChatContext = createContext<ChatContextType>({} as ChatContextType);

// Starter demo contacts for instant out-of-the-box interactive testing on Vercel & Expo Go
const SEED_CONTACTS: Contact[] = [
  {
    uid: 'user_phantom7',
    handle: '@phantom_ops',
    displayName: 'Cipher Sentinel',
    avatar: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150',
    bio: 'Decentralized nodes • Online',
    status: 'accepted',
    unreadCount: 1,
    lastSeen: 'Just now',
    isOnline: true,
  },
  {
    uid: 'user_echo99',
    handle: '@echo_shadow',
    displayName: 'Echo Chamber',
    avatar: 'https://images.unsplash.com/photo-1570295999919-56ceb5ecca61?w=150',
    bio: 'Encrypted relay • P2P Active',
    status: 'accepted',
    unreadCount: 0,
    lastSeen: '5m ago',
    isOnline: true,
  },
  {
    uid: 'user_4x19ab',
    handle: '@anonymous_node',
    displayName: 'Node 4X19',
    avatar: 'https://images.unsplash.com/photo-1527980965255-d3b416303d12?w=150',
    bio: 'Incoming contact request',
    status: 'pending_incoming',
    unreadCount: 0,
    lastSeen: '12m ago',
    isOnline: false,
  },
];

const INITIAL_MESSAGES: Record<string, Message[]> = {
  user_phantom7: [
    {
      id: 'm1',
      chatId: 'user_phantom7',
      senderUid: 'user_phantom7',
      receiverUid: 'me',
      type: 'text',
      content: 'Welcome to ShadowChat. Zero phones, zero emails, end-to-end encrypted.',
      timestamp: new Date(Date.now() - 3600000).toISOString(),
      status: 'read',
    },
    {
      id: 'm2',
      chatId: 'user_phantom7',
      senderUid: 'user_phantom7',
      receiverUid: 'me',
      type: 'voice',
      content: 'Voice transmission attached.',
      duration: 8,
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      status: 'read',
    },
    {
      id: 'm3',
      chatId: 'user_phantom7',
      senderUid: 'user_phantom7',
      receiverUid: 'me',
      type: 'text',
      content: 'Tap the Phone or Video icon on top to test the WebRTC Peer-to-Peer calling engine anytime!',
      timestamp: new Date(Date.now() - 60000).toISOString(),
      status: 'delivered',
    },
  ],
  user_echo99: [
    {
      id: 'm4',
      chatId: 'user_echo99',
      senderUid: 'user_echo99',
      receiverUid: 'me',
      type: 'text',
      content: 'P2P tunnel active. You can share images, voice notes, and test read receipts.',
      timestamp: new Date(Date.now() - 7200000).toISOString(),
      status: 'read',
    },
  ],
};

export const ChatProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { session } = useAuth();
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [activeChatContact, setActiveChatContact] = useState<Contact | null>(null);
  const [activeChatMessages, setActiveChatMessages] = useState<Message[]>([]);
  const [isPeerTyping, setIsPeerTyping] = useState<boolean>(false);

  useEffect(() => {
    initContacts();
  }, [session?.uid]);

  async function initContacts() {
    const stored = await StorageService.getContacts();
    if (stored && stored.length > 0) {
      setContacts(stored);
    } else {
      await StorageService.saveContacts(SEED_CONTACTS);
      setContacts(SEED_CONTACTS);

      // Seed initial messages
      for (const [uid, msgs] of Object.entries(INITIAL_MESSAGES)) {
        await StorageService.saveMessages(uid, msgs);
      }
    }
  }

  async function loadMessagesForContact(contact: Contact) {
    setActiveChatContact(contact);
    const msgs = await StorageService.getMessages(contact.uid);
    setActiveChatMessages(msgs);
    markAsRead(contact.uid);
  }

  async function sendMessage(
    content: string,
    type: MessageType = 'text',
    mediaUrl?: string,
    duration?: number
  ) {
    if (!activeChatContact || !session) return;

    const newMsg: Message = {
      id: `msg_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      chatId: activeChatContact.uid,
      senderUid: session.uid,
      receiverUid: activeChatContact.uid,
      type,
      content,
      mediaUrl,
      duration,
      timestamp: new Date().toISOString(),
      status: 'sending',
    };

    // Immediate optimistic update
    const updated = [...activeChatMessages, newMsg];
    setActiveChatMessages(updated);
    await StorageService.saveMessages(activeChatContact.uid, updated);

    // Simulated network transition: sending -> sent -> delivered -> read
    setTimeout(async () => {
      newMsg.status = 'sent';
      const sentUpdated = updated.map(m => (m.id === newMsg.id ? { ...m, status: 'sent' as const } : m));
      setActiveChatMessages(sentUpdated);
      await StorageService.saveMessages(activeChatContact.uid, sentUpdated);
    }, 400);

    setTimeout(async () => {
      newMsg.status = 'delivered';
      const delUpdated = updated.map(m => (m.id === newMsg.id ? { ...m, status: 'delivered' as const } : m));
      setActiveChatMessages(delUpdated);
      await StorageService.saveMessages(activeChatContact.uid, delUpdated);
    }, 1200);

    setTimeout(async () => {
      newMsg.status = 'read';
      const readUpdated = updated.map(m => (m.id === newMsg.id ? { ...m, status: 'read' as const } : m));
      setActiveChatMessages(readUpdated);
      await StorageService.saveMessages(activeChatContact.uid, readUpdated);
    }, 2500);

    // Realistic auto-reply from demo peers if chatting with phantom7 or echo99
    if (activeChatContact.uid === 'user_phantom7' || activeChatContact.uid === 'user_echo99') {
      setTimeout(() => setIsPeerTyping(true), 1800);
      setTimeout(async () => {
        setIsPeerTyping(false);
        const replyResponses = [
          'Transmission received securely. No IP or metadata was logged.',
          'Acknowledged. End-to-end cryptographic verification confirmed.',
          'Understood. Voice and video channels are standby.',
          'P2P packets delivered without hop records.',
        ];
        const randomText = replyResponses[Math.floor(Math.random() * replyResponses.length)];
        const replyMsg: Message = {
          id: `msg_reply_${Date.now()}`,
          chatId: activeChatContact.uid,
          senderUid: activeChatContact.uid,
          receiverUid: session.uid,
          type: 'text',
          content: randomText,
          timestamp: new Date().toISOString(),
          status: 'read',
        };
        const currentMsgs = await StorageService.getMessages(activeChatContact.uid);
        const withReply = [...currentMsgs, replyMsg];
        setActiveChatMessages(withReply);
        await StorageService.saveMessages(activeChatContact.uid, withReply);
      }, 4200);
    }
  }

  async function sendContactRequest(uidOrHandle: string): Promise<{ success: boolean; message: string }> {
    const query = uidOrHandle.trim().toLowerCase();
    if (!query) return { success: false, message: 'Please enter a valid Unique ID or @handle.' };
    if (session && (query === session.uid.toLowerCase() || query === session.handle.toLowerCase())) {
      return { success: false, message: 'You cannot add your own Unique ID.' };
    }

    const exists = contacts.find(
      c => c.uid.toLowerCase() === query || c.handle.toLowerCase() === query
    );
    if (exists) {
      if (exists.status === 'accepted') {
        return { success: false, message: 'This user is already in your contacts.' };
      }
      return { success: false, message: 'A request for this contact is already pending.' };
    }

    // Create new contact in outgoing status
    const formattedUid = query.startsWith('user_') ? query : `user_${Math.random().toString(36).substring(2, 8)}`;
    const formattedHandle = query.startsWith('@') ? query : `@${query}`;
    const newContact: Contact = {
      uid: formattedUid,
      handle: formattedHandle,
      displayName: `Agent ${formattedUid.slice(-4).toUpperCase()}`,
      avatar: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150',
      bio: 'Peer communicator',
      status: 'pending_outgoing',
      unreadCount: 0,
      isOnline: true,
    };

    const updated = [newContact, ...contacts];
    setContacts(updated);
    await StorageService.saveContacts(updated);
    return { success: true, message: `Contact request sent to ${formattedHandle}!` };
  }

  async function respondToContactRequest(uid: string, action: 'accept' | 'reject') {
    let updated: Contact[];
    if (action === 'accept') {
      updated = contacts.map(c => (c.uid === uid ? { ...c, status: 'accepted' as const } : c));
    } else {
      updated = contacts.filter(c => c.uid !== uid);
    }
    setContacts(updated);
    await StorageService.saveContacts(updated);
  }

  async function markAsRead(contactUid: string) {
    const updated = contacts.map(c => (c.uid === contactUid ? { ...c, unreadCount: 0 } : c));
    setContacts(updated);
    await StorageService.saveContacts(updated);
  }

  async function deleteChat(contactUid: string) {
    await StorageService.saveMessages(contactUid, []);
    if (activeChatContact?.uid === contactUid) {
      setActiveChatMessages([]);
    }
  }

  // Derive active threads from contacts list
  const threads: ChatThread[] = contacts
    .filter(c => c.status === 'accepted')
    .map(c => ({
      contact: c,
      lastMessage: undefined, // Will be populated in screen view
      unreadCount: c.unreadCount,
      updatedAt: new Date().toISOString(),
    }));

  return (
    <ChatContext.Provider
      value={{
        contacts,
        threads,
        activeChatMessages,
        activeChatContact,
        isPeerTyping,
        setActiveChatContact,
        loadMessagesForContact,
        sendMessage,
        sendContactRequest,
        respondToContactRequest,
        markAsRead,
        deleteChat,
      }}
    >
      {children}
    </ChatContext.Provider>
  );
};

export const useChat = () => useContext(ChatContext);
