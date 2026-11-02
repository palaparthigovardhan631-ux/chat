import AsyncStorage from '@react-native-async-storage/async-storage';
import { UserSession, Contact, Message, CallRecord, PrivacySettings } from '../types';

const KEYS = {
  SESSION: '@shadowchat_user_session',
  CONTACTS: '@shadowchat_contacts_list',
  MESSAGES_PREFIX: '@shadowchat_msgs_',
  CALLS: '@shadowchat_call_history',
  PRIVACY: '@shadowchat_privacy_settings',
};

export const StorageService = {
  // Session
  async getSession(): Promise<UserSession | null> {
    try {
      const data = await AsyncStorage.getItem(KEYS.SESSION);
      return data ? JSON.parse(data) : null;
    } catch {
      return null;
    }
  },

  async saveSession(session: UserSession): Promise<void> {
    await AsyncStorage.setItem(KEYS.SESSION, JSON.stringify(session));
  },

  async clearSession(): Promise<void> {
    await AsyncStorage.removeItem(KEYS.SESSION);
  },

  // Contacts
  async getContacts(): Promise<Contact[]> {
    try {
      const data = await AsyncStorage.getItem(KEYS.CONTACTS);
      return data ? JSON.parse(data) : [];
    } catch {
      return [];
    }
  },

  async saveContacts(contacts: Contact[]): Promise<void> {
    await AsyncStorage.setItem(KEYS.CONTACTS, JSON.stringify(contacts));
  },

  // Messages per Chat
  async getMessages(chatId: string): Promise<Message[]> {
    try {
      const data = await AsyncStorage.getItem(`${KEYS.MESSAGES_PREFIX}${chatId}`);
      return data ? JSON.parse(data) : [];
    } catch {
      return [];
    }
  },

  async saveMessages(chatId: string, messages: Message[]): Promise<void> {
    await AsyncStorage.setItem(`${KEYS.MESSAGES_PREFIX}${chatId}`, JSON.stringify(messages));
  },

  // Calls
  async getCalls(): Promise<CallRecord[]> {
    try {
      const data = await AsyncStorage.getItem(KEYS.CALLS);
      return data ? JSON.parse(data) : [];
    } catch {
      return [];
    }
  },

  async saveCalls(calls: CallRecord[]): Promise<void> {
    await AsyncStorage.setItem(KEYS.CALLS, JSON.stringify(calls));
  },

  // Privacy Settings
  async getPrivacySettings(): Promise<PrivacySettings> {
    try {
      const data = await AsyncStorage.getItem(KEYS.PRIVACY);
      if (data) return JSON.parse(data);
    } catch {}
    return {
      allowContactRequests: true,
      showReadReceipts: true,
      showOnlineStatus: true,
      encryptLocalCache: true,
    };
  },

  async savePrivacySettings(settings: PrivacySettings): Promise<void> {
    await AsyncStorage.setItem(KEYS.PRIVACY, JSON.stringify(settings));
  },

  // Wipe All Local Data (Burn Identity)
  async wipeAllData(): Promise<void> {
    await AsyncStorage.clear();
  },
};
