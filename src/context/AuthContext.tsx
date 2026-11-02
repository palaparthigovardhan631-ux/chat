import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserSession, PrivacySettings } from '../types';
import { StorageService } from '../services/storageService';
import { generateUniqueId, generateSeedPhrase, deriveKeyPair, deriveUidFromSeed } from '../services/cryptoService';

interface AuthContextType {
  session: UserSession | null;
  isLoading: boolean;
  privacy: PrivacySettings;
  updateProfile: (displayName: string, bio: string, avatar: string, handle?: string) => Promise<void>;
  updatePrivacy: (settings: Partial<PrivacySettings>) => Promise<void>;
  restoreFromSeed: (seedPhrase: string) => Promise<{ success: boolean; error?: string }>;
  burnIdentity: () => Promise<void>;
  showSeedModal: boolean;
  setShowSeedModal: (show: boolean) => void;
  showQRModal: boolean;
  setShowQRModal: (show: boolean) => void;
}

const AuthContext = createContext<AuthContextType>({} as AuthContextType);

const DEFAULT_AVATARS = [
  'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150',
  'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150',
  'https://images.unsplash.com/photo-1517841905240-472988babdf9?w=150',
  'https://images.unsplash.com/photo-1539571696357-5a69c17a67c6?w=150',
];

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [session, setSession] = useState<UserSession | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [privacy, setPrivacy] = useState<PrivacySettings>({
    allowContactRequests: true,
    showReadReceipts: true,
    showOnlineStatus: true,
    encryptLocalCache: true,
  });
  const [showSeedModal, setShowSeedModal] = useState(false);
  const [showQRModal, setShowQRModal] = useState(false);

  useEffect(() => {
    initAuth();
  }, []);

  async function initAuth() {
    try {
      const stored = await StorageService.getSession();
      const storedPrivacy = await StorageService.getPrivacySettings();
      setPrivacy(storedPrivacy);

      if (stored) {
        setSession(stored);
      } else {
        // First-time open: generate cryptographically secure Unique ID and 12-word seed
        const seed = generateSeedPhrase();
        const uid = generateUniqueId();
        const keys = deriveKeyPair(seed);
        const randomAvatar = DEFAULT_AVATARS[Math.floor(Math.random() * DEFAULT_AVATARS.length)];

        const newSession: UserSession = {
          uid,
          handle: `@${uid.replace('user_', 'ghost_')}`,
          displayName: `Agent ${uid.slice(-4).toUpperCase()}`,
          bio: 'Anonymous communicator • End-to-end pseudonymous',
          avatar: randomAvatar,
          seedPhrase: seed,
          publicKey: keys.publicKey,
          privateKey: keys.privateKey,
          createdAt: new Date().toISOString(),
        };

        await StorageService.saveSession(newSession);
        setSession(newSession);
      }
    } catch (e) {
      console.error('Error during initAuth', e);
    } finally {
      setIsLoading(false);
    }
  }

  async function updateProfile(displayName: string, bio: string, avatar: string, handle?: string) {
    if (!session) return;
    const updated: UserSession = {
      ...session,
      displayName: displayName.trim() || session.displayName,
      bio: bio.trim(),
      avatar: avatar.trim() || session.avatar,
      handle: handle ? (handle.startsWith('@') ? handle : `@${handle}`) : session.handle,
    };
    await StorageService.saveSession(updated);
    setSession(updated);
  }

  async function updatePrivacy(newSettings: Partial<PrivacySettings>) {
    const updated = { ...privacy, ...newSettings };
    setPrivacy(updated);
    await StorageService.savePrivacySettings(updated);
  }

  async function restoreFromSeed(seedPhrase: string): Promise<{ success: boolean; error?: string }> {
    const words = seedPhrase.trim().toLowerCase().split(/\s+/);
    if (words.length !== 12) {
      return { success: false, error: 'Recovery phrase must be exactly 12 words.' };
    }

    try {
      const cleanSeed = words.join(' ');
      const derivedUid = deriveUidFromSeed(cleanSeed);
      const keys = deriveKeyPair(cleanSeed);

      const restoredSession: UserSession = {
        uid: derivedUid,
        handle: `@${derivedUid.replace('user_', 'anon_')}`,
        displayName: `Restored Agent ${derivedUid.slice(-4).toUpperCase()}`,
        bio: 'Recovered via 12-word seed phrase.',
        avatar: DEFAULT_AVATARS[0],
        seedPhrase: cleanSeed,
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
        createdAt: new Date().toISOString(),
      };

      await StorageService.saveSession(restoredSession);
      setSession(restoredSession);
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Failed to restore identity from seed.' };
    }
  }

  async function burnIdentity() {
    await StorageService.wipeAllData();
    setSession(null);
    await initAuth();
  }

  return (
    <AuthContext.Provider
      value={{
        session,
        isLoading,
        privacy,
        updateProfile,
        updatePrivacy,
        restoreFromSeed,
        burnIdentity,
        showSeedModal,
        setShowSeedModal,
        showQRModal,
        setShowQRModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
