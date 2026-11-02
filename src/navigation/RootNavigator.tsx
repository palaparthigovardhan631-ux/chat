import React, { useState } from 'react';
import { View, StyleSheet, Platform, Text, TouchableOpacity } from 'react-native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { MessageSquare, Phone, Users, Shield, ArrowLeft } from 'lucide-react-native';
import { COLORS, RADIUS } from '../constants/theme';
import { ChatsListScreen } from '../screens/chats/ChatsListScreen';
import { ChatRoomScreen } from '../screens/chats/ChatRoomScreen';
import { CallsHistoryScreen } from '../screens/calls/CallsHistoryScreen';
import { ContactsScreen } from '../screens/contacts/ContactsScreen';
import { SettingsScreen } from '../screens/settings/SettingsScreen';
import { CallOverlay } from '../components/CallOverlay';
import { QRCodeModal } from '../components/QRCodeModal';
import { RecoveryPhraseModal } from '../components/RecoveryPhraseModal';
import { useAuth } from '../context/AuthContext';
import { useChat } from '../context/ChatContext';
import { Contact } from '../types';

const Tab = createBottomTabNavigator();

export const RootNavigator: React.FC = () => {
  const { session, showQRModal, setShowQRModal, showSeedModal, setShowSeedModal } = useAuth();
  const { activeChatContact, setActiveChatContact } = useChat();
  const [currentTab, setCurrentTab] = useState<'chats' | 'calls' | 'contacts' | 'settings'>('chats');

  // If a chat room is actively open, render ChatRoomScreen directly with a back action
  if (activeChatContact) {
    return (
      <View style={styles.appShell}>
        <View style={styles.responsiveContainer}>
          <ChatRoomScreen onBack={() => setActiveChatContact(null)} />
          <CallOverlay />
          {session && (
            <>
              <QRCodeModal
                visible={showQRModal}
                onClose={() => setShowQRModal(false)}
                uid={session.uid}
                handle={session.handle}
                displayName={session.displayName}
              />
              <RecoveryPhraseModal
                visible={showSeedModal}
                onClose={() => setShowSeedModal(false)}
                seedPhrase={session.seedPhrase}
              />
            </>
          )}
        </View>
      </View>
    );
  }

  return (
    <View style={styles.appShell}>
      <View style={styles.responsiveContainer}>
        {/* Main Content View based on Active Tab */}
        <View style={styles.mainContent}>
          {currentTab === 'chats' && (
            <ChatsListScreen
              onSelectChat={contact => setActiveChatContact(contact)}
              onNavigateToContacts={() => setCurrentTab('contacts')}
            />
          )}

          {currentTab === 'calls' && <CallsHistoryScreen />}

          {currentTab === 'contacts' && (
            <ContactsScreen
              onStartChat={contact => {
                setActiveChatContact(contact);
              }}
            />
          )}

          {currentTab === 'settings' && <SettingsScreen />}
        </View>

        {/* Global Bottom Navigation Bar */}
        <View style={styles.bottomBar}>
          <TouchableOpacity
            activeOpacity={0.7}
            onPress={() => setCurrentTab('chats')}
            style={styles.tabBtn}
          >
            <MessageSquare
              size={22}
              color={currentTab === 'chats' ? COLORS.primary : COLORS.textMuted}
            />
            <Text
              style={[
                styles.tabLabel,
                currentTab === 'chats' ? styles.tabLabelActive : null,
              ]}
            >
              Chats
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            activeOpacity={0.7}
            onPress={() => setCurrentTab('calls')}
            style={styles.tabBtn}
          >
            <Phone
              size={22}
              color={currentTab === 'calls' ? COLORS.primary : COLORS.textMuted}
            />
            <Text
              style={[
                styles.tabLabel,
                currentTab === 'calls' ? styles.tabLabelActive : null,
              ]}
            >
              Calls
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            activeOpacity={0.7}
            onPress={() => setCurrentTab('contacts')}
            style={styles.tabBtn}
          >
            <Users
              size={22}
              color={currentTab === 'contacts' ? COLORS.primary : COLORS.textMuted}
            />
            <Text
              style={[
                styles.tabLabel,
                currentTab === 'contacts' ? styles.tabLabelActive : null,
              ]}
            >
              Contacts
            </Text>
          </TouchableOpacity>

          <TouchableOpacity
            activeOpacity={0.7}
            onPress={() => setCurrentTab('settings')}
            style={styles.tabBtn}
          >
            <Shield
              size={22}
              color={currentTab === 'settings' ? COLORS.primary : COLORS.textMuted}
            />
            <Text
              style={[
                styles.tabLabel,
                currentTab === 'settings' ? styles.tabLabelActive : null,
              ]}
            >
              Settings
            </Text>
          </TouchableOpacity>
        </View>

        {/* Global Call Overlay & Modals */}
        <CallOverlay />

        {session && (
          <>
            <QRCodeModal
              visible={showQRModal}
              onClose={() => setShowQRModal(false)}
              uid={session.uid}
              handle={session.handle}
              displayName={session.displayName}
            />
            <RecoveryPhraseModal
              visible={showSeedModal}
              onClose={() => setShowSeedModal(false)}
              seedPhrase={session.seedPhrase}
            />
          </>
        )}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  appShell: {
    flex: 1,
    backgroundColor: '#070A11',
    alignItems: 'center',
    justifyContent: 'center',
  },
  responsiveContainer: {
    width: '100%',
    maxWidth: 520, // Clean responsive desktop container or full native mobile
    flex: 1,
    backgroundColor: COLORS.bgDark,
    overflow: 'hidden',
    ...Platform.select({
      web: {
        boxShadow: '0 20px 40px rgba(0,0,0,0.6)',
      },
      default: {},
    }),
  },
  mainContent: {
    flex: 1,
  },
  bottomBar: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-around',
    backgroundColor: COLORS.bgCard,
    borderTopWidth: 1,
    borderTopColor: COLORS.border,
    paddingVertical: 10,
    height: 64,
  },
  tabBtn: {
    alignItems: 'center',
    justifyContent: 'center',
    flex: 1,
    gap: 4,
  },
  tabLabel: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '600',
  },
  tabLabelActive: {
    color: COLORS.primary,
    fontWeight: '700',
  },
});
