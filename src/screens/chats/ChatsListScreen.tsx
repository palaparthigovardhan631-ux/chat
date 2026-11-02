import React, { useState } from 'react';
import { View, Text, StyleSheet, FlatList, TouchableOpacity, TextInput } from 'react-native';
import { Search, Plus, QrCode, Shield, PhoneCall } from 'lucide-react-native';
import { COLORS, SPACING, RADIUS } from '../../constants/theme';
import { Avatar } from '../../components/Avatar';
import { ReadReceipt, UnreadBadge } from '../../components/Badge';
import { useChat } from '../../context/ChatContext';
import { useAuth } from '../../context/AuthContext';
import { Contact } from '../../types';

interface ChatsListScreenProps {
  onSelectChat: (contact: Contact) => void;
  onNavigateToContacts: () => void;
}

export const ChatsListScreen: React.FC<ChatsListScreenProps> = ({
  onSelectChat,
  onNavigateToContacts,
}) => {
  const { contacts, loadMessagesForContact } = useChat();
  const { session, setShowQRModal } = useAuth();
  const [searchQuery, setSearchQuery] = useState('');

  const acceptedContacts = contacts.filter(c => c.status === 'accepted');

  const filtered = acceptedContacts.filter(c => {
    const q = searchQuery.toLowerCase();
    return (
      c.displayName.toLowerCase().includes(q) ||
      c.handle.toLowerCase().includes(q) ||
      c.uid.toLowerCase().includes(q)
    );
  });

  const handleOpenChat = (contact: Contact) => {
    loadMessagesForContact(contact);
    onSelectChat(contact);
  };

  return (
    <View style={styles.container}>
      {/* Header Bar */}
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          <Shield size={22} color={COLORS.primary} />
          <View>
            <Text style={styles.headerTitle}>ShadowChat</Text>
            <Text style={styles.headerSubtitle}>
              {session?.uid || 'Connecting...'}
            </Text>
          </View>
        </View>

        <TouchableOpacity onPress={() => setShowQRModal(true)} style={styles.iconBtn}>
          <QrCode size={20} color={COLORS.textPrimary} />
        </TouchableOpacity>
      </View>

      {/* Search Input */}
      <View style={styles.searchContainer}>
        <View style={styles.searchBar}>
          <Search size={18} color={COLORS.textMuted} />
          <TextInput
            placeholder="Search by Unique ID or name..."
            placeholderTextColor={COLORS.textMuted}
            value={searchQuery}
            onChangeText={setSearchQuery}
            style={styles.searchInput}
          />
        </View>
      </View>

      {/* Chats List */}
      <FlatList
        data={filtered}
        keyExtractor={item => item.uid}
        contentContainerStyle={styles.listContent}
        showsVerticalScrollIndicator={false}
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Shield size={48} color={COLORS.borderLight} />
            <Text style={styles.emptyTitle}>No Anonymous Chats Yet</Text>
            <Text style={styles.emptySubtitle}>
              Add a contact using their exact Unique ID or scan their QR code to begin communicating.
            </Text>
            <TouchableOpacity onPress={onNavigateToContacts} style={styles.addContactBtn}>
              <Text style={styles.addContactBtnText}>Add Contact by Unique ID</Text>
            </TouchableOpacity>
          </View>
        }
        renderItem={({ item }) => (
          <TouchableOpacity
            activeOpacity={0.7}
            onPress={() => handleOpenChat(item)}
            style={styles.chatRow}
          >
            <Avatar
              source={item.avatar}
              name={item.displayName}
              size={52}
              isOnline={item.isOnline}
              showStatus={true}
            />

            <View style={styles.chatInfo}>
              <View style={styles.rowTop}>
                <Text style={styles.contactName} numberOfLines={1}>
                  {item.displayName}
                </Text>
                <Text style={styles.timestamp}>{item.lastSeen || 'Active'}</Text>
              </View>

              <View style={styles.rowBottom}>
                <View style={styles.previewContainer}>
                  <ReadReceipt status="read" size={14} />
                  <Text style={styles.previewText} numberOfLines={1}>
                    {item.bio || 'Encrypted direct messaging channel'}
                  </Text>
                </View>

                <UnreadBadge count={item.unreadCount} />
              </View>
            </View>
          </TouchableOpacity>
        )}
      />

      {/* Floating Add Contact Button */}
      <TouchableOpacity
        activeOpacity={0.85}
        onPress={onNavigateToContacts}
        style={styles.fab}
      >
        <Plus size={24} color={COLORS.textInverse} />
      </TouchableOpacity>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.bgDark,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: SPACING.lg,
    paddingTop: SPACING.lg,
    paddingBottom: SPACING.md,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  headerLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  headerTitle: {
    color: COLORS.textPrimary,
    fontSize: 20,
    fontWeight: '800',
    letterSpacing: 0.3,
  },
  headerSubtitle: {
    color: COLORS.primaryLight,
    fontSize: 12,
    fontFamily: 'monospace',
  },
  iconBtn: {
    padding: 8,
    backgroundColor: COLORS.bgCard,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  searchContainer: {
    paddingHorizontal: SPACING.lg,
    paddingVertical: SPACING.md,
  },
  searchBar: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.bgCard,
    borderRadius: RADIUS.md,
    paddingHorizontal: SPACING.md,
    borderWidth: 1,
    borderColor: COLORS.border,
    height: 44,
  },
  searchInput: {
    flex: 1,
    marginLeft: 10,
    color: COLORS.textPrimary,
    fontSize: 14,
  },
  listContent: {
    paddingBottom: 80,
  },
  chatRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: SPACING.lg,
    paddingVertical: SPACING.md,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(30, 41, 59, 0.4)',
  },
  chatInfo: {
    flex: 1,
    marginLeft: SPACING.md,
  },
  rowTop: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  contactName: {
    color: COLORS.textPrimary,
    fontSize: 16,
    fontWeight: '700',
    flex: 1,
    marginRight: 8,
  },
  timestamp: {
    color: COLORS.textMuted,
    fontSize: 12,
  },
  rowBottom: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  previewContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
    marginRight: 8,
    gap: 4,
  },
  previewText: {
    color: COLORS.textSecondary,
    fontSize: 13,
  },
  emptyContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    padding: SPACING.xxxl,
    marginTop: 40,
  },
  emptyTitle: {
    color: COLORS.textPrimary,
    fontSize: 18,
    fontWeight: '700',
    marginTop: 16,
    marginBottom: 8,
  },
  emptySubtitle: {
    color: COLORS.textSecondary,
    fontSize: 13,
    textAlign: 'center',
    lineHeight: 20,
    marginBottom: 20,
  },
  addContactBtn: {
    backgroundColor: COLORS.primary,
    paddingVertical: 10,
    paddingHorizontal: 20,
    borderRadius: RADIUS.md,
  },
  addContactBtnText: {
    color: COLORS.textInverse,
    fontWeight: '700',
    fontSize: 13,
  },
  fab: {
    position: 'absolute',
    bottom: 24,
    right: 20,
    width: 56,
    height: 56,
    borderRadius: 28,
    backgroundColor: COLORS.primary,
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: COLORS.primary,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.4,
    shadowRadius: 8,
    elevation: 6,
  },
});
