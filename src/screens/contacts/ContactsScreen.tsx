import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TextInput,
  TouchableOpacity,
  Alert,
} from 'react-native';
import {
  UserPlus,
  QrCode,
  ShieldAlert,
  Check,
  X,
  MessageSquare,
  Search,
  Users,
} from 'lucide-react-native';
import { COLORS, SPACING, RADIUS } from '../../constants/theme';
import { Avatar } from '../../components/Avatar';
import { Button } from '../../components/Button';
import { useChat } from '../../context/ChatContext';
import { useAuth } from '../../context/AuthContext';
import { Contact } from '../../types';

interface ContactsScreenProps {
  onStartChat: (contact: Contact) => void;
}

export const ContactsScreen: React.FC<ContactsScreenProps> = ({ onStartChat }) => {
  const {
    contacts,
    sendContactRequest,
    respondToContactRequest,
    loadMessagesForContact,
  } = useChat();
  const { setShowQRModal } = useAuth();

  const [inputUid, setInputUid] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ text: string; isError?: boolean } | null>(null);

  const pendingIncoming = contacts.filter(c => c.status === 'pending_incoming');
  const acceptedContacts = contacts.filter(c => c.status === 'accepted');

  const handleAddContact = async () => {
    if (!inputUid.trim()) return;
    setIsSubmitting(true);
    setStatusMsg(null);

    const res = await sendContactRequest(inputUid);
    setIsSubmitting(false);

    if (res.success) {
      setInputUid('');
      setStatusMsg({ text: res.message, isError: false });
    } else {
      setStatusMsg({ text: res.message, isError: true });
    }
  };

  const handleChatDirect = (contact: Contact) => {
    loadMessagesForContact(contact);
    onStartChat(contact);
  };

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <View>
          <Text style={styles.title}>Contacts</Text>
          <Text style={styles.subtitle}>Pseudonymous Address Book</Text>
        </View>

        <TouchableOpacity onPress={() => setShowQRModal(true)} style={styles.qrBtn}>
          <QrCode size={20} color={COLORS.primary} />
          <Text style={styles.qrBtnText}>My QR</Text>
        </TouchableOpacity>
      </View>

      <FlatList
        data={acceptedContacts}
        keyExtractor={item => item.uid}
        showsVerticalScrollIndicator={false}
        contentContainerStyle={styles.listContent}
        ListHeaderComponent={
          <>
            {/* Add by Unique ID Card */}
            <View style={styles.card}>
              <View style={styles.cardHeader}>
                <UserPlus size={18} color={COLORS.primary} />
                <Text style={styles.cardTitle}>Add by Unique ID or @Handle</Text>
              </View>

              <Text style={styles.cardDesc}>
                Connect without phone numbers or emails. Enter your contact's alphanumeric Unique ID
                (e.g. `user_8x92fa`) or their chosen handle.
              </Text>

              <View style={styles.addInputRow}>
                <TextInput
                  placeholder="e.g. user_8x92fa or @handle"
                  placeholderTextColor={COLORS.textMuted}
                  value={inputUid}
                  onChangeText={setInputUid}
                  style={styles.addInput}
                  autoCapitalize="none"
                  autoCorrect={false}
                />
                <Button
                  title="Send Request"
                  onPress={handleAddContact}
                  loading={isSubmitting}
                  size="sm"
                  style={{ minWidth: 110 }}
                />
              </View>

              {statusMsg && (
                <Text
                  style={[
                    styles.statusText,
                    statusMsg.isError ? styles.statusError : styles.statusSuccess,
                  ]}
                >
                  {statusMsg.text}
                </Text>
              )}
            </View>

            {/* Pending Requests Section */}
            {pendingIncoming.length > 0 && (
              <View style={styles.pendingSection}>
                <View style={styles.sectionHeader}>
                  <ShieldAlert size={16} color={COLORS.warning} />
                  <Text style={styles.sectionTitle}>
                    Incoming Contact Requests ({pendingIncoming.length})
                  </Text>
                </View>

                {pendingIncoming.map(item => (
                  <View key={item.uid} style={styles.requestRow}>
                    <Avatar source={item.avatar} name={item.displayName} size={44} />
                    <View style={styles.requestInfo}>
                      <Text style={styles.requestName}>{item.displayName}</Text>
                      <Text style={styles.requestUid}>{item.uid}</Text>
                    </View>

                    <View style={styles.requestActions}>
                      <TouchableOpacity
                        onPress={() => respondToContactRequest(item.uid, 'reject')}
                        style={[styles.actionBtn, styles.declineBtn]}
                      >
                        <X size={16} color={COLORS.danger} />
                      </TouchableOpacity>

                      <TouchableOpacity
                        onPress={() => respondToContactRequest(item.uid, 'accept')}
                        style={[styles.actionBtn, styles.acceptBtn]}
                      >
                        <Check size={16} color={COLORS.primary} />
                      </TouchableOpacity>
                    </View>
                  </View>
                ))}
              </View>
            )}

            <View style={styles.directoryHeader}>
              <Users size={16} color={COLORS.textSecondary} />
              <Text style={styles.directoryTitle}>
                Verified Contacts ({acceptedContacts.length})
              </Text>
            </View>
          </>
        }
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyText}>No contacts added yet.</Text>
          </View>
        }
        renderItem={({ item }) => (
          <View style={styles.contactRow}>
            <Avatar
              source={item.avatar}
              name={item.displayName}
              size={46}
              isOnline={item.isOnline}
              showStatus={true}
            />

            <View style={styles.contactDetails}>
              <Text style={styles.contactName}>{item.displayName}</Text>
              <Text style={styles.contactHandle}>
                {item.handle} • {item.uid}
              </Text>
            </View>

            <TouchableOpacity
              onPress={() => handleChatDirect(item)}
              style={styles.chatActionBtn}
            >
              <MessageSquare size={18} color={COLORS.primary} />
            </TouchableOpacity>
          </View>
        )}
      />
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
  title: {
    color: COLORS.textPrimary,
    fontSize: 22,
    fontWeight: '800',
  },
  subtitle: {
    color: COLORS.textSecondary,
    fontSize: 12,
    marginTop: 2,
  },
  qrBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.bgCard,
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderRadius: RADIUS.md,
    gap: 6,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  qrBtnText: {
    color: COLORS.primaryLight,
    fontSize: 12,
    fontWeight: '700',
  },
  listContent: {
    paddingHorizontal: SPACING.lg,
    paddingVertical: SPACING.md,
    paddingBottom: 60,
  },
  card: {
    backgroundColor: COLORS.bgCard,
    borderRadius: RADIUS.lg,
    padding: SPACING.lg,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: SPACING.lg,
  },
  cardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 6,
  },
  cardTitle: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '700',
  },
  cardDesc: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 18,
    marginBottom: SPACING.md,
  },
  addInputRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  addInput: {
    flex: 1,
    backgroundColor: COLORS.bgInput,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
    paddingHorizontal: 12,
    paddingVertical: 8,
    color: COLORS.textPrimary,
    fontSize: 13,
  },
  statusText: {
    fontSize: 12,
    marginTop: 8,
    fontWeight: '500',
  },
  statusSuccess: {
    color: COLORS.primary,
  },
  statusError: {
    color: COLORS.danger,
  },
  pendingSection: {
    backgroundColor: 'rgba(245, 158, 11, 0.08)',
    borderRadius: RADIUS.lg,
    padding: SPACING.md,
    borderWidth: 1,
    borderColor: 'rgba(245, 158, 11, 0.25)',
    marginBottom: SPACING.lg,
  },
  sectionHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    marginBottom: SPACING.md,
  },
  sectionTitle: {
    color: COLORS.warning,
    fontSize: 13,
    fontWeight: '700',
  },
  requestRow: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.bgCard,
    padding: SPACING.sm,
    borderRadius: RADIUS.md,
    marginBottom: 6,
  },
  requestInfo: {
    flex: 1,
    marginLeft: 10,
  },
  requestName: {
    color: COLORS.textPrimary,
    fontSize: 14,
    fontWeight: '600',
  },
  requestUid: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontFamily: 'monospace',
  },
  requestActions: {
    flexDirection: 'row',
    gap: 8,
  },
  actionBtn: {
    width: 32,
    height: 32,
    borderRadius: 16,
    justifyContent: 'center',
    alignItems: 'center',
  },
  declineBtn: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
  },
  acceptBtn: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
  },
  directoryHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    marginVertical: SPACING.sm,
  },
  directoryTitle: {
    color: COLORS.textSecondary,
    fontSize: 12,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  contactRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: SPACING.md,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(30, 41, 59, 0.4)',
  },
  contactDetails: {
    flex: 1,
    marginLeft: SPACING.md,
  },
  contactName: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '600',
  },
  contactHandle: {
    color: COLORS.textMuted,
    fontSize: 12,
    marginTop: 2,
  },
  chatActionBtn: {
    padding: 10,
    backgroundColor: COLORS.bgCard,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  emptyContainer: {
    padding: SPACING.xl,
    alignItems: 'center',
  },
  emptyText: {
    color: COLORS.textMuted,
    fontSize: 13,
  },
});
