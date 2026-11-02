import React from 'react';
import { View, Text, StyleSheet, FlatList, TouchableOpacity } from 'react-native';
import { Phone, PhoneIncoming, PhoneOutgoing, PhoneMissed, Video, PhoneCall } from 'lucide-react-native';
import { COLORS, SPACING, RADIUS } from '../../constants/theme';
import { Avatar } from '../../components/Avatar';
import { useCall } from '../../context/CallContext';
import { useChat } from '../../context/ChatContext';
import { CallRecord } from '../../types';

export const CallsHistoryScreen: React.FC = () => {
  const { callHistory, startCall } = useCall();
  const { contacts } = useChat();

  const handleCallBack = (record: CallRecord) => {
    const contact = contacts.find(c => c.uid === record.peerUid) || {
      uid: record.peerUid,
      handle: `@${record.peerUid}`,
      displayName: record.peerName,
      avatar: record.peerAvatar,
      bio: 'P2P Contact',
      status: 'accepted',
      unreadCount: 0,
      isOnline: true,
    };
    startCall(contact, record.type);
  };

  const renderCallIcon = (record: CallRecord) => {
    if (record.direction === 'missed') {
      return <PhoneMissed size={16} color={COLORS.danger} />;
    }
    if (record.direction === 'incoming') {
      return <PhoneIncoming size={16} color={COLORS.primary} />;
    }
    return <PhoneOutgoing size={16} color={COLORS.textSecondary} />;
  };

  const formatDuration = (sec: number) => {
    if (sec <= 0) return 'Missed';
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m > 0 ? `${m}m ` : ''}${s}s`;
  };

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>Calls</Text>
        <Text style={styles.subtitle}>Direct Peer-to-Peer Encrypted Calls</Text>
      </View>

      <FlatList
        data={callHistory}
        keyExtractor={item => item.id}
        contentContainerStyle={styles.listContent}
        showsVerticalScrollIndicator={false}
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <PhoneCall size={48} color={COLORS.borderLight} />
            <Text style={styles.emptyTitle}>No Recent Calls</Text>
            <Text style={styles.emptySubtitle}>
              Direct audio and video calls initiated between Unique IDs will appear here.
            </Text>
          </View>
        }
        renderItem={({ item }) => (
          <View style={styles.callRow}>
            <Avatar source={item.peerAvatar} name={item.peerName} size={48} />

            <View style={styles.callInfo}>
              <Text style={styles.peerName}>{item.peerName}</Text>
              <View style={styles.callMeta}>
                {renderCallIcon(item)}
                <Text style={styles.metaText}>
                  {item.type === 'video' ? 'Video' : 'Audio'} • {formatDuration(item.duration)} •{' '}
                  {new Date(item.timestamp).toLocaleDateString([], {
                    month: 'short',
                    day: 'numeric',
                  })}
                </Text>
              </View>
            </View>

            <TouchableOpacity
              onPress={() => handleCallBack(item)}
              style={styles.callBackBtn}
            >
              {item.type === 'video' ? (
                <Video size={18} color={COLORS.primary} />
              ) : (
                <Phone size={18} color={COLORS.primary} />
              )}
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
  listContent: {
    paddingHorizontal: SPACING.lg,
    paddingVertical: SPACING.sm,
  },
  callRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: SPACING.md,
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(30, 41, 59, 0.4)',
  },
  callInfo: {
    flex: 1,
    marginLeft: SPACING.md,
  },
  peerName: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '700',
    marginBottom: 4,
  },
  callMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
  },
  metaText: {
    color: COLORS.textSecondary,
    fontSize: 12,
  },
  callBackBtn: {
    padding: 10,
    backgroundColor: COLORS.bgCard,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  emptyContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    padding: SPACING.xxxl,
    marginTop: 60,
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
  },
});
