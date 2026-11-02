import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  StyleSheet,
  FlatList,
  TextInput,
  TouchableOpacity,
  KeyboardAvoidingView,
  Platform,
  Image,
} from 'react-native';
import {
  ArrowLeft,
  Phone,
  Video,
  Send,
  Image as ImageIcon,
  Mic,
  Paperclip,
  Play,
  Pause,
  ShieldCheck,
  CheckCheck,
} from 'lucide-react-native';
import { COLORS, SPACING, RADIUS } from '../../constants/theme';
import { Avatar } from '../../components/Avatar';
import { ReadReceipt } from '../../components/Badge';
import { useChat } from '../../context/ChatContext';
import { useCall } from '../../context/CallContext';
import { useAuth } from '../../context/AuthContext';
import { Message } from '../../types';

interface ChatRoomScreenProps {
  onBack: () => void;
}

const SAMPLE_MEDIA = [
  'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?w=400',
  'https://images.unsplash.com/photo-1550745165-9bc0b252726f?w=400',
];

export const ChatRoomScreen: React.FC<ChatRoomScreenProps> = ({ onBack }) => {
  const { session } = useAuth();
  const {
    activeChatContact,
    activeChatMessages,
    sendMessage,
    isPeerTyping,
  } = useChat();
  const { startCall } = useCall();

  const [inputVal, setInputVal] = useState('');
  const [playingVoiceId, setPlayingVoiceId] = useState<string | null>(null);
  const flatListRef = useRef<FlatList>(null);

  useEffect(() => {
    flatListRef.current?.scrollToEnd({ animated: true });
  }, [activeChatMessages, isPeerTyping]);

  if (!activeChatContact) return null;

  const handleSend = () => {
    const trimmed = inputVal.trim();
    if (!trimmed) return;
    sendMessage(trimmed, 'text');
    setInputVal('');
  };

  const handleSendImage = () => {
    const randomImg = SAMPLE_MEDIA[Math.floor(Math.random() * SAMPLE_MEDIA.length)];
    sendMessage('Encrypted photo attachment', 'image', randomImg);
  };

  const handleSendVoiceNote = () => {
    const randomDuration = Math.floor(Math.random() * 8) + 4;
    sendMessage('Voice Note', 'voice', undefined, randomDuration);
  };

  const toggleVoicePlayback = (id: string) => {
    setPlayingVoiceId(playingVoiceId === id ? null : id);
  };

  const renderMessageItem = ({ item }: { item: Message }) => {
    const isMe = item.senderUid === session?.uid;

    return (
      <View
        style={[
          styles.msgRow,
          isMe ? styles.msgRowSent : styles.msgRowReceived,
        ]}
      >
        <View
          style={[
            styles.bubble,
            isMe ? styles.bubbleSent : styles.bubbleReceived,
          ]}
        >
          {/* Image Attachment */}
          {item.type === 'image' && item.mediaUrl && (
            <Image source={{ uri: item.mediaUrl }} style={styles.imageAttachment} />
          )}

          {/* Voice Note Attachment */}
          {item.type === 'voice' && (
            <View style={styles.voiceContainer}>
              <TouchableOpacity
                onPress={() => toggleVoicePlayback(item.id)}
                style={styles.playBtn}
              >
                {playingVoiceId === item.id ? (
                  <Pause size={16} color={COLORS.textInverse} />
                ) : (
                  <Play size={16} color={COLORS.textInverse} />
                )}
              </TouchableOpacity>
              <View style={styles.voiceWaves}>
                <View style={[styles.waveBar, { height: 12 }]} />
                <View style={[styles.waveBar, { height: 22 }]} />
                <View style={[styles.waveBar, { height: 16 }]} />
                <View style={[styles.waveBar, { height: 28 }]} />
                <View style={[styles.waveBar, { height: 14 }]} />
                <View style={[styles.waveBar, { height: 20 }]} />
                <View style={[styles.waveBar, { height: 8 }]} />
              </View>
              <Text style={styles.voiceDuration}>
                {item.duration || 6}s
              </Text>
            </View>
          )}

          {/* Text Content */}
          {item.content ? (
            <Text
              style={[
                styles.msgText,
                isMe ? styles.msgTextSent : styles.msgTextReceived,
              ]}
            >
              {item.content}
            </Text>
          ) : null}

          {/* Timestamp & Read Receipt */}
          <View style={styles.msgFooter}>
            <Text style={styles.timeText}>
              {new Date(item.timestamp).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
              })}
            </Text>
            {isMe && <ReadReceipt status={item.status} size={13} />}
          </View>
        </View>
      </View>
    );
  };

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
      style={styles.container}
    >
      {/* Top Header */}
      <View style={styles.header}>
        <TouchableOpacity onPress={onBack} style={styles.backBtn}>
          <ArrowLeft size={22} color={COLORS.textPrimary} />
        </TouchableOpacity>

        <View style={styles.peerInfo}>
          <Avatar
            source={activeChatContact.avatar}
            name={activeChatContact.displayName}
            size={40}
            isOnline={activeChatContact.isOnline}
            showStatus={true}
          />
          <View style={{ marginLeft: 10, flex: 1 }}>
            <Text style={styles.peerName} numberOfLines={1}>
              {activeChatContact.displayName}
            </Text>
            <Text style={styles.peerStatus} numberOfLines={1}>
              {isPeerTyping
                ? 'typing...'
                : activeChatContact.isOnline
                ? 'Online • P2P Active'
                : 'Offline'}
            </Text>
          </View>
        </View>

        {/* Audio & Video Call Triggers */}
        <View style={styles.headerActions}>
          <TouchableOpacity
            onPress={() => startCall(activeChatContact, 'audio')}
            style={styles.actionBtn}
          >
            <Phone size={20} color={COLORS.primary} />
          </TouchableOpacity>

          <TouchableOpacity
            onPress={() => startCall(activeChatContact, 'video')}
            style={styles.actionBtn}
          >
            <Video size={20} color={COLORS.primary} />
          </TouchableOpacity>
        </View>
      </View>

      {/* Encryption Notice */}
      <View style={styles.encryptionPill}>
        <ShieldCheck size={14} color={COLORS.primary} />
        <Text style={styles.encryptionNotice}>
          Messages are pseudonymous & E2E encrypted. No phone number or logs.
        </Text>
      </View>

      {/* Messages List */}
      <FlatList
        ref={flatListRef}
        data={activeChatMessages}
        keyExtractor={item => item.id}
        renderItem={renderMessageItem}
        contentContainerStyle={styles.messagesList}
        showsVerticalScrollIndicator={false}
      />

      {/* Peer Typing Indicator */}
      {isPeerTyping && (
        <View style={styles.typingBanner}>
          <Text style={styles.typingText}>
            {activeChatContact.displayName} is typing...
          </Text>
        </View>
      )}

      {/* Input Row */}
      <View style={styles.inputContainer}>
        <TouchableOpacity onPress={handleSendImage} style={styles.mediaBtn}>
          <ImageIcon size={20} color={COLORS.textSecondary} />
        </TouchableOpacity>

        <TouchableOpacity onPress={handleSendVoiceNote} style={styles.mediaBtn}>
          <Mic size={20} color={COLORS.textSecondary} />
        </TouchableOpacity>

        <TextInput
          placeholder="Message anonymously..."
          placeholderTextColor={COLORS.textMuted}
          value={inputVal}
          onChangeText={setInputVal}
          multiline
          style={styles.inputField}
          onSubmitEditing={handleSend}
        />

        <TouchableOpacity
          onPress={handleSend}
          disabled={!inputVal.trim()}
          style={[
            styles.sendBtn,
            inputVal.trim() ? styles.sendBtnActive : styles.sendBtnDisabled,
          ]}
        >
          <Send size={18} color={inputVal.trim() ? COLORS.textInverse : COLORS.textMuted} />
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.bgDark,
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: SPACING.md,
    paddingTop: SPACING.lg,
    paddingBottom: SPACING.md,
    backgroundColor: COLORS.bgCard,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border,
  },
  backBtn: {
    padding: 6,
    marginRight: 6,
  },
  peerInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  peerName: {
    color: COLORS.textPrimary,
    fontSize: 16,
    fontWeight: '700',
  },
  peerStatus: {
    color: COLORS.primaryLight,
    fontSize: 11,
  },
  headerActions: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  actionBtn: {
    padding: 8,
    backgroundColor: COLORS.bgInput,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  encryptionPill: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(16, 185, 129, 0.08)',
    paddingVertical: 6,
    paddingHorizontal: 12,
    marginHorizontal: SPACING.lg,
    marginTop: SPACING.sm,
    borderRadius: RADIUS.full,
    gap: 6,
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.2)',
  },
  encryptionNotice: {
    color: COLORS.primaryLight,
    fontSize: 11,
    fontWeight: '500',
  },
  messagesList: {
    paddingHorizontal: SPACING.md,
    paddingVertical: SPACING.md,
  },
  msgRow: {
    flexDirection: 'row',
    marginVertical: 4,
    width: '100%',
  },
  msgRowSent: {
    justifyContent: 'flex-end',
  },
  msgRowReceived: {
    justifyContent: 'flex-start',
  },
  bubble: {
    maxWidth: '82%',
    paddingHorizontal: 12,
    paddingTop: 8,
    paddingBottom: 6,
    borderRadius: RADIUS.md,
  },
  bubbleSent: {
    backgroundColor: COLORS.bubbleSent,
    borderBottomRightRadius: 2,
  },
  bubbleReceived: {
    backgroundColor: COLORS.bubbleReceived,
    borderBottomLeftRadius: 2,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  imageAttachment: {
    width: 220,
    height: 150,
    borderRadius: RADIUS.sm,
    marginBottom: 6,
  },
  voiceContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingVertical: 4,
    minWidth: 160,
  },
  playBtn: {
    width: 32,
    height: 32,
    borderRadius: 16,
    backgroundColor: COLORS.primary,
    justifyContent: 'center',
    alignItems: 'center',
  },
  voiceWaves: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 3,
    flex: 1,
  },
  waveBar: {
    width: 3,
    backgroundColor: COLORS.primaryLight,
    borderRadius: 2,
  },
  voiceDuration: {
    color: COLORS.textSecondary,
    fontSize: 11,
    fontWeight: '600',
  },
  msgText: {
    fontSize: 14,
    lineHeight: 20,
  },
  msgTextSent: {
    color: COLORS.bubbleTextSent,
  },
  msgTextReceived: {
    color: COLORS.bubbleTextReceived,
  },
  msgFooter: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'flex-end',
    marginTop: 4,
    gap: 4,
  },
  timeText: {
    color: COLORS.receiptGrey,
    fontSize: 10,
  },
  typingBanner: {
    paddingHorizontal: SPACING.lg,
    paddingVertical: 4,
  },
  typingText: {
    color: COLORS.primaryLight,
    fontSize: 12,
    fontStyle: 'italic',
  },
  inputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: SPACING.md,
    paddingVertical: SPACING.sm,
    backgroundColor: COLORS.bgCard,
    borderTopWidth: 1,
    borderTopColor: COLORS.border,
    gap: 8,
  },
  mediaBtn: {
    padding: 8,
  },
  inputField: {
    flex: 1,
    backgroundColor: COLORS.bgInput,
    borderRadius: RADIUS.md,
    paddingHorizontal: 12,
    paddingVertical: 8,
    color: COLORS.textPrimary,
    fontSize: 14,
    maxHeight: 100,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  sendBtn: {
    width: 38,
    height: 38,
    borderRadius: 19,
    justifyContent: 'center',
    alignItems: 'center',
  },
  sendBtnActive: {
    backgroundColor: COLORS.primary,
  },
  sendBtnDisabled: {
    backgroundColor: COLORS.bgElevated,
  },
});
