import React, { useState } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TouchableOpacity,
  Switch,
  Alert,
} from 'react-native';
import {
  Shield,
  KeyRound,
  QrCode,
  Copy,
  Check,
  Flame,
  UserCheck,
  Eye,
  Lock,
  ChevronRight,
  Info,
} from 'lucide-react-native';
import { COLORS, SPACING, RADIUS } from '../../constants/theme';
import { Avatar } from '../../components/Avatar';
import { Button } from '../../components/Button';
import { Input } from '../../components/Input';
import { useAuth } from '../../context/AuthContext';

export const SettingsScreen: React.FC = () => {
  const {
    session,
    privacy,
    updateProfile,
    updatePrivacy,
    burnIdentity,
    setShowSeedModal,
    setShowQRModal,
  } = useAuth();

  const [displayName, setDisplayName] = useState(session?.displayName || '');
  const [bio, setBio] = useState(session?.bio || '');
  const [handle, setHandle] = useState(session?.handle || '');
  const [isEditingProfile, setIsEditingProfile] = useState(false);
  const [copiedUid, setCopiedUid] = useState(false);

  const handleSaveProfile = async () => {
    if (!session) return;
    await updateProfile(displayName, bio, session.avatar, handle);
    setIsEditingProfile(false);
  };

  const handleCopyUid = () => {
    setCopiedUid(true);
    setTimeout(() => setCopiedUid(false), 2000);
  };

  const handleBurn = () => {
    if (PlatformAlertConfirm()) {
      burnIdentity();
    }
  };

  // Safe confirm for Web and Native
  const PlatformAlertConfirm = () => {
    if (typeof window !== 'undefined' && window.confirm) {
      return window.confirm(
        'Burn Identity: This wipes your private keys, seed phrase, contacts, and all messages locally. This action cannot be undone!'
      );
    }
    return true;
  };

  if (!session) return null;

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.title}>Settings</Text>
        <Text style={styles.subtitle}>Privacy & Pseudonymous Identity</Text>
      </View>

      {/* Identity Card */}
      <View style={styles.identityCard}>
        <View style={styles.profileRow}>
          <Avatar
            source={session.avatar}
            name={session.displayName}
            size={64}
            isOnline={true}
            showStatus={true}
          />

          <View style={styles.profileDetails}>
            <Text style={styles.profileName}>{session.displayName}</Text>
            <Text style={styles.profileHandle}>{session.handle}</Text>
            <Text style={styles.profileBio} numberOfLines={2}>
              {session.bio}
            </Text>
          </View>
        </View>

        {/* Unique ID Container */}
        <View style={styles.uidContainer}>
          <View style={{ flex: 1 }}>
            <Text style={styles.uidLabel}>Unique Anonymous ID</Text>
            <Text style={styles.uidValue}>{session.uid}</Text>
          </View>
          <TouchableOpacity onPress={handleCopyUid} style={styles.copyBtn}>
            {copiedUid ? <Check size={16} color={COLORS.primary} /> : <Copy size={16} color={COLORS.textSecondary} />}
            <Text style={styles.copyBtnText}>{copiedUid ? 'Copied' : 'Copy'}</Text>
          </TouchableOpacity>
        </View>

        {/* Edit Profile Toggle */}
        <TouchableOpacity
          onPress={() => setIsEditingProfile(!isEditingProfile)}
          style={styles.editToggleBtn}
        >
          <Text style={styles.editToggleText}>
            {isEditingProfile ? 'Close Editor' : 'Edit Profile Display Details'}
          </Text>
        </TouchableOpacity>

        {isEditingProfile && (
          <View style={styles.editorBox}>
            <Input
              label="Display Name"
              value={displayName}
              onChangeText={setDisplayName}
              placeholder="e.g. Ghost Operator"
            />
            <Input
              label="Handle"
              value={handle}
              onChangeText={setHandle}
              placeholder="e.g. @shadow_ghost"
            />
            <Input
              label="Bio / Status"
              value={bio}
              onChangeText={setBio}
              placeholder="e.g. Zero-footprint messaging"
            />
            <Button
              title="Save Profile"
              onPress={handleSaveProfile}
              variant="primary"
              size="sm"
              style={{ marginTop: 8 }}
            />
          </View>
        )}
      </View>

      {/* Security & Recovery Menu */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Security & Credentials</Text>

        <TouchableOpacity onPress={() => setShowSeedModal(true)} style={styles.menuItem}>
          <View style={[styles.menuIcon, { backgroundColor: 'rgba(16, 185, 129, 0.15)' }]}>
            <KeyRound size={20} color={COLORS.primary} />
          </View>
          <View style={styles.menuContent}>
            <Text style={styles.menuLabel}>12-Word Recovery Phrase</Text>
            <Text style={styles.menuSub}>Backup or restore your Unique ID</Text>
          </View>
          <ChevronRight size={18} color={COLORS.textMuted} />
        </TouchableOpacity>

        <TouchableOpacity onPress={() => setShowQRModal(true)} style={styles.menuItem}>
          <View style={[styles.menuIcon, { backgroundColor: 'rgba(99, 102, 241, 0.15)' }]}>
            <QrCode size={20} color={COLORS.secondary} />
          </View>
          <View style={styles.menuContent}>
            <Text style={styles.menuLabel}>My Anonymous QR Code</Text>
            <Text style={styles.menuSub}>Display QR code to connect in person</Text>
          </View>
          <ChevronRight size={18} color={COLORS.textMuted} />
        </TouchableOpacity>
      </View>

      {/* Privacy Controls */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Privacy & Spam Protection</Text>

        <View style={styles.switchRow}>
          <View style={styles.switchInfo}>
            <Text style={styles.switchLabel}>Incoming Contact Requests</Text>
            <Text style={styles.switchSub}>
              Require strangers to request approval before sending messages.
            </Text>
          </View>
          <Switch
            value={privacy.allowContactRequests}
            onValueChange={v => updatePrivacy({ allowContactRequests: v })}
            trackColor={{ false: COLORS.bgElevated, true: COLORS.primaryDark }}
            thumbColor={privacy.allowContactRequests ? COLORS.primary : '#FFF'}
          />
        </View>

        <View style={styles.switchRow}>
          <View style={styles.switchInfo}>
            <Text style={styles.switchLabel}>Read Receipts</Text>
            <Text style={styles.switchSub}>
              Show sent, delivered, and read double checkmarks.
            </Text>
          </View>
          <Switch
            value={privacy.showReadReceipts}
            onValueChange={v => updatePrivacy({ showReadReceipts: v })}
            trackColor={{ false: COLORS.bgElevated, true: COLORS.primaryDark }}
            thumbColor={privacy.showReadReceipts ? COLORS.primary : '#FFF'}
          />
        </View>

        <View style={styles.switchRow}>
          <View style={styles.switchInfo}>
            <Text style={styles.switchLabel}>Online Status Visibility</Text>
            <Text style={styles.switchSub}>
              Broadcast P2P presence when the app is active.
            </Text>
          </View>
          <Switch
            value={privacy.showOnlineStatus}
            onValueChange={v => updatePrivacy({ showOnlineStatus: v })}
            trackColor={{ false: COLORS.bgElevated, true: COLORS.primaryDark }}
            thumbColor={privacy.showOnlineStatus ? COLORS.primary : '#FFF'}
          />
        </View>
      </View>

      {/* Burn Identity Section */}
      <View style={styles.burnSection}>
        <Text style={styles.burnTitle}>Danger Zone</Text>
        <Text style={styles.burnDesc}>
          Burning your identity permanently erases all cryptographic keys, chat history, and contacts
          from this device. A new anonymous ID will be generated immediately.
        </Text>

        <Button
          title="Burn Identity & Reset Everything"
          onPress={handleBurn}
          variant="danger"
          icon={<Flame size={18} color="#FFF" />}
        />
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: COLORS.bgDark,
  },
  content: {
    paddingHorizontal: SPACING.lg,
    paddingTop: SPACING.lg,
    paddingBottom: 80,
  },
  header: {
    marginBottom: SPACING.lg,
  },
  title: {
    color: COLORS.textPrimary,
    fontSize: 24,
    fontWeight: '800',
  },
  subtitle: {
    color: COLORS.textSecondary,
    fontSize: 13,
    marginTop: 2,
  },
  identityCard: {
    backgroundColor: COLORS.bgCard,
    borderRadius: RADIUS.lg,
    padding: SPACING.lg,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: SPACING.xl,
  },
  profileRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  profileDetails: {
    flex: 1,
    marginLeft: SPACING.md,
  },
  profileName: {
    color: COLORS.textPrimary,
    fontSize: 17,
    fontWeight: '700',
  },
  profileHandle: {
    color: COLORS.primaryLight,
    fontSize: 13,
    marginTop: 2,
  },
  profileBio: {
    color: COLORS.textSecondary,
    fontSize: 12,
    marginTop: 4,
  },
  uidContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.bgInput,
    padding: SPACING.md,
    borderRadius: RADIUS.md,
    marginTop: SPACING.md,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  uidLabel: {
    color: COLORS.textMuted,
    fontSize: 11,
    textTransform: 'uppercase',
    fontWeight: '600',
  },
  uidValue: {
    color: COLORS.primary,
    fontSize: 14,
    fontWeight: '700',
    fontFamily: 'monospace',
    marginTop: 2,
  },
  copyBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
    paddingVertical: 6,
    paddingHorizontal: 10,
    backgroundColor: COLORS.bgElevated,
    borderRadius: RADIUS.sm,
  },
  copyBtnText: {
    color: COLORS.textSecondary,
    fontSize: 12,
    fontWeight: '600',
  },
  editToggleBtn: {
    marginTop: SPACING.md,
    alignSelf: 'center',
    paddingVertical: 4,
  },
  editToggleText: {
    color: COLORS.primaryLight,
    fontSize: 12,
    fontWeight: '600',
  },
  editorBox: {
    marginTop: SPACING.md,
    paddingTop: SPACING.md,
    borderTopWidth: 1,
    borderTopColor: COLORS.border,
  },
  section: {
    marginBottom: SPACING.xl,
  },
  sectionTitle: {
    color: COLORS.textSecondary,
    fontSize: 12,
    fontWeight: '700',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: SPACING.md,
  },
  menuItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.bgCard,
    padding: SPACING.md,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 8,
  },
  menuIcon: {
    width: 38,
    height: 38,
    borderRadius: 19,
    justifyContent: 'center',
    alignItems: 'center',
  },
  menuContent: {
    flex: 1,
    marginLeft: 12,
  },
  menuLabel: {
    color: COLORS.textPrimary,
    fontSize: 14,
    fontWeight: '600',
  },
  menuSub: {
    color: COLORS.textMuted,
    fontSize: 11,
    marginTop: 2,
  },
  switchRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: COLORS.bgCard,
    padding: SPACING.md,
    borderRadius: RADIUS.md,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 8,
  },
  switchInfo: {
    flex: 1,
    marginRight: 12,
  },
  switchLabel: {
    color: COLORS.textPrimary,
    fontSize: 14,
    fontWeight: '600',
  },
  switchSub: {
    color: COLORS.textMuted,
    fontSize: 11,
    marginTop: 2,
    lineHeight: 16,
  },
  burnSection: {
    backgroundColor: 'rgba(239, 68, 68, 0.08)',
    borderRadius: RADIUS.lg,
    padding: SPACING.lg,
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.25)',
  },
  burnTitle: {
    color: COLORS.danger,
    fontSize: 14,
    fontWeight: '700',
    textTransform: 'uppercase',
    marginBottom: 6,
  },
  burnDesc: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 18,
    marginBottom: SPACING.lg,
  },
});
