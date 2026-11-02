import React, { useState } from 'react';
import { View, Text, Modal, StyleSheet, TouchableOpacity, ScrollView } from 'react-native';
import { X, KeyRound, Copy, Check, AlertTriangle, RefreshCw } from 'lucide-react-native';
import { COLORS, SPACING, RADIUS } from '../constants/theme';
import { Button } from './Button';
import { Input } from './Input';
import { useAuth } from '../context/AuthContext';

interface RecoveryPhraseModalProps {
  visible: boolean;
  onClose: () => void;
  seedPhrase: string;
}

export const RecoveryPhraseModal: React.FC<RecoveryPhraseModalProps> = ({
  visible,
  onClose,
  seedPhrase,
}) => {
  const { restoreFromSeed } = useAuth();
  const [copied, setCopied] = useState(false);
  const [isImportMode, setIsImportMode] = useState(false);
  const [inputWords, setInputWords] = useState('');
  const [importError, setImportError] = useState<string | null>(null);
  const [isRestoring, setIsRestoring] = useState(false);

  const words = seedPhrase.trim().split(/\s+/);

  const handleCopy = () => {
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRestore = async () => {
    setImportError(null);
    setIsRestoring(true);
    const result = await restoreFromSeed(inputWords);
    setIsRestoring(false);
    if (result.success) {
      setIsImportMode(false);
      setInputWords('');
      onClose();
    } else {
      setImportError(result.error || 'Invalid 12-word recovery phrase.');
    }
  };

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.overlay}>
        <View style={styles.card}>
          {/* Header */}
          <View style={styles.header}>
            <View style={styles.headerTitleRow}>
              <KeyRound size={20} color={COLORS.primary} />
              <Text style={styles.title}>
                {isImportMode ? 'Restore Identity' : 'Backup Recovery Phrase'}
              </Text>
            </View>
            <TouchableOpacity onPress={onClose} style={styles.closeBtn}>
              <X size={20} color={COLORS.textSecondary} />
            </TouchableOpacity>
          </View>

          <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={{ paddingBottom: 10 }}>
            {!isImportMode ? (
              <>
                {/* Warning Banner */}
                <View style={styles.warningBanner}>
                  <AlertTriangle size={18} color={COLORS.warning} />
                  <Text style={styles.warningText}>
                    Write these 12 words down offline. If you switch devices or clear storage, this is the
                    ONLY way to recover your Unique ID. No email reset exists.
                  </Text>
                </View>

                {/* 12-Word Grid */}
                <View style={styles.wordsGrid}>
                  {words.map((word, index) => (
                    <View key={index} style={styles.wordCard}>
                      <Text style={styles.wordIndex}>{index + 1}</Text>
                      <Text style={styles.wordText}>{word}</Text>
                    </View>
                  ))}
                </View>

                <Button
                  title={copied ? 'Copied 12 Words to Clipboard!' : 'Copy 12-Word Phrase'}
                  onPress={handleCopy}
                  icon={copied ? <Check size={18} color={COLORS.textInverse} /> : <Copy size={18} color={COLORS.textInverse} />}
                  variant="primary"
                  style={{ marginTop: SPACING.md }}
                />

                <TouchableOpacity
                  onPress={() => {
                    setIsImportMode(true);
                    setImportError(null);
                  }}
                  style={styles.switchModeBtn}
                >
                  <RefreshCw size={15} color={COLORS.primary} />
                  <Text style={styles.switchModeText}>Have an existing 12-word seed? Restore here</Text>
                </TouchableOpacity>
              </>
            ) : (
              <>
                <Text style={styles.restoreDesc}>
                  Enter your 12-word recovery seed phrase separated by single spaces to restore your
                  pseudonymous identity and private keys.
                </Text>

                <Input
                  label="12-Word Recovery Phrase"
                  placeholder="e.g. apple banana cat dog..."
                  value={inputWords}
                  onChangeText={setInputWords}
                  multiline
                  numberOfLines={4}
                  style={{ minHeight: 90, textAlignVertical: 'top' }}
                  error={importError || undefined}
                />

                <Button
                  title="Restore My Unique ID"
                  onPress={handleRestore}
                  loading={isRestoring}
                  variant="primary"
                  style={{ marginTop: SPACING.md }}
                />

                <TouchableOpacity
                  onPress={() => {
                    setIsImportMode(false);
                    setImportError(null);
                  }}
                  style={styles.switchModeBtn}
                >
                  <Text style={styles.switchModeText}>Back to My Backup Phrase</Text>
                </TouchableOpacity>
              </>
            )}
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
};

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.8)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: SPACING.lg,
  },
  card: {
    width: '100%',
    maxWidth: 420,
    maxHeight: '90%',
    backgroundColor: COLORS.bgCard,
    borderRadius: RADIUS.lg,
    padding: SPACING.xl,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: SPACING.md,
  },
  headerTitleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  title: {
    color: COLORS.textPrimary,
    fontSize: 18,
    fontWeight: '700',
  },
  closeBtn: {
    padding: 4,
  },
  warningBanner: {
    flexDirection: 'row',
    backgroundColor: 'rgba(245, 158, 11, 0.12)',
    borderRadius: RADIUS.md,
    padding: SPACING.md,
    gap: 10,
    borderWidth: 1,
    borderColor: 'rgba(245, 158, 11, 0.3)',
    marginBottom: SPACING.md,
  },
  warningText: {
    flex: 1,
    color: '#FCD34D',
    fontSize: 12,
    lineHeight: 18,
  },
  wordsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    justifyContent: 'space-between',
    marginVertical: SPACING.xs,
  },
  wordCard: {
    width: '31%',
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.bgInput,
    paddingVertical: 10,
    paddingHorizontal: 8,
    borderRadius: RADIUS.sm,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  wordIndex: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '600',
    width: 20,
  },
  wordText: {
    color: COLORS.textPrimary,
    fontSize: 13,
    fontWeight: '600',
  },
  switchModeBtn: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    marginTop: SPACING.lg,
    paddingVertical: 6,
  },
  switchModeText: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '600',
  },
  restoreDesc: {
    color: COLORS.textSecondary,
    fontSize: 13,
    lineHeight: 19,
    marginBottom: SPACING.md,
  },
});
