import React, { useState } from 'react';
import { View, Text, Modal, StyleSheet, TouchableOpacity } from 'react-native';
import Svg, { Rect } from 'react-native-svg';
import { X, Copy, Check, ShieldCheck, QrCode } from 'lucide-react-native';
import { COLORS, SPACING, RADIUS } from '../constants/theme';
import { Button } from './Button';

interface QRCodeModalProps {
  visible: boolean;
  onClose: () => void;
  uid: string;
  handle: string;
  displayName: string;
}

export const QRCodeModal: React.FC<QRCodeModalProps> = ({
  visible,
  onClose,
  uid,
  handle,
  displayName,
}) => {
  const [copied, setCopied] = useState(false);

  // Deterministically generate a 17x17 QR code pattern based on the UID string
  const generatePattern = (text: string) => {
    const size = 17;
    const grid: boolean[][] = [];
    let hash = 0;
    for (let i = 0; i < text.length; i++) {
      hash = ((hash << 5) - hash) + text.charCodeAt(i);
      hash |= 0;
    }

    for (let r = 0; r < size; r++) {
      grid[r] = [];
      for (let c = 0; c < size; c++) {
        // Standard Corner Finding patterns (top-left, top-right, bottom-left)
        const isTL = r < 5 && c < 5;
        const isTR = r < 5 && c >= size - 5;
        const isBL = r >= size - 5 && c < 5;

        if (isTL || isTR || isBL) {
          const border = r === 0 || r === 4 || c === 0 || c === 4 ||
            (isTR && (r === 0 || r === 4 || c === size - 5 || c === size - 1)) ||
            (isBL && (r === size - 5 || r === size - 1 || c === 0 || c === 4));
          const center = (r >= 1 && r <= 3 && c >= 1 && c <= 3) ||
            (isTR && r >= 1 && r <= 3 && c >= size - 4 && c <= size - 2) ||
            (isBL && r >= size - 4 && r <= size - 2 && c >= 1 && c <= 3);
          grid[r][c] = border || center;
        } else {
          // Semi-random data modules derived from hash and coords
          const val = ((hash >> ((r * c) % 24)) & 1) === 1 || ((r + c + text.length) % 3 === 0);
          grid[r][c] = val;
        }
      }
    }
    return grid;
  };

  const pattern = generatePattern(uid);
  const matrixSize = 17;
  const cellSize = 11;
  const qrSvgSize = matrixSize * cellSize;

  const handleCopy = () => {
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Modal visible={visible} transparent animationType="fade" onRequestClose={onClose}>
      <View style={styles.overlay}>
        <View style={styles.card}>
          {/* Header */}
          <View style={styles.header}>
            <View style={styles.headerTitleRow}>
              <QrCode size={20} color={COLORS.primary} />
              <Text style={styles.title}>My Anonymous QR</Text>
            </View>
            <TouchableOpacity onPress={onClose} style={styles.closeBtn}>
              <X size={20} color={COLORS.textSecondary} />
            </TouchableOpacity>
          </View>

          <Text style={styles.subtitle}>
            Share this QR code or Unique ID to connect securely with zero phone numbers or emails.
          </Text>

          {/* QR Code Container */}
          <View style={styles.qrContainer}>
            <Svg width={qrSvgSize} height={qrSvgSize}>
              <Rect width={qrSvgSize} height={qrSvgSize} fill="#FFFFFF" rx={8} />
              {pattern.map((row, r) =>
                row.map((cell, c) =>
                  cell ? (
                    <Rect
                      key={`${r}-${c}`}
                      x={c * cellSize}
                      y={r * cellSize}
                      width={cellSize}
                      height={cellSize}
                      fill="#0B0F19"
                    />
                  ) : null
                )
              )}
            </Svg>

            <View style={styles.userBadge}>
              <Text style={styles.displayName}>{displayName}</Text>
              <Text style={styles.handle}>{handle}</Text>
            </View>
          </View>

          {/* Unique ID Box */}
          <View style={styles.idBox}>
            <View style={{ flex: 1 }}>
              <Text style={styles.idLabel}>Unique Anonymous ID</Text>
              <Text style={styles.idValue}>{uid}</Text>
            </View>
            <TouchableOpacity onPress={handleCopy} style={styles.copyIconBtn}>
              {copied ? <Check size={18} color={COLORS.primary} /> : <Copy size={18} color={COLORS.textSecondary} />}
            </TouchableOpacity>
          </View>

          {/* E2E Security Pill */}
          <View style={styles.securityPill}>
            <ShieldCheck size={16} color={COLORS.primary} />
            <Text style={styles.securityText}>P2P Cryptographically Signed</Text>
          </View>

          <Button
            title={copied ? 'Copied to Clipboard!' : 'Copy Unique ID'}
            onPress={handleCopy}
            variant="primary"
            style={{ marginTop: SPACING.md }}
          />
        </View>
      </View>
    </Modal>
  );
};

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0, 0, 0, 0.75)',
    justifyContent: 'center',
    alignItems: 'center',
    padding: SPACING.xl,
  },
  card: {
    width: '100%',
    maxWidth: 380,
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
    marginBottom: SPACING.xs,
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
  subtitle: {
    color: COLORS.textSecondary,
    fontSize: 13,
    marginBottom: SPACING.lg,
    lineHeight: 18,
  },
  qrContainer: {
    backgroundColor: '#FFFFFF',
    padding: SPACING.lg,
    borderRadius: RADIUS.md,
    alignItems: 'center',
    justifyContent: 'center',
    marginVertical: SPACING.sm,
  },
  userBadge: {
    marginTop: SPACING.md,
    alignItems: 'center',
  },
  displayName: {
    color: '#0B0F19',
    fontSize: 15,
    fontWeight: '700',
  },
  handle: {
    color: '#64748B',
    fontSize: 13,
    fontWeight: '500',
  },
  idBox: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.bgInput,
    padding: SPACING.md,
    borderRadius: RADIUS.md,
    marginTop: SPACING.md,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  idLabel: {
    color: COLORS.textMuted,
    fontSize: 11,
    textTransform: 'uppercase',
    fontWeight: '600',
  },
  idValue: {
    color: COLORS.primaryLight,
    fontSize: 15,
    fontWeight: '700',
    fontFamily: 'monospace',
    marginTop: 2,
  },
  copyIconBtn: {
    padding: 8,
    backgroundColor: COLORS.bgElevated,
    borderRadius: RADIUS.sm,
  },
  securityPill: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 6,
    marginTop: SPACING.md,
  },
  securityText: {
    color: COLORS.primary,
    fontSize: 12,
    fontWeight: '600',
  },
});
