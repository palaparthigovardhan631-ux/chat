import React from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { Check, CheckCheck, Clock } from 'lucide-react-native';
import { COLORS } from '../constants/theme';
import { MessageStatus } from '../types';

interface ReadReceiptProps {
  status: MessageStatus;
  size?: number;
}

export const ReadReceipt: React.FC<ReadReceiptProps> = ({ status, size = 14 }) => {
  switch (status) {
    case 'sending':
      return <Clock size={size} color={COLORS.receiptGrey} />;
    case 'sent':
      return <Check size={size} color={COLORS.receiptGrey} strokeWidth={2.5} />;
    case 'delivered':
      return <CheckCheck size={size + 2} color={COLORS.receiptGrey} strokeWidth={2.5} />;
    case 'read':
      return <CheckCheck size={size + 2} color={COLORS.receiptBlue} strokeWidth={2.5} />;
    default:
      return null;
  }
};

interface UnreadBadgeProps {
  count: number;
}

export const UnreadBadge: React.FC<UnreadBadgeProps> = ({ count }) => {
  if (count <= 0) return null;
  return (
    <View style={styles.badge}>
      <Text style={styles.badgeText}>{count > 99 ? '99+' : count}</Text>
    </View>
  );
};

const styles = StyleSheet.create({
  badge: {
    backgroundColor: COLORS.primary,
    borderRadius: 12,
    minWidth: 20,
    height: 20,
    justifyContent: 'center',
    alignItems: 'center',
    paddingHorizontal: 6,
  },
  badgeText: {
    color: COLORS.textInverse,
    fontSize: 11,
    fontWeight: '700',
  },
});
