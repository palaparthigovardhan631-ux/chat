import React from 'react';
import { View, Image, Text, StyleSheet } from 'react-native';
import { COLORS, RADIUS } from '../constants/theme';

interface AvatarProps {
  source?: string;
  name: string;
  size?: number;
  isOnline?: boolean;
  showStatus?: boolean;
}

export const Avatar: React.FC<AvatarProps> = ({
  source,
  name,
  size = 48,
  isOnline = false,
  showStatus = false,
}) => {
  const getInitials = (n: string) => {
    if (!n) return '?';
    const clean = n.replace(/^@|^user_/, '');
    const parts = clean.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return clean.slice(0, 2).toUpperCase();
  };

  const statusSize = Math.max(10, Math.floor(size * 0.28));

  return (
    <View style={[styles.container, { width: size, height: size }]}>
      {source ? (
        <Image
          source={{ uri: source }}
          style={[styles.image, { width: size, height: size, borderRadius: size / 2 }]}
        />
      ) : (
        <View
          style={[
            styles.placeholder,
            { width: size, height: size, borderRadius: size / 2 },
          ]}
        >
          <Text style={[styles.initials, { fontSize: Math.floor(size * 0.4) }]}>
            {getInitials(name)}
          </Text>
        </View>
      )}

      {showStatus && (
        <View
          style={[
            styles.statusBadge,
            {
              width: statusSize,
              height: statusSize,
              borderRadius: statusSize / 2,
              backgroundColor: isOnline ? COLORS.online : COLORS.offline,
              borderWidth: 2,
              borderColor: COLORS.bgDark,
            },
          ]}
        />
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    position: 'relative',
    justifyContent: 'center',
    alignItems: 'center',
  },
  image: {
    backgroundColor: COLORS.bgCardHover,
  },
  placeholder: {
    backgroundColor: COLORS.primaryDark,
    justifyContent: 'center',
    alignItems: 'center',
  },
  initials: {
    color: '#FFF',
    fontWeight: '700',
  },
  statusBadge: {
    position: 'absolute',
    bottom: 0,
    right: 0,
  },
});
