export const COLORS = {
  // Deep Cyber Slate (Telegram / Signal Dark Mode)
  bgDark: '#0B0F19',
  bgCard: '#131C2E',
  bgCardHover: '#1B273F',
  bgElevated: '#1F2937',
  bgInput: '#182235',
  
  // Neon Cyber Accents
  primary: '#10B981',           // Emerald Neon (Signal / WhatsApp Green)
  primaryDark: '#059669',
  primaryLight: '#34D399',
  primaryMuted: 'rgba(16, 185, 129, 0.15)',
  
  secondary: '#6366F1',         // Indigo
  accent: '#06B6D4',            // Cyber Cyan
  
  // Status Colors
  online: '#10B981',
  offline: '#64748B',
  danger: '#EF4444',
  dangerMuted: 'rgba(239, 68, 68, 0.15)',
  warning: '#F59E0B',
  
  // Message Bubbles
  bubbleSent: '#064E3B',        // Deep Emerald
  bubbleReceived: '#1E293B',    // Slate Dark
  bubbleTextSent: '#ECFDF5',
  bubbleTextReceived: '#F8FAFC',
  
  // Text Hierarchy
  textPrimary: '#F8FAFC',
  textSecondary: '#94A3B8',
  textMuted: '#64748B',
  textInverse: '#0B0F19',
  
  // Borders & Dividers
  border: '#1E293B',
  borderLight: '#334155',
  borderFocus: '#10B981',
  
  // Read Receipts
  receiptGrey: '#94A3B8',
  receiptBlue: '#38BDF8',
};

export const SPACING = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 24,
  xxxl: 32,
};

export const RADIUS = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  full: 9999,
};

export const SHADOWS = {
  subtle: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.25,
    shadowRadius: 3.84,
    elevation: 3,
  },
  glow: {
    shadowColor: '#10B981',
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.4,
    shadowRadius: 8,
    elevation: 6,
  },
  card: {
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 6,
    elevation: 4,
  },
};
