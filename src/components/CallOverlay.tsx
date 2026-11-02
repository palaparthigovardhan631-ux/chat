import React from 'react';
import { View, Text, StyleSheet, TouchableOpacity, Modal } from 'react-native';
import {
  PhoneOff,
  Phone,
  Mic,
  MicOff,
  Volume2,
  VolumeX,
  Video as VideoIcon,
  VideoOff,
  SwitchCamera,
  ShieldCheck,
} from 'lucide-react-native';
import { COLORS, SPACING, RADIUS } from '../constants/theme';
import { Avatar } from './Avatar';
import { useCall } from '../context/CallContext';

export const CallOverlay: React.FC = () => {
  const {
    activeCall,
    endCall,
    acceptIncomingCall,
    toggleMute,
    toggleSpeaker,
    toggleVideo,
    flipCamera,
  } = useCall();

  if (!activeCall) return null;

  const formatDuration = (sec: number) => {
    const mins = Math.floor(sec / 60);
    const s = sec % 60;
    return `${mins.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  const isIncomingRinging = activeCall.direction === 'incoming' && activeCall.status === 'ringing';

  return (
    <Modal visible={true} transparent={false} animationType="slide">
      <View style={styles.container}>
        {/* Top Bar / WebRTC Status */}
        <View style={styles.topBar}>
          <View style={styles.encryptionBadge}>
            <ShieldCheck size={14} color={COLORS.primary} />
            <Text style={styles.encryptionText}>WebRTC P2P • Zero-Server Hop</Text>
          </View>
        </View>

        {/* Video / Call Canvas */}
        <View style={styles.canvasContainer}>
          {activeCall.type === 'video' && activeCall.isVideoEnabled ? (
            <View style={styles.videoPlaceholder}>
              <View style={styles.videoMeshBackground}>
                <Avatar source={activeCall.peer.avatar} name={activeCall.peer.displayName} size={110} />
                <Text style={styles.videoSimulationText}>
                  {activeCall.status === 'connected'
                    ? '● Live Video Tunnel Active (720p 30fps)'
                    : 'Negotiating ICE Candidates...'}
                </Text>
              </View>

              {/* Self Video PIP Preview */}
              <View style={styles.pipBox}>
                <Text style={styles.pipLabel}>You</Text>
                <Text style={styles.pipStatus}>{activeCall.isFrontCamera ? 'Front Cam' : 'Back Cam'}</Text>
              </View>
            </View>
          ) : (
            <View style={styles.audioCenter}>
              <View style={styles.avatarGlow}>
                <Avatar source={activeCall.peer.avatar} name={activeCall.peer.displayName} size={120} />
              </View>
            </View>
          )}

          {/* Caller Details */}
          <View style={styles.infoBox}>
            <Text style={styles.peerName}>{activeCall.peer.displayName}</Text>
            <Text style={styles.peerHandle}>{activeCall.peer.handle} ({activeCall.peer.uid})</Text>

            <Text style={styles.statusText}>
              {activeCall.status === 'connected'
                ? formatDuration(activeCall.duration)
                : activeCall.status === 'ringing'
                ? activeCall.direction === 'incoming'
                  ? 'Incoming Anonymous Call...'
                  : 'Ringing peer...'
                : 'Connecting peer-to-peer...'}
            </Text>
          </View>
        </View>

        {/* Call Controls */}
        <View style={styles.controlsContainer}>
          {isIncomingRinging ? (
            /* Incoming Call Actions: Accept or Decline */
            <View style={styles.incomingButtonsRow}>
              <TouchableOpacity onPress={endCall} style={[styles.circleBtn, styles.declineBtn]}>
                <PhoneOff size={28} color="#FFF" />
                <Text style={styles.btnLabel}>Decline</Text>
              </TouchableOpacity>

              <TouchableOpacity onPress={acceptIncomingCall} style={[styles.circleBtn, styles.acceptBtn]}>
                <Phone size={28} color="#FFF" />
                <Text style={styles.btnLabel}>Accept</Text>
              </TouchableOpacity>
            </View>
          ) : (
            /* In-Call Controls */
            <View style={styles.inCallControls}>
              {/* Row 1: Toggles */}
              <View style={styles.togglesRow}>
                <TouchableOpacity
                  onPress={toggleMute}
                  style={[styles.smallToggle, activeCall.isMuted && styles.activeToggle]}
                >
                  {activeCall.isMuted ? <MicOff size={22} color="#FFF" /> : <Mic size={22} color="#FFF" />}
                  <Text style={styles.toggleLabel}>{activeCall.isMuted ? 'Muted' : 'Mute'}</Text>
                </TouchableOpacity>

                <TouchableOpacity
                  onPress={toggleSpeaker}
                  style={[styles.smallToggle, activeCall.isSpeakerOn && styles.activeToggle]}
                >
                  {activeCall.isSpeakerOn ? <Volume2 size={22} color="#FFF" /> : <VolumeX size={22} color="#FFF" />}
                  <Text style={styles.toggleLabel}>{activeCall.isSpeakerOn ? 'Speaker' : 'Earpiece'}</Text>
                </TouchableOpacity>

                {activeCall.type === 'video' && (
                  <>
                    <TouchableOpacity
                      onPress={toggleVideo}
                      style={[styles.smallToggle, !activeCall.isVideoEnabled && styles.activeToggle]}
                    >
                      {activeCall.isVideoEnabled ? <VideoIcon size={22} color="#FFF" /> : <VideoOff size={22} color="#FFF" />}
                      <Text style={styles.toggleLabel}>{activeCall.isVideoEnabled ? 'Video' : 'Off'}</Text>
                    </TouchableOpacity>

                    <TouchableOpacity onPress={flipCamera} style={styles.smallToggle}>
                      <SwitchCamera size={22} color="#FFF" />
                      <Text style={styles.toggleLabel}>Flip</Text>
                    </TouchableOpacity>
                  </>
                )}
              </View>

              {/* Row 2: End Call */}
              <TouchableOpacity onPress={endCall} style={[styles.circleBtn, styles.endCallBtn]}>
                <PhoneOff size={30} color="#FFF" />
              </TouchableOpacity>
            </View>
          )}
        </View>
      </View>
    </Modal>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#070A11',
    justifyContent: 'space-between',
    paddingVertical: SPACING.xxl,
    paddingHorizontal: SPACING.lg,
  },
  topBar: {
    alignItems: 'center',
    paddingTop: SPACING.md,
  },
  encryptionBadge: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: RADIUS.full,
    gap: 6,
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.3)',
  },
  encryptionText: {
    color: COLORS.primaryLight,
    fontSize: 12,
    fontWeight: '600',
  },
  canvasContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  audioCenter: {
    alignItems: 'center',
    justifyContent: 'center',
    marginBottom: SPACING.lg,
  },
  avatarGlow: {
    padding: 8,
    borderRadius: 999,
    backgroundColor: 'rgba(16, 185, 129, 0.1)',
    borderWidth: 2,
    borderColor: 'rgba(16, 185, 129, 0.3)',
  },
  videoPlaceholder: {
    width: '100%',
    height: 320,
    backgroundColor: COLORS.bgCard,
    borderRadius: RADIUS.lg,
    overflow: 'hidden',
    position: 'relative',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: SPACING.lg,
    borderWidth: 1,
    borderColor: COLORS.border,
  },
  videoMeshBackground: {
    alignItems: 'center',
    justifyContent: 'center',
  },
  videoSimulationText: {
    color: COLORS.primaryLight,
    fontSize: 13,
    marginTop: 14,
    fontWeight: '500',
  },
  pipBox: {
    position: 'absolute',
    top: 12,
    right: 12,
    width: 85,
    height: 110,
    backgroundColor: '#1E293B',
    borderRadius: RADIUS.sm,
    borderWidth: 1,
    borderColor: COLORS.primary,
    justifyContent: 'center',
    alignItems: 'center',
  },
  pipLabel: {
    color: '#FFF',
    fontSize: 12,
    fontWeight: '700',
  },
  pipStatus: {
    color: COLORS.textMuted,
    fontSize: 10,
    marginTop: 2,
  },
  infoBox: {
    alignItems: 'center',
  },
  peerName: {
    color: '#FFF',
    fontSize: 24,
    fontWeight: '700',
    marginBottom: 4,
  },
  peerHandle: {
    color: COLORS.textSecondary,
    fontSize: 14,
    marginBottom: 12,
  },
  statusText: {
    color: COLORS.primaryLight,
    fontSize: 16,
    fontWeight: '600',
    letterSpacing: 0.5,
  },
  controlsContainer: {
    paddingBottom: SPACING.xl,
  },
  incomingButtonsRow: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    width: '100%',
  },
  declineBtn: {
    backgroundColor: COLORS.danger,
  },
  acceptBtn: {
    backgroundColor: COLORS.primary,
  },
  circleBtn: {
    width: 68,
    height: 68,
    borderRadius: 34,
    justifyContent: 'center',
    alignItems: 'center',
  },
  endCallBtn: {
    backgroundColor: COLORS.danger,
    marginTop: SPACING.lg,
    alignSelf: 'center',
  },
  btnLabel: {
    color: '#FFF',
    fontSize: 12,
    marginTop: 6,
    fontWeight: '600',
  },
  inCallControls: {
    alignItems: 'center',
  },
  togglesRow: {
    flexDirection: 'row',
    justifyContent: 'center',
    gap: 16,
  },
  smallToggle: {
    width: 64,
    height: 64,
    borderRadius: 32,
    backgroundColor: COLORS.bgElevated,
    justifyContent: 'center',
    alignItems: 'center',
  },
  activeToggle: {
    backgroundColor: 'rgba(239, 68, 68, 0.4)',
    borderWidth: 1,
    borderColor: COLORS.danger,
  },
  toggleLabel: {
    color: COLORS.textSecondary,
    fontSize: 10,
    marginTop: 4,
  },
});
