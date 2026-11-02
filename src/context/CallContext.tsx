import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import { Contact, CallType, CallRecord, ActiveCallState } from '../types';
import { StorageService } from '../services/storageService';

interface CallContextType {
  activeCall: ActiveCallState | null;
  callHistory: CallRecord[];
  startCall: (peer: Contact, type: CallType) => void;
  acceptIncomingCall: () => void;
  endCall: () => void;
  toggleMute: () => void;
  toggleSpeaker: () => void;
  toggleVideo: () => void;
  flipCamera: () => void;
  simulateIncomingCall: (peer: Contact, type: CallType) => void;
}

const CallContext = createContext<CallContextType>({} as CallContextType);

export const CallProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeCall, setActiveCall] = useState<ActiveCallState | null>(null);
  const [callHistory, setCallHistory] = useState<CallRecord[]>([]);
  const timerRef = useRef<any>(null);

  useEffect(() => {
    loadCallHistory();
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  async function loadCallHistory() {
    const records = await StorageService.getCalls();
    if (records && records.length > 0) {
      setCallHistory(records);
    } else {
      // Starter sample call records
      const initial: CallRecord[] = [
        {
          id: 'c1',
          peerUid: 'user_phantom7',
          peerName: 'Cipher Sentinel',
          peerAvatar: 'https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=150',
          type: 'video',
          direction: 'incoming',
          status: 'connected',
          duration: 142,
          timestamp: new Date(Date.now() - 86400000).toISOString(),
        },
        {
          id: 'c2',
          peerUid: 'user_echo99',
          peerName: 'Echo Chamber',
          peerAvatar: 'https://images.unsplash.com/photo-1570295999919-56ceb5ecca61?w=150',
          type: 'audio',
          direction: 'outgoing',
          status: 'connected',
          duration: 45,
          timestamp: new Date(Date.now() - 172800000).toISOString(),
        },
      ];
      setCallHistory(initial);
      await StorageService.saveCalls(initial);
    }
  }

  function startCall(peer: Contact, type: CallType) {
    if (timerRef.current) clearInterval(timerRef.current);

    const callId = `call_${Date.now()}`;
    const newCall: ActiveCallState = {
      callId,
      peer,
      type,
      direction: 'outgoing',
      status: 'ringing',
      duration: 0,
      isMuted: false,
      isSpeakerOn: true,
      isVideoEnabled: type === 'video',
      isFrontCamera: true,
    };
    setActiveCall(newCall);

    // Simulated WebRTC signaling progression: ringing -> connecting -> connected
    setTimeout(() => {
      setActiveCall(prev => (prev && prev.callId === callId ? { ...prev, status: 'connecting' } : prev));
    }, 1800);

    setTimeout(() => {
      setActiveCall(prev => {
        if (!prev || prev.callId !== callId) return prev;
        startTimer();
        return { ...prev, status: 'connected' };
      });
    }, 3200);
  }

  function simulateIncomingCall(peer: Contact, type: CallType) {
    if (timerRef.current) clearInterval(timerRef.current);

    const callId = `call_in_${Date.now()}`;
    setActiveCall({
      callId,
      peer,
      type,
      direction: 'incoming',
      status: 'ringing',
      duration: 0,
      isMuted: false,
      isSpeakerOn: true,
      isVideoEnabled: type === 'video',
      isFrontCamera: true,
    });
  }

  function acceptIncomingCall() {
    if (!activeCall) return;
    setActiveCall(prev => (prev ? { ...prev, status: 'connecting' } : null));

    setTimeout(() => {
      setActiveCall(prev => {
        if (!prev) return null;
        startTimer();
        return { ...prev, status: 'connected' };
      });
    }, 800);
  }

  function startTimer() {
    if (timerRef.current) clearInterval(timerRef.current);
    timerRef.current = setInterval(() => {
      setActiveCall(prev => {
        if (!prev || prev.status !== 'connected') return prev;
        return { ...prev, duration: prev.duration + 1 };
      });
    }, 1000);
  }

  async function endCall() {
    if (timerRef.current) clearInterval(timerRef.current);

    if (activeCall) {
      const record: CallRecord = {
        id: activeCall.callId,
        peerUid: activeCall.peer.uid,
        peerName: activeCall.peer.displayName,
        peerAvatar: activeCall.peer.avatar,
        type: activeCall.type,
        direction: activeCall.direction,
        status: activeCall.status,
        duration: activeCall.duration,
        timestamp: new Date().toISOString(),
      };

      const updatedHistory = [record, ...callHistory];
      setCallHistory(updatedHistory);
      await StorageService.saveCalls(updatedHistory);
    }

    setActiveCall(null);
  }

  function toggleMute() {
    setActiveCall(prev => (prev ? { ...prev, isMuted: !prev.isMuted } : null));
  }

  function toggleSpeaker() {
    setActiveCall(prev => (prev ? { ...prev, isSpeakerOn: !prev.isSpeakerOn } : null));
  }

  function toggleVideo() {
    setActiveCall(prev => (prev ? { ...prev, isVideoEnabled: !prev.isVideoEnabled } : null));
  }

  function flipCamera() {
    setActiveCall(prev => (prev ? { ...prev, isFrontCamera: !prev.isFrontCamera } : null));
  }

  return (
    <CallContext.Provider
      value={{
        activeCall,
        callHistory,
        startCall,
        acceptIncomingCall,
        endCall,
        toggleMute,
        toggleSpeaker,
        toggleVideo,
        flipCamera,
        simulateIncomingCall,
      }}
    >
      {children}
    </CallContext.Provider>
  );
};

export const useCall = () => useContext(CallContext);
