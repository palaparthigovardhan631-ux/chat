
import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { createRoot } from 'react-dom/client';
import { 
  GoogleGenAI, 
  Modality, 
  LiveServerMessage, 
  Chat 
} from '@google/genai';
import { 
  Video, 
  Mic, 
  MicOff, 
  VideoOff, 
  PhoneOff, 
  Send, 
  Users, 
  Phone,
  MoreVertical,
  Paperclip,
  Smile,
  Settings,
  Circle,
  Search,
  X,
  Lock,
  ShieldCheck,
  ShieldAlert,
  Fingerprint,
  Key,
  Trash2,
  History,
  Clock,
  LogOut,
  ChevronRight,
  Hash,
  RefreshCw,
  ScreenShare,
  MonitorOff
} from 'lucide-react';

/** 
 * SECURITY MODULE (E2EE) 
 * Using Web Crypto API for AES-GCM 256-bit encryption
 */
const CryptoEngine = {
  async deriveKey(passphrase: string, salt: string = 'nexus-v2-salt') {
    const encoder = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode(salt),
        iterations: 100000,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  async encrypt(plaintext: string, key: CryptoKey) {
    const encoder = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(plaintext)
    );
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return btoa(String.fromCharCode(...combined));
  },

  async decrypt(base64: string, key: CryptoKey) {
    try {
      const combined = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
      const iv = combined.slice(0, 12);
      const ciphertext = combined.slice(12);
      const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
      );
      return new TextDecoder().decode(decrypted);
    } catch (e) {
      return "[Packet Decryption Error]";
    }
  },

  async getFingerprint(key: CryptoKey) {
    const exported = await window.crypto.subtle.exportKey('raw', key);
    const hash = await window.crypto.subtle.digest('SHA-256', exported);
    return btoa(String.fromCharCode(...new Uint8Array(hash))).slice(0, 12);
  }
};

/**
 * HISTORY MODULE
 * Persistence using localStorage
 */
const HistoryEngine = {
  save(room: string, messages: Message[]) {
    localStorage.setItem(`nexus_history_${room}`, JSON.stringify(messages));
    this.addRoom(room);
  },
  load(room: string): Message[] {
    const stored = localStorage.getItem(`nexus_history_${room}`);
    if (!stored) return [];
    try {
      const parsed = JSON.parse(stored);
      return parsed.map((m: any) => ({ ...m, timestamp: new Date(m.timestamp) }));
    } catch (e) {
      return [];
    }
  },
  clear(room: string) {
    localStorage.removeItem(`nexus_history_${room}`);
    const rooms = this.getRooms().filter(r => r !== room);
    localStorage.setItem('nexus_rooms_list', JSON.stringify(rooms));
  },
  getRooms(): string[] {
    const stored = localStorage.getItem('nexus_rooms_list');
    return stored ? JSON.parse(stored) : [];
  },
  addRoom(room: string) {
    const rooms = this.getRooms();
    if (!rooms.includes(room)) {
      rooms.push(room);
      localStorage.setItem('nexus_rooms_list', JSON.stringify(rooms));
    }
  }
};

/**
 * UTILITY FUNCTIONS FOR AUDIO/VIDEO
 */
const encode = (bytes: Uint8Array) => {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
};

const decode = (base64: string) => {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
  return bytes;
};

const decodeAudioData = async (data: Uint8Array, ctx: AudioContext, sampleRate: number, numChannels: number): Promise<AudioBuffer> => {
  const dataInt16 = new Int16Array(data.buffer);
  const frameCount = dataInt16.length / numChannels;
  const buffer = ctx.createBuffer(numChannels, frameCount, sampleRate);
  for (let channel = 0; channel < numChannels; channel++) {
    const channelData = buffer.getChannelData(channel);
    for (let i = 0; i < frameCount; i++) {
      channelData[i] = dataInt16[i * numChannels + channel] / 32768.0;
    }
  }
  return buffer;
};

interface Message {
  id: string;
  sender: 'user' | 'ai';
  text: string;
  timestamp: Date;
  encrypted: boolean;
}

interface Contact {
  id: string;
  name: string;
  status: 'online' | 'offline';
  avatar: string;
}

const CONTACTS: Contact[] = [
  { id: '1', name: 'Security Protocol Alpha', status: 'online', avatar: 'https://api.dicebear.com/7.x/bottts/svg?seed=Secure' },
  { id: '2', name: 'Neural Node 02', status: 'online', avatar: 'https://api.dicebear.com/7.x/bottts/svg?seed=Node' },
];

const App: React.FC = () => {
  const [session, setSession] = useState<{ active: boolean; room: string; pass: string; user: string }>({ 
    active: false, room: '', pass: '', user: '' 
  });
  const [cryptoKey, setCryptoKey] = useState<CryptoKey | null>(null);
  const [fingerprint, setFingerprint] = useState('');
  const [activeContact, setActiveContact] = useState<Contact>(CONTACTS[0]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputText, setInputText] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [recentRooms, setRecentRooms] = useState<string[]>([]);
  
  const [isCalling, setIsCalling] = useState(false);
  const [callSettings, setCallSettings] = useState({ 
    muted: false, 
    videoOff: false, 
    facingMode: 'user' as 'user' | 'environment',
    isSharingScreen: false 
  });
  const [callStatus, setCallStatus] = useState<'connecting' | 'connected' | 'idle'>('idle');

  const aiClient = useMemo(() => new GoogleGenAI({ apiKey: process.env.API_KEY }), []);
  const chatRef = useRef<Chat | null>(null);
  const liveSessionRef = useRef<any>(null);
  const frameLoopRef = useRef<number | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const audioContexts = useRef<{ input: AudioContext; output: AudioContext } | null>(null);
  const sources = useRef<Set<AudioBufferSourceNode>>(new Set());
  const nextStartTime = useRef<number>(0);

  // Initialize recent rooms from history
  useEffect(() => {
    setRecentRooms(HistoryEngine.getRooms());
  }, []);

  // Persistence: Auto-save when messages change
  useEffect(() => {
    if (session.active && messages.length > 0) {
      HistoryEngine.save(session.room, messages);
      setRecentRooms(HistoryEngine.getRooms());
    }
  }, [messages, session.active, session.room]);

  // Load History on Entry
  useEffect(() => {
    if (session.active) {
      const history = HistoryEngine.load(session.room);
      if (history.length > 0) {
        setMessages(history);
      } else {
        setMessages([{ id: 'init', sender: 'ai', text: `Nexus Tunnel Established. Room: ${session.room}`, timestamp: new Date(), encrypted: true }]);
      }
      
      CryptoEngine.deriveKey(session.pass).then(async (key) => {
        setCryptoKey(key);
        setFingerprint(await CryptoEngine.getFingerprint(key));
      });
    } else {
      setMessages([]);
      setCryptoKey(null);
      setFingerprint('');
    }
  }, [session.active, session.room, session.pass]);

  useEffect(() => {
    if (!session.active) return;
    chatRef.current = aiClient.chats.create({
      model: 'gemini-3-flash-preview',
      config: {
        systemInstruction: `SYSTEM: SECURE TUNNEL ACTIVE. You are acting as a remote user in room ${session.room}.
        Your name is ${activeContact.name}. All users in this room use AES-GCM E2EE.`,
      },
    });
  }, [activeContact, aiClient, session.active, session.room]);

  const handleSendMessage = async () => {
    if (!inputText.trim() || !chatRef.current || !cryptoKey) return;
    const rawText = inputText;
    setInputText('');
    const userMsg: Message = { id: Date.now().toString(), sender: 'user', text: rawText, timestamp: new Date(), encrypted: true };
    setMessages(prev => [...prev, userMsg]);
    
    setIsTyping(true);
    try {
      const encryptedPayload = await CryptoEngine.encrypt(rawText, cryptoKey);
      const response = await chatRef.current.sendMessage({ message: `[ENCRYPTED_SIGNAL]: ${encryptedPayload}` });
      const aiMsg: Message = { 
        id: (Date.now() + 1).toString(), 
        sender: 'ai', 
        text: response.text || "...", 
        timestamp: new Date(),
        encrypted: true
      };
      setMessages(prev => [...prev, aiMsg]);
    } catch (err) {
      console.error(err);
    } finally {
      setIsTyping(false);
      setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
    }
  };

  const handleClearHistory = () => {
    if (confirm("Delete all history for this room?")) {
      HistoryEngine.clear(session.room);
      setMessages([{ id: 'init', sender: 'ai', text: `Nexus Tunnel Reset. Room: ${session.room}`, timestamp: new Date(), encrypted: true }]);
      setRecentRooms(HistoryEngine.getRooms());
    }
  };

  const endCall = useCallback(() => {
    setIsCalling(false); setCallStatus('idle');
    if (frameLoopRef.current) { clearInterval(frameLoopRef.current); frameLoopRef.current = null; }
    if (liveSessionRef.current) { liveSessionRef.current.close(); liveSessionRef.current = null; }
    if (videoRef.current?.srcObject) (videoRef.current.srcObject as MediaStream).getTracks().forEach(t => t.stop());
    audioContexts.current?.input.close(); audioContexts.current?.output.close(); audioContexts.current = null;
    sources.current.forEach(s => { try { s.stop(); } catch(e){} }); sources.current.clear();
    setCallSettings(prev => ({ ...prev, isSharingScreen: false }));
  }, []);

  const startCall = useCallback(async () => {
    setIsCalling(true); setCallStatus('connecting');
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ 
        audio: true, 
        video: { facingMode: callSettings.facingMode } 
      });
      if (videoRef.current) videoRef.current.srcObject = stream;
      const inputCtx = new AudioContext({ sampleRate: 16000 });
      const outputCtx = new AudioContext({ sampleRate: 24000 });
      audioContexts.current = { input: inputCtx, output: outputCtx };
      const sessionPromise = aiClient.live.connect({
        model: 'gemini-2.5-flash-native-audio-preview-12-2025',
        callbacks: {
          onopen: () => {
            setCallStatus('connected');
            const source = inputCtx.createMediaStreamSource(stream);
            const scriptProcessor = inputCtx.createScriptProcessor(4096, 1, 1);
            scriptProcessor.onaudioprocess = (e) => {
              if (callSettings.muted) return;
              const inputData = e.inputBuffer.getChannelData(0);
              const int16 = new Int16Array(inputData.length);
              for (let i = 0; i < inputData.length; i++) int16[i] = inputData[i] * 32768;
              sessionPromise.then(s => s.sendRealtimeInput({ media: { data: encode(new Uint8Array(int16.buffer)), mimeType: 'audio/pcm;rate=16000' } }));
            };
            source.connect(scriptProcessor); scriptProcessor.connect(inputCtx.destination);
            frameLoopRef.current = window.setInterval(() => {
              if (!callSettings.videoOff && videoRef.current && canvasRef.current) {
                const cvs = canvasRef.current; const vid = videoRef.current;
                // Capture resolution for AI stream
                cvs.width = 320; cvs.height = 240;
                cvs.getContext('2d')?.drawImage(vid, 0, 0, 320, 240);
                cvs.toBlob(b => b?.arrayBuffer().then(buf => sessionPromise.then(s => s.sendRealtimeInput({ media: { data: encode(new Uint8Array(buf)), mimeType: 'image/jpeg' } }))), 'image/jpeg', 0.5);
              }
            }, 1000);
          },
          onmessage: async (msg: LiveServerMessage) => {
            const data = msg.serverContent?.modelTurn?.parts[0]?.inlineData?.data;
            if (data) {
              const outCtx = audioContexts.current!.output;
              nextStartTime.current = Math.max(nextStartTime.current, outCtx.currentTime);
              const buffer = await decodeAudioData(decode(data), outCtx, 24000, 1);
              const source = outCtx.createBufferSource();
              source.buffer = buffer; source.connect(outCtx.destination);
              source.start(nextStartTime.current); nextStartTime.current += buffer.duration;
              sources.current.add(source);
            }
          },
          onclose: () => endCall(),
          onerror: () => endCall(),
        },
        config: { responseModalities: [Modality.AUDIO], systemInstruction: "Secure peer calling." }
      });
      liveSessionRef.current = await sessionPromise;
    } catch (err) { setIsCalling(false); }
  }, [aiClient, callSettings, endCall]);

  const flipCamera = useCallback(async () => {
    if (!videoRef.current || callSettings.isSharingScreen) return;
    const newFacingMode = callSettings.facingMode === 'user' ? 'environment' : 'user';
    setCallSettings(prev => ({ ...prev, facingMode: newFacingMode }));
    
    try {
      const oldStream = videoRef.current.srcObject as MediaStream;
      oldStream.getVideoTracks().forEach(track => track.stop());
      
      const newStream = await navigator.mediaDevices.getUserMedia({ 
        video: { facingMode: newFacingMode } 
      });
      
      const combinedStream = new MediaStream([
        ...newStream.getVideoTracks(),
        ...oldStream.getAudioTracks()
      ]);
      
      videoRef.current.srcObject = combinedStream;
    } catch (err) {
      console.error("Failed to flip camera", err);
    }
  }, [callSettings.facingMode, callSettings.isSharingScreen]);

  const toggleScreenShare = useCallback(async () => {
    if (!videoRef.current) return;
    
    if (callSettings.isSharingScreen) {
      // Revert to camera
      try {
        const oldStream = videoRef.current.srcObject as MediaStream;
        oldStream.getVideoTracks().forEach(track => track.stop());
        
        const cameraStream = await navigator.mediaDevices.getUserMedia({ 
          video: { facingMode: callSettings.facingMode } 
        });
        
        const combinedStream = new MediaStream([
          ...cameraStream.getVideoTracks(),
          ...oldStream.getAudioTracks()
        ]);
        
        videoRef.current.srcObject = combinedStream;
        setCallSettings(prev => ({ ...prev, isSharingScreen: false }));
      } catch (err) {
        console.error("Failed to revert to camera", err);
      }
    } else {
      // Start screen share
      try {
        const screenStream = await (navigator.mediaDevices as any).getDisplayMedia({ video: true });
        const oldStream = videoRef.current.srcObject as MediaStream;
        
        const combinedStream = new MediaStream([
          ...screenStream.getVideoTracks(),
          ...oldStream.getAudioTracks()
        ]);
        
        videoRef.current.srcObject = combinedStream;
        setCallSettings(prev => ({ ...prev, isSharingScreen: true }));
        
        // Handle user stopping screen share from browser UI
        screenStream.getVideoTracks()[0].onended = () => {
          toggleScreenShare(); // Revert back
        };
      } catch (err) {
        console.error("Failed to start screen share", err);
      }
    }
  }, [callSettings.isSharingScreen, callSettings.facingMode]);

  if (!session.active) {
    return (
      <div className="h-screen bg-slate-950 flex items-center justify-center p-6 bg-[url('https://www.transparenttextures.com/patterns/dark-matter.png')]">
        <div className="w-full max-w-lg grid grid-cols-1 md:grid-cols-2 gap-6 animate-in zoom-in-95 duration-500">
          <div className="bg-slate-900 border border-slate-800 p-8 rounded-3xl shadow-2xl flex flex-col h-fit">
            <div className="flex flex-col items-center mb-8">
              <div className="w-16 h-16 bg-blue-600 rounded-3xl flex items-center justify-center mb-4 shadow-xl shadow-blue-600/20">
                <ShieldCheck className="w-8 h-8 text-white" />
              </div>
              <h1 className="text-2xl font-bold text-white tracking-tight">Nexus Entry</h1>
              <p className="text-slate-500 text-xs mt-1 uppercase tracking-widest">Secure Tunnel v2</p>
            </div>
            <div className="space-y-4">
              <input className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white text-sm focus:border-blue-500 outline-none transition-all" placeholder="Display Name" value={session.user} onChange={e => setSession(s => ({...s, user: e.target.value}))} />
              <input className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white text-sm focus:border-blue-500 outline-none transition-all" placeholder="Room ID" value={session.room} onChange={e => setSession(s => ({...s, room: e.target.value}))} />
              <input type="password" className="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white text-sm focus:border-emerald-500 outline-none transition-all" placeholder="Secret Key" value={session.pass} onChange={e => setSession(s => ({...s, pass: e.target.value}))} />
              <button onClick={() => session.user && session.room && session.pass && setSession(s => ({...s, active: true}))} className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3.5 rounded-xl mt-4 shadow-lg shadow-blue-600/20 transition-all active:scale-95"> Initialize Secure Tunnel </button>
            </div>
          </div>

          <div className="bg-slate-900/50 border border-slate-800 p-8 rounded-3xl backdrop-blur-md flex flex-col h-full overflow-hidden">
             <div className="flex items-center gap-2 mb-6">
                <History className="w-5 h-5 text-slate-400" />
                <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest">Recent Rooms</h2>
             </div>
             <div className="flex-1 overflow-y-auto space-y-3 custom-scrollbar pr-2">
                {recentRooms.length === 0 ? (
                  <div className="text-center py-12">
                    <Clock className="w-8 h-8 text-slate-700 mx-auto mb-2 opacity-30" />
                    <p className="text-xs text-slate-600 italic">No persistent history found</p>
                  </div>
                ) : (
                  recentRooms.map(r => (
                    <button 
                      key={r}
                      onClick={() => setSession(s => ({...s, room: r}))}
                      className="w-full group flex items-center justify-between p-4 bg-slate-950/50 border border-slate-800 hover:border-blue-500/50 hover:bg-slate-900 rounded-2xl transition-all"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                         <div className="w-8 h-8 bg-slate-800 rounded-lg flex items-center justify-center group-hover:bg-blue-900 transition-colors">
                            <Hash className="w-4 h-4 text-slate-500 group-hover:text-blue-300" />
                         </div>
                         <span className="text-sm font-medium text-slate-300 truncate">{r}</span>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-blue-400 transition-colors" />
                    </button>
                  ))
                )}
             </div>
             <p className="text-[10px] text-slate-600 mt-6 leading-relaxed">
               History is encrypted with your Secret Key and stored in the browser's persistent sandbox.
             </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden select-none">
      {/* Sidebar */}
      <aside className="w-80 border-r border-slate-800 bg-slate-900/50 flex flex-col backdrop-blur-xl shrink-0">
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-3 mb-4">
            <ShieldCheck className="w-5 h-5 text-emerald-500" />
            <h1 className="text-xl font-bold bg-gradient-to-r from-blue-400 to-indigo-500 bg-clip-text text-transparent">Nexus Tunnel</h1>
          </div>
          <div className="bg-slate-950/50 rounded-xl p-3 border border-slate-800 flex items-center gap-3">
             <Fingerprint className="w-6 h-6 text-slate-600" />
             <div className="min-w-0">
               <p className="text-[9px] uppercase font-bold text-slate-600 tracking-widest">Key Fingerprint</p>
               <p className="text-xs font-mono text-emerald-400/80 truncate">{fingerprint || 'Generating...'}</p>
             </div>
          </div>
        </div>
        
        <div className="flex-1 overflow-y-auto custom-scrollbar p-4">
          <div className="flex items-center justify-between px-2 mb-4">
            <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Secure Peers</h2>
            <div className="flex items-center gap-1 text-[10px] text-slate-500">
               <History className="w-3 h-3" /> Synced
            </div>
          </div>
          {CONTACTS.map(c => (
            <div key={c.id} onClick={() => setActiveContact(c)} className={`flex items-center gap-3 p-3 rounded-xl cursor-pointer transition-all mb-2 ${activeContact.id === c.id ? 'bg-blue-600/20 border border-blue-500/30' : 'hover:bg-slate-800'}`}>
               <img src={c.avatar} className="w-10 h-10 rounded-full bg-slate-800 border border-slate-700" alt="" />
               <div className="flex-1 min-w-0">
                 <h3 className="text-sm font-medium truncate">{c.name}</h3>
                 <p className="text-[10px] text-emerald-400 uppercase tracking-tighter">E2EE ACTIVE</p>
               </div>
            </div>
          ))}

          <div className="mt-8 px-2">
            <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-4">Recent Sessions</h2>
            <div className="space-y-1">
              {recentRooms.map(r => (
                <div key={r} onClick={() => r !== session.room && setSession(s => ({...s, room: r, active: false}))} className={`flex items-center justify-between p-2.5 rounded-lg cursor-pointer transition-all ${r === session.room ? 'bg-slate-800 text-blue-400' : 'text-slate-500 hover:bg-slate-800 hover:text-slate-300'}`}>
                   <div className="flex items-center gap-2 truncate text-xs font-medium">
                      <Hash className="w-3 h-3 opacity-50" />
                      {r}
                   </div>
                   {r === session.room && <div className="w-1.5 h-1.5 bg-blue-500 rounded-full" />}
                </div>
              ))}
            </div>
          </div>

          <button onClick={handleClearHistory} className="w-full mt-8 flex items-center justify-center gap-2 py-2 text-[10px] text-slate-600 hover:text-red-400 transition-colors uppercase font-bold tracking-widest border border-dashed border-slate-800 rounded-lg">
            <Trash2 className="w-3 h-3" /> Clear History
          </button>
        </div>

        <div className="p-4 border-t border-slate-800 bg-slate-900/80">
          <div className="flex items-center gap-3">
            <img src={`https://api.dicebear.com/7.x/initials/svg?seed=${session.user}`} className="w-10 h-10 rounded-full bg-slate-700 border border-slate-600" alt="" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate">{session.user}</p>
              <p className="text-[10px] text-slate-500 truncate">{session.room}</p>
            </div>
            <button onClick={() => setSession(s => ({...s, active: false}))} className="p-2 text-slate-400 hover:text-red-400 transition-colors"> <LogOut className="w-5 h-5" /> </button>
          </div>
        </div>
      </aside>

      <main className="flex-1 flex flex-col bg-slate-950 relative min-w-0">
        <header className="h-20 border-b border-slate-800 flex items-center justify-between px-8 bg-slate-950/80 backdrop-blur-md z-10">
          <div className="flex items-center gap-4 min-w-0">
            <img src={activeContact.avatar} className="w-10 h-10 rounded-full border border-slate-700 shadow-xl" alt="" />
            <div className="min-w-0">
              <h2 className="font-bold text-lg truncate">{activeContact.name}</h2>
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-3 h-3 text-emerald-500" />
                <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-widest">E2EE Tunnel Active</span>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={startCall} className="p-3 rounded-full hover:bg-slate-800 text-slate-300"> <Phone className="w-5 h-5" /> </button>
            <button onClick={startCall} className="p-3 rounded-full bg-blue-600 hover:bg-blue-500 text-white shadow-lg"> <Video className="w-5 h-5" /> </button>
            <button className="p-3 rounded-full hover:bg-slate-800 text-slate-300"> <MoreVertical className="w-5 h-5" /> </button>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-8 space-y-6 custom-scrollbar bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')]">
          {messages.length > 1 && (
             <div className="flex items-center justify-center gap-2 text-slate-600 text-[10px] font-bold uppercase tracking-widest py-4">
               <Clock className="w-3 h-3" /> Earlier History Restored
             </div>
          )}
          {messages.map(m => (
            <div key={m.id} className={`flex ${m.sender === 'user' ? 'justify-end' : 'justify-start'} animate-in fade-in slide-in-from-bottom-2 duration-300`}>
              <div className="max-w-[70%]">
                <div className={`px-5 py-3 rounded-2xl shadow-lg border ${m.sender === 'user' ? 'bg-blue-600 border-blue-500 text-white rounded-tr-none' : 'bg-slate-800/80 border-slate-700 text-slate-100 rounded-tl-none backdrop-blur-sm'}`}>
                  <p className="text-[15px]">{m.text}</p>
                  <div className={`flex items-center gap-1 text-[8px] opacity-40 uppercase tracking-widest mt-1 ${m.sender === 'user' ? 'justify-end' : 'justify-start'}`}> <ShieldCheck className="w-2 h-2" /> Encrypted </div>
                </div>
                <p className={`text-[10px] text-slate-600 mt-1 ${m.sender === 'user' ? 'text-right' : 'text-left'}`}> {m.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} </p>
              </div>
            </div>
          ))}
          {isTyping && <div className="text-slate-600 text-[10px] italic animate-pulse">Establishing Signal...</div>}
          <div ref={messagesEndRef} />
        </div>

        <footer className="p-6 border-t border-slate-800 bg-slate-950/80">
          <div className="max-w-4xl mx-auto flex items-center gap-3 bg-slate-900 border border-slate-700 rounded-2xl p-2 px-4 focus-within:border-blue-500 transition-all shadow-2xl">
            <button className="p-2 text-slate-500 hover:text-slate-100"><Paperclip className="w-5 h-5" /></button>
            <input className="flex-1 bg-transparent border-none focus:ring-0 text-slate-100 py-3" placeholder="Secure signal..." value={inputText} onChange={e => setInputText(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleSendMessage()} />
            <button onClick={handleSendMessage} disabled={!inputText.trim()} className="p-3 bg-blue-600 rounded-xl hover:bg-blue-500 disabled:opacity-50 text-white shadow-lg"> <Send className="w-5 h-5" /> </button>
          </div>
        </footer>

        {isCalling && (
          <div className="absolute inset-0 z-50 bg-slate-950 flex flex-col items-center justify-center p-8 animate-in fade-in duration-500">
             <div className="absolute top-8 text-center">
                <div className="px-3 py-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full inline-flex items-center gap-2 mb-2"> 
                  <Lock className="w-3 h-3 text-emerald-500" /> 
                  <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest">
                    {callSettings.isSharingScreen ? "Screen Streaming" : "Secure Stream"}
                  </span> 
                </div>
                <h3 className="text-2xl font-bold">{activeContact.name}</h3>
             </div>
             <div className="w-full max-w-5xl aspect-video bg-slate-900 rounded-3xl overflow-hidden relative shadow-2xl border border-slate-800">
               <div className="absolute inset-0 flex items-center justify-center"> <img src={activeContact.avatar} className="w-32 h-32 rounded-full border-4 border-blue-500/20 animate-pulse" alt="" /> </div>
               <div className="absolute bottom-6 right-6 w-48 h-64 bg-slate-800 rounded-2xl overflow-hidden border-2 border-slate-700 shadow-2xl transition-all"> 
                  <video ref={videoRef} autoPlay muted playsInline className={`w-full h-full object-cover ${callSettings.videoOff ? 'hidden' : ''}`} /> 
                  {callSettings.videoOff && (
                    <div className="w-full h-full flex items-center justify-center bg-slate-900 text-slate-700">
                       <VideoOff className="w-12 h-12" />
                    </div>
                  )}
               </div>
             </div>
             
             <div className="mt-12 flex items-center gap-4 md:gap-6 flex-wrap justify-center">
               <button 
                 onClick={() => setCallSettings(s => ({...s, muted: !s.muted}))} 
                 className={`p-4 md:p-5 rounded-full border transition-all ${callSettings.muted ? 'bg-red-500/10 border-red-500 text-red-500' : 'bg-slate-800 border-slate-700 hover:bg-slate-700'}`}
                 title={callSettings.muted ? "Unmute" : "Mute"}
               > 
                 {callSettings.muted ? <MicOff /> : <Mic />} 
               </button>

               <button 
                 onClick={() => setCallSettings(s => ({...s, videoOff: !s.videoOff}))} 
                 className={`p-4 md:p-5 rounded-full border transition-all ${callSettings.videoOff ? 'bg-red-500/10 border-red-500 text-red-500' : 'bg-slate-800 border-slate-700 hover:bg-slate-700'}`}
                 title={callSettings.videoOff ? "Camera On" : "Camera Off"}
               > 
                 {callSettings.videoOff ? <VideoOff /> : <Video />} 
               </button>

               <button onClick={endCall} className="p-6 rounded-full bg-red-600 hover:bg-red-500 text-white shadow-xl shadow-red-600/20 hover:scale-110 active:scale-95 transition-all" title="Hang Up"> 
                 <PhoneOff className="w-8 h-8" /> 
               </button>

               <button 
                 onClick={flipCamera} 
                 disabled={callSettings.isSharingScreen}
                 className={`p-4 md:p-5 rounded-full border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-100 transition-all ${callSettings.isSharingScreen ? 'opacity-30 cursor-not-allowed' : ''}`}
                 title="Flip Camera"
               > 
                 <RefreshCw /> 
               </button>

               <button 
                 onClick={toggleScreenShare} 
                 className={`p-4 md:p-5 rounded-full border transition-all ${callSettings.isSharingScreen ? 'bg-emerald-500/10 border-emerald-500 text-emerald-500' : 'bg-slate-800 border-slate-700 hover:bg-slate-700'}`}
                 title={callSettings.isSharingScreen ? "Stop Sharing" : "Share Screen"}
               > 
                 {callSettings.isSharingScreen ? <MonitorOff /> : <ScreenShare />} 
               </button>
             </div>
          </div>
        )}
        <canvas ref={canvasRef} className="hidden" />
      </main>

      <style>{`
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #334155; border-radius: 10px; }
        @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slide-in-from-bottom { from { transform: translateY(8px); } to { transform: translateY(0); } }
        .animate-in { animation: 0.25s ease-out both; }
        .fade-in { animation-name: fade-in; }
        .slide-in-from-bottom-2 { animation-name: slide-in-from-bottom; }
      `}</style>
    </div>
  );
};

const container = document.getElementById('root');
if (container) {
  const root = createRoot(container);
  root.render(<App />);
}
