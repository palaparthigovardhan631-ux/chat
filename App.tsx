import React from 'react';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { AuthProvider } from './src/context/AuthContext';
import { ChatProvider } from './src/context/ChatContext';
import { CallProvider } from './src/context/CallContext';
import { RootNavigator } from './src/navigation/RootNavigator';

export default function App() {
  return (
    <SafeAreaProvider>
      <AuthProvider>
        <ChatProvider>
          <CallProvider>
            <StatusBar style="light" backgroundColor="#0B0F19" />
            <RootNavigator />
          </CallProvider>
        </ChatProvider>
      </AuthProvider>
    </SafeAreaProvider>
  );
}
