"use client";

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./card";
import { Button } from "./button";
import { Input } from "./input";
import { Plus, Key, Trash2, Copy, Check, Download, Upload, Eye, EyeOff, AlertCircle } from 'lucide-react';
import { Alert, AlertDescription } from "./alert";
import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { sha512 } from '@noble/hashes/sha512';

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

interface KeyPair {
  id: number;
  publicKey: string;
  privateKey: string;
  createdAt: string;
  name: string;
  lastUsed?: string;
  description?: string;
}

interface SignedMessage {
  message: string;
  signature: string;
  timestamp: string;
  keyId: number;
}

const KeyManagementTool = () => {
  const [keys, setKeys] = useState<KeyPair[]>([]);
  const [selectedKeyIndex, setSelectedKeyIndex] = useState<number | null>(null);
  const [message, setMessage] = useState<string>('');
  const [signature, setSignature] = useState<string>('');
  const [copied, setCopied] = useState<boolean>(false);
  const [showPrivateKey, setShowPrivateKey] = useState<boolean>(false);
  const [keyName, setKeyName] = useState<string>('');
  const [keyDescription, setKeyDescription] = useState<string>('');
  const [signedMessages, setSignedMessages] = useState<SignedMessage[]>([]);
  const [verifyMessage, setVerifyMessage] = useState<string>('');
  const [verifySignature, setVerifySignature] = useState<string>('');
  const [verificationResult, setVerificationResult] = useState<boolean | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [showBackupReminder, setShowBackupReminder] = useState<boolean>(false);

  // Load keys from localStorage
  useEffect(() => {
    try {
      const savedKeys = localStorage.getItem('amaci-keys');
      if (savedKeys) {
        setKeys(JSON.parse(savedKeys));
      }
      
      // Check if backup reminder should be shown
      const lastBackup = localStorage.getItem('last-backup-date');
      if (!lastBackup || Date.now() - new Date(lastBackup).getTime() > 7 * 24 * 60 * 60 * 1000) {
        setShowBackupReminder(true);
      }
    } catch (err) {
      console.error('Failed to load keys:', err);
      setError('Failed to load saved keys');
    }
  }, []);

  // Save keys to localStorage
  useEffect(() => {
    try {
      localStorage.setItem('amaci-keys', JSON.stringify(keys));
    } catch (err) {
      console.error('Failed to save keys:', err);
      setError('Failed to save keys');
    }
  }, [keys]);

  const deleteKeyPair = (index: number) => {
    try {
      const newKeys = [...keys];
      newKeys.splice(index, 1);
      setKeys(newKeys);
      
      // Reset selected key if we're deleting it
      if (selectedKeyIndex === index) {
        setSelectedKeyIndex(null);
        setSignature('');
        setMessage('');
        setVerifyMessage('');
        setVerifySignature('');
        setVerificationResult(null);
      }
      // Adjust selectedKeyIndex if we're deleting a key before it
      else if (selectedKeyIndex !== null && index < selectedKeyIndex) {
        setSelectedKeyIndex(selectedKeyIndex - 1);
      }
      
      setError(null);
    } catch (err) {
      console.error('Failed to delete keypair:', err);
      setError('Failed to delete keypair');
    }
  };

  const generateNewKeyPair = async () => {
    if (!keyName.trim()) {
      setError('Please provide a name for the key');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      // Generate key pair using EdDSA
      const privateBytes = randomBytes(32);
      const privateKey = bytesToHex(privateBytes);
      const publicKeyBytes = await ed.getPublicKey(privateBytes);
      const publicKey = bytesToHex(publicKeyBytes);
      
      const newKeyPair: KeyPair = {
        id: Date.now(),
        publicKey,
        privateKey,
        createdAt: new Date().toISOString(),
        lastUsed: new Date().toISOString(),
        name: keyName.trim(),
        description: keyDescription.trim() || undefined,
      };
      
      setKeys(prevKeys => [...prevKeys, newKeyPair]);
      setKeyName('');
      setKeyDescription('');
      
      // Show backup reminder
      setShowBackupReminder(true);
    } catch (err) {
      console.error('Failed to generate keypair:', err);
      setError('Failed to generate new keypair');
    } finally {
      setLoading(false);
    }
  };

  const backupKeys = () => {
    try {
      const keyData = JSON.stringify(keys, null, 2);
      const blob = new Blob([keyData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `amaci-keys-backup-${new Date().toISOString()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      // Update last backup date
      localStorage.setItem('last-backup-date', new Date().toISOString());
      setShowBackupReminder(false);
    } catch (err) {
      console.error('Failed to backup keys:', err);
      setError('Failed to backup keys');
    }
  };

  const restoreBackup = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const backupData = JSON.parse(e.target?.result as string);
        
        if (!Array.isArray(backupData)) {
          throw new Error('Invalid backup file format');
        }

        // Validate each key pair
        for (const keyPair of backupData) {
          if (!keyPair.publicKey || !keyPair.privateKey) {
            throw new Error('Invalid key pair in backup');
          }

          const privateBytes = hexToBytes(keyPair.privateKey);
          const derivedPublicKey = bytesToHex(await ed.getPublicKey(privateBytes));
          
          if (derivedPublicKey !== keyPair.publicKey) {
            throw new Error('Invalid key pair detected');
          }
        }

        setKeys(backupData);
        setError(null);
      } catch (err) {
        console.error('Failed to restore backup:', err);
        setError('Failed to restore backup: Invalid or corrupted backup file');
      }
    };
    reader.readAsText(file);
  };

  const exportKey = (keyPair: KeyPair) => {
    try {
      const keyData = JSON.stringify(keyPair, null, 2);
      const blob = new Blob([keyData], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${keyPair.name.replace(/\s+/g, '-')}-${keyPair.id}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export key:', err);
      setError('Failed to export key');
    }
  };

  const importKey = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const keyPair = JSON.parse(e.target?.result as string);
        
        if (!keyPair.publicKey || !keyPair.privateKey) {
          throw new Error('Invalid key file format');
        }

        // Validate the key pair
        const privateBytes = hexToBytes(keyPair.privateKey);
        const derivedPublicKey = bytesToHex(await ed.getPublicKey(privateBytes));
        
        if (derivedPublicKey !== keyPair.publicKey) {
          throw new Error('Invalid key pair');
        }

        // Check for duplicates
        if (keys.some(k => k.publicKey === keyPair.publicKey)) {
          throw new Error('Key pair already exists');
        }

        setKeys(prevKeys => [...prevKeys, {
          ...keyPair,
          id: Date.now(),
          createdAt: new Date().toISOString(),
          lastUsed: new Date().toISOString()
        }]);
        
        setError(null);
      } catch (err) {
        console.error('Failed to import key:', err);
  setError(`Failed to import key: ${(err as Error).message}`);
      }
    };
    reader.readAsText(file);
  };

  const signMessage = async () => {
    if (selectedKeyIndex === null || !message.trim()) return;

    try {
      setLoading(true);
      setError(null);
      
      const keyPair = keys[selectedKeyIndex];
      const messageBytes = new TextEncoder().encode(message);
      const privateBytes = hexToBytes(keyPair.privateKey);
      const signatureBytes = await ed.sign(messageBytes, privateBytes);
      const signature = bytesToHex(signatureBytes);

      const signedMessage: SignedMessage = {
        message,
        signature,
        timestamp: new Date().toISOString(),
        keyId: keyPair.id,
      };

      setSignedMessages(prev => [...prev, signedMessage]);
      setSignature(signature);
      setMessage('');

      // Update last used timestamp
      const updatedKeys = [...keys];
      updatedKeys[selectedKeyIndex] = {
        ...keyPair,
        lastUsed: new Date().toISOString()
      };
      setKeys(updatedKeys);
    } catch (err) {
      console.error('Failed to sign message:', err);
      setError('Failed to sign message');
    } finally {
      setLoading(false);
    }
  };

  const verifyMessageSignature = async () => {
    if (!verifyMessage.trim() || !verifySignature.trim() || selectedKeyIndex === null) return;

    try {
      setLoading(true);
      setError(null);

      const messageBytes = new TextEncoder().encode(verifyMessage);
      const signatureBytes = hexToBytes(verifySignature);
      const publicKeyBytes = hexToBytes(keys[selectedKeyIndex].publicKey);

      const isValid = await ed.verify(signatureBytes, messageBytes, publicKeyBytes);
      setVerificationResult(isValid);
    } catch (err) {
      console.error('Failed to verify signature:', err);
      setError('Failed to verify signature: Invalid format');
      setVerificationResult(false);
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
      setError('Failed to copy to clipboard');
    }
  };

  const filteredKeys = keys.filter(key => 
    key.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    key.publicKey.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="max-w-4xl mx-auto p-4 space-y-4">
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
  
      {showBackupReminder && (
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertDescription className="flex items-center justify-between">
            <span>Don't forget to backup your keys!</span>
            <Button variant="outline" size="sm" onClick={backupKeys}>
              Backup Now
            </Button>
          </AlertDescription>
        </Alert>
      )}
      
      <Card className="w-full">
        <CardHeader>
          <CardTitle>A-MACI Key Management</CardTitle>
          <CardDescription>
            Securely manage your EdDSA keypairs for A-MACI voting system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Key Management Tools */}
            <div className="flex flex-wrap gap-4">
              <div className="flex-1 min-w-[200px]">
                <Input
                  placeholder="Key name (required)"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                />
              </div>
              <div className="flex-1 min-w-[200px]">
                <Input
                  placeholder="Key description (optional)"
                  value={keyDescription}
                  onChange={(e) => setKeyDescription(e.target.value)}
                />
              </div>
              <Button
                onClick={generateNewKeyPair}
                disabled={loading || !keyName.trim()}
                className="flex items-center gap-2"
              >
                <Plus size={16} />
                Generate New Keypair
              </Button>
            </div>
  
            <div className="flex gap-4">
              <Button variant="outline" onClick={backupKeys} disabled={loading || keys.length === 0}>
                <Download size={16} className="mr-2" />
                Backup All Keys
              </Button>
              <label className="flex">
                <input
                  type="file"
                  onChange={restoreBackup}
                  className="hidden"
                  accept=".json"
                />
                <Button variant="outline" disabled={loading}>
                  <Upload size={16} className="mr-2" />
                  Restore Backup
                </Button>
              </label>
            </div>
  
            {/* Search Keys */}
            {keys.length > 0 && (
              <Input
                placeholder="Search keys..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="max-w-md"
              />
            )}
  
            {/* Key List */}
            <div className="space-y-2">
              {filteredKeys.map((keyPair, index) => (
                <div
                  key={keyPair.id}
                  className={`p-4 rounded-lg border ${
                    selectedKeyIndex === index ? 'border-blue-500 bg-blue-50' : ''
                  }`}
                >
                  <div className="space-y-4">
                    <div className="flex justify-between items-start">
                      <div className="space-y-2 flex-1">
                        <div className="flex items-center gap-2">
                          <Key size={16} />
                          <span className="font-medium">{keyPair.name}</span>
                          {keyPair.description && (
                            <span className="text-sm text-gray-500">
                              - {keyPair.description}
                            </span>
                          )}
                        </div>
                        <div className="text-sm text-gray-500">
                          Created: {new Date(keyPair.createdAt).toLocaleString()}
                          {keyPair.lastUsed && (
                            <span className="ml-4">
                              Last used: {new Date(keyPair.lastUsed).toLocaleString()}
                            </span>
                          )}
                        </div>
                        <div className="space-y-2">
                          <div className="space-y-1">
                            <span className="text-sm text-gray-500">Public Key:</span>
                            <div className="flex items-center gap-2">
                              <code className="text-sm bg-gray-100 p-1 rounded break-all">
                                {keyPair.publicKey}
                              </code>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => copyToClipboard(keyPair.publicKey)}
                                disabled={loading}
                              >
                                {copied ? <Check size={14} /> : <Copy size={14} />}
                              </Button>
                            </div>
                          </div>
                          {showPrivateKey && (
                            <div className="space-y-1">
                              <span className="text-sm text-gray-500">Private Key:</span>
                              <div className="flex items-center gap-2">
                                <code className="text-sm bg-gray-100 p-1 rounded break-all">
                                  {keyPair.privateKey}
                                </code>
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setShowPrivateKey(!showPrivateKey)}
                          title={showPrivateKey ? "Hide private key" : "Show private key"}
                          disabled={loading}
                        >
                          {showPrivateKey ? <EyeOff size={14} /> : <Eye size={14} />}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => exportKey(keyPair)}
                          title="Export key"
                          disabled={loading}
                        >
                          <Download size={14} />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedKeyIndex(index)}
                          title="Select for signing"
                          disabled={loading}
                        >
                          Sign
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => window.confirm('Are you sure you want to delete this key?') && deleteKeyPair(index)}
                          title="Delete key"
                          disabled={loading}
                        >
                          <Trash2 size={14} />
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
  
            {/* Signing Section */}
            {selectedKeyIndex !== null && (
              <Card className="mt-4">
                <CardHeader>
                  <CardTitle className="text-lg">Sign & Verify Messages</CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Signing */}
                  <div className="space-y-4">
                    <h4 className="font-medium">Sign Message</h4>
                    <Input
                      placeholder="Enter message to sign..."
                      value={message}
                      onChange={(e) => setMessage(e.target.value)}
                      disabled={loading}
                    />
                    <Button
                      onClick={signMessage}
                      disabled={!message || loading}
                      className="w-full"
                    >
                      {loading ? 'Signing...' : 'Sign Message'}
                    </Button>
                    {signature && (
                      <Alert>
                        <AlertDescription>
                          <div className="space-y-2">
                            <div>
                              <span className="font-medium">Signature:</span>
                              <code className="block text-sm mt-1 bg-gray-100 p-2 rounded break-all">
                                {signature}
                              </code>
                            </div>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(signature)}
                              disabled={loading}
                            >
                              {copied ? (
                                <Check size={14} className="mr-2" />
                              ) : (
                                <Copy size={14} className="mr-2" />
                              )}
                              Copy Signature
                            </Button>
                          </div>
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
  
                  {/* Verification */}
                  <div className="space-y-4">
                    <h4 className="font-medium">Verify Signature</h4>
                    <Input
                      placeholder="Enter message..."
                      value={verifyMessage}
                      onChange={(e) => setVerifyMessage(e.target.value)}
                      disabled={loading}
                    />
                    <Input
                      placeholder="Enter signature..."
                      value={verifySignature}
                      onChange={(e) => setVerifySignature(e.target.value)}
                      disabled={loading}
                    />
                    <Button
                      onClick={verifyMessageSignature}
                      disabled={!verifyMessage || !verifySignature || loading}
                      className="w-full"
                    >
                      {loading ? 'Verifying...' : 'Verify Signature'}
                    </Button>
                    {verificationResult !== null && (
                      <Alert>
                        <AlertDescription>
                          {verificationResult ? (
                            <span className="text-green-600 font-medium">✓ Signature is valid</span>
                          ) : (
                            <span className="text-red-600 font-medium">✗ Invalid signature</span>
                          )}
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default KeyManagementTool;