"use client";

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./card";
import { Button } from "./button";
import { Input } from "./input";
import { Plus, Key, Trash2, Copy, Check, Download, Upload, Eye, EyeOff } from 'lucide-react';
import { Alert, AlertDescription } from "./alert";
import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { sha512 } from '@noble/hashes/sha512';

// Use SHA-512 for message hashing
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

interface KeyPair {
  id: number;
  publicKey: string;
  privateKey: string;
  createdAt: string;
  name: string;
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
  const [signedMessages, setSignedMessages] = useState<SignedMessage[]>([]);
  const [verifyMessage, setVerifyMessage] = useState<string>('');
  const [verifySignature, setVerifySignature] = useState<string>('');
  const [verificationResult, setVerificationResult] = useState<boolean | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    try {
      const savedKeys = localStorage.getItem('amaci-keys');
      if (savedKeys) {
        setKeys(JSON.parse(savedKeys));
      }
    } catch (err) {
      console.error('Failed to load keys:', err);
      setError('Failed to load saved keys');
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem('amaci-keys', JSON.stringify(keys));
    } catch (err) {
      console.error('Failed to save keys:', err);
      setError('Failed to save keys');
    }
  }, [keys]);

  const generateNewKeyPair = async () => {
    try {
      setLoading(true);
      setError(null);
      const privateBytes = randomBytes(32);
      const privateKey = bytesToHex(privateBytes);
      const publicKeyBytes = await ed.getPublicKey(privateBytes);
      const publicKey = bytesToHex(publicKeyBytes);
      
      const newKeyPair: KeyPair = {
        id: Date.now(),
        publicKey,
        privateKey,
        createdAt: new Date().toISOString(),
        name: keyName || `Key ${keys.length + 1}`,
      };
      
      setKeys([...keys, newKeyPair]);
      setKeyName('');
    } catch (err) {
      console.error('Failed to generate keypair:', err);
      setError('Failed to generate new keypair');
    } finally {
      setLoading(false);
    }
  };

  const deleteKeyPair = (index: number) => {
    try {
      const newKeys = keys.filter((_, idx) => idx !== index);
      setKeys(newKeys);
      if (selectedKeyIndex === index) {
        setSelectedKeyIndex(null);
        setSignature('');
      }
    } catch (err) {
      console.error('Failed to delete keypair:', err);
      setError('Failed to delete keypair');
    }
  };

  const signMessage = async () => {
    if (selectedKeyIndex !== null && message) {
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

        setSignedMessages([...signedMessages, signedMessage]);
        setSignature(signature);
        setMessage('');
      } catch (err) {
        console.error('Failed to sign message:', err);
        setError('Failed to sign message');
      } finally {
        setLoading(false);
      }
    }
  };

  const verifyMessageSignature = async () => {
    if (!verifyMessage || !verifySignature || selectedKeyIndex === null) return;

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
      setError('Failed to verify signature');
      setVerificationResult(false);
    } finally {
      setLoading(false);
    }
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

  const importKey = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const keyPair = JSON.parse(e.target?.result as string);
        
        if (!keyPair.publicKey || !keyPair.privateKey) {
          throw new Error('Invalid key file format');
        }

        const privateBytes = hexToBytes(keyPair.privateKey);
        const derivedPublicKey = bytesToHex(await ed.getPublicKey(privateBytes));
        
        if (derivedPublicKey !== keyPair.publicKey) {
          throw new Error('Invalid key pair');
        }

        setKeys([...keys, { ...keyPair, id: Date.now() }]);
      } catch (err) {
        console.error('Failed to import key:', err);
        setError('Failed to import key: Invalid key file');
      }
    };
    reader.readAsText(file);
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
  

  return (
    <div className="max-w-4xl mx-auto p-4 space-y-4">
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      
      <Card className="w-full">
        <CardHeader>
          <CardTitle>A-MACI Key Management</CardTitle>
          <CardDescription>
            Manage your EdDSA keypairs for A-MACI voting system
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {/* Key Generation Section */}
            <div className="space-y-4">
              <div className="flex gap-4">
                <Input
                  placeholder="Key name (optional)"
                  value={keyName}
                  onChange={(e) => setKeyName(e.target.value)}
                  className="max-w-xs"
                />
                <Button
                  onClick={generateNewKeyPair}
                  disabled={loading}
                  className="flex items-center gap-2"
                >
                  {loading ? (
                    'Generating...'
                  ) : (
                    <>
                      <Plus size={16} />
                      Generate New Keypair
                    </>
                  )}
                </Button>
                <label className="flex items-center gap-2">
                  <input
                    type="file"
                    onChange={importKey}
                    className="hidden"
                    accept=".json"
                  />
                  <Button variant="outline" disabled={loading}>
                    <Upload size={16} className="mr-2" />
                    Import Key
                  </Button>
                </label>
              </div>
            </div>
  
            {/* Key List */}
            <div className="space-y-2">
              {keys.map((keyPair, index) => (
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
                          disabled={loading}
                        >
                          {showPrivateKey ? <EyeOff size={14} /> : <Eye size={14} />}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => exportKey(keyPair)}
                          disabled={loading}
                        >
                          <Download size={14} />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedKeyIndex(index)}
                          disabled={loading}
                        >
                          Sign
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteKeyPair(index)}
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