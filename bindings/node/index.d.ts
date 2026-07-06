export declare function version(): string;

export declare function encode(data: Buffer, passphrase: string, pepper?: Buffer): string;
export declare function decode(symbols: string, passphrase: string, pepper?: Buffer): Buffer;

export interface StreamOptions { pepper?: Buffer; chunkSize?: number; }
export declare function encryptStream(data: Buffer, passphrase: string, opts?: StreamOptions): Buffer;
export declare function decryptStream(blob: Buffer, passphrase: string, opts?: { pepper?: Buffer }): Buffer;

export interface KeyPair { publicKey: Buffer; secretKey: Buffer; }
export declare function generateKeypair(): KeyPair;
export declare function encryptToRecipient(data: Buffer, publicKey: Buffer): string;
export declare function decryptAsRecipient(symbols: string, secretKey: Buffer): Buffer;

export interface SigningKeyPair { verifyingKey: Buffer; signingKey: Buffer; }
export declare function generateSigningKeypair(): SigningKeyPair;
export declare function sign(data: Buffer, signingKey: Buffer): string;
export declare function verify(symbols: string, verifyingKey: Buffer): Buffer;

export type QuipuErrorCode = 'AUTH' | 'KEY' | 'CHUNK' | 'NULL_ARG' | 'INTERNAL';
export declare class QuipuError extends Error { code: QuipuErrorCode; }
