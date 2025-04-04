// Passkey Model: Stores WebAuthn passkeys (credential ID, public key, authentication counter).

import { User } from './user.model.js';
import mongoose, { Schema, Document } from 'mongoose';

export interface IPasskey extends Document {
    userId: mongoose.Schema.Types.ObjectId;
    credentialID: Buffer;
    publicKey: Buffer;
    transports: ("usb" | "nfc" | "ble" | "internal" | "hybrid")[];
    counter: number;
}

const PasskeySchema = new Schema<IPasskey>({
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    credentialID: { type: Buffer, required: true, unique: true }, // Fixed typo: 'requiired' -> 'required'
    publicKey: { type: Buffer, required: true },
    transports: {
        type: [String],
        enum: ['usb', 'nfc', 'ble', 'internal', 'hybrid'],
    },
    counter: { type: Number, required: true, default: 0 },
}, { timestamps: true });

export const Passkey = mongoose.model<IPasskey>("Passkey", PasskeySchema);
// mongodb+srv://shrutisharma:<db_password>@webauthncluster.mgozed7.mongodb.net/?retryWrites=true&w=majority&appName=webauthncluster