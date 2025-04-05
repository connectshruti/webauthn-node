// Passkey Model: Stores WebAuthn passkeys (credential ID, public key, authentication counter).
import mongoose, { Schema } from 'mongoose';
const PasskeySchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: "User", required: true },
    credentialID: { type: Buffer, required: true, unique: true }, // Fixed typo: 'requiired' -> 'required'
    publicKey: { type: Buffer, required: true },
    transports: {
        type: [String],
        enum: ['usb', 'nfc', 'ble', 'internal', 'hybrid'],
    },
    counter: { type: Number, required: true, default: 0 },
}, { timestamps: true });
export const Passkey = mongoose.model("Passkey", PasskeySchema);
// mongodb+srv://shrutisharma:<db_password>@webauthncluster.mgozed7.mongodb.net/?retryWrites=true&w=majority&appName=webauthncluster
