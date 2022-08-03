import {
  generateBls12381G2KeyPair,
  blsSign,
  blsVerify,
  blsCreateProof,
  blsVerifyProof,
} from "@mattrglobal/bbs-signatures";



import fs from 'fs'
import crypto from 'crypto'


export function encryptText(plainText) {
  return crypto.publicEncrypt({
    key: fs.readFileSync('public_key.pem', 'utf8'),
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  },
    // We convert the data string to a buffer
    Buffer.from(plainText)
  )
}

export function decryptText(encryptedText) {
  return crypto.privateDecrypt(
    {
      key: fs.readFileSync('private_key.pem', 'utf8'),
      // In order to decrypt the data, we need to specify the
      // same hashing function and padding scheme that we used to
      // encrypt the data in the previous step
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256'
    },
    encryptedText
  )
}



const plainText_Medication = "Medication X";
const plainText_Personal_Info = "Personal Info Y";

const encrypted_Medication = encryptText(plainText_Medication)
const encrypted_Personal_Info = encryptText(plainText_Personal_Info)
// encryptedText will be returned as Buffer
// in order to see it in more readble form, convert it to base64
//console.log('encrypted text1: ', encryptedText_1.toString('base64'))
//console.log('encrypted text2: ', encryptedText_2.toString('base64'))


const encrypted_Medication_string = encrypted_Medication.toString('base64')
const encrypted_Personal_Info_string= encrypted_Personal_Info.toString('base64')


//console.log(typeof(encryptedText_2_string))


//Generate a new key pair
const keyPair = await generateBls12381G2KeyPair();

//Set of messages we wish to sign
const messages = [
  Uint8Array.from(Buffer.from(encrypted_Medication_string, "base64")),
  Uint8Array.from(Buffer.from(encrypted_Personal_Info_string, "base64")),
];

//Create the signature
const signature = await blsSign({
  keyPair,
  messages: messages,
});

//Verify the signature
const isVerified = await blsVerify({
  publicKey: keyPair.publicKey,
  messages: messages,
  signature,
});

//Derive a proof from the signature revealing the first message
const proof = await blsCreateProof({
  signature,
  publicKey: keyPair.publicKey,
  messages,
  nonce: Uint8Array.from(Buffer.from("nonce", "utf8")),
  revealed: [0],
});

//Verify the created proof
const isProofVerified = await blsVerifyProof({
  proof,
  publicKey: keyPair.publicKey,
  messages: messages.slice(0, 1),
  nonce: Uint8Array.from(Buffer.from("nonce", "utf8")),
});




const decryptedText = decryptText(encrypted_Medication)
console.log('decrypted text:', decryptedText.toString())