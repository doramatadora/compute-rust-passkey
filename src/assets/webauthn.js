const PASSKEY_FORM = document.getElementById("passkeySupported");
const COMPAT_MESSAGE = document.getElementById("passkeyNotSupported");
const REGISTER_BUTTON = document.getElementById("register");
const AUTHENTICATE_BUTTON = document.getElementById("authenticate");

// Availability of `window.PublicKeyCredential` means WebAuthn is usable.
// `isUserVerifyingPlatformAuthenticatorAvailable` means the feature detection is usable.
if (
  window.PublicKeyCredential &&
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable
) {
  // Check if user verifying platform authenticator is available.
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
    .then((result) => {
      if (result) {
        // Display form to register or authenticate.
        PASSKEY_FORM.style.display = "block";
      } else {
        throw new Error(
          "User verifying platform authenticator is not available."
        );
      }
    })
    .catch((error) => {
      // Display message that WebAuthn is not supported.
      COMPAT_MESSAGE.style.display = "block";
    });
}

const randomStringFromServer = "1234";
const publicKeyCredentialCreationOptions = {
  challenge: Uint8Array.from(randomStringFromServer, (c) => c.charCodeAt(0)),
  rp: {
    name: "Fastly Compute@Edge",
    id: "localhost",
  },
  user: {
    id: Uint8Array.from("UZSL85T9AFC", (c) => c.charCodeAt(0)),
    name: "dora",
    displayName: "dora",
  },
  pubKeyCredParams: [
    { type: "public-key", alg: -7 },
    { type: "public-key", alg: -257 },
  ], // -7 for "ES256" and -257 for "RS256"
  authenticatorSelection: {
    authenticatorAttachment: "platform",
    requireResidentKey: true,
    // residentKey: "preferred",
    // requireResidentKey: false,
    // userVerification: "preferred",
  },
  timeout: 60000,
  attestation: "none",
  extensions: { credProps: true },
};

navigator.credentials
  .create({
    publicKey: publicKeyCredentialCreationOptions,
  })
  .then((credential) => {
    console.log(credential);
    console.log(credential.response.getPublicKey())
    // decode the clientDataJSON into a utf-8 string
const utf8Decoder = new TextDecoder('utf-8');
const decodedClientData = utf8Decoder.decode(
    credential.response.clientDataJSON)

// parse the string as an object
const clientDataObj = JSON.parse(decodedClientData);

console.log(clientDataObj)

  });
