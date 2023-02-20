const {
  browserSupportsWebAuthn,
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthnAutofill,
} = SimpleWebAuthnBrowser;

const PASSKEY_SUPPORTED = document.getElementById("passkeySupported");
const PASSKEY_FORM = document.getElementById("passkeyForm");
const COMPAT_MESSAGE = document.getElementById("passkeyNotSupported");
const REGISTER_BUTTON = document.getElementById("register");
const AUTHENTICATE_BUTTON = document.getElementById("authenticate");
const USER_NAME = document.getElementById("name");

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
        PASSKEY_SUPPORTED.style.display = "block";
        REGISTER_BUTTON.addEventListener("click", async (e) => {
          e.preventDefault();
          const regStartResp = await fetch("/registration/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: USER_NAME.value,
            }),
          });
          const registrationOptionsJSON = await regStartResp.json();
          console.log({ registrationOptionsJSON });
          // Start WebAuthn registration
          const regResp = await startRegistration(
            registrationOptionsJSON.publicKey
          );
          console.log({ regResp });
          // Submit response
          const regFinishResp = await fetch("/registration/finish", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: USER_NAME.value,
              response: regResp,
            }),
          });
          // Display outcome
          if (regFinishResp.ok === true) {
            alert(`Success! Now try to authenticate...`);
          } else {
            alert(`Registration failed`);
          }
        });
        AUTHENTICATE_BUTTON.addEventListener("click", async (e) => {
          e.preventDefault();
          const authStartResp = await fetch("/authentication/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: USER_NAME.value,
            }),
          });
          const authenticationOptionsJSON = await authStartResp.json();
          console.log({ authenticationOptionsJSON });
          // Start WebAuthn authentication
          const authResp = await startAuthentication(authenticationOptionsJSON);
          console.log({ authResp });
          // Submit response
          const authFinishResp = await fetch("/authentication/finish", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: USER_NAME.value,
              response: authResp,
            }),
          });
          // Display outcome
          if (authFinishResp.ok === true) {
            alert(`Success! You're authenticated`);
          } else {
            alert(`Authentication failed`);
          }
        });
      } else {
        throw new Error(
          `User verifying platform authenticator is not available.`
        );
      }
    })
    .catch(() => {
      // Display message that WebAuthn is not supported.
      COMPAT_MESSAGE.style.display = "block";
    });
}
