const {
  browserSupportsWebAuthn,
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthnAutofill
} = SimpleWebAuthnBrowser

const PASSKEY_SUPPORTED = document.getElementById('passkeySupported')
const PASSKEY_FORM = document.getElementById('passkeyForm')
const COMPAT_MESSAGE = document.getElementById('passkeyNotSupported')
const REGISTER_BUTTON = document.getElementById('register')
const AUTHENTICATE_BUTTON = document.getElementById('authenticate')
const USER_NAME = document.getElementById('name')
const ANNOUNCER = document.getElementById('announcer')

const announce = (msg, keepMs = 3000) => {
  ANNOUNCER.innerText = msg
  ANNOUNCER.style.display = 'block'
  setTimeout(() => {
    ANNOUNCER.style.display = 'none'
  }, keepMs)
}

// Before invoking a conditional WebAuthn API call, check if:
// The browser supports WebAuthn.
// `isUserVerifyingPlatformAuthenticatorAvailable` – feature detection is usable.
// `isConditionalMediationAvailable` - the browser supports WebAuthn conditional UI.
// In practice, this means autofilling available credentials;
// you need to include autocomplete="webauthn" on your form fields.
if (
  window.PublicKeyCredential &&
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&  
  PublicKeyCredential.isConditionalMediationAvailable
) {
  // Check if user verifying platform authenticator is available.
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
    .then(result => result && PublicKeyCredential.isConditionalMediationAvailable())
    .then(isCMA => {
      if (isCMA) {
        // Display form to register or authenticate.
        PASSKEY_SUPPORTED.style.display = 'block'
        REGISTER_BUTTON.addEventListener('click', async e => {
          e.preventDefault()
          if (!USER_NAME.value.length) {
            announce(`Please enter a username`, 2000)
            USER_NAME.focus()
            return
          } 
          try {
            const regStartResp = await fetch('/registration/start', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                username: USER_NAME.value
              })
            })
            const regOptions = await regStartResp.json()
            // Start WebAuthn registration
            const regResp = await startRegistration(regOptions.publicKey)
            // Submit response
            const regFinishResp = await fetch('/registration/finish', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                username: USER_NAME.value,
                response: regResp
              })
            })
            // Display outcome
            if (regFinishResp.ok === true) {
              announce(`Success! Now try to authenticate...`)
            } else {
              announce(`Registration failed`)
            }
          } catch (err) {
            announce(`Error: ${err.message}`)
            throw err
          }
        })
        AUTHENTICATE_BUTTON.addEventListener('click', async e => {
          e.preventDefault()
          try {
            const authStartResp = await fetch('/authentication/start', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                username: USER_NAME.value
              })
            })
            const authOpts = await authStartResp.json()
            // Start WebAuthn authentication
            const authResp = await startAuthentication(authOpts.publicKey, true)
            // Submit response
            const authFinishResp = await fetch('/authentication/finish', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                username: USER_NAME.value,
                response: authResp
              })
            })
            // Display outcome
            if (authFinishResp.ok === true) {
              announce(`Success! You're authenticated`)
            } else {
              announce(`Authentication failed`)
            }
          } catch (err) {
            announce(`Error: ${err.message}`)
            throw err
          }
        })
      } else {
        announce(`User verifying platform authenticator is not available`)
        throw new Error(
          `User verifying platform authenticator is not available`
        )
      }
    })
    .catch(() => {
      // Display message that WebAuthn is not supported.
      COMPAT_MESSAGE.style.display = 'block'
    })
}
