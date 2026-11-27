# Assignment 5 Reflection

Leena Joshi

The trickiest requirement was making the Google callback create exactly one general user record per email. The starter code already exchanged the authorization code for Google credentials, so I added the database step after the callback checks the OAuth state and receives a verified email. The callback records the email with an empty password and sets the account type to `general`. A uniqueness constraint prevents duplicate accounts when someone signs in again or when two callbacks arrive close together. Once the database step succeeds, Flask stores the email and role in the session and redirects to the photo portal.

I used the session role to determine which controls the portal displays and which requests the server accepts. Search and logout read the stored role, and Flask checks for the admin role before accepting upload, tag update, or delete requests. The admin registration endpoint hashes passwords with bcrypt, and `GET /users` returns account details without passwords.

I ran the app locally on Windows over HTTPS on port 5009, registered `Admin1` through `POST /users`, and confirmed that an incorrect password displayed the expected error. With the correct password, I reached the admin portal and saw the upload and photo management controls. Separate automated checks verified the stored bcrypt hash, duplicate admin rejection, and both admin login errors. A mocked Google callback also confirmed that two sign-ins with the same verified email produced one user record and that a general user received HTTP 403 when attempting an upload.

On EC2, Google initially returned `redirect_uri_mismatch`. I checked the callback URL in the error details and compared the OAuth client ID on the server with the client in Google Cloud. After saving the exact EC2 callback URL on that client, I successfully signed in with Google from the deployed portal.

![Admin password error](screenshots/01-invalid-admin-password.png)

*Requirement 2.5. The admin sign-in page displays “password does not match” when an existing admin enters an incorrect password.*

![Admin photo portal after sign-in](screenshots/02-admin-photo-portal.png)

*Requirement 4. A successful admin sign-in opens the portal with the upload form and photo management controls.*
