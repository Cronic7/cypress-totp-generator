# Cypress TOTP Plugin

A plugin to generate TOTP (Time-Based One-Time Password) codes for use in Cypress tests.

## Features
- Generate TOTP codes based on a Base32-encoded secret.
- Fully compatible with Cypress custom commands.
- Supports dynamic time step and digit configuration.

## Installation

Install the package via npm:

```bash
npm install cypress-totp
```

## Usage

1. **Import the Plugin**
   Add the following line to your `cypress/support/commands.js` file:

   ```javascript
   require("cypress-totp");
   ```

2. **Use the Custom Command**
   In your Cypress test, use the `cy.generateTOTP` command to generate a TOTP code:

   ```javascript
   describe("2FA Login Test", () => {
       it("should generate a valid TOTP code", () => {
           const secret = "YOUR_BASE32_SECRET"; // Replace with your secret key

           cy.generateTOTP(secret).then((totp) => {
               cy.log(`Generated TOTP Code: ${totp}`);

               // Use the TOTP code in your test
               cy.get("#otp-input").type(totp);
               cy.get("#submit-button").click();
           });
       });
   });
   ```

## API

### `cy.generateTOTP(secret, timeStep = 30, digits = 6)`

Generates a TOTP code.

- **Parameters**:
  - `secret` *(string)*: Base32-encoded secret key.
  - `timeStep` *(number, optional)*: Time step in seconds (default: 30 seconds).
  - `digits` *(number, optional)*: Number of digits in the TOTP code (default: 6 digits).

- **Returns**: A promise that resolves to the generated TOTP code.

## Example

```javascript
describe("Login Test", () => {
    it("logs in with a TOTP code", () => {
        const secret = "HVR4CFHAFOWFGGFAGSA5JVTIMMPG6GMT";

        cy.generateTOTP(secret).then((totp) => {
            cy.get("#otp-input").type(totp);
            cy.get("#submit").click();
        });
    });
});
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Author

Developed by  Cronic7

