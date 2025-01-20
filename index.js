const { generateTOTP } = require("./totp");

Cypress.Commands.add("generateTOTP", (secret, timeStep = 30, digits = 6) => {
    return generateTOTP(secret, timeStep, digits);
});
