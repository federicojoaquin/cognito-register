import { CognitoIdentityProviderClient, AdminInitiateAuthCommand } from "@aws-sdk/client-cognito-identity-provider"
import jwt from 'jsonwebtoken';

const { COGNITO_REGION, COGNITO_APP_CLIENT_ID, COGNITO_USER_POOL_ID } = process.env

export default async function handler(req, res) {
	if (req.method !== 'POST') return res.status(405).send()

	const params = {
		AuthFlow: 'ADMIN_USER_PASSWORD_AUTH',
		ClientId: COGNITO_APP_CLIENT_ID,
		UserPoolId: COGNITO_USER_POOL_ID,
		AuthParameters: {
			USERNAME: req.body.username,
			PASSWORD: req.body.password
		}
	}

	const cognitoClient = new CognitoIdentityProviderClient({
		region: COGNITO_REGION
	})
	const adminInitiateAuthCommand = new AdminInitiateAuthCommand(params)

	try {
        const response = await cognitoClient.send(adminInitiateAuthCommand);
        console.log(response);

        // Decodifica el IdToken
        const decodedToken = jwt.decode(response.AuthenticationResult.IdToken);
        console.log("Token decodificado:", decodedToken);

        return res.status(response['$metadata'].httpStatusCode).json({
            ...response.AuthenticationResult,
            userId: decodedToken ? decodedToken.sub : null
        });
    } catch (err) {
        console.error("Error al decodificar el token:", err);
        return res.status(err['$metadata'].httpStatusCode).json({ message: err.toString() });
    }
}