import People from "@klaudsol/commons/models/People";
import { withSession } from "@klaudsol/commons/lib/Session";
import { defaultErrorHandler } from "@klaudsol/commons/lib/ErrorHandler";
import { OK, UNPROCESSABLE_ENTITY } from "@klaudsol/commons/lib/HttpStatuses";
import UnauthorizedError from "@klaudsol/commons/errors/UnauthorizedError";
import RecordNotFound from "@klaudsol/commons/errors/RecordNotFound";
import Session from "@klaudsol/commons/models/Session";
import { assertUserIsLoggedIn } from "@klaudsol/commons/lib/Permissions";

export default withSession(handler);

async function handler(req, res) {
  try {
    switch (req.method) {
      case "POST":
        return login(req, res);
      case "DELETE":
        return logout(req, res);
      default:
        throw new Error(`Unsupported method: ${req.method}`);
    }
  } catch (error) {
    await defaultErrorHandler(error, req, res);
  }
}

async function login(req, res) {
  try {
    const { email = null, password = null } = req.body;

    if (!email || !password) {
     return res.status(UNPROCESSABLE_ENTITY).json({ message: "Email/username and password are required." });
    }

    const {
      session_token,
      user: { firstName, lastName, roles, capabilities, forcePasswordChange },
    } = await People.login(email, password);
    req.session.session_token = session_token;
    req.session.cache = {
      firstName,
      lastName,
      defaultEntityType: "Articles",
      homepage: "/admin",
      forcePasswordChange,
    };

    if (!forcePasswordChange) {
      req.session.cache.roles = roles;
      req.session.cache.capabilities = capabilities;
    }

    // We will refrain from assigning roles and capabilities if the forcePasswordChange flag is set to true.
    // This is to prevent logged-in users from accessing protected api routes before changing their password.

    await req.session.save();
    res.status(OK).json({ forcePasswordChange });
  } catch (error) {
    if (error instanceof UnauthorizedError || error instanceof RecordNotFound) {
      res.status(UNPROCESSABLE_ENTITY).json({ message: error.message });
    } else {
      await defaultErrorHandler(error, req, res);
    }
  }
}

async function logout(req, res) {
  try {
    const session_token = assertUserIsLoggedIn(req);
    await Session.logout(session_token);
    req.session.destroy();
    res.status(200).json({ message: "OK" });
  } catch (error) {
    await defaultErrorHandler(error, req, res);
  }
}
