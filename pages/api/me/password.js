/**
 * MIT License

Copyright (c) 2022 KlaudSol Philippines, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
**/

import { withSession } from "@klaudsol/commons/lib/Session";
import { defaultErrorHandler } from "@klaudsol/commons/lib/ErrorHandler";
import { assert } from "@klaudsol/commons/lib/Permissions";
import { OK, UNPROCESSABLE_ENTITY } from "@klaudsol/commons/lib/HttpStatuses";
import Session from "@klaudsol/commons/models/Session";
import People from "@klaudsol/commons/models/People";
import UnauthorizedError from "@klaudsol/commons/errors/UnauthorizedError";
import RecordNotFound from "@klaudsol/commons/errors/RecordNotFound";

export default withSession(handler);

async function handler(req, res) {
  try {
    switch (req.method) {
      case "PUT":
        return update(req, res);
      default:
        throw new Error(`Unsupported method: ${req.method}`);
    }
  } catch (error) {
    await defaultErrorHandler(error, req, res);
  }
}

async function update(req, res) {
  try {
 
    const { session_token } = req.session;
    const { email, currentPassword, newPassword, confirmNewPassword } = req.body;

    //these should be captured by the front-end validator, but the backend should detect
    //it as well.
    if (!newPassword || !confirmNewPassword) {
     return res.status(UNPROCESSABLE_ENTITY).json({ message: "Password is required." });
    }

    if (newPassword !== confirmNewPassword) {
      return res.status(UNPROCESSABLE_ENTITY).json({ message:  "The password does not match the confirmation password." });
    }

    await assert(
      {
        loggedIn: true,
      },
      req
    );

    const forcePasswordChange = await People.updatePassword({
      email,
      session: session_token,
      oldPassword: currentPassword,
      newPassword,
    });
    
    console.log(forcePasswordChange)

    req.session.cache = {
      ...req.session.cache,
      forcePasswordChange,
    };
    await req.session.save();

    res.status(OK).json({ message: "Successfully changed your password." });
  } catch (error) {
    if (error instanceof UnauthorizedError || error instanceof RecordNotFound) {
      res.status(UNPROCESSABLE_ENTITY).json({ message: error.message });
    } else {
      await defaultErrorHandler(error, req, res);
    }
  }
}
