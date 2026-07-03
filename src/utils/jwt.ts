import jwt, { JwtPayload, SignOptions } from "jsonwebtoken";

const createToken = (
  payload: JwtPayload,
  secret: string,
  expiresIn: SignOptions,
) => {
  return jwt.sign(payload, secret, expiresIn);
};

// verify token function
const verifyToken = (token: string, secret: string) => {
  try {
    const verifiedToken = jwt.verify(token, secret);
    return verifiedToken;
  } catch (error: any) {
    console.error("Token verification failed:", error);
    throw new Error(error.message);
  }
};

export const jwtUtils = {
  createToken,
  verifyToken,
};
