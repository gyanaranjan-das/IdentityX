import jwt from "jsonwebtoken";
import { env } from "../../config/index.js";
import { findUserByEmail, createUser } from "./auth.repository.js";

const register = async ({ email, password }) => {
  const existingUser = await findUserByEmail(email);
  if (existingUser) {
    throw new Error("User already exists");
  }

  const user = await createUser({ email, password });

  return {
    id: user._id,
    email: user.email
  };
};

const login = async ({ email, password }) => {
  const user = await findUserByEmail(email);
  if (!user) {
    throw new Error("Invalid credentials");
  }

  const isMatch = await user.comparePassword(password);
  if (!isMatch) {
    throw new Error("Invalid credentials");
  }

  const accessToken = jwt.sign(
    { userId: user._id, role: user.role },
    env.jwt.accessSecret,
    { expiresIn: env.jwt.accessExpiry }
  );

  return { accessToken };
};

export {
  register,
  login
};
