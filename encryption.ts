import * as crypto from "crypto";

export const SIGNATURE = "[ENCRYPTED]";

export const encrypt = (text: string, password: string): string => {
  const iv = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, 'salt', 32);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);

  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  encrypted = SIGNATURE + iv.toString('hex') + encrypted;

  return encrypted;
};

export const decrypt = (text: string, password: string): string => {
  const key = crypto.scryptSync(password, 'salt', 32);
  
  if (text.startsWith(SIGNATURE)) {
    text = text.substring(SIGNATURE.length);
  } else {
    return text;
  }

  const iv = Buffer.from(text.substring(0, 32), 'hex');
  text = text.substring(32);
  
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(text, "hex", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
};

export const hashPassword = (password: string): string => {
  const hash = crypto.createHash("sha256");
  hash.update(password);
  return hash.digest("hex");
};

export const verifyPassword = (inputPassword: string, storedHash: string): boolean => {
  return hashPassword(inputPassword) === storedHash;
};
