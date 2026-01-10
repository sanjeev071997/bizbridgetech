
export const normalizeEmail = (email) => {
  if (!email) return email;
  
  email = email.toLowerCase().trim();

  const [localPart, domain] = email.split("@");

  if (domain === "gmail.com" || domain === "googlemail.com") {
    const cleanLocal = localPart
      .split("+")[0]     
      .replace(/\./g, ""); 

    return `${cleanLocal}@gmail.com`;
  }

  return email;
};