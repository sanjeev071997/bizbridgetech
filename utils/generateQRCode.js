import QRCode from "qrcode";

export const generateQRCode = async (upiId, amount) => {
  try {
    const upiUrl = `upi://pay?pa=${upiId}&pn=Seller&am=${amount}&cu=INR`;
    const qr = await QRCode.toDataURL(upiUrl);
    return qr; // base64 encoded QR
  } catch (err) {
    console.error("QR Code generation failed", err);
    return null;
  }
};
